import asyncio
import collections
import contextlib
import datetime
import functools
import logging
import operator
import struct
from abc import (
    ABC,
    abstractmethod
)

from typing import (
    Any,
    AsyncIterable,
    AsyncIterator,
    Callable,
    cast,
    Dict,
    Iterator,
    List,
    NamedTuple,
    Set,
    Tuple,
    Type,
    TypeVar,
)

import sha3

from cytoolz import groupby

import rlp

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.constant_time import bytes_eq

from eth_utils import (
    to_tuple,
)

from eth_keys import datatypes

from cancel_token import CancelToken, OperationCancelled

from p2p import auth
from p2p import protocol
from p2p.kademlia import Node
from p2p.exceptions import (
    BadAckMessage,
    DecryptionError,
    HandshakeFailure,
    MalformedMessage,
    NoMatchingPeerCapabilities,
    PeerConnectionLost,
    RemoteDisconnected,
    UnexpectedMessage,
    UnknownProtocolCommand,
    UnreachablePeer,
)
from p2p.service import BaseService
from p2p.utils import (
    get_devp2p_cmd_id,
    roundup_16,
    sxor,
    time_since,
)
from p2p.p2p_proto import (
    Disconnect,
    DisconnectReason,
    Hello,
    P2PProtocol,
    Ping,
    Pong,
)

from .constants import (
    CONN_IDLE_TIMEOUT,
    DEFAULT_MAX_PEERS,
    HEADER_LEN,
    MAC_LEN,
)


TPeer = TypeVar('TPeer', bound='BasePeer')


TInitPeerFn = Callable[
    [
        Node,  # remote
        datatypes.PrivateKey,  # privkey
        asyncio.StreamReader,  # reader
        asyncio.StreamWriter,  # writer
        bytes,  # aes_secret
        bytes,  # mac_secret
        sha3.keccak_256,  # egress_mac
        sha3.keccak_256,  # ingress_mac
        bool,  # inbound
        CancelToken,  # token
    ],
    TPeer,
]


async def handshake(remote: Node,
                    privkey: datatypes.PrivateKey,
                    mk_peer_fn: TInitPeerFn,
                    token: CancelToken,
                    ) -> 'TPeer':
    """Perform the auth and P2P handshakes with the given remote.

    Return an instance of the given peer_class (must be a subclass of BasePeer) connected to that
    remote in case both handshakes are successful and at least one of the sub-protocols supported
    by peer_class is also supported by the remote.

    Raises UnreachablePeer if we cannot connect to the peer or HandshakeFailure if the remote
    disconnects before completing the handshake or if none of the sub-protocols supported by us is
    also supported by the remote.
    """
    try:
        (aes_secret,
         mac_secret,
         egress_mac,
         ingress_mac,
         reader,
         writer
         ) = await auth.handshake(remote, privkey, token)
    except (ConnectionRefusedError, OSError) as e:
        raise UnreachablePeer() from e
    peer = mk_peer_fn(
        remote=remote,
        privkey=privkey,
        reader=reader,
        writer=writer,
        aes_secret=aes_secret,
        mac_secret=mac_secret,
        egress_mac=egress_mac,
        ingress_mac=ingress_mac,
        inbound=False,
    )
    await peer.do_p2p_handshake()
    await peer.do_sub_proto_handshake()
    return peer


class BasePeer(BaseService):
    conn_idle_timeout = CONN_IDLE_TIMEOUT
    # Must be defined in subclasses. All items here must be Protocol classes representing
    # different versions of the same P2P sub-protocol (e.g. ETH, LES, etc).
    _supported_sub_protocols: List[Type[protocol.Protocol]] = []
    # FIXME: Must be configurable.
    listen_port = 30303
    # Will be set upon the successful completion of a P2P handshake.
    sub_proto: protocol.Protocol = None

    def __init__(self,
                 remote: Node,
                 privkey: datatypes.PrivateKey,
                 reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter,
                 aes_secret: bytes,
                 mac_secret: bytes,
                 egress_mac: sha3.keccak_256,
                 ingress_mac: sha3.keccak_256,
                 inbound: bool = False,
                 token: CancelToken = None,
                 ) -> None:
        super().__init__(token)
        # The `Node` that this peer is connected to
        self.remote = remote
        self.privkey = privkey
        self.reader = reader
        self.writer = writer
        self.base_protocol = P2PProtocol(self)
        self.inbound = inbound
        self._subscribers: List[PeerSubscriber] = []
        self.start_time = datetime.datetime.now()
        self.received_msgs: Dict[protocol.Command, int] = collections.defaultdict(int)

        self.booted = asyncio.Event()

        self.egress_mac = egress_mac
        self.ingress_mac = ingress_mac
        # FIXME: Yes, the encryption is insecure, see: https://github.com/ethereum/devp2p/issues/32
        iv = b"\x00" * 16
        aes_cipher = Cipher(algorithms.AES(aes_secret), modes.CTR(iv), default_backend())
        self.aes_enc = aes_cipher.encryptor()
        self.aes_dec = aes_cipher.decryptor()
        mac_cipher = Cipher(algorithms.AES(mac_secret), modes.ECB(), default_backend())
        self.mac_enc = mac_cipher.encryptor().update

    def get_extra_stats(self) -> List[str]:
        return []

    @abstractmethod
    async def send_sub_proto_handshake(self) -> None:
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    async def process_sub_proto_handshake(
            self, cmd: protocol.Command, msg: protocol.PayloadType) -> None:
        raise NotImplementedError("Must be implemented by subclasses")

    @contextlib.contextmanager
    def collect_sub_proto_messages(self) -> Iterator['MsgBuffer']:
        """
        Can be used to gather up all messages that are sent to the peer.
        """
        if not self.is_running:
            raise RuntimeError("Cannot collect messages if peer is not running")
        msg_buffer = MsgBuffer()

        with msg_buffer.subscribe_peer(self):
            yield msg_buffer

    @property
    def received_msgs_count(self) -> int:
        return sum(self.received_msgs.values())

    @property
    def uptime(self) -> str:
        return '%d:%02d:%02d:%02d' % time_since(self.start_time)

    def add_subscriber(self, subscriber: 'PeerSubscriber') -> None:
        self._subscribers.append(subscriber)

    def remove_subscriber(self, subscriber: 'PeerSubscriber') -> None:
        if subscriber in self._subscribers:
            self._subscribers.remove(subscriber)

    async def do_sub_proto_handshake(self) -> None:
        """Perform the handshake for the sub-protocol agreed with the remote peer.

        Raises HandshakeFailure if the handshake is not successful.
        """
        await self.send_sub_proto_handshake()
        cmd, msg = await self.read_msg()
        if isinstance(cmd, Ping):
            # Parity sends a Ping before the sub-proto handshake, so respond to that and read the
            # next one, which hopefully will be the actual handshake.
            self.base_protocol.send_pong()
            cmd, msg = await self.read_msg()
        if isinstance(cmd, Disconnect):
            msg = cast(Dict[str, Any], msg)
            # Peers sometimes send a disconnect msg before they send the sub-proto handshake.
            raise HandshakeFailure(
                f"{self} disconnected before completing sub-proto handshake: {msg['reason_name']}"
            )
        await self.process_sub_proto_handshake(cmd, msg)
        self.logger.debug("Finished %s handshake with %s", self.sub_proto, self.remote)

    async def do_p2p_handshake(self) -> None:
        """Perform the handshake for the P2P base protocol.

        Raises HandshakeFailure if the handshake is not successful.
        """
        self.base_protocol.send_handshake()

        try:
            cmd, msg = await self.read_msg()
        except rlp.DecodingError:
            raise HandshakeFailure("Got invalid rlp data during handshake")
        except MalformedMessage as e:
            raise HandshakeFailure("Got malformed message during handshake") from e

        if isinstance(cmd, Disconnect):
            msg = cast(Dict[str, Any], msg)
            # Peers sometimes send a disconnect msg before they send the initial P2P handshake.
            raise HandshakeFailure(
                f"{self} disconnected before completing sub-proto handshake: {msg['reason_name']}"
            )
        await self.process_p2p_handshake(cmd, msg)

    @property
    def capabilities(self) -> List[Tuple[str, int]]:
        return [(klass.name, klass.version) for klass in self._supported_sub_protocols]

    def get_protocol_command_for(self, msg: bytes) -> protocol.Command:
        """Return the Command corresponding to the cmd_id encoded in the given msg."""
        cmd_id = get_devp2p_cmd_id(msg)
        self.logger.trace("Got msg with cmd_id: %s", cmd_id)
        if cmd_id < self.base_protocol.cmd_length:
            return self.base_protocol.cmd_by_id[cmd_id]
        elif cmd_id < self.sub_proto.cmd_id_offset + self.sub_proto.cmd_length:
            return self.sub_proto.cmd_by_id[cmd_id]
        else:
            raise UnknownProtocolCommand(f"No protocol found for cmd_id {cmd_id}")

    async def read(self, n: int) -> bytes:
        self.logger.trace("Waiting for %s bytes from %s", n, self.remote)
        try:
            return await self.wait(self.reader.readexactly(n), timeout=self.conn_idle_timeout)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError) as e:
            raise PeerConnectionLost(repr(e))

    async def boot(self) -> None:
        try:
            await self._boot()
        except OperationCancelled:
            # If a cancellation happens during boot we silence it and exit
            # without setting the `booted` event.
            # TODO: ensure that the OperationCancelled is coming from this
            # token's ancestry
            return
        else:
            self.booted.set()

    async def _boot(self) -> None:
        """
        Hook for doing any operations that need to happen *after* the service
        has started but before the peer should be considered *ready*.
        """
        pass

    def close(self) -> None:
        """Close this peer's reader/writer streams.

        This will cause the peer to stop in case it is running.

        If the streams have already been closed, do nothing.
        """
        if self.reader.at_eof():
            return
        self.reader.feed_eof()
        self.writer.close()

    @property
    def is_closing(self) -> bool:
        return self.writer.transport.is_closing()

    async def _cleanup(self) -> None:
        self.close()

    async def _run(self) -> None:
        # The `boot` task runs in the background to allow access to the full peer API
        self.run_task(self.boot())

        while self.is_operational:
            try:
                cmd, msg = await self.read_msg()
            except (PeerConnectionLost, TimeoutError) as err:
                self.logger.debug(
                    "%s stopped responding (%r), disconnecting", self.remote, err)
                return
            except DecryptionError as err:
                self.logger.warn(
                    "Unable to decrypt message from %s, disconnecting: %r",
                    self, err,
                    exc_info=True,
                )
                return
            except MalformedMessage as err:
                await self.disconnect(DisconnectReason.bad_protocol)
                return

            try:
                self.process_msg(cmd, msg)
            except RemoteDisconnected as e:
                self.logger.debug("%s disconnected: %s", self, e)
                return

    async def read_msg(self) -> Tuple[protocol.Command, protocol.PayloadType]:
        header_data = await self.read(HEADER_LEN + MAC_LEN)
        header = self.decrypt_header(header_data)
        frame_size = self.get_frame_size(header)
        # The frame_size specified in the header does not include the padding to 16-byte boundary,
        # so need to do this here to ensure we read all the frame's data.
        read_size = roundup_16(frame_size)
        frame_data = await self.read(read_size + MAC_LEN)
        msg = self.decrypt_body(frame_data, frame_size)
        cmd = self.get_protocol_command_for(msg)
        # NOTE: This used to be a bottleneck but it doesn't seem to be so anymore. If we notice
        # too much time is being spent on this again, we need to consider running this in a
        # ProcessPoolExecutor(). Need to make sure we don't use all CPUs in the machine for that,
        # though, otherwise asyncio's event loop can't run and we can't keep up with other peers.
        try:
            decoded_msg = cast(Dict[str, Any], cmd.decode(msg))
        except MalformedMessage as err:
            self.logger.debug(
                "Malformed message from peer %s: CMD:%s Error: %r",
                self, type(cmd).__name__, err,
            )
            raise
        else:
            self.logger.trace("Successfully decoded %s msg: %s", cmd, decoded_msg)
            self.received_msgs[cmd] += 1
            return cmd, decoded_msg

    def handle_p2p_msg(self, cmd: protocol.Command, msg: protocol.PayloadType) -> None:
        """Handle the base protocol (P2P) messages."""
        if isinstance(cmd, Disconnect):
            msg = cast(Dict[str, Any], msg)
            raise RemoteDisconnected(msg['reason_name'])
        elif isinstance(cmd, Ping):
            self.base_protocol.send_pong()
        elif isinstance(cmd, Pong):
            # Currently we don't do anything when we get a pong, but eventually we should
            # update the last time we heard from a peer in our DB (which doesn't exist yet).
            pass
        else:
            raise UnexpectedMessage(f"Unexpected msg: {cmd} ({msg})")

    def handle_sub_proto_msg(self, cmd: protocol.Command, msg: protocol.PayloadType) -> None:
        cmd_type = type(cmd)

        if self._subscribers:
            was_added = tuple(
                subscriber.add_msg(PeerMessage(self, cmd, msg))
                for subscriber
                in self._subscribers
            )
            if not any(was_added):
                self.logger.warn(
                    "Peer %s has no subscribers for msg type %s",
                    self,
                    cmd_type.__name__,
                )
        else:
            self.logger.warn("Peer %s has no subscribers, discarding %s msg", self, cmd)

    def process_msg(self, cmd: protocol.Command, msg: protocol.PayloadType) -> None:
        if cmd.is_base_protocol:
            self.handle_p2p_msg(cmd, msg)
        else:
            self.handle_sub_proto_msg(cmd, msg)

    async def process_p2p_handshake(
            self, cmd: protocol.Command, msg: protocol.PayloadType) -> None:
        msg = cast(Dict[str, Any], msg)
        if not isinstance(cmd, Hello):
            await self.disconnect(DisconnectReason.bad_protocol)
            raise HandshakeFailure(f"Expected a Hello msg, got {cmd}, disconnecting")
        remote_capabilities = msg['capabilities']
        try:
            self.sub_proto = self.select_sub_protocol(remote_capabilities)
        except NoMatchingPeerCapabilities:
            await self.disconnect(DisconnectReason.useless_peer)
            raise HandshakeFailure(
                f"No matching capabilities between us ({self.capabilities}) and {self.remote} "
                f"({remote_capabilities}), disconnecting"
            )
        self.logger.debug(
            "Finished P2P handshake with %s, using sub-protocol %s",
            self.remote, self.sub_proto)

    def encrypt(self, header: bytes, frame: bytes) -> bytes:
        if len(header) != HEADER_LEN:
            raise ValueError(f"Unexpected header length: {len(header)}")

        header_ciphertext = self.aes_enc.update(header)
        mac_secret = self.egress_mac.digest()[:HEADER_LEN]
        self.egress_mac.update(sxor(self.mac_enc(mac_secret), header_ciphertext))
        header_mac = self.egress_mac.digest()[:HEADER_LEN]

        frame_ciphertext = self.aes_enc.update(frame)
        self.egress_mac.update(frame_ciphertext)
        fmac_seed = self.egress_mac.digest()[:HEADER_LEN]

        mac_secret = self.egress_mac.digest()[:HEADER_LEN]
        self.egress_mac.update(sxor(self.mac_enc(mac_secret), fmac_seed))
        frame_mac = self.egress_mac.digest()[:HEADER_LEN]

        return header_ciphertext + header_mac + frame_ciphertext + frame_mac

    def decrypt_header(self, data: bytes) -> bytes:
        if len(data) != HEADER_LEN + MAC_LEN:
            raise ValueError(
                f"Unexpected header length: {len(data)}, expected {HEADER_LEN} + {MAC_LEN}"
            )

        header_ciphertext = data[:HEADER_LEN]
        header_mac = data[HEADER_LEN:]
        mac_secret = self.ingress_mac.digest()[:HEADER_LEN]
        aes = self.mac_enc(mac_secret)[:HEADER_LEN]
        self.ingress_mac.update(sxor(aes, header_ciphertext))
        expected_header_mac = self.ingress_mac.digest()[:HEADER_LEN]
        if not bytes_eq(expected_header_mac, header_mac):
            raise DecryptionError(
                f'Invalid header mac: expected {expected_header_mac}, got {header_mac}'
            )
        return self.aes_dec.update(header_ciphertext)

    def decrypt_body(self, data: bytes, body_size: int) -> bytes:
        read_size = roundup_16(body_size)
        if len(data) < read_size + MAC_LEN:
            raise ValueError(
                f'Insufficient body length; Got {len(data)}, wanted {read_size} + {MAC_LEN}'
            )

        frame_ciphertext = data[:read_size]
        frame_mac = data[read_size:read_size + MAC_LEN]

        self.ingress_mac.update(frame_ciphertext)
        fmac_seed = self.ingress_mac.digest()[:MAC_LEN]
        self.ingress_mac.update(sxor(self.mac_enc(fmac_seed), fmac_seed))
        expected_frame_mac = self.ingress_mac.digest()[:MAC_LEN]
        if not bytes_eq(expected_frame_mac, frame_mac):
            raise DecryptionError(
                f'Invalid frame mac: expected {expected_frame_mac}, got {frame_mac}'
            )
        return self.aes_dec.update(frame_ciphertext)[:body_size]

    def get_frame_size(self, header: bytes) -> int:
        # The frame size is encoded in the header as a 3-byte int, so before we unpack we need
        # to prefix it with an extra byte.
        encoded_size = b'\x00' + header[:3]
        (size,) = struct.unpack(b'>I', encoded_size)
        return size

    def send(self, header: bytes, body: bytes) -> None:
        cmd_id = rlp.decode(body[:1], sedes=rlp.sedes.big_endian_int)
        self.logger.trace("Sending msg with cmd id %d to %s", cmd_id, self)
        if self.is_closing:
            self.logger.error(
                "Attempted to send msg with cmd id %d to disconnected peer %s", cmd_id, self)
            return
        self.writer.write(self.encrypt(header, body))

    async def disconnect(self, reason: DisconnectReason) -> None:
        """Send a disconnect msg to the remote node and stop this Peer.

        Also awaits for self.cancel() to ensure any pending tasks are cleaned up.

        :param reason: An item from the DisconnectReason enum.
        """
        if not isinstance(reason, DisconnectReason):
            raise ValueError(
                f"Reason must be an item of DisconnectReason, got {reason}"
            )
        self.logger.debug("Disconnecting from remote peer; reason: %s", reason.name)
        self.base_protocol.send_disconnect(reason.value)
        self.close()
        if self.is_operational:
            await self.cancel()

    def select_sub_protocol(self, remote_capabilities: List[Tuple[bytes, int]]
                            ) -> protocol.Protocol:
        """Select the sub-protocol to use when talking to the remote.

        Find the highest version of our supported sub-protocols that is also supported by the
        remote and stores an instance of it (with the appropriate cmd_id offset) in
        self.sub_proto.

        Raises NoMatchingPeerCapabilities if none of our supported protocols match one of the
        remote's protocols.
        """
        matching_capabilities = set(self.capabilities).intersection(remote_capabilities)
        if not matching_capabilities:
            raise NoMatchingPeerCapabilities()
        _, highest_matching_version = max(matching_capabilities, key=operator.itemgetter(1))
        offset = self.base_protocol.cmd_length
        for proto_class in self._supported_sub_protocols:
            if proto_class.version == highest_matching_version:
                return proto_class(self, offset)
        raise NoMatchingPeerCapabilities()

    def __str__(self) -> str:
        return f"{self.__class__.__name__} {self.remote}"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__} {self.remote!r}"

    def __hash__(self) -> int:
        return hash(self.remote)


class PeerMessage(NamedTuple):
    peer: BasePeer
    command: protocol.Command
    payload: protocol.PayloadType


class PeerSubscriber(ABC):
    _msg_queue: 'asyncio.Queue[PeerMessage]' = None

    @property
    @abstractmethod
    def subscription_msg_types(self) -> Set[Type[protocol.Command]]:
        """
        The `p2p.protocol.Command` types that this class subscribes to.  Any
        command which is not in this set will not be passed to this subscriber.

        The base command class `p2p.protocol.Command` can be used to enable
        **all** command types.

        .. note: This API only applies to sub-protocol commands.  Base protocol
        commands are handled exclusively at the peer level and cannot be
        consumed with this API.
        """
        pass

    @functools.lru_cache(maxsize=64)
    def is_subscription_command(self, cmd_type: Type[protocol.Command]) -> bool:
        return bool(self.subscription_msg_types.intersection(
            {cmd_type, protocol.Command}
        ))

    @property
    @abstractmethod
    def msg_queue_maxsize(self) -> int:
        pass

    def register_peer(self, peer: BasePeer) -> None:
        """
        Notify about each registered peer in the :class:`~p2p.peer.PeerPool`. Is called upon
        subscription for each :class:`~p2p.peer.BasePeer` that exists in the pool at that time and
        then for each :class:`~p2p.peer.BasePeer` that joins the pool later on.

        A :class:`~p2p.peer.PeerSubscriber` that wants to act upon peer registration needs to
        overwrite this method to provide an implementation.
        """
        pass

    def deregister_peer(self, peer: BasePeer) -> None:
        """Called when a peer is removed from the pool."""
        pass

    @property
    def msg_queue(self) -> 'asyncio.Queue[PeerMessage]':
        if self._msg_queue is None:
            self._msg_queue = asyncio.Queue(maxsize=self.msg_queue_maxsize)
        return self._msg_queue

    @property
    def queue_size(self) -> int:
        return self.msg_queue.qsize()

    def add_msg(self, msg: PeerMessage) -> bool:
        peer, cmd, _ = msg

        if not self.is_subscription_command(type(cmd)):
            if hasattr(self, 'logger'):
                self.logger.trace(  # type: ignore
                    "Discarding %s msg from %s; not subscribed to msg type; "
                    "subscriptions: %s",
                    cmd, peer, self.subscription_msg_types,
                )
            return False

        try:
            if hasattr(self, 'logger'):
                self.logger.trace(  # type: ignore
                    "Adding %s msg from %s to queue; queue_size=%d", cmd, peer, self.queue_size)
            self.msg_queue.put_nowait(msg)
            return True
        except asyncio.queues.QueueFull:
            if hasattr(self, 'logger'):
                self.logger.warn(  # type: ignore
                    "%s msg queue is full; discarding %s msg from %s",
                    self.__class__.__name__, cmd, peer)
            return False

    @contextlib.contextmanager
    def subscribe(self, peer_pool: 'PeerPool') -> Iterator[None]:
        peer_pool.subscribe(self)
        try:
            yield
        finally:
            peer_pool.unsubscribe(self)

    @contextlib.contextmanager
    def subscribe_peer(self, peer: BasePeer) -> Iterator[None]:
        peer.add_subscriber(self)
        try:
            yield
        finally:
            peer.remove_subscriber(self)


class MsgBuffer(PeerSubscriber):
    logger = logging.getLogger('p2p.peer.MsgBuffer')
    msg_queue_maxsize = 500
    subscription_msg_types = {protocol.Command}

    @to_tuple
    def get_messages(self) -> Iterator[PeerMessage]:
        while not self.msg_queue.empty():
            yield self.msg_queue.get_nowait()


class BasePeerPool(BaseService, AsyncIterable[TPeer]):
    """
    PeerPool maintains connections to up-to max_peers on a given network.
    """
    def __init__(self,
                 privkey: datatypes.PrivateKey,
                 max_peers: int = DEFAULT_MAX_PEERS,
                 token: CancelToken = None,
                 ) -> None:
        super().__init__(token)
        self.privkey = privkey
        self.max_peers = max_peers
        self.connected_nodes: Dict[Node, TPeer] = {}
        self._subscribers: List[PeerSubscriber] = []

    @property
    @abstractmethod
    def peer_class(self) -> Type[TPeer]:
        pass

    def mk_peer(self,
                remote: Node,
                privkey: datatypes.PrivateKey,
                reader: asyncio.StreamReader,
                writer: asyncio.StreamWriter,
                aes_secret: bytes,
                mac_secret: bytes,
                egress_mac: sha3.keccak_256,
                ingress_mac: sha3.keccak_256,
                inbound: bool = False) -> TPeer:
        """
        Hook to create a instance of the `peer_class` for this pool.
        """
        return self.peer_class(
            remote=remote,
            privkey=privkey,
            reader=reader,
            writer=writer,
            aes_secret=aes_secret,
            mac_secret=mac_secret,
            egress_mac=egress_mac,
            ingress_mac=ingress_mac,
            inbound=inbound,
            token=self.cancel_token,
        )

    def __len__(self) -> int:
        return len(self.connected_nodes)

    @property
    def is_full(self) -> bool:
        return len(self) >= self.max_peers

    def is_valid_connection_candidate(self, candidate: Node) -> bool:
        # connect to no more then 2 nodes with the same IP
        nodes_by_ip = groupby(
            operator.attrgetter('remote.address.ip'),
            self.connected_nodes.values(),
        )
        matching_ip_nodes = nodes_by_ip.get(candidate.address.ip, [])
        return len(matching_ip_nodes) <= 2

    def subscribe(self, subscriber: PeerSubscriber) -> None:
        self._subscribers.append(subscriber)
        for peer in self.connected_nodes.values():
            subscriber.register_peer(peer)
            peer.add_subscriber(subscriber)

    def unsubscribe(self, subscriber: PeerSubscriber) -> None:
        if subscriber in self._subscribers:
            self._subscribers.remove(subscriber)
        for peer in self.connected_nodes.values():
            peer.remove_subscriber(subscriber)

    async def start_peer(self, peer: TPeer) -> None:
        self.run_child_service(peer)
        await self.wait(peer.events.started.wait(), timeout=1)

        # We collect any messages the peer may receive during boot so that once
        # boot has completed we can pass them onto subscribers.
        with peer.collect_sub_proto_messages() as buffer:
            await self.wait(peer.booted.wait())
        self._add_peer(peer, buffer.get_messages())

    def _add_peer(self,
                  peer: TPeer,
                  msgs: Tuple[PeerMessage, ...]) -> None:
        """Add the given peer to the pool.

        Appart from adding it to our list of connected nodes and adding each of our subscriber's
        to the peer, we also add the given messages to our subscriber's queues.
        """
        self.logger.info('Adding %s to pool', peer)
        self.connected_nodes[peer.remote] = peer
        peer.add_finished_callback(self._peer_finished)
        for subscriber in self._subscribers:
            subscriber.register_peer(peer)
            peer.add_subscriber(subscriber)
            for msg in msgs:
                subscriber.add_msg(msg)

    async def _run(self) -> None:
        # FIXME: PeerPool should probably no longer be a BaseService, but for now we're keeping it
        # so in order to ensure we cancel all peers when we terminate.
        self.run_task(self._periodically_report_stats())
        await self.cancel_token.wait()

    async def stop_all_peers(self) -> None:
        self.logger.info("Stopping all peers ...")
        peers = self.connected_nodes.values()
        await asyncio.gather(*[
            peer.disconnect(DisconnectReason.client_quitting) for peer in peers if peer.is_running
        ])

    async def _cleanup(self) -> None:
        await self.stop_all_peers()

    async def connect(self, remote: Node) -> TPeer:
        """
        Connect to the given remote and return a Peer instance when successful.
        Returns None if the remote is unreachable, times out or is useless.
        """
        if remote in self.connected_nodes:
            self.logger.debug("Skipping %s; already connected to it", remote)
            return None
        expected_exceptions = (
            HandshakeFailure,
            PeerConnectionLost,
            TimeoutError,
            UnreachablePeer,
        )
        try:
            self.logger.trace("Connecting to %s...", remote)
            # We use self.wait() as well as passing our CancelToken to handshake() as a workaround
            # for https://github.com/ethereum/py-evm/issues/670.
            peer = await self.wait(handshake(remote, self.privkey, self.mk_peer, self.cancel_token))

            return peer
        except OperationCancelled:
            # Pass it on to instruct our main loop to stop.
            raise
        except BadAckMessage:
            # This is kept separate from the `expected_exceptions` to be sure that we aren't
            # silencing an error in our authentication code.
            self.logger.error('Got bad auth ack from %r', remote)
            # dump the full stacktrace in the debug logs
            self.logger.debug('Got bad auth ack from %r', remote, exc_info=True)
        except MalformedMessage:
            # This is kept separate from the `expected_exceptions` to be sure that we aren't
            # silencing an error in how we decode messages during handshake.
            self.logger.error('Got malformed response from %r during handshake', remote)
            # dump the full stacktrace in the debug logs
            self.logger.debug('Got malformed response from %r', remote, exc_info=True)
        except expected_exceptions as e:
            self.logger.debug("Could not complete handshake with %r: %s", remote, repr(e))
        except Exception:
            self.logger.exception("Unexpected error during auth/p2p handshake with %r", remote)
        return None

    async def connect_to_nodes(self, nodes: Iterator[Node]) -> None:
        for node in nodes:
            if self.is_full:
                return

            # TODO: Consider changing connect() to raise an exception instead of returning None,
            # as discussed in
            # https://github.com/ethereum/py-evm/pull/139#discussion_r152067425
            peer = await self.connect(node)
            if peer is not None:
                await self.start_peer(peer)

    def _peer_finished(self, peer: BaseService) -> None:
        """Remove the given peer from our list of connected nodes.
        This is passed as a callback to be called when a peer finishes.
        """
        peer = cast(TPeer, peer)
        if peer.remote in self.connected_nodes:
            self.logger.info("%s finished, removing from pool", peer)
            self.connected_nodes.pop(peer.remote)
        else:
            self.logger.warn(
                "%s finished but was not found in connected_nodes (%s)", peer, self.connected_nodes)
        for subscriber in self._subscribers:
            subscriber.deregister_peer(peer)

    def __aiter__(self) -> AsyncIterator[TPeer]:
        return ConnectedPeersIterator(tuple(self.connected_nodes.values()))

    _report_interval = 60

    async def _periodically_report_stats(self) -> None:
        while self.is_operational:
            inbound_peers = len(
                [peer for peer in self.connected_nodes.values() if peer.inbound])
            self.logger.info("Connected peers: %d inbound, %d outbound",
                             inbound_peers, (len(self.connected_nodes) - inbound_peers))
            subscribers = len(self._subscribers)
            if subscribers:
                longest_queue = max(
                    self._subscribers, key=operator.attrgetter('queue_size'))
                self.logger.info(
                    "Peer subscribers: %d, longest queue: %s(%d)",
                    subscribers, longest_queue.__class__.__name__, longest_queue.queue_size)

            self.logger.debug("== Peer details == ")
            for peer in self.connected_nodes.values():
                if not peer.is_running:
                    self.logger.warning(
                        "%s is no longer alive but has not been removed from pool", peer)
                    continue
                most_received_type, count = max(
                    peer.received_msgs.items(), key=operator.itemgetter(1))
                self.logger.debug(
                    "%s: uptime=%s, received_msgs=%d, most_received=%s(%d)",
                    peer, peer.uptime, peer.received_msgs_count,
                    most_received_type, count)
                for line in peer.get_extra_stats():
                    self.logger.debug("    %s", line)
            self.logger.debug("== End peer details == ")
            try:
                await self.sleep(self._report_interval)
            except OperationCancelled:
                break


class ConnectedPeersIterator(AsyncIterator[TPeer]):

    def __init__(self, peers: Tuple[TPeer, ...]) -> None:
        self.iter = iter(peers)

    async def __anext__(self) -> TPeer:
        while True:
            # Yield control to ensure we process any disconnection requests from peers. Otherwise
            # we could return peers that should have been disconnected already.
            await asyncio.sleep(0)
            try:
                peer = next(self.iter)
                if not peer.is_closing:
                    return peer
            except StopIteration:
                raise StopAsyncIteration
