from typing import (
    Tuple,
    Type,
    TYPE_CHECKING,
)

from eth_typing import (
    BlockIdentifier,
    Hash32,
)

from eth.rlp.headers import BlockHeader

from p2p.protocol import (
    Command,
)

from trinity.protocol.common.managers import (
    BaseRequestManager,
)

from .commands import (
    BlockHeaders,
    NodeData,
)
from .requests import (
    HeaderRequest,
    NodeDataRequest,
)

if TYPE_CHECKING:
    from .peer import ETHPeer  # noqa: F401


BaseGetBlockHeadersRequestManager = BaseRequestManager[
    'ETHPeer',
    HeaderRequest,
    Tuple[BlockHeader, ...],
    Tuple[BlockHeader, ...],
]


class GetBlockHeadersRequestManager(BaseGetBlockHeadersRequestManager):
    msg_queue_maxsize = 100

    _response_msg_type: Type[Command] = BlockHeaders

    # All `RequestManager` classes are expected to implement the `__call__`
    # method, including changing the function signature, thus the
    # `# type: ignore` here is both expected and required.
    async def __call__(self,  # type: ignore
                       block_number_or_hash: BlockIdentifier,
                       max_headers: int = None,
                       skip: int = 0,
                       reverse: bool = True,
                       timeout: int = None) -> Tuple[BlockHeader, ...]:
        request = HeaderRequest(
            block_number_or_hash,
            max_headers,
            skip,
            reverse,
        )
        return await self._request_and_wait(request, timeout)

    def _send_sub_proto_request(self, request: HeaderRequest) -> None:
        self._peer.sub_proto.send_get_block_headers(request)

    def _normalize_response(self, response: Tuple[BlockHeader, ...]) -> Tuple[BlockHeader, ...]:
        return response


BaseGetNodeDataRequestManager = BaseRequestManager[
    'ETHPeer',
    NodeDataRequest,
    Tuple[bytes, ...],
    Tuple[bytes, ...],
]


class GetNodeDataRequestManager(BaseGetNodeDataRequestManager):
    msg_queue_maxsize = 100

    _response_msg_type: Type[Command] = NodeData

    async def __call__(self,  # type: ignore
                       node_hashes: Tuple[Hash32, ...],
                       timeout: int = None) -> Tuple[bytes, ...]:
        request = NodeDataRequest(node_hashes)
        return await self._request_and_wait(request, timeout)

    def _send_sub_proto_request(self, request: NodeDataRequest) -> None:
        self._peer.sub_proto.send_get_node_data(request)

    def _normalize_response(self, response: Tuple[bytes, ...]) -> Tuple[bytes, ...]:
        return response
