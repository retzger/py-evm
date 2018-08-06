from typing import (
    Any,
    cast,
    Tuple,
)

from eth_typing import (
    BlockIdentifier,
    Hash32,
)

from eth_hash.auto import keccak

from eth.rlp.headers import BlockHeader

from p2p.exceptions import ValidationError

from trinity.protocol.common.requests import (
    BaseHeaderRequest,
    BaseRequest,
)

from . import constants


class HeaderRequest(BaseHeaderRequest):
    @property
    def max_size(self) -> int:
        return constants.MAX_HEADERS_FETCH

    def __init__(self,
                 block_number_or_hash: BlockIdentifier,
                 max_headers: int,
                 skip: int,
                 reverse: bool) -> None:
        self.block_number_or_hash = block_number_or_hash
        self.max_headers = max_headers
        self.skip = skip
        self.reverse = reverse

    def validate_response(self, response: Any) -> None:
        """
        Core `Request` API used for validation.
        """
        if not isinstance(response, tuple):
            raise ValidationError("Response to `HeaderRequest` must be a tuple")
        elif not all(isinstance(item, BlockHeader) for item in response):
            raise ValidationError("Response must be a tuple of `BlockHeader` objects")

        return self.validate_headers(cast(Tuple[BlockHeader, ...], response))


class NodeDataRequest(BaseRequest):
    @property
    def max_size(self) -> int:
        return constants.MAX_STATE_FETCH

    def __init__(self, node_hashes: Tuple[Hash32, ...]) -> None:
        self.node_hashes = node_hashes

    def validate_response(self, response: Any) -> None:
        """
        Core `Request` API used for validation.
        """
        if not isinstance(response, tuple):
            raise ValidationError("Response to `HeaderRequest` must be a tuple")
        elif not all(isinstance(item, bytes) for item in response):
            raise ValidationError("Response must be a tuple of `BlockHeader` objects")
        return self.validate_nodes(cast(Tuple[bytes, ...], response))

    def validate_nodes(self, nodes: Tuple[bytes, ...]) -> None:
        if not nodes:
            # an empty response is always valid
            return

        # TODO: move to executor since keccak is expensive
        expected_node_keys = set(self.node_hashes)
        actual_node_keys = set(map(keccak, nodes))

        if len(actual_node_keys) != len(nodes):
            # TODO: is this something that needs to be enforced.
            raise ValidationError("Response may not contain duplicate nodes")

        unexpected_keys = actual_node_keys.difference(expected_node_keys)

        if unexpected_keys:
            raise ValidationError(
                "Response contains {0} unexpected nodes".format(len(unexpected_keys))
            )
