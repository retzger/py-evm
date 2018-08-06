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

from eth_utils import encode_hex

from eth.db.trie import make_trie_root_and_nodes
from eth.rlp.headers import BlockHeader
from eth.rlp.receipts import Receipt

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


class ReceiptsRequest(BaseRequest):
    def __init__(self, headers: Tuple[BlockHeader, ...]) -> None:
        self.headers = headers

    @property
    def block_hashes(self) -> Tuple[Hash32, ...]:
        return tuple(header.hash for header in self.headers)

    def validate_response(self, response: Any) -> None:
        """
        Core `Request` API used for validation.
        """
        if not isinstance(response, tuple):
            raise ValidationError(
                "Response to `HeaderRequest` must be a tuple. Got: {0}".format(
                    type(response)
                )
            )
        elif not all(isinstance(item, tuple) for item in response):
            raise ValidationError(
                "Response to `HeaderRequest` must be a tuple of tuples. "
            )

        for item in response:
            if not all(isinstance(value, Receipt) for value in item):
                raise ValidationError(
                    "Response must be a tuple of tuples of `BlockHeader` objects. Got: ")
        return self.validate_receipts(cast(Tuple[Tuple[Receipt, ...], ...], response))

    def validate_receipts(self, receipts_by_block: Tuple[Tuple[Receipt, ...], ...]) -> None:
        if not receipts_by_block:
            # empty response is always valid.
            return

        expected_receipt_roots = set(header.receipt_root for header in self.headers)

        for receipts in receipts_by_block:
            # TODO: We need to run this in an executor as it is quite expensive
            receipt_root, _ = make_trie_root_and_nodes(receipts)

            if receipt_root not in expected_receipt_roots:
                raise ValidationError(
                    "Got unexpected receipt root: %s".format(encode_hex(receipt_root))
                )
