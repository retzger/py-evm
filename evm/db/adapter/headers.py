from .base import (
    BaseAdapter,
)


class HeaderDB(BaseAdapter):
    #
    # Block Header API
    #
    def get_block_header_by_hash(self, block_hash):
        """
        Returns the requested block header as specified by block hash.

        Raises BlockNotFound if it is not present in the db.
        """
        raise NotImplementedError("ChainDB classes must implement this method")

    def header_exists(self, block_hash):
        """
        Returns True if the header with the given block hash is in our DB.
        """
        raise NotImplementedError("ChainDB classes must implement this method")

    def persist_header_to_db(self, header):
        """
        :returns: iterable of headers newly on the canonical chain
        """
        raise NotImplementedError("ChainDB classes must implement this method")
