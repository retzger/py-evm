from evm.utils.datatypes import (
    Configurable,
)


class BaseAdapter(Configurable):
    db = None

    def __init__(self, db):
        self.db = db

    #
    # Common API
    #
    def exists(self, key):
        return key in self.db
