from typing import NamedTuple

from eth.db.backends.base import BaseAtomicDB

from trinity.config import TrinityConfig
from trinity.db.chain import AsyncChainDB
from trinity.db.header import AsyncHeaderDB
from trinity.initialization import (
    is_database_initialized,
    initialize_database,
)


class DatabaseConnection(NamedTuple):
    base_db: BaseAtomicDB
    chaindb: AsyncChainDB
    headerdb: AsyncHeaderDB


def get_database_connection(trinity_config: TrinityConfig) -> DatabaseConnection:
    base_db = trinity_config.db_class(db_path=trinity_config.database_dir)
    chaindb = AsyncChainDB(base_db)
    headerdb = AsyncHeaderDB(base_db)

    if not is_database_initialized(chaindb):
        initialize_database(trinity_config, chaindb)

    return DatabaseConnection(
        base_db=base_db,
        chaindb=chaindb,
        headerdb=headerdb,
    )
