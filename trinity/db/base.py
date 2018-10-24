from abc import abstractmethod
from eth.db.backends.base import BaseDB


class AsyncBaseDB(BaseDB):
    @abstractmethod
    async def coro_set(self, key: bytes, value: bytes) -> None:
        pass

    @abstractmethod
    async def coro_exists(self, key: bytes) -> bool:
        pass
