import abc
from typing import Optional

class BaseDNS(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    async def add_record(
        self,
        hostname: str,
        domain: str,
        record_type: str,
        record_value: str,
    ) -> None:
        raise NotImplementedError()
    
    @abc.abstractmethod
    async def remove_record(
        self,
        hostname: str,
        domain: str,
        record_type: str,
    ) -> None:
        raise NotImplementedError()
    
    @abc.abstractmethod
    async def modify_record(
        self,
        hostname: str,
        domain: str,
        record_type: str,
        record_value: str,
    ) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    async def get_record(
        self,
        hostname: str,
        domain: str,
        record_type: str,
    ) -> Optional[str]:
        raise NotImplementedError()
    
    @abc.abstractmethod
    async def list_records(
        self,
        domain: str,
    ) -> list:
        raise NotImplementedError()
    