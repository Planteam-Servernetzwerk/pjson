import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typing import Literal, Optional, Type, TypeVar, Union, overload, Dict, Any, List
import requests
import psql
from requests.exceptions import SSLError


JSONType = TypeVar("JSONType", bound="JSONObject")


class JSONObject:
    FQ_HOST: str = ...                               # type: ignore
    TABLE_NAME: str = ...                            # type: ignore
    SUFFIX_GET: str = "/get"
    SUFFIX_GETS: str = "/gets"

    KEYS: list[str] = ...                            # type: ignore
    PRIMARY_KEY: str = ...                           # type: ignore

    AUTH_METHOD: Literal["challenge", "http"] = ...  # type: ignore

    HTTP_USERNAME: str = ...                         # type: ignore
    HTTP_PASSWORD: str = ...                         # type: ignore
    HTTP_LOGIN_ENDPOINT: str = ...                   # type: ignore

    SSH_PRIVATE_KEY: Ed25519PrivateKey = ...         # type: ignore
    SSH_CHALLENGE_START_ENDPOINT: str = ...          # type: ignore
    SSH_CHALLENGE_COMPLETE_ENDPOINT: str = ...       # type: ignore

    tls = False
    session = None

    @classmethod
    def get_host(cls) -> str:
        return ("https://" if cls.tls else "http://") + cls.FQ_HOST

    @classmethod
    def urlfor(cls, endpoint: str) -> str:
        return cls.get_host() + ('' if endpoint.startswith('/') else '/') + endpoint

    @classmethod
    def s(cls) -> requests.Session:
        if cls.session is None:
            cls.session = requests.Session()
            # probe for tls
            cls.tls = True
            try:
                cls.session.get(cls.urlfor("/"))
            except SSLError:
                cls.tls = False

            if cls.AUTH_METHOD == "challenge":
                raise NotImplementedError()
            elif cls.AUTH_METHOD == "http":
                assert cls.HTTP_USERNAME and cls.HTTP_PASSWORD and cls.HTTP_LOGIN_ENDPOINT
                cls.session = requests.Session()
                auth_response = cls.session.post(
                    cls.urlfor(cls.HTTP_LOGIN_ENDPOINT),
                    data={"username": cls.HTTP_USERNAME, "password": cls.HTTP_PASSWORD}
                )
                if auth_response.status_code == 401:
                    raise ConnectionError("Invalid credentials.")
                elif auth_response.status_code != 200:
                    raise ConnectionError(f"Authentication failed. Host returned {auth_response.status_code} {auth_response.reason}.")
        return cls.session

    @classmethod
    def reauth(cls) -> requests.Session:
        cls.session = None
        return cls.s()

    @classmethod
    def gets(cls: Type[JSONType], **kwargs) -> list[JSONType]:
        resp = cls.s().get(
            cls.urlfor(cls.SUFFIX_GETS),
            data=kwargs
        )

        if resp.status_code != 200:
            raise ConnectionError(f"Host returned {resp.status_code} {resp.reason}.")

        return [cls(*[getattr(obj, k) for k in cls.KEYS]) for obj in resp.json()]

    @classmethod
    def get(cls: Type[JSONType], **kwargs) -> JSONType:
        resp = cls.s().get(
            cls.urlfor(cls.SUFFIX_GET),
            data=kwargs
        )

        if resp.status_code != 200:
            raise ConnectionError(f"Host returned {resp.status_code} {resp.reason}.")

        return cls(*[getattr(resp, k) for k in cls.KEYS])

    def argsdict(self) -> dict:
        return {k: getattr(self, k) for k in self.KEYS}

    @classmethod
    def from_sqlobject(cls: Type[JSONType], obj: psql.SQLObject, custom_keys: Optional[List] = None) -> JSONType:
        keys = cls.KEYS if not custom_keys else custom_keys
        return cls(**{k: getattr(obj, k) for k in keys})

    @classmethod
    def gets_from_sql(cls: Type[JSONType], c: Type[psql.SQLType], custom_keys: Optional[List] = None, **kwargs) -> list[JSONType]:
        resp = c.gets(**kwargs)
        return [cls.from_sqlobject(obj, custom_keys) for obj in resp]

    @classmethod
    def get_from_sql(cls: Type[JSONType], c: Type[psql.SQLType], custom_keys: Optional[List] = None, primary_value = None, **kwargs) -> JSONType:
        obj = c.get(primary_value, **kwargs)
        return cls.from_sqlobject(obj, custom_keys)

    @classmethod
    def parse_json(cls: Type[JSONType], parsed_psql: Union[JSONType, List[JSONType]]) -> str:
        if isinstance(parsed_psql, list):
            result = [obj.argsdict() for obj in parsed_psql]
        else:
            result = parsed_psql.argsdict()
        return json.dumps(result)


class SQLInterface:
    def __init__(self, c: Type[psql.SQLType]) -> None:
        self.c = c

    def gets(self, custom_keys: Optional[List] = None, **kwargs) -> str:
        return JSONObject.parse_json(JSONObject.gets_from_sql(self.c, custom_keys, **kwargs))

    def get(self, custom_keys: Optional[List] = None, primary_value = None, **kwargs) -> str:
        return JSONObject.parse_json(JSONObject.get_from_sql(self.c, custom_keys, primary_value, **kwargs))

