from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typing import Literal, Optional, Type, TypeVar, Union, overload, Dict, Any, List, Generic, Callable
import requests
from requests.exceptions import SSLError


JSONType = TypeVar("JSONType", bound="JSONObject")


def handle_status_code(response: requests.Response):
    if response.status_code == 200:
        return

    match response.status_code:
        case 400:
            raise AttributeError("400 BAD REQUEST")
        case 404:
            raise KeyError("404 NOT FOUND")
        case _:
            raise ConnectionError(f"{response.status_code} {response.reason}")


class JSONObject:
    FQ_HOST: str = ...                               # type: ignore
    TABLE_NAME: str = ...                            # type: ignore
    ENDPOINT_GET: str = "/get"
    ENDPOINT_GETS: str = "/gets"

    PRIMARY_KEY: str = ...                           # type: ignore

    AUTH_METHOD: Optional[Literal["challenge", "http", "validator"]] = ...  # type: ignore

    HTTP_USERNAME: str = ...                         # type: ignore
    HTTP_PASSWORD: str = ...                         # type: ignore
    HTTP_LOGIN_ENDPOINT: str = ...                   # type: ignore

    VALIDATOR: str = ...                             # type: ignore

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
            elif cls.AUTH_METHOD == "validator":
                assert cls.VALIDATOR
                cls.session = requests.Session()
                cls.session.cookies.set("validator", cls.VALIDATOR)
        return cls.session

    @classmethod
    def reauth(cls) -> requests.Session:
        cls.session = None
        return cls.s()

    def primary_value(self):
        return getattr(self, self.PRIMARY_KEY)

    @classmethod
    def from_json(cls: Type[JSONType], o: dict) -> JSONType:
        return cls(**o)

    @classmethod
    def gets(cls: Type[JSONType], **kwargs) -> list[JSONType]:
        resp = cls.s().get(
            cls.urlfor(cls.ENDPOINT_GETS + "/" + cls.TABLE_NAME),
            params=kwargs
        )

        handle_status_code(resp)

        return [cls.from_json(obj) for obj in resp.json()]

    @classmethod
    def get(cls: Type[JSONType], **kwargs) -> JSONType:
        resp = cls.s().get(
            cls.urlfor(cls.ENDPOINT_GET + "/" + cls.TABLE_NAME),
            params=kwargs
        )

        handle_status_code(resp)

        return cls.from_json(resp.json())


class SQLInterface:
    def __init__(self, psql_cls, exclude_keys: Optional[list[str]] = None,
                 include_keys: Optional[list[str]] = None, aliases: Optional[dict[str, str]] = None) -> None:
        """
        :param exclude_keys: Excludes certain SQL keys from serving
        :param include_keys: Includes certain custom properties for serving
        """
        self.psql_cls = psql_cls

        exclude_keys = exclude_keys or []
        include_keys = include_keys or []
        self.aliases = aliases or {}

        self.keys = [key for key in (self.psql_cls.SQL_KEYS + include_keys) if key not in exclude_keys]

    def get_value(self, obj, key: str):
        alias = self.aliases.get(key)
        if alias:
            return getattr(obj, alias)
        else:
            return getattr(obj, key)

    def gets(self, **kwargs) -> list[dict]:
        objs = self.psql_cls.gets(**kwargs)
        return [self.parse_json(obj) for obj in objs]

    def get(self, primary_value = None, **kwargs) -> dict:
        obj = self.psql_cls.get(primary_value, **kwargs)
        return self.parse_json(obj)

    def parse_json(self, psql_obj) -> dict:
        return {key: self.get_value(psql_obj, key) for key in self.keys}


class Lookup(Generic[JSONType]):
    """@brief Creates a dictionary-like lookup of a psql table with a defined key"""
    def __init__(self, table: Type[JSONType], key: Union[str, Callable] = lambda o: o.primary_value()) -> None:
        objs = table.gets()
        __key = key if callable(key) else lambda o: getattr(o, key)
        self.table = table
        self.lookup = {__key(obj): obj for obj in objs}

    def __getitem__(self, k) -> JSONType:
        return self.lookup[k]

    def __repr__(self) -> str:
        return f"<pjson.Lookup {self.lookup}>"
