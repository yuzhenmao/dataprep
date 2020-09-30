"""Strong typed schema definition."""
from __future__ import annotations

import http.server
import random
import socketserver
import string
from base64 import b64encode
from enum import Enum
from threading import Thread
from time import time
from typing import Any, Dict, List, Optional, Union
from urllib.parse import parse_qs, urlparse

import requests
from pydantic import Field

from ...utils import is_notebook
from .base import BaseDef, BaseDefT

# pylint: disable=missing-class-docstring,missing-function-docstring


def get_random_string(length: int) -> str:
    letters = string.ascii_lowercase
    result_str = "".join(random.choice(letters) for _ in range(length))
    return result_str


class OffsetPaginationDef(BaseDef):
    type: str = Field("offset", const=True)
    max_count: int
    limit_key: str
    offset_key: str


class SeekPaginationDef(BaseDef):
    type: str = Field("seek", const=True)
    max_count: int
    limit_key: str
    seek_id: str
    seek_key: str


class PagePaginationDef(BaseDef):
    type: str = Field("page", const=True)
    max_count: int
    limit_key: str
    page_key: str


class TokenLocation(str, Enum):
    Header = "header"
    Body = "body"


class TokenPaginationDef(BaseDef):
    type: str = Field("token", const=True)
    max_count: int
    limit_key: str
    token_location: TokenLocation
    token_accessor: str
    token_key: str


PaginationDef = Union[
    OffsetPaginationDef, SeekPaginationDef, PagePaginationDef, TokenPaginationDef
]


class FieldDef(BaseDef):
    required: bool
    from_key: Optional[str]
    to_key: Optional[str]
    template: Optional[str]
    remove_if_empty: bool


FieldDefUnion = Union[FieldDef, bool, str]  # Put bool before str


class OAuth2AuthorizationCodeAuthorizationDef(BaseDef):
    type: str = Field("OAuth2", const=True)
    grant_type: str = Field("AuthorizationCode", const=True)
    scopes: List[str]
    auth_server_url: str
    token_server_url: str

    def build(
        self,
        req_data: Dict[str, Any],
        params: Dict[str, Any],
        storage: Optional[Dict[str, Any]] = None,
    ) -> None:
        if storage is None:
            raise ValueError("storage is required for OAuth2")

        if "access_token" not in storage or storage.get("expires_at", 0) < time():
            port = params.get("port", 9999)
            code = self._auth(params["client_id"], port)

            ckey = params["client_id"]
            csecret = params["client_secret"]
            b64cred = b64encode(f"{ckey}:{csecret}".encode("ascii")).decode()

            resp: Dict[str, Any] = requests.post(
                self.token_server_url,
                headers={"Authorization": f"Basic {b64cred}"},
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": f"http://localhost:{port}/",
                },
            ).json()

            if resp["token_type"].lower() != "bearer":
                raise RuntimeError("token_type is not bearer")

            access_token = resp["access_token"]
            storage["access_token"] = access_token
            if "expires_in" in resp:
                storage["expires_at"] = (
                    time() + resp["expires_in"] - 60
                )  # 60 seconds grace period to avoid clock lag

        req_data["headers"]["Authorization"] = f"Bearer {storage['access_token']}"

    def _auth(self, client_id: str, port: int = 9999) -> str:

        state = get_random_string(23)
        scope = ",".join(self.scopes)
        authurl = (
            f"{self.auth_server_url}?"
            f"response_type=code&client_id={client_id}&"
            f"redirect_uri=http%3A%2F%2Flocalhost:{port}/&scope={scope}&"
            f"state={state}"
        )
        if is_notebook():
            from IPython.display import Javascript, display

            display(Javascript(f"window.open('{authurl}');"))
        else:
            import webbrowser

            webbrowser.open_new_tab(authurl)

        code, state2 = None, None

        class Server(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                qs = urlparse(self.path).query
                parsed = parse_qs(qs)

                nonlocal code, state2
                (code,) = parsed["code"]
                (state2,) = parsed["state"]

                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><head><title>OAuth2 Success</title></head>")
                self.wfile.write(b"<body><p>OAuth2 Success</p>")
                self.wfile.write(b"</body></html>")

                Thread(target=httpd.shutdown).start()
                httpd.server_close()

        with socketserver.TCPServer(("", 9999), Server) as httpd:
            httpd.serve_forever()

        if state != state2:
            raise RuntimeError("state does not match")

        if code is None:
            raise RuntimeError(
                "OAuth2 authorization code auth failed, no code acquired."
            )
        return code


class OAuth2ClientCredentialsAuthorizationDef(BaseDef):
    type: str = Field("OAuth2", const=True)
    grant_type: str = Field("ClientCredentials", const=True)
    token_server_url: str

    def build(
        self,
        req_data: Dict[str, Any],
        params: Dict[str, Any],
        storage: Optional[Dict[str, Any]] = None,
    ) -> None:
        if storage is None:
            raise ValueError("storage is required for OAuth2")

        if "access_token" not in storage or storage.get("expires_at", 0) < time():
            # Not yet authorized
            ckey = params["client_id"]
            csecret = params["client_secret"]
            b64cred = b64encode(f"{ckey}:{csecret}".encode("ascii")).decode()
            resp: Dict[str, Any] = requests.post(
                self.token_server_url,
                headers={"Authorization": f"Basic {b64cred}"},
                data={"grant_type": "client_credentials"},
            ).json()
            if resp["token_type"].lower() != "bearer":
                raise RuntimeError("token_type is not bearer")

            access_token = resp["access_token"]
            storage["access_token"] = access_token
            if "expires_in" in resp:
                storage["expires_at"] = (
                    time() + resp["expires_in"] - 60
                )  # 60 seconds grace period to avoid clock lag

        req_data["headers"]["Authorization"] = f"Bearer {storage['access_token']}"


class QueryParamAuthorizationDef(BaseDef):
    type: str = Field("QueryParam", const=True)
    key_param: str

    def build(
        self,
        req_data: Dict[str, Any],
        params: Dict[str, Any],
        storage: Optional[Dict[str, Any]] = None,  # pylint: disable=unused-argument
    ) -> None:
        """Populate some required fields to the request data."""

        req_data["params"][self.key_param] = params["access_token"]


class BearerAuthorizationDef(BaseDef):
    type: str = Field("Bearer", const=True)

    @staticmethod
    def build(
        req_data: Dict[str, Any],
        params: Dict[str, Any],
        storage: Optional[Dict[str, Any]] = None,  # pylint: disable=unused-argument
    ) -> None:
        """Populate some required fields to the request data."""

        req_data["headers"]["Authorization"] = f"Bearer {params['access_token']}"


class HeaderAuthorizationDef(BaseDef):
    type: str = Field("Header", const=True)
    key_name: str
    extra: Dict[str, str] = Field(default_factory=dict)

    def build(
        self,
        req_data: Dict[str, Any],
        params: Dict[str, Any],
        storage: Optional[Dict[str, Any]] = None,  # pylint: disable=unused-argument
    ) -> None:
        """Populate some required fields to the request data."""

        req_data["headers"][self.key_name] = params["access_token"]
        req_data["headers"].update(self.extra)


AuthorizationDef = Union[
    OAuth2ClientCredentialsAuthorizationDef,
    OAuth2AuthorizationCodeAuthorizationDef,
    QueryParamAuthorizationDef,
    BearerAuthorizationDef,
    HeaderAuthorizationDef,
]


class BodyDef(BaseDef):
    ctype: str = Field(regex=r"^(application/x-www-form-urlencoded|application/json)$")
    content: Dict[str, FieldDefUnion]


class Method(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"


class SearchDef(BaseDef):
    key: str


class RequestDef(BaseDef):
    url: str
    method: Method

    headers: Optional[Dict[str, FieldDefUnion]]
    params: Dict[str, FieldDefUnion]
    body: Optional[BodyDef]
    cookies: Optional[Dict[str, FieldDefUnion]]

    authorization: Optional[AuthorizationDef]
    pagination: Optional[PaginationDef]
    search: Optional[SearchDef]


class SchemaFieldDef(BaseDef):
    target: str
    type: str
    description: Optional[str]

    def merge(self, rhs: BaseDefT) -> BaseDefT:
        if not isinstance(rhs, SchemaFieldDef):
            raise ValueError(f"Cannot merge {type(self)} with {type(rhs)}")

        if self.target != rhs.target:
            raise ValueError("Cannot merge SchemaFieldDef with different target.")

        merged_type = merge_type(self.type, rhs.type)

        cur: SchemaFieldDef = self.copy()  # type: ignore
        cur.type = merged_type
        cur.description = rhs.description

        return cur  # type: ignore


TYPE_TREE = {
    "object": None,
    "string": None,
    "float": "string",
    "int": "float",
    "boolean": "string",
}


def merge_type(a: str, b: str) -> str:  # pylint: disable=invalid-name
    if a == b:
        return a

    aset = {a}
    bset = {b}

    while True:
        aparent = TYPE_TREE[a]
        if aparent is not None:
            if aparent in bset:
                return aparent
            else:
                aset.add(aparent)
        bparent = TYPE_TREE[b]
        if bparent is not None:
            if bparent in aset:
                return bparent
            else:
                bset.add(bparent)

        if aparent is None and bparent is None:
            raise RuntimeError("Unreachable")


class ResponseDef(BaseDef):
    ctype: str = Field(regex=r"^(application/xml|application/json)$")
    table_path: str
    schema_: Dict[str, SchemaFieldDef] = Field(alias="schema")
    orient: str = Field(regex=r"^(records|split)$")


class ConfigDef(BaseDef):
    version: int = Field(1, const=True)
    request: RequestDef
    response: ResponseDef
