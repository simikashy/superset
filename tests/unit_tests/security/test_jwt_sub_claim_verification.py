# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Tests for JWT sub claim verification on guest tokens.

Covers:
- Guest tokens include a string ``sub`` claim derived from the username.
- Tokens with non-string ``sub`` values are rejected when ``JWT_VERIFY_SUB``
  is enabled (the default).
- Tokens with non-string ``sub`` values are accepted when ``JWT_VERIFY_SUB``
  is disabled (backward-compat escape hatch).
- Legacy tokens (missing ``sub``) are still accepted.
"""

from __future__ import annotations

from typing import Any, cast

import jwt
from flask import current_app
from pytest_mock import MockerFixture

from superset.extensions import appbuilder
from superset.security.guest_token import (
    GuestTokenResources,
    GuestTokenResourceType,
    GuestTokenRlsRule,
    GuestTokenUser,
)
from superset.security.manager import SupersetSecurityManager

USER: GuestTokenUser = {"username": "guest"}
RESOURCES: GuestTokenResources = [
    {"type": GuestTokenResourceType.DASHBOARD, "id": "some-uuid"}
]
RLS: list[GuestTokenRlsRule] = []


def _decode_raw(
    raw_token: bytes | str, secret: str, algo: str, audience: str
) -> dict[str, Any]:
    return jwt.decode(raw_token, secret, algorithms=[algo], audience=audience)


def test_guest_token_includes_string_sub_claim(app_context: None) -> None:
    """Minted guest tokens carry a ``sub`` claim equal to the user's username."""
    sm = SupersetSecurityManager(appbuilder)
    raw_token = sm.create_guest_access_token(USER, RESOURCES, RLS)

    secret = current_app.config["GUEST_TOKEN_JWT_SECRET"]
    algo = current_app.config["GUEST_TOKEN_JWT_ALGO"]
    audience = sm._get_guest_token_jwt_audience()

    decoded = _decode_raw(cast(str, raw_token), secret, algo, audience)
    assert decoded["sub"] == "guest"
    assert isinstance(decoded["sub"], str)


def test_guest_token_sub_defaults_to_guest_user(app_context: None) -> None:
    """When the user dict has no username, ``sub`` defaults to 'guest_user'."""
    sm = SupersetSecurityManager(appbuilder)
    raw_token = sm.create_guest_access_token({}, RESOURCES, RLS)

    secret = current_app.config["GUEST_TOKEN_JWT_SECRET"]
    algo = current_app.config["GUEST_TOKEN_JWT_ALGO"]
    audience = sm._get_guest_token_jwt_audience()

    decoded = _decode_raw(cast(str, raw_token), secret, algo, audience)
    assert decoded["sub"] == "guest_user"


def test_non_string_sub_rejected_with_verify_enabled(
    mocker: MockerFixture, app_context: None
) -> None:
    """A hand-crafted token with a non-string ``sub`` is rejected when
    ``JWT_VERIFY_SUB`` is True."""
    sm = SupersetSecurityManager(appbuilder)
    secret = current_app.config["GUEST_TOKEN_JWT_SECRET"]
    algo = current_app.config["GUEST_TOKEN_JWT_ALGO"]
    audience = sm._get_guest_token_jwt_audience()
    current_app.config["JWT_VERIFY_SUB"] = True

    claims: dict[str, Any] = {
        "user": dict(USER),
        "resources": list(RESOURCES),
        "rls_rules": list(RLS),
        "iat": sm._get_current_epoch_time(),
        "exp": sm._get_current_epoch_time() + 300,
        "aud": audience,
        "sub": 12345,
        "type": "guest",
    }
    raw_token = jwt.encode(claims, secret, algorithm=algo)

    header_name = current_app.config["GUEST_TOKEN_HEADER_NAME"]
    request = mocker.MagicMock()
    request.headers = {header_name: raw_token}
    request.form = {}

    assert sm.get_guest_user_from_request(request) is None


def test_non_string_sub_accepted_with_verify_disabled(
    mocker: MockerFixture, app_context: None
) -> None:
    """A token with a non-string ``sub`` is accepted when
    ``JWT_VERIFY_SUB`` is set to False (backward-compat escape hatch)."""
    sm = SupersetSecurityManager(appbuilder)
    secret = current_app.config["GUEST_TOKEN_JWT_SECRET"]
    algo = current_app.config["GUEST_TOKEN_JWT_ALGO"]
    audience = sm._get_guest_token_jwt_audience()
    current_app.config["JWT_VERIFY_SUB"] = False

    claims: dict[str, Any] = {
        "user": dict(USER),
        "resources": list(RESOURCES),
        "rls_rules": list(RLS),
        "iat": sm._get_current_epoch_time(),
        "exp": sm._get_current_epoch_time() + 300,
        "aud": audience,
        "sub": 12345,
        "type": "guest",
    }
    raw_token = jwt.encode(claims, secret, algorithm=algo)

    header_name = current_app.config["GUEST_TOKEN_HEADER_NAME"]
    request = mocker.MagicMock()
    request.headers = {header_name: raw_token}
    request.form = {}

    guest_user = sm.get_guest_user_from_request(request)
    assert guest_user is not None
    assert guest_user.username == "guest"


def test_legacy_token_without_sub_accepted(
    mocker: MockerFixture, app_context: None
) -> None:
    """Legacy tokens that lack a ``sub`` claim are accepted even with
    ``JWT_VERIFY_SUB`` enabled, preserving backward compatibility."""
    sm = SupersetSecurityManager(appbuilder)
    secret = current_app.config["GUEST_TOKEN_JWT_SECRET"]
    algo = current_app.config["GUEST_TOKEN_JWT_ALGO"]
    audience = sm._get_guest_token_jwt_audience()
    current_app.config["JWT_VERIFY_SUB"] = True

    claims: dict[str, Any] = {
        "user": dict(USER),
        "resources": list(RESOURCES),
        "rls_rules": list(RLS),
        "iat": sm._get_current_epoch_time(),
        "exp": sm._get_current_epoch_time() + 300,
        "aud": audience,
        "type": "guest",
    }
    raw_token = jwt.encode(claims, secret, algorithm=algo)

    header_name = current_app.config["GUEST_TOKEN_HEADER_NAME"]
    request = mocker.MagicMock()
    request.headers = {header_name: raw_token}
    request.form = {}

    guest_user = sm.get_guest_user_from_request(request)
    assert guest_user is not None
    assert guest_user.username == "guest"


def test_valid_string_sub_accepted(mocker: MockerFixture, app_context: None) -> None:
    """A token with a valid string ``sub`` claim passes verification."""
    sm = SupersetSecurityManager(appbuilder)
    current_app.config["JWT_VERIFY_SUB"] = True

    raw_token = sm.create_guest_access_token(USER, RESOURCES, RLS)

    header_name = current_app.config["GUEST_TOKEN_HEADER_NAME"]
    request = mocker.MagicMock()
    request.headers = {header_name: raw_token}
    request.form = {}

    guest_user = sm.get_guest_user_from_request(request)
    assert guest_user is not None
    assert guest_user.username == "guest"


def test_jwt_verify_sub_defaults_to_true(app_context: None) -> None:
    """JWT_VERIFY_SUB defaults to True in the shipped configuration."""
    assert current_app.config["JWT_VERIFY_SUB"] is True
