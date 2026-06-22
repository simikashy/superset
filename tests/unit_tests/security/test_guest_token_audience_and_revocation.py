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
"""Tests for guest token audience enforcement and revocation controls."""

from typing import Any, cast

import jwt
from flask import current_app
from pytest_mock import MockerFixture

from superset.extensions import appbuilder
from superset.security.guest_token import (
    GUEST_TOKEN_REVOCATION_CLAIM,
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
AUDIENCE = "https://legit.example.com"  # noqa: S105
AUDIENCE_OTHER = "https://other.example.com"  # noqa: S105


def _decode_raw(
    raw_token: bytes, secret: str, algo: str, audience: str
) -> dict[str, Any]:
    return jwt.decode(raw_token, secret, algorithms=[algo], audience=audience)


def test_token_with_wrong_audience_rejected(
    mocker: MockerFixture, app_context: None
) -> None:
    """A guest token minted for one audience is rejected when the configured
    audience differs at validation time."""
    sm = SupersetSecurityManager(appbuilder)
    current_app.config["GUEST_TOKEN_JWT_AUDIENCE"] = AUDIENCE

    raw_token = sm.create_guest_access_token(USER, RESOURCES, RLS)

    current_app.config["GUEST_TOKEN_JWT_AUDIENCE"] = AUDIENCE_OTHER

    header_name = current_app.config["GUEST_TOKEN_HEADER_NAME"]
    request = mocker.MagicMock()
    request.headers = {header_name: raw_token}
    request.form = {}

    assert sm.get_guest_user_from_request(request) is None


def test_token_with_correct_audience_accepted(
    mocker: MockerFixture, app_context: None
) -> None:
    """A guest token with a matching audience is accepted."""
    sm = SupersetSecurityManager(appbuilder)
    current_app.config["GUEST_TOKEN_JWT_AUDIENCE"] = AUDIENCE

    raw_token = sm.create_guest_access_token(USER, RESOURCES, RLS)

    header_name = current_app.config["GUEST_TOKEN_HEADER_NAME"]
    request = mocker.MagicMock()
    request.headers = {header_name: raw_token}
    request.form = {}

    guest_user = sm.get_guest_user_from_request(request)
    assert guest_user is not None
    assert guest_user.username == "guest"


def test_token_without_audience_claim_rejected_when_audience_configured(
    mocker: MockerFixture, app_context: None
) -> None:
    """A hand-crafted token lacking an ``aud`` claim is rejected when the server
    has a configured audience."""
    sm = SupersetSecurityManager(appbuilder)
    secret = current_app.config["GUEST_TOKEN_JWT_SECRET"]
    algo = current_app.config["GUEST_TOKEN_JWT_ALGO"]

    claims: dict[str, Any] = {
        "user": dict(USER),
        "resources": list(RESOURCES),
        "rls_rules": list(RLS),
        "iat": sm._get_current_epoch_time(),
        "exp": sm._get_current_epoch_time() + 300,
        "type": "guest",
    }
    raw_token = jwt.encode(claims, secret, algorithm=algo)

    current_app.config["GUEST_TOKEN_JWT_AUDIENCE"] = AUDIENCE

    header_name = current_app.config["GUEST_TOKEN_HEADER_NAME"]
    request = mocker.MagicMock()
    request.headers = {header_name: raw_token}
    request.form = {}

    assert sm.get_guest_user_from_request(request) is None


def test_revoked_token_rejected_after_version_bump(
    mocker: MockerFixture, app_context: None
) -> None:
    """After a revocation version bump, tokens minted at a lower version are
    rejected through the full request flow."""
    sm = SupersetSecurityManager(appbuilder)
    current_app.config["GUEST_TOKEN_REVOCATION_ENABLED"] = True

    mocker.patch(
        "superset.security.manager.get_current_guest_token_revocation_version",
        return_value=1,
    )
    raw_token = sm.create_guest_access_token(USER, RESOURCES, RLS)

    secret = current_app.config["GUEST_TOKEN_JWT_SECRET"]
    algo = current_app.config["GUEST_TOKEN_JWT_ALGO"]
    audience = sm._get_guest_token_jwt_audience()
    decoded = jwt.decode(
        cast(str, raw_token), secret, algorithms=[algo], audience=audience
    )
    assert decoded[GUEST_TOKEN_REVOCATION_CLAIM] == 1

    header_name = current_app.config["GUEST_TOKEN_HEADER_NAME"]
    request = mocker.MagicMock()
    request.headers = {header_name: raw_token}
    request.form = {}

    mocker.patch(
        "superset.security.manager.get_current_guest_token_revocation_version",
        return_value=2,
    )
    assert sm.get_guest_user_from_request(request) is None


def test_current_version_token_accepted_after_bump(
    mocker: MockerFixture, app_context: None
) -> None:
    """Tokens minted at or above the expected revocation version are accepted."""
    sm = SupersetSecurityManager(appbuilder)
    current_app.config["GUEST_TOKEN_REVOCATION_ENABLED"] = True

    mocker.patch(
        "superset.security.manager.get_current_guest_token_revocation_version",
        return_value=2,
    )
    raw_token = sm.create_guest_access_token(USER, RESOURCES, RLS)

    header_name = current_app.config["GUEST_TOKEN_HEADER_NAME"]
    request = mocker.MagicMock()
    request.headers = {header_name: raw_token}
    request.form = {}

    guest_user = sm.get_guest_user_from_request(request)
    assert guest_user is not None
    assert guest_user.is_guest_user is True


def test_revocation_default_enabled() -> None:
    """GUEST_TOKEN_REVOCATION_ENABLED defaults to True."""
    assert current_app.config["GUEST_TOKEN_REVOCATION_ENABLED"] is True
