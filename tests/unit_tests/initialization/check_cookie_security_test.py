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
"""Unit tests for the cookie security startup check."""

from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from superset.initialization import SupersetAppInitializer


def _make_initializer(
    *,
    session_cookie_secure: bool = True,
    jwt_cookie_secure: bool = True,
    jwt_cookie_samesite: str | None = "Lax",
    debug: bool = False,
    testing: bool = False,
) -> SupersetAppInitializer:
    initializer = SupersetAppInitializer.__new__(SupersetAppInitializer)
    app = MagicMock()
    app.debug = debug
    app.config = {
        "SESSION_COOKIE_SECURE": session_cookie_secure,
        "GLOBAL_ASYNC_QUERIES_JWT_COOKIE_SECURE": jwt_cookie_secure,
        "GLOBAL_ASYNC_QUERIES_JWT_COOKIE_SAMESITE": jwt_cookie_samesite,
        "TESTING": testing,
    }
    initializer.superset_app = app
    initializer.config = app.config
    return initializer


def test_check_cookie_security_passes_with_secure_defaults(
    mocker: MockerFixture,
) -> None:
    """All secure settings should not raise."""
    mocker.patch("superset.initialization.is_test", return_value=False)
    initializer = _make_initializer()

    initializer.check_cookie_security()


def test_check_cookie_security_rejects_insecure_session_cookie(
    mocker: MockerFixture,
) -> None:
    """SESSION_COOKIE_SECURE=False refuses to start in production."""
    mocker.patch("superset.initialization.is_test", return_value=False)
    initializer = _make_initializer(session_cookie_secure=False)

    with pytest.raises(SystemExit):
        initializer.check_cookie_security()


def test_check_cookie_security_rejects_insecure_jwt_cookie(
    mocker: MockerFixture,
) -> None:
    """GLOBAL_ASYNC_QUERIES_JWT_COOKIE_SECURE=False refuses to start in production."""
    mocker.patch("superset.initialization.is_test", return_value=False)
    initializer = _make_initializer(jwt_cookie_secure=False)

    with pytest.raises(SystemExit):
        initializer.check_cookie_security()


def test_check_cookie_security_rejects_none_samesite(
    mocker: MockerFixture,
) -> None:
    """SameSite=None refuses to start in production."""
    mocker.patch("superset.initialization.is_test", return_value=False)
    initializer = _make_initializer(jwt_cookie_samesite=None)

    with pytest.raises(SystemExit):
        initializer.check_cookie_security()


def test_check_cookie_security_warns_only_in_debug(
    mocker: MockerFixture,
) -> None:
    """In debug mode insecure cookies warn but do not exit."""
    mocker.patch("superset.initialization.is_test", return_value=False)
    initializer = _make_initializer(
        session_cookie_secure=False,
        jwt_cookie_secure=False,
        jwt_cookie_samesite=None,
        debug=True,
    )

    initializer.check_cookie_security()


def test_check_cookie_security_warns_only_in_testing(
    mocker: MockerFixture,
) -> None:
    """In testing mode insecure cookies warn but do not exit."""
    mocker.patch("superset.initialization.is_test", return_value=False)
    initializer = _make_initializer(
        session_cookie_secure=False,
        jwt_cookie_secure=False,
        jwt_cookie_samesite=None,
        testing=True,
    )

    initializer.check_cookie_security()
