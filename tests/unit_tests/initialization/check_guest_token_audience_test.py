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
"""Unit tests for the GUEST_TOKEN_JWT_AUDIENCE startup check."""

from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from superset.initialization import SupersetAppInitializer


def _make_initializer(
    audience: str | None,
    *,
    debug: bool = False,
    testing: bool = False,
) -> SupersetAppInitializer:
    initializer = SupersetAppInitializer.__new__(SupersetAppInitializer)
    app = MagicMock()
    app.debug = debug
    app.config = {
        "GUEST_TOKEN_JWT_AUDIENCE": audience,
        "TESTING": testing,
    }
    initializer.superset_app = app
    initializer.config = app.config
    return initializer


def test_check_guest_token_audience_rejects_none_in_production(
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "superset.initialization.feature_flag_manager.is_feature_enabled",
        return_value=True,
    )
    mocker.patch("superset.initialization.is_test", return_value=False)
    initializer = _make_initializer(None)

    with pytest.raises(SystemExit):
        initializer.check_guest_token_audience()


def test_check_guest_token_audience_allows_explicit_audience(
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "superset.initialization.feature_flag_manager.is_feature_enabled",
        return_value=True,
    )
    mocker.patch("superset.initialization.is_test", return_value=False)
    initializer = _make_initializer("https://superset.example.com")

    initializer.check_guest_token_audience()


def test_check_guest_token_audience_skipped_when_embedded_disabled(
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "superset.initialization.feature_flag_manager.is_feature_enabled",
        return_value=False,
    )
    mocker.patch("superset.initialization.is_test", return_value=False)
    initializer = _make_initializer(None)

    initializer.check_guest_token_audience()


def test_check_guest_token_audience_warns_only_in_debug(
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "superset.initialization.feature_flag_manager.is_feature_enabled",
        return_value=True,
    )
    mocker.patch("superset.initialization.is_test", return_value=False)
    initializer = _make_initializer(None, debug=True)

    initializer.check_guest_token_audience()


def test_check_guest_token_audience_warns_only_in_testing(
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "superset.initialization.feature_flag_manager.is_feature_enabled",
        return_value=True,
    )
    mocker.patch("superset.initialization.is_test", return_value=False)
    initializer = _make_initializer(None, testing=True)

    initializer.check_guest_token_audience()


def test_check_guest_token_audience_allows_callable(
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "superset.initialization.feature_flag_manager.is_feature_enabled",
        return_value=True,
    )
    mocker.patch("superset.initialization.is_test", return_value=False)
    initializer = _make_initializer(None)
    initializer.config["GUEST_TOKEN_JWT_AUDIENCE"] = lambda: "https://my-app.example"

    initializer.check_guest_token_audience()
