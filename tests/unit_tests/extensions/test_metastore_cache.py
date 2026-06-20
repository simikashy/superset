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
from __future__ import annotations

from typing import Any

import pytest
from flask import Flask

from superset.extensions.metastore_cache import SupersetMetastoreCache
from superset.key_value.types import (
    JsonKeyValueCodec,
    PickleKeyValueCodec,
)


@pytest.fixture
def app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret"  # noqa: S105
    app.config["HASH_ALGORITHM"] = "sha256"
    return app


def test_factory_defaults_to_json_codec_when_codec_missing(app: Flask) -> None:
    config: dict[str, Any] = {}
    args: list[Any] = []
    kwargs: dict[str, Any] = {"default_timeout": 600}

    with app.app_context():
        cache = SupersetMetastoreCache.factory(app, config, args, kwargs)

    assert isinstance(cache.codec, JsonKeyValueCodec)


def test_factory_uses_provided_json_codec(app: Flask) -> None:
    codec = JsonKeyValueCodec()
    config: dict[str, Any] = {"CODEC": codec}
    args: list[Any] = []
    kwargs: dict[str, Any] = {"default_timeout": 600}

    with app.app_context():
        cache = SupersetMetastoreCache.factory(app, config, args, kwargs)

    assert cache.codec is codec


def test_factory_rejects_pickle_codec_without_opt_in(app: Flask) -> None:
    config: dict[str, Any] = {"CODEC": PickleKeyValueCodec()}
    args: list[Any] = []
    kwargs: dict[str, Any] = {"default_timeout": 600}

    with app.app_context():
        cache = SupersetMetastoreCache.factory(app, config, args, kwargs)

    assert isinstance(cache.codec, JsonKeyValueCodec)


def test_factory_allows_pickle_codec_with_explicit_opt_in(app: Flask) -> None:
    config: dict[str, Any] = {
        "CODEC": PickleKeyValueCodec(),
        "ALLOW_PICKLE_CODEC": True,
    }
    args: list[Any] = []
    kwargs: dict[str, Any] = {"default_timeout": 600}

    with app.app_context():
        cache = SupersetMetastoreCache.factory(app, config, args, kwargs)

    assert isinstance(cache.codec, PickleKeyValueCodec)
