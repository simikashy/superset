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
from unittest.mock import MagicMock, patch

from superset.extensions.metastore_cache import SupersetMetastoreCache
from superset.key_value.types import JsonKeyValueCodec, PickleKeyValueCodec


def test_factory_defaults_to_json_codec() -> None:
    app = MagicMock()
    config: dict[str, Any] = {"CACHE_KEY_PREFIX": "test_"}
    kwargs: dict[str, Any] = {}

    with patch("superset.extensions.metastore_cache.get_uuid_namespace") as mock_ns:
        mock_ns.return_value = "fake-namespace"
        cache = SupersetMetastoreCache.factory(app, config, [], kwargs)

    assert isinstance(cache.codec, JsonKeyValueCodec)


def test_factory_does_not_use_pickle_by_default() -> None:
    app = MagicMock()
    config: dict[str, Any] = {}
    kwargs: dict[str, Any] = {}

    with patch("superset.extensions.metastore_cache.get_uuid_namespace") as mock_ns:
        mock_ns.return_value = "fake-namespace"
        cache = SupersetMetastoreCache.factory(app, config, [], kwargs)

    assert not isinstance(cache.codec, PickleKeyValueCodec)


def test_factory_uses_explicit_pickle_codec() -> None:
    app = MagicMock()
    config: dict[str, Any] = {"CODEC": PickleKeyValueCodec()}
    kwargs: dict[str, Any] = {}

    with patch("superset.extensions.metastore_cache.get_uuid_namespace") as mock_ns:
        mock_ns.return_value = "fake-namespace"
        cache = SupersetMetastoreCache.factory(app, config, [], kwargs)

    assert isinstance(cache.codec, PickleKeyValueCodec)


def test_factory_uses_explicit_json_codec() -> None:
    app = MagicMock()
    codec = JsonKeyValueCodec()
    config: dict[str, Any] = {"CODEC": codec}
    kwargs: dict[str, Any] = {}

    with patch("superset.extensions.metastore_cache.get_uuid_namespace") as mock_ns:
        mock_ns.return_value = "fake-namespace"
        cache = SupersetMetastoreCache.factory(app, config, [], kwargs)

    assert cache.codec is codec
