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

import pytest
from flask import Flask
from flask_wtf.csrf import generate_csrf

from superset.security.csrf import (
    _has_token_auth,
    _origin_matches_host,
    SupersetCSRFProtect,
)


@pytest.fixture
def csrf_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret-key"  # noqa: S105
    app.config["WTF_CSRF_ENABLED"] = True
    app.config["WTF_CSRF_METHODS"] = {"POST", "PUT", "PATCH", "DELETE"}
    app.config["WTF_CSRF_HEADERS"] = ["X-CSRFToken", "X-CSRF-Token"]
    app.config["WTF_CSRF_TIME_LIMIT"] = 3600
    app.config["WTF_CSRF_SSL_STRICT"] = False
    app.config["WTF_CSRF_FIELD_NAME"] = "csrf_token"
    app.config["TESTING"] = True
    app.config["SERVER_NAME"] = "superset.example.com"

    SupersetCSRFProtect(app)

    @app.route("/api/v1/chart/data", methods=["POST"])
    def chart_data():
        return "ok"

    @app.route(
        "/api/v1/dashboard/<int:pk>/cache_dashboard_screenshot/", methods=["POST"]
    )
    def cache_screenshot(pk: int):
        return "ok"

    @app.route("/superset/explore_json/", methods=["POST"])
    def explore_json():
        return "ok"

    @app.route("/superset/log/", methods=["POST"])
    def log():
        return "ok"

    @app.route("/datasource/samples", methods=["POST"])
    def samples():
        return "ok"

    return app


def test_cross_origin_post_without_csrf_token_is_rejected(csrf_app: Flask) -> None:
    with csrf_app.test_client() as client:
        resp = client.post(
            "/api/v1/chart/data",
            headers={"Origin": "https://evil.example.com"},
            json={"query": "test"},
        )
        assert resp.status_code == 400


def test_cross_origin_post_to_explore_json_is_rejected(csrf_app: Flask) -> None:
    with csrf_app.test_client() as client:
        resp = client.post(
            "/superset/explore_json/",
            headers={"Origin": "https://evil.example.com"},
            json={"form_data": "{}"},
        )
        assert resp.status_code == 400


def test_cross_origin_post_to_log_is_rejected(csrf_app: Flask) -> None:
    with csrf_app.test_client() as client:
        resp = client.post(
            "/superset/log/",
            headers={"Origin": "https://evil.example.com"},
            json={"events": []},
        )
        assert resp.status_code == 400


def test_cross_origin_post_to_samples_is_rejected(csrf_app: Flask) -> None:
    with csrf_app.test_client() as client:
        resp = client.post(
            "/datasource/samples",
            headers={"Origin": "https://evil.example.com"},
            json={"datasource_id": 1},
        )
        assert resp.status_code == 400


def test_cross_origin_post_to_screenshot_cache_is_rejected(csrf_app: Flask) -> None:
    with csrf_app.test_client() as client:
        resp = client.post(
            "/api/v1/dashboard/1/cache_dashboard_screenshot/",
            headers={"Origin": "https://evil.example.com"},
            json={},
        )
        assert resp.status_code == 400


def test_cross_origin_referer_is_rejected(csrf_app: Flask) -> None:
    with csrf_app.test_client() as client:
        resp = client.post(
            "/api/v1/chart/data",
            headers={"Referer": "https://evil.example.com/page"},
            json={"query": "test"},
        )
        assert resp.status_code == 400


def test_bearer_token_bypasses_csrf(csrf_app: Flask) -> None:
    with csrf_app.test_client() as client:
        resp = client.post(
            "/api/v1/chart/data",
            headers={
                "Authorization": "Bearer some-api-token",
                "Origin": "https://evil.example.com",
            },
            json={"query": "test"},
        )
        assert resp.status_code == 200


def test_basic_auth_bypasses_csrf(csrf_app: Flask) -> None:
    with csrf_app.test_client() as client:
        resp = client.post(
            "/api/v1/chart/data",
            headers={
                "Authorization": "Basic dXNlcjpwYXNz",
                "Origin": "https://evil.example.com",
            },
            json={"query": "test"},
        )
        assert resp.status_code == 200


def test_same_origin_with_csrf_token_succeeds(csrf_app: Flask) -> None:
    @csrf_app.route("/get-csrf-token")
    def get_token():
        return generate_csrf()

    with csrf_app.test_client() as client:
        token_resp = client.get("/get-csrf-token")
        token = token_resp.data.decode()
        resp = client.post(
            "/api/v1/chart/data",
            headers={
                "Origin": "http://superset.example.com",
                "X-CSRFToken": token,
            },
            json={"query": "test"},
        )
        assert resp.status_code == 200


def test_no_origin_no_referer_requires_csrf_token(csrf_app: Flask) -> None:
    with csrf_app.test_client() as client:
        resp = client.post(
            "/api/v1/chart/data",
            json={"query": "test"},
        )
        assert resp.status_code == 400


def test_get_requests_not_blocked(csrf_app: Flask) -> None:
    app = csrf_app
    with app.app_context():

        @app.route("/api/v1/chart/data-get", methods=["GET"])
        def chart_data_get():
            return "ok"

    with app.test_client() as client:
        resp = client.get(
            "/api/v1/chart/data-get",
            headers={"Origin": "https://evil.example.com"},
        )
        assert resp.status_code == 200


def test_has_token_auth_bearer() -> None:
    app = Flask(__name__)
    app.config["SERVER_NAME"] = "superset.example.com"
    with app.test_request_context("/test", headers={"Authorization": "Bearer abc123"}):
        assert _has_token_auth() is True


def test_has_token_auth_basic() -> None:
    app = Flask(__name__)
    app.config["SERVER_NAME"] = "superset.example.com"
    with app.test_request_context(
        "/test", headers={"Authorization": "Basic dXNlcjpwYXNz"}
    ):
        assert _has_token_auth() is True


def test_has_token_auth_no_header() -> None:
    app = Flask(__name__)
    app.config["SERVER_NAME"] = "superset.example.com"
    with app.test_request_context("/test"):
        assert _has_token_auth() is False


def test_origin_matches_host_same_origin() -> None:
    app = Flask(__name__)
    app.config["SERVER_NAME"] = "superset.example.com"
    with app.test_request_context(
        "/test",
        headers={"Origin": "http://superset.example.com"},
    ):
        assert _origin_matches_host() is True


def test_origin_matches_host_different_origin() -> None:
    app = Flask(__name__)
    app.config["SERVER_NAME"] = "superset.example.com"
    with app.test_request_context(
        "/test",
        headers={"Origin": "https://evil.example.com"},
    ):
        assert _origin_matches_host() is False


def test_origin_matches_host_no_origin_no_referer() -> None:
    app = Flask(__name__)
    app.config["SERVER_NAME"] = "superset.example.com"
    with app.test_request_context("/test"):
        assert _origin_matches_host() is True


def test_origin_matches_host_referer_same() -> None:
    app = Flask(__name__)
    app.config["SERVER_NAME"] = "superset.example.com"
    with app.test_request_context(
        "/test",
        headers={"Referer": "http://superset.example.com/dashboard/1"},
    ):
        assert _origin_matches_host() is True


def test_origin_matches_host_referer_different() -> None:
    app = Flask(__name__)
    app.config["SERVER_NAME"] = "superset.example.com"
    with app.test_request_context(
        "/test",
        headers={"Referer": "https://evil.example.com/page"},
    ):
        assert _origin_matches_host() is False


def test_config_exempt_list_only_contains_saml_acs() -> None:
    from superset.config import WTF_CSRF_EXEMPT_LIST

    assert WTF_CSRF_EXEMPT_LIST == ["flask_appbuilder.security.views.acs"]
