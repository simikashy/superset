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

from urllib.parse import urlparse

from flask import request
from flask_wtf.csrf import CSRFProtect


def _has_token_auth() -> bool:
    """Return True when the request carries non-cookie credentials.

    Authorization headers cannot be set cross-origin without a CORS preflight,
    so their presence proves the request was NOT triggered by a plain browser
    form submission (the CSRF attack vector).
    """
    auth_header = request.headers.get("Authorization", "")
    return auth_header.startswith("Bearer ") or auth_header.startswith("Basic ")


def _origin_matches_host() -> bool:
    """Validate that Origin (or Referer) matches the request host.

    Returns True when the request origin is the same as the server, or when
    neither Origin nor Referer headers are present (non-browser clients).
    """
    origin = request.headers.get("Origin")
    if not origin:
        referer = request.headers.get("Referer")
        if not referer:
            return True
        origin = f"{urlparse(referer).scheme}://{urlparse(referer).netloc}"

    parsed_origin = urlparse(origin)
    origin_host = parsed_origin.netloc or parsed_origin.path

    request_host = request.host
    return origin_host == request_host


class SupersetCSRFProtect(CSRFProtect):
    """Extended CSRF protection that conditionally exempts token-authenticated requests.

    Browsers cannot set Authorization headers on cross-origin requests without
    a CORS preflight.  If the request carries a Bearer or Basic Authorization
    header, it was NOT produced by a plain form submission (the CSRF vector),
    so CSRF token validation is skipped.

    For session/cookie-based requests, standard CSRF token validation and
    Origin/Referer checking are enforced.
    """

    def protect(self, apply_exemptions: bool = False) -> None:
        if apply_exemptions:
            if not request.endpoint:
                return
            if self._is_exempt():
                return

        from flask import current_app

        if request.method not in current_app.config["WTF_CSRF_METHODS"]:
            return

        if _has_token_auth():
            return

        if not _origin_matches_host():
            self._error_response(
                "Origin validation failed: cross-origin request blocked."
            )

        super().protect(apply_exemptions=False)
