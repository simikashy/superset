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
import re
from pathlib import Path

DOCKER_INIT_SCRIPT = Path(__file__).resolve().parents[2] / "docker" / "docker-init.sh"


def test_docker_init_does_not_log_admin_password() -> None:
    content = DOCKER_INIT_SCRIPT.read_text()

    echo_step_calls = re.findall(r"echo_step\s+.*", content)
    for call in echo_step_calls:
        assert "$ADMIN_PASSWORD" not in call, (
            f"echo_step leaks $ADMIN_PASSWORD in log output: {call}"
        )

    echo_calls = re.findall(r'\becho\s+"[^"]*\$ADMIN_PASSWORD[^"]*"', content)
    assert not echo_calls, f"echo leaks $ADMIN_PASSWORD in log output: {echo_calls}"


def test_docker_init_does_not_default_password_to_admin() -> None:
    content = DOCKER_INIT_SCRIPT.read_text()

    assert "ADMIN_PASSWORD:-admin" not in content, (
        "ADMIN_PASSWORD must not default to a well-known value like 'admin'"
    )
