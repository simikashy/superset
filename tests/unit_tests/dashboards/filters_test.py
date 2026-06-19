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
from unittest.mock import MagicMock, patch


def test_dashboard_title_or_slug_filter_empty_noop() -> None:
    from superset.dashboards.filters import DashboardTitleOrSlugFilter

    query = MagicMock()
    f = DashboardTitleOrSlugFilter("dashboard_title", MagicMock())
    result = f.apply(query, "")
    assert result is query
    query.filter.assert_not_called()


@patch("superset.dashboards.filters.or_")
@patch("superset.dashboards.filters.Dashboard")
def test_dashboard_title_or_slug_filter_escapes_wildcards(
    mock_dashboard: MagicMock, mock_or: MagicMock
) -> None:
    from superset.dashboards.filters import DashboardTitleOrSlugFilter

    query = MagicMock()
    f = DashboardTitleOrSlugFilter("dashboard_title", MagicMock())
    f.apply(query, "50%_off\\promo")

    expected = "%50\\%\\_off\\\\promo%"
    mock_dashboard.dashboard_title.ilike.assert_called_once_with(expected, escape="\\")
    mock_dashboard.slug.ilike.assert_called_once_with(expected, escape="\\")


@patch("superset.dashboards.filters.or_")
@patch("superset.dashboards.filters.Dashboard")
def test_dashboard_title_or_slug_filter_coerces_non_string(
    mock_dashboard: MagicMock, mock_or: MagicMock
) -> None:
    from superset.dashboards.filters import DashboardTitleOrSlugFilter

    query = MagicMock()
    f = DashboardTitleOrSlugFilter("dashboard_title", MagicMock())
    f.apply(query, 123)

    expected = "%123%"
    mock_dashboard.dashboard_title.ilike.assert_called_once_with(expected, escape="\\")
    mock_dashboard.slug.ilike.assert_called_once_with(expected, escape="\\")
