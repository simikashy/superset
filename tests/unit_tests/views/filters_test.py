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


@patch("superset.views.filters.or_")
@patch("superset.views.filters.security_manager", new_callable=MagicMock)
def test_filter_related_owners_escapes_wildcards(
    mock_sm: MagicMock, mock_or: MagicMock
) -> None:
    from superset.views.filters import FilterRelatedOwners

    mock_user_model = MagicMock()
    mock_sm.user_model = mock_user_model

    query = MagicMock()
    f = FilterRelatedOwners("first_name", MagicMock())
    f.apply(query, "50%_off\\promo")

    expected = "%50\\%\\_off\\\\promo%"
    mock_user_model.username.ilike.assert_called_once_with(expected, escape="\\")


@patch("superset.views.filters.security_manager", new_callable=MagicMock)
def test_filter_related_tables_escapes_wildcards(mock_sm: MagicMock) -> None:
    from superset.views.filters import FilterRelatedTables

    query = MagicMock()
    f = FilterRelatedTables("table_name", MagicMock())

    with patch("superset.connectors.sqla.models.SqlaTable"):
        f.apply(query, "50%_off\\promo")

    query.filter.assert_called_once()
