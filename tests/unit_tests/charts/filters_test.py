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


def test_chart_all_text_filter_empty_noop() -> None:
    from superset.charts.filters import ChartAllTextFilter

    query = MagicMock()
    f = ChartAllTextFilter("slice_name", MagicMock())
    result = f.apply(query, "")
    assert result is query
    query.filter.assert_not_called()


@patch("superset.charts.filters.or_")
@patch("superset.charts.filters.SqlaTable")
@patch("superset.charts.filters.Slice")
def test_chart_all_text_filter_escapes_wildcards(
    mock_slice: MagicMock, mock_sqla_table: MagicMock, mock_or: MagicMock
) -> None:
    from superset.charts.filters import ChartAllTextFilter

    query = MagicMock()
    f = ChartAllTextFilter("slice_name", MagicMock())
    f.apply(query, "50%_off\\promo")

    expected = "%50\\%\\_off\\\\promo%"
    mock_slice.slice_name.ilike.assert_called_once_with(expected, escape="\\")
    mock_slice.description.ilike.assert_called_once_with(expected, escape="\\")
    mock_slice.viz_type.ilike.assert_called_once_with(expected, escape="\\")
    mock_sqla_table.table_name.ilike.assert_called_once_with(expected, escape="\\")
