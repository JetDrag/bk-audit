# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making
蓝鲸智云 - 审计中心 (BlueKing - Audit Center) available.
Copyright (C) 2023 THL A29 Limited,
a Tencent company. All rights reserved.
Licensed under the MIT License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
either express or implied. See the License for the
specific language governing permissions and limitations under the License.
We undertake not to change the open source license (MIT license) applicable
to the current version of the project delivered to anyone in the future.
"""
from typing import Dict

from pypika import Field as PypikaField
from pypika import Table
from pypika.queries import QueryBuilder
from pypika.terms import BasicCriterion, EmptyCriterion

from core.sql.constants import AggregateType, FilterConnector, Operator
from core.sql.exceptions import (
    InvalidAggregateTypeError,
    MissingFromOrJoinError,
    TableNotRegisteredError,
    UnsupportedJoinTypeError,
    UnsupportedOperatorError,
)
from core.sql.model import Condition, Field, SqlConfig, WhereCondition


class SQLGenerator:
    """SQL 生成器"""

    def __init__(self, query_builder: QueryBuilder, config: SqlConfig):
        """
        初始化生成器
        :param query_builder: PyPika 的 QueryBuilder 对象
        :param config: SQL 配置
        """
        self.query_builder = query_builder
        self.config = config
        self.table_map: Dict[str, Table] = {}

    def _register_tables(self):
        """注册所有有效的表名"""
        valid_tables = set()
        if self.config.from_table:
            valid_tables.add(self.config.from_table)
        if self.config.join_tables:
            for join_table in self.config.join_tables:
                valid_tables.add(join_table.left_table)
                valid_tables.add(join_table.right_table)
        # 记录所有表名对应的 Table 对象
        for table_name in valid_tables:
            self.table_map[table_name] = Table(table_name)

    def _get_table(self, table_name: str) -> Table:
        """根据表名获取 Table 对象"""
        if table_name not in self.table_map:
            raise TableNotRegisteredError(table_name)
        return self.table_map[table_name]

    def _get_pypika_field(self, field: Field) -> PypikaField:
        """根据 Field 获取 PyPika 字段"""
        return self._get_table(field.table).field(field.raw_name)

    def generate(self) -> QueryBuilder:
        """根据配置构建 SQL 查询"""
        self._register_tables()
        query = self.query_builder
        query = self._build_from(query)
        query = self._build_select(query)
        query = self._build_where(query)
        query = self._build_group_by(query)
        query = self._build_order_by(query)
        query = self._build_pagination(query)
        return query

    def _build_from(self, query: QueryBuilder) -> QueryBuilder:
        """添加 FROM 子句"""
        if not (self.config.from_table or self.config.join_tables):
            raise MissingFromOrJoinError()
        if self.config.from_table:
            query = query.from_(self._get_table(self.config.from_table))
        if self.config.join_tables:
            query = self._build_join(query)
        return query

    def _build_join(self, query: QueryBuilder) -> QueryBuilder:
        """添加 JOIN 子句"""
        for join_table in self.config.join_tables:
            left_table = self._get_table(join_table.left_table)
            right_table = self._get_table(join_table.right_table)
            join_type_str = join_table.join_type.value.upper()
            try:
                join_function = getattr(query, join_type_str.lower())
            except AttributeError:
                raise UnsupportedJoinTypeError(join_table.join_type)
            if not join_function:
                raise UnsupportedJoinTypeError(join_table.join_type)
            for link_field in join_table.link_fields:
                query = join_function(right_table).on(
                    left_table.field(link_field.left_field) == right_table.field(link_field.right_field)
                )
        return query

    def _build_select(self, query: QueryBuilder) -> QueryBuilder:
        """添加 SELECT 子句"""
        for field in self.config.select_fields:
            pypika_field = self._get_pypika_field(field)

            # 如果存在聚合函数，使用 fn 调用
            if field.aggregate:
                aggregate_func = AggregateType.get_function(field.aggregate)
                if not aggregate_func:
                    raise InvalidAggregateTypeError(field.aggregate)
                pypika_field = aggregate_func(pypika_field)

            pypika_field = pypika_field.as_(field.display_name)

            query = query.select(pypika_field)
        return query

    def _build_where(self, query: QueryBuilder) -> QueryBuilder:
        """添加 WHERE 子句"""
        if self.config.where:
            criterion = self._apply_where_conditions(self.config.where)
            if criterion:
                query = query.where(criterion)
        return query

    def handle_condition(self, condition: Condition) -> BasicCriterion:
        """处理条件"""
        field = self._get_pypika_field(condition.field)
        operator = condition.operator
        handler = Operator.match_handler(operator)
        if not handler:
            raise UnsupportedOperatorError(operator)

        # 根据操作符类型调用对应的处理函数
        if operator in {Operator.INCLUDE, Operator.EXCLUDE}:
            return handler(field, condition.filters)
        return handler(field, condition.filter)

    def _apply_where_conditions(self, where_condition: WhereCondition) -> BasicCriterion:
        """递归构建 WHERE 子句"""
        sql_condition = EmptyCriterion()
        if where_condition.condition:
            return self.handle_condition(where_condition.condition)

        if where_condition.conditions:
            for sub_condition in where_condition.conditions:
                sub_condition = self._apply_where_conditions(sub_condition)
                if where_condition.connector == FilterConnector.AND:
                    sql_condition &= sub_condition
                elif where_condition.connector == FilterConnector.OR:
                    sql_condition |= sub_condition
        return sql_condition

    def _build_group_by(self, query: QueryBuilder) -> QueryBuilder:
        """添加 GROUP BY 子句"""
        if self.config.group_by:
            # 如果明确指定了 group_by 字段，则使用它们
            for field in self.config.group_by:
                query = query.groupby(self._get_pypika_field(field))
        else:
            # 检查是否存在聚合字段
            has_aggregate = any(field.aggregate for field in self.config.select_fields)
            if not has_aggregate:
                return query
            # 自动推导非聚合字段进行分组
            for field in self.config.select_fields:
                if not field.aggregate:
                    query = query.groupby(self._get_pypika_field(field))
        return query

    def _build_order_by(self, query: QueryBuilder) -> QueryBuilder:
        """添加 ORDER BY 子句"""
        if self.config.order_by:
            for order in self.config.order_by:
                pypika_field = self._get_pypika_field(order.field)
                query = query.orderby(pypika_field, order=order.order)
        return query

    def _build_pagination(self, query: QueryBuilder) -> QueryBuilder:
        """添加 LIMIT 和 OFFSET 子句"""
        if self.config.pagination:
            if self.config.pagination.limit:
                query = query.limit(self.config.pagination.limit)
            if self.config.pagination.offset:
                query = query.offset(self.config.pagination.offset)
        return query
