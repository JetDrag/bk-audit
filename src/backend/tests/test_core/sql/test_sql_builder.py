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
import unittest

from pydantic import ValidationError
from pypika import Order as pypikaOrder
from pypika.queries import QueryBuilder

from core.sql.constants import (
    AggregateType,
    FieldType,
    FilterConnector,
    JoinType,
    Operator,
)
from core.sql.exceptions import TableNotRegisteredError
from core.sql.model import (
    Condition,
    Field,
    JoinTable,
    LinkField,
    Order,
    Pagination,
    SqlConfig,
    WhereCondition,
)
from core.sql.sql_builder import SQLGenerator
from tests.base import TestCase


class TestSQLGenerator(TestCase):
    """使用 unittest.TestCase 编写的单元测试示例"""

    def setUp(self):
        self.query_builder = QueryBuilder()

    def test_single_table_query(self):
        """测试单表查询的 SQL 生成"""
        config = SqlConfig(
            select_fields=[
                Field(table="users", raw_name="id", display_name="user_id", field_type=FieldType.INT),
                Field(table="users", raw_name="name", display_name="user_name", field_type=FieldType.STRING),
            ],
            from_table="users",
        )
        generator = SQLGenerator(self.query_builder, config)
        query = generator.generate()
        expected_query = 'SELECT "users"."id" "user_id","users"."name" "user_name" FROM "users" "users"'
        self.assertEqual(str(query), expected_query, f"Expected: {expected_query}, but got: {query}")

    def test_join_table_query(self):
        """测试联表查询的 SQL 生成"""
        config = SqlConfig(
            select_fields=[
                Field(table="users", raw_name="id", display_name="user_id", field_type=FieldType.INT),
                Field(table="orders", raw_name="order_id", display_name="order_id", field_type=FieldType.INT),
            ],
            from_table="users",
            join_tables=[
                JoinTable(
                    join_type=JoinType.INNER_JOIN,
                    link_fields=[LinkField(left_field="id", right_field="user_id")],
                    left_table="users",
                    right_table="orders",
                )
            ],
        )
        generator = SQLGenerator(self.query_builder, config)
        query = generator.generate()
        expected_query = (
            'SELECT "users"."id" "user_id","orders"."order_id" "order_id" FROM "users" '
            '"users" JOIN "orders" "orders" ON "users"."id"="orders"."user_id"'
        )
        self.assertEqual(str(query), expected_query, f"Expected: {expected_query}, but got: {query}")

    def test_where_conditions(self):
        """测试条件筛选的 SQL 生成"""

        config = SqlConfig(
            select_fields=[
                Field(table="users", raw_name="id", display_name="user_id", field_type=FieldType.INT),
            ],
            from_table="users",
            where=WhereCondition(
                connector=FilterConnector.AND,
                conditions=[
                    WhereCondition(
                        condition=Condition(
                            field=Field(
                                table="users", raw_name="age", display_name="user_age", field_type=FieldType.INT
                            ),
                            operator=Operator.EQ,
                            filter=18,
                        )
                    ),
                    WhereCondition(
                        condition=Condition(
                            field=Field(
                                table="users",
                                raw_name="country",
                                display_name="user_country",
                                field_type=FieldType.STRING,
                            ),
                            operator=Operator.EQ,
                            filter="Ireland",
                        )
                    ),
                ],
            ),
        )
        generator = SQLGenerator(self.query_builder, config)
        query = generator.generate()
        expected_query = (
            'SELECT "users"."id" "user_id" FROM "users" "users" WHERE "users"."age"=18 '
            'AND "users"."country"=\'Ireland\''
        )
        self.assertEqual(str(query), expected_query, f"Expected: {expected_query}, but got: {query}")

    def test_invalid_field_source(self):
        """测试无效字段来源的捕获"""
        self.query_builder = QueryBuilder()
        config = SqlConfig(
            select_fields=[
                Field(table="invalid_table", raw_name="id", display_name="invalid_id", field_type=FieldType.INT),
            ],
            from_table="users",
        )
        generator = SQLGenerator(self.query_builder, config)
        with self.assertRaisesRegex(TableNotRegisteredError, r"表 'invalid_table' 未在配置中声明。"):
            generator.generate()

    def test_order_by_with_invalid_table(self):
        """测试排序字段来源不合法时的异常捕获"""

        config = SqlConfig(
            select_fields=[
                Field(table="users", raw_name="id", display_name="user_id", field_type=FieldType.INT),
            ],
            from_table="users",
            order_by=[
                Order(
                    field=Field(
                        table="orders", raw_name="date", display_name="order_date", field_type=FieldType.STRING
                    ),
                    order=pypikaOrder.desc,
                )
            ],
        )
        generator = SQLGenerator(self.query_builder, config)
        with self.assertRaisesRegex(TableNotRegisteredError, r"表 'orders' 未在配置中声明。"):
            generator.generate()

    def test_pagination_disabled(self):
        """测试无分页功能的查询"""

        config = SqlConfig(
            select_fields=[
                Field(table="users", raw_name="id", display_name="user_id", field_type=FieldType.INT),
            ],
            from_table="users",
        )
        generator = SQLGenerator(self.query_builder, config)
        query = generator.generate()
        expected_query = 'SELECT "users"."id" "user_id" FROM "users" "users"'
        self.assertEqual(str(query), expected_query, f"Expected: {expected_query}, but got: {query}")

    def test_multiple_join_tables(self):
        """测试多表 JOIN 的 SQL 生成"""

        config = SqlConfig(
            select_fields=[
                Field(table="users", raw_name="id", display_name="user_id", field_type=FieldType.INT),
                Field(table="orders", raw_name="order_id", display_name="order_id", field_type=FieldType.INT),
                Field(
                    table="products", raw_name="product_name", display_name="product_name", field_type=FieldType.STRING
                ),
            ],
            from_table="users",
            join_tables=[
                JoinTable(
                    join_type=JoinType.INNER_JOIN,
                    link_fields=[LinkField(left_field="id", right_field="user_id")],
                    left_table="users",
                    right_table="orders",
                ),
                JoinTable(
                    join_type=JoinType.LEFT_JOIN,
                    link_fields=[LinkField(left_field="order_id", right_field="id")],
                    left_table="orders",
                    right_table="products",
                ),
            ],
        )
        generator = SQLGenerator(self.query_builder, config)
        query = generator.generate()
        expected_query = (
            'SELECT "users"."id" "user_id","orders"."order_id" "order_id","products"."product_name" "product_name" '
            'FROM "users" "users" JOIN "orders" "orders" ON "users"."id"="orders"."user_id" '
            'LEFT JOIN "products" "products" ON "orders"."order_id"="products"."id"'
        )
        self.assertEqual(str(query), expected_query, f"Expected: {expected_query}, but got: {query}")

    def test_order_by_multiple_fields(self):
        """测试 ORDER BY 多字段"""

        config = SqlConfig(
            select_fields=[
                Field(table="users", raw_name="id", display_name="user_id", field_type=FieldType.INT),
            ],
            from_table="users",
            order_by=[
                Order(
                    field=Field(table="users", raw_name="age", display_name="user_age", field_type=FieldType.INT),
                    order=pypikaOrder.asc,
                ),
                Order(
                    field=Field(table="users", raw_name="name", display_name="user_name", field_type=FieldType.STRING),
                    order=pypikaOrder.desc,
                ),
            ],
        )
        generator = SQLGenerator(self.query_builder, config)
        query = generator.generate()
        expected_query = (
            'SELECT "users"."id" "user_id" ' 'FROM "users" "users" ORDER BY "users"."age" ASC,"users"."name" DESC'
        )
        self.assertEqual(str(query), expected_query, f"Expected: {expected_query}, but got: {query}")

    def test_group_by_with_having(self):
        """测试 GROUP BY 子句"""

        config = SqlConfig(
            select_fields=[
                Field(
                    table="users", raw_name="id", display_name="user_id", field_type=FieldType.INT, aggregate="COUNT"
                ),
                Field(table="users", raw_name="country", display_name="user_country", field_type=FieldType.STRING),
            ],
            from_table="users",
            group_by=[
                Field(table="users", raw_name="country", display_name="user_country", field_type=FieldType.STRING),
            ],
            where=WhereCondition(
                condition=Condition(
                    field=Field(
                        table="users", raw_name="country", display_name="user_country", field_type=FieldType.STRING
                    ),
                    operator=Operator.EQ,
                    filter="Ireland",
                )
            ),
        )
        generator = SQLGenerator(self.query_builder, config)
        query = generator.generate()
        expected_query = (
            'SELECT COUNT("users"."id") "user_id","users"."country" "user_country" '
            'FROM "users" "users" WHERE "users"."country"=\'Ireland\' GROUP BY "users"."country"'
        )
        self.assertEqual(str(query), expected_query, f"Expected: {expected_query}, but got: {query}")

    def test_auto_inferred_group_by(self):
        """
        测试自动推导 GROUP BY：如果没有指定 group_by，但存在聚合字段，则对非聚合字段进行分组
        """

        config = SqlConfig(
            select_fields=[
                Field(table="orders", raw_name="id", display_name="order_id", field_type=FieldType.INT),
                Field(
                    table="orders",
                    raw_name="amount",
                    display_name="amount_sum",
                    field_type=FieldType.INT,
                    aggregate=AggregateType.SUM,
                ),
            ],
            from_table="orders",
        )
        generator = SQLGenerator(self.query_builder, config)
        query = generator.generate()
        # 期望自动分组 "id"
        expected_query = (
            'SELECT "orders"."id" "order_id",SUM("orders"."amount") "amount_sum" '
            'FROM "orders" "orders" GROUP BY "orders"."id"'
        )
        self.assertEqual(str(query), expected_query, f"Expected: {expected_query}, got: {query}")

    def test_unsupported_operator(self):
        """测试不支持的 Operator 时抛出异常"""

        with self.assertRaises(ValidationError):
            config = SqlConfig(
                select_fields=[
                    Field(table="users", raw_name="id", display_name="user_id", field_type=FieldType.INT),
                ],
                from_table="users",
                where=WhereCondition(
                    condition=Condition(
                        field=Field(
                            table="users", raw_name="name", display_name="user_name", field_type=FieldType.STRING
                        ),
                        operator="unknown_op",  # 这里传入一个无效操作符
                        filter="test",
                        filters=[],
                    )
                ),
            )
            generator = SQLGenerator(self.query_builder, config)
            generator.generate()

    def test_nested_where_conditions(self):
        """
        测试复杂嵌套的 AND/OR 条件，仅使用 EQ / NEQ / REG / NREG / INCLUDE / EXCLUDE 操作符:
        """

        config = SqlConfig(
            select_fields=[
                Field(table="users", raw_name="id", display_name="user_id", field_type=FieldType.INT),
            ],
            from_table="users",
            where=WhereCondition(
                connector=FilterConnector.AND,  # 顶层使用 AND
                conditions=[
                    WhereCondition(
                        connector=FilterConnector.OR,  # 子条件使用 OR
                        conditions=[
                            WhereCondition(
                                condition=Condition(
                                    field=Field(
                                        table="users",
                                        raw_name="name",
                                        display_name="user_name",
                                        field_type=FieldType.STRING,
                                    ),
                                    operator=Operator.NEQ,  # name != 'David'
                                    filter="David",
                                    filters=[],
                                )
                            ),
                            WhereCondition(
                                condition=Condition(
                                    field=Field(
                                        table="users",
                                        raw_name="name",
                                        display_name="user_name",
                                        field_type=FieldType.STRING,
                                    ),
                                    operator=Operator.EQ,  # name = 'Jack'
                                    filter="Jack",
                                    filters=[],
                                )
                            ),
                        ],
                    ),
                    WhereCondition(
                        condition=Condition(
                            field=Field(
                                table="users",
                                raw_name="country",
                                display_name="user_country",
                                field_type=FieldType.STRING,
                            ),
                            operator=Operator.REG,  # country ~ '^Ire'
                            filter="^Ire",
                            filters=[],
                        )
                    ),
                ],
            ),
        )
        generator = SQLGenerator(self.query_builder, config)
        query = generator.generate()

        expected_query = (
            'SELECT "users"."id" "user_id" '
            'FROM "users" "users" '
            'WHERE ("users"."name"<>\'David\' OR "users"."name"=\'Jack\') AND "users"."country" REGEX \'^Ire\''
        )
        self.assertEqual(str(query), expected_query, f"Expected: {expected_query}, got: {query}")

    def test_multiple_aggregates(self):
        """测试同一条 SELECT 中包含多个聚合字段"""

        config = SqlConfig(
            select_fields=[
                Field(
                    table="orders",
                    raw_name="id",
                    display_name="order_count",
                    field_type=FieldType.INT,
                    aggregate=AggregateType.COUNT,
                ),
                Field(
                    table="orders",
                    raw_name="amount",
                    display_name="amount_max",
                    field_type=FieldType.INT,
                    aggregate=AggregateType.MAX,
                ),
                Field(table="orders", raw_name="status", display_name="status", field_type=FieldType.STRING),
            ],
            from_table="orders",
        )
        generator = SQLGenerator(self.query_builder, config)
        query = generator.generate()
        # 期望自动分组 "orders"."status"
        expected_query = (
            'SELECT COUNT("orders"."id") "order_count",MAX("orders"."amount") "amount_max","orders"."status" "status" '
            'FROM "orders" "orders" GROUP BY "orders"."status"'
        )
        self.assertEqual(str(query), expected_query, f"Expected: {expected_query}, got: {query}")

    def test_invalid_aggregate_type(self):
        """测试不支持的聚合类型时，是否正确抛出异常"""

        with self.assertRaises(ValidationError):
            config = SqlConfig(
                select_fields=[
                    Field(
                        table="orders",
                        raw_name="price",
                        display_name="price_custom",
                        field_type=FieldType.INT,
                        aggregate="INVALID_AGG",
                    ),
                ],
                from_table="orders",
            )
            generator = SQLGenerator(self.query_builder, config)
            generator.generate()

    def test_multi_join_simple_where(self):
        """
        测试多表联表 + 简单 WHERE 条件
        """

        config = SqlConfig(
            select_fields=[
                Field(table="users", raw_name="id", display_name="user_id", field_type=FieldType.INT),
                Field(table="orders", raw_name="order_id", display_name="order_id", field_type=FieldType.INT),
                Field(table="products", raw_name="name", display_name="product_name", field_type=FieldType.STRING),
            ],
            from_table="users",
            join_tables=[
                JoinTable(
                    join_type=JoinType.INNER_JOIN,
                    link_fields=[LinkField(left_field="id", right_field="user_id")],
                    left_table="users",
                    right_table="orders",
                ),
                JoinTable(
                    join_type=JoinType.LEFT_JOIN,
                    link_fields=[LinkField(left_field="product_id", right_field="id")],
                    left_table="orders",
                    right_table="products",
                ),
            ],
            where=WhereCondition(
                condition=Condition(
                    field=Field(
                        table="users", raw_name="country", display_name="user_country", field_type=FieldType.STRING
                    ),
                    operator=Operator.EQ,
                    filter="Ireland",
                    filters=[],
                )
            ),
        )
        generator = SQLGenerator(self.query_builder, config)
        query = generator.generate()
        expected_query = (
            'SELECT "users"."id" "user_id","orders"."order_id" "order_id","products"."name" "product_name" '
            'FROM "users" "users" '
            'JOIN "orders" "orders" '
            'ON "users"."id"="orders"."user_id" '
            'LEFT JOIN "products" "products" '
            'ON "orders"."product_id"="products"."id" '
            'WHERE "users"."country"=\'Ireland\''
        )
        self.assertEqual(str(query), expected_query, f"Expected: {expected_query}, got: {query}")

    def test_multi_join_nested_where(self):
        """
        测试多表联表 + 复杂嵌套 WHERE 条件
        """

        config = SqlConfig(
            select_fields=[
                Field(table="users", raw_name="id", display_name="user_id", field_type=FieldType.INT),
            ],
            from_table="users",
            join_tables=[
                JoinTable(
                    join_type=JoinType.INNER_JOIN,
                    link_fields=[LinkField(left_field="id", right_field="user_id")],
                    left_table="users",
                    right_table="orders",
                ),
                JoinTable(
                    join_type=JoinType.LEFT_JOIN,
                    link_fields=[LinkField(left_field="product_id", right_field="id")],
                    left_table="orders",
                    right_table="products",
                ),
            ],
            where=WhereCondition(
                connector=FilterConnector.AND,
                conditions=[
                    # 条件A: (users.name != 'David' OR users.name = 'Jack')
                    WhereCondition(
                        connector=FilterConnector.OR,
                        conditions=[
                            WhereCondition(
                                condition=Condition(
                                    field=Field(
                                        table="users",
                                        raw_name="name",
                                        display_name="user_name",
                                        field_type=FieldType.STRING,
                                    ),
                                    operator=Operator.NEQ,
                                    filter="David",
                                    filters=[],
                                )
                            ),
                            WhereCondition(
                                condition=Condition(
                                    field=Field(
                                        table="users",
                                        raw_name="name",
                                        display_name="user_name",
                                        field_type=FieldType.STRING,
                                    ),
                                    operator=Operator.EQ,
                                    filter="Jack",
                                    filters=[],
                                )
                            ),
                        ],
                    ),
                    # 条件B
                    WhereCondition(
                        connector=FilterConnector.AND,
                        conditions=[
                            WhereCondition(
                                connector=FilterConnector.OR,
                                conditions=[
                                    WhereCondition(
                                        condition=Condition(
                                            field=Field(
                                                table="orders",
                                                raw_name="status",
                                                display_name="order_status",
                                                field_type=FieldType.STRING,
                                            ),
                                            operator=Operator.EQ,
                                            filter="pending",
                                            filters=[],
                                        )
                                    ),
                                    WhereCondition(
                                        condition=Condition(
                                            field=Field(
                                                table="orders",
                                                raw_name="status",
                                                display_name="order_status",
                                                field_type=FieldType.STRING,
                                            ),
                                            operator=Operator.NEQ,
                                            filter="canceled",
                                            filters=[],
                                        )
                                    ),
                                ],
                            ),
                            WhereCondition(
                                condition=Condition(
                                    field=Field(
                                        table="products",
                                        raw_name="category",
                                        display_name="product_category",
                                        field_type=FieldType.STRING,
                                    ),
                                    operator=Operator.REG,
                                    filter="^food$",
                                    filters=[],
                                )
                            ),
                        ],
                    ),
                ],
            ),
        )
        generator = SQLGenerator(self.query_builder, config)
        query = generator.generate()
        expected_query = (
            'SELECT "users"."id" "user_id" '
            'FROM "users" "users" '
            'JOIN "orders" "orders" ON "users"."id"="orders"."user_id" '
            'LEFT JOIN "products" "products" ON "orders"."product_id"="products"."id" '
            'WHERE ("users"."name"<>\'David\' OR "users"."name"=\'Jack\') AND '
            '("orders"."status"=\'pending\' OR "orders"."status"<>\'canceled\') '
            'AND "products"."category" REGEX \'^food$\''
        )
        self.assertEqual(str(query), expected_query, f"Expected: {expected_query}, got: {query}")

    def test_join_with_aggregation_and_group_by(self):
        """
        测试联表 + 聚合函数 + 显式分组
        """

        config = SqlConfig(
            select_fields=[
                Field(
                    table="orders",
                    raw_name="price",
                    display_name="total_price",
                    field_type=FieldType.INT,
                    aggregate="SUM",
                ),
                Field(
                    table="users",
                    raw_name="country",
                    display_name="user_country",
                    field_type=FieldType.STRING,
                ),
            ],
            from_table="users",
            join_tables=[
                JoinTable(
                    join_type=JoinType.INNER_JOIN,
                    link_fields=[LinkField(left_field="id", right_field="user_id")],
                    left_table="users",
                    right_table="orders",
                )
            ],
            where=WhereCondition(
                condition=Condition(
                    field=Field(
                        table="users", raw_name="country", display_name="user_country", field_type=FieldType.STRING
                    ),
                    operator=Operator.EQ,
                    filter="Ireland",
                    filters=[],
                )
            ),
            group_by=[
                Field(table="users", raw_name="country", display_name="user_country", field_type=FieldType.STRING),
            ],
        )
        generator = SQLGenerator(self.query_builder, config)
        query = generator.generate()
        expected_query = (
            'SELECT SUM("orders"."price") "total_price","users"."country" "user_country" '
            'FROM "users" "users" '
            'JOIN "orders" "orders" ON "users"."id"="orders"."user_id" '
            'WHERE "users"."country"=\'Ireland\' '
            'GROUP BY "users"."country"'
        )
        self.assertEqual(str(query), expected_query, f"Expected: {expected_query}, got: {query}")

    def test_join_with_auto_group_by(self):
        """
        当 group_by 未指定，但出现聚合字段 + 非聚合字段时，应自动对非聚合字段进行分组
        """

        config = SqlConfig(
            select_fields=[
                # 聚合字段
                Field(
                    table="orders",
                    raw_name="price",
                    display_name="total_price",
                    field_type=FieldType.INT,
                    aggregate=AggregateType.SUM,
                ),
                # 非聚合字段
                Field(
                    table="orders",
                    raw_name="status",
                    display_name="order_status",
                    field_type=FieldType.STRING,
                ),
            ],
            from_table="users",
            join_tables=[
                JoinTable(
                    join_type=JoinType.INNER_JOIN,
                    link_fields=[LinkField(left_field="id", right_field="user_id")],
                    left_table="users",
                    right_table="orders",
                )
            ],
        )
        generator = SQLGenerator(self.query_builder, config)
        query = generator.generate()
        expected_query = (
            'SELECT SUM("orders"."price") "total_price","orders"."status" "order_status" '
            'FROM "users" "users" '
            'JOIN "orders" "orders" ON "users"."id"="orders"."user_id" '
            'GROUP BY "orders"."status"'
        )
        self.assertEqual(str(query), expected_query, f"Expected: {expected_query}, got: {query}")

    def test_join_with_order_by_and_pagination(self):
        """
        测试联表 + 排序 + 分页
        """

        config = SqlConfig(
            select_fields=[
                Field(table="users", raw_name="id", display_name="user_id", field_type=FieldType.INT),
                Field(table="orders", raw_name="order_id", display_name="order_id", field_type=FieldType.INT),
            ],
            from_table="users",
            join_tables=[
                JoinTable(
                    join_type=JoinType.INNER_JOIN,
                    link_fields=[LinkField(left_field="id", right_field="user_id")],
                    left_table="users",
                    right_table="orders",
                )
            ],
            order_by=[
                Order(
                    field=Field(
                        table="orders", raw_name="created_at", display_name="created_at", field_type=FieldType.STRING
                    ),
                    order=pypikaOrder.desc,
                )
            ],
            pagination=Pagination(limit=10, offset=20),
        )
        generator = SQLGenerator(self.query_builder, config)
        query = generator.generate()
        expected_query = (
            'SELECT "users"."id" "user_id","orders"."order_id" "order_id" '
            'FROM "users" "users" '
            'JOIN "orders" "orders" ON "users"."id"="orders"."user_id" '
            'ORDER BY "orders"."created_at" DESC '
            'LIMIT 10 OFFSET 20'
        )
        self.assertEqual(str(query), expected_query, f"Expected: {expected_query}, got: {query}")


if __name__ == "__main__":
    unittest.main()
