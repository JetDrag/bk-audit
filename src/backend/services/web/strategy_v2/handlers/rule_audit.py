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
from typing import List, Optional

from django.shortcuts import get_object_or_404
from pydantic import BaseModel
from pypika import CustomFunction
from pypika.terms import Function, ValueWrapper

from apps.meta.utils.fields import SYSTEM_ID
from core.sql.builder import BKBaseQueryBuilder
from core.sql.constants import FilterConnector, Operator
from core.sql.model import (
    Condition,
    Field,
    JoinTable,
    LinkField,
    SqlConfig,
    WhereCondition,
)
from core.sql.sql_builder import SQLGenerator
from services.web.risk.constants import EventMappingFields
from services.web.strategy_v2.constants import LinkTableTableType, RuleAuditConfigType
from services.web.strategy_v2.exceptions import LinkTableConfigError
from services.web.strategy_v2.models import LinkTable, Strategy


class JsonObject(CustomFunction):
    def __init__(self):
        super().__init__('JSON_OBJECT', ["*"])

    def __call__(self, *args, **kwargs) -> Function:
        return Function(self.name, *args, alias=kwargs.get("alias"))


class FieldMap(BaseModel):
    """
    字段映射,来源字段和固定值至少设置一个,优先级：固定值>来源字段
    """

    source_field: Optional[str] = None  # 来源字段的display_name
    target_value: Optional[str] = None  # 固定值


class RuleAuditSQLGenerator:
    """
    规则审计 SQL 生成器
    """

    def __init__(self, strategy: Strategy):
        self.strategy = strategy
        self.query_builder = BKBaseQueryBuilder()

    def parse_where_condition(self, where_json: dict) -> WhereCondition:
        """
        解析前端的 where JSON，转换为内部 WhereCondition（可能是一个条件组或单个条件）。
        """
        connector = where_json["connector"]

        # 如果是单个 condition
        if condition := where_json.get("condition"):
            return WhereCondition(
                connector=connector,
                condition=self.parse_single_condition(condition),
            )

        # 否则是条件组
        sub_conditions = []
        for sub_json in where_json.get("conditions", []):
            sub_conditions.append(self.parse_where_condition(sub_json))

        return WhereCondition(
            connector=connector,
            conditions=sub_conditions,
        )

    def parse_single_condition(self, cond_json: dict) -> Condition:
        """
        解析前端单条 condition，转换为内部 Condition 对象。
        """
        return Condition(
            field=self.trans_field(cond_json["field"]),
            operator=cond_json["operator"],
            filters=cond_json.get("filters", []),
            filter=cond_json.get("filter", ""),
        )

    def trans_field(self, field_json: dict) -> Field:
        """
        将前端传来的字段描述转换为 SQLGenerator 的 Field 对象。
        """
        return Field(
            table=field_json["rt_id"],  # 这里直接把 rt_id 当做 table 名
            raw_name=field_json["raw_name"],
            display_name=field_json["display_name"],
            field_type=field_json["field_type"],
            aggregate=field_json.get("aggregate"),
        )

    def build_system_ids_condition(self, table_rt_id: str, system_ids: list) -> WhereCondition:
        """
        根据给定的表 rt_id 及 system_ids 列表，构建一个 AND 条件，用于拼接到最终的 WHERE 中。
        """
        system_condition = Condition(
            field=Field(
                table=table_rt_id,
                raw_name=SYSTEM_ID.field_name,
                display_name=SYSTEM_ID.alias_name,
                field_type=SYSTEM_ID.field_type,
            ),
            operator=Operator.INCLUDE,
            filters=system_ids,
        )
        return WhereCondition(connector=FilterConnector.AND, condition=system_condition)

    def build_single_table_config(self, data_source: dict) -> (str, list, dict):
        """
        处理单表场景，返回:
         - from_table: str
         - join_tables: 空列表 (单表无 join)
         - tables_with_system_ids: {rt_id: [system_ids]}
        """
        from_table = data_source["rt_id"]
        system_ids = data_source.get("system_ids", [])
        tables_with_system_ids = {from_table: system_ids}
        return from_table, [], tables_with_system_ids

    def build_link_table_config(self, data_source: dict) -> (str, list, dict):
        """
        处理联表场景，从 link_table 配置中构建:
         - from_table: 主表
         - join_tables: List[JoinTable]
         - tables_with_system_ids: {rt_id: [system_ids]}
        """
        link_table_uid = data_source["link_table"]["uid"]
        link_table_version = data_source["link_table"]["version"]

        link_table_obj = get_object_or_404(LinkTable, uid=link_table_uid, version=link_table_version)
        link_config = link_table_obj.config
        links = link_config.get("links", [])

        if not links:
            raise LinkTableConfigError(data=link_config)

        # 确定主表 (from_table)
        first_link = links[0]
        from_table = first_link["left_table"]["rt_id"]
        join_tables = []
        tables_with_system_ids = {}

        for lk in links:
            left_table = lk["left_table"]
            right_table = lk["right_table"]

            # 如果 left_table 或 right_table 是 EVENT_LOG，则将它们的 system_ids 收集起来
            if left_table["table_type"] == LinkTableTableType.EVENT_LOG:
                tables_with_system_ids[left_table["rt_id"]] = left_table.get("system_ids", [])
            if right_table["table_type"] == LinkTableTableType.EVENT_LOG:
                tables_with_system_ids[right_table["rt_id"]] = right_table.get("system_ids", [])

            # link_fields
            link_fields_list = [
                LinkField(left_field=lf["left_field"], right_field=lf["right_field"]) for lf in lk["link_fields"]
            ]

            # 构建 JoinTable
            join_tables.append(
                JoinTable(
                    join_type=lk["join_type"],
                    link_fields=link_fields_list,
                    left_table=left_table["rt_id"],
                    right_table=right_table["rt_id"],
                )
            )

        return from_table, join_tables, tables_with_system_ids

    def format(self, config_json: dict) -> SqlConfig:
        """
        将前端 JSON 配置转换为可供 SQLGenerator 使用的 SqlConfig。
        """
        config_type = config_json["config_type"]
        data_source = config_json["data_source"]

        # Step A. 解析 select_fields
        select_fields_json = config_json.get("select", [])
        select_fields = [self.trans_field(f_json) for f_json in select_fields_json]

        # Step B. 根据 config_type 构建 from_table, join_tables, tables_with_system_ids
        if config_type == RuleAuditConfigType.LINK_TABLE:
            from_table, join_tables, tables_with_system_ids = self.build_link_table_config(data_source)
        else:
            from_table, join_tables, tables_with_system_ids = self.build_single_table_config(data_source)

        # Step C. 构建前端传入的 where 条件
        where_json = config_json.get("where")
        conditions_to_merge = []
        if where_json:
            front_where = self.parse_where_condition(where_json)
            conditions_to_merge.append(front_where)

        # Step D. 为每个包含 system_ids 的表构建条件
        for rt_id, system_ids in tables_with_system_ids.items():
            if not system_ids:  # 若没有 system_ids，可根据需要决定是否忽略或抛异常
                continue
            system_ids_where = self.build_system_ids_condition(rt_id, system_ids)
            conditions_to_merge.append(system_ids_where)

        # Step E. 合并所有条件
        final_where = None
        if conditions_to_merge:
            final_where = WhereCondition(connector=FilterConnector.AND, conditions=conditions_to_merge)

        # Step F. 构造 SqlConfig 并返回
        return SqlConfig(
            select_fields=select_fields,
            from_table=from_table,
            join_tables=join_tables,
            where=final_where,
        )

    def build_sql(self) -> str:
        """
        将规则审计策略生成 sql
        field_mapping 中的 key 为 select 中的字段名，value 为 FieldMap 对象,用于映射字段
        """

        config_json: dict = self.strategy.configs
        event_basic_field_configs: List[dict] = self.strategy.event_basic_field_configs
        field_mapping = {
            field["field_name"]: FieldMap(**field["map_config"])
            for field in event_basic_field_configs
            if field.get("map_config")
        }
        # 1. 生成子查询 (sub_table)
        sql_config = self.format(config_json)
        sub_table = SQLGenerator(query_builder=self.query_builder, config=sql_config).generate().as_("sub_table")
        # 2. 构造 JSON_OBJECT(...) 参数
        json_obj_args = []
        for field in sql_config.select_fields:
            json_obj_args.extend([ValueWrapper(field.display_name), sub_table.field(field.display_name)])
        # 3. 最外层 select 列表
        #    3.1 JSON_OBJECT(...) => event_data
        #    3.2 strategy_id => strategy_id
        #    3.3 其他字段 => 来自 field_mapping
        select_fields = [
            JsonObject()(*json_obj_args).as_(EventMappingFields.EVENT_DATA.field_name),
            ValueWrapper(self.strategy.strategy_id, EventMappingFields.STRATEGY_ID.field_name),
        ]
        for field_name, map_config in field_mapping.items():
            if map_config.target_value:
                select_fields.append(ValueWrapper(map_config.target_value, field_name))
            elif map_config.source_field:
                select_fields.append(sub_table.field(map_config.source_field).as_(field_name))
        # 4. 构建最终查询: from sub_table select ...
        return str(self.query_builder.from_(sub_table).select(*select_fields))
