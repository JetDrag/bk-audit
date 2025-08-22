# -*- coding: utf-8 -*-
"""
调用方资源权限判定的统一入口。

当前支持：
- risk：当携带 caller_resource_type=risk 与 caller_resource_id 时，校验用户是否有风险查看权限；
  通过则允许跳过原有工具/报表权限校验。

后续如有新增类型，请按策略注册方式扩展。
"""
from __future__ import annotations

from collections.abc import Mapping as _Mapping
from contextlib import suppress
from enum import Enum
from typing import Any, Dict, Optional, Tuple, Type

from apps.permission.handlers.actions import ActionEnum
from apps.permission.handlers.resource_types import ResourceEnum


class BaseCallerPermission:
    """调用方资源权限判定策略抽象类"""

    def has_permission(self, instance_id: str, username: str, **kwargs) -> bool:  # pragma: no cover - 简单封装
        raise NotImplementedError


class RiskCallerPermission(BaseCallerPermission):
    def has_permission(self, instance_id: str, username: str, **kwargs) -> bool:
        from services.web.risk.permissions import RiskViewPermission

        perm = RiskViewPermission(actions=[ActionEnum.LIST_RISK], resource_meta=ResourceEnum.RISK)
        # 1) 先校验风险查看权限（失败会抛出权限异常，成功继续）
        perm.has_risk_permission(instance_id, username)

        # 2) 如传入 tool_uid，则校验该风险所属策略是否关联该工具
        tool_uid = kwargs.get("tool_uid")
        if not tool_uid:
            # 未指定工具ID，仅基于风险权限放行（允许跳过原有工具权限）
            return True
        return is_tool_related_to_risk(instance_id, tool_uid)


# 权限处理器注册表：resource_type -> 权限处理器
# 受支持的调用者资源类型
class CallerResourceType(str, Enum):
    RISK = "risk"


CALLER_RESOURCE_TYPE_CHOICES = tuple((i.value, i.value) for i in CallerResourceType)

_CALLER_PERMISSIONS: Dict[str, Type[BaseCallerPermission]] = {
    CallerResourceType.RISK.value: RiskCallerPermission,
}


def should_skip_permission(
    caller_resource_type: Optional[str], caller_resource_id: Optional[str], username: str, **kwargs
) -> bool:
    """
    依据调用方资源上下文判断是否跳过原有权限校验。

    返回：
      - True：已验证调用方资源权限，通过，允许跳过后续原有权限校验；
      - False：未命中或不支持该类型，走原有权限校验。
    """

    if not caller_resource_type or not caller_resource_id:
        return False

    rtype = str(caller_resource_type).lower()
    permission_handler = _CALLER_PERMISSIONS.get(rtype)
    if not permission_handler:
        return False

    if permission_handler().has_permission(caller_resource_id, username, **kwargs):
        return True
    return False


def extract_caller_context(source: Any) -> Tuple[Optional[str], Optional[str]]:
    """从 dict 或 request 中提取 caller_resource_type 与 caller_resource_id"""
    crt = None
    cri = None

    if isinstance(source, _Mapping):
        crt = source.get("caller_resource_type")
        cri = source.get("caller_resource_id")
        return crt, cri
    for attr in ("data", "query_params"):
        if hasattr(source, attr):
            with suppress(Exception):
                crt = getattr(source, attr).get("caller_resource_type")
                cri = getattr(source, attr).get("caller_resource_id")
    return crt, cri


def extract_extra_variables(source: Any) -> Dict[str, Any]:
    """
    从 dict 或 request 中提取额外上下文参数，形成动态 kwargs。
    当前支持：
      - tool_uid：优先取 tool_uid，其次兼容 uid 字段
    """
    extra: Dict[str, Any] = {}

    def _collect(mapping: _Mapping):
        with suppress(Exception):
            for variable in ("tool_uid",):
                value = mapping.get(variable)
                if value:
                    extra[variable] = value

    if isinstance(source, _Mapping):
        _collect(source)
    else:
        for attr in ("data", "query_params"):
            if hasattr(source, attr):
                _collect(getattr(source, attr))
    return extra


def is_tool_related_to_risk(risk_id: str, tool_uid: str) -> bool:
    """
    校验指定风险的策略是否关联给定工具。
    返回 True 表示存在关联，False 表示不存在或无法定位。
    """
    from services.web.risk.models import Risk
    from services.web.strategy_v2.models import StrategyTool

    strategy_id = Risk.objects.filter(risk_id=risk_id).values_list("strategy_id", flat=True).first()
    if not strategy_id:
        return False
    return StrategyTool.objects.filter(strategy_id=strategy_id, tool_uid=tool_uid).exists()


def should_skip_permission_from(source: Any, username: str) -> bool:
    crt, cri = extract_caller_context(source)
    extras = extract_extra_variables(source)
    return should_skip_permission(crt, cri, username, **extras)
