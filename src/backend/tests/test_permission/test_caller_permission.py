# -*- coding: utf-8 -*-
from unittest import mock

from django.test import TestCase

from core.exceptions import PermissionException
from services.web.common.caller_permission import (
    extract_extra_variables,
    is_tool_related_to_risk,
    should_skip_permission,
    should_skip_permission_from,
)
from services.web.tool.serializers import ExecuteToolReqSerializer


class TestCallerPermission(TestCase):
    def test_should_skip_permission_risk_allowed(self):
        with mock.patch("services.web.common.caller_permission.RiskCallerPermission.has_permission", return_value=True):
            self.assertTrue(should_skip_permission("risk", "R123", username="u1"))

    def test_should_skip_permission_risk_denied(self):
        with mock.patch(
            "services.web.common.caller_permission.RiskCallerPermission.has_permission",
            return_value=False,
            side_effect=PermissionException(action_name="list_risk", permission={}, apply_url=""),
        ):
            with self.assertRaises(PermissionException):
                should_skip_permission("risk", "R123", username="u1")

    def test_should_skip_permission_unsupported_type(self):
        self.assertFalse(should_skip_permission("unknown", "RID", username="u1"))

    def test_serializer_choice_validation(self):
        # 非法的 caller_resource_type 应校验失败
        s = ExecuteToolReqSerializer(
            data={"uid": "u", "params": {}, "caller_resource_type": "unsupported", "caller_resource_id": "1"}
        )
        self.assertFalse(s.is_valid())
        self.assertIn("caller_resource_type", s.errors)

    @mock.patch("services.web.risk.permissions.RiskViewPermission.has_risk_permission", return_value=True)
    def test_skip_when_tool_related_to_risk(self, _):
        # 构造策略、风险与工具关联
        from django.utils import timezone

        from services.web.risk.models import Risk
        from services.web.strategy_v2.constants import StrategyFieldSourceEnum
        from services.web.strategy_v2.models import Strategy, StrategyTool

        strategy = Strategy.objects.create(namespace="ns", strategy_name="s1")
        # 风险关联到策略
        risk = Risk.objects.create(
            raw_event_id="e1",
            strategy=strategy,
            event_time=timezone.now(),
        )
        # 策略与工具建立关联
        StrategyTool.objects.create(
            strategy=strategy,
            tool_uid="T1",
            tool_version=1,
            field_name="f1",
            field_source=StrategyFieldSourceEnum.BASIC.value,
        )

        data = {"caller_resource_type": "risk", "caller_resource_id": risk.risk_id, "uid": "T1"}
        self.assertTrue(should_skip_permission_from(data, username="u1"))

    @mock.patch("services.web.risk.permissions.RiskViewPermission.has_risk_permission", return_value=True)
    def test_no_skip_when_tool_not_related(self, _):
        # 构造策略、风险，但不建立指定工具关联
        from django.utils import timezone

        from services.web.risk.models import Risk
        from services.web.strategy_v2.models import Strategy

        strategy = Strategy.objects.create(namespace="ns", strategy_name="s2")
        risk = Risk.objects.create(
            raw_event_id="e2",
            strategy=strategy,
            event_time=timezone.now(),
        )

        data = {"caller_resource_type": "risk", "caller_resource_id": risk.risk_id, "tool_uid": "UnRelatedTool"}
        self.assertFalse(should_skip_permission_from(data, username="u1"))

    def test_is_tool_related_to_risk_edge_cases(self):
        # 风险不存在
        self.assertFalse(is_tool_related_to_risk("R-not-exist", "T1"))

    def test_extract_extra_variables(self):
        # 优先读取 tool_uid
        self.assertEqual(extract_extra_variables({"tool_uid": "T1", "uid": "T2"}).get("tool_uid"), "T1")
