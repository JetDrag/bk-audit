# -*- coding: utf-8 -*-
from unittest import mock

from core.exceptions import PermissionException
from core.models import get_request_username
from services.web.tool.constants import ToolTypeEnum
from services.web.tool.exceptions import BkVisionSearchPermissionProhibited
from services.web.tool.models import BkVisionToolConfig, Tool
from services.web.vision.models import Scenario, VisionPanel

from ..base import TestCase


class TestToolViewPermissions(TestCase):
    def setUp(self):
        self.current_user = get_request_username() or "admin"

        # 创建两个 BK Vision 工具：一个归当前用户所有，一个归他人所有
        self.owner_tool = Tool.objects.create(
            namespace="ns",
            name="owner_vision_tool",
            uid="owner_vision_tool_uid",
            version=1,
            tool_type=ToolTypeEnum.BK_VISION.value,
            config={"uid": "owner_panel_uid", "input_variable": []},
            updated_by=self.current_user,
        )
        self.owner_panel = VisionPanel.objects.create(
            id="owner_panel_id",
            vision_id="owner_panel_uid",
            scenario=Scenario.TOOL.value,
            handler="VisionHandler",
        )
        BkVisionToolConfig.objects.create(tool=self.owner_tool, panel=self.owner_panel)

        self.other_tool = Tool.objects.create(
            namespace="ns",
            name="other_vision_tool",
            uid="other_vision_tool_uid",
            version=1,
            tool_type=ToolTypeEnum.BK_VISION.value,
            config={"uid": "other_panel_uid", "input_variable": []},
            updated_by="someone_else",
        )
        self.other_panel = VisionPanel.objects.create(
            id="other_panel_id",
            vision_id="other_panel_uid",
            scenario=Scenario.TOOL.value,
            handler="VisionHandler",
        )
        BkVisionToolConfig.objects.create(tool=self.other_tool, panel=self.other_panel)

    def tearDown(self):
        mock.patch.stopall()

    def test_execute_with_caller_context_allowed(self):
        # 调用方上下文有权限，应放行（即使非创建/更新者）
        with mock.patch("services.web.common.caller_permission.RiskCallerPermission.has_permission", return_value=True):
            result = self.resource.tool.execute_tool(
                {
                    "uid": self.other_tool.uid,
                    "params": {},
                    "caller_resource_type": "risk",
                    "caller_resource_id": "RID-1",
                }
            )
        self.assertEqual(result["tool_type"], ToolTypeEnum.BK_VISION.value)
        self.assertEqual(result["data"]["panel_id"], self.other_panel.id)

    def test_execute_with_caller_context_denied_raises(self):
        # 调用方上下文无权限，应抛权限异常
        with mock.patch(
            "services.web.common.caller_permission.RiskCallerPermission.has_permission",
            return_value=False,
            side_effect=PermissionException(action_name="list_risk", permission={}, apply_url=""),
        ):
            with self.assertRaises(PermissionException):
                self.resource.tool.execute_tool(
                    {
                        "uid": self.other_tool.uid,
                        "params": {},
                        "caller_resource_type": "risk",
                        "caller_resource_id": "RID-2",
                    }
                )

    def test_execute_as_owner_allowed(self):
        # 工具更新者应始终放行
        with mock.patch(
            "services.web.tool.permissions.api.bk_vision.check_share_auth", return_value={"check_result": True}
        ):
            result = self.resource.tool.execute_tool({"uid": self.owner_tool.uid, "params": {}})
        self.assertEqual(result["tool_type"], ToolTypeEnum.BK_VISION.value)
        self.assertEqual(result["data"]["panel_id"], self.owner_panel.id)

    def test_execute_without_caller_and_not_owner_denied(self):
        # 非调用方上下文，且无图标使用权限 -> 应抛权限异常
        with (
            mock.patch(
                "services.web.tool.permissions.api.bk_vision.check_share_auth", return_value={"check_result": False}
            )
        ):
            with self.assertRaises(BkVisionSearchPermissionProhibited):
                self.resource.tool.execute_tool({"uid": self.other_tool.uid, "params": {}})
