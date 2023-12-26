/*
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
*/
export default {
  riskManage: {
    '事件ID：': 'Event ID: ',
    事件证据: 'Event evidence',
    所有风险: 'All',
    '解除误报后，风险单会重新打开至“待处理”请谨慎确认是否解除误报？': 'After the false positive is released, the risk ticket will be reopened to "Open" status. Please confirm carefully whether to release the false positive.',
    '策略方案可能采集误报数据作为优化依据，请谨慎确认是否为误报？': 'The strategy may collect false positive data as optimization basis. Please confirm carefully whether it is a false positive.',
    '标记误报后，风险单会自动关闭，请谨慎确认是否为误报？': 'After marking as false positive, the risk ticket will be automatically closed. Please confirm carefully whether it is a false positive.',
    '标记误报后，风险单会在套餐处理结束（终止）后自动关闭，请谨慎确认是否为误报？': 'After marking as false positive, the risk ticket will be automatically closed when the tool processing is finished (or terminated). Please confirm carefully whether it is a false positive.',
    '解除误报后，风险单会按原流程继续执行，请谨慎确认是否解除误报？': 'After releasing the false positive, the risk ticket will continue to execute the unfinished processing tool. Please confirm carefully whether to release the false positive.',
    '确认解除误报？': 'Are you sure to release the false positive ?',
    '确认标记误报？': 'Are you sure to marking the risk ticket as false positive ?',
    误报说明: 'False positive description',
    解除: 'Release',
    标记: 'Mark',
    解除误报成功: 'Successfully released false positive.',
    标记误报成功: 'Successfully marked false positive',
    '“套餐处理中”的风险单暂时不支持直接标记误报；请点开风险单详情，终止套餐或等套餐执行完毕后再标记误报。': 'Cannot marking as "false positive" if the risk ticket is in "Processing" status, Please wait until the tool processing finished or terminated.',
    '“套餐处理中”的风险单暂时不支持直接解除误报；请点开风险单详情，终止套餐或等套餐执行完毕后再标记误报。': 'Cannot release "false positive" if the risk ticket is in "Processing" status, Please wait until the tool processing finished or terminated.',
    '风险命中策略(ID)': 'Related strategy(ID)',
    风险标记: 'Tagging',
    通知人员: 'Notify to',
    当前处理人: 'Assigned to',
    首次发现时间: 'First detected time',
    最后一次处理时间: 'Last processing time',
    标记误报: 'Mark as F.P.',
    风险命中策略: 'Related strategy',
    风险标签: 'Tags',
    请选择责任人: 'Responsible by',
    请选择当前处理人: 'Assign to',
    '已填写“风险总结”': 'Risk summary',
    人工处理: 'Manual Processing',
    风险单产生: 'Ticket Generated',
    误报: 'False Positive',
    重开单据: 'Reopen ticket',
    执行前审批: 'Pre-Approval',
    执行套餐动作: 'Tool action',
    风险单关闭: 'Risk closed',
    误报说明不能为空: 'False Positive mark up description is required',
    处理人不能为空: 'Assignee is required',
    解除误报: 'Release F.P.',
    '事件 id': 'Event ID',
    事件数据字段: 'Event data field',
    '命中策略(ID)': 'Related strategy(ID)',
    最后发现时间: 'Last detected time',
    转单: 'Reassignment',
    处理方法: 'Processing by',
    处理说明: 'Description',
    人工关单: 'Manual Closed',
    审批结果: 'Approval result',
    关联单据: 'Related ticket',
    执行处理套餐: 'Execute Processing Tool',
    转单人不能为空: 'Reassign to is required',
    说明不能为空: 'Description is required',
    不通过: 'Approval not passed',
    正在审批中: 'In approval',
    任务名称: 'Task name',
    任务状态: 'Task status',
    强制终止: 'Force terminated',
    执行结束时间: 'Finished at',
    执行开始时间: 'Launched at',
    添加风险总结: 'Add risk summary',
    编辑风险总结: 'Edit risk summary',
    人工处理提交处理套餐成功: 'Successfully launched tool',
    人工关单成功: 'Ticket has been successfully closed.',
    当前状态不支持人工处理: 'Manual processing is not supported in current state.',
    自动处理失败: 'Auto processing failed.',
    重试成功: 'Success',
    '指定处理人：': 'Assignee:',
    '解除误报，系统自动重开单据': 'The ticket will automatically reopen if the false positive is released.',
    原套餐继续执行: 'The original tool will continue to execute.',
    近一周: 'Last 1 week',
    近一个月: 'Last 1 month',
    近三个月: 'Last 3 months',
    近半年: 'Last half year',
    近一年: 'Last 1 year',
    强制终止执行中: 'Force terminating',
    处理: 'Detail',
    请输入人员: 'Enter username here...',
    转单人员: 'Transfer to',
    '解除误报后，风险单会重新打开至“待处理” 请谨慎确认是否解除误报？': 'After the false positive is released, the risk ticket will be reopened to "Open" status. Please confirm carefully whether to release the false positive.',
    审计报表: 'Analysis',
  },
};
