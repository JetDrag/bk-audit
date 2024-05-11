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
  strategyManage: {
    审计策略: 'Strategies',
    全部策略: 'All',
    编辑策略: 'Edit Strategy',
    新建策略: 'New Strategy',
    策略详情: 'Strategy Details',
    策略名称: 'Name',
    策略类型: 'Type',
    启停: 'On / Off',
    '启/停': 'On / Off',
    查看: 'Detail',
    克隆: 'Clone',
    常规策略: 'General',
    AI策略: 'AI strategy',
    基础配置: 'Basic Information',
    该系统暂未接入审计中心: 'The system is not  accessible',
    请输入策略名称: 'Please enter the strategy name',
    请输入策略名称进行搜索: 'Type strategy name to search',
    '策略名称不超过 32 个字符': 'Strategy name cannot exceed 32 characters',
    '策略名称仅支持：中文A-Za-z0-9_': 'Strategy name only supports: A-Za-z0-9_',
    类型: 'Type',
    筛选条件: 'Filtering',
    触发规则: 'Trigger rules',
    点击切换: 'Click to switch',
    添加条件: 'Add condition',
    是否启用该策略: 'Do you want to enable this strategy ?',
    暂不启用: 'No',
    '启用策略将开始按照策略进行审计并输出异常事件，请确认是否启用该策略': 'Enabling the strategy will start auditing according to the strategy and outputting abnormal events. Please confirm whether to enable this strategy.',
    请选择: 'Please select',
    输入并回车可创建新标签: 'Enter the name and press Enter to create new tag',
    请输入并Enter结束: 'Press Enter to finish',
    请输入: 'Please enter...',
    无匹配数据: 'No match data',
    '无匹配数据, 敲击Enter可创建新标签': 'Press Enter to create new one if no tag matched',
    标签不能为空: 'Tag is required',
    统计字段不能为空: 'Statistical fields is required',
    通知组不能为空: 'Notification Group is required',
    内置策略: 'Built-in',
    保存: 'Save',
    数据匹配次数: 'f data matching times',
    '“内置策略”是官方团队从安全审计专业角度出发，直接提供的常用安全审计策略方法；由平台直接更新维护，无需用户配置升级，直接应用即可。': '"Built-in strategy" is a common security audit strategy method directly provided by the official team from the perspective of the security audit profession; It is directly updated and maintained by the platform, and can be directly applied without user configuration upgrade.',
    '“AI策略”是官方团队从安全审计专业角度出发，直接提供的常用安全审计策略方法；由平台直接更新维护，无需用户配置升级，直接应用即可。': '"AI strategy" is a common security audit strategy method directly provided by the official team from the perspective of the security audit profession; It is directly updated and maintained by the platform, and can be directly applied without user configuration upgrade.',
    '“内置策略”是官方团队从安全审计专业角度出发，直接提供的常用安全审计策略方法；由平台直接更新维护，不可删除。': '"Built-in strategy" is a common security audit strategy method directly provided by the official team from the perspective of the security audit profession; It is directly updated and maintained by the platform, cannot be deleted.',
    '“AI策略”是官方团队从安全审计专业角度出发，直接提供的常用安全审计策略方法；由平台直接更新维护，不可删除。': '"AI strategy" is a common security audit strategy method directly provided by the official team from the perspective of the security audit profession; It is directly updated and maintained by the platform, cannot be deleted.',
    '“AI策略”是官方团队从安全审计专业角度出发，直接提供的常用安全审计策略方法；由平台直接更新维护，不可克隆。': '"AI strategy" is a common security audit strategy method directly provided by the official team from the perspective of the security audit profession; It is directly updated and maintained by the platform, cannot be cloned.',
    请输入正则表达式并Enter结束: 'Please enter a regular expression and enter to end',
    复制链接: 'copy link',
    算法不能为空: 'Algorithm cannot be empty',
    算法参数: 'Algorithm parameters',
    算法: 'Algorithm',
    模型设置: 'Model settings',
    数据源: 'Data source',
    模型参数: 'Model parameters',
    系统不能为空: 'System cannot be empty.',
    该模型暂无参数: 'This model has no parameters',
    检测条件: 'Conditions',
    取模型的输出做过滤: 'Filter the output of the model',
    模型输入字段: 'Model input fields',
    映射值: 'Mapping values',
    策略启用失败: 'Failed to enable the strategy',
    策略停用失败: 'Failed to disable the strategy',
    复制成功: 'Copy successfully',
    启用: 'Enabled',
    停用: 'Disabled',
    请选择标签: 'Please select a label',
    请选择策略类型: 'Please select the policy type',
    请选择启停状态: 'Please select the start and stop status',
    '请输入策略ID (只允许输入整数)': 'Please enter the policy ID (only integer is allowed)',
    策略ID只允许输入整数: 'Policy ID only integer is allowed',
    '标签只允许中文、字母、数字、中划线或下划线组成': 'Tags are only allowed Composed of Chinese characters, letters, numbers, Center lines or underlines',
    标签不能为纯数字: 'Tag cannot be consisted of all digit',
    策略名称不能为空: 'name cannot be empty',
    检测条件不能为空: 'filter cannot be empty',
    策略ID: 'ID',
    启停状态: 'On/Off status',
    作业平台: 'Platform',
    节点管理: 'Node management',
    参数名: 'Name',
    参数值: 'value',
    在: 'during',
    每: 'Detect every',
    '的时段内,': ',',
    '为一个统计周期,': 'generate risk ticket i',
    秒: 'Second',
    统计周期最小为5分钟: 'The minimum statistical period is 5 minutes',
    '策略ID、策略名称、标签、状态': 'Strategy ID、Name、Tag、Status',
    请选择状态: 'Please choose status',
    操作日志: 'Event log',
    状态: 'Status',
    方案: 'Solution',
    请选择方案: 'Please select a solution',
    其他配置: 'Other',
    内置: 'Built-in',
    方案输入: 'Solution input',
    方案参数: 'Solution parameters',
    调度配置: 'Scheduling configuration',
    数据源类型: 'Data source type',
    操作记录: 'Operation record',
    '资源数据(预置)': 'Resource data (pre-set)',
    '资源数据(业务)': 'Resource data (business)',
    输入字段映射: 'Input field mapping',
    版本信息: 'Version information',
    方案描述: 'Solution description',
    版本号: 'Version',
    发布标签: 'Release tag',
    发布人: 'Release by',
    发布时间: 'Release time',
    方案输出: 'Solution output',
    暂无方案说明: 'No solution description available',
    AIops方案: 'AIops solution',
    筛选输入数据: 'Filter input data',
    数据源表: 'Data source table',
    资产: 'Asset',
    调度周期: 'Scheduling cycle',
    '策略状态异常，不能启停': 'Strategy status is abnormal, cannot start/stop',
    '处理中，不能编辑': 'Processing, cannot edit',
    '处理中，不能删除': 'Processing, cannot delete',
    '处理中，不能克隆': 'Processing, cannot clone',
    方案输入字段: 'Solution input fields',
    业务资产: 'Business asset',
    内置资产: 'Built-in asset',
    调度周期不能为空: 'Scheduling cycle cannot be empty',
    停用策略确认: 'Confirmation to disable strategy',
    启动策略确认: 'Confirmation to start strategy',
    '策略停用后对应风险可能无法及时发现，请确认是否停用': 'Disabling the strategy may result in delayed detection of corresponding risks. Please confirm whether to disable',
    '策略启动后会开始检测并可能输出审计事件，请确认是否启动': 'Starting the strategy will begin detection and may output audit events. Please confirm whether to start',

    策略提交确认: 'Confirmation of Strategy Submission',
    '策略一旦提交，审计中心会开启策略配置的相关检测，若有风险命中策略会立即输出风险，请仔细检查策略配置是否正确以免输出错误风险。': 'Once the strategy is submitted, the audit center will initiate relevant checks on the strategy configuration. If the strategy hits any risks, the risks will be immediately outputted. Please carefully check whether the strategy configuration is correct to avoid outputting incorrect risks.',
    该标签不存在: 'tag does not exist',
    '创建数据处理链路中，预计10分钟后策略正式运行': 'Creating a data processing flow on BKBASE, the strategy is expected to run  in 10 minutes.',
    '由于不同操作对应的拓展字段不同，若需要使用拓展字段作为映射值，映射值类型请选择拓展字段。若不使用拓展字段则映射值类型选为公共字段': 'Due to different extension fields for different operations, if you need to use extension fields as mapping values, please select the extension field as the mapping value type. If you don\'t use extension fields, please select the common field as the mapping value type.',
    该系统暂未上报资源数据: 'The system has not  reported resource data',
    '审计中心暂未获得该业务数据的使用授权，请联系系统管理员到BKBASE上申请权限': 'BK-Audit  hasn\'t been granted permission to access the business data. Please contact the system administrator to apply for permission on BKBASE.',
    策略运行的周期: 'The cycle of strategy execution',
    满足检测条件的操作记录的汇聚维度: 'The Aggregation Dimension of the data being detected',
    确认升级差异: '确认升级差异',
    更新方案配置: '更新方案配置',
    '策略使用的方案，有新版本待升级': 'The strategy implementation plan has a new version pending upgrade.',
    待补充: '待补充',
    各应用系统按照审计中心规范上报的系统操作日志: 'System operation logs reported by each application system in accordance with BKAudit specifications.',
    各应用系统接入审计中心时上报的系统资源数据: 'System resource data reported by each application system when accessing BKAudit.',
    待升级: '待升级',
    '策略启用中，预计最长10分钟后开始正式运行': 'The strategy is being enabled, to be completed within 10 minutes.',
    '策略停用中，预计最长2分钟后停用成功': 'The strategy is being disabled, to be completed within 2 minutes.',
    映射值类型: 'Mapping value type',
    数据源中与方案输入参数匹配的字段: 'Fields in the data source that match the input parameters of the plan.',
    重试: 'retry',
    升级确认: 'Upgrade confirm',
    确认升级: 'Upgrade confirm',
    '升级后将按照方案新版本设定的最新输出字段输出审计风险，请确认是否升级？': 'After the upgrade, the latest output fields set in the new version of the plan will be used to output audit risks. Please confirm if you want to upgrade？',

    失败: 'Failure',
    更新失败: 'Update Failed',
    停用失败: 'Stop Failed',
    删除失败: 'Delete Failed',
    启动中: 'Starting',
    更新中: 'Updating',
    停用中: 'Stopping',
    运行中: 'Running',
    已停用: 'Stopped',
    '删除(Remove)': 'Remove',
    删除: 'Delete',
    取消: 'Cancel',
    '取消(No)': 'No',
    请输入描述: 'Please enter the description',
  },
};
