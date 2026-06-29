# ohos-notificationManager

## 概述

OpenHarmony 通知管理命令行工具，用于通知的发布、取消、移除和活跃通知查询。不支持通知订阅和交互式UI操作。

## 功能列表

- 发布通知（publish）— 不支持订阅类通知
- 按应用和通知ID取消通知（cancelById）— 不支持无包名信息的通知取消
- 按应用取消所有通知（cancelByBundle）
- 批量取消通知（batchCancel）
- 设置应用通知开关（enableNotification）— 不支持无包名信息的状态设置
- 设置应用渠道标志（setSlotFlags）— 不支持无包名信息的标志设置
- 查询活跃通知列表（listAllNotification）— 不支持查询其他用户的通知

## 依赖

- 系统能力：SystemCapability.Notification.Notification
- 权限：ohos.permission.NOTIFICATION_CONTROLLER, ohos.permission.NOTIFICATION_AGENT_CONTROLLER

## 基本用法

```bash
ohos-notificationManager <command> [options]
```

## 命令列表

| 命令 | 说明 | 必填参数 | 权限 |
|------|------|----------|------|
| help | 显示帮助信息，可查看指定命令详细帮助 | 无或[command] | 无 |
| publish | 发布通知到系统，不支持订阅类通知 | --notificationContent | 无 |
| cancelById | 按应用和ID取消通知，不支持无包名信息的取消 | --bundleOption, --notificationId | ohos.permission.NOTIFICATION_CONTROLLER, ohos.permission.NOTIFICATION_AGENT_CONTROLLER |
| cancelByBundle | 按应用取消所有通知 | --bundleOption | ohos.permission.NOTIFICATION_CONTROLLER |
| batchCancel | 批量取消通知 | --hashcodes | ohos.permission.NOTIFICATION_CONTROLLER |
| enableNotification | 设置应用通知开关，不支持无包名信息的设置 | --bundleOption, --enabled | ohos.permission.NOTIFICATION_CONTROLLER |
| setSlotFlags | 设置应用渠道标志，不支持无包名信息的设置 | --bundleOption, --flags | ohos.permission.NOTIFICATION_CONTROLLER |
| listAllNotification | 查询活跃通知列表，不支持查询其他用户的通知 | 无 | ohos.permission.NOTIFICATION_CONTROLLER |

## 示例

```bash
# 查看帮助信息
ohos-notificationManager --help

# 查看 publish 子命令帮助
ohos-notificationManager publish --help

# 发布一条基本通知（使用默认通知ID=0）
ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Test\",\"text\":\"Hello\"}"

# 发布一条基本通知（指定通知ID=1）
ohos-notificationManager publish --notificationId 1 --notificationContent "{\"type\":\"basic\",\"title\":\"Test\",\"text\":\"Hello\"}"

# 发布带有指定渠道类型的通知（SERVICE_REMINDER=1）
ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Alert\",\"text\":\"Content\"}" --slotType 1

# 发布带有角标增加数量的通知（在当前角标基础上增加3）
ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Test\",\"text\":\"Hello\"}" --badgeNumber 3

# 发布长文本通知
ohos-notificationManager publish --notificationContent "{\"type\":\"long_text\",\"title\":\"Long\",\"text\":\"Short\",\"longText\":\"Very long text\",\"expandedTitle\":\"Expanded\",\"briefText\":\"Brief\"}"

# 发布多行通知
ohos-notificationManager publish --notificationContent "{\"type\":\"multiline\",\"title\":\"Multi\",\"text\":\"Content\",\"expandedTitle\":\"Expanded\",\"briefText\":\"Brief\",\"lines\":[\"line1\",\"line2\"]}"

# 按应用和ID取消通知
ohos-notificationManager cancelById --bundleOption "{\"bundleName\":\"com.example\",\"uid\":10100}" --notificationId 1

# 按应用取消所有通知
ohos-notificationManager cancelByBundle --bundleOption "{\"bundleName\":\"com.example\",\"uid\":10100}"

# 批量取消通知
ohos-notificationManager batchCancel --hashcodes "[\"hash1\",\"hash2\"]"

# 启用指定应用通知
ohos-notificationManager enableNotification --bundleOption "{\"bundleName\":\"com.example\",\"uid\":10100}" --enabled true

# 禁用指定应用通知
ohos-notificationManager enableNotification --bundleOption "{\"bundleName\":\"com.example\",\"uid\":10100}" --enabled false

# 设置渠道标志（全部提醒=63, bit0-bit5全开）
ohos-notificationManager setSlotFlags --bundleOption "{\"bundleName\":\"com.example\",\"uid\":10100}" --flags 63

# 设置渠道标志（十六进制格式）
ohos-notificationManager setSlotFlags --bundleOption "{\"bundleName\":\"com.example\",\"uid\":10100}" --flags 0x3F

# 查询活跃通知列表
ohos-notificationManager listAllNotification
```

## publish 命令参数说明

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| --notificationId | integer | 否 | 通知ID（≥0，默认0） |
| --notificationContent | string(JSON) | 是 | 通知内容JSON字符串（最长4096字节） |
| --slotType | integer | 否 | 渠道类型（0-7，不支持5，默认3） |
| --updateOnly | boolean | 否 | 仅更新已存在的通知，不创建新通知（默认false） |
| --appMessageId | string | 否 | 应用消息ID（最长256字节） |
| --priorityNotificationType | string | 否 | 优先级通知类型（枚举值见下方说明） |
| --alertOneTime | boolean | 否 | 仅提醒一次，后续更新不再提醒（默认false） |
| --sound | string | 否 | 自定义通知声音URI（最长204字节） |
| --badgeNumber | integer | 否 | 角标增加数量（在当前角标基础上增加的数字，≥0） |
| --tapDismissed | boolean | 否 | 点击后自动消失（默认false） |
| --autoDeletedTime | integer | 否 | 自动删除时间（毫秒，≥0） |
| --label | string | 否 | 通知标签（最长204字节） |
| --groupName | string | 否 | 通知分组名称（最长204字节，超长截取） |
| --additionalParams | string(JSON) | 否 | 附加数据WantParams序列化字符串（最长4096字节） |
| --inProgress | boolean | 否 | 标记为进行中通知（默认false） |
| --unRemovable | boolean | 否 | 标记为不可移除通知（默认false） |
| --actionButtons | string(JSON) | 否 | 操作按钮JSON数组（仅支持title字段，最长4096字节） |
| --notificationFlags | string(JSON) | 否 | 通知提醒标志（支持soundEnabled/vibrationEnabled/bannerEnabled/lockScreenEnabled，值=2为关闭） |
| --notificationTemplate | string(JSON) | 否 | 通知模板（包含name和可选data字段，最长4096字节） |

## notificationContent 格式说明

所有类型公共必填字段: title(≤1024B), text(≤3072B)；公共可选: additionalText(≤3072B)；所有属性超长截取。type仅支持basic、long_text、multiline。

| type | 必填字段 | 可选字段 | 说明 |
|------|----------|----------|------|
| basic | title, text | additionalText | 基本通知 |
| long_text | title, text, longText, expandedTitle, briefText | additionalText | 长文本通知 |
| multiline | title, text, expandedTitle, briefText, lines | additionalText | 多行通知（lines最多3行，每行≤1024B） |

### notificationContent 示例

```json
// basic
{"type":"basic","title":"通知标题","text":"通知内容","additionalText":"附加文本"}

// long_text
{"type":"long_text","title":"通知标题","text":"短内容","longText":"长文本内容","expandedTitle":"展开标题","briefText":"摘要","additionalText":"附加文本"}

// multiline
{"type":"multiline","title":"通知标题","text":"通知内容","expandedTitle":"展开标题","briefText":"摘要","lines":["第一行","第二行","第三行"],"additionalText":"附加文本"}
```

## 渠道类型说明

| 值 | 类型 | 说明 |
|----|------|------|
| 0 | SOCIAL_COMMUNICATION | 社交沟通 |
| 1 | SERVICE_REMINDER | 服务提醒 |
| 2 | CONTENT_INFORMATION | 内容信息 |
| 3 | OTHER | 其他（默认） |
| 4 | CUSTOM | 自定义 |
| 5 | LIVE_VIEW | 实况通知（**不支持**） |
| 6 | CUSTOMER_SERVICE | 客服 |
| 7 | EMERGENCY_INFORMATION | 紧急信息 |

## 优先级通知类型说明

| 枚举值 | 说明 |
|--------|------|
| alarm | 闹钟定时器 |
| call | 来电通话 |
| email | 邮件 |
| err | 后台错误/认证 |
| event | 日历事件 |
| msg | 短信即时消息 |
| navigation | 地图导航 |
| progress | 后台长时间进程 |
| promo | 广告推广 |
| recommendation | 及时推荐 |
| reminder | 用户提醒 |
| service | 后台服务 |
| social | 社交更新 |
| status | 设备状态 |
| sys | 系统状态更新 |
| transport | 媒体播放控制 |

## 渠道标志位说明

仅bit0-bit5有效（范围0-63）。其中亮屏(bit3)和状态栏图标(bit5)设置关闭不会生效，服务端会强制保持开启。

| 位 | 值 | 标志 | 说明 |
|----|----|------|------|
| bit0 | 0x01 | SOUND | 提示音 |
| bit1 | 0x02 | LOCKSCREEN | 锁屏显示 |
| bit2 | 0x04 | BANNER | 横幅通知 |
| bit3 | 0x08 | LIGHTSCREEN | 亮屏（不可关闭） |
| bit4 | 0x10 | VIBRATION | 振动 |
| bit5 | 0x20 | STATUSBAR_ICON | 状态栏图标（不可关闭） |

## listAllNotification 输出字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| notificationId | integer | 通知ID |
| createTime | integer | 创建时间（毫秒时间戳） |
| ownerUid | integer | 创建者UID |
| ownerUserId | integer | 创建者UserId |
| ownerBundleName | string | 创建者包名 |
| label | string | 通知标签 |
| appInstanceKey | string | 应用实例Key |
| slotType | integer | 渠道类型值 |
| additionalParams | string | 附加参数（WantParams序列化字符串） |
| notificationContent | object | 通知内容（按type字段区分不同类型，详见下方） |
| actionButtons | array | 操作按钮列表（每个按钮含title字段） |
| notificationFlags | string | 提醒标志（包含soundEnabled、vibrationEnabled、bannerEnabled、lockScreenEnabled等字段） |
| extendInfo | string | 扩展信息（WantParams序列化字符串） |
| hashCode | string | 通知哈希码 |

### listAllNotification notificationContent 内容类型

输出中notificationContent按type字段区分不同类型：

| type | 字段 | 说明 |
|------|------|------|
| 公共 | type, title, text | 所有类型都有 |
| 公共(可选) | additionalText | 所有类型可选 |
| basic | 仅公共字段 | 基本通知 |
| long_text | +longText, expandedTitle, briefText | 长文本 |
| multiline | +expandedTitle, briefText, lines(数组) | 多行通知 |
| picture | +expandedTitle, briefText | 图片通知 |
| conversation | +conversationTitle, isGroup, messages(含text/arrivedTime/senderName/senderKey) | 会话通知 |
| media | +shownActions(按钮序号数组) | 媒体通知 |
| live_view | +liveViewStatus, version, extraInfo | 实况通知 |
| local_live_view | +liveViewType | 本地实况通知 |
