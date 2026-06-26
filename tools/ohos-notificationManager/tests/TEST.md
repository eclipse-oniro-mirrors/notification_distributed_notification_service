| 命令示例 | 说明 | 权限 | 前置依赖 |
|------|------|------|----------|
| ohos-notificationManager --help | 显示全量帮助信息 | 无 | 无 |
| ohos-notificationManager help | 显示帮助信息 | 无 | 无 |
| ohos-notificationManager help publish | 显示 publish 子命令帮助 | 无 | 无 |
| ohos-notificationManager help cancelById | 显示 cancelById 子命令帮助 | 无 | 无 |
| ohos-notificationManager help cancelByBundle | 显示 cancelByBundle 子命令帮助 | 无 | 无 |
| ohos-notificationManager help batchCancel | 显示 batchCancel 子命令帮助 | 无 | 无 |
| ohos-notificationManager help enableNotification | 显示 enableNotification 子命令帮助 | 无 | 无 |
| ohos-notificationManager help setSlotFlags | 显示 setSlotFlags 子命令帮助 | 无 | 无 |
| ohos-notificationManager help listAllNotification | 显示 listAllNotification 子命令帮助 | 无 | 无 |
| ohos-notificationManager publish --help | 显示 publish 子命令帮助 | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Test\",\"text\":\"Hello\"}" | 发布基本通知（使用默认通知ID=0，默认渠道类型=3） | 无 | 无 |
| ohos-notificationManager publish --notificationId 1 --notificationContent "{\"type\":\"basic\",\"title\":\"Test\",\"text\":\"Hello\"}" | 发布基本通知（指定通知ID=1） | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Alert\",\"text\":\"Content\"}" --slotType 0 | 发布社交通信类通知(slotType=0) | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Service\",\"text\":\"Reminder\"}" --slotType 1 | 发布服务提醒类通知(slotType=1) | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Info\",\"text\":\"Detail\"}" --slotType 2 | 发布内容信息类通知(slotType=2) | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"long_text\",\"title\":\"Long\",\"text\":\"Short\",\"longText\":\"Very long text\",\"expandedTitle\":\"Expanded\",\"briefText\":\"Brief\"}" | 发布长文本通知 | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"multiline\",\"title\":\"Multi\",\"text\":\"Content\",\"expandedTitle\":\"Expanded\",\"briefText\":\"Brief\",\"lines\":[\"line1\",\"line2\"]}" | 发布多行通知 | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Test\",\"text\":\"Hello\"}" --badgeNumber 3 | 发布带角标增加数量的通知（在当前角标基础上增加3） | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Test\",\"text\":\"Hello\"}" --inProgress | 发布进行中通知 | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Test\",\"text\":\"Hello\"}" --unRemovable | 发布不可移除通知 | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Test\",\"text\":\"Hello\"}" --updateOnly | 仅更新已存在的通知，不创建新通知 | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Test\",\"text\":\"Hello\"}" --label "myLabel" --groupName "myGroup" | 发布带标签和分组的通知 | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Test\",\"text\":\"Hello\"}" --notificationFlags "{\"soundEnabled\":2,\"vibrationEnabled\":2}" | 发布带提醒标志的通知（关闭声音和振动） | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Test\",\"text\":\"Hello\"}" --actionButtons "[{\"title\":\"OK\"},{\"title\":\"Cancel\"}]" | 发布带操作按钮的通知 | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Test\",\"text\":\"Hello\"}" --alertOneTime --tapDismissed --autoDeletedTime 5000 | 发布仅提醒一次、点击消失、5秒自动删除的通知 | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Test\",\"text\":\"Hello\"}" --additionalParams "{\"key1\":\"val1\"}" | 发布带附加参数的通知 | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Test\",\"text\":\"Hello\"}" --notificationTemplate "{\"name\":\"downloadTemplate\"}" | 发布带模板的通知 | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Test\",\"text\":\"Hello\"}" --sound "file:///ringtone.mp3" | 发布带自定义声音的通知 | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Test\",\"text\":\"Hello\"}" --appMessageId "msg001" --priorityNotificationType alarm | 发布带消息ID和优先级类型的通知 | 无 | 无 |
| ohos-notificationManager publish --notificationContent "{\"type\":\"basic\",\"title\":\"Test\",\"text\":\"Hello\"}" --priorityNotificationType call | 发布带来电通话优先级类型的通知 | 无 | 无 |
| ohos-notificationManager cancelById --help | 显示 cancelById 子命令帮助 | 无 | 无 |
| ohos-notificationManager cancelById --bundleOption "{\"bundleName\":\"com.example\",\"uid\":10100}" --notificationId 1 | 按应用和ID取消通知 | ohos.permission.NOTIFICATION_CONTROLLER, ohos.permission.NOTIFICATION_AGENT_CONTROLLER | 无 |
| ohos-notificationManager cancelByBundle --help | 显示 cancelByBundle 子命令帮助 | 无 | 无 |
| ohos-notificationManager cancelByBundle --bundleOption "{\"bundleName\":\"com.example\",\"uid\":10100}" | 按应用取消所有通知 | ohos.permission.NOTIFICATION_CONTROLLER | 无 |
| ohos-notificationManager batchCancel --help | 显示 batchCancel 子命令帮助 | 无 | 无 |
| ohos-notificationManager batchCancel --hashcodes "[\"hash1\",\"hash2\"]" | 批量取消通知 | ohos.permission.NOTIFICATION_CONTROLLER | 无 |
| ohos-notificationManager enableNotification --help | 显示 enableNotification 子命令帮助 | 无 | 无 |
| ohos-notificationManager enableNotification --bundleOption "{\"bundleName\":\"com.example\",\"uid\":10100}" --enabled true | 启用指定应用通知 | ohos.permission.NOTIFICATION_CONTROLLER | 无 |
| ohos-notificationManager enableNotification --bundleOption "{\"bundleName\":\"com.example\",\"uid\":10100}" --enabled false | 禁用指定应用通知 | ohos.permission.NOTIFICATION_CONTROLLER | 无 |
| ohos-notificationManager setSlotFlags --help | 显示 setSlotFlags 子命令帮助 | 无 | 无 |
| ohos-notificationManager setSlotFlags --bundleOption "{\"bundleName\":\"com.example\",\"uid\":10100}" --flags 63 | 设置全部提醒标志(0x3F, bit0-bit5全开) | ohos.permission.NOTIFICATION_CONTROLLER | 无 |
| ohos-notificationManager setSlotFlags --bundleOption "{\"bundleName\":\"com.example\",\"uid\":10100}" --flags 0x3F | 设置提醒标志（十六进制格式） | ohos.permission.NOTIFICATION_CONTROLLER | 无 |
| ohos-notificationManager setSlotFlags --bundleOption "{\"bundleName\":\"com.example\",\"uid\":10100}" --flags 1 | 仅设置提示音标志(bit0) | ohos.permission.NOTIFICATION_CONTROLLER | 无 |
| ohos-notificationManager setSlotFlags --bundleOption "{\"bundleName\":\"com.example\",\"uid\":10100}" --flags 5 | 设置提示音+横幅标志(bit0+bit2) | ohos.permission.NOTIFICATION_CONTROLLER | 无 |
| ohos-notificationManager listAllNotification --help | 显示 listAllNotification 子命令帮助 | 无 | 无 |
| ohos-notificationManager listAllNotification | 查询活跃通知列表 | ohos.permission.NOTIFICATION_CONTROLLER | 无 |
