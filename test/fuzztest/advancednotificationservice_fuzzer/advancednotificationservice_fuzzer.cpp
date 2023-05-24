/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define private public
#define protected public
#include "advanced_notification_service.h"
#undef private
#undef protected
#include "advancednotificationservice_fuzzer.h"
#include "ans_subscriber_stub.h"
#include "notification_request.h"

constexpr uint8_t SLOT_TYPE_NUM = 5;

namespace OHOS {

    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        std::string stringData(data);
        Notification::AdvancedNotificationService advancedNotificationService;
        sptr<Notification::NotificationRequest> notification = new Notification::NotificationRequest();
        const std::string label = "this is a notification label";
        const std::string deviceId = "this is a notification deviceId";
        advancedNotificationService.Publish(label, notification);
        int notificationId = 1;
        advancedNotificationService.Cancel(notificationId, label);
        advancedNotificationService.CancelAll();
        const std::string representativeBundle = "this is a notification representativeBundle";
        int32_t userId = 1;
        advancedNotificationService.CancelAsBundle(notificationId, representativeBundle, userId);
        uint8_t type = *data % SLOT_TYPE_NUM;
        Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType(type);
        advancedNotificationService.AddSlotByType(slotType);
        std::vector<sptr<Notification::NotificationSlot>> slots;
        advancedNotificationService.AddSlots(slots);
        advancedNotificationService.RemoveSlotByType(slotType);
        advancedNotificationService.RemoveAllSlots();
        sptr<Notification::NotificationSlot> slot = new Notification::NotificationSlot();
        advancedNotificationService.GetSlotByType(slotType, slot);
        advancedNotificationService.GetSlots(slots);
        sptr<Notification::NotificationBundleOption> bundleOption = new Notification::NotificationBundleOption();
        uint64_t num = 1;
        advancedNotificationService.GetSlotNumAsBundle(bundleOption, num);
        std::vector<sptr<Notification::NotificationRequest>> notifications;
        advancedNotificationService.GetActiveNotifications(notifications);
        advancedNotificationService.GetActiveNotificationNums(num);
        std::vector<sptr<Notification::Notification>> notificationss;
        advancedNotificationService.GetAllActiveNotifications(notificationss);
        std::vector<std::string> key;
        advancedNotificationService.GetSpecialActiveNotifications(key, notificationss);
        std::string agent = "this is a notification agent";
        advancedNotificationService.SetNotificationAgent(agent);
        advancedNotificationService.GetNotificationAgent(agent);
        bool canPublish = true;
        advancedNotificationService.CanPublishAsBundle(representativeBundle, canPublish);
        advancedNotificationService.PublishAsBundle(notification, representativeBundle);
        advancedNotificationService.SetNotificationBadgeNum(num);
        int importance = 1;
        advancedNotificationService.GetBundleImportance(importance);
        bool granted = true;
        advancedNotificationService.HasNotificationPolicyAccessPermission(granted);
        int32_t removeReason = 1;
        advancedNotificationService.RemoveNotification(bundleOption, notificationId, label, removeReason);
        advancedNotificationService.RemoveAllNotifications(bundleOption);
        const std::string keys = "this is a notification keys";
        advancedNotificationService.Delete(keys, removeReason);
        advancedNotificationService.DeleteByBundle(bundleOption);
        advancedNotificationService.DeleteAll();
        advancedNotificationService.GetSlotsByBundle(bundleOption, slots);
        advancedNotificationService.UpdateSlots(bundleOption, slots);
        advancedNotificationService.RequestEnableNotification(deviceId);
        const std::string bundle = "this is a notification bundle";
        bool enabled = true;
        advancedNotificationService.SetNotificationsEnabledForBundle(bundle, enabled);
        advancedNotificationService.SetNotificationsEnabledForAllBundles(deviceId, enabled);
        advancedNotificationService.SetNotificationsEnabledForSpecialBundle(deviceId, bundleOption, enabled);
        advancedNotificationService.SetShowBadgeEnabledForBundle(bundleOption, enabled);
        advancedNotificationService.GetShowBadgeEnabledForBundle(bundleOption, enabled);
        advancedNotificationService.GetShowBadgeEnabled(enabled);
        sptr<Notification::AnsSubscriberStub> subscriber = new Notification::AnsSubscriberStub();
        sptr<Notification::NotificationSubscribeInfo> info = new Notification::NotificationSubscribeInfo();
        advancedNotificationService.Subscribe(subscriber, info);
        advancedNotificationService.Unsubscribe(subscriber, info);
        bool allowed = true;
        advancedNotificationService.IsAllowedNotify(allowed);
        advancedNotificationService.IsAllowedNotifySelf(allowed);
        advancedNotificationService.IsSpecialBundleAllowedNotify(bundleOption, allowed);
        const std::string groupName = "this is a notification groupName";
        advancedNotificationService.CancelGroup(groupName);
        advancedNotificationService.RemoveGroupByBundle(bundleOption, groupName);
        sptr<Notification::NotificationDoNotDisturbDate> date = new Notification::NotificationDoNotDisturbDate();
        advancedNotificationService.SetDoNotDisturbDate(date);
        advancedNotificationService.GetDoNotDisturbDate(date);
        bool doesSupport = true;
        advancedNotificationService.DoesSupportDoNotDisturbMode(doesSupport);
        advancedNotificationService.IsDistributedEnabled(enabled);
        advancedNotificationService.EnableDistributedByBundle(bundleOption, enabled);
        advancedNotificationService.EnableDistributedSelf(enabled);
        advancedNotificationService.IsDistributedEnableByBundle(bundleOption, enabled);
        Notification::NotificationConstant::RemindType remindType;
        advancedNotificationService.GetDeviceRemindType(remindType);
        sptr<Notification::NotificationRequest> request = new Notification::NotificationRequest();
        advancedNotificationService.PublishContinuousTaskNotification(request);
        advancedNotificationService.CancelContinuousTaskNotification(label, notificationId);
        sptr<Notification::ReminderRequest> reminder = new Notification::ReminderRequest();
        advancedNotificationService.PublishReminder(reminder);
        const int32_t reminderId = 1;
        advancedNotificationService.CancelReminder(reminderId);
        std::vector<sptr<Notification::ReminderRequest>> reminders;
        advancedNotificationService.GetValidReminders(reminders);
        advancedNotificationService.CancelAllReminders();
        const std::string templateName = "this is a notification templateName";
        bool support = true;
        advancedNotificationService.IsSupportTemplate(templateName, support);
        advancedNotificationService.IsSpecialUserAllowedNotify(userId, allowed);
        const int32_t deviceIds = 1;
        advancedNotificationService.SetNotificationsEnabledByUser(deviceIds, enabled);
        advancedNotificationService.DeleteAllByUser(userId);
        advancedNotificationService.SetDoNotDisturbDate(date);
        advancedNotificationService.GetDoNotDisturbDate(date);
        advancedNotificationService.SetEnabledForBundleSlot(bundleOption, slotType, enabled);
        advancedNotificationService.GetEnabledForBundleSlot(bundleOption, slotType, enabled);
        const std::string cmd = "this is a notification cmd";
        std::vector<std::string> dumpInfo;
        advancedNotificationService.ShellDump(cmd, bundle, userId, dumpInfo);
        advancedNotificationService.SetSyncNotificationEnabledWithoutApp(userId, enabled);
        advancedNotificationService.GetSyncNotificationEnabledWithoutApp(userId, enabled);
        int32_t badgeNum = 1;
        advancedNotificationService.SetBadgeNumber(badgeNum);

        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    char *ch = ParseData(data, size);
    if (ch != nullptr && size >= GetU32Size()) {
        OHOS::DoSomethingInterestingWithMyAPI(ch, size);
        free(ch);
        ch = nullptr;
    }
    return 0;
}
