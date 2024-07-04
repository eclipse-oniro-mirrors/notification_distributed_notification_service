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
#include "ans_permission_def.h"
#include "notification_request.h"

constexpr uint8_t SLOT_TYPE_NUM = 5;
constexpr uint8_t ENABLE = 2;

namespace OHOS {
    Notification::AdvancedNotificationService advancedNotificationService;

    bool DoSomethingInterestingWithMyAPI(FuzzData fuzzData)
    {
        std::string stringData = fuzzData.GenerateRandomString();
        sptr<Notification::NotificationRequest> notification = new Notification::NotificationRequest();
        advancedNotificationService.Publish(stringData, notification);
        int notificationId = fuzzData.GenerateRandomInt32();
        advancedNotificationService.Cancel(notificationId, stringData, 0);
        advancedNotificationService.CancelAll(0);
        int32_t userId = fuzzData.GenerateRandomInt32();
        advancedNotificationService.CancelAsBundle(notificationId, stringData, userId);
        uint8_t type = fuzzData.GetData<uint8_t>() % SLOT_TYPE_NUM;
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
        bundleOption->SetBundleName(fuzzData.GenerateRandomString());
        bundleOption->SetUid(fuzzData.GenerateRandomInt32());
        uint64_t num = fuzzData.GetData<uint64_t>();
        advancedNotificationService.GetSlotNumAsBundle(bundleOption, num);
        std::vector<sptr<Notification::NotificationRequest>> notifications;
        advancedNotificationService.GetActiveNotifications(notifications, 0);
        advancedNotificationService.GetActiveNotificationNums(num);
        std::vector<sptr<Notification::Notification>> notificationss;
        advancedNotificationService.GetAllActiveNotifications(notificationss);
        std::vector<std::string> key;
        advancedNotificationService.GetSpecialActiveNotifications(key, notificationss);
        advancedNotificationService.SetNotificationAgent(stringData);
        advancedNotificationService.GetNotificationAgent(stringData);
        bool canPublish = fuzzData.GenerateRandomBool();
        advancedNotificationService.CanPublishAsBundle(stringData, canPublish);
        advancedNotificationService.PublishAsBundle(notification, stringData);
        advancedNotificationService.SetNotificationBadgeNum(num);
        int importance = fuzzData.GenerateRandomInt32();
        advancedNotificationService.GetBundleImportance(importance);
        bool granted = fuzzData.GenerateRandomBool();
        advancedNotificationService.HasNotificationPolicyAccessPermission(granted);
        int32_t removeReason = fuzzData.GenerateRandomInt32();
        advancedNotificationService.RemoveNotification(bundleOption, notificationId, stringData, removeReason);
        advancedNotificationService.RemoveAllNotifications(bundleOption);
        advancedNotificationService.Delete(stringData, removeReason);
        advancedNotificationService.DeleteByBundle(bundleOption);
        advancedNotificationService.DeleteAll();
        advancedNotificationService.GetSlotsByBundle(bundleOption, slots);
        advancedNotificationService.UpdateSlots(bundleOption, slots);
        bool enabled = fuzzData.GenerateRandomBool();
        advancedNotificationService.SetNotificationsEnabledForBundle(stringData, enabled);
        advancedNotificationService.SetNotificationsEnabledForAllBundles(stringData, enabled);
        advancedNotificationService.SetNotificationsEnabledForSpecialBundle(stringData, bundleOption, enabled);
        advancedNotificationService.SetShowBadgeEnabledForBundle(bundleOption, enabled);
        advancedNotificationService.GetShowBadgeEnabledForBundle(bundleOption, enabled);
        advancedNotificationService.GetShowBadgeEnabled(enabled);
        sptr<Notification::AnsSubscriberStub> subscriber = new Notification::AnsSubscriberStub();
        sptr<Notification::NotificationSubscribeInfo> info = new Notification::NotificationSubscribeInfo();
        advancedNotificationService.Subscribe(subscriber, info);
        advancedNotificationService.Unsubscribe(subscriber, info);
        bool allowed = fuzzData.GenerateRandomBool();
        advancedNotificationService.IsAllowedNotify(allowed);
        advancedNotificationService.IsAllowedNotifySelf(allowed);
        advancedNotificationService.IsSpecialBundleAllowedNotify(bundleOption, allowed);
        advancedNotificationService.CancelGroup(stringData, 0);
        advancedNotificationService.RemoveGroupByBundle(bundleOption, stringData);
        sptr<Notification::NotificationDoNotDisturbDate> date = new Notification::NotificationDoNotDisturbDate();
        advancedNotificationService.SetDoNotDisturbDate(date);
        advancedNotificationService.GetDoNotDisturbDate(date);
        bool doesSupport = fuzzData.GenerateRandomBool();
        advancedNotificationService.DoesSupportDoNotDisturbMode(doesSupport);
        advancedNotificationService.IsDistributedEnabled(enabled);
        advancedNotificationService.EnableDistributedByBundle(bundleOption, enabled);
        advancedNotificationService.EnableDistributedSelf(enabled);
        advancedNotificationService.EnableDistributed(enabled);
        advancedNotificationService.IsDistributedEnableByBundle(bundleOption, enabled);
        Notification::NotificationConstant::RemindType remindType;
        advancedNotificationService.GetDeviceRemindType(remindType);
        sptr<Notification::NotificationRequest> request = new Notification::NotificationRequest();
        advancedNotificationService.PublishContinuousTaskNotification(request);
        advancedNotificationService.CancelContinuousTaskNotification(stringData, notificationId);
        sptr<Notification::ReminderRequest> reminder = new Notification::ReminderRequest();
        advancedNotificationService.PublishReminder(reminder);
        int32_t reminderId = fuzzData.GenerateRandomInt32();
        advancedNotificationService.CancelReminder(reminderId);
        std::vector<sptr<Notification::ReminderRequest>> reminders;
        advancedNotificationService.GetValidReminders(reminders);
        advancedNotificationService.CancelAllReminders();
        uint64_t excludeDate = fuzzData.GetData<uint64_t>();
        advancedNotificationService.AddExcludeDate(reminderId, excludeDate);
        advancedNotificationService.DelExcludeDates(reminderId);
        std::vector<uint64_t> excludeDates;
        advancedNotificationService.GetExcludeDates(reminderId, excludeDates);
        bool support = fuzzData.GenerateRandomBool();
        advancedNotificationService.IsSupportTemplate(stringData, support);
        advancedNotificationService.IsSpecialUserAllowedNotify(userId, allowed);
        int32_t deviceIds = fuzzData.GenerateRandomInt32();
        advancedNotificationService.SetNotificationsEnabledByUser(deviceIds, enabled);
        advancedNotificationService.DeleteAllByUser(userId);
        advancedNotificationService.SetDoNotDisturbDate(date);
        advancedNotificationService.GetDoNotDisturbDate(date);
        advancedNotificationService.SetEnabledForBundleSlot(bundleOption, slotType, enabled, false);
        advancedNotificationService.GetEnabledForBundleSlot(bundleOption, slotType, enabled);
        std::vector<std::string> dumpInfo;
        advancedNotificationService.ShellDump(stringData, stringData, userId, userId, dumpInfo);
        advancedNotificationService.SetSyncNotificationEnabledWithoutApp(userId, enabled);
        advancedNotificationService.GetSyncNotificationEnabledWithoutApp(userId, enabled);
        int32_t badgeNum = fuzzData.GenerateRandomInt32();
        advancedNotificationService.SetBadgeNumber(badgeNum, 0);
        sptr<Notification::AnsDialogCallback> dialogCallback = NULL;
        sptr<IRemoteObject> callerToken = NULL;
        advancedNotificationService.RequestEnableNotification(stringData, dialogCallback, callerToken);

        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data != nullptr && size >= GetU32Size()) {
        OHOS::FuzzData fuzzData(data, size);
        std::vector<std::string> requestPermission = {
            OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER,
            OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER,
            OHOS::Notification::OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION
        };
        NativeTokenGet(requestPermission);
        OHOS::DoSomethingInterestingWithMyAPI(fuzzData);
    }
    return 0;
}
