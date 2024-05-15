/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "ans_manager_stub.h"
#undef private
#undef protected
#include "ansmanagerstub_fuzzer.h"
#include "notification_request.h"

constexpr uint8_t SLOT_TYPE_NUM = 5;
constexpr uint8_t ENABLE = 2;

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        std::string stringData(data, size);
        Notification::AnsManagerStub ansManagerStub;
        uint32_t code = GetU32Data(data);
        MessageParcel datas;
        MessageParcel reply;
        MessageOption flags;
        ansManagerStub.OnRemoteRequest(code, datas, reply, flags);
        ansManagerStub.HandlePublish(datas, reply);
        ansManagerStub.HandleCancel(datas, reply);
        ansManagerStub.HandleCancelAll(datas, reply);
        ansManagerStub.HandleCancelAsBundle(datas, reply);
        ansManagerStub.HandleAddSlotByType(datas, reply);
        ansManagerStub.HandleAddSlots(datas, reply);
        ansManagerStub.HandleRemoveSlotByType(datas, reply);
        ansManagerStub.HandleRemoveAllSlots(datas, reply);
        ansManagerStub.HandleGetSlots(datas, reply);
        ansManagerStub.HandleGetSlotByType(datas, reply);
        ansManagerStub.HandleGetSlotNumAsBundle(datas, reply);
        ansManagerStub.HandleGetActiveNotifications(datas, reply);
        ansManagerStub.HandleGetActiveNotificationNums(datas, reply);
        ansManagerStub.HandleGetAllActiveNotifications(datas, reply);
        ansManagerStub.HandleGetSpecialActiveNotifications(datas, reply);
        ansManagerStub.HandleSetNotificationAgent(datas, reply);
        ansManagerStub.HandleGetNotificationAgent(datas, reply);
        ansManagerStub.HandleCanPublishAsBundle(datas, reply);
        ansManagerStub.HandlePublishAsBundle(datas, reply);
        ansManagerStub.HandleSetNotificationBadgeNum(datas, reply);
        ansManagerStub.HandleGetBundleImportance(datas, reply);
        ansManagerStub.HandleSetDoNotDisturbDate(datas, reply);
        ansManagerStub.HandleGetDoNotDisturbDate(datas, reply);
        ansManagerStub.HandleDoesSupportDoNotDisturbMode(datas, reply);
        ansManagerStub.HandlePublishContinuousTaskNotification(datas, reply);
        ansManagerStub.HandleCancelContinuousTaskNotification(datas, reply);
        ansManagerStub.HandleIsNotificationPolicyAccessGranted(datas, reply);
        ansManagerStub.HandleRemoveNotification(datas, reply);
        ansManagerStub.HandleRemoveAllNotifications(datas, reply);
        ansManagerStub.HandleDelete(datas, reply);
        ansManagerStub.HandleDeleteByBundle(datas, reply);
        ansManagerStub.HandleDeleteAll(datas, reply);
        ansManagerStub.HandleGetSlotsByBundle(datas, reply);
        ansManagerStub.HandleUpdateSlots(datas, reply);
        ansManagerStub.HandleRequestEnableNotification(datas, reply);
        ansManagerStub.HandleSetNotificationsEnabledForBundle(datas, reply);
        ansManagerStub.HandleSetNotificationsEnabledForAllBundles(datas, reply);
        ansManagerStub.HandleSetNotificationsEnabledForSpecialBundle(datas, reply);
        ansManagerStub.HandleSetShowBadgeEnabledForBundle(datas, reply);
        ansManagerStub.HandleGetShowBadgeEnabledForBundle(datas, reply);
        ansManagerStub.HandleGetShowBadgeEnabled(datas, reply);
        ansManagerStub.HandleSubscribe(datas, reply);
        ansManagerStub.HandleUnsubscribe(datas, reply);
        ansManagerStub.HandleIsAllowedNotify(datas, reply);
        ansManagerStub.HandleIsAllowedNotifySelf(datas, reply);
        ansManagerStub.HandleIsSpecialBundleAllowedNotify(datas, reply);
        ansManagerStub.HandleCancelGroup(datas, reply);
        ansManagerStub.HandleRemoveGroupByBundle(datas, reply);
        ansManagerStub.HandleIsDistributedEnabled(datas, reply);
        ansManagerStub.HandleEnableDistributed(datas, reply);
        ansManagerStub.HandleEnableDistributedByBundle(datas, reply);
        ansManagerStub.HandleEnableDistributedSelf(datas, reply);
        ansManagerStub.HandleIsDistributedEnableByBundle(datas, reply);
        ansManagerStub.HandleGetDeviceRemindType(datas, reply);
        ansManagerStub.HandleShellDump(datas, reply);
        ansManagerStub.HandlePublishReminder(datas, reply);
        ansManagerStub.HandleCancelReminder(datas, reply);
        ansManagerStub.HandleCancelAllReminders(datas, reply);
        ansManagerStub.HandleGetValidReminders(datas, reply);
        ansManagerStub.HandleAddExcludeDate(datas, reply);
        ansManagerStub.HandleDelExcludeDates(datas, reply);
        ansManagerStub.HandleGetExcludeDates(datas, reply);
        ansManagerStub.HandleIsSupportTemplate(datas, reply);
        ansManagerStub.HandleIsSpecialUserAllowedNotifyByUser(datas, reply);
        ansManagerStub.HandleSetNotificationsEnabledByUser(datas, reply);
        ansManagerStub.HandleDeleteAllByUser(datas, reply);
        ansManagerStub.HandleSetDoNotDisturbDateByUser(datas, reply);
        ansManagerStub.HandleGetDoNotDisturbDateByUser(datas, reply);
        ansManagerStub.HandleSetEnabledForBundleSlot(datas, reply);
        ansManagerStub.HandleGetEnabledForBundleSlot(datas, reply);
        ansManagerStub.HandleDistributedSetEnabledWithoutApp(datas, reply);
        ansManagerStub.HandleDistributedGetEnabledWithoutApp(datas, reply);
        sptr<Notification::NotificationRequest> notification = new Notification::NotificationRequest();
        ansManagerStub.Publish(stringData, notification);
        int notificationId = static_cast<int>(GetU32Data(data));
        ansManagerStub.Cancel(notificationId, stringData);
        ansManagerStub.CancelAll();
        int32_t userId = static_cast<int32_t>(GetU32Data(data));
        ansManagerStub.CancelAsBundle(notificationId, stringData, userId);
        uint8_t type = *data % SLOT_TYPE_NUM;
        Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType(type);
        ansManagerStub.AddSlotByType(slotType);
        std::vector<sptr<Notification::NotificationSlot>> slots;
        ansManagerStub.AddSlots(slots);
        ansManagerStub.RemoveSlotByType(slotType);
        ansManagerStub.RemoveAllSlots();
        sptr<Notification::NotificationSlot> slot = new Notification::NotificationSlot();
        ansManagerStub.GetSlotByType(slotType, slot);
        ansManagerStub.GetSlots(slots);
        sptr<Notification::NotificationBundleOption> bundleOption = new Notification::NotificationBundleOption();
        uint64_t num = static_cast<uint64_t>(GetU32Data(data));
        ansManagerStub.GetSlotNumAsBundle(bundleOption, num);
        std::vector<sptr<Notification::NotificationRequest>> notifications;
        ansManagerStub.GetActiveNotifications(notifications);
        ansManagerStub.GetActiveNotificationNums(num);
        std::vector<sptr<Notification::Notification>> notificationss;
        ansManagerStub.GetAllActiveNotifications(notificationss);
        std::vector<std::string> key;
        ansManagerStub.GetSpecialActiveNotifications(key, notificationss);
        ansManagerStub.SetNotificationAgent(stringData);
        ansManagerStub.GetNotificationAgent(stringData);
        bool canPublish = *data % ENABLE;
        ansManagerStub.CanPublishAsBundle(stringData, canPublish);
        ansManagerStub.PublishAsBundle(notification, stringData);
        ansManagerStub.SetNotificationBadgeNum(num);
        int importance = static_cast<int>(GetU32Data(data));
        ansManagerStub.GetBundleImportance(importance);
        bool granted = *data % ENABLE;
        ansManagerStub.HasNotificationPolicyAccessPermission(granted);
        int32_t removeReason = static_cast<int32_t>(GetU32Data(data));
        ansManagerStub.RemoveNotification(bundleOption, notificationId, stringData, removeReason);
        ansManagerStub.RemoveAllNotifications(bundleOption);
        ansManagerStub.Delete(stringData, removeReason);
        ansManagerStub.DeleteByBundle(bundleOption);
        ansManagerStub.DeleteAll();
        ansManagerStub.GetSlotsByBundle(bundleOption, slots);
        ansManagerStub.UpdateSlots(bundleOption, slots);
        sptr<Notification::AnsDialogCallback> dialogCallback = nullptr;
        sptr<IRemoteObject> callerToken = nullptr;
        ansManagerStub.RequestEnableNotification(stringData, dialogCallback, callerToken);
        bool enabled = *data % ENABLE;
        ansManagerStub.SetNotificationsEnabledForBundle(stringData, enabled);
        ansManagerStub.SetNotificationsEnabledForSpecialBundle(stringData, bundleOption, enabled);
        ansManagerStub.SetShowBadgeEnabledForBundle(bundleOption, enabled);
        ansManagerStub.GetShowBadgeEnabledForBundle(bundleOption, enabled);
        ansManagerStub.GetShowBadgeEnabled(enabled);
        bool allowed = *data % ENABLE;
        ansManagerStub.IsAllowedNotify(allowed);
        ansManagerStub.IsSpecialBundleAllowedNotify(bundleOption, allowed);
        ansManagerStub.CancelGroup(stringData);
        ansManagerStub.RemoveGroupByBundle(bundleOption, stringData);
        sptr<Notification::NotificationDoNotDisturbDate> date = new Notification::NotificationDoNotDisturbDate();
        ansManagerStub.SetDoNotDisturbDate(date);
        ansManagerStub.GetDoNotDisturbDate(date);
        bool doesSupport = *data % ENABLE;
        ansManagerStub.DoesSupportDoNotDisturbMode(doesSupport);
        ansManagerStub.IsDistributedEnabled(enabled);
        ansManagerStub.EnableDistributedByBundle(bundleOption, enabled);
        ansManagerStub.EnableDistributedSelf(enabled);
        ansManagerStub.IsDistributedEnableByBundle(bundleOption, enabled);
        Notification::NotificationConstant::RemindType remindType;
        ansManagerStub.GetDeviceRemindType(remindType);
        sptr<Notification::NotificationRequest> request = new Notification::NotificationRequest();
        ansManagerStub.PublishContinuousTaskNotification(request);
        ansManagerStub.CancelContinuousTaskNotification(stringData, notificationId);
        sptr<Notification::ReminderRequest> reminder = new Notification::ReminderRequest();
        ansManagerStub.PublishReminder(reminder);
        int32_t reminderId = static_cast<int32_t>(GetU32Data(data));
        ansManagerStub.CancelReminder(reminderId);
        std::vector<sptr<Notification::ReminderRequest>> reminders;
        ansManagerStub.GetValidReminders(reminders);
        ansManagerStub.CancelAllReminders();
        uint64_t excludeDate = static_cast<uint64_t>(GetU32Data(data));
        ansManagerStub.AddExcludeDate(reminderId, excludeDate);
        ansManagerStub.DelExcludeDates(reminderId);
        std::vector<uint64_t> excludeDates;
        ansManagerStub.GetExcludeDates(reminderId, excludeDates);
        bool support = *data % ENABLE;
        ansManagerStub.IsSupportTemplate(stringData, support);
        ansManagerStub.IsSpecialUserAllowedNotify(userId, allowed);
        int32_t deviceIds = static_cast<int32_t>(GetU32Data(data));
        ansManagerStub.SetNotificationsEnabledByUser(deviceIds, enabled);
        ansManagerStub.DeleteAllByUser(userId);
        ansManagerStub.SetDoNotDisturbDate(date);
        ansManagerStub.GetDoNotDisturbDate(date);
        ansManagerStub.SetEnabledForBundleSlot(bundleOption, slotType, enabled, false);
        ansManagerStub.GetEnabledForBundleSlot(bundleOption, slotType, enabled);
        std::vector<std::string> dumpInfo;
        ansManagerStub.ShellDump(stringData, stringData, userId, userId, dumpInfo);
        ansManagerStub.SetSyncNotificationEnabledWithoutApp(userId, enabled);
        ansManagerStub.GetSyncNotificationEnabledWithoutApp(userId, enabled);
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
