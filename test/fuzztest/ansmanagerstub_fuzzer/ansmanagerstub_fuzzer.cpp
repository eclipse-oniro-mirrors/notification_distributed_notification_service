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

#include "notification_constant.h"
#include "notification_content.h"
#include "notification_normal_content.h"
#include "refbase.h"
#include <memory>
#include <new>
#include <string>
#include <vector>
#define private public
#define protected public
#include "ans_manager_proxy.h"
#include "ans_manager_stub.h"
#include "ans_subscriber_stub.h"
#undef private
#undef protected
#include "ansmanagerstub_fuzzer.h"
#include "notification_request.h"
#include "ans_permission_def.h"

constexpr uint8_t SLOT_TYPE_NUM = 5;

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(FuzzData fuzzData)
    {
        std::string stringData = fuzzData.GenerateRandomString();
        int32_t intData = fuzzData.GenerateRandomInt32();
        bool boolData = fuzzData.GenerateRandomBool();
        Notification::AnsManagerStub ansManagerStub;
        MessageParcel datas;
        MessageParcel reply;
        MessageOption flags;
        // test HandleIsNeedSilentInDoNotDisturbMode function
        ansManagerStub.HandleIsNeedSilentInDoNotDisturbMode(datas, reply);
        // test HandleRegisterSwingCallback function
        #ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
        ansManagerStub.HandleRegisterSwingCallback(datas, reply);
        #endif
        ansManagerStub.OnRemoteRequest(0, datas, reply, flags);
        ansManagerStub.OnRemoteRequest((int) Notification::NotificationInterfaceCode::PUBLISH_NOTIFICATION,
            datas, reply, flags);
        sptr<Notification::NotificationRequest> notification = new Notification::NotificationRequest();
        notification->SetOwnerUid(fuzzData.GenerateRandomInt32());
        notification->SetCreatorUid(fuzzData.GenerateRandomInt32());
        notification->SetSlotType(Notification::NotificationConstant::SlotType::LIVE_VIEW);
        auto content = std::make_shared<Notification::NotificationLiveViewContent>();
        notification->SetContent(std::make_shared<Notification::NotificationContent>(content));

        sptr<Notification::NotificationBundleOption> bundleOption = new Notification::NotificationBundleOption();
        bundleOption->SetBundleName(fuzzData.GenerateRandomString());
        bundleOption->SetUid(fuzzData.GenerateRandomInt32());

        sptr<Notification::NotificationButtonOption> buttonOption = new Notification::NotificationButtonOption();

        sptr<Notification::AnsSubscriberStub> subscriber = new Notification::AnsSubscriberStub();
        sptr<Notification::NotificationSubscribeInfo> info = new Notification::NotificationSubscribeInfo();

        sptr<Notification::NotificationSlot> slot = new Notification::NotificationSlot();
        std::vector<sptr<Notification::NotificationSlot>> slots {slot};

        uint8_t type = fuzzData.GetData<uint8_t>() % SLOT_TYPE_NUM;

        sptr<Notification::NotificationDoNotDisturbDate> distribuDate = new Notification::NotificationDoNotDisturbDate();

        datas.WriteString(stringData);
        datas.WriteParcelable(notification);
        ansManagerStub.HandlePublish(datas, reply);
        datas.WriteInt32(intData);
        datas.WriteString(stringData);
        datas.WriteInt32(intData);
        ansManagerStub.HandleCancelAsBundle(datas, reply);
        datas.WriteParcelable(bundleOption);
        datas.WriteInt32(intData);
        ansManagerStub.HandleCancelAsBundleOption(datas, reply);
        datas.WriteInt32(intData);
        ansManagerStub.HandleCancelAll(datas, reply);
        datas.WriteInt32(intData);
        datas.WriteString(stringData);
        datas.WriteInt32(intData);
        ansManagerStub.HandleCancel(datas, reply);
        datas.WriteParcelable(bundleOption);
        datas.WriteInt32(intData);
        datas.WriteInt32(intData);
        ansManagerStub.HandleCancelAsBundleAndUser(datas, reply);
        datas.WriteInt32(type);
        ansManagerStub.HandleAddSlotByType(datas, reply);
        ansManagerStub.HandleAddSlots(datas, reply);
        datas.WriteInt32(type);
        ansManagerStub.HandleRemoveSlotByType(datas, reply);
        ansManagerStub.HandleRemoveAllSlots(datas, reply);
        ansManagerStub.HandleGetSlots(datas, reply);
        datas.WriteInt32(type);
        ansManagerStub.HandleGetSlotByType(datas, reply);
        datas.WriteParcelable(bundleOption);
        ansManagerStub.HandleGetSlotNumAsBundle(datas, reply);
        datas.WriteParcelable(bundleOption);
        datas.WriteInt32(intData);
        ansManagerStub.HandleSetSlotFlagsAsBundle(datas, reply);
        datas.WriteParcelable(bundleOption);
        ansManagerStub.HandleGetSlotFlagsAsBundle(datas, reply);
        datas.WriteInt32(intData);
        ansManagerStub.HandleGetActiveNotifications(datas, reply);
        ansManagerStub.HandleGetActiveNotificationNums(datas, reply);
        ansManagerStub.HandleGetAllActiveNotifications(datas, reply);
        std::vector<std::string> stringVector { stringData };
        datas.WriteStringVector(stringVector);
        ansManagerStub.HandleGetSpecialActiveNotifications(datas, reply);
        datas.WriteParcelable(bundleOption);
        datas.WriteInt32(intData);
        datas.WriteString(stringData);
        datas.WriteStringVector(stringVector);
        ansManagerStub.HandleGetActiveNotificationByFilter(datas, reply);
        datas.WriteString(stringData);
        ansManagerStub.HandleSetNotificationAgent(datas, reply);
        ansManagerStub.HandleGetNotificationAgent(datas, reply);
        datas.WriteString(stringData);
        ansManagerStub.HandleCanPublishAsBundle(datas, reply);
        datas.WriteParcelable(notification);
        datas.WriteString(stringData);
        ansManagerStub.HandlePublishAsBundle(datas, reply);
        datas.WriteInt32(intData);
        ansManagerStub.HandleSetNotificationBadgeNum(datas, reply);
        ansManagerStub.HandleGetBundleImportance(datas, reply);
        datas.WriteParcelable(distribuDate);
        ansManagerStub.HandleSetDoNotDisturbDate(datas, reply);
        ansManagerStub.HandleGetDoNotDisturbDate(datas, reply);
        ansManagerStub.HandleDoesSupportDoNotDisturbMode(datas, reply);
        datas.WriteParcelable(notification);
        datas.WriteInt32(intData);
        ansManagerStub.HandlePublishContinuousTaskNotification(datas, reply);
        datas.WriteString(stringData);
        datas.WriteInt32(intData);
        ansManagerStub.HandleCancelContinuousTaskNotification(datas, reply);
        ansManagerStub.HandleIsNotificationPolicyAccessGranted(datas, reply);
        datas.WriteParcelable(bundleOption);
        datas.WriteInt32(intData);
        datas.WriteParcelable(buttonOption);
        ansManagerStub.HandleTriggerLocalLiveView(datas, reply);
        datas.WriteParcelable(bundleOption);
        datas.WriteInt32(intData);
        datas.WriteString(stringData);
        datas.WriteInt32(intData);
        ansManagerStub.HandleRemoveNotification(datas, reply);
        ansManagerStub.HandleRemoveAllNotifications(datas, reply);
        datas.WriteInt32(intData);
        datas.WriteStringVector(stringVector);
        datas.WriteInt32(intData);
        ansManagerStub.HandleRemoveNotifications(datas, reply);
        datas.WriteString(stringData);
        datas.WriteInt32(intData);
        ansManagerStub.HandleDelete(datas, reply);
        datas.WriteParcelable(bundleOption);
        ansManagerStub.HandleDeleteByBundle(datas, reply);
        ansManagerStub.HandleDeleteAll(datas, reply);
        datas.WriteParcelable(bundleOption);
        datas.WriteInt32(intData);
        ansManagerStub.HandleGetSlotByBundle(datas, reply);
        ansManagerStub.HandleGetSlotsByBundle(datas, reply);
        datas.WriteParcelable(bundleOption);
        ansManagerStub.HandleUpdateSlots(datas, reply);
        datas.WriteString(stringData);
        datas.WriteRemoteObject(subscriber);
        datas.WriteBool(boolData);
        if (boolData) {
            datas.WriteRemoteObject(subscriber);
        }
        ansManagerStub.HandleRequestEnableNotification(datas, reply);
        datas.WriteString(stringData);
        datas.WriteBool(boolData);
        ansManagerStub.HandleSetNotificationsEnabledForBundle(datas, reply);
        datas.WriteString(stringData);
        datas.WriteBool(boolData);
        ansManagerStub.HandleSetNotificationsEnabledForAllBundles(datas, reply);
        datas.WriteString(stringData);
        datas.WriteParcelable(bundleOption);
        datas.WriteBool(boolData);
        ansManagerStub.HandleSetNotificationsEnabledForSpecialBundle(datas, reply);
        datas.WriteParcelable(bundleOption);
        datas.WriteBool(boolData);
        ansManagerStub.HandleSetShowBadgeEnabledForBundle(datas, reply);
        datas.WriteParcelable(bundleOption);
        ansManagerStub.HandleGetShowBadgeEnabledForBundle(datas, reply);
        ansManagerStub.HandleGetShowBadgeEnabled(datas, reply);
        datas.WriteRemoteObject(subscriber);
        datas.WriteBool(boolData);
        if (boolData) {
            datas.WriteParcelable(info);
        }
        ansManagerStub.HandleSubscribe(datas, reply);
        datas.WriteRemoteObject(subscriber);
        ansManagerStub.HandleSubscribeSelf(datas, reply);
        datas.WriteRemoteObject(subscriber);
        datas.WriteBool(boolData);
        if (boolData) {
            datas.WriteParcelable(info);
        }
        datas.WriteBool(boolData);
        ansManagerStub.HandleSubscribeLocalLiveView(datas, reply);
        datas.WriteRemoteObject(subscriber);
        datas.WriteBool(boolData);
        if (boolData) {
            datas.WriteParcelable(info);
        }
        ansManagerStub.HandleUnsubscribe(datas, reply);
        ansManagerStub.HandleIsAllowedNotify(datas, reply);
        ansManagerStub.HandleIsAllowedNotifySelf(datas, reply);
        datas.WriteRemoteObject(subscriber);
        ansManagerStub.HandleCanPopEnableNotificationDialog(datas, reply);
        datas.WriteParcelable(bundleOption);
        ansManagerStub.HandleIsSpecialBundleAllowedNotify(datas, reply);
        datas.WriteString(stringData);
        datas.WriteInt32(intData);
        ansManagerStub.HandleCancelGroup(datas, reply);
        datas.WriteParcelable(bundleOption);
        datas.WriteString(stringData);
        ansManagerStub.HandleRemoveGroupByBundle(datas, reply);
        ansManagerStub.HandleIsDistributedEnabled(datas, reply);
        datas.WriteBool(boolData);
        ansManagerStub.HandleEnableDistributed(datas, reply);
        datas.WriteParcelable(bundleOption);
        datas.WriteBool(boolData);
        ansManagerStub.HandleEnableDistributedByBundle(datas, reply);
        datas.WriteBool(boolData);
        ansManagerStub.HandleEnableDistributedSelf(datas, reply);
        datas.WriteParcelable(bundleOption);
        ansManagerStub.HandleIsDistributedEnableByBundle(datas, reply);
        ansManagerStub.HandleGetDeviceRemindType(datas, reply);
        datas.WriteString(stringData);
        datas.WriteString(stringData);
        datas.WriteInt32(intData);
        datas.WriteInt32(intData);
        ansManagerStub.HandleShellDump(datas, reply);
        ansManagerStub.HandlePublishReminder(datas, reply);
        datas.WriteInt32(intData);
        ansManagerStub.HandleCancelReminder(datas, reply);
        ansManagerStub.HandleCancelAllReminders(datas, reply);
        ansManagerStub.HandleGetValidReminders(datas, reply);
        datas.WriteInt32(intData);
        datas.WriteUint64(intData);
        ansManagerStub.HandleAddExcludeDate(datas, reply);
        datas.WriteInt32(intData);
        ansManagerStub.HandleDelExcludeDates(datas, reply);
        datas.WriteInt32(intData);
        ansManagerStub.HandleGetExcludeDates(datas, reply);
        datas.WriteString(stringData);
        ansManagerStub.HandleIsSupportTemplate(datas, reply);
        datas.WriteInt32(intData);
        ansManagerStub.HandleIsSpecialUserAllowedNotifyByUser(datas, reply);
        datas.WriteInt32(intData);
        datas.WriteBool(boolData);
        ansManagerStub.HandleSetNotificationsEnabledByUser(datas, reply);
        datas.WriteInt32(intData);
        ansManagerStub.HandleDeleteAllByUser(datas, reply);
        datas.WriteInt32(intData);
        datas.WriteParcelable(distribuDate);
        ansManagerStub.HandleSetDoNotDisturbDateByUser(datas, reply);
        datas.WriteInt32(intData);
        ansManagerStub.HandleGetDoNotDisturbDateByUser(datas, reply);
        datas.WriteParcelable(bundleOption);
        datas.WriteInt32(type);
        datas.WriteBool(boolData);
        datas.WriteBool(boolData);
        ansManagerStub.HandleSetEnabledForBundleSlot(datas, reply);
        datas.WriteParcelable(bundleOption);
        datas.WriteInt32(type);
        ansManagerStub.HandleGetEnabledForBundleSlot(datas, reply);
        datas.WriteInt32(type);
        ansManagerStub.HandleGetEnabledForBundleSlotSelf(datas, reply);
        datas.WriteInt32(intData);
        datas.WriteBool(boolData);
        ansManagerStub.HandleDistributedSetEnabledWithoutApp(datas, reply);
        datas.WriteInt32(intData);
        ansManagerStub.HandleDistributedGetEnabledWithoutApp(datas, reply);
        datas.WriteInt32(intData);
        datas.WriteInt32(intData);
        ansManagerStub.HandleSetBadgeNumber(datas, reply);
        datas.WriteParcelable(bundleOption);
        datas.WriteInt32(intData);
        ansManagerStub.HandleSetBadgeNumberByBundle(datas, reply);
        ansManagerStub.HandleGetAllNotificationEnableStatus(datas, reply);
        ansManagerStub.HandleRegisterPushCallback(datas, reply);
        ansManagerStub.HandleUnregisterPushCallback(datas, reply);
        ansManagerStub.HandleAddDoNotDisturbProfiles(datas, reply);
        datas.WriteParcelable(bundleOption);
        datas.WriteString(stringData);
        datas.WriteBool(boolData);
        ansManagerStub.HandleSetDistributedEnabledByBundle(datas, reply);
        ansManagerStub.HandleRemoveDoNotDisturbProfiles(datas, reply);
        datas.WriteParcelable(bundleOption);
        datas.WriteString(stringData);
        ansManagerStub.HandleIsDistributedEnabledByBundle(datas, reply);
        datas.WriteString(stringData);
        datas.WriteBool(boolData);
        ansManagerStub.HandleSetSmartReminderEnabled(datas, reply);
        datas.WriteString(stringData);
        ansManagerStub.HandleIsSmartReminderEnabled(datas, reply);
        datas.WriteString(stringData);
        datas.WriteString(stringData);
        ansManagerStub.HandleSetAdditionConfig(datas, reply);
        datas.WriteParcelable(bundleOption);
        datas.WriteInt32(intData);
        ansManagerStub.HandleCancelAsBundleWithAgent(datas, reply);
        datas.WriteString(stringData);
        datas.WriteInt32(intData);
        ansManagerStub.HandleSetTargetDeviceStatus(datas, reply);
        datas.WriteInt32(intData);
        datas.WriteBool(boolData);
        ansManagerStub.HandleUpdateNotificationTimerByUid(datas, reply);
        sptr<Notification::NotificationRequest> notification2 = new Notification::NotificationRequest();
        notification2->SetOwnerUid(fuzzData.GenerateRandomInt32());
        notification2->SetCreatorUid(fuzzData.GenerateRandomInt32());
        notification2->SetSlotType(Notification::NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
        auto content2 = std::make_shared<Notification::NotificationNormalContent>();
        notification2->SetContent(std::make_shared<Notification::NotificationContent>(content2));
        ansManagerStub.Publish(stringData, notification2);
        int notificationId = fuzzData.GetData<int>();
        ansManagerStub.Cancel(notificationId, stringData, 0);
        ansManagerStub.CancelAll("");
        int32_t userId = fuzzData.GetData<int32_t>();
        ansManagerStub.CancelAsBundle(notificationId, stringData, userId);
        Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType(type);
        ansManagerStub.AddSlotByType(slotType);
        ansManagerStub.AddSlots(slots);
        ansManagerStub.RemoveSlotByType(slotType);
        ansManagerStub.RemoveAllSlots();
        ansManagerStub.GetSlotByType(slotType, slot);
        ansManagerStub.GetSlots(slots);
        uint64_t num = fuzzData.GetData<uint64_t>();
        ansManagerStub.GetSlotNumAsBundle(bundleOption, num);
        std::vector<sptr<Notification::NotificationRequest>> notifications;
        ansManagerStub.GetActiveNotifications(notifications, "");
        ansManagerStub.GetActiveNotificationNums(num);
        std::vector<sptr<Notification::Notification>> notificationss;
        ansManagerStub.GetAllActiveNotifications(notificationss);
        std::vector<std::string> key;
        ansManagerStub.GetSpecialActiveNotifications(key, notificationss);
        ansManagerStub.SetNotificationAgent(stringData);
        ansManagerStub.GetNotificationAgent(stringData);
        bool canPublish = fuzzData.GenerateRandomBool();
        ansManagerStub.CanPublishAsBundle(stringData, canPublish);
        ansManagerStub.PublishAsBundle(notification, stringData);
        ansManagerStub.SetNotificationBadgeNum(num);
        int importance = fuzzData.GetData<int>();
        ansManagerStub.GetBundleImportance(importance);
        bool granted = fuzzData.GenerateRandomBool();
        ansManagerStub.HasNotificationPolicyAccessPermission(granted);
        int32_t removeReason = fuzzData.GetData<int32_t>();
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
        bool enabled = fuzzData.GenerateRandomBool();
        ansManagerStub.SetNotificationsEnabledForBundle(stringData, enabled);
        ansManagerStub.SetNotificationsEnabledForSpecialBundle(stringData, bundleOption, enabled);
        ansManagerStub.SetShowBadgeEnabledForBundle(bundleOption, enabled);
        ansManagerStub.GetShowBadgeEnabledForBundle(bundleOption, enabled);
        ansManagerStub.GetShowBadgeEnabled(enabled);
        bool allowed = fuzzData.GenerateRandomBool();
        ansManagerStub.IsAllowedNotify(allowed);
        ansManagerStub.IsSpecialBundleAllowedNotify(bundleOption, allowed);
        ansManagerStub.CancelGroup(stringData, "");
        ansManagerStub.RemoveGroupByBundle(bundleOption, stringData);
        sptr<Notification::NotificationDoNotDisturbDate> date = new Notification::NotificationDoNotDisturbDate();
        ansManagerStub.SetDoNotDisturbDate(date);
        ansManagerStub.GetDoNotDisturbDate(date);
        bool doesSupport = fuzzData.GenerateRandomBool();
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
        int32_t reminderId = fuzzData.GetData<int32_t>();
        ansManagerStub.CancelReminder(reminderId);
        std::vector<sptr<Notification::ReminderRequest>> reminders;
        ansManagerStub.GetValidReminders(reminders);
        ansManagerStub.CancelAllReminders();
        uint64_t excludeDate = fuzzData.GetData<uint64_t>();
        ansManagerStub.AddExcludeDate(reminderId, excludeDate);
        ansManagerStub.DelExcludeDates(reminderId);
        std::vector<uint64_t> excludeDates;
        ansManagerStub.GetExcludeDates(reminderId, excludeDates);
        bool support = fuzzData.GenerateRandomBool();
        ansManagerStub.IsSupportTemplate(stringData, support);
        ansManagerStub.IsSpecialUserAllowedNotify(userId, allowed);
        int32_t deviceIds = fuzzData.GetData<int32_t>();
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
