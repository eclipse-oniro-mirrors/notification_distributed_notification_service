/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <new>
#include <string>
#include <vector>
#define private public
#define protected public
#include "advanced_notification_service.h"
#include "ans_manager_proxy.h"
#include "ans_manager_stub.h"
#include "ans_subscriber_stub.h"
#undef private
#undef protected
#include "ansmanagerstubannex_fuzzer.h"
#include "notification_request.h"
#include "ans_permission_def.h"

constexpr uint8_t SLOT_TYPE_NUM = 5;

namespace OHOS {
    inline int64_t GetCurrentTime()
    {
        auto now = std::chrono::system_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
        return duration.count();
    }

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        std::string stringData = fuzzData->ConsumeRandomLengthString();
        int32_t intData = fuzzData->ConsumeIntegral<int32_t>();
        bool boolData = fuzzData->ConsumeBool();
        Notification::AdvancedNotificationService ansManagerStub;
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
        notification->SetOwnerUid(fuzzData->ConsumeIntegral<int32_t>());
        notification->SetCreatorUid(fuzzData->ConsumeIntegral<int32_t>());
        notification->SetSlotType(Notification::NotificationConstant::SlotType::LIVE_VIEW);
        auto content = std::make_shared<Notification::NotificationLiveViewContent>();
        notification->SetContent(std::make_shared<Notification::NotificationContent>(content));

        sptr<Notification::NotificationBundleOption> bundleOption = new Notification::NotificationBundleOption();
        bundleOption->SetBundleName(fuzzData->ConsumeRandomLengthString());
        bundleOption->SetUid(fuzzData->ConsumeIntegral<int32_t>());

        sptr<Notification::NotificationButtonOption> buttonOption = new Notification::NotificationButtonOption();

        sptr<Notification::NotificationSubscribeInfo> info = new Notification::NotificationSubscribeInfo();

        sptr<Notification::NotificationSlot> slot = new Notification::NotificationSlot();
        std::vector<sptr<Notification::NotificationSlot>> slots {slot};

        uint8_t type = fuzzData->ConsumeIntegral<uint8_t>() % SLOT_TYPE_NUM;

        sptr<Notification::NotificationDoNotDisturbDate> distribuDate = new Notification::NotificationDoNotDisturbDate();

        datas.WriteString(stringData);
        datas.WriteParcelable(notification);
        ansManagerStub.HandlePublish(datas, reply);
        datas.WriteParcelable(notification);
        ansManagerStub.HandlePublishNotificationForIndirectProxy(datas, reply);
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
        datas.WriteInt32(intData);
        ansManagerStub.HandleGetDoNotDisturbProfile(datas, reply);
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
        datas.WriteBool(boolData);
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
        datas.WriteBool(boolData);
        if (boolData) {
            datas.WriteParcelable(info);
        }
        ansManagerStub.HandleSubscribe(datas, reply);
        ansManagerStub.HandleSubscribeSelf(datas, reply);
        datas.WriteBool(boolData);
        if (boolData) {
            datas.WriteParcelable(info);
        }
        datas.WriteBool(boolData);
        ansManagerStub.HandleSubscribeLocalLiveView(datas, reply);
        datas.WriteBool(boolData);
        if (boolData) {
            datas.WriteParcelable(info);
        }
        ansManagerStub.HandleUnsubscribe(datas, reply);
        ansManagerStub.HandleIsAllowedNotify(datas, reply);
        ansManagerStub.HandleIsAllowedNotifySelf(datas, reply);
        ansManagerStub.HandleCanPopEnableNotificationDialog(datas, reply);
        ansManagerStub.HandleRemoveEnableNotificationDialog(datas, reply);
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
        datas.WriteString(stringData);
        datas.WriteBool(boolData);
        ansManagerStub.HandleSetDistributedEnabledBySlot(datas, reply);
        datas.WriteString(stringData);
        ansManagerStub.HandleGetAllDistributedEnabledBundles(datas, reply);
        datas.WriteInt32(intData);
        ansManagerStub.HandleGetAllNotificationsBySlotType(datas, reply);
        datas.WriteString(stringData);
        ansManagerStub.HandleAllowUseReminder(datas, reply);
        datas.WriteString(stringData);
        datas.WriteInt32(intData);
        datas.WriteInt32(intData);
        ansManagerStub.HandleSetDeviceStatus(datas, reply);
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
        datas.WriteString(stringData);
        ansManagerStub.HandleGetDeviceStatus(datas, reply);
        sptr<Notification::NotificationRequest> notification2 = new Notification::NotificationRequest();
        notification2->SetOwnerUid(fuzzData->ConsumeIntegral<int32_t>());
        notification2->SetCreatorUid(fuzzData->ConsumeIntegral<int32_t>());
        notification2->SetSlotType(Notification::NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
        auto content2 = std::make_shared<Notification::NotificationNormalContent>();
        notification2->SetContent(std::make_shared<Notification::NotificationContent>(content2));
        ansManagerStub.Publish(stringData, notification2);
        int notificationId = fuzzData->ConsumeIntegral<int>();
        ansManagerStub.Cancel(notificationId, stringData, "");
        ansManagerStub.CancelAll("");
        int32_t userId = fuzzData->ConsumeIntegral<int32_t>();
        ansManagerStub.CancelAsBundle(notificationId, stringData, userId);
        Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType(type);
        ansManagerStub.AddSlotByType(slotType);
        ansManagerStub.AddSlots(slots);
        ansManagerStub.RemoveSlotByType(slotType);
        ansManagerStub.RemoveAllSlots();
        ansManagerStub.GetSlotByType(slotType, slot);
        ansManagerStub.GetSlots(slots);
        uint64_t num = fuzzData->ConsumeIntegral<uint64_t>();
        ansManagerStub.GetSlotNumAsBundle(bundleOption, num);
        std::vector<sptr<Notification::NotificationRequest>> notifications;
        ansManagerStub.GetActiveNotifications(notifications, "");
        ansManagerStub.GetActiveNotificationNums(num);
        std::vector<sptr<Notification::Notification>> notificationss;
        ansManagerStub.GetAllActiveNotifications(notificationss);
        std::vector<std::string> key;
        ansManagerStub.GetSpecialActiveNotifications(key, notificationss);
        bool canPublish = fuzzData->ConsumeBool();
        ansManagerStub.CanPublishAsBundle(stringData, canPublish);
        ansManagerStub.PublishAsBundle(notification, stringData);
        ansManagerStub.SetNotificationBadgeNum(num);
        int importance = fuzzData->ConsumeIntegral<int>();
        ansManagerStub.GetBundleImportance(importance);
        bool granted = fuzzData->ConsumeBool();
        ansManagerStub.HasNotificationPolicyAccessPermission(granted);
        int32_t removeReason = fuzzData->ConsumeIntegral<int32_t>();
        ansManagerStub.RemoveNotification(bundleOption, notificationId, stringData, removeReason);
        ansManagerStub.RemoveAllNotifications(bundleOption);
        ansManagerStub.Delete(stringData, removeReason);
        ansManagerStub.DeleteByBundle(bundleOption);
        ansManagerStub.DeleteAll();
        ansManagerStub.GetSlotsByBundle(bundleOption, slots);
        ansManagerStub.UpdateSlots(bundleOption, slots);
        sptr<Notification::IAnsDialogCallback> dialogCallback = nullptr;
        sptr<IRemoteObject> callerToken = nullptr;
        ansManagerStub.RequestEnableNotification(stringData, dialogCallback, callerToken);
        bool enabled = fuzzData->ConsumeBool();
        ansManagerStub.SetNotificationsEnabledForBundle(stringData, enabled);
        ansManagerStub.SetNotificationsEnabledForSpecialBundle(stringData, bundleOption, enabled);
        ansManagerStub.SetShowBadgeEnabledForBundle(bundleOption, enabled);
        ansManagerStub.GetShowBadgeEnabledForBundle(bundleOption, enabled);
        ansManagerStub.GetShowBadgeEnabled(enabled);
        bool allowed = fuzzData->ConsumeBool();
        ansManagerStub.IsAllowedNotify(allowed);
        ansManagerStub.IsSpecialBundleAllowedNotify(bundleOption, allowed);
        ansManagerStub.CancelGroup(stringData, "");
        ansManagerStub.RemoveGroupByBundle(bundleOption, stringData);
        sptr<Notification::NotificationDoNotDisturbDate> date = new Notification::NotificationDoNotDisturbDate();
        ansManagerStub.SetDoNotDisturbDate(date);
        ansManagerStub.GetDoNotDisturbDate(date);
        bool doesSupport = fuzzData->ConsumeBool();
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
        bool support = fuzzData->ConsumeBool();
        ansManagerStub.IsSupportTemplate(stringData, support);
        ansManagerStub.IsSpecialUserAllowedNotify(userId, allowed);
        int32_t deviceIds = fuzzData->ConsumeIntegral<int32_t>();
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
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> requestPermission = {
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION
    };
    SystemHapTokenGet(requestPermission);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
