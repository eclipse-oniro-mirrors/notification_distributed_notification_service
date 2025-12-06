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


#define private public
#define protected public
#include "advanced_notification_service.h"
#undef private
#undef protected
#include "ans_dialog_callback_proxy.h"
#include "ans_permission_def.h"
#include "ans_result_data_synchronizer.h"
#include "ans_subscriber_local_live_view_proxy.h"
#include "ans_subscriber_proxy.h"
#include "ansmanagerstubannexthree_fuzzer.h"
#include "reminder_request_timer.h"
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include "swing_call_back_proxy.h"
#endif

constexpr uint8_t SLOT_TYPE_NUM = 5;

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        auto service = std::make_shared<Notification::AdvancedNotificationService>();
        service->InitPublishProcess();
        service->CreateDialogManager();

        bool allowed = fuzzData->ConsumeBool();
        bool canPublish = fuzzData->ConsumeBool();
        bool enabled = fuzzData->ConsumeBool();
        bool granted = fuzzData->ConsumeBool();
        bool isForceControl = fuzzData->ConsumeBool();
        bool isNative = fuzzData->ConsumeBool();
        bool isPaused = fuzzData->ConsumeBool();
        bool support = fuzzData->ConsumeBool();

        uint8_t type = fuzzData->ConsumeIntegral<uint8_t>() % SLOT_TYPE_NUM;
        uint32_t controlFlag = fuzzData->ConsumeIntegral<uint32_t>();
        uint32_t hashCodeType = fuzzData->ConsumeIntegral<uint32_t>();
        uint32_t slotFlags = fuzzData->ConsumeIntegral<uint32_t>();
        uint32_t status = fuzzData->ConsumeIntegral<uint32_t>();
        int32_t badgeNum = fuzzData->ConsumeIntegral<int32_t>();
        int32_t callerType = fuzzData->ConsumeIntegral<int32_t>();
        int32_t deviceIds = fuzzData->ConsumeIntegral<int32_t>();
        int32_t deviceStatus = fuzzData->ConsumeIntegral<int32_t>();
        int32_t importance = fuzzData->ConsumeIntegral<int32_t>();
        int32_t notificationId = fuzzData->ConsumeIntegral<int32_t>();
        int32_t remindType = fuzzData->ConsumeIntegral<int32_t>();
        int32_t removeReason = fuzzData->ConsumeIntegral<int32_t>();
        int32_t result = fuzzData->ConsumeIntegral<int32_t>();
        int32_t uid = fuzzData->ConsumeIntegral<int32_t>();
        int32_t userId = fuzzData->ConsumeIntegral<int32_t>();
        uint64_t num = fuzzData->ConsumeIntegral<uint64_t>();
        int64_t id = fuzzData->ConsumeIntegral<uint64_t>();

        std::string stringData = fuzzData->ConsumeRandomLengthString();
        std::string phoneNumber = fuzzData->ConsumeRandomLengthString();
        std::string deviceType = fuzzData->ConsumeRandomLengthString();
        std::string bundleName = fuzzData->ConsumeRandomLengthString();
        std::string value = fuzzData->ConsumeRandomLengthString();
        std::string key1 = fuzzData->ConsumeRandomLengthString();
        std::vector<std::string> keys;
        keys.emplace_back(fuzzData->ConsumeRandomLengthString());

        sptr<Notification::NotificationButtonOption> buttonOption = new Notification::NotificationButtonOption();
        sptr<Notification::NotificationBundleOption> bundleOption = new Notification::NotificationBundleOption();
        bundleOption->SetBundleName(fuzzData->ConsumeRandomLengthString());
        bundleOption->SetUid(fuzzData->ConsumeIntegral<int32_t>());
        sptr<Notification::NotificationSubscribeInfo> info = new Notification::NotificationSubscribeInfo();
        Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType(type);
        sptr<Notification::NotificationRequest> notificationRequest = new Notification::NotificationRequest();
        notificationRequest->SetOwnerUid(fuzzData->ConsumeIntegral<int32_t>());
        notificationRequest->SetCreatorUid(fuzzData->ConsumeIntegral<int32_t>());
        notificationRequest->SetSlotType(Notification::NotificationConstant::SlotType::LIVE_VIEW);
        auto content = std::make_shared<Notification::NotificationLiveViewContent>();
        notificationRequest->SetContent(std::make_shared<Notification::NotificationContent>(content));
        sptr<Notification::NotificationOperationInfo> operationInfo = new Notification::NotificationOperationInfo();
        operationInfo->SetActionName(fuzzData->ConsumeRandomLengthString());
        operationInfo->SetUserInput(fuzzData->ConsumeRandomLengthString());
        operationInfo->SetHashCode(fuzzData->ConsumeRandomLengthString());
        operationInfo->SetEventId(fuzzData->ConsumeRandomLengthString());

        sptr<Notification::NotificationDisable> notificationDisable = new Notification::NotificationDisable();
        sptr<Notification::NotificationSlot> slot = new Notification::NotificationSlot();
        sptr<Notification::NotificationDoNotDisturbDate> disturbDate = new Notification::NotificationDoNotDisturbDate();
        sptr<Notification::IAnsDialogCallback> callback = new Notification::AnsDialogCallbackProxy(nullptr);
        sptr<Notification::NotificationCheckRequest> notificationCheckRequest =
            new Notification::NotificationCheckRequest();

        std::vector<sptr<Notification::NotificationDoNotDisturbProfile>> profiles;
        sptr<Notification::NotificationDoNotDisturbProfile> profile =
            new Notification::NotificationDoNotDisturbProfile();
        profiles.emplace_back(profile);

        std::vector<sptr<Notification::Notification>> notificationsVector;
        std::vector<Notification::NotificationBundleOption> bundleOptions;
        std::vector<sptr<Notification::NotificationSlot>> slots;
        std::vector<sptr<Notification::NotificationRequest>> notificationRequests;
        sptr<Notification::AnsResultDataSynchronizerImpl> synchronizer =
            new Notification::AnsResultDataSynchronizerImpl();

        service->Delete(stringData, removeReason);
        service->DeleteByBundle(bundleOption);
        service->DeleteAll();
        service->GetSlotsByBundle(bundleOption, slots);
        service->UpdateSlots(bundleOption, slots);
        service->SetNotificationsEnabledForBundle(stringData, enabled);
        service->SetNotificationsEnabledForAllBundles(stringData, enabled);
        service->SetNotificationsEnabledForSpecialBundle(stringData, bundleOption, enabled);
        service->SetShowBadgeEnabledForBundle(bundleOption, enabled);
        service->GetShowBadgeEnabledForBundle(bundleOption, enabled);
        if (service->GetShowBadgeEnabledForBundle(bundleOption,
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->GetShowBadgeEnabled(enabled);
        if (service->GetShowBadgeEnabled(
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->IsAllowedNotify(allowed);
        service->IsAllowedNotifySelf(allowed);
        service->IsAllowedNotifySelf(bundleOption, allowed);
        service->IsSpecialBundleAllowedNotify(bundleOption, allowed);
        service->CancelGroup(stringData, fuzzData->ConsumeRandomLengthString());
        service->RemoveGroupByBundle(bundleOption, stringData);
        service->IsDistributedEnabled(enabled);
        service->EnableDistributedByBundle(bundleOption, enabled);
        service->EnableDistributedSelf(enabled);
        service->EnableDistributed(enabled);
        service->IsDistributedEnableByBundle(bundleOption, enabled);
        service->GetDeviceRemindType(remindType);
        service->ShellDump(stringData, stringData, userId, userId, keys);
        service->IsSupportTemplate(stringData, support);
        service->IsSpecialUserAllowedNotify(userId, allowed);
        service->SetNotificationsEnabledByUser(deviceIds, enabled);
        service->DeleteAllByUser(userId);
        service->SetEnabledForBundleSlot(bundleOption, slotType, enabled, isForceControl);
        service->RequestEnableNotification(stringData, callback, nullptr);
        service->RequestEnableNotification(stringData, callback);
        service->Subscribe(nullptr, info, fuzzData->ConsumeIntegral<uint32_t>());
        service->Subscribe(nullptr, fuzzData->ConsumeIntegral<uint32_t>());
        service->Unsubscribe(nullptr, info);
        service->Unsubscribe(nullptr);
        service->SubscribeLocalLiveView(nullptr, info, isNative);
        service->SubscribeLocalLiveView(nullptr, isNative);
        service->IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType);
        service->Publish(stringData, notificationRequest);
        service->PublishWithMaxCapacity(stringData, notificationRequest);
        service->PublishNotificationForIndirectProxy(notificationRequest);
        service->PublishNotificationForIndirectProxyWithMaxCapacity(notificationRequest);
        service->CancelAsBundle(notificationId, stringData, userId);
        if (service->CancelAsBundle(notificationId, stringData, userId,
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->CancelAsBundle(bundleOption, notificationId);
        if (service->CancelAsBundle(bundleOption, notificationId,
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->CancelAsBundle(bundleOption, notificationId, userId);
        if (service->CancelAsBundle(bundleOption, notificationId, userId,
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->CancelAll(key1);
        if (service->CancelAll(key1,
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->Cancel(notificationId, stringData, key1);
        if (service->Cancel(notificationId, stringData, key1,
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->AddSlotByType(slotType);
        service->AddSlots(slots);
        service->RemoveSlotByType(slotType);
        service->RemoveAllSlots();
        service->GetSlots(slots);
        service->GetSlotByType(slotType, slot);
        service->GetSlotNumAsBundle(bundleOption, num);
        service->SetSlotFlagsAsBundle(bundleOption, slotFlags);
        service->GetSlotFlagsAsBundle(bundleOption, slotFlags);
        service->GetActiveNotifications(notificationRequests, key1);
        if (service->GetActiveNotifications(key1,
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->GetActiveNotificationNums(num);
        service->GetAllActiveNotifications(notificationsVector);
        if (service->GetAllActiveNotifications(
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->GetSpecialActiveNotifications(keys, notificationsVector);
        service->GetActiveNotificationByFilter(
            bundleOption, notificationId, stringData, userId, keys, notificationRequest);
        service->CanPublishAsBundle(stringData, canPublish);
        service->PublishAsBundle(notificationRequest, stringData);
        service->PublishAsBundleWithMaxCapacity(notificationRequest, stringData);
        service->SetNotificationBadgeNum(num);
        service->GetBundleImportance(importance);
        service->PublishContinuousTaskNotification(notificationRequest);
        service->CancelContinuousTaskNotification(stringData, notificationId);
        service->HasNotificationPolicyAccessPermission(granted);
        service->TriggerLocalLiveView(bundleOption, notificationId, buttonOption);
        service->RemoveNotification(bundleOption, notificationId, stringData, removeReason);
        service->RemoveAllNotifications(bundleOption);
        service->RemoveNotifications(keys, removeReason);
        service->GetSlotByBundle(bundleOption, slotType, slot);
        service->CanPopEnableNotificationDialog(nullptr, enabled, bundleName);
        service->RemoveEnableNotificationDialog();
        service->RemoveEnableNotificationDialog(bundleOption);
        service->GetEnabledForBundleSlot(bundleOption, slotType, enabled);
        service->GetEnabledForBundleSlotSelf(slotType, enabled);
        service->SetSyncNotificationEnabledWithoutApp(userId, enabled);
        service->GetSyncNotificationEnabledWithoutApp(userId, enabled);
        service->SetBadgeNumber(badgeNum, key1);
        service->SetBadgeNumberByBundle(bundleOption, badgeNum);
        service->GetAllNotificationEnabledBundles(bundleOptions);
        service->RegisterPushCallback(nullptr, notificationCheckRequest);
        service->UnregisterPushCallback();
        service->SetDistributedEnabledBySlot(slotType, deviceType, enabled);
        service->GetAllDistribuedEnabledBundles(deviceType, bundleOptions);
        service->GetAllNotificationsBySlotType(notificationsVector, slotType);
        service->AllowUseReminder(bundleName, allowed);
        service->SetTargetDeviceStatus(deviceType, status, stringData);
        service->SetTargetDeviceStatus(deviceType, status, controlFlag, stringData, userId);
        service->SetDistributedEnabledByBundle(bundleOption, deviceType, enabled);
        service->IsDistributedEnabledByBundle(bundleOption, deviceType, enabled);
        service->SetSmartReminderEnabled(deviceType, enabled);
        service->IsSmartReminderEnabled(deviceType, enabled);
        service->SetAdditionConfig(key1, value);
        service->CancelAsBundleWithAgent(bundleOption, userId);
        if (service->CancelAsBundleWithAgent(bundleOption, userId,
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->GetTargetDeviceStatus(deviceType, deviceStatus);

        service->AddDoNotDisturbProfiles(profiles);
        service->RemoveDoNotDisturbProfiles(profiles);
        service->SetDoNotDisturbDate(disturbDate);
        service->GetDoNotDisturbDate(disturbDate);
        service->SetDoNotDisturbDateByUser(userId, disturbDate);
        service->GetDoNotDisturbDateByUser(userId, disturbDate);
        service->GetDoNotDisturbProfile(id, profile);
        service->DoesSupportDoNotDisturbMode(support);

        service->SetBadgeNumberForDhByBundle(bundleOption, badgeNum);
        service->GetNotificationRequestByHashCode(stringData, notificationRequest);
        service->DistributeOperation(operationInfo, nullptr);
        service->SetHashCodeRule(hashCodeType);
        service->GetAllLiveViewEnabledBundles(bundleOptions);
        service->GetAllLiveViewEnabledBundles(bundleOptions, userId);
        service->DisableNotificationFeature(notificationDisable);
        service->ReplyDistributeOperation(stringData, result);
        service->UpdateNotificationTimerByUid(uid, isPaused);
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
        sptr<Notification::ISwingCallBack> swingCallBack = new Notification::SwingCallBackProxy(nullptr);
        service->RegisterSwingCallback(swingCallBack->AsObject());
#endif
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
    NativeTokenGet(requestPermission);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
