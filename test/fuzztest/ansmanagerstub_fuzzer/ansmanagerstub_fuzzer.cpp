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

#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "advanced_notification_service.h"
#undef private
#undef protected
#include "ans_dialog_callback_proxy.h"
#include "ans_permission_def.h"
#include "ans_result_data_synchronizer.h"
#include "ansmanagerstub_fuzzer.h"
#include "notification_record.h"
#include "notification_request.h"
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
        std::string stringData = fuzzData->ConsumeRandomLengthString();
        sptr<Notification::NotificationRequest> notification = new Notification::NotificationRequest();
        notification->SetOwnerUid(fuzzData->ConsumeIntegral<int32_t>());
        notification->SetCreatorUid(fuzzData->ConsumeIntegral<int32_t>());
        notification->SetSlotType(Notification::NotificationConstant::SlotType::LIVE_VIEW);
        auto content = std::make_shared<Notification::NotificationLiveViewContent>();
        notification->SetContent(std::make_shared<Notification::NotificationContent>(content));
        service->Publish(stringData, notification);
        service->PublishWithMaxCapacity(stringData, notification);
        int notificationId = fuzzData->ConsumeIntegral<int32_t>();
        int32_t userId = fuzzData->ConsumeIntegral<int32_t>();
        sptr<Notification::AnsResultDataSynchronizerImpl> synchronizer =
            new (std::nothrow) Notification::AnsResultDataSynchronizerImpl();
        if (service->Cancel(notificationId, stringData, fuzzData->ConsumeRandomLengthString(),
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        if (service->CancelAll(fuzzData->ConsumeRandomLengthString(),
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        if (service->CancelAsBundle(notificationId, stringData, userId,
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        uint8_t type = fuzzData->ConsumeIntegral<uint8_t>() % SLOT_TYPE_NUM;
        Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType(type);
        service->AddSlotByType(slotType);
        std::vector<sptr<Notification::NotificationSlot>> slots;
        service->AddSlots(slots);
        service->RemoveSlotByType(slotType);
        service->RemoveAllSlots();
        sptr<Notification::NotificationSlot> slot = new Notification::NotificationSlot();
        service->GetSlotByType(slotType, slot);
        service->GetSlots(slots);
        sptr<Notification::NotificationBundleOption> bundleOption = new Notification::NotificationBundleOption();
        sptr<Notification::NotificationButtonOption> buttonOption = new Notification::NotificationButtonOption();
        bundleOption->SetBundleName(fuzzData->ConsumeRandomLengthString());
        bundleOption->SetUid(fuzzData->ConsumeIntegral<int32_t>());
        uint64_t num = fuzzData->ConsumeIntegral<uint64_t>();
        if (service->CancelAsBundle(bundleOption, fuzzData->ConsumeIntegral<int32_t>(),
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        if (service->CancelAsBundle(bundleOption, fuzzData->ConsumeIntegral<int32_t>(), userId,
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        if (service->CancelAsBundleWithAgent(bundleOption, fuzzData->ConsumeIntegral<int32_t>(),
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->GetSlotNumAsBundle(bundleOption, num);
        if (service->GetActiveNotifications(fuzzData->ConsumeRandomLengthString(),
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->GetActiveNotificationNums(num);
        std::vector<sptr<Notification::Notification>> notificationss;
        if (service->GetAllActiveNotifications(
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        std::vector<std::string> key;
        service->GetSpecialActiveNotifications(key, notificationss);
        bool canPublish = fuzzData->ConsumeBool();
        service->CanPublishAsBundle(stringData, canPublish);
        service->PublishAsBundle(notification, stringData);
        service->PublishAsBundleWithMaxCapacity(notification, stringData);
        service->SetNotificationBadgeNum(num);
        int importance = fuzzData->ConsumeIntegral<int32_t>();
        service->GetBundleImportance(importance);
        bool granted = fuzzData->ConsumeBool();
        service->HasNotificationPolicyAccessPermission(granted);
        int32_t removeReason = fuzzData->ConsumeIntegral<int32_t>();
        service->RemoveNotification(bundleOption, notificationId, stringData, removeReason);
        service->RemoveAllNotifications(bundleOption);
        service->Delete(stringData, removeReason);
        service->DeleteByBundle(bundleOption);
        service->DeleteAll();
        service->GetSlotsByBundle(bundleOption, slots);
        service->UpdateSlots(bundleOption, slots);
        bool enabled = fuzzData->ConsumeBool();
        service->SetNotificationsEnabledForBundle(stringData, enabled);
        service->SetNotificationsEnabledForAllBundles(stringData, enabled);
        service->SetNotificationsEnabledForSpecialBundle(stringData, bundleOption, enabled);
        service->SetShowBadgeEnabledForBundle(bundleOption, enabled);
        if (service->GetShowBadgeEnabledForBundle(bundleOption,
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        if (service->GetShowBadgeEnabled(
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        sptr<Notification::NotificationSubscribeInfo> info = new Notification::NotificationSubscribeInfo();
        bool allowed = fuzzData->ConsumeBool();
        service->IsAllowedNotify(allowed);
        service->IsAllowedNotifySelf(allowed);
        service->IsAllowedNotifySelf(bundleOption, allowed);
        service->IsAllowedNotifyForBundle(bundleOption, allowed);
        service->IsSpecialBundleAllowedNotify(bundleOption, allowed);
        service->CancelGroup(stringData, fuzzData->ConsumeRandomLengthString());
        service->RemoveGroupByBundle(bundleOption, stringData);
        sptr<Notification::NotificationDoNotDisturbDate> date = new Notification::NotificationDoNotDisturbDate();
        service->SetDoNotDisturbDateByUser(userId, date);
        service->GetDoNotDisturbDateByUser(userId, date);
        bool doesSupport = fuzzData->ConsumeBool();
        service->DoesSupportDoNotDisturbMode(doesSupport);
        service->IsDistributedEnabled(enabled);
        service->EnableDistributedByBundle(bundleOption, enabled);
        service->EnableDistributedSelf(enabled);
        service->EnableDistributed(enabled);
        service->IsDistributedEnableByBundle(bundleOption, enabled);
        int32_t remindType;
        service->GetDeviceRemindType(remindType);
        sptr<Notification::NotificationRequest> request = new Notification::NotificationRequest();
        service->PublishContinuousTaskNotification(request);
        service->CancelContinuousTaskNotification(stringData, notificationId);
        bool support = fuzzData->ConsumeBool();
        service->IsSupportTemplate(stringData, support);
        service->IsSpecialUserAllowedNotify(userId, allowed);
        int32_t deviceIds = fuzzData->ConsumeIntegral<int32_t>();
        service->SetNotificationsEnabledByUser(deviceIds, enabled);
        service->DeleteAllByUser(userId);
        service->SetDoNotDisturbDate(date);
        service->GetDoNotDisturbDate(date);
        service->SetEnabledForBundleSlot(bundleOption, slotType, enabled, false);
        service->GetEnabledForBundleSlot(bundleOption, slotType, enabled);
        std::vector<std::string> dumpInfo;
        service->ShellDump(stringData, stringData, userId, userId, dumpInfo);
        service->SetSyncNotificationEnabledWithoutApp(userId, enabled);
        service->GetSyncNotificationEnabledWithoutApp(userId, enabled);
        int32_t badgeNum = fuzzData->ConsumeIntegral<int32_t>();
        service->SetBadgeNumber(badgeNum, fuzzData->ConsumeRandomLengthString());
        std::shared_ptr<Notification::NotificationUnifiedGroupInfo> groupInfo;
        bool enable = fuzzData->ConsumeBool();
        std::string bundleName = fuzzData->ConsumeRandomLengthString();
        std::string phoneNumber = fuzzData->ConsumeRandomLengthString();
        std::string groupName = fuzzData->ConsumeRandomLengthString();
        std::string deviceType = fuzzData->ConsumeRandomLengthString();
        std::string localSwitch = fuzzData->ConsumeRandomLengthString();
        std::vector<std::shared_ptr<Notification::NotificationRecord>> recordList;
        bool isNative = fuzzData->ConsumeBool();
        service->CanPopEnableNotificationDialog(nullptr, enable, bundleName);
        service->RemoveEnableNotificationDialog();
        service->RemoveEnableNotificationDialog(bundleOption);
        std::vector<std::string> keys;
        std::string key1 = fuzzData->ConsumeRandomLengthString();
        keys.emplace_back(fuzzData->ConsumeRandomLengthString());
        service->RemoveNotifications(keys, fuzzData->ConsumeIntegral<int32_t>());
        service->SetBadgeNumberByBundle(bundleOption, fuzzData->ConsumeIntegral<int32_t>());
        service->SetDistributedEnabledByBundle(bundleOption, fuzzData->ConsumeRandomLengthString(),
            fuzzData->ConsumeBool());
        service->IsDistributedEnableByBundle(bundleOption, enable);
        service->SetDefaultNotificationEnabled(bundleOption, enabled);
        if (service->ExcuteCancelAll(bundleOption, fuzzData->ConsumeIntegral<int32_t>(),
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->ExcuteDelete(stringData, fuzzData->ConsumeIntegral<int32_t>());
        service->HandleBadgeEnabledChanged(bundleOption, enabled);
        service->RemoveSystemLiveViewNotifications(bundleName, fuzzData->ConsumeIntegral<int32_t>());
        service->RemoveSystemLiveViewNotificationsOfSa(fuzzData->ConsumeIntegral<int32_t>());
        service->TriggerLocalLiveView(bundleOption, fuzzData->ConsumeIntegral<int32_t>(), buttonOption);
        service->RemoveNotificationBySlot(bundleOption, slot, fuzzData->ConsumeIntegral<int32_t>());
        service->IsNeedSilentInDoNotDisturbMode(phoneNumber, fuzzData->ConsumeIntegral<int32_t>());
        service->CheckNeedSilent(phoneNumber, fuzzData->ConsumeIntegral<int32_t>(),
            fuzzData->ConsumeIntegral<int32_t>());
        service->ExcuteCancelGroupCancel(bundleOption, groupName, fuzzData->ConsumeIntegral<int32_t>());
        service->RemoveNotificationFromRecordList(recordList);
        service->UpdateUnifiedGroupInfo(key1, groupInfo);
        service->PublishNotificationBySa(request);
        service->IsDistributedEnabledByBundle(bundleOption, deviceType, enabled);
        service->DuplicateMsgControl(request);
        service->DeleteDuplicateMsgs(bundleOption);
        service->RemoveExpiredUniqueKey();
        service->SetSmartReminderEnabled(deviceType, enabled);
        service->IsSmartReminderEnabled(deviceType, enabled);

        uint32_t status = fuzzData->ConsumeIntegral<uint32_t>();
        uint32_t controlFlag = fuzzData->ConsumeIntegral<uint32_t>();
        service->SetTargetDeviceStatus(deviceType, status, stringData);
        service->SetTargetDeviceStatus(deviceType, status, controlFlag, stringData, userId);
        service->ClearAllNotificationGroupInfo(localSwitch);

        service->SetSlotFlagsAsBundle(bundleOption, fuzzData->ConsumeIntegral<int32_t>());
        uint32_t slotFlags;
        service->GetSlotFlagsAsBundle(bundleOption, slotFlags);
        service->GetActiveNotificationByFilter(bundleOption, notificationId, stringData, userId, keys, request);
        service->GetSlotByBundle(bundleOption, slotType, slot);
        std::vector<Notification::NotificationBundleOption> bundleOptions;
        service->GetAllNotificationEnabledBundles(bundleOptions);
        std::vector<sptr<Notification::NotificationDoNotDisturbProfile>> profiles;
        sptr<Notification::NotificationDoNotDisturbProfile> profile =
            new Notification::NotificationDoNotDisturbProfile();
        profiles.emplace_back(profile);
        service->AddDoNotDisturbProfiles(profiles);
        service->RemoveDoNotDisturbProfiles(profiles);
        std::string value = fuzzData->ConsumeRandomLengthString();

        sptr<Notification::NotificationCheckRequest> notificationCheckRequest =
            new Notification::NotificationCheckRequest();
        service->RegisterPushCallback(nullptr, notificationCheckRequest);
        service->UnregisterPushCallback();
        service->SetAdditionConfig(key1, value);
        service->PublishNotificationForIndirectProxy(notification);
        service->PublishNotificationForIndirectProxyWithMaxCapacity(notification);

        bool enabledByslot;
        service->GetEnabledForBundleSlotSelf(slotType, enabledByslot);

        service->Subscribe(nullptr, info, fuzzData->ConsumeIntegral<uint32_t>());
        service->Subscribe(nullptr, fuzzData->ConsumeIntegral<uint32_t>());
        service->Unsubscribe(nullptr, info);
        service->Unsubscribe(nullptr);
        service->SubscribeSelf(nullptr, fuzzData->ConsumeIntegral<uint32_t>());

        service->SubscribeLocalLiveView(nullptr, info, isNative);
        service->SubscribeLocalLiveView(nullptr, isNative);

        int32_t uid = fuzzData->ConsumeIntegral<int32_t>();
        sptr<Notification::IAnsDialogCallback> callback = new Notification::AnsDialogCallbackProxy(nullptr);
        service->RequestEnableNotification(stringData, callback, nullptr);
        service->RequestEnableNotification(stringData, callback);

        service->SetDistributedEnabledBySlot(slotType, deviceType, enabled);
        service->GetAllDistribuedEnabledBundles(deviceType, bundleOptions);
        std::vector<sptr<Notification::Notification>> notificationsVector;
        service->GetAllNotificationsBySlotType(notificationsVector, slotType);
        service->AllowUseReminder(bundleName, allowed);
        int32_t deviceStatus;
        service->GetTargetDeviceStatus(deviceType, deviceStatus);
        bool isPaused = fuzzData->ConsumeBool();
        service->UpdateNotificationTimerByUid(uid, isPaused);

        service->SetBadgeNumberForDhByBundle(bundleOption, badgeNum);
        service->GetNotificationRequestByHashCode(stringData, notification);
        sptr<Notification::NotificationOperationInfo> operationInfo = new Notification::NotificationOperationInfo();
        operationInfo->SetActionName(fuzzData->ConsumeRandomLengthString());
        operationInfo->SetUserInput(fuzzData->ConsumeRandomLengthString());
        operationInfo->SetHashCode(fuzzData->ConsumeRandomLengthString());
        operationInfo->SetEventId(fuzzData->ConsumeRandomLengthString());
        service->DistributeOperation(operationInfo, nullptr);
        service->SetHashCodeRule(fuzzData->ConsumeIntegral<uint32_t>());
        service->GetAllLiveViewEnabledBundles(bundleOptions);
        sptr<Notification::NotificationDisable> notificationDisable = new Notification::NotificationDisable();
        service->DisableNotificationFeature(notificationDisable);
        service->ReplyDistributeOperation(stringData, fuzzData->ConsumeIntegral<int32_t>());
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
    SystemHapTokenGet(requestPermission);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
