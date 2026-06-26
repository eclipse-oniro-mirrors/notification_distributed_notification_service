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
        std::string deviceType = fuzzData->ConsumeRandomLengthString();
        std::string stringData = fuzzData->ConsumeRandomLengthString();
        std::string localSwitch = fuzzData->ConsumeRandomLengthString();
        sptr<Notification::NotificationBundleOption> bundleOption = new Notification::NotificationBundleOption();
        bundleOption->SetBundleName(fuzzData->ConsumeRandomLengthString());
        bundleOption->SetUid(fuzzData->ConsumeIntegral<int32_t>());
        uint8_t type = fuzzData->ConsumeIntegral<uint8_t>() % SLOT_TYPE_NUM;
        Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType(type);
        sptr<Notification::NotificationSlot> slot = new Notification::NotificationSlot();
        int32_t userId = fuzzData->ConsumeIntegral<int32_t>();
        std::vector<std::string> keys;
        keys.emplace_back(fuzzData->ConsumeRandomLengthString());
        sptr<Notification::NotificationRequest> request = new Notification::NotificationRequest();
        int notificationId = fuzzData->ConsumeIntegral<int32_t>();
        std::string key1 = fuzzData->ConsumeRandomLengthString();
        sptr<Notification::NotificationSubscribeInfo> info = new Notification::NotificationSubscribeInfo();
        bool isNative = fuzzData->ConsumeBool();
        std::string bundleName = fuzzData->ConsumeRandomLengthString();
        bool allowed = fuzzData->ConsumeBool();
        sptr<Notification::NotificationRequest> notification = new Notification::NotificationRequest();
        notification->SetOwnerUid(fuzzData->ConsumeIntegral<int32_t>());
        notification->SetCreatorUid(fuzzData->ConsumeIntegral<int32_t>());
        notification->SetSlotType(Notification::NotificationConstant::SlotType::LIVE_VIEW);
        auto content = std::make_shared<Notification::NotificationLiveViewContent>();
        notification->SetContent(std::make_shared<Notification::NotificationContent>(content));
        bool enabled = fuzzData->ConsumeBool();

        uint32_t status = fuzzData->ConsumeIntegral<uint32_t>();
        uint32_t controlFlag = fuzzData->ConsumeIntegral<uint32_t>();
        service->SetTargetDeviceStatus(deviceType, status, stringData);
        service->SetTargetDeviceStatus(deviceType, status, controlFlag, stringData, userId);
        service->ClearAllNotificationGroupInfo(localSwitch);
        service->SetSlotFlagsAsBundle(bundleOption, fuzzData->ConsumeIntegral<int32_t>());
        uint32_t slotFlags;
        service->GetSlotFlagsAsBundle(bundleOption, slotFlags);
        service->GetActiveNotificationByFilter(bundleOption, notificationId, stringData, userId, keys, request);
        sptr<NotificationParameters> parameters = nullptr;
        service->GetNotificationParameters(notificationId, stringData, parameters);
        service->GetSlotByBundle(bundleOption, slotType, slot);
        std::vector<Notification::NotificationBundleOption> bundleOptions;
        service->GetAllNotificationEnabledBundles(bundleOptions);
        service->GetAllNotificationEnabledBundles(bundleOptions, userId);
        std::vector<sptr<Notification::NotificationDoNotDisturbProfile>> profiles;
        sptr<Notification::NotificationDoNotDisturbProfile> profile =
            new Notification::NotificationDoNotDisturbProfile();
        profiles.emplace_back(profile);
        service->AddDoNotDisturbProfiles(profiles);
        service->AddDoNotDisturbProfiles(profiles, userId);
        service->RemoveDoNotDisturbProfiles(profiles);
        service->RemoveDoNotDisturbProfiles(profiles, userId);
        std::string value = fuzzData->ConsumeRandomLengthString();
        sptr<Notification::NotificationCheckRequest> notificationCheckRequest =
            new Notification::NotificationCheckRequest();
        service->RegisterPushCallback(nullptr, notificationCheckRequest);
        service->UnregisterPushCallback();
        service->SetAdditionConfig(key1, value);
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
        int32_t state;
        service->GetNotificationSwitch(bundleOption, state);
        service->SetDistributedEnabledBySlot(slotType, deviceType, enabled);
        std::vector<sptr<Notification::Notification>> notificationsVector;
        service->GetAllNotificationsBySlotType(notificationsVector, slotType);
        service->GetAllNotificationsBySlotType(notificationsVector, slotType, userId);
        service->AllowUseReminder(bundleName, allowed);
        service->AllowUseReminder(bundleName, userId, allowed);
        int32_t deviceStatus;
        service->GetTargetDeviceStatus(deviceType, deviceStatus);
        bool isPaused = fuzzData->ConsumeBool();
        service->UpdateNotificationTimerByUid(uid, isPaused);
        service->GetNotificationRequestByHashCode(stringData, notification);
        sptr<Notification::NotificationOperationInfo> operationInfo = new Notification::NotificationOperationInfo();
        operationInfo->SetActionName(fuzzData->ConsumeRandomLengthString());
        operationInfo->SetUserInput(fuzzData->ConsumeRandomLengthString());
        operationInfo->SetHashCode(fuzzData->ConsumeRandomLengthString());
        operationInfo->SetEventId(fuzzData->ConsumeRandomLengthString());
        service->DistributeOperation(operationInfo, nullptr);
        service->SetHashCodeRule(fuzzData->ConsumeIntegral<uint32_t>());
        service->SetHashCodeRule(fuzzData->ConsumeIntegral<uint32_t>(), userId);
        service->GetAllLiveViewEnabledBundles(bundleOptions);
        service->GetAllLiveViewEnabledBundles(bundleOptions, userId);
        sptr<Notification::NotificationDisable> notificationDisable = new Notification::NotificationDisable();
        service->DisableNotificationFeature(notificationDisable);
        service->ReplyDistributeOperation(stringData, fuzzData->ConsumeIntegral<int32_t>());
        service->UpdateNotificationTimerByUid(uid, isPaused);
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
        sptr<Notification::ISwingCallBack> swingCallBack = new Notification::SwingCallBackProxy(nullptr);
        service->RegisterSwingCallback(swingCallBack->AsObject());
#endif
        service->SelfClean();
        constexpr int sleepMs = 1000;
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
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
