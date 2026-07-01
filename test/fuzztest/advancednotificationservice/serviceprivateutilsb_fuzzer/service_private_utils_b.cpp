/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "notification_live_view_content.h"
#include "notification_record.h"
#define private public
#define protected public
#include "advanced_notification_service.h"
#include "notification_trigger.h"
#include "notification_geofence.h"
#include "notification_ringtone_info.h"
#undef private
#undef protected
#include "service_private_utils_b.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <chrono>
#include <thread>
#include "ans_dialog_callback_proxy.h"
#include "ans_subscriber_stub.h"
#include "ans_permission_def.h"
#include "ans_result_data_synchronizer.h"
#include "mock_notification_bundle_option.h"
#include "mock_notification_request.h"
#include "mock_notification_slot.h"
#include "notification_button_option.h"
#include "notification_content.h"
#include "notification_do_not_disturb_date.h"
#include "notification.h"
#include "notification_request.h"
#include "notification_preferences.h"
#include "want_params.h"

namespace OHOS {
namespace Notification {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        auto service = std::make_shared<AdvancedNotificationService>();
        sptr<AnsResultDataSynchronizerImpl> synchronizer = new AnsResultDataSynchronizerImpl();
        service->InitPublishProcess();
        service->CreateDialogManager();
        {
            // Geofence (L259-L327)
        int32_t num = fuzzData->ConsumeIntegralInRange<int32_t>(1, 100);
        int64_t timeNum = fuzzData->ConsumeIntegralInRange<int64_t>(1, 10000);
        bool enabled = fuzzData->ConsumeBool();
        std::string str = fuzzData->ConsumeRandomLengthString();
        auto service = AdvancedNotificationService::GetInstance();

        // create request with geofence trigger
        sptr<NotificationRequest> request = new NotificationRequest();
        request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
        request->SetNotificationId(num);

        // create NotificationTrigger with geofence
        auto trigger = std::make_shared<NotificationTrigger>();
        trigger->SetTriggerType(NotificationConstant::TriggerType::TRIGGER_TYPE_FENCE);
        trigger->SetConfigPath(NotificationConstant::ConfigPath::CONFIG_PATH_DEVICE_CONFIG);
        trigger->SetDisplayTime(num);

        // create NotificationGeofence
        auto geofence = std::make_shared<NotificationGeofence>();
        geofence->SetLatitude(static_cast<double>(fuzzData->ConsumeIntegralInRange<int32_t>(-90, 90)));
        geofence->SetLongitude(static_cast<double>(fuzzData->ConsumeIntegralInRange<int32_t>(-180, 180)));
        geofence->SetRadius(static_cast<double>(fuzzData->ConsumeIntegralInRange<int32_t>(0, 1000)));
        trigger->SetGeofence(geofence);

        request->SetNotificationTrigger(trigger);

        // create bundle and record
        sptr<NotificationBundleOption> bundle = new NotificationBundleOption(str, num);
        auto record = service->MakeNotificationRecord(request, bundle);
        // test SetGeofenceTriggerTimer
        if (record != nullptr && record->request != nullptr) {
            service->SetGeofenceTriggerTimer(record);
            // test StartGeofenceTriggerTimer with various expired time points
            int64_t expiredTimePoint = timeNum;
            int32_t reason = NotificationConstant::TRIGGER_GEOFENCE_REASON_DELETE;
            service->StartGeofenceTriggerTimer(record, expiredTimePoint, reason);

            // test StartGeofenceTriggerTimer with different reasons
            service->StartGeofenceTriggerTimer(record, expiredTimePoint + 1000,
                NotificationConstant::TRIGGER_GEOFENCE_REASON_DELETE);

            // test StartGeofenceTriggerTimer with larger expired time
            service->StartGeofenceTriggerTimer(record, timeNum + 5000, reason);

            // test with record having notification object
            if (record->notification != nullptr) {
                service->SetGeofenceTriggerTimer(record);
            }
        }

        // test with nullptr trigger
        sptr<NotificationRequest> nullTriggerRequest = new NotificationRequest();
        nullTriggerRequest->SetNotificationTrigger(nullptr);
        auto nullTriggerRecord = service->MakeNotificationRecord(nullTriggerRequest, bundle);
        if (nullTriggerRecord != nullptr) {
            service->SetGeofenceTriggerTimer(nullTriggerRecord);
        }

        // test with different trigger types
        auto timerTrigger = std::make_shared<NotificationTrigger>();
        timerTrigger->SetTriggerType(NotificationConstant::TriggerType::TRIGGER_TYPE_FENCE);
        timerTrigger->SetDisplayTime(num);
        sptr<NotificationRequest> timerRequest = new NotificationRequest();
        timerRequest->SetNotificationTrigger(timerTrigger);
        auto timerRecord = service->MakeNotificationRecord(timerRequest, bundle);
        if (timerRecord != nullptr) {
            service->SetGeofenceTriggerTimer(timerRecord);
        }

        }
        {
            // Disable (L333-L420)
        int32_t num = fuzzData->ConsumeIntegralInRange<int32_t>(1, 100);
        bool enabled = fuzzData->ConsumeBool();
        std::string str = fuzzData->ConsumeRandomLengthString();
        auto service = AdvancedNotificationService::GetInstance();

        // test IsDisableNotification with bundleName only
        bool isDisabled = service->IsDisableNotification(str);
        isDisabled = service->IsDisableNotification("com.test.bundle");

        // test IsDisableNotification with bundleOption
        sptr<NotificationBundleOption> bundle = new NotificationBundleOption(str, num);
        bool isDisabledByBundle = service->IsDisableNotification(bundle);

        // test IsDisableNotification with nullptr bundleOption
        sptr<NotificationBundleOption> nullBundle = nullptr;
        bool isDisabledByNull = service->IsDisableNotification(nullBundle);

        // test IsDisableNotification with bundleName and userId
        int32_t userId = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        bool isDisabledByUser = service->IsDisableNotification(str, userId);
        isDisabledByUser = service->IsDisableNotification(str, 0);
        isDisabledByUser = service->IsDisableNotification(str, -1);

        // test IsExistRestrictedModeTrustList
        bool isInTrustList = service->IsExistRestrictedModeTrustList(str, userId);
        isInTrustList = service->IsExistRestrictedModeTrustList("com.trust.bundle", userId);
        isInTrustList = service->IsExistRestrictedModeTrustList(str, 0);
        isInTrustList = service->IsExistRestrictedModeTrustList(str, -1);

        // test ClearSlotTypeData with various source types
        sptr<NotificationRequest> clearRequest = new NotificationRequest();
        clearRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
        clearRequest->SetOwnerUid(num);
        clearRequest->SetCreatorUid(num);
        clearRequest->SetNotificationId(num);
        auto liveContent = std::make_shared<NotificationLiveViewContent>();
        clearRequest->SetContent(std::make_shared<NotificationContent>(liveContent));

        // test ClearSlotTypeData with CLEAR_SLOT_FROM_AVSEESAION (1)
        service->ClearSlotTypeData(clearRequest, num, 1);

        // test ClearSlotTypeData with CLEAR_SLOT_FROM_RSS (2)
        service->ClearSlotTypeData(clearRequest, num, 2);

        // test ClearSlotTypeData with invalid source type
        service->ClearSlotTypeData(clearRequest, num, 0);
        service->ClearSlotTypeData(clearRequest, num, 3);
        service->ClearSlotTypeData(clearRequest, num, -1);

        // test ClearSlotTypeData with nullptr request
        service->ClearSlotTypeData(nullptr, num, 1);

        // test PublishExtensionServiceStateChange with various event codes
        sptr<NotificationBundleOption> extBundle = new NotificationBundleOption(str, num);
        std::vector<sptr<NotificationBundleOption>> enabledBundles;
        enabledBundles.push_back(bundle);

        // test with USER_GRANTED_STATE
        service->PublishExtensionServiceStateChange(NotificationConstant::USER_GRANTED_STATE,
            extBundle, enabled, enabledBundles);

        // test with USER_GRANTED_BUNDLE_STATE
        service->PublishExtensionServiceStateChange(NotificationConstant::USER_GRANTED_BUNDLE_STATE,
            extBundle, enabled, enabledBundles);

        // test with EXTENSION_ABILITY_ADDED
        service->PublishExtensionServiceStateChange(NotificationConstant::EXTENSION_ABILITY_ADDED,
            extBundle, enabled, enabledBundles);

        // test with EXTENSION_ABILITY_REMOVED
        service->PublishExtensionServiceStateChange(NotificationConstant::EXTENSION_ABILITY_REMOVED,
            extBundle, enabled, enabledBundles);

        // test with invalid event code
        service->PublishExtensionServiceStateChange(
            static_cast<NotificationConstant::EventCodeType>(0), extBundle, enabled, enabledBundles);
        service->PublishExtensionServiceStateChange(
            static_cast<NotificationConstant::EventCodeType>(5), extBundle, enabled, enabledBundles);

        // test with nullptr bundleOption
        service->PublishExtensionServiceStateChange(NotificationConstant::USER_GRANTED_STATE,
            nullBundle, enabled, enabledBundles);

        // test with empty enabledBundles
        std::vector<sptr<NotificationBundleOption>> emptyBundles;
        service->PublishExtensionServiceStateChange(NotificationConstant::USER_GRANTED_BUNDLE_STATE,
            extBundle, enabled, emptyBundles);

        }
        {
            // Ringtone (L426-L495)
        int32_t num = fuzzData->ConsumeIntegralInRange<int32_t>(1, 100);
        std::string str = fuzzData->ConsumeRandomLengthString();
        std::string str2 = fuzzData->ConsumeRandomLengthString();
        std::string str3 = fuzzData->ConsumeRandomLengthString();
        auto service = AdvancedNotificationService::GetInstance();

        // test ClearOverTimeRingToneInfo
        service->ClearOverTimeRingToneInfo();

        // test ClearRingtoneByApplication with empty vector
        std::vector<NotificationRingtoneInfo> emptyRingtoneInfos;
        int32_t userId = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        service->ClearRingtoneByApplication(userId, emptyRingtoneInfos);

        // test ClearRingtoneByApplication with ringtone infos
        std::vector<NotificationRingtoneInfo> ringtoneInfos;

        // create ringtone info with RINGTONE_TYPE_LOCAL
        NotificationRingtoneInfo localRingtone;
        localRingtone.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
        localRingtone.SetRingtoneTitle(str);
        localRingtone.SetRingtoneFileName(str2);
        localRingtone.SetRingtoneUri(str3);
        ringtoneInfos.push_back(localRingtone);

        // create ringtone info with RINGTONE_TYPE_ONLINE
        NotificationRingtoneInfo onlineRingtone;
        onlineRingtone.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE);
        onlineRingtone.SetRingtoneTitle(fuzzData->ConsumeRandomLengthString());
        onlineRingtone.SetRingtoneFileName(fuzzData->ConsumeRandomLengthString());
        onlineRingtone.SetRingtoneUri(fuzzData->ConsumeRandomLengthString());
        ringtoneInfos.push_back(onlineRingtone);

        // create ringtone info with RINGTONE_TYPE_SYSTEM
        NotificationRingtoneInfo systemRingtone;
        systemRingtone.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_SYSTEM);
        systemRingtone.SetRingtoneTitle(fuzzData->ConsumeRandomLengthString());
        systemRingtone.SetRingtoneFileName(fuzzData->ConsumeRandomLengthString());
        systemRingtone.SetRingtoneUri(fuzzData->ConsumeRandomLengthString());
        ringtoneInfos.push_back(systemRingtone);

        // create ringtone info with RINGTONE_TYPE_BUTT
        NotificationRingtoneInfo buttRingtone;
        buttRingtone.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_BUTT);
        buttRingtone.SetRingtoneTitle(fuzzData->ConsumeRandomLengthString());
        buttRingtone.SetRingtoneFileName(fuzzData->ConsumeRandomLengthString());
        buttRingtone.SetRingtoneUri(fuzzData->ConsumeRandomLengthString());
        ringtoneInfos.push_back(buttRingtone);

        // test ClearRingtoneByApplication with ringtone infos
        service->ClearRingtoneByApplication(userId, ringtoneInfos);

        // test ClearRingtoneByApplication with userId = 0
        service->ClearRingtoneByApplication(0, ringtoneInfos);

        // test ClearRingtoneByApplication with userId = -1
        service->ClearRingtoneByApplication(-1, ringtoneInfos);

        // test ClearRingtoneByApplication with empty ringtoneUri
        std::vector<NotificationRingtoneInfo> emptyUriRingtoneInfos;
        NotificationRingtoneInfo emptyUriRingtone;
        emptyUriRingtone.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
        emptyUriRingtone.SetRingtoneUri("");
        emptyUriRingtoneInfos.push_back(emptyUriRingtone);
        service->ClearRingtoneByApplication(userId, emptyUriRingtoneInfos);

        // test ClearOverTimeRingToneInfo multiple times
        service->ClearOverTimeRingToneInfo();
        service->ClearOverTimeRingToneInfo();

        }
        return true;
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> requestPermission = {
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION
    };
    SystemHapTokenGet(requestPermission);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    constexpr int sleepMs = 1000;
    std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
    return 0;
}
