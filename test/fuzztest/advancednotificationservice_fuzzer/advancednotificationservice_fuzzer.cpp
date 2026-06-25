/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <string>
#define private public
#define protected public
#include "advanced_notification_service.h"
#include "notification_trigger.h"
#include "notification_geofence.h"
#include "notification_ringtone_info.h"
#undef private
#undef protected
#include "advancednotificationservice_fuzzer.h"
#include "ans_dialog_callback_proxy.h"
#include "ans_subscriber_stub.h"
#include "ans_permission_def.h"
#include "ans_result_data_synchronizer.h"
#include "mock_notification_bundle_option.h"
#include "notification_request.h"
#include "notification_preferences.h"
#include "want_params.h"

constexpr uint8_t SLOT_TYPE_NUM = 5;
constexpr int32_t TEST_NOTIFICATION_COUNT = 5;
constexpr int32_t TEST_CANCELED_NOTIFICATION_COUNT = 3;
constexpr int32_t TEST_NOTIFICATION_RECORD_COUNT = 3;

namespace OHOS {
namespace Notification {
    bool DoTestForAdvancedNotificationUtilsV1(std::shared_ptr<AdvancedNotificationService> service,
        FuzzedDataProvider *fuzzData)
    {
        service->GetNotificationSvrQueue();
        sptr<NotificationBundleOption> bundleOption = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        sptr<NotificationBundleOption> targetBundleOption = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        service->GetAppTargetBundle(bundleOption, targetBundleOption);

        std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
        std::string bundleName = ConsumePrintableString(fuzzData);
        std::vector<std::string> dumpInfo;
        int32_t creatorUserId = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        int32_t recvUserId = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        int32_t nid = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        int32_t uid = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        int32_t ownerId = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
        sptr<NotificationRequest> req = new NotificationRequest(nid);
        record->request = req;
        req->SetOwnerBundleName(bundleName);
        req->SetCreatorUserId(creatorUserId);
        req->SetReceiverUserId(recvUserId);
        req->SetSlotType(slotType);
        req->SetOwnerUid(uid);
        req->SetOwnerUserId(ownerId);
        record->notification = new Notification(req);
        service->notificationList_.push_back(record);

        auto recentNotification = std::make_shared<AdvancedNotificationService::RecentNotification>();
        recentNotification->isActive = true;
        recentNotification->notification = new Notification(req);
        service->recentInfo_->list.emplace_front(recentNotification);
#ifdef ANM_SUPPORT_DUMP
        service->ActiveNotificationDump(bundleName, creatorUserId, recvUserId, dumpInfo);
        service->RecentNotificationDump(bundleName, ownerId, recvUserId, dumpInfo);
        service->TimeToString(fuzzData->ConsumeIntegralInRange<int64_t>(0, 10000));
        service->ShellDump(fuzzData->ConsumeRandomLengthString(), fuzzData->ConsumeRandomLengthString(),
            recvUserId, recvUserId, dumpInfo);

        std::vector<std::u16string> args;
        args.push_back(Str8ToStr16("args"));
        std::string result = fuzzData->ConsumeRandomLengthString();
        service->GetDumpInfo(args, result);
#endif

        std::vector<std::string> keys;
        keys.push_back(recentNotification->notification->GetKey());
        keys.push_back(fuzzData->ConsumeRandomLengthString());
        service->OnRecoverLiveView(keys);

        service->GetLockScreenPictureFromDb(req);
        service->StartPublishDelayedNotificationTimeOut(ownerId, nid);
        service->UpdateRecordByOwner(record, false);
        service->HandleUpdateLiveViewNotificationTimer(uid, true);
        service->HandleUpdateLiveViewNotificationTimer(uid, false);
        return true;
    }

    bool DoTestForAdvancedNotificationUtilsV2(std::shared_ptr<AdvancedNotificationService> service,
        FuzzedDataProvider *fuzzData)
    {
        int64_t beginDate = fuzzData->ConsumeIntegralInRange<int64_t>(0, 10000);
        int64_t endDate = fuzzData->ConsumeIntegralInRange<int64_t>(10000, 100000);
        service->AdjustDateForDndTypeOnce(beginDate, endDate);

        int32_t userId = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        service->OnUserRemoved(userId);
        service->OnUserStopped(userId);

        // Prepare notification records for DeleteAllByUserStopped test
        for (int i = 0; i < TEST_NOTIFICATION_RECORD_COUNT; i++) {
            sptr<NotificationRequest> delRequest = new NotificationRequest(fuzzData->ConsumeIntegral<int32_t>());
            delRequest->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
            delRequest->SetReceiverUserId(userId);
            auto delContent = std::make_shared<NotificationContent>(std::make_shared<NotificationNormalContent>());
            delRequest->SetContent(delContent);
            sptr<NotificationBundleOption> delBundle = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
            std::shared_ptr<NotificationRecord> delRecord = service->MakeNotificationRecord(delRequest, delBundle);
            if (delRecord != nullptr) {
                delRecord->slot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
                service->notificationList_.push_back(delRecord);
            }
        }
        // Test with zero user id notifications
        sptr<NotificationRequest> zeroUserRequest = new NotificationRequest(fuzzData->ConsumeIntegral<int32_t>());
        zeroUserRequest->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
        zeroUserRequest->SetReceiverUserId(0);
        auto zeroUserContent = std::make_shared<NotificationContent>(std::make_shared<NotificationNormalContent>());
        zeroUserRequest->SetContent(zeroUserContent);
        sptr<NotificationBundleOption> zeroUserBundle = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        std::shared_ptr<NotificationRecord> zeroUserRecord =
            service->MakeNotificationRecord(zeroUserRequest, zeroUserBundle);
        if (zeroUserRecord != nullptr) {
            zeroUserRecord->slot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
            service->notificationList_.push_back(zeroUserRecord);
        }
        service->DeleteAllByUserStopped(userId);

        std::string oldKey = fuzzData->ConsumeRandomLengthString();
        std::string oldKey1 = fuzzData->ConsumeRandomLengthString();
        NotificationPreferences::GetInstance()->SetKvToDb(oldKey, "1", 0);
        NotificationPreferences::GetInstance()->SetKvToDb(oldKey1, "1", 0);
        service->ResetDistributedEnabled();

        std::string bundleName = ConsumePrintableString(fuzzData);
        int32_t uid = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        NotificationCloneBundleInfo cloneBundleInfo;
        cloneBundleInfo.SetBundleName(bundleName);
        cloneBundleInfo.SetUid(uid);
        cloneBundleInfo.SetIsShowBadge(true);
        cloneBundleInfo.SetEnableNotification(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
        cloneBundleInfo.SetSlotFlags(fuzzData->ConsumeIntegralInRange<int32_t>(0, 100));
        NotificationCloneBundleInfo::SlotInfo info;
        info.slotType_ = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
        info.enable_ = true;
        cloneBundleInfo.AddSlotInfo(info);
        service->UpdateCloneBundleInfo(cloneBundleInfo, userId);

        return true;
    }

    bool DoTestForAdvancedNotificationLiveView(std::shared_ptr<AdvancedNotificationService> service,
        FuzzedDataProvider *fuzzData)
    {
        sptr<AnsResultDataSynchronizerImpl> synchronizer =
            new AnsResultDataSynchronizerImpl();
        if (service->CancelPreparedNotification(0, "label", nullptr, 0,
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }

        sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
        sptr<NotificationBundleOption> bundle = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        request->SetNotificationId(fuzzData->ConsumeIntegral<int32_t>());
        auto record = service->MakeNotificationRecord(request, bundle);
        auto now = std::chrono::system_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
        service->SetFinishTimer(record);
        service->SetUpdateTimer(record);
        service->StartArchiveTimer(record);

        std::string phoneNum = fuzzData->ConsumeRandomLengthString();
        std::string policy = fuzzData->ConsumeRandomLengthString();
        service->QueryContactByProfileId(phoneNum, policy, fuzzData->ConsumeIntegral<int32_t>());

        service->PublishSubscriberExistFlagEvent(fuzzData->ConsumeBool(), fuzzData->ConsumeBool());
        service->RemoveAllNotificationsByBundleName(ConsumePrintableString(fuzzData),
            fuzzData->ConsumeIntegral<int32_t>(), fuzzData->ConsumeIntegral<int32_t>());
        service->RemoveAllNotificationsByBundleName("", 0, 0);

        request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
        auto liveContent = std::make_shared<NotificationLiveViewContent>();
        liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
        auto content = std::make_shared<NotificationContent>(liveContent);
        request->SetContent(content);
        service->UpdateNotificationTimerInfo(record);

        return true;
    }

    bool DoTestForAdvancedNotificationEnable(std::shared_ptr<AdvancedNotificationService> service,
        FuzzedDataProvider *fuzzData)
    {
        std::string name = "com.easy.abroad";
        std::string bundleName = ConsumePrintableString(fuzzData);
        int32_t uid = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);

        service->RequestEnableNotification(name, uid);
        service->RequestEnableNotification(bundleName, uid);

        sptr<NotificationDoNotDisturbDate> getDate = new NotificationDoNotDisturbDate();

        int64_t beginDate = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        int64_t endDate = fuzzData->ConsumeIntegralInRange<int32_t>(100, 1000);
        NotificationConstant::DoNotDisturbType disturbType =
            NotificationConstant::DoNotDisturbType::DAILY;
        sptr<NotificationDoNotDisturbDate> date =
            new NotificationDoNotDisturbDate(disturbType, beginDate, endDate);

        service->SetDoNotDisturbDate(-1, date);
        service->SetDoNotDisturbDate(uid, date);

        service->GetDoNotDisturbDate(uid, getDate);
        service->GetDoNotDisturbDate(-1, getDate);

        std::string deviceType = fuzzData->ConsumeRandomLengthString();
        std::string deviceId = fuzzData->ConsumeRandomLengthString();
        int32_t operateType = fuzzData->ConsumeIntegralInRange<int32_t>(0, 2);
        std::vector<std::string> bundleList;
        std::vector<std::string> labelList;
        labelList.emplace_back(fuzzData->ConsumeRandomLengthString());
        bundleList.emplace_back(fuzzData->ConsumeRandomLengthString());
        service->SetTargetDeviceBundleList(deviceType, deviceId, operateType, bundleList, labelList);
        service->SetTargetDeviceSwitch(deviceType, deviceId,
            fuzzData->ConsumeBool(), fuzzData->ConsumeBool());

        bool enable = fuzzData->ConsumeBool();
        service->SetDistributedEnabled(deviceType, enable);
        service->IsDistributedEnabled(deviceType, enable);

        int32_t abilityId = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        service->GetDistributedAbility(abilityId);

        bool isAuth = fuzzData->ConsumeBool();
        service->GetDistributedAuthStatus(deviceType, deviceId, uid, isAuth);
        service->SetDistributedAuthStatus(deviceType, deviceId, uid, isAuth);

        return true;
    }

    bool TestGeofenceTrigger(FuzzedDataProvider *fdp)
    {
        int32_t num = fdp->ConsumeIntegralInRange<int32_t>(1, 100);
        int64_t timeNum = fdp->ConsumeIntegralInRange<int64_t>(1, 10000);
        bool enabled = fdp->ConsumeBool();
        std::string str = fdp->ConsumeRandomLengthString();
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
        geofence->SetLatitude(static_cast<double>(fdp->ConsumeIntegralInRange<int32_t>(-90, 90)));
        geofence->SetLongitude(static_cast<double>(fdp->ConsumeIntegralInRange<int32_t>(-180, 180)));
        geofence->SetRadius(static_cast<double>(fdp->ConsumeIntegralInRange<int32_t>(0, 1000)));
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

        return true;
    }

    bool TestDisableNotification(FuzzedDataProvider *fdp)
    {
        int32_t num = fdp->ConsumeIntegralInRange<int32_t>(1, 100);
        bool enabled = fdp->ConsumeBool();
        std::string str = fdp->ConsumeRandomLengthString();
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
        int32_t userId = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
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

        return true;
    }

    bool TestRingtone(FuzzedDataProvider *fdp)
    {
        int32_t num = fdp->ConsumeIntegralInRange<int32_t>(1, 100);
        std::string str = fdp->ConsumeRandomLengthString();
        std::string str2 = fdp->ConsumeRandomLengthString();
        std::string str3 = fdp->ConsumeRandomLengthString();
        auto service = AdvancedNotificationService::GetInstance();

        // test ClearOverTimeRingToneInfo
        service->ClearOverTimeRingToneInfo();

        // test ClearRingtoneByApplication with empty vector
        std::vector<NotificationRingtoneInfo> emptyRingtoneInfos;
        int32_t userId = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
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
        onlineRingtone.SetRingtoneTitle(fdp->ConsumeRandomLengthString());
        onlineRingtone.SetRingtoneFileName(fdp->ConsumeRandomLengthString());
        onlineRingtone.SetRingtoneUri(fdp->ConsumeRandomLengthString());
        ringtoneInfos.push_back(onlineRingtone);

        // create ringtone info with RINGTONE_TYPE_SYSTEM
        NotificationRingtoneInfo systemRingtone;
        systemRingtone.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_SYSTEM);
        systemRingtone.SetRingtoneTitle(fdp->ConsumeRandomLengthString());
        systemRingtone.SetRingtoneFileName(fdp->ConsumeRandomLengthString());
        systemRingtone.SetRingtoneUri(fdp->ConsumeRandomLengthString());
        ringtoneInfos.push_back(systemRingtone);

        // create ringtone info with RINGTONE_TYPE_BUTT
        NotificationRingtoneInfo buttRingtone;
        buttRingtone.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_BUTT);
        buttRingtone.SetRingtoneTitle(fdp->ConsumeRandomLengthString());
        buttRingtone.SetRingtoneFileName(fdp->ConsumeRandomLengthString());
        buttRingtone.SetRingtoneUri(fdp->ConsumeRandomLengthString());
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

        return true;
    }

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        auto service = std::make_shared<AdvancedNotificationService>();
        sptr<AnsResultDataSynchronizerImpl> synchronizer =
            new AnsResultDataSynchronizerImpl();
        service->InitPublishProcess();
        service->CreateDialogManager();
        DoTestForAdvancedNotificationUtilsV1(service, fuzzData);
        DoTestForAdvancedNotificationUtilsV2(service, fuzzData);
        DoTestForAdvancedNotificationLiveView(service, fuzzData);
        DoTestForAdvancedNotificationEnable(service, fuzzData);
        std::string stringData = fuzzData->ConsumeRandomLengthString();
        sptr<NotificationRequest> notification = new NotificationRequest();
        notification->SetOwnerUid(fuzzData->ConsumeIntegral<int32_t>());
        notification->SetCreatorUid(fuzzData->ConsumeIntegral<int32_t>());
        notification->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
        auto content = std::make_shared<NotificationLiveViewContent>();
        notification->SetContent(std::make_shared<NotificationContent>(content));
        service->Publish(stringData, notification);
        int notificationId = fuzzData->ConsumeIntegral<int32_t>();
        int32_t userId = fuzzData->ConsumeIntegral<int32_t>();
        service->Cancel(notificationId, stringData, fuzzData->ConsumeRandomLengthString());
        if (service->Cancel(notificationId, stringData, fuzzData->ConsumeRandomLengthString(),
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->CancelAll(fuzzData->ConsumeRandomLengthString());
        if (service->CancelAll(fuzzData->ConsumeRandomLengthString(),
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->CancelAsBundle(notificationId, stringData, userId);
        if (service->CancelAsBundle(notificationId, stringData, userId,
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        uint8_t type = fuzzData->ConsumeIntegral<uint8_t>() % SLOT_TYPE_NUM;
        NotificationConstant::SlotType slotType = NotificationConstant::SlotType(type);
        service->AddSlotByType(slotType);
        std::vector<sptr<NotificationSlot>> slots;
        service->AddSlots(slots);
        service->RemoveSlotByType(slotType);
        service->RemoveAllSlots();
        sptr<NotificationSlot> slot = new NotificationSlot();
        service->GetSlotByType(slotType, slot);
        service->GetSlots(slots);
        sptr<NotificationBundleOption> bundleOption = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        sptr<NotificationButtonOption> buttonOption = new NotificationButtonOption();
        uint64_t num = fuzzData->ConsumeIntegral<uint64_t>();
        service->CancelAsBundle(bundleOption, fuzzData->ConsumeIntegral<int32_t>());
        if (service->CancelAsBundle(bundleOption, fuzzData->ConsumeIntegral<int32_t>(),
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->CancelAsBundleWithAgent(bundleOption, fuzzData->ConsumeIntegral<int32_t>());
        if (service->CancelAsBundleWithAgent(bundleOption, fuzzData->ConsumeIntegral<int32_t>(),
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->GetSlotNumAsBundle(bundleOption, num);
        std::vector<sptr<NotificationRequest>> notifications;
        if (service->GetActiveNotifications(fuzzData->ConsumeRandomLengthString(),
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->GetActiveNotificationNums(num);
        std::vector<sptr<Notification>> notificationss;
        service->GetActiveNotifications(notifications, fuzzData->ConsumeRandomLengthString());
        if (service->GetAllActiveNotifications(
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        std::vector<std::string> key;
        service->GetSpecialActiveNotifications(key, notificationss);
        bool canPublish = fuzzData->ConsumeBool();
        service->CanPublishAsBundle(stringData, canPublish);
        service->PublishAsBundle(notification, stringData);
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
        service->GetShowBadgeEnabledForBundle(bundleOption, enabled);
        if (service->GetShowBadgeEnabledForBundle(bundleOption,
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->GetShowBadgeEnabled(enabled);
        if (service->GetShowBadgeEnabled(
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
        bool allowed = fuzzData->ConsumeBool();
        service->IsAllowedNotify(allowed);
        service->IsAllowedNotifySelf(bundleOption, allowed);
        service->IsAllowedNotifyForBundle(bundleOption, allowed);
        service->IsSpecialBundleAllowedNotify(bundleOption, allowed);
        service->CancelGroup(stringData, fuzzData->ConsumeRandomLengthString());
        service->RemoveGroupByBundle(bundleOption, stringData);
        sptr<NotificationDoNotDisturbDate> date = new NotificationDoNotDisturbDate();
        service->SetDoNotDisturbDate(date);
        service->GetDoNotDisturbDate(date);
        bool doesSupport = fuzzData->ConsumeBool();
        service->DoesSupportDoNotDisturbMode(doesSupport);
        service->IsDistributedEnabled(enabled);
        service->EnableDistributedByBundle(bundleOption, enabled);
        service->EnableDistributedSelf(enabled);
        service->EnableDistributed(enabled);
        service->IsDistributedEnableByBundle(bundleOption, enabled);
        int32_t remindType;
        service->GetDeviceRemindType(remindType);
        sptr<NotificationRequest> request = new NotificationRequest();
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
        service->SetSyncNotificationEnabledWithoutApp(userId, enabled);
        service->GetSyncNotificationEnabledWithoutApp(userId, enabled);
        int32_t badgeNum = fuzzData->ConsumeIntegral<int32_t>();
        service->SetBadgeNumber(badgeNum, fuzzData->ConsumeRandomLengthString());
        sptr<IAnsDialogCallback> dialogCallback = new AnsDialogCallbackProxy(nullptr);
        std::shared_ptr<NotificationUnifiedGroupInfo> groupInfo;
        bool enable = fuzzData->ConsumeBool();
        std::string bundleName = ConsumePrintableString(fuzzData);
        std::string phoneNumber = fuzzData->ConsumeRandomLengthString();
        std::string groupName = fuzzData->ConsumeRandomLengthString();
        std::string deviceType = fuzzData->ConsumeRandomLengthString();
        std::string localSwitch = fuzzData->ConsumeRandomLengthString();
        std::vector<std::shared_ptr<NotificationRecord>> recordList;
        bool isNative = fuzzData->ConsumeBool();
        service->CanPopEnableNotificationDialog(nullptr, enable, bundleName);
        std::vector<std::string> keys;
        std::string key1 = fuzzData->ConsumeRandomLengthString();
        keys.emplace_back(fuzzData->ConsumeRandomLengthString());
        service->RemoveNotifications(keys, fuzzData->ConsumeIntegral<int32_t>());
        service->SetBadgeNumberByBundle(bundleOption, fuzzData->ConsumeIntegral<int32_t>());
        service->SetDistributedEnabledByBundle(bundleOption, fuzzData->ConsumeRandomLengthString(),
            fuzzData->ConsumeBool(), fuzzData->ConsumeBool());
        service->IsDistributedEnableByBundle(bundleOption, enable);
        service->SetDefaultNotificationEnabled(bundleOption, enabled);
        service->ExcuteCancelAll(bundleOption, fuzzData->ConsumeIntegral<int32_t>());
        if (service->ExcuteCancelAll(bundleOption, fuzzData->ConsumeIntegral<int32_t>(),
            iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->ExcuteDelete(stringData, fuzzData->ConsumeIntegral<int32_t>());
        service->HandleBadgeEnabledChanged(bundleOption, enabled);
        service->RemoveSystemLiveViewNotifications(bundleName,
            fuzzData->ConsumeIntegral<int32_t>(), fuzzData->ConsumeIntegral<int32_t>());
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
        bool notifictaion = fuzzData->ConsumeBool();
        int32_t enabledType = fuzzData->ConsumeIntegral<int32_t>();
        service->IsDistributedEnabledByBundle(bundleOption, deviceType, notifictaion, enabledType);
        service->DuplicateMsgControl(request);
        service->DeleteDuplicateMsgs(bundleOption);
        service->RemoveExpiredUniqueKey();
        service->SetSmartReminderEnabled(deviceType, enabled);
        service->IsSmartReminderEnabled(deviceType, enabled);
        service->SetTargetDeviceStatus(deviceType, fuzzData->ConsumeIntegral<int32_t>(), "");
        service->ClearAllNotificationGroupInfo(localSwitch);
        service->IsDistributedEnabledBySlot(slotType, deviceType, enabled);

        TestGeofenceTrigger(fuzzData);
        TestDisableNotification(fuzzData);
        TestRingtone(fuzzData);
        DoTestForAdvancedNotificationUtils(service, fuzzData);
        DoTestForAdvancedNotificationService(service, fuzzData);
        return true;
    }

    bool DoTestForAdvancedNotificationUtils(std::shared_ptr<AdvancedNotificationService> service,
        FuzzedDataProvider *fuzzData)
    {
        std::string randomString = fuzzData->ConsumeRandomLengthString();
        int32_t randomInt32 = fuzzData->ConsumeIntegral<int32_t>();
        sptr<NotificationBundleOption> bundleOption = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        sptr<NotificationBundleOption> targetBundleOption = nullptr;
        sptr<NotificationRequest> request = new NotificationRequest();
        request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
        auto content = std::make_shared<NotificationLiveViewContent>();
        request->SetContent(std::make_shared<NotificationContent>(content));
        request->SetOwnerUid(randomInt32);
        request->SetCreatorUid(randomInt32);
        auto flag = std::make_shared<NotificationFlags>();
        request->SetFlags(flag);
        service->GetAppTargetBundle(bundleOption, targetBundleOption);
        std::vector<std::string> infos;
        infos.emplace_back(randomString);
        service->SetAgentNotification(request, randomString);
        service->OnBundleRemoved(bundleOption);
        service->OnBundleDataAdd(bundleOption);
        service->OnBundleDataUpdate(bundleOption);
        service->GetBundlesOfActiveUser();
        service->InitNotificationEnableList();
        std::shared_ptr<NotificationRecord> record =
            service->MakeNotificationRecord(request, bundleOption);
        record->slot = new NotificationSlot(NotificationConstant::SlotType::LIVE_VIEW);
        service->PrePublishNotificationBySa(request, randomInt32, randomString);
        service->SetRequestBundleInfo(request, randomInt32, randomString);
        service->OnResourceRemove(randomInt32);
        service->CheckApiCompatibility(bundleOption);
        service->OnBundleDataCleared(bundleOption);
#ifdef ANS_FEATURE_ORIGINAL_DISTRIBUTED
        service->CheckPublishWithoutApp(randomInt32, request);
        service->GetLocalNotificationKeys(bundleOption);
        service->OnDistributedPublish(randomString, randomString, request);
        service->OnDistributedUpdate(randomString, randomString, request);
        service->OnDistributedDelete(randomString, randomString, randomString, randomInt32);
#endif

        // test PrePublishRequest
        sptr<NotificationRequest> prePubRequest = new NotificationRequest();
        prePubRequest->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
        prePubRequest->SetCreatorUid(fuzzData->ConsumeIntegralInRange<int32_t>(1, 100));
        prePubRequest->SetReceiverUserId(fuzzData->ConsumeIntegralInRange<int32_t>(0, 100));
        prePubRequest->SetCreatorUserId(fuzzData->ConsumeIntegralInRange<int32_t>(0, 100));
        prePubRequest->SetDeliveryTime(fuzzData->ConsumeIntegralInRange<int64_t>(0, 100000));
        auto prePubContent = std::make_shared<NotificationContent>(std::make_shared<NotificationNormalContent>());
        prePubRequest->SetContent(prePubContent);
        service->PrePublishRequest(prePubRequest);

        // test PrePublishRequest with negative creator uid
        sptr<NotificationRequest> negUidRequest = new NotificationRequest();
        negUidRequest->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
        negUidRequest->SetCreatorUid(-1);
        negUidRequest->SetDeliveryTime(-1);
        auto negUidContent = std::make_shared<NotificationContent>(std::make_shared<NotificationNormalContent>());
        negUidRequest->SetContent(negUidContent);
        service->PrePublishRequest(negUidRequest);

        // test SendNotificationsOnCanceled
        std::vector<sptr<Notification>> canceledNotifications;
        for (int i = 0; i < TEST_CANCELED_NOTIFICATION_COUNT; i++) {
            sptr<NotificationRequest> cancelReq = new NotificationRequest(fuzzData->ConsumeIntegral<int32_t>());
            cancelReq->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
            auto cancelReqContent =
                std::make_shared<NotificationContent>(std::make_shared<NotificationNormalContent>());
            cancelReq->SetContent(cancelReqContent);
            sptr<Notification> cancelNotification = new Notification(cancelReq);
            canceledNotifications.push_back(cancelNotification);
        }
        sptr<NotificationSortingMap> sortingMap = new NotificationSortingMap();
        int32_t deleteReason = fuzzData->ConsumeIntegralInRange<int32_t>(0, 10);
        service->SendNotificationsOnCanceled(canceledNotifications, sortingMap, deleteReason);

        // test SendNotificationsOnCanceled with empty notifications
        std::vector<sptr<Notification>> emptyCanceledNotifications;
        service->SendNotificationsOnCanceled(emptyCanceledNotifications, nullptr, deleteReason);

        // test UpdateNotificationSwitchState
        AppExecFwk::BundleInfo bundleInfo;
        bundleInfo.applicationInfo.bundleName = randomString;
        bundleInfo.uid = randomInt32;
        bundleInfo.applicationInfo.allowEnableNotification = fuzzData->ConsumeBool();
        service->UpdateNotificationSwitchState(bundleOption, bundleInfo);

        // test InitNotificationStatistics
        service->InitNotificationStatistics();

        // test RecoverAncoApplicationUserId
        int32_t ancoUserId = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        service->RecoverAncoApplicationUserId(ancoUserId);

        // test ResetDistributedEnabled
        service->ResetDistributedEnabled();

#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
        // test GenerateCloneValidBundleOption with valid bundleOption
        sptr<NotificationBundleOption> cloneBundleOption = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        cloneBundleOption->SetAppIndex(fuzzData->ConsumeIntegralInRange<int32_t>(0, 5));
        cloneBundleOption->SetInstanceKey(fuzzData->ConsumeRandomLengthString());
        sptr<NotificationBundleOption> validCloneBundle = service->GenerateCloneValidBundleOption(cloneBundleOption);

        // test GenerateCloneValidBundleOption with nullptr
        sptr<NotificationBundleOption> nullBundleOption = nullptr;
        sptr<NotificationBundleOption> nullResult = service->GenerateCloneValidBundleOption(nullBundleOption);

        // test GenerateCloneValidBundleOption with empty bundle name
        sptr<NotificationBundleOption> emptyNameBundle = new NotificationBundleOption("", randomInt32);
        sptr<NotificationBundleOption> emptyNameResult = service->GenerateCloneValidBundleOption(emptyNameBundle);
#endif

        // test FillRequestByKeys with various scenarios
        sptr<NotificationRequest> oldRequest = new NotificationRequest();
        oldRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
        auto liveContent = std::make_shared<NotificationLiveViewContent>();
        auto extraInfo = std::make_shared<AAFwk::WantParams>();
        liveContent->SetExtraInfo(extraInfo);
        auto liveViewContent = std::make_shared<NotificationContent>(liveContent);
        oldRequest->SetContent(liveViewContent);
        std::vector<std::string> keys = {"key1", "key2", "invalid_key"};
        sptr<NotificationRequest> newRequest;
        service->FillRequestByKeys(oldRequest, keys, newRequest);

        // test FillRequestByKeys with empty keys
        std::vector<std::string> emptyKeys;
        sptr<NotificationRequest> newRequest2;
        service->FillRequestByKeys(oldRequest, emptyKeys, newRequest2);

        // test FillRequestByKeys with non-existent keys
        std::vector<std::string> nonExistKeys = {"non_exist_key1", "non_exist_key2"};
        sptr<NotificationRequest> newRequest3;
        service->FillRequestByKeys(oldRequest, nonExistKeys, newRequest3);

        // test onBundleRemovedByUserId
        int32_t userId = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        service->onBundleRemovedByUserId(bundleOption, userId);

        // test IsAllowedGetNotificationByFilter with matching bundleOption
        sptr<NotificationRequest> filterRequest = new NotificationRequest();
        filterRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
        auto filterContent = std::make_shared<NotificationLiveViewContent>();
        filterRequest->SetContent(std::make_shared<NotificationContent>(filterContent));
        filterRequest->SetOwnerUid(randomInt32);
        filterRequest->SetCreatorUid(randomInt32);
        std::shared_ptr<NotificationRecord> filterRecord = service->MakeNotificationRecord(filterRequest, bundleOption);
        if (filterRecord != nullptr && filterRecord->bundleOption != nullptr) {
            sptr<NotificationBundleOption> matchingBundleOption = new NotificationBundleOption(
                filterRecord->bundleOption->GetBundleName(), filterRecord->bundleOption->GetUid());
            service->IsAllowedGetNotificationByFilter(filterRecord, matchingBundleOption);
            // test with non-matching bundleOption
            sptr<NotificationBundleOption> nonMatchingBundleOption = new NotificationBundleOption(
                "non.matching.bundle", randomInt32 + 1000);
            service->IsAllowedGetNotificationByFilter(filterRecord, nonMatchingBundleOption);
        }

        // test ExecBatchCancel with empty notifications
        std::vector<sptr<Notification>> emptyNotifications;
        int32_t reason = fuzzData->ConsumeIntegral<int32_t>();
        service->ExecBatchCancel(emptyNotifications, reason);

        // test ExecBatchCancel with notifications
        std::vector<sptr<Notification>> notifications;
        for (int i = 0; i < TEST_NOTIFICATION_COUNT; i++) {
            sptr<NotificationRequest> req = new NotificationRequest(fuzzData->ConsumeIntegral<int32_t>());
            req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
            auto reqContent = std::make_shared<NotificationContent>(std::make_shared<NotificationNormalContent>());
            req->SetContent(reqContent);
            sptr<Notification> notification = new Notification(req);
            notifications.push_back(notification);
        }
        service->ExecBatchCancel(notifications, reason);

        // test RemoveDoNotDisturbProfileTrustList (single parameter version)
        service->RemoveDoNotDisturbProfileTrustList(bundleOption);

        // test RemoveDoNotDisturbProfileTrustList (two parameter version)
        service->RemoveDoNotDisturbProfileTrustList(bundleOption, userId);

        // test OnBundleDataUpdate
        service->OnBundleDataUpdate(bundleOption);

        // test GetTargetRecordList with empty result
        std::vector<std::shared_ptr<NotificationRecord>> targetRecordList;
        int32_t targetUid = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        int32_t targetPid = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        NotificationConstant::SlotType targetSlotType = NotificationConstant::SlotType::LIVE_VIEW;
        NotificationContent::Type contentType = NotificationContent::Type::LIVE_VIEW;
        service->GetTargetRecordList(targetUid, targetPid, targetSlotType, contentType, targetRecordList);

        // test GetTargetRecordList with matching records
        sptr<NotificationRequest> targetRequest = new NotificationRequest(fuzzData->ConsumeIntegral<int32_t>());
        targetRequest->SetSlotType(targetSlotType);
        targetRequest->SetCreatorUid(targetUid);
        targetRequest->SetCreatorPid(targetPid);
        auto targetLiveContent = std::make_shared<NotificationLiveViewContent>();
        targetRequest->SetContent(std::make_shared<NotificationContent>(targetLiveContent));
        sptr<NotificationBundleOption> targetBundle = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        std::shared_ptr<NotificationRecord> targetRecord = service->MakeNotificationRecord(targetRequest, targetBundle);
        if (targetRecord != nullptr) {
            targetRecord->slot = new NotificationSlot(targetSlotType);
            service->notificationList_.push_back(targetRecord);
            std::vector<std::shared_ptr<NotificationRecord>> matchRecordList;
            service->GetTargetRecordList(targetUid, targetPid, targetSlotType, contentType, matchRecordList);
        }

        // test GetCommonTargetRecordList with empty result
        std::vector<std::shared_ptr<NotificationRecord>> commonRecordList;
        int32_t commonUid = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        NotificationConstant::SlotType commonSlotType = NotificationConstant::SlotType::LIVE_VIEW;
        NotificationContent::Type commonContentType = NotificationContent::Type::LIVE_VIEW;
        service->GetCommonTargetRecordList(commonUid, commonSlotType, commonContentType, commonRecordList);

        // test GetCommonTargetRecordList with common live view records
        sptr<NotificationRequest> commonRequest = new NotificationRequest(fuzzData->ConsumeIntegral<int32_t>());
        commonRequest->SetSlotType(commonSlotType);
        commonRequest->SetCreatorUid(commonUid);
        auto commonLiveViewContent = std::make_shared<NotificationLiveViewContent>();
        commonLiveViewContent->SetIsOnlyLocalUpdate(true);
        commonRequest->SetContent(std::make_shared<NotificationContent>(commonLiveViewContent));
        sptr<NotificationBundleOption> commonBundle = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        std::shared_ptr<NotificationRecord> commonRecord = service->MakeNotificationRecord(commonRequest, commonBundle);
        if (commonRecord != nullptr) {
            commonRecord->slot = new NotificationSlot(commonSlotType);
            service->notificationList_.push_back(commonRecord);
            std::vector<std::shared_ptr<NotificationRecord>> matchCommonRecordList;
            service->GetCommonTargetRecordList(commonUid, commonSlotType, commonContentType, matchCommonRecordList);
        }

        // test PrepareContinuousTaskNotificationRequest
        sptr<NotificationRequest> continuousRequest = new NotificationRequest();
        continuousRequest->SetSlotType(NotificationConstant::SlotType::SERVICE_REMINDER);
        continuousRequest->SetDeliveryTime(fuzzData->ConsumeIntegralInRange<int64_t>(0, 100000));
        int32_t continuousUid = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        service->PrepareContinuousTaskNotificationRequest(continuousRequest, continuousUid);

        // test PrepareContinuousTaskNotificationRequest with negative delivery time
        sptr<NotificationRequest> negativeTimeRequest = new NotificationRequest();
        negativeTimeRequest->SetSlotType(NotificationConstant::SlotType::SERVICE_REMINDER);
        negativeTimeRequest->SetDeliveryTime(-1);
        service->PrepareContinuousTaskNotificationRequest(negativeTimeRequest, continuousUid);

        // test UpdateAncoBundleUserId
        sptr<NotificationBundleOption> ancoBundleOption = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        service->UpdateAncoBundleUserId(ancoBundleOption);

        // test UpdateCloneBundleInfoForRingtone
        NotificationRingtoneInfo ringtoneInfo;
        NotificationRingtoneInfo buttRingtoneInfo;
        NotificationCloneBundleInfo cloneBundleInfoForRingtone;
        cloneBundleInfoForRingtone.SetBundleName(randomString);
        cloneBundleInfoForRingtone.SetUid(randomInt32);
        int32_t ringtoneUserId = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        service->UpdateCloneBundleInfoForRingtone(ringtoneInfo, ringtoneUserId,
            bundleOption, cloneBundleInfoForRingtone);

        // test UpdateCloneBundleInfoForRingtone with RINGTONE_TYPE_BUTT
        service->UpdateCloneBundleInfoForRingtone(buttRingtoneInfo, ringtoneUserId,
            bundleOption, cloneBundleInfoForRingtone);

#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
        // test UpdateCloneBundleInfoForExtensionSubscription
        NotificationCloneBundleInfo extensionCloneBundleInfo;
        extensionCloneBundleInfo.SetBundleName(randomString);
        extensionCloneBundleInfo.SetUid(randomInt32);
        extensionCloneBundleInfo.SetEnabledExtensionSubscription(
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
        sptr<NotificationBundleOption> extensionBundle = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        service->UpdateCloneBundleInfoForExtensionSubscription(ringtoneUserId,
            extensionCloneBundleInfo, extensionBundle);

        // test UpdateCloneBundleInfoForExtensionSubscription with SYSTEM_DEFAULT_OFF
        extensionCloneBundleInfo.SetEnabledExtensionSubscription(
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
        service->UpdateCloneBundleInfoForExtensionSubscription(ringtoneUserId,
            extensionCloneBundleInfo, extensionBundle);
#endif

        // test CheckRemovalWantAgent
        sptr<NotificationRequest> removalRequest = new NotificationRequest();
        service->CheckRemovalWantAgent(removalRequest);

        // test CheckRemovalWantAgent with request having RemovalWantAgent
        sptr<NotificationRequest> removalRequestWithAgent = new NotificationRequest();
        service->CheckRemovalWantAgent(removalRequestWithAgent);

        // test GetCommonLiveViewRecordList
        std::vector<std::shared_ptr<NotificationRecord>> commonLiveViewRecordList;
        int32_t testPid = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        service->GetCommonLiveViewRecordList(testPid, commonLiveViewRecordList);

        // test GetCommonLiveViewRecordList with common live view records
        sptr<NotificationRequest> commonLiveReq = new NotificationRequest(fuzzData->ConsumeIntegral<int32_t>());
        commonLiveReq->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
        commonLiveReq->SetCreatorPid(testPid);
        auto commonLiveViewContent2 = std::make_shared<NotificationLiveViewContent>();
        commonLiveViewContent2->SetCreatePid(testPid);
        commonLiveViewContent2->SetRemoveOnProcessExitState(
            NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
        commonLiveReq->SetContent(std::make_shared<NotificationContent>(commonLiveViewContent2));
        sptr<NotificationBundleOption> commonLiveBundle = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        std::shared_ptr<NotificationRecord> commonLiveRecord =
            service->MakeNotificationRecord(commonLiveReq, commonLiveBundle);
        if (commonLiveRecord != nullptr) {
            commonLiveRecord->slot = new NotificationSlot(NotificationConstant::SlotType::LIVE_VIEW);
            service->notificationList_.push_back(commonLiveRecord);
            std::vector<std::shared_ptr<NotificationRecord>> matchedCommonLiveRecords;
            service->GetCommonLiveViewRecordList(testPid, matchedCommonLiveRecords);
        }

        // test IsExistsPidInObservers
        bool existsPid = service->IsExistsPidInObservers(testPid);
        bool existsInvalidPid = service->IsExistsPidInObservers(-1);

        // test RemoveAppObserver
        service->RemoveAppObserver(testPid);
        service->RemoveAppObserver(-1);

        // test RemoveCommonLiveViewNotification
        service->RemoveCommonLiveViewNotification(testPid);
        service->RemoveCommonLiveViewNotification(-1);

#ifdef ANM_SUPPORT_DUMP
        // test Dump
        std::vector<std::u16string> dumpArgs;
        dumpArgs.push_back(Str8ToStr16("-h"));
        int32_t dumpFd = fuzzData->ConsumeIntegralInRange<int32_t>(0, 100);
        service->Dump(dumpFd, dumpArgs);

        // test Dump with empty args
        std::vector<std::u16string> emptyDumpArgs;
        service->Dump(dumpFd, emptyDumpArgs);

        // test Dump with multiple args
        std::vector<std::u16string> multiDumpArgs;
        multiDumpArgs.push_back(Str8ToStr16("-A"));
        multiDumpArgs.push_back(Str8ToStr16("test_bundle"));
        service->Dump(dumpFd, multiDumpArgs);

        // test GetDumpInfo with various argument sizes
        std::string dumpResult;
        service->GetDumpInfo(dumpArgs, dumpResult);
        service->GetDumpInfo(emptyDumpArgs, dumpResult);
        service->GetDumpInfo(multiDumpArgs, dumpResult);
#endif

        return true;
    }

    bool DoTestForAdvancedNotificationService(std::shared_ptr<AdvancedNotificationService> service,
        FuzzedDataProvider *fuzzData)
    {
        std::string randomString = fuzzData->ConsumeRandomLengthString();
        int32_t randomInt32 = fuzzData->ConsumeIntegral<int32_t>();
        sptr<NotificationBundleOption> bundleOption = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        sptr<NotificationBundleOption> targetBundleOption = nullptr;
        sptr<NotificationRequest> request = new NotificationRequest();
        request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
        auto content = std::make_shared<NotificationLiveViewContent>();
        request->SetContent(std::make_shared<NotificationContent>(content));
        request->SetOwnerUid(randomInt32);
        request->SetCreatorUid(randomInt32);
        auto flag = std::make_shared<NotificationFlags>();
        request->SetFlags(flag);
        std::shared_ptr<NotificationRecord> record =
            service->MakeNotificationRecord(request, bundleOption);
        record->slot = new NotificationSlot(NotificationConstant::SlotType::LIVE_VIEW);
        service->QueryDoNotDisturbProfile(randomInt32, randomString, randomString);
        service->CheckDoNotDisturbProfile(record);
        service->DoNotDisturbUpdataReminderFlags(record);
        service->UpdateSlotAuthInfo(record);
        service->Filter(record, fuzzData->ConsumeBool());
        service->ChangeNotificationByControlFlags(record, fuzzData->ConsumeBool());
        service->CheckPublishPreparedNotification(record, fuzzData->ConsumeBool());
        service->UpdateInNotificationList(record);
        service->PublishInNotificationList(record);
        service->IsNeedPushCheck(request);
        return true;
    }
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
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
