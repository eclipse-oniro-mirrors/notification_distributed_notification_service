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
#include "service_private_utils_a.h"

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

constexpr int32_t TEST_NOTIFICATION_RECORD_COUNT = 3;

namespace OHOS {
namespace Notification {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        auto service = std::make_shared<AdvancedNotificationService>();
        sptr<AnsResultDataSynchronizerImpl> synchronizer = new AnsResultDataSynchronizerImpl();
        service->InitPublishProcess();
        service->CreateDialogManager();
        {
            // V1 (L50-L101)
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
        }
        {
            // V2 (L108-L164)
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

        }
        {
            // LiveView (L171-L203)
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

        }
        {
            // Enable (L210-L253)
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
