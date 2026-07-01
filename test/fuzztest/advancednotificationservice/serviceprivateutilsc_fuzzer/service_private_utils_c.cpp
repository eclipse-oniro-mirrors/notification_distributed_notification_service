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
#include "service_private_utils_c.h"

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

constexpr int32_t TEST_CANCELED_NOTIFICATION_COUNT = 3;
constexpr int32_t TEST_NOTIFICATION_COUNT = 5;

namespace OHOS {
namespace Notification {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        auto service = std::make_shared<AdvancedNotificationService>();
        sptr<AnsResultDataSynchronizerImpl> synchronizer = new AnsResultDataSynchronizerImpl();
        service->InitPublishProcess();
        service->CreateDialogManager();
        {
            // Utils (L704-L1046)
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
