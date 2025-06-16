/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "advanced_notification_service.h"

#include "accesstoken_kit.h"
#include "access_token_helper.h"
#include "advanced_notification_flow_control_service.h"
#include "advanced_notification_inline.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_status.h"

#include "hitrace_meter_adapter.h"
#include "notification_analytics_util.h"
#include "os_account_manager.h"
#include "os_account_manager_helper.h"
#include "string_wrapper.h"
#include "hitrace_util.h"

namespace OHOS {
namespace Notification {

constexpr char FOUNDATION_BUNDLE_NAME[] = "ohos.global.systemres";
constexpr int32_t RESSCHED_UID = 1096;
constexpr int32_t OPERATION_TYPE_COMMON_EVENT = 4;
constexpr int32_t TYPE_CODE_DOWNLOAD = 8;

ErrCode AdvancedNotificationService::PublishWithMaxCapacity(
    const std::string& label, const sptr<NotificationRequest>& request)
{
    return Publish(label, request);
}

ErrCode AdvancedNotificationService::Publish(const std::string &label, const sptr<NotificationRequest> &request)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    TraceChainUtil traceChain = TraceChainUtil();
    OHOS::HiviewDFX::HiTraceId traceId = OHOS::HiviewDFX::HiTraceChain::GetId();
    ANS_LOGD("%{public}s", __FUNCTION__);

    const auto checkResult = CheckNotificationRequest(request);
    if (checkResult != ERR_OK) {
        return checkResult;
    }

    SetChainIdToExtraInfo(request, traceId);
    if (request->GetDistributedCollaborate()) {
        return CollaboratePublish(request);
    }

    if (!InitPublishProcess()) {
        return ERR_ANS_NO_MEMORY;
    }

    request->SetCreateTime(GetCurrentTime());
    
    bool isUpdateByOwnerAllowed = IsUpdateSystemLiveviewByOwner(request);
    AnsStatus ansStatus = publishProcess_[request->GetSlotType()]->PublishPreWork(request, isUpdateByOwnerAllowed);
    if (!ansStatus.Ok()) {
        ansStatus.AppendSceneBranch(EventSceneId::SCENE_1, EventBranchId::BRANCH_0, "publish prework failed");
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, ansStatus.BuildMessage(true));
        return ansStatus.GetErrCode();
    }

    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_1, EventBranchId::BRANCH_1);
    ErrCode result = CheckUserIdParams(request->GetReceiverUserId());
    if (result != ERR_OK) {
        message.SceneId(EventSceneId::SCENE_3).ErrorCode(result).Message("User is invalid", true);
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return result;
    }
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    request->SetIsSystemApp(AccessTokenHelper::IsSystemApp() || isSubsystem);
    if (isSubsystem) {
        return PublishNotificationBySa(request);
    }
    if (request->GetRemovalWantAgent() != nullptr && request->GetRemovalWantAgent()->GetPendingWant() != nullptr) {
        uint32_t operationType = (uint32_t)(request->GetRemovalWantAgent()->GetPendingWant()
            ->GetType(request->GetRemovalWantAgent()->GetPendingWant()->GetTarget()));
        bool isSystemApp = AccessTokenHelper::IsSystemApp();
        if (!isSubsystem && !isSystemApp && operationType != OPERATION_TYPE_COMMON_EVENT) {
            ANS_LOGI("SetRemovalWantAgent as nullptr");
            request->SetRemovalWantAgent(nullptr);
        }
    }
    do {
        result = publishProcess_[request->GetSlotType()]->PublishNotificationByApp(request);
        if (result != ERR_OK) {
            break;
        }

        sptr<NotificationBundleOption> bundleOption;
        result = PrepareNotificationInfo(request, bundleOption);
        if (result != ERR_OK) {
            message.ErrorCode(result).Message("PrepareNotificationInfo failed.");
            NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
            break;
        }

        result = CheckSoundPermission(request, bundleOption->GetBundleName());
        if (result != ERR_OK) {
            message.ErrorCode(result).Message("Check sound failed.");
            NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
            break;
        }

#ifndef IS_EMULATOR
        if (IsNeedPushCheck(request)) {
            result = PushCheck(request);
        }
#endif

        if (result != ERR_OK) {
            break;
        }
        result = PublishPreparedNotification(request, bundleOption, isUpdateByOwnerAllowed);
        if (result != ERR_OK) {
            break;
        }
    } while (0);

    NotificationAnalyticsUtil::ReportAllBundlesSlotEnabled();
    SendPublishHiSysEvent(request, result);
    return result;
}

void AdvancedNotificationService::SetChainIdToExtraInfo
    (const sptr<NotificationRequest> &request, OHOS::HiviewDFX::HiTraceId traceId)
{
    std::shared_ptr<AAFwk::WantParams> additionalData = request->GetAdditionalData();
    if (!additionalData) {
        additionalData = std::make_shared<AAFwk::WantParams>();
    }
    std::stringstream chainId;
    chainId << std::hex << traceId.GetChainId();
    std::string hexTransId;
    chainId >> std::hex >> hexTransId;
    additionalData->SetParam("_oh_ans_sys_traceid", AAFwk::String::Box(hexTransId));
    request->SetAdditionalData(additionalData);
}

ErrCode AdvancedNotificationService::PublishNotificationForIndirectProxyWithMaxCapacity(
    const sptr<NotificationRequest>& request)
{
    return PublishNotificationForIndirectProxy(request);
}

ErrCode AdvancedNotificationService::PublishNotificationForIndirectProxy(const sptr<NotificationRequest> &request)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_9, EventBranchId::BRANCH_0);
    if (!request) {
        ANS_LOGE("Request object is nullptr");
        message.ErrorCode(ERR_ANS_INVALID_PARAM).Message("Request object is nullptr");
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = PrePublishRequest(request);
    if (result != ERR_OK) {
        return result;
    }
    auto tokenCaller = IPCSkeleton::GetCallingTokenID();
    bool isAgentController = AccessTokenHelper::VerifyCallerPermission(tokenCaller,
        OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER);
    // SA not support sound
    if (!request->GetSound().empty()) {
        request->SetSound("");
    }
    std::string bundle = request->GetCreatorBundleName();
    int32_t uid = request->GetCreatorUid();
    request->SetOwnerUid(uid);
    request->SetOwnerBundleName(bundle);
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->isThirdparty = false;
    record->bundleOption = new (std::nothrow) NotificationBundleOption(bundle, uid);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundle, uid);
    if (record->bundleOption == nullptr || bundleOption == nullptr) {
        ANS_LOGE("Failed to create bundleOption");
        message.ErrorCode(ERR_ANS_NO_MEMORY).Message("Failed to create bundleOption");
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return ERR_ANS_NO_MEMORY;
    }
    record->bundleOption->SetAppInstanceKey(request->GetAppInstanceKey());
    record->notification = new (std::nothrow) Notification(request);
    if (record->notification == nullptr) {
        ANS_LOGE("Failed to create notification");
        message.ErrorCode(ERR_ANS_NO_MEMORY).Message("Failed to create notification");
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return ERR_ANS_NO_MEMORY;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        message.ErrorCode(ERR_ANS_NO_MEMORY).Message("Serial queue is invalid.");
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return ERR_ANS_INVALID_PARAM;
    }

    SetRequestBySlotType(record->request, bundleOption);

    const int32_t ipcUid = IPCSkeleton::GetCallingUid();
    ffrt::task_handle handler = notificationSvrQueue_->submit_h([&]() {
        if (IsDisableNotification(bundle)) {
            ANS_LOGE("bundle in Disable Notification list, bundleName=%{public}s", bundle.c_str());
            result = ERR_ANS_REJECTED_WITH_DISABLE_NOTIFICATION;
            message.BranchId(EventBranchId::BRANCH_1)
                .ErrorCode(result).Message("bundle in Disable Notification list, bundleName=" + bundle);
            return;
        }
        if (AssignValidNotificationSlot(record, bundleOption) != ERR_OK) {
            ANS_LOGE("Can not assign valid slot!");
        }
        result = Filter(record);
        if (result != ERR_OK) {
            ANS_LOGE("Reject by filters: %{public}d", result);
            return;
        }

        if (!request->IsDoNotDisturbByPassed()) {
            CheckDoNotDisturbProfile(record);
        }
        ChangeNotificationByControlFlags(record, isAgentController);
        if (IsSaCreateSystemLiveViewAsBundle(record, ipcUid) &&
        (std::static_pointer_cast<OHOS::Notification::NotificationLocalLiveViewContent>(
        record->request->GetContent()->GetNotificationContent())->GetType() == TYPE_CODE_DOWNLOAD)) {
            result = SaPublishSystemLiveViewAsBundle(record);
            if (result == ERR_OK) {
                SendLiveViewUploadHiSysEvent(record, UploadStatus::CREATE);
            }
            return;
        }

        bool isNotificationExists = IsNotificationExists(record->notification->GetKey());
        result = FlowControlService::GetInstance().FlowControl(record, ipcUid, isNotificationExists);
        if (result != ERR_OK) {
            message.BranchId(EventBranchId::BRANCH_5).ErrorCode(result).Message("publish failed with FlowControl");
            return;
        }
        if (AssignToNotificationList(record) != ERR_OK) {
            ANS_LOGE("Failed to assign notification list");
            message.BranchId(EventBranchId::BRANCH_5).ErrorCode(result).Message("Failed to assign notification list");
            return;
        }

        sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
        NotificationSubscriberManager::GetInstance()->NotifyConsumed(record->notification, sortingMap);
        if ((record->request->GetAutoDeletedTime() > GetCurrentTime()) && !record->request->IsCommonLiveView()) {
            StartAutoDeletedTimer(record);
        }
    });
    notificationSvrQueue_->wait(handler);
    if (result != ERR_OK) {
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return result;
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::PublishAsBundle(
    const sptr<NotificationRequest>& notification, const std::string &representativeBundle)
{
    return ERR_INVALID_OPERATION;
}

ErrCode AdvancedNotificationService::PublishAsBundleWithMaxCapacity(
    const sptr<NotificationRequest>& notification, const std::string &representativeBundle)
{
    return PublishAsBundle(notification, representativeBundle);
}

ErrCode AdvancedNotificationService::PublishContinuousTaskNotification(const sptr<NotificationRequest> &request)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem) {
        return ERR_ANS_NOT_SYSTEM_SERVICE;
    }

    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t userId = SUBSCRIBE_USER_INIT;
    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    request->SetCreatorUserId(userId);
    ANS_LOGD("%{public}s, uid=%{public}d userId=%{public}d", __FUNCTION__, uid, userId);

    if (request->GetCreatorBundleName().empty()) {
        request->SetCreatorBundleName(FOUNDATION_BUNDLE_NAME);
    }

    if (request->GetOwnerBundleName().empty()) {
        request->SetOwnerBundleName(FOUNDATION_BUNDLE_NAME);
    }

    sptr<NotificationBundleOption> bundleOption = nullptr;
    bundleOption = new (std::nothrow) NotificationBundleOption(std::string(), uid);
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption instance");
        return ERR_NO_MEMORY;
    }

    ErrCode result = PrepareContinuousTaskNotificationRequest(request, uid);
    if (result != ERR_OK) {
        return result;
    }
    request->SetUnremovable(true);
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->bundleOption = bundleOption;
    record->notification = new (std::nothrow) Notification(request);
    if (record->notification == nullptr) {
        ANS_LOGE("Failed to create Notification instance");
        return ERR_NO_MEMORY;
    }
    record->notification->SetSourceType(NotificationConstant::SourceType::TYPE_CONTINUOUS);

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        if (!IsNotificationExists(record->notification->GetKey())) {
            AddToNotificationList(record);
        } else {
            if (record->request->IsAlertOneTime()) {
                CloseAlert(record);
            }
            UpdateInNotificationList(record);
        }

        UpdateRecentNotification(record->notification, false, 0);
        sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
        NotificationSubscriberManager::GetInstance()->NotifyConsumed(record->notification, sortingMap);
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::UpdateNotificationTimerByUid(const int32_t uid, const bool isPaused)
{
    bool isSubSystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (!isSubSystem || callingUid != RESSCHED_UID) {
        ANS_LOGE("caller is not ressched, callingUid: %{public}d", callingUid);
        return ERR_ANS_NOT_SYSTEM_SERVICE;
    }

    if (!notificationSvrQueue_) {
        ANS_LOGE("Serial queue is invalidated.");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        HandleUpdateLiveViewNotificationTimer(uid, isPaused);
    }));
    notificationSvrQueue_->wait(handler);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::CheckNotificationRequest(const sptr<NotificationRequest> &request)
{
    if (!request) {
        ANSR_LOGE("ReminderRequest object is nullptr");
        return ERR_ANS_INVALID_PARAM;
    }
    auto tokenCaller = IPCSkeleton::GetCallingTokenID();
    bool isSystemApp = AccessTokenHelper::IsSystemApp();
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(tokenCaller);
    bool isAgentController = AccessTokenHelper::VerifyCallerPermission(tokenCaller,
        OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER);

    const auto wantAgent = request->GetWantAgent();
    const auto removalWantAgent = request->GetRemovalWantAgent();
    const auto isLocalWantAgent = (wantAgent != nullptr && wantAgent->IsLocal()) ||
        (removalWantAgent != nullptr && removalWantAgent->IsLocal());
    bool isSpecifiedAccess = (isSystemApp || isSubsystem) && isAgentController;
    if (isLocalWantAgent && !isSpecifiedAccess) {
        ANSR_LOGE("Local wantAgent does not support non system app");
        return ERR_ANS_NON_SYSTEM_APP;
    }
    return ERR_OK;
}

} // Notification
} // OHOS