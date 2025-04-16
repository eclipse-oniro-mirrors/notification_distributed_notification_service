/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include <functional>
#include <iomanip>
#include <sstream>

#include "accesstoken_kit.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "errors.h"

#include "ipc_skeleton.h"
#include "notification_bundle_option.h"
#include "notification_constant.h"
#include "hitrace_meter_adapter.h"
#include "notification_unified_group_Info.h"
#include "os_account_manager.h"
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
#include "distributed_screen_status_manager.h"
#endif
#include "notification_extension_wrapper.h"
#include "notification_local_live_view_subscriber_manager.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "common_event_publish_info.h"
#include "os_account_manager_helper.h"
#include "want_params_wrapper.h"
#include "ans_convert_enum.h"
#include "notification_analytics_util.h"

#include "advanced_notification_inline.cpp"
#include "notification_analytics_util.h"
#include "advanced_datashare_helper.h"
#include "advanced_datashare_helper_ext.h"
#include "datashare_result_set.h"
#include "parameter.h"
#include "system_ability_definition.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "datashare_predicates.h"
#include "notification_config_parse.h"
#include "advanced_notification_flow_control_service.h"
#include "notification_operation_info.h"
#include "notification_operation_service.h"

namespace OHOS {
namespace Notification {

constexpr char FOUNDATION_BUNDLE_NAME[] = "ohos.global.systemres";
constexpr uint32_t SECONDS_IN_ONE_DAY = 24 * 60 * 60;
const static std::string NOTIFICATION_EVENT_PUSH_AGENT = "notification.event.PUSH_AGENT";
const static std::string NOTIFICATION_EVENT_SUBSCRIBER_STATUS = "notification.event.SUBSCRIBER_STATUS";
constexpr int32_t RSS_PID = 3051;
constexpr int32_t ANS_UID = 5523;
constexpr int32_t AVSEESAION_PID = 6700;
constexpr int32_t TYPE_CODE_DOWNLOAD = 8;
constexpr const char *FOCUS_MODE_REPEAT_CALLERS_ENABLE = "1";
constexpr const char *CONTACT_DATA = "datashare:///com.ohos.contactsdataability/contacts/contact_data?Proxy=true";
constexpr const char *SUPPORT_INTEGELLIGENT_SCENE = "true";
constexpr int32_t OPERATION_TYPE_COMMON_EVENT = 4;
const static std::string BUNDLE_NAME_ZYT = "com.zhuoyi.appstore.lite";
const static std::string BUNDLE_NAME_ABROAD = "com.easy.transfer.abroad";
const static std::string INSTALL_SOURCE_EASYABROAD = "com.easy.abroad";
constexpr int32_t BADGE_NUM_LIMIT = 0;

ErrCode AdvancedNotificationService::SetDefaultNotificationEnabled(
    const sptr<NotificationBundleOption> &bundleOption, bool enabled)
{
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    sptr<EnabledNotificationCallbackData> bundleData =
        new (std::nothrow) EnabledNotificationCallbackData(bundle->GetBundleName(), bundle->GetUid(), enabled);
    if (bundleData == nullptr) {
        ANS_LOGE("Failed to create EnabledNotificationCallbackData instance");
        return ERR_NO_MEMORY;
    }
    SetSlotFlagsTrustlistsAsBundle(bundle);
    ErrCode result = ERR_OK;
    result = NotificationPreferences::GetInstance()->SetNotificationsEnabledForBundle(bundle, enabled);
    if (result == ERR_OK) {
        NotificationSubscriberManager::GetInstance()->NotifyEnabledNotificationChanged(bundleData);
        PublishSlotChangeCommonEvent(bundle);
    }

    SendEnableNotificationHiSysEvent(bundleOption, enabled, result);
    return result;
}

ErrCode AdvancedNotificationService::PublishWithMaxCapacity(
    const std::string& label, const sptr<NotificationRequest>& request)
{
    return Publish(label, request);
}

ErrCode AdvancedNotificationService::Publish(const std::string &label, const sptr<NotificationRequest> &request)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!request) {
        ANSR_LOGE("ReminderRequest object is nullptr");
        return ERR_ANS_INVALID_PARAM;
    }

    if (request->GetDistributedCollaborate()) {
        return CollaboratePublish(request);
    }

    if (!InitPublishProcess()) {
        return ERR_ANS_NO_MEMORY;
    }

    request->SetCreateTime(GetCurrentTime());
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_1, EventBranchId::BRANCH_1);
    bool isUpdateByOwnerAllowed = IsUpdateSystemLiveviewByOwner(request);
    ErrCode result = publishProcess_[request->GetSlotType()]->PublishPreWork(request, isUpdateByOwnerAllowed);
    if (result != ERR_OK) {
        message.BranchId(EventBranchId::BRANCH_0).ErrorCode(result).Message("publish prework failed", true);
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return result;
    }
    result = CheckUserIdParams(request->GetReceiverUserId());
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

    SendPublishHiSysEvent(request, result);
    return result;
}

void AdvancedNotificationService::SetCollaborateReminderFlag(const sptr<NotificationRequest> &request)
{
    ANS_LOGI("Before %{public}s", request->GetKey().c_str());
    auto flags = std::make_shared<NotificationFlags>();
    flags->SetReminderFlags(request->GetCollaboratedReminderFlag());
    request->SetFlags(flags);
    ANS_LOGI("SetFlags %{public}d %{public}d", flags->GetReminderFlags(),
        request->GetCollaboratedReminderFlag());
}

void AdvancedNotificationService::UpdateCollaborateTimerInfo(const std::shared_ptr<NotificationRecord> &record)
{
    if (!record->request->IsCommonLiveView()) {
        return;
    }

    auto content = record->request->GetContent()->GetNotificationContent();
    auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(content);
    auto status = liveViewContent->GetLiveViewStatus();
    switch (status) {
        case NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE: {
            SetFinishTimer(record);
            SetUpdateTimer(record);
            CancelArchiveTimer(record);
            return;
        }
        case NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE:
        case NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE: {
            if (record->notification->GetFinishTimer() == NotificationConstant::INVALID_TIMER_ID) {
                int64_t finishedTime = record->request->GetFinishDeadLine();
                StartFinishTimer(record, finishedTime,
                    NotificationConstant::TRIGGER_EIGHT_HOUR_REASON_DELETE);
            }
            CancelUpdateTimer(record);
            SetUpdateTimer(record);
            CancelArchiveTimer(record);
            return;
        }
        case NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END:
            CancelUpdateTimer(record);
            CancelFinishTimer(record);
            StartArchiveTimer(record);
            break;
        default:
            ANS_LOGE("Invalid status %{public}d.", status);
    }
}

ErrCode AdvancedNotificationService::CollaboratePublish(const sptr<NotificationRequest> &request)
{
    auto tokenCaller = IPCSkeleton::GetCallingTokenID();
    if (!AccessTokenHelper::VerifyNativeToken(tokenCaller) ||
        !AccessTokenHelper::VerifyCallerPermission(tokenCaller, OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Collaborate publish cheak permission failed.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t pid = IPCSkeleton::GetCallingPid();
    request->SetCreatorUid(uid);
    request->SetCreatorPid(pid);
    if (request->GetOwnerUid() == DEFAULT_UID) {
        request->SetOwnerUid(uid);
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    request->SetCreatorUserId(userId);
    request->SetCreateTime(GetCurrentTime());
    if (request->GetDeliveryTime() <= 0) {
        request->SetDeliveryTime(GetCurrentTime());
    }
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = new (std::nothrow) Notification(request);
    if (record->notification == nullptr) {
        ANS_LOGE("Failed to create notification");
        return ERR_ANS_NO_MEMORY;
    }
    record->bundleOption = new (std::nothrow) NotificationBundleOption(request->GetCreatorBundleName(), 0);
    record->notification->SetKey(request->GetLabel() + request->GetDistributedHashCode());
    SetCollaborateReminderFlag(record->request);
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h([&]() {
        if (AssignToNotificationList(record) != ERR_OK) {
            ANS_LOGE("Failed to assign notification list");
            return;
        }

        UpdateRecentNotification(record->notification, false, 0);
        sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
        NotificationSubscriberManager::GetInstance()->NotifyConsumed(record->notification, sortingMap);

        NotificationRequestDb requestDb = { .request = record->request, .bundleOption = record->bundleOption};
        UpdateCollaborateTimerInfo(record);
        SetNotificationRequestToDb(requestDb);
    });
    notificationSvrQueue_->wait(handler);
    return ERR_OK;
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

        CheckDoNotDisturbProfile(record);
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
        result = FlowControlService::GetInstance()->FlowControl(record, ipcUid, isNotificationExists);
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
    });
    notificationSvrQueue_->wait(handler);
    if (result != ERR_OK) {
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return result;
    }

    if ((record->request->GetAutoDeletedTime() > GetCurrentTime()) && !record->request->IsCommonLiveView()) {
        StartAutoDelete(record,
            record->request->GetAutoDeletedTime(), NotificationConstant::TRIGGER_AUTO_DELETE_REASON_DELETE);
    }
    return ERR_OK;
}

bool AdvancedNotificationService::InitPublishProcess()
{
    if (publishProcess_.size() > 0) {
        return true;
    }

    std::shared_ptr<LivePublishProcess> livePublishProcess = LivePublishProcess::GetInstance();
    if (livePublishProcess == nullptr) {
        ANS_LOGE("InitPublishProcess fail as livePublishProcess is nullptr.");
        return false;
    }
    publishProcess_.insert_or_assign(NotificationConstant::SlotType::LIVE_VIEW, livePublishProcess);
    std::shared_ptr<CommonNotificationPublishProcess> commonNotificationPublishProcess =
        CommonNotificationPublishProcess::GetInstance();
    if (commonNotificationPublishProcess == nullptr) {
        ANS_LOGE("InitPublishProcess fail as commonNotificationPublishProcess is nullptr.");
        publishProcess_.clear();
        return false;
    }
    publishProcess_.insert_or_assign(
        NotificationConstant::SlotType::SOCIAL_COMMUNICATION, commonNotificationPublishProcess);
    publishProcess_.insert_or_assign(
        NotificationConstant::SlotType::SERVICE_REMINDER, commonNotificationPublishProcess);
    publishProcess_.insert_or_assign(
        NotificationConstant::SlotType::CONTENT_INFORMATION, commonNotificationPublishProcess);
    publishProcess_.insert_or_assign(
        NotificationConstant::SlotType::OTHER, commonNotificationPublishProcess);
    publishProcess_.insert_or_assign(
        NotificationConstant::SlotType::CUSTOM, commonNotificationPublishProcess);
    publishProcess_.insert_or_assign(
        NotificationConstant::SlotType::CUSTOMER_SERVICE, commonNotificationPublishProcess);
    publishProcess_.insert_or_assign(
        NotificationConstant::SlotType::EMERGENCY_INFORMATION, commonNotificationPublishProcess);
    return true;
}

ErrCode AdvancedNotificationService::Cancel(int32_t notificationId,
    const std::string &label, const std::string &instanceKey)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        std::string message = "get bundleOption is null.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(1, 1)
            .ErrorCode(ERR_ANS_INVALID_BUNDLE).NotificationId(notificationId);
        ReportDeleteFailedEventPush(haMetaMessage, NotificationConstant::APP_CANCEL_REASON_DELETE,
            message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_BUNDLE;
    }
    bundleOption->SetAppInstanceKey(instanceKey);
    return CancelPreparedNotification(notificationId, label, bundleOption,
        NotificationConstant::APP_CANCEL_REASON_DELETE);
}

ErrCode AdvancedNotificationService::CancelAll(const std::string &instanceKey)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    const int reason = NotificationConstant::APP_CANCEL_ALL_REASON_DELETE;
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    bundleOption->SetAppInstanceKey(instanceKey);

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidated.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ExcuteCancelAll(bundleOption, reason);
    return result;
}

ErrCode AdvancedNotificationService::ExcuteCancelAll(
    const sptr<NotificationBundleOption>& bundleOption, const int32_t reason)
{
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<Notification> notification = nullptr;

        std::vector<std::string> keys = GetNotificationKeysByBundle(bundleOption);
        std::vector<sptr<Notification>> notifications;
        std::vector<uint64_t> timerIds;
        for (auto key : keys) {
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            std::string deviceId;
            std::string bundleName;
            GetDistributedInfo(key, deviceId, bundleName);
#endif
            result = RemoveFromNotificationList(key, notification, true, reason);
            if (result != ERR_OK) {
                continue;
            }

            if (notification != nullptr) {
                UpdateRecentNotification(notification, true, reason);
                notifications.emplace_back(notification);
                timerIds.emplace_back(notification->GetAutoDeletedTimer());
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(deviceId, bundleName, notification);
#endif
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                std::vector<sptr<Notification>> currNotificationList = notifications;
                NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                    currNotificationList, nullptr, reason);
                notifications.clear();
            }
        }

        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                notifications, nullptr, reason);
        }
        BatchCancelTimer(timerIds);
        result = ERR_OK;
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::CancelAsBundle(
    const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId, int32_t userId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    int32_t reason = NotificationConstant::APP_CANCEL_AS_BUNELE_REASON_DELETE;
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is invalid");
        return ERR_ANS_INVALID_PARAM;
    }
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        std::string message = "not systemApp";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(2, 1)
            .ErrorCode(ERR_ANS_NON_SYSTEM_APP).NotificationId(notificationId);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER) ||
        !AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER)) {
        std::string message = "no acl permission";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(2, 2)
            .ErrorCode(ERR_ANS_PERMISSION_DENIED).NotificationId(notificationId);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t errCode = CheckUserIdParams(userId);
    if (errCode != ERR_OK) {
        return errCode;
    }

    int32_t uid = -1;
    if (bundleOption->GetUid() == DEFAULT_UID) {
        std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
        if (bundleManager != nullptr) {
            uid = BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(bundleOption->GetBundleName(), userId);
        }
    } else {
        uid = bundleOption->GetUid();
    }
    if (uid < 0) {
        std::string message = "uid error";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(2, 3)
            .ErrorCode(ERR_ANS_INVALID_UID).NotificationId(notificationId);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_UID;
    }
    sptr<NotificationBundleOption> bundle = new (std::nothrow) NotificationBundleOption(
        bundleOption->GetBundleName(), uid);
    return CancelPreparedNotification(notificationId, "", bundle, reason);
}

ErrCode AdvancedNotificationService::CancelAsBundle(
    const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId)
{
    ANS_LOGD("%{public}s, uid = %{public}d", __FUNCTION__, bundleOption->GetUid());
    int32_t userId = -1;
    if (bundleOption->GetUid() != 0) {
        OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(bundleOption->GetUid(), userId);
    } else {
        OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(IPCSkeleton::GetCallingUid(), userId);
    }
    return CancelAsBundle(bundleOption, notificationId, userId);
}

ErrCode AdvancedNotificationService::CancelAsBundle(
    int32_t notificationId, const std::string &representativeBundle, int32_t userId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(
         representativeBundle, DEFAULT_UID);
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is nullptr.");
        return ERR_ANS_TASK_ERR;
    }
    return CancelAsBundle(bundleOption, notificationId, userId);
}

ErrCode AdvancedNotificationService::CancelAsBundleWithAgent(
    const sptr<NotificationBundleOption> &bundleOption, const int32_t id)
{
    ANS_LOGD("Called.");
    int32_t reason = NotificationConstant::APP_CANCEL_AS_BUNELE_WITH_AGENT_REASON_DELETE;
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        std::string message = "not systemApp";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(2, 4)
            .ErrorCode(ERR_ANS_NON_SYSTEM_APP).NotificationId(id);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (IsAgentRelationship(GetClientBundleName(), bundleOption->GetBundleName())) {
        int32_t userId = -1;
        if (bundleOption->GetUid() != 0) {
            OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(bundleOption->GetUid(), userId);
        } else {
            OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(IPCSkeleton::GetCallingUid(), userId);
        }
        int32_t uid = -1;
        if (bundleOption->GetUid() == DEFAULT_UID) {
            std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
            if (bundleManager != nullptr) {
                uid = BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(
                    bundleOption->GetBundleName(), userId);
            }
        } else {
            uid = bundleOption->GetUid();
        }
        if (uid < 0) {
            std::string message = "uid error";
            OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(2, 5)
                .ErrorCode(ERR_ANS_INVALID_UID).NotificationId(id);
            ReportDeleteFailedEventPush(haMetaMessage, reason, message);
            ANS_LOGE("%{public}s", message.c_str());
            return ERR_ANS_INVALID_UID;
        }
        sptr<NotificationBundleOption> bundle = new (std::nothrow) NotificationBundleOption(
            bundleOption->GetBundleName(), uid);
        return CancelPreparedNotification(id, "", bundle, reason);
    }
    std::string message = "no agent setting";
    OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(2, 6)
        .ErrorCode(ERR_ANS_NO_AGENT_SETTING).NotificationId(id);
    ReportDeleteFailedEventPush(haMetaMessage, reason, message);
    ANS_LOGE("%{public}s", message.c_str());
    return ERR_ANS_NO_AGENT_SETTING;
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

ErrCode AdvancedNotificationService::SetNotificationBadgeNum(int32_t num)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGD("BundleOption is null.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(
        std::bind([&]() {
            ANS_LOGD("ffrt enter!");
            result = NotificationPreferences::GetInstance()->SetTotalBadgeNums(bundleOption, num);
        }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::Delete(const std::string &key, int32_t removeReason)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        std::string message = "not systemApp. key:" + key + ".";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(4, 1)
            .ErrorCode(ERR_ANS_NON_SYSTEM_APP);
        ReportDeleteFailedEventPush(haMetaMessage, removeReason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        std::string message = "no acl permission. key:" + key + ".";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(4, 2)
            .ErrorCode(ERR_ANS_PERMISSION_DENIED);
        ReportDeleteFailedEventPush(haMetaMessage, removeReason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        std::string message = "Serial queue is invalidated. key:" + key + ".";
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_PARAM;
    }

    return ExcuteDelete(key, removeReason);
}

ErrCode AdvancedNotificationService::ExcuteDelete(const std::string &key, const int32_t removeReason)
{
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<Notification> notification = nullptr;
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
        std::string deviceId;
        std::string bundleName;
        GetDistributedInfo(key, deviceId, bundleName);
#endif
        result = RemoveFromNotificationList(key, notification, false, removeReason);
        if (result != ERR_OK) {
            return;
        }

        if (notification != nullptr) {
            UpdateRecentNotification(notification, true, removeReason);
            CancelTimer(notification->GetAutoDeletedTimer());
            NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, nullptr, removeReason);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            DoDistributedDelete(deviceId, bundleName, notification);
#endif
        }
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::DeleteByBundle(const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("VerifyNativeToken is false.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGD("bundle is false.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        std::vector<std::string> keys = GetNotificationKeys(bundle);
        for (auto key : keys) {
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            std::string deviceId;
            std::string bundleName;
            GetDistributedInfo(key, deviceId, bundleName);
#endif
            sptr<Notification> notification = nullptr;

            result = RemoveFromNotificationList(key, notification, false, NotificationConstant::CANCEL_REASON_DELETE);
            if (result != ERR_OK) {
                continue;
            }

            if (notification != nullptr) {
                int32_t reason = NotificationConstant::CANCEL_REASON_DELETE;
                UpdateRecentNotification(notification, true, reason);
                CancelTimer(notification->GetAutoDeletedTimer());
                NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, nullptr, reason);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(deviceId, bundleName, notification);
#endif
            }
        }

        result = ERR_OK;
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::DeleteAll()
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    const int32_t reason = NotificationConstant::CANCEL_ALL_REASON_DELETE;
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        std::string message = "not system app.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(6, 8)
            .ErrorCode(ERR_ANS_NON_SYSTEM_APP);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        std::string message = "no acl permission.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(6, 9)
            .ErrorCode(ERR_ANS_PERMISSION_DENIED);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        std::string message = "Serial queue is invalidity.";
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        int32_t activeUserId = SUBSCRIBE_USER_INIT;
        if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(activeUserId) != ERR_OK) {
            return;
        }
        std::vector<std::string> keys = GetNotificationKeys(nullptr);
        std::vector<sptr<Notification>> notifications;
        std::vector<uint64_t> timerIds;
        for (auto key : keys) {
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            std::string deviceId;
            std::string bundleName;
            GetDistributedInfo(key, deviceId, bundleName);
#endif
            sptr<Notification> notification = nullptr;

            result = RemoveFromNotificationListForDeleteAll(key, activeUserId, notification);
            if ((result != ERR_OK) || (notification == nullptr)) {
                continue;
            }

            if (notification->GetUserId() == activeUserId) {
                UpdateRecentNotification(notification, true, reason);
                notifications.emplace_back(notification);
                timerIds.emplace_back(notification->GetAutoDeletedTimer());
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(deviceId, bundleName, notification);
#endif
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                ANS_LOGD("Notifications size greater than or equal to MAX_CANCELED_PARCELABLE_VECTOR_NUM.");
                SendNotificationsOnCanceled(notifications, nullptr, reason);
            }
        }
        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                notifications, nullptr, reason);
        }
        BatchCancelTimer(timerIds);
        result = ERR_OK;
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::SetShowBadgeEnabledForBundle(
    const sptr<NotificationBundleOption> &bundleOption, bool enabled)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("BundleOption is null.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_8, EventBranchId::BRANCH_3);
    message.Message(bundleOption->GetBundleName() + "_" + std::to_string(bundleOption->GetUid()) +
        " enabled:" + std::to_string(enabled));

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("IsSystemApp is false.");
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).Append(" Not SystemApp");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission Denied.");
        message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Append(" Permission Denied");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("Bundle is nullptr.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(
        std::bind([&]() {
            ANS_LOGD("ffrt enter!");
            result = NotificationPreferences::GetInstance()->SetShowBadge(bundle, enabled);
            if (result == ERR_OK) {
                HandleBadgeEnabledChanged(bundle, enabled);
            }
        }));
    notificationSvrQueue_->wait(handler);
    ANS_LOGI("%{public}s_%{public}d, enabled: %{public}s, Set show badge enabled for bundle result: %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), std::to_string(enabled).c_str(), result);
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    return result;
}

void AdvancedNotificationService::HandleBadgeEnabledChanged(
    const sptr<NotificationBundleOption> &bundleOption, bool enabled)
{
    sptr<EnabledNotificationCallbackData> enabledData = new (std::nothrow)
        EnabledNotificationCallbackData(bundleOption->GetBundleName(), bundleOption->GetUid(), enabled);
    if (enabledData == nullptr) {
        ANS_LOGE("Failed to create badge enabled data object.");
        return;
    }

    NotificationSubscriberManager::GetInstance()->NotifyBadgeEnabledChanged(enabledData);
}

ErrCode AdvancedNotificationService::GetShowBadgeEnabledForBundle(
    const sptr<NotificationBundleOption> &bundleOption, bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("VerifyNativeToken is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGD("Failed to generateValidBundleOption.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->IsShowBadge(bundle, enabled);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            enabled = true;
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::GetShowBadgeEnabled(bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is ineffective.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->IsShowBadge(bundleOption, enabled);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            enabled = true;
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::RequestEnableNotification(const std::string &deviceId,
    const sptr<IAnsDialogCallback> &callback)
{
    return RequestEnableNotification(deviceId, callback, nullptr);
}

ErrCode AdvancedNotificationService::RequestEnableNotification(const std::string &deviceId,
    const sptr<IAnsDialogCallback> &callback,
    const sptr<IRemoteObject> &callerToken)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (callback == nullptr) {
        ANS_LOGE("callback == nullptr");
        return ERR_ANS_INVALID_PARAM;
    }
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is nullptr.");
        return ERROR_INTERNAL_ERROR;
    }
    return CommonRequestEnableNotification(deviceId, callback, callerToken, bundleOption, false);
}

ErrCode AdvancedNotificationService::RequestEnableNotification(const std::string& bundleName, int32_t uid)
{
    ANS_LOGI("RequestEnableNotification bundleName = %{public}s uid = %{public}d", bundleName.c_str(), uid);
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }
    if (bundleName == BUNDLE_NAME_ZYT || bundleName == BUNDLE_NAME_ABROAD) {
        ANS_LOGI("RequestEnableNotification zyt or abroad");
        return ERR_ANS_NOT_ALLOWED;
    }

    AppExecFwk::BundleInfo bundleInfo;
    BundleManagerHelper::GetInstance()->GetBundleInfoV9(bundleName, 1, bundleInfo, 0);
    if (bundleInfo.applicationInfo.installSource == INSTALL_SOURCE_EASYABROAD) {
        ANS_LOGI("RequestEnableNotification abroad app");
        return ERR_ANS_NOT_ALLOWED;
    }
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundleName, uid);
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is nullptr.");
        return ERROR_INTERNAL_ERROR;
    }
    return CommonRequestEnableNotification("", nullptr, nullptr, bundleOption, true);
}

ErrCode AdvancedNotificationService::CommonRequestEnableNotification(const std::string &deviceId,
    const sptr<IAnsDialogCallback> &callback,
    const sptr<IRemoteObject> &callerToken,
    const sptr<NotificationBundleOption> bundleOption,
    const bool innerLake)
{
    ANS_LOGI("%{public}s", __FUNCTION__);
    ErrCode result = ERR_OK;
    // To get the permission
    bool allowedNotify = false;
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_8, EventBranchId::BRANCH_5);
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is nullptr.");
        return ERROR_INTERNAL_ERROR;
    }
    message.Message(bundleOption->GetBundleName() + "_" + std::to_string(bundleOption->GetUid()) +
            " deviceId:" + deviceId);
    result = IsAllowedNotifySelf(bundleOption, allowedNotify);
    if (result != ERR_OK) {
        ANS_LOGE("Not allowed notify self");
        message.ErrorCode(result).Append(" Allow failed");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERROR_INTERNAL_ERROR;
    }
    ANS_LOGI("allowedNotify = %{public}d, bundle = %{public}s", allowedNotify,
        bundleOption->GetBundleName().c_str());
    if (allowedNotify) {
        message.ErrorCode(ERR_OK).Append(" Allow success");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_OK;
    }
    // Check to see if it has been popover before
    bool hasPopped = false;
    result = GetHasPoppedDialog(bundleOption, hasPopped);
    if (result != ERR_OK) {
        ANS_LOGE("Get has popped dialog failed.");
        message.ErrorCode(result).Append(" Get dialog failed.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERROR_INTERNAL_ERROR;
    }
    if (hasPopped) {
        ANS_LOGE("Has popped is true.");
        message.ErrorCode(ERR_ANS_NOT_ALLOWED).Append(" Has popped");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_NOT_ALLOWED;
    }

    if (!CreateDialogManager()) {
        ANS_LOGE("Create dialog manager failed.");
        message.ErrorCode(ERR_ANS_NOT_ALLOWED).Append(" Create dialog failed");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERROR_INTERNAL_ERROR;
    }

    result = dialogManager_->RequestEnableNotificationDailog(bundleOption, callback, callerToken, innerLake);
    if (result == ERR_OK) {
        result = ERR_ANS_DIALOG_POP_SUCCEEDED;
    }

    ANS_LOGI("%{public}s_%{public}d, deviceId: %{public}s, Request enable notification dailog result: %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), deviceId.c_str(), result);
    message.ErrorCode(result);
    if (!innerLake || result == ERR_ANS_DIALOG_POP_SUCCEEDED) {
        NotificationAnalyticsUtil::ReportModifyEvent(message);
    }
    return result;
}

ErrCode AdvancedNotificationService::SetNotificationsEnabledForBundle(const std::string &deviceId, bool enabled)
{
    return ERR_INVALID_OPERATION;
}

ErrCode AdvancedNotificationService::SetNotificationsEnabledForAllBundles(const std::string &deviceId, bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("VerifyNativeToken and IsSystemApp is false.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        if (deviceId.empty()) {
            // Local device
            result = NotificationPreferences::GetInstance()->SetNotificationsEnabled(userId, enabled);
        } else {
            // Remote device
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::SetNotificationsEnabledForSpecialBundle(
    const std::string &deviceId, const sptr<NotificationBundleOption> &bundleOption, bool enabled)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr) {
        ANS_LOGE("BundleOption is null.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_8, EventBranchId::BRANCH_4);
    message.Message(bundleOption->GetBundleName() + "_" + std::to_string(bundleOption->GetUid()) +
            " enabled:" + std::to_string(enabled) +
            " deviceId:" + deviceId);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("IsSystemApp is false.");
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).Append(" Not SystemApp");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_NON_SYSTEM_APP;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != ANS_UID && !AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission Denied.");
        message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Append(" Permission Denied");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        message.ErrorCode(ERR_ANS_INVALID_BUNDLE).Append(" Bundle is nullptr.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE(" Bundle is nullptr.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    sptr<EnabledNotificationCallbackData> bundleData = new (std::nothrow)
        EnabledNotificationCallbackData(bundle->GetBundleName(), bundle->GetUid(), enabled);
    if (bundleData == nullptr) {
        ANS_LOGE("Failed to create EnabledNotificationCallbackData instance");
        return ERR_NO_MEMORY;
    }

    ErrCode result = ERR_OK;
    if (deviceId.empty()) {
        // Local device
        result = NotificationPreferences::GetInstance()->SetNotificationsEnabledForBundle(bundle, enabled);
        if (result == ERR_OK) {
            if (!enabled) {
                result = RemoveAllNotificationsForDisable(bundle);
            }
            SetSlotFlagsTrustlistsAsBundle(bundle);
            NotificationSubscriberManager::GetInstance()->NotifyEnabledNotificationChanged(bundleData);
            PublishSlotChangeCommonEvent(bundle);
        }
    } else {
        // Remote device
    }

    ANS_LOGI("%{public}s_%{public}d, deviceId: %{public}s, enable: %{public}s, "
        "Set notifications enabled for special bundle result: %{public}d", bundleOption->GetBundleName().c_str(),
        bundleOption->GetUid(), deviceId.c_str(), std::to_string(enabled).c_str(), result);
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    SendEnableNotificationHiSysEvent(bundleOption, enabled, result);
    return result;
}

ErrCode AdvancedNotificationService::IsAllowedNotify(bool &allowed)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("AccessTokenHelper::CheckPermission is false");
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        allowed = false;
        result = NotificationPreferences::GetInstance()->GetNotificationsEnabled(userId, allowed);
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::IsAllowedNotifySelf(bool &allowed)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    return IsAllowedNotifySelf(bundleOption, allowed);
}

ErrCode AdvancedNotificationService::CanPopEnableNotificationDialog(
    const sptr<IAnsDialogCallback> &callback, bool &canPop, std::string &bundleName)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    canPop = false;
    ErrCode result = ERR_OK;
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is nullptr.");
        return ERR_ANS_INVALID_BUNDLE;
    }
    // To get the permission
    bool allowedNotify = false;
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_2, EventBranchId::BRANCH_2);
    message.Message(bundleOption->GetBundleName() + "_" + std::to_string(bundleOption->GetUid()) +
        " canPop:" + std::to_string(canPop));
    result = IsAllowedNotifySelf(bundleOption, allowedNotify);
    if (result != ERR_OK) {
        ANS_LOGE("Not allowed Notify self.");
        message.ErrorCode(result).Append(" Not Allow");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERROR_INTERNAL_ERROR;
    }
    ANS_LOGI("allowedNotify = %{public}d, bundle = %{public}s", allowedNotify,
        bundleOption->GetBundleName().c_str());
    if (allowedNotify) {
        message.ErrorCode(ERR_OK).Append(" Allow success");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_OK;
    }
    // Check to see if it has been popover before
    bool hasPopped = false;
    result = GetHasPoppedDialog(bundleOption, hasPopped);
    if (result != ERR_OK) {
        ANS_LOGE("Get has popped dialog failed. result: %{public}d", result);
        message.ErrorCode(result).Append(" Has popped");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERROR_INTERNAL_ERROR;
    }
    if (hasPopped) {
        ANS_LOGE("Has popped is true.");
        message.ErrorCode(ERR_ANS_NOT_ALLOWED).Append(" Haspopped true");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_NOT_ALLOWED;
    }

    if (!CreateDialogManager()) {
        ANS_LOGE("Create dialog manager failed.");
        message.ErrorCode(ERR_ANS_NOT_ALLOWED).Append(" Create dialog failed");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERROR_INTERNAL_ERROR;
    }
    result = dialogManager_->AddDialogInfo(bundleOption, callback);
    if (result != ERR_OK) {
        ANS_LOGI("AddDialogInfo result: %{public}d", result);
        message.ErrorCode(result).Append(" AddDialogInfo");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return result;
    }

    canPop = true;
    bundleName = bundleOption->GetBundleName();
    ANS_LOGI("%{public}s_%{public}d, canPop: %{public}s, CanPopEnableNotificationDialog result: %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), std::to_string(canPop).c_str(), result);
    message.ErrorCode(result).Append(" CanPopEnableNotificationDialog end");
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::RemoveEnableNotificationDialog()
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    ErrCode result = ERR_OK;
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption == nullptr");
        return ERR_ANS_INVALID_BUNDLE;
    }
    return RemoveEnableNotificationDialog(bundleOption);
}

ErrCode AdvancedNotificationService::RemoveEnableNotificationDialog(const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGI("RemoveEnableNotificationDialog  %{public}s, %{public}d",
        bundleOption->GetBundleName().c_str(),
        bundleOption->GetUid());
    if (!CreateDialogManager()) {
        return ERROR_INTERNAL_ERROR;
    }
    std::unique_ptr<NotificationDialogManager::DialogInfo> dialogInfoRemoved = nullptr;
    dialogManager_->RemoveDialogInfoByBundleOption(bundleOption, dialogInfoRemoved);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::IsAllowedNotifySelf(const sptr<NotificationBundleOption> &bundleOption,
    bool &allowed)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGD("GetActiveUserId is false");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    ErrCode result = ERR_OK;
    allowed = false;
    result = NotificationPreferences::GetInstance()->GetNotificationsEnabled(userId, allowed);
    if (result == ERR_OK && allowed) {
        result = NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundleOption, allowed);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            // FA model app can publish notification without user confirm
            allowed = CheckApiCompatibility(bundleOption);
            SetDefaultNotificationEnabled(bundleOption, allowed);
        }
    }
    return result;
}

ErrCode AdvancedNotificationService::IsAllowedNotifyForBundle(const sptr<NotificationBundleOption>
    &bundleOption, bool &allowed)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGD("GetActiveUserId is false");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    ErrCode result = ERR_OK;
    allowed = false;
    result = NotificationPreferences::GetInstance()->GetNotificationsEnabled(userId, allowed);
    if (result == ERR_OK && allowed) {
        result = NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundleOption, allowed);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            // FA model app can publish notification without user confirm
            allowed = CheckApiCompatibility(bundleOption);
        }
    }
    return result;
}

ErrCode AdvancedNotificationService::IsSpecialBundleAllowedNotify(
    const sptr<NotificationBundleOption> &bundleOption, bool &allowed)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("Not system application");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != ANS_UID && !AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> targetBundle = nullptr;
    if (isSubsystem) {
        if (bundleOption != nullptr) {
            targetBundle = GenerateValidBundleOption(bundleOption);
        }
    } else {
        ErrCode result = GetAppTargetBundle(bundleOption, targetBundle);
        if (result != ERR_OK) {
            return result;
        }
    }

    if (targetBundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    ErrCode result = ERR_OK;
        allowed = false;
        result = NotificationPreferences::GetInstance()->GetNotificationsEnabled(userId, allowed);
        if (result == ERR_OK && allowed) {
            result = NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(targetBundle, allowed);
            if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
                result = ERR_OK;
                allowed = CheckApiCompatibility(targetBundle);
                SetNotificationsEnabledForSpecialBundle("", bundleOption, allowed);
            }
        }
    return result;
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

ErrCode AdvancedNotificationService::CancelContinuousTaskNotification(const std::string &label, int32_t notificationId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem) {
        return ERR_ANS_NOT_SYSTEM_SERVICE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<Notification> notification = nullptr;
        for (auto record : notificationList_) {
            if ((record->bundleOption->GetBundleName().empty()) && (record->bundleOption->GetUid() == uid) &&
                (record->notification->GetId() == notificationId) && (record->notification->GetLabel() == label)) {
                notification = record->notification;
                notificationList_.remove(record);
                result = ERR_OK;
                break;
            }
        }
        if (notification != nullptr) {
            int32_t reason = NotificationConstant::APP_CANCEL_REASON_DELETE;
            UpdateRecentNotification(notification, true, reason);
            CancelTimer(notification->GetAutoDeletedTimer());
            NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, nullptr, reason);
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::RemoveSystemLiveViewNotifications(
    const std::string& bundleName, const int32_t uid)
{
    std::vector<std::shared_ptr<NotificationRecord>> recordList;
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue is nullptr");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        LivePublishProcess::GetInstance()->EraseLiveViewSubsciber(uid);
        GetTargetRecordList(uid,  NotificationConstant::SlotType::LIVE_VIEW,
            NotificationContent::Type::LOCAL_LIVE_VIEW, recordList);
        GetCommonTargetRecordList(uid,  NotificationConstant::SlotType::LIVE_VIEW,
            NotificationContent::Type::LIVE_VIEW, recordList);
        if (recordList.size() == 0) {
            ANS_LOGE("Get Target record list fail.");
            result = ERR_ANS_NOTIFICATION_NOT_EXISTS;
            return;
        }
        result = RemoveNotificationFromRecordList(recordList);
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::RemoveSystemLiveViewNotificationsOfSa(int32_t uid)
{
    {
        std::lock_guard<std::mutex> lock(delayNotificationMutext_);
        for (auto iter = delayNotificationList_.begin(); iter != delayNotificationList_.end();) {
            if ((*iter).first->notification->GetNotificationRequest().GetCreatorUid() == uid &&
                (*iter).first->notification->GetNotificationRequest().IsInProgress()) {
                CancelTimer((*iter).second);
                iter = delayNotificationList_.erase(iter);
            } else {
                iter++;
            }
        }
    }

    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        LivePublishProcess::GetInstance()->EraseLiveViewSubsciber(uid);
        std::vector<std::shared_ptr<NotificationRecord>> recordList;
        for (auto item : notificationList_) {
            if (item->notification->GetNotificationRequest().GetCreatorUid() == uid &&
                item->notification->GetNotificationRequest().IsInProgress()) {
                recordList.emplace_back(item);
            }
        }
        if (!recordList.empty()) {
            result = RemoveNotificationFromRecordList(recordList);
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::TriggerLocalLiveView(const sptr<NotificationBundleOption> &bundleOption,
    const int32_t notificationId, const sptr<NotificationButtonOption> &buttonOption)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("AccessTokenHelper::CheckPermission is bogus.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_ANS_NOTIFICATION_NOT_EXISTS;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<Notification> notification = nullptr;

        for (auto record : notificationList_) {
            if (record->request->GetAgentBundle() != nullptr) {
                if ((record->request->GetAgentBundle()->GetBundleName() == bundle->GetBundleName()) &&
                    (record->request->GetAgentBundle()->GetUid() == bundle->GetUid()) &&
                    (record->notification->GetId() == notificationId)) {
                    notification = record->notification;
                    result = ERR_OK;
                    break;
                }
            } else {
                if ((record->bundleOption->GetBundleName() == bundle->GetBundleName()) &&
                    (record->bundleOption->GetUid() == bundle->GetUid()) &&
                    (record->notification->GetId() == notificationId)) {
                    notification = record->notification;
                    result = ERR_OK;
                    break;
                }
            }
        }

        if (notification != nullptr) {
            NotificationLocalLiveViewSubscriberManager::GetInstance()->NotifyTriggerResponse(notification,
                buttonOption);
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::RemoveNotification(const sptr<NotificationBundleOption> &bundleOption,
    int32_t notificationId, const std::string &label, int32_t removeReason)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        std::string message = "not systemApp.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(4, 4)
            .ErrorCode(ERR_ANS_NON_SYSTEM_APP).NotificationId(notificationId);
        ReportDeleteFailedEventPush(haMetaMessage, removeReason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        std::string message = "no acl controller permission.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(4, 5)
            .ErrorCode(ERR_ANS_PERMISSION_DENIED).NotificationId(notificationId);
        ReportDeleteFailedEventPush(haMetaMessage, removeReason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        std::string message = "NotificationSvrQueue_ is null.";
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_ANS_NOTIFICATION_NOT_EXISTS;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        bool isThirdParty = true;
        sptr<Notification> notification = nullptr;
        sptr<NotificationRequest> notificationRequest = nullptr;

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
        std::string deviceId;
        std::string bundleName;
#endif
        for (auto record : notificationList_) {
            if ((record->bundleOption->GetBundleName() == bundle->GetBundleName()) &&
                (record->bundleOption->GetUid() == bundle->GetUid()) &&
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                (record->deviceId.empty()) &&
#endif
                (record->notification->GetId() == notificationId) && (record->notification->GetLabel() == label)) {
                if (!record->notification->IsRemoveAllowed()) {
                    result = ERR_ANS_NOTIFICATION_IS_UNALLOWED_REMOVEALLOWED;
                    break;
                }
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                deviceId = record->deviceId;
                bundleName = record->bundleName;
#endif
                notification = record->notification;
                notificationRequest = record->request;
                isThirdParty = record->isThirdparty;

                if (removeReason != NotificationConstant::CLICK_REASON_DELETE) {
                    ProcForDeleteLiveView(record);
                }

                notificationList_.remove(record);
                result = ERR_OK;
                break;
            }
        }

        if (notification != nullptr) {
            UpdateRecentNotification(notification, true, removeReason);
            CancelTimer(notification->GetAutoDeletedTimer());
            NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, nullptr, removeReason);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            DoDistributedDelete(deviceId, bundleName, notification);
#endif
        }
        if (removeReason != NotificationConstant::CLICK_REASON_DELETE) {
            TriggerRemoveWantAgent(notificationRequest, removeReason, isThirdParty);
        }
    }));
    notificationSvrQueue_->wait(handler);
    if (result != ERR_OK) {
        std::string message = "remove notificaiton error";
        ANS_LOGE("%{public}s", message.c_str());
    }
    SendRemoveHiSysEvent(notificationId, label, bundleOption, result);
    return result;
}

ErrCode AdvancedNotificationService::RemoveAllNotificationsForDisable(
    const sptr<NotificationBundleOption> &bundleOption)
{
    return RemoveAllNotificationsInner(bundleOption, NotificationConstant::DISABLE_NOTIFICATION_REASON_DELETE);
}

ErrCode AdvancedNotificationService::RemoveAllNotifications(const sptr<NotificationBundleOption> &bundleOption)
{
    return RemoveAllNotificationsInner(bundleOption, NotificationConstant::APP_REMOVE_ALL_REASON_DELETE);
}

ErrCode AdvancedNotificationService::RemoveAllNotificationsInner(const sptr<NotificationBundleOption> &bundleOption,
    int32_t reason)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        std::string message = "not system app.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(6, 1)
            .ErrorCode(ERR_ANS_NON_SYSTEM_APP);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_NON_SYSTEM_APP;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != ANS_UID && !AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        std::string message = "no acl permission.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(6, 2)
            .ErrorCode(ERR_ANS_PERMISSION_DENIED);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        std::string message = "budle is nullptr.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(6, 3)
            .ErrorCode(ERR_ANS_INVALID_BUNDLE);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        std::string message = "Serial queue is nullptr.";
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        std::vector<std::shared_ptr<NotificationRecord>> removeList;
        ANS_LOGD("ffrt enter!");
        for (auto record : notificationList_) {
            bool isAllowedNotification = true;
            if (IsAllowedNotifyForBundle(bundleOption, isAllowedNotification) != ERR_OK) {
                ANSR_LOGW("The application does not request enable notification.");
            }
            if (!record->notification->IsRemoveAllowed() && isAllowedNotification) {
                ANS_LOGI("BatchRemove-FILTER-RemoveNotAllowed-%{public}s", record->notification->GetKey().c_str());
                continue;
            }
            if (record->slot != nullptr) {
                if (record->slot->GetForceControl() && record->slot->GetEnable()) {
                    ANS_LOGI("BatchRemove-FILTER-ForceControl-%{public}s", record->notification->GetKey().c_str());
                    continue;
                }
            }
            if ((record->bundleOption->GetBundleName() == bundle->GetBundleName()) &&
                (record->bundleOption->GetUid() == bundle->GetUid())
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                && record->deviceId.empty()
#endif
                ) {
                auto notificationRequest = record->request;
                if (!BundleManagerHelper::GetInstance()->IsSystemApp(bundle->GetUid()) &&
                    notificationRequest->IsSystemLiveView()) {
                    auto localLiveviewContent = std::static_pointer_cast<NotificationLocalLiveViewContent>(
                        notificationRequest->GetContent()->GetNotificationContent());
                    if (localLiveviewContent->GetType() == 0) {
                        continue;
                    }
                }
                ProcForDeleteLiveView(record);
                removeList.push_back(record);
            }
        }

        std::vector<sptr<Notification>> notifications;
        std::vector<uint64_t> timerIds;
        for (auto record : removeList) {
            notificationList_.remove(record);
            if (record->notification != nullptr) {
                ANS_LOGD("record->notification is not nullptr.");
                UpdateRecentNotification(record->notification, true, reason);
                notifications.emplace_back(record->notification);
                timerIds.emplace_back(record->notification->GetAutoDeletedTimer());
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(record->deviceId, record->bundleName, record->notification);
#endif
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                SendNotificationsOnCanceled(notifications, nullptr, reason);
            }

            TriggerRemoveWantAgent(record->request, reason, record->isThirdparty);
        }

        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(notifications, nullptr, reason);
        }
        BatchCancelTimer(timerIds);
    }));
    notificationSvrQueue_->wait(handler);

    return ERR_OK;
}

ErrCode AdvancedNotificationService::RemoveNotifications(
    const std::vector<std::string> &keys, int32_t removeReason)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("enter");

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        std::vector<sptr<Notification>> notifications;
        std::vector<uint64_t> timerIds;
        for (auto key : keys) {
            sptr<Notification> notification = nullptr;
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            std::string deviceId;
            std::string bundleName;
            GetDistributedInfo(key, deviceId, bundleName);
#endif
            ErrCode result = RemoveFromNotificationList(key, notification, false, removeReason);
            if (result != ERR_OK) {
                continue;
            }
            if (notification != nullptr) {
                UpdateRecentNotification(notification, true, removeReason);
                notifications.emplace_back(notification);
                timerIds.emplace_back(notification->GetAutoDeletedTimer());
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(deviceId, bundleName, notification);
#endif
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                std::vector<sptr<Notification>> currNotificationList = notifications;
                NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                    currNotificationList, nullptr, removeReason);
                notifications.clear();
            }
        }

        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(notifications, nullptr, removeReason);
        }
        BatchCancelTimer(timerIds);
    }));
    notificationSvrQueue_->wait(handler);

    return ERR_OK;
}

ErrCode AdvancedNotificationService::RemoveNotificationBySlot(const sptr<NotificationBundleOption> &bundleOption,
    const sptr<NotificationSlot> &slot, const int reason)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    ErrCode result = ERR_ANS_NOTIFICATION_NOT_EXISTS;
    std::vector<std::shared_ptr<NotificationRecord>> removeList;
    for (auto record : notificationList_) {
        if (record == nullptr) {
            ANS_LOGE("record is nullptr");
            continue;
        }
        if ((record->bundleOption->GetBundleName() == bundle->GetBundleName()) &&
            (record->bundleOption->GetUid() == bundle->GetUid()) &&
            (record->request->GetSlotType() == slot->GetType())) {
                if ((record->request->GetAgentBundle() != nullptr && record->request->IsSystemLiveView())) {
                    ANS_LOGW("Agent systemliveview no need remove.");
                    continue;
                }
                ProcForDeleteLiveView(record);
                removeList.push_back(record);
        }
    }

    std::vector<sptr<Notification>> notifications;
    std::vector<uint64_t> timerIds;
    for (auto record : removeList) {
        if (record == nullptr) {
            ANS_LOGE("record is nullptr");
            continue;
        }
        notificationList_.remove(record);
        if (record->notification != nullptr) {
            ANS_LOGD("record->notification is not nullptr.");
            UpdateRecentNotification(record->notification, true, reason);
            notifications.emplace_back(record->notification);
            timerIds.emplace_back(record->notification->GetAutoDeletedTimer());
        }
        if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
            SendNotificationsOnCanceled(notifications, nullptr, reason);
        }

        TriggerRemoveWantAgent(record->request, reason, record->isThirdparty);
        result = ERR_OK;
    }

    if (!notifications.empty()) {
        NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(notifications, nullptr, reason);
    }
    BatchCancelTimer(timerIds);
    return result;
}

ErrCode AdvancedNotificationService::IsNeedSilentInDoNotDisturbMode(
    const std::string &phoneNumber, int32_t callerType)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != ANS_UID && !AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("IsNeedSilentInDoNotDisturbMode CheckPermission failed.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGD("GetActiveUserId is false");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }
    return CheckNeedSilent(phoneNumber, callerType, userId);
}

ErrCode AdvancedNotificationService::CheckNeedSilent(
    const std::string &phoneNumber, int32_t callerType, int32_t userId)
{
    auto datashareHelper = DelayedSingleton<AdvancedDatashareHelper>::GetInstance();
    if (datashareHelper == nullptr) {
        ANS_LOGE("The data share helper is nullptr.");
        return -1;
    }

    int isNeedSilent = 0;
    std::string policy;
    Uri policyUri(datashareHelper->GetFocusModeCallPolicyUri(userId));
    bool ret = datashareHelper->Query(policyUri, KEY_FOCUS_MODE_CALL_MESSAGE_POLICY, policy);
    if (!ret) {
        ANS_LOGE("Query focus mode call message policy fail.");
        return -1;
    }
    std::string repeat_call;
    Uri repeatUri(datashareHelper->GetFocusModeRepeatCallUri(userId));
    bool repeat_ret = datashareHelper->Query(repeatUri, KEY_FOCUS_MODE_REPEAT_CALLERS_ENABLE, repeat_call);
    if (!repeat_ret) {
        ANS_LOGE("Query focus mode repeat callers enable fail.");
    }
    ANS_LOGI("IsNeedSilent: policy: %{public}s, repeat: %{public}s, callerType: %{public}d",
        policy.c_str(), repeat_call.c_str(), callerType);
    if (repeat_call == FOCUS_MODE_REPEAT_CALLERS_ENABLE &&
        callerType == 0 && atoi(policy.c_str()) != ContactPolicy::ALLOW_EVERYONE) {
        if (datashareHelper->isRepeatCall(phoneNumber)) {
            return 1;
        }
    }
    switch (atoi(policy.c_str())) {
        case ContactPolicy::FORBID_EVERYONE:
            break;
        case ContactPolicy::ALLOW_EVERYONE:
            isNeedSilent = 1;
            break;
        case ContactPolicy::ALLOW_EXISTING_CONTACTS:
        case ContactPolicy::ALLOW_FAVORITE_CONTACTS:
        case ContactPolicy::ALLOW_SPECIFIED_CONTACTS:
        case ContactPolicy::FORBID_SPECIFIED_CONTACTS:
            isNeedSilent = QueryContactByProfileId(phoneNumber, policy, userId);
            break;
    }
    ANS_LOGI("IsNeedSilentInDoNotDisturbMode: %{public}d", isNeedSilent);
    return isNeedSilent;
}

ErrCode AdvancedNotificationService::QueryContactByProfileId(const std::string &phoneNumber,
    const std::string &policy, int32_t userId)
{
    char buf[256] = { 0 };
    const std::string &paramName = "const.intelligentscene.enable";
    std::string isSupportIntelligentScene = "false";
    const std::string defaultValue = "false";

    auto res = GetParameter(paramName.c_str(), defaultValue.c_str(), buf, sizeof(buf));
    if (res <= 0) {
        ANS_LOGD("isSupportIntelligentScene GetParameter is false");
    } else {
        isSupportIntelligentScene = buf;
    }
    ANS_LOGI("isSupportIntelligentScene is %{public}s", isSupportIntelligentScene.c_str());

    auto datashareHelper = DelayedSingleton<AdvancedDatashareHelper>::GetInstance();
    if (datashareHelper == nullptr) {
        ANS_LOGE("The data share helper is nullptr.");
        return -1;
    }

    std::string uri = CONTACT_DATA;
    if (isSupportIntelligentScene == SUPPORT_INTEGELLIGENT_SCENE &&
        (atoi(policy.c_str()) == ContactPolicy::ALLOW_SPECIFIED_CONTACTS ||
        atoi(policy.c_str()) == ContactPolicy::FORBID_SPECIFIED_CONTACTS)) {
        uri = datashareHelper->GetIntelligentUri();
    }
    ANS_LOGI("QueryContactByProfileId uri is %{public}s", uri.c_str());

    std::string profileId;
    Uri profileIdUri(datashareHelper->GetFocusModeProfileUri(userId));
    bool profile_ret = datashareHelper->Query(profileIdUri, KEY_FOCUS_MODE_PROFILE, profileId);
    if (!profile_ret) {
        ANS_LOGE("Query profile id fail.");
        return -1;
    }

    Uri contactUri(uri);
    return datashareHelper->QueryContact(contactUri, phoneNumber, policy, profileId, isSupportIntelligentScene);
}

ErrCode AdvancedNotificationService::CancelGroup(const std::string &groupName, const std::string &instanceKey)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    int32_t reason = NotificationConstant::APP_CANCEL_GROPU_REASON_DELETE;
    if (groupName.empty()) {
        std::string message = "groupName empty.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(3, 1)
            .ErrorCode(ERR_ANS_INVALID_PARAM);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        std::string message = "bundle is nullptr.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(3, 2)
            .ErrorCode(ERR_ANS_INVALID_BUNDLE);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_BUNDLE;
    }
    bundleOption->SetAppInstanceKey(instanceKey);

    if (notificationSvrQueue_ == nullptr) {
        std::string message = "Serial queue is invalid.";
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_PARAM;
    }

    ExcuteCancelGroupCancel(bundleOption, groupName, reason);
    return ERR_OK;
}

void AdvancedNotificationService::ExcuteCancelGroupCancel(
    const sptr<NotificationBundleOption>& bundleOption,
    const std::string &groupName, const int32_t reason)
{
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        std::vector<std::shared_ptr<NotificationRecord>> removeList;
        for (auto record : notificationList_) {
            ANS_LOGD("ExcuteCancelGroupCancel instanceKey(%{public}s, %{public}s).",
                record->notification->GetInstanceKey().c_str(), bundleOption->GetAppInstanceKey().c_str());
            if ((record->bundleOption->GetBundleName() == bundleOption->GetBundleName()) &&
                (record->bundleOption->GetUid() == bundleOption->GetUid()) &&
                (record->notification->GetInstanceKey() == bundleOption->GetAppInstanceKey()) &&
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                record->deviceId.empty() &&
#endif
                (record->request->GetGroupName() == groupName)) {
                removeList.push_back(record);
            }
        }

        std::vector<sptr<Notification>> notifications;
        std::vector<uint64_t> timerIds;
        for (auto record : removeList) {
            notificationList_.remove(record);
            if (record->notification != nullptr) {
                UpdateRecentNotification(record->notification, true, reason);
                notifications.emplace_back(record->notification);
                timerIds.emplace_back(record->notification->GetAutoDeletedTimer());
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(record->deviceId, record->bundleName, record->notification);
#endif
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                std::vector<sptr<Notification>> currNotificationList = notifications;
                NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                    currNotificationList, nullptr, reason);
                notifications.clear();
            }
        }

        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                notifications, nullptr, reason);
        }
        BatchCancelTimer(timerIds);
    }));
    notificationSvrQueue_->wait(handler);
}

ErrCode AdvancedNotificationService::RemoveGroupByBundle(
    const sptr<NotificationBundleOption> &bundleOption, const std::string &groupName)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    const int32_t reason = NotificationConstant::APP_REMOVE_GROUP_REASON_DELETE;
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        std::string message = "not systemApp.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(5, 1)
            .ErrorCode(ERR_ANS_NON_SYSTEM_APP);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        std::string message = "no acl permission";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(5, 2)
            .ErrorCode(ERR_ANS_PERMISSION_DENIED);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (bundleOption == nullptr || groupName.empty()) {
        std::string message = "groupName empty";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(5, 3)
            .ErrorCode(ERR_ANS_INVALID_PARAM);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        std::string message = "bundle is nullptr";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(5, 4)
            .ErrorCode(ERR_ANS_INVALID_PARAM);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        std::string message = "Serial queue is invalid.";
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        std::vector<std::shared_ptr<NotificationRecord>> removeList;
        int32_t reason = NotificationConstant::CANCEL_REASON_DELETE;
        for (auto record : notificationList_) {
            if (!record->notification->IsRemoveAllowed()) {
                continue;
            }
            if ((record->bundleOption->GetBundleName() == bundle->GetBundleName()) &&
                (record->bundleOption->GetUid() == bundle->GetUid()) && !record->request->IsUnremovable() &&
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                record->deviceId.empty() &&
#endif
                (record->request->GetGroupName() == groupName)) {
                ANS_LOGD("RemoveList push enter.");
                removeList.push_back(record);
            }
        }

        std::vector<sptr<Notification>> notifications;
        std::vector<uint64_t> timerIds;
        for (auto record : removeList) {
            notificationList_.remove(record);
            ProcForDeleteLiveView(record);

            if (record->notification != nullptr) {
                UpdateRecentNotification(record->notification, true, reason);
                notifications.emplace_back(record->notification);
                timerIds.emplace_back(record->notification->GetAutoDeletedTimer());
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(record->deviceId, record->bundleName, record->notification);
#endif
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                SendNotificationsOnCanceled(notifications, nullptr, reason);
            }
        }

        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(notifications, nullptr, reason);
        }
        BatchCancelTimer(timerIds);
    }));
    notificationSvrQueue_->wait(handler);

    return ERR_OK;
}

ErrCode AdvancedNotificationService::RemoveNotificationFromRecordList(
    const std::vector<std::shared_ptr<NotificationRecord>>& recordList)
{
    ErrCode result = ERR_OK;
        std::vector<sptr<Notification>> notifications;
        std::vector<uint64_t> timerIds;
        for (auto& record : recordList) {
            std::string key = record->notification->GetKey();
            sptr<Notification> notification = nullptr;
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            std::string deviceId;
            std::string bundleName;
            GetDistributedInfo(key, deviceId, bundleName);
#endif
            result = RemoveFromNotificationList(key, notification, true,
                NotificationConstant::USER_STOPPED_REASON_DELETE);
            if (result != ERR_OK) {
                continue;
            }
            if (notification != nullptr) {
                int32_t reason = NotificationConstant::USER_STOPPED_REASON_DELETE;
                UpdateRecentNotification(notification, true, reason);
                notifications.emplace_back(notification);
                timerIds.emplace_back(notification->GetAutoDeletedTimer());
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            DoDistributedDelete(deviceId, bundleName, notification);
#endif
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                std::vector<sptr<Notification>> currNotificationList = notifications;
                NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                    currNotificationList, nullptr, NotificationConstant::USER_STOPPED_REASON_DELETE);
                notifications.clear();
            }
        }
        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                notifications, nullptr, NotificationConstant::USER_STOPPED_REASON_DELETE);
        }
        BatchCancelTimer(timerIds);
        return result;
}

ErrCode AdvancedNotificationService::IsSpecialUserAllowedNotify(int32_t userId, bool &allowed)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("Failed to checkPermission");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        allowed = false;
        result = NotificationPreferences::GetInstance()->GetNotificationsEnabled(userId, allowed);
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::SetNotificationsEnabledByUser(int32_t userId, bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is ineffectiveness.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->SetNotificationsEnabled(userId, enabled);
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

void AdvancedNotificationService::UpdateUnifiedGroupInfo(const std::string &key,
    std::shared_ptr<NotificationUnifiedGroupInfo> &groupInfo)
{
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return;
    }

    ffrt::task_handle handler = notificationSvrQueue_->submit_h([=]() {
        for (const auto& item : notificationList_) {
            if (item->notification->GetKey() == key) {
                ANS_LOGD("update group info matched key %s", key.c_str());
                item->notification->GetNotificationRequestPoint()->SetUnifiedGroupInfo(groupInfo);

                CloseAlert(item);

                UpdateRecentNotification(item->notification, false, 0);
                sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
                NotificationSubscriberManager::GetInstance()->NotifyConsumed(item->notification, sortingMap);
                break;
            }
        }
    });
}

void AdvancedNotificationService::ClearSlotTypeData(const sptr<NotificationRequest> &request, int32_t callingUid)
{
    if (request == nullptr || callingUid != AVSEESAION_PID) {
        return;
    }
    if (request->GetSlotType() != NotificationConstant::SlotType::LIVE_VIEW) {
        return;
    }

    int32_t uid = request->GetOwnerUid();
    std::string bundleName = BundleManagerHelper::GetInstance()->GetBundleNameByUid(uid);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundleName, uid);
    if (bundleOption == nullptr) {
        ANS_LOGW("Notification get bundle failed %{public}d", uid);
        return;
    }

    if (NotificationPreferences::GetInstance()->GetBundleRemoveFlag(bundleOption,
        NotificationConstant::SlotType::LIVE_VIEW)) {
        return;
    }
    NotificationPreferences::GetInstance()->RemoveNotificationSlot(bundleOption,
        NotificationConstant::SlotType::LIVE_VIEW);
    NotificationPreferences::GetInstance()->SetBundleRemoveFlag(bundleOption,
        NotificationConstant::SlotType::LIVE_VIEW);
}

ErrCode AdvancedNotificationService::PublishNotificationBySa(const sptr<NotificationRequest> &request)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    auto tokenCaller = IPCSkeleton::GetCallingTokenID();
    bool isSystemApp = AccessTokenHelper::IsSystemApp();
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(tokenCaller);
    bool isThirdparty;
    if (isSystemApp || isSubsystem) {
        isThirdparty = false;
    } else {
        isThirdparty = true;
    }
    bool isAgentController = AccessTokenHelper::VerifyCallerPermission(tokenCaller,
        OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_4, EventBranchId::BRANCH_1);
    int32_t uid = request->GetCreatorUid();
    if (request->GetOwnerUid() != DEFAULT_UID) {
        std::shared_ptr<NotificationBundleOption> agentBundle =
        std::make_shared<NotificationBundleOption>("", uid);
        request->SetAgentBundle(agentBundle);
    }

    if (request->IsAgentNotification()) {
        uid = request->GetOwnerUid();
    }
    if (uid <= 0) {
        message.ErrorCode(ERR_ANS_INVALID_UID).Message("createUid failed" + std::to_string(uid), true);
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return ERR_ANS_INVALID_UID;
    }
    std::string bundle = "";
    ErrCode result = PrePublishNotificationBySa(request, uid, bundle);
    if (request->GetCreatorUid() == RSS_PID && request->IsSystemLiveView() &&
        (std::static_pointer_cast<OHOS::Notification::NotificationLocalLiveViewContent>(
        request->GetContent()->GetNotificationContent())->GetType() != TYPE_CODE_DOWNLOAD)) {
        request->SetSlotType(NotificationConstant::SlotType::OTHER);
        request->GetContent()->ResetToBasicContent();
        request->SetUnremovable(true);
        request->SetTapDismissed(false);
    }
    if (result != ERR_OK) {
        return result;
    }

    // SA not support sound
    if (!request->GetSound().empty()) {
        request->SetSound("");
    }
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->isThirdparty = isThirdparty;
    if (request->IsAgentNotification()) {
        record->bundleOption = new (std::nothrow) NotificationBundleOption("", request->GetCreatorUid());
    } else {
#ifdef ENABLE_ANS_ADDITIONAL_CONTROL
        int32_t ctrlResult = EXTENTION_WRAPPER->LocalControl(request);
        if (ctrlResult != ERR_OK) {
            message.ErrorCode(ctrlResult);
            NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
            return ctrlResult;
        }
#endif
        record->bundleOption = new (std::nothrow) NotificationBundleOption(bundle, uid);
    }
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundle, uid);
    if (record->bundleOption == nullptr || bundleOption == nullptr) {
        ANS_LOGE("Failed to create bundleOption");
        return ERR_ANS_NO_MEMORY;
    }
    record->bundleOption->SetAppInstanceKey(request->GetAppInstanceKey());
    int32_t ipcUid = IPCSkeleton::GetCallingUid();
    uint32_t hashCodeGeneratetype = NotificationPreferences::GetInstance()->GetHashCodeRule(ipcUid);
    request->SetHashCodeGenerateType(hashCodeGeneratetype);
    record->notification = new (std::nothrow) Notification(request);
    if (record->notification == nullptr) {
        ANS_LOGE("Failed to create notification");
        return ERR_ANS_NO_MEMORY;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    SetRequestBySlotType(record->request, bundleOption);
#ifdef ENABLE_ANS_AGGREGATION
    EXTENTION_WRAPPER->GetUnifiedGroupInfo(request);
#endif

    ffrt::task_handle handler = notificationSvrQueue_->submit_h([&]() {
        if (!bundle.empty() && IsDisableNotification(bundle)) {
            ANS_LOGE("bundle in Disable Notification list, bundleName=%{public}s", bundle.c_str());
            result = ERR_ANS_REJECTED_WITH_DISABLE_NOTIFICATION;
            return;
        }
        if (!bundleOption->GetBundleName().empty() &&
            !(request->GetSlotType() == NotificationConstant::SlotType::LIVE_VIEW && request->IsAgentNotification())) {
            ErrCode ret = AssignValidNotificationSlot(record, bundleOption);
            if (ret != ERR_OK) {
                ANS_LOGE("PublishNotificationBySA Can not assign valid slot!");
            }
            if (!request->IsAgentNotification()) {
                result = Filter(record);
                if (result != ERR_OK) {
                    ANS_LOGE("PublishNotificationBySA Reject by filters: %{public}d", result);
                    return;
                }
            }
        }

        CheckDoNotDisturbProfile(record);
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
        result = FlowControlService::GetInstance()->FlowControl(record, ipcUid, isNotificationExists);
        if (result != ERR_OK) {
            return;
        }
        if (AssignToNotificationList(record) != ERR_OK) {
            ANS_LOGE("Failed to assign notification list");
            return;
        }

        ClearSlotTypeData(record->request, ipcUid);
        UpdateRecentNotification(record->notification, false, 0);
        sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
        NotificationSubscriberManager::GetInstance()->NotifyConsumed(record->notification, sortingMap);
    });
    notificationSvrQueue_->wait(handler);
    if (result != ERR_OK) {
        return result;
    }

    if ((record->request->GetAutoDeletedTime() > GetCurrentTime()) && !record->request->IsCommonLiveView()) {
        StartAutoDeletedTimer(record);
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetTargetDeviceStatus(const std::string &deviceType, int32_t &status)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem) {
        ANS_LOGD("isSubsystem is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }
    if (deviceType.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    uint32_t result = DelayedSingleton<DistributedDeviceStatus>::GetInstance()->GetDeviceStatus(deviceType);
    status = static_cast<int32_t>(result);
    ANS_LOGI("Get %{public}s status %{public}u", deviceType.c_str(), status);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetBadgeNumber(int32_t badgeNumber, const std::string &instanceKey)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName = GetClientBundleName();
    ANS_LOGD("SetBadgeNumber receive instanceKey:%{public}s", instanceKey.c_str());
    sptr<BadgeNumberCallbackData> badgeData = new (std::nothrow) BadgeNumberCallbackData(
        bundleName, instanceKey, callingUid, badgeNumber);
    if (badgeData == nullptr) {
        ANS_LOGE("Failed to create BadgeNumberCallbackData.");
        return ERR_ANS_NO_MEMORY;
    }

    ffrt::task_handle handler = notificationSvrQueue_->submit_h([&]() {
        ANS_LOGD("ffrt enter!");
        NotificationSubscriberManager::GetInstance()->SetBadgeNumber(badgeData);
    });
    notificationSvrQueue_->wait(handler);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetBadgeNumberForDhByBundle(
    const sptr<NotificationBundleOption> &bundleOption, int32_t badgeNumber)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("SetBadgeNumberForDhByBundle bundleOption is null");
    }
    if (bundleOption->GetBundleName().empty()) {
        ANS_LOGE("SetBadgeNumberForDhByBundle Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }
    if (bundleOption->GetUid() <= DEFAULT_UID) {
        ANS_LOGE("SetBadgeNumberForDhByBundle invalid uid");
        return ERR_ANS_INVALID_PARAM;
    }
    if (badgeNumber < BADGE_NUM_LIMIT) {
        ANS_LOGE("SetBadgeNumberForDhByBundle invalid badgeNumber");
        return ERR_ANS_INVALID_PARAM;
    }
    ANS_LOGI("SetBadgeNumberForDhByBundle bundleName = %{public}s uid = %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid());
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_7, EventBranchId::BRANCH_6);
    message.Message(bundleOption->GetBundleName() + "_" +std::to_string(bundleOption->GetUid()) +
        " badgeNumber: " + std::to_string(badgeNumber));
    if (notificationSvrQueue_ == nullptr) {
        return ERR_ANS_INVALID_PARAM;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).Append(" Not system app.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("Not system app.");
        return ERR_ANS_NON_SYSTEM_APP;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<BadgeNumberCallbackData> badgeData = new (std::nothrow) BadgeNumberCallbackData(
            bundleOption->GetBundleName(), bundleOption->GetUid(), badgeNumber);
        if (badgeData == nullptr) {
            ANS_LOGE("Failed to create badge number callback data.");
            result = ERR_ANS_NO_MEMORY;
        }
        NotificationSubscriberManager::GetInstance()->SetBadgeNumber(badgeData);
    });
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::SetBadgeNumberByBundle(
    const sptr<NotificationBundleOption> &bundleOption, int32_t badgeNumber)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_7, EventBranchId::BRANCH_6);
    message.Message(bundleOption->GetBundleName() + "_" +std::to_string(bundleOption->GetUid()) +
        " badgeNumber: " + std::to_string(badgeNumber));
    if (notificationSvrQueue_ == nullptr) {
        return ERR_ANS_INVALID_PARAM;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).Append(" Not system app.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("Not system app.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    sptr<NotificationBundleOption> bundle = bundleOption;
    ErrCode result = CheckBundleOptionValid(bundle);
    if (result != ERR_OK) {
        ANS_LOGE("Bundle is invalid.");
        return result;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER)) {
        std::string bundleName = GetClientBundleName();
        if (bundleName.empty()) {
            ANS_LOGE("Failed to get client bundle name.");
            return result;
        }
        bool isAgent = false;
        isAgent = IsAgentRelationship(bundleName, bundle->GetBundleName());
        if (!isAgent) {
            message.ErrorCode(ERR_ANS_NO_AGENT_SETTING).Append(" No agent setting.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            ANS_LOGE("No agent setting.");
            return ERR_ANS_NO_AGENT_SETTING;
        }
    }

    ffrt::task_handle handler = notificationSvrQueue_->submit_h([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<BadgeNumberCallbackData> badgeData = new (std::nothrow) BadgeNumberCallbackData(
            bundle->GetBundleName(), bundle->GetUid(), badgeNumber);
        if (badgeData == nullptr) {
            ANS_LOGE("Failed to create badge number callback data.");
            result = ERR_ANS_NO_MEMORY;
        }
        NotificationSubscriberManager::GetInstance()->SetBadgeNumber(badgeData);
    });
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::SubscribeLocalLiveView(
    const sptr<IAnsSubscriberLocalLiveView> &subscriber, const bool isNative)
{
    return SubscribeLocalLiveView(subscriber, nullptr, isNative);
}

ErrCode AdvancedNotificationService::SubscribeLocalLiveView(
    const sptr<IAnsSubscriberLocalLiveView> &subscriber,
    const sptr<NotificationSubscribeInfo> &info, const bool isNative)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s, isNative: %{public}d", __FUNCTION__, isNative);

    ErrCode errCode = ERR_OK;
    do {
        if (!isNative) {
            bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
            if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
                ANS_LOGE("Client is not a system app or subsystem.");
                errCode = ERR_ANS_NON_SYSTEM_APP;
                break;
            }
        }

        if (subscriber == nullptr) {
            errCode = ERR_ANS_INVALID_PARAM;
            break;
        }

        errCode = NotificationLocalLiveViewSubscriberManager::GetInstance()->AddLocalLiveViewSubscriber(
            subscriber, info);
        if (errCode != ERR_OK) {
            break;
        }
    } while (0);
    if (errCode == ERR_OK) {
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
            LivePublishProcess::GetInstance()->AddLiveViewSubscriber(callingUid);
        }));
        notificationSvrQueue_->wait(handler);
    }
    SendSubscribeHiSysEvent(IPCSkeleton::GetCallingPid(), IPCSkeleton::GetCallingUid(), info, errCode);
    return errCode;
}

ErrCode AdvancedNotificationService::SetDistributedEnabledByBundle(const sptr<NotificationBundleOption> &bundleOption,
    const std::string &deviceType, const bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr) {
        ANS_LOGE("BundleOption is null.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_9, EventBranchId::BRANCH_3);
    message.Message(bundleOption->GetBundleName() + "_" + std::to_string(bundleOption->GetUid()) +
        " enabled:" + std::to_string(enabled) +
        " deviceType:" + deviceType);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("IsSystemApp is false.");
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).Append("Not SystemApp");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission Denied.");
        message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Append("No permission");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("bundle is nullptr");
        return ERR_ANS_INVALID_BUNDLE;
    }
    ErrCode result = NotificationPreferences::GetInstance()->SetDistributedEnabledByBundle(bundle,
        deviceType, enabled);

    ANS_LOGI("%{public}s_%{public}d, deviceType: %{public}s, enabled: %{public}s, "
        "SetDistributedEnabledByBundle result: %{public}d", bundleOption->GetBundleName().c_str(),
        bundleOption->GetUid(), deviceType.c_str(), std::to_string(enabled).c_str(), result);
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);

    return result;
}

ErrCode AdvancedNotificationService::IsDistributedEnabledByBundle(const sptr<NotificationBundleOption> &bundleOption,
    const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("IsSystemApp is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("no permission");
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    return NotificationPreferences::GetInstance()->IsDistributedEnabledByBundle(bundle, deviceType, enabled);
}

ErrCode AdvancedNotificationService::SetDistributedEnabledBySlot(
    int32_t slotTypeInt, const std::string &deviceType, bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(slotTypeInt);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_8, EventBranchId::BRANCH_7);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("IsSystemApp is false.");
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).Append("Not SystemApp");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission Denied.");
        message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Append("No permission");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_PERMISSION_DENIED;
    }

    ErrCode result = NotificationPreferences::GetInstance()->SetDistributedEnabledBySlot(slotType,
        deviceType, enabled);

    ANS_LOGI("SetDistributedEnabledBySlot %{public}d, deviceType: %{public}s, enabled: %{public}s, "
        "SetDistributedEnabledBySlot result: %{public}d",
        slotType, deviceType.c_str(), std::to_string(enabled).c_str(), result);
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);

    return result;
}

ErrCode AdvancedNotificationService::IsDistributedEnabledBySlot(
    int32_t slotTypeInt, const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(slotTypeInt);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("IsSystemApp is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("no permission");
        return ERR_ANS_PERMISSION_DENIED;
    }

    return NotificationPreferences::GetInstance()->IsDistributedEnabledBySlot(slotType, deviceType, enabled);
}

ErrCode AdvancedNotificationService::DuplicateMsgControl(const sptr<NotificationRequest> &request)
{
    if (request->IsCommonLiveView() || request->GetAppMessageId().empty()) {
        return ERR_OK;
    }

    RemoveExpiredUniqueKey();
    std::string uniqueKey = request->GenerateUniqueKey();
    if (IsDuplicateMsg(uniqueKey)) {
        ANS_LOGI("Duplicate msg, no need to notify, key is %{public}s, appmessageId is %{public}s",
            request->GetKey().c_str(), request->GetAppMessageId().c_str());
        return ERR_ANS_DUPLICATE_MSG;
    }

    uniqueKeyList_.emplace_back(std::make_pair(std::chrono::system_clock::now(), uniqueKey));
    return ERR_OK;
}

void AdvancedNotificationService::DeleteDuplicateMsgs(const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is nullptr");
        return;
    }
    const char *keySpliter = "_";
    std::stringstream stream;
    stream << bundleOption->GetUid() << keySpliter << bundleOption->GetBundleName() << keySpliter;
    std::string uniqueKeyHead = stream.str();
    auto iter = uniqueKeyList_.begin();
    for (auto iter = uniqueKeyList_.begin(); iter != uniqueKeyList_.end();) {
        if ((*iter).second.find(uniqueKeyHead) == 0) {
            iter = uniqueKeyList_.erase(iter);
        } else {
            ++iter;
        }
    }
}

void AdvancedNotificationService::RemoveExpiredUniqueKey()
{
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    auto iter = uniqueKeyList_.begin();
    while (iter != uniqueKeyList_.end()) {
        uint32_t duration = std::chrono::duration_cast<std::chrono::seconds>(abs(now - (*iter).first)).count();
        ANS_LOGD("RemoveExpiredUniqueKey duration is %{public}u", duration);
        if (duration > SECONDS_IN_ONE_DAY) {
            ANS_LOGD("RemoveExpiredUniqueKey end duration is %{public}u", duration);
            iter = uniqueKeyList_.erase(iter);
        } else {
            break;
        }
    }
}

bool AdvancedNotificationService::IsDuplicateMsg(const std::string &uniqueKey)
{
    for (auto record : uniqueKeyList_) {
        if (strcmp(record.second.c_str(), uniqueKey.c_str()) == 0) {
            return true;
        }
    }

    return false;
}

ErrCode AdvancedNotificationService::PublishRemoveDuplicateEvent(const std::shared_ptr<NotificationRecord> &record)
{
    if (record == nullptr) {
        return ERR_ANS_INVALID_PARAM;
    }

    if (!record->request->IsAgentNotification()) {
        ANS_LOGD("Only push agent need remove duplicate event");
        return ERR_OK;
    }

    std::string extraStr;
    if (record->request->GetUnifiedGroupInfo() != nullptr) {
        auto extraInfo = record->request->GetUnifiedGroupInfo()->GetExtraInfo();
        if (extraInfo != nullptr) {
            AAFwk::WantParamWrapper wWrapper(*extraInfo);
            extraStr = wWrapper.ToString();
        }
    }

    NotificationNapi::SlotType slotType;
    NotificationNapi::ContentType contentType;
    NotificationNapi::AnsEnumUtil::ContentTypeCToJS(
        static_cast<NotificationContent::Type>(record->request->GetNotificationType()), contentType);
    NotificationNapi::AnsEnumUtil::SlotTypeCToJS(
        static_cast<NotificationConstant::SlotType>(record->request->GetSlotType()), slotType);

    EventFwk::Want want;
    want.SetParam("bundleName", record->bundleOption->GetBundleName());
    want.SetParam("uid", record->request->GetOwnerUid());
    want.SetParam("id", record->request->GetNotificationId());
    want.SetParam("slotType", static_cast<int32_t>(slotType));
    want.SetParam("contentType", static_cast<int32_t>(contentType));
    want.SetParam("appMessageId", record->request->GetAppMessageId());
    want.SetParam("extraInfo", extraStr);
    want.SetAction(NOTIFICATION_EVENT_PUSH_AGENT);
    EventFwk::CommonEventData commonData {want, 1, ""};
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberPermissions({OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER});
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonData, publishInfo)) {
        ANS_LOGE("PublishCommonEvent failed");
        return ERR_ANS_TASK_ERR;
    }

    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetSmartReminderEnabled(const std::string &deviceType, const bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_8, EventBranchId::BRANCH_6);
    message.Message(" enabled:" + std::to_string(enabled) + " deviceType:" + deviceType);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("IsSystemApp is false.");
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).Append(" Not SystemApp");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission Denied.");
        message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Append(" Permission Denied");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_PERMISSION_DENIED;
    }
    ErrCode result = NotificationPreferences::GetInstance()->SetSmartReminderEnabled(deviceType, enabled);

    ANS_LOGI("enabled: %{public}s, deviceType: %{public}s,Set smart reminder enabled: %{public}d",
        std::to_string(enabled).c_str(), deviceType.c_str(), result);
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    return result;
}

ErrCode AdvancedNotificationService::IsSmartReminderEnabled(const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("IsSystemApp is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("no permission");
        return ERR_ANS_PERMISSION_DENIED;
    }

    return NotificationPreferences::GetInstance()->IsSmartReminderEnabled(deviceType, enabled);
}

ErrCode AdvancedNotificationService::SetTargetDeviceStatus(const std::string &deviceType, uint32_t status,
    const std::string &deveiceId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    uint32_t status_ = status;
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem) {
        ANS_LOGD("isSubsystem is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }
    if (deviceType.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    DelayedSingleton<DistributedDeviceStatus>::GetInstance()->SetDeviceStatus(deviceType, status_,
        DistributedDeviceStatus::DISTURB_DEFAULT_FLAG);
    ANS_LOGI("update %{public}s status %{public}u", deviceType.c_str(), status);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetTargetDeviceStatus(const std::string &deviceType, uint32_t status,
    uint32_t controlFlag, const std::string &deveiceId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (deviceType.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem) {
        ANS_LOGD("isSubsystem is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("no permission");
        return ERR_ANS_PERMISSION_DENIED;
    }

    DelayedSingleton<DistributedDeviceStatus>::GetInstance()->SetDeviceStatus(deviceType, status, controlFlag);
    ANS_LOGI("update %{public}s status %{public}u %{public}u", deviceType.c_str(), status, controlFlag);
    return ERR_OK;
}

void AdvancedNotificationService::ClearAllNotificationGroupInfo(std::string localSwitch)
{
    ANS_LOGD("ClearNotification enter.");
    bool status = (localSwitch == "true");
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("ClearNotification Serial queue is invalid.");
        return;
    }

    ffrt::task_handle handler = notificationSvrQueue_->submit_h([=]() {
        if (aggregateLocalSwitch_ && !status) {
            for (const auto& item : notificationList_) {
                item->notification->GetNotificationRequestPoint()->SetUnifiedGroupInfo(nullptr);
            }
        }
        aggregateLocalSwitch_ = status;
    });
}

bool AdvancedNotificationService::IsDisableNotification(const std::string &bundleName)
{
    NotificationDisable notificationDisable;
    if (NotificationPreferences::GetInstance()->GetDisableNotificationInfo(notificationDisable)) {
        if (notificationDisable.GetDisabled()) {
            ANS_LOGD("get disabled is open");
            std::vector<std::string> bundleList = notificationDisable.GetBundleList();
            auto it = std::find(bundleList.begin(), bundleList.end(), bundleName);
            if (it != bundleList.end()) {
                return true;
            }
        }
    } else {
        ANS_LOGD("no disabled has been set up or set disabled to close");
    }
    return false;
}

bool AdvancedNotificationService::IsNeedToControllerByDisableNotification(const sptr<NotificationRequest> &request)
{
    if (request == nullptr) {
        ANS_LOGE("request is nullptr");
        return false;
    }
    if (request->IsAgentNotification()) {
        return true;
    }
    std::string bundleName = "";
    auto agentBundle = request->GetAgentBundle();
    if (agentBundle != nullptr) {
        bundleName = agentBundle->GetBundleName();
    }
    if (!(request->GetOwnerBundleName().empty()) && !bundleName.empty() &&
        NotificationPreferences::GetInstance()->IsAgentRelationship(bundleName, request->GetOwnerBundleName()) &&
        AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER)) {
        return false;
    }
    return true;
}

void AdvancedNotificationService::SetAndPublishSubscriberExistFlag(const std::string& deviceType, bool existFlag)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (deviceType.empty()) {
        ANS_LOGE("deviceType is empty");
        return;
    }

    auto result = NotificationPreferences::GetInstance()->SetSubscriberExistFlag(deviceType, existFlag);
    if (result != ERR_OK) {
        ANS_LOGE("SetSubscriberExistFlag failed");
        return;
    }

    bool headsetExistFlag = false;
    bool wearableExistFlag = false;
    if (deviceType == DEVICE_TYPE_HEADSET) {
        headsetExistFlag = existFlag;
        result =
            NotificationPreferences::GetInstance()->GetSubscriberExistFlag(DEVICE_TYPE_WEARABLE, wearableExistFlag);
        if (result != ERR_OK) {
            ANS_LOGE("GetSubscriberExistFlag failed");
            return;
        }
    } else if (deviceType == DEVICE_TYPE_WEARABLE) {
        wearableExistFlag = existFlag;
        result = NotificationPreferences::GetInstance()->GetSubscriberExistFlag(DEVICE_TYPE_HEADSET, headsetExistFlag);
        if (result != ERR_OK) {
            ANS_LOGE("GetSubscriberExistFlag failed");
            return;
        }
    }
    PublishSubscriberExistFlagEvent(headsetExistFlag, wearableExistFlag);
}

void AdvancedNotificationService::PublishSubscriberExistFlagEvent(bool headsetExistFlag, bool wearableExistFlag)
{
    ANS_LOGD("%{public}s, headsetExistFlag = %{public}d, wearableExistFlag = %{public}d", __FUNCTION__,
        headsetExistFlag, wearableExistFlag);
    EventFwk::Want want;
    want.SetParam("SUBSCRIBER_EXISTED_HEADSET", headsetExistFlag);
    want.SetParam("SUBSCRIBER_EXISTED_WEARABLE", wearableExistFlag);
    want.SetAction(NOTIFICATION_EVENT_SUBSCRIBER_STATUS);
    EventFwk::CommonEventData commonData { want, 0, "" };
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSticky(true);
    publishInfo.SetSubscriberType(EventFwk::SubscriberType::SYSTEM_SUBSCRIBER_TYPE);
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGD("GetCurrentActiveUserId failed");
        return;
    }
    if (!EventFwk::CommonEventManager::PublishCommonEventAsUser(commonData, publishInfo, userId)) {
        ANS_LOGE("PublishCommonEventAsUser failed");
    }
}

ErrCode AdvancedNotificationService::RemoveAllNotificationsByBundleName(const std::string &bundleName, int32_t reason)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (bundleName.empty()) {
        std::string message = "bundle name is empty.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(8, 1).ErrorCode(ERR_ANS_INVALID_BUNDLE);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        std::string message = "Serial queue is nullptr.";
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        std::vector<std::shared_ptr<NotificationRecord>> removeList;
        ANS_LOGD("ffrt enter!");
        for (auto record : notificationList_) {
            if (record == nullptr) {
                ANS_LOGE("record is nullptr");
                continue;
            }
            if ((record->bundleOption->GetBundleName() == bundleName)
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                && record->deviceId.empty()
#endif
            ) {
                ProcForDeleteLiveView(record);
                removeList.push_back(record);
            }
        }

        std::vector<sptr<Notification>> notifications;
        std::vector<uint64_t> timerIds;
        for (auto record : removeList) {
            if (record == nullptr) {
                ANS_LOGE("record is nullptr");
                continue;
            }
            notificationList_.remove(record);
            if (record->notification != nullptr) {
                ANS_LOGD("record->notification is not nullptr.");
                UpdateRecentNotification(record->notification, true, reason);
                notifications.emplace_back(record->notification);
                timerIds.emplace_back(record->notification->GetAutoDeletedTimer());
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(record->deviceId, record->bundleName, record->notification);
#endif
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                SendNotificationsOnCanceled(notifications, nullptr, reason);
            }

            TriggerRemoveWantAgent(record->request, reason, record->isThirdparty);
        }

        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(notifications, nullptr, reason);
        }
        BatchCancelTimer(timerIds);
    }));
    notificationSvrQueue_->wait(handler);

    return ERR_OK;
}

ErrCode DistributeOperationParamCheck(const sptr<NotificationOperationInfo>& operationInfo,
    const sptr<IAnsOperationCallback> &callback)
{
    if (operationInfo == nullptr || operationInfo->GetHashCode().empty()) {
        ANS_LOGE("hashCode is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    OperationType operationType = operationInfo->GetOperationType();
    if (operationType != OperationType::DISTRIBUTE_OPERATION_JUMP &&
        operationType != OperationType::DISTRIBUTE_OPERATION_REPLY) {
        ANS_LOGE("operation type is error.");
        return ERR_ANS_INVALID_PARAM;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("is not system app.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("not have permission.");
        return ERR_ANS_PERMISSION_DENIED;
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::DistributeOperation(const sptr<NotificationOperationInfo>& operationInfo,
    const sptr<IAnsOperationCallback> &callback)
{
    ErrCode result = DistributeOperationParamCheck(operationInfo, callback);
    if (result != ERR_OK) {
        return result;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidated");
        return ERR_ANS_INVALID_PARAM;
    }

    OperationType operationType = operationInfo->GetOperationType();
    if (operationType == OperationType::DISTRIBUTE_OPERATION_REPLY) {
        operationInfo->SetEventId(std::to_string(GetCurrentTime()));
        std::string key = operationInfo->GetHashCode() + operationInfo->GetEventId();
        DistributedOperationService::GetInstance().AddOperation(key, callback);
    }
    ANS_LOGI("DistributeOperation trigger hashcode %{public}s.", operationInfo->GetHashCode().c_str());
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        std::string hashCode = operationInfo->GetHashCode();
        for (auto record : notificationList_) {
            if (record->notification->GetKey() != hashCode) {
                continue;
            }
            if (record->notification->GetNotificationRequestPoint() == nullptr) {
                continue;
            }
            auto request = record->notification->GetNotificationRequestPoint();
            if (!request->GetDistributedCollaborate()) {
                ANS_LOGI("Not collaborate hashcode %{public}s.", hashCode.c_str());
                continue;
            }
            result = NotificationSubscriberManager::GetInstance()->DistributeOperation(operationInfo);
            return;
        }
        ANS_LOGI("DistributeOperation not exist hashcode.");
        result = ERR_ANS_INVALID_PARAM;
    }));
    notificationSvrQueue_->wait(handler);
    if (result != ERR_OK && operationType == OperationType::DISTRIBUTE_OPERATION_REPLY) {
        std::string key = operationInfo->GetHashCode() + operationInfo->GetEventId();
        DistributedOperationService::GetInstance().RemoveOperationResponse(key);
    }
    return result;
}

ErrCode AdvancedNotificationService::SetHashCodeRule(const uint32_t type)
{
    ANS_LOGI("%{public}s", __FUNCTION__);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_8, EventBranchId::BRANCH_8);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("IsSystemApp is false.");
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).Append("Not SystemApp");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_NON_SYSTEM_APP;
    }

    int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid != AVSEESAION_PID) {
        ANS_LOGE("Permission Denied.");
        message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Append("No permission");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_PERMISSION_DENIED;
    }
    ErrCode result = NotificationPreferences::GetInstance()->SetHashCodeRule(uid, type);
    ANS_LOGI("SetHashCodeRule uid = %{public}d type =  %{public}d, result  %{public}d", uid, type, result);
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);

    return result;
}
}  // namespace Notification
}  // namespace OHOS
