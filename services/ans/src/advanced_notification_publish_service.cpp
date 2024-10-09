/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "distributed_screen_status_manager.h"
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
#include "system_ability_definition.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "datashare_predicates.h"

namespace OHOS {
namespace Notification {

constexpr char FOUNDATION_BUNDLE_NAME[] = "ohos.global.systemres";
constexpr uint32_t SECONDS_IN_ONE_DAY = 24 * 60 * 60;
const static std::string NOTIFICATION_EVENT_PUSH_AGENT = "notification.event.PUSH_AGENT";
constexpr int32_t RSS_PID = 3051;
constexpr int32_t ANS_UID = 5523;
constexpr int32_t BROKER_UID = 5557;
constexpr int32_t TYPE_CODE_DOWNLOAD = 8;
constexpr const char *FOCUS_MODE_REPEAT_CALLERS_ENABLE = "1";
constexpr const char *CONTACT_DATA = "datashare:///com.ohos.contactsdataability/contacts/contact_data?Proxy=true";
constexpr int32_t OPERATION_TYPE_COMMON_EVENT = 4;

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

    ErrCode result = ERR_OK;
    result = NotificationPreferences::GetInstance()->SetNotificationsEnabledForBundle(bundle, enabled);
    if (result == ERR_OK) {
        NotificationSubscriberManager::GetInstance()->NotifyEnabledNotificationChanged(bundleData);
        PublishSlotChangeCommonEvent(bundle);
    }

    SendEnableNotificationHiSysEvent(bundleOption, enabled, result);
    return result;
}

ErrCode AdvancedNotificationService::Publish(const std::string &label, const sptr<NotificationRequest> &request)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!request) {
        ANSR_LOGE("ReminderRequest object is nullptr");
        return ERR_ANS_INVALID_PARAM;
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
            break;
        }

        result = CheckSoundPermission(request, bundleOption->GetBundleName());
        if (result != ERR_OK) {
            message.ErrorCode(result).Message("Check sound failed.");
            break;
        }

        if (IsNeedPushCheck(request)) {
            result = PushCheck(request);
        }
        if (result != ERR_OK) {
            message.ErrorCode(result).Message("Push check failed.");
            break;
        }
        result = PublishPreparedNotification(request, bundleOption, isUpdateByOwnerAllowed);
        if (result != ERR_OK) {
            message.ErrorCode(result).Message("Publish prepared failed.");
            break;
        }
    } while (0);

    SendPublishHiSysEvent(request, result);
    return result;
}

ErrCode AdvancedNotificationService::PublishNotificationForIndirectProxy(const sptr<NotificationRequest> &request)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!request) {
        ANSR_LOGE("ReminderRequest object is nullptr");
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
    record->bundleOption = new (std::nothrow) NotificationBundleOption(bundle, uid);
    record->bundleOption->SetInstanceKey(request->GetCreatorInstanceKey());
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundle, uid);
    if (record->bundleOption == nullptr || bundleOption == nullptr) {
        ANS_LOGE("Failed to create bundleOption");
        return ERR_ANS_NO_MEMORY;
    }
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

    auto ipcUid = IPCSkeleton::GetCallingUid();
    ffrt::task_handle handler = notificationSvrQueue_->submit_h([&]() {
        if (AssignValidNotificationSlot(record, bundleOption) != ERR_OK) {
            ANS_LOGE("Can not assign valid slot!");
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

        if (AssignToNotificationList(record) != ERR_OK) {
            ANS_LOGE("Failed to assign notification list");
            return;
        }

        sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
        NotificationSubscriberManager::GetInstance()->NotifyConsumed(record->notification, sortingMap);
    });
    notificationSvrQueue_->wait(handler);
    if (result != ERR_OK) {
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

ErrCode AdvancedNotificationService::Cancel(int32_t notificationId, const std::string &label, int32_t instanceKey)
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
    bundleOption->SetInstanceKey(instanceKey);
    return CancelPreparedNotification(notificationId, label, bundleOption,
        NotificationConstant::APP_CANCEL_REASON_DELETE);
}

ErrCode AdvancedNotificationService::CancelAll(int32_t instanceKey)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    const int reason = NotificationConstant::APP_CANCEL_ALL_REASON_DELETE;
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    bundleOption->SetInstanceKey(instanceKey);

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

        std::vector<std::string> keys = GetNotificationKeys(bundleOption);
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
    const sptr<NotificationRequest> notification, const std::string &representativeBundle)
{
    return ERR_INVALID_OPERATION;
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
    const sptr<NotificationBundleOption> &bundleOption, bool &enabled)
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
    const sptr<AnsDialogCallback> &callback,
    const sptr<IRemoteObject> &callerToken)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (callback == nullptr) {
        ANS_LOGE("callback == nullptr");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is nullptr.");
        return ERR_ANS_INVALID_BUNDLE;
    }
    // To get the permission
    bool allowedNotify = false;
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_8, EventBranchId::BRANCH_5);
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

    result = dialogManager_->RequestEnableNotificationDailog(bundleOption, callback, callerToken);
    if (result == ERR_OK) {
        result = ERR_ANS_DIALOG_POP_SUCCEEDED;
    }

    ANS_LOGI("%{public}s_%{public}d, deviceId: %{public}s, Request enable notification dailog result: %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), deviceId.c_str(), result);
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
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
    const sptr<AnsDialogCallback> &callback, bool &canPop, std::string &bundleName)
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
    ANS_LOGI("allowedNotify = %{public}d", allowedNotify);
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
            SetSlotFlagsTrustlistsAsBundle(bundleOption);
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
    if ((callingUid != ANS_UID && callingUid != BROKER_UID)
        && !AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
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

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != BROKER_UID && !AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
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
            TriggerRemoveWantAgent(notificationRequest);
        }
    }));
    notificationSvrQueue_->wait(handler);
    if (result != ERR_OK) {
        std::string message = "remove notificaiton error";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(4, 7)
            .ErrorCode(result).NotificationId(notificationId);
        ReportDeleteFailedEventPush(haMetaMessage, removeReason, message);
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

            TriggerRemoveWantAgent(record->request);
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
    sptr<Notification> notification = nullptr;
    sptr<NotificationRequest> notificationRequest = nullptr;

    for (std::list<std::shared_ptr<NotificationRecord>>::iterator it = notificationList_.begin();
        it != notificationList_.end();) {
        if (((*it)->bundleOption->GetBundleName() == bundle->GetBundleName()) &&
            ((*it)->bundleOption->GetUid() == bundle->GetUid()) &&
            ((*it)->request->GetSlotType() == slot->GetType())) {
            if (((*it)->request->GetAgentBundle() != nullptr && (*it)->request->IsSystemLiveView())) {
                ANS_LOGI("Agent systemliveview no need remove.");
                it++;
                continue;
            }
            notification = (*it)->notification;
            notificationRequest = (*it)->request;

            ProcForDeleteLiveView(*it);
            it = notificationList_.erase(it);

            if (notification != nullptr) {
                UpdateRecentNotification(notification, true, NotificationConstant::DISABLE_SLOT_REASON_DELETE);
                CancelTimer(notification->GetAutoDeletedTimer());
                NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, nullptr,
                    NotificationConstant::DISABLE_SLOT_REASON_DELETE);
            }

            TriggerRemoveWantAgent(notificationRequest);
            result = ERR_OK;
        } else {
            it++;
        }
    }
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
            Uri uri(CONTACT_DATA);
            isNeedSilent = datashareHelper->QueryContact(uri, phoneNumber, policy);
            break;
    }
    ANS_LOGI("IsNeedSilentInDoNotDisturbMode: %{public}d", isNeedSilent);
    return isNeedSilent;
}

ErrCode AdvancedNotificationService::CancelGroup(const std::string &groupName, int32_t instanceKey)
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
    bundleOption->SetInstanceKey(instanceKey);

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
            if ((record->bundleOption->GetBundleName() == bundleOption->GetBundleName()) &&
                (record->bundleOption->GetUid() == bundleOption->GetUid()) &&
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

ErrCode AdvancedNotificationService::IsSpecialUserAllowedNotify(const int32_t &userId, bool &allowed)
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

ErrCode AdvancedNotificationService::SetNotificationsEnabledByUser(const int32_t &userId, bool enabled)
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

ErrCode AdvancedNotificationService::SetEnabledForBundleSlot(const sptr<NotificationBundleOption> &bundleOption,
    const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("slotType: %{public}d, enabled: %{public}d, isForceControl: %{public}d",
        slotType, enabled, isForceControl);

    ErrCode result = CheckCommonParams();
    if (result != ERR_OK) {
        return result;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_5, EventBranchId::BRANCH_4);
    message.Message(bundleOption->GetBundleName() + "_" +std::to_string(bundleOption->GetUid()) +
        " slotType: " + std::to_string(static_cast<uint32_t>(slotType)) +
        " enabled: " +std::to_string(enabled) + "isForceControl" + std::to_string(isForceControl));
    result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        sptr<NotificationSlot> slot;
        result = NotificationPreferences::GetInstance()->GetNotificationSlot(bundle, slotType, slot);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST ||
            result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            slot = new (std::nothrow) NotificationSlot(slotType);
            if (slot == nullptr) {
                ANS_LOGE("Failed to create NotificationSlot ptr.");
                result = ERR_ANS_NO_MEMORY;
                return;
            }
            GenerateSlotReminderMode(slot, bundleOption);
        } else if ((result == ERR_OK) && (slot != nullptr)) {
            if (slot->GetEnable() == enabled && slot->GetForceControl() == isForceControl) {
                // 设置authorizedStatus为已授权
                slot->SetAuthorizedStatus(NotificationSlot::AuthorizedStatus::AUTHORIZED);
                std::vector<sptr<NotificationSlot>> slots;
                slots.push_back(slot);
                result = NotificationPreferences::GetInstance()->AddNotificationSlots(bundle, slots);
                return;
            }
            NotificationPreferences::GetInstance()->RemoveNotificationSlot(bundle, slotType);
        } else {
            ANS_LOGE("Set enable slot: GetNotificationSlot failed");
            return;
        }
        bool allowed = false;
        result = NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, allowed);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            allowed = CheckApiCompatibility(bundle);
            SetDefaultNotificationEnabled(bundle, allowed);
        }

        slot->SetEnable(enabled);
        slot->SetForceControl(isForceControl);
        // 设置authorizedStatus为已授权
        slot->SetAuthorizedStatus(NotificationSlot::AuthorizedStatus::AUTHORIZED);
        std::vector<sptr<NotificationSlot>> slots;
        slots.push_back(slot);
        result = NotificationPreferences::GetInstance()->AddNotificationSlots(bundle, slots);
        if (result != ERR_OK) {
            ANS_LOGE("Set enable slot: AddNotificationSlot failed");
            return;
        }

        if (!slot->GetEnable()) {
            RemoveNotificationBySlot(bundle, slot, NotificationConstant::DISABLE_SLOT_REASON_DELETE);
        } else {
            if (!slot->GetForceControl() && !allowed) {
                RemoveNotificationBySlot(bundle, slot, NotificationConstant::DISABLE_NOTIFICATION_REASON_DELETE);
            }
        }

        PublishSlotChangeCommonEvent(bundle);
    }));
    notificationSvrQueue_->wait(handler);

    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    ANS_LOGI("%{public}s_%{public}d, SetEnabledForBundleSlot successful.",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid());
    SendEnableNotificationSlotHiSysEvent(bundleOption, slotType, enabled, result);
    return result;
}

ErrCode AdvancedNotificationService::GetEnabledForBundleSlot(
    const sptr<NotificationBundleOption> &bundleOption, const NotificationConstant::SlotType &slotType, bool &enabled)
{
    ANS_LOGD("slotType: %{public}d", slotType);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("VerifyNativeToken and isSystemApp failed.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<NotificationSlot> slot;
        result = NotificationPreferences::GetInstance()->GetNotificationSlot(bundle, slotType, slot);
        if (result != ERR_OK) {
            ANS_LOGE("Get enable slot: GetNotificationSlot failed");
            return;
        }
        if (slot == nullptr) {
            ANS_LOGW("Get enable slot: object is null, enabled default true");
            enabled = true;
            result = ERR_OK;
            return;
        }
        enabled = slot->GetEnable();
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

ErrCode AdvancedNotificationService::PublishNotificationBySa(const sptr<NotificationRequest> &request)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isAgentController = AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER);
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
    record->isThirdparty = false;
    if (request->IsAgentNotification()) {
        record->bundleOption = new (std::nothrow) NotificationBundleOption("", request->GetCreatorUid());
    } else {
        record->bundleOption = new (std::nothrow) NotificationBundleOption(bundle, uid);
    }
    record->bundleOption->SetInstanceKey(request->GetCreatorInstanceKey());
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundle, uid);
    if (record->bundleOption == nullptr || bundleOption == nullptr) {
        ANS_LOGE("Failed to create bundleOption");
        return ERR_ANS_NO_MEMORY;
    }
    record->notification = new (std::nothrow) Notification(request);
    if (record->notification == nullptr) {
        ANS_LOGE("Failed to create notification");
        return ERR_ANS_NO_MEMORY;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    result = FlowControl(record);
    if (result != ERR_OK) {
        return result;
    }
    SetRequestBySlotType(record->request, bundleOption);
#ifdef ENABLE_ANS_EXT_WRAPPER
    EXTENTION_WRAPPER->GetUnifiedGroupInfo(request);
#endif

    auto ipcUid = IPCSkeleton::GetCallingUid();
    ffrt::task_handle handler = notificationSvrQueue_->submit_h([&]() {
        if (!bundleOption->GetBundleName().empty()) {
            ErrCode ret = AssignValidNotificationSlot(record, bundleOption);
            if (ret != ERR_OK) {
                ANS_LOGE("Can not assign valid slot!");
            }
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

        if (AssignToNotificationList(record) != ERR_OK) {
            ANS_LOGE("Failed to assign notification list");
            return;
        }

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

ErrCode AdvancedNotificationService::SetBadgeNumber(int32_t badgeNumber, int32_t instanceKey)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName = GetClientBundleName();
    sptr<BadgeNumberCallbackData> badgeData = new (std::nothrow) BadgeNumberCallbackData(
        bundleName, callingUid, badgeNumber, instanceKey);
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
        message.ErrorCode(result).Append(" Bundle is invalid.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
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
    const sptr<AnsSubscriberLocalLiveViewInterface> &subscriber,
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

    uniqueKeyList_.emplace_back(std::make_pair(std::chrono::steady_clock::now(), uniqueKey));
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
    std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
    auto iter = uniqueKeyList_.begin();
    while (iter != uniqueKeyList_.end()) {
        if (std::chrono::duration_cast<std::chrono::seconds>(now - (*iter).first).count() > SECONDS_IN_ONE_DAY) {
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

ErrCode AdvancedNotificationService::SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status)
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

    int ret = DelayedSingleton<DistributedDeviceStatus>::GetInstance()->SetDeviceStatus(deviceType, status_);
    ANS_LOGI("%{public}s device status update with %{public}u",
        deviceType.c_str(), DelayedSingleton<DistributedDeviceStatus>::GetInstance()->GetDeviceStatus(deviceType));
    return ret;
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
}  // namespace Notification
}  // namespace OHOS
