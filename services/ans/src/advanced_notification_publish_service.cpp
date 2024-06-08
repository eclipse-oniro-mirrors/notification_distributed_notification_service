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
#include "want_params_wrapper.h"
#include "ans_convert_enum.h"

#include "advanced_notification_inline.cpp"

namespace OHOS {
namespace Notification {

constexpr char FOUNDATION_BUNDLE_NAME[] = "ohos.global.systemres";
constexpr int32_t HOURS_IN_ONE_DAY = 24;
const static std::string NOTIFICATION_EVENT_PUSH_AGENT = "notification.event.PUSH_AGENT";

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
    result = NotificationPreferences::GetInstance().SetNotificationsEnabledForBundle(bundle, enabled);

    if (!enabled) {
        ANS_LOGI("result = %{public}d", result);
        result = RemoveAllNotificationsForDisable(bundle);
    }
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

    bool isUpdateByOwnerAllowed = IsUpdateSystemLiveviewByOwner(request);
    ErrCode result = publishProcess_[request->GetSlotType()]->PublishPreWork(request, isUpdateByOwnerAllowed);
    if (result != ERR_OK) {
        ANSR_LOGE("Failed to process request, result is %{public}d", result);
        return result;
    }
    result = CheckUserIdParams(request->GetReceiverUserId());
    if (result != ERR_OK) {
        ANSR_LOGE("User is invalid");
        return result;
    }
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (isSubsystem) {
        return PublishNotificationBySa(request);
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
            break;
        }

        if (IsNeedPushCheck(request)) {
            result = PushCheck(request);
        }
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

ErrCode AdvancedNotificationService::Cancel(int32_t notificationId, const std::string &label)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    return CancelPreparedNotification(notificationId, label, bundleOption);
}

ErrCode AdvancedNotificationService::CancelAll()
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidated.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<Notification> notification = nullptr;

        std::vector<std::string> keys = GetNotificationKeys(bundleOption);
        std::vector<sptr<Notification>> notifications;
        for (auto key : keys) {
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            std::string deviceId;
            std::string bundleName;
            GetDistributedInfo(key, deviceId, bundleName);
#endif
            result = RemoveFromNotificationList(key, notification, true,
                NotificationConstant::APP_CANCEL_ALL_REASON_DELETE);
            if (result != ERR_OK) {
                continue;
            }

            if (notification != nullptr) {
                int32_t reason = NotificationConstant::APP_CANCEL_ALL_REASON_DELETE;
                UpdateRecentNotification(notification, true, reason);
                notifications.emplace_back(notification);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(deviceId, bundleName, notification);
#endif
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                std::vector<sptr<Notification>> currNotificationList = notifications;
                NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                    currNotificationList, nullptr, NotificationConstant::APP_CANCEL_ALL_REASON_DELETE);
                notifications.clear();
            }
        }

        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                notifications, nullptr, NotificationConstant::APP_CANCEL_ALL_REASON_DELETE);
        }
        result = ERR_OK;
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::CancelAsBundle(
    const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId, int32_t userId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER) ||
        !CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER)) {
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
        return ERR_ANS_INVALID_UID;
    }
    sptr<NotificationBundleOption> bundle = new (std::nothrow) NotificationBundleOption(
        bundleOption->GetBundleName(), uid);
    return CancelPreparedNotification(notificationId, "", bundle);
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

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
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
            return ERR_ANS_INVALID_UID;
        }
        sptr<NotificationBundleOption> bundle = new (std::nothrow) NotificationBundleOption(
            bundleOption->GetBundleName(), uid);
        return CancelPreparedNotification(id, "", bundle);
    }

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
            result = NotificationPreferences::GetInstance().SetTotalBadgeNums(bundleOption, num);
        }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::Delete(const std::string &key, int32_t removeReason)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("VerifyNativeToken and IsSystemApp is false.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidated.");
        return ERR_ANS_INVALID_PARAM;
    }
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

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
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

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("CheckPermission is false.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        int32_t activeUserId = SUBSCRIBE_USER_INIT;
        if (!GetActiveUserId(activeUserId)) {
            return;
        }
        std::vector<std::string> keys = GetNotificationKeys(nullptr);
        std::vector<sptr<Notification>> notifications;
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
                int32_t reason = NotificationConstant::CANCEL_ALL_REASON_DELETE;
                UpdateRecentNotification(notification, true, reason);
                notifications.emplace_back(notification);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(deviceId, bundleName, notification);
#endif
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                ANS_LOGD("Notifications size greater than or equal to MAX_CANCELED_PARCELABLE_VECTOR_NUM.");
                SendNotificationsOnCanceled(notifications, nullptr, NotificationConstant::CANCEL_ALL_REASON_DELETE);
            }
        }
        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                notifications, nullptr, NotificationConstant::CANCEL_REASON_DELETE);
        }

        result = ERR_OK;
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::SetShowBadgeEnabledForBundle(
    const sptr<NotificationBundleOption> &bundleOption, bool enabled)
{
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("Check permission is false.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
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
            result = NotificationPreferences::GetInstance().SetShowBadge(bundle, enabled);
            if (result == ERR_OK) {
                HandleBadgeEnabledChanged(bundle, enabled);
            }
        }));
    notificationSvrQueue_->wait(handler);
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

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
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
        result = NotificationPreferences::GetInstance().IsShowBadge(bundle, enabled);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            enabled = false;
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
        result = NotificationPreferences::GetInstance().IsShowBadge(bundleOption, enabled);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            enabled = false;
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
        ANS_LOGD("bundleOption == nullptr");
        return ERR_ANS_INVALID_BUNDLE;
    }
    // To get the permission
    bool allowedNotify = false;
    result = IsAllowedNotifySelf(bundleOption, allowedNotify);
    if (result != ERR_OK) {
        return ERROR_INTERNAL_ERROR;
    }
    ANS_LOGI("allowedNotify = %{public}d", allowedNotify);
    if (allowedNotify) {
        return ERR_OK;
    }
    // Check to see if it has been popover before
    bool hasPopped = false;
    result = GetHasPoppedDialog(bundleOption, hasPopped);
    if (result != ERR_OK) {
        return ERROR_INTERNAL_ERROR;
    }
    if (hasPopped) {
        return ERR_ANS_NOT_ALLOWED;
    }

    if (!CreateDialogManager()) {
        return ERROR_INTERNAL_ERROR;
    }
    result = dialogManager_->RequestEnableNotificationDailog(bundleOption, callback, callerToken);
    if (result == ERR_OK) {
        result = ERR_ANS_DIALOG_POP_SUCCEEDED;
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

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!GetActiveUserId(userId)) {
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
            result = NotificationPreferences::GetInstance().SetNotificationsEnabled(userId, enabled);
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

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("IsSystemApp is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
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
        result = NotificationPreferences::GetInstance().SetNotificationsEnabledForBundle(bundle, enabled);
        if (!enabled) {
            result = RemoveAllNotificationsForDisable(bundle);
        }
        if (result == ERR_OK) {
            NotificationSubscriberManager::GetInstance()->NotifyEnabledNotificationChanged(bundleData);
            PublishSlotChangeCommonEvent(bundle);
        }
    } else {
        // Remote device
    }

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

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("CheckPermission is false");
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!GetActiveUserId(userId)) {
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
        result = NotificationPreferences::GetInstance().GetNotificationsEnabled(userId, allowed);
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

ErrCode AdvancedNotificationService::IsAllowedNotifySelf(const sptr<NotificationBundleOption> &bundleOption,
    bool &allowed)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!GetActiveUserId(userId)) {
        ANS_LOGD("GetActiveUserId is false");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    ErrCode result = ERR_OK;
    allowed = false;
    result = NotificationPreferences::GetInstance().GetNotificationsEnabled(userId, allowed);
    if (result == ERR_OK && allowed) {
        result = NotificationPreferences::GetInstance().GetNotificationsEnabledForBundle(bundleOption, allowed);
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
    if (!GetActiveUserId(userId)) {
        ANS_LOGD("GetActiveUserId is false");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    ErrCode result = ERR_OK;
    allowed = false;
    result = NotificationPreferences::GetInstance().GetNotificationsEnabled(userId, allowed);
    if (result == ERR_OK && allowed) {
        result = NotificationPreferences::GetInstance().GetNotificationsEnabledForBundle(bundleOption, allowed);
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

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
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
    if (!GetActiveUserId(userId)) {
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    ErrCode result = ERR_OK;
        allowed = false;
        result = NotificationPreferences::GetInstance().GetNotificationsEnabled(userId, allowed);
        if (result == ERR_OK && allowed) {
            result = NotificationPreferences::GetInstance().GetNotificationsEnabledForBundle(targetBundle, allowed);
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
    LivePublishProcess::GetInstance()->EraseLiveViewSubsciber(uid);
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue is nullptr");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        if ((GetTargetRecordList(bundleName,  NotificationConstant::SlotType::LIVE_VIEW,
            NotificationContent::Type::LOCAL_LIVE_VIEW, recordList) != ERR_OK) &&
            (GetCommonTargetRecordList(bundleName,  NotificationConstant::SlotType::LIVE_VIEW,
            NotificationContent::Type::LIVE_VIEW, recordList) != ERR_OK)) {
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
    LivePublishProcess::GetInstance()->EraseLiveViewSubsciber(uid);
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

    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
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

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("CheckPermission is bogus.");
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
            if ((record->bundleOption->GetBundleName() == bundle->GetBundleName()) &&
                (record->bundleOption->GetUid() == bundle->GetUid()) &&
                (record->notification->GetId() == notificationId)) {
                notification = record->notification;
                result = ERR_OK;
                break;
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
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("CheckPermission is bogus.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is null.");
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
    return RemoveAllNotificationsInner(bundleOption, NotificationConstant::CANCEL_REASON_DELETE);
}

ErrCode AdvancedNotificationService::RemoveAllNotificationsInner(const sptr<NotificationBundleOption> &bundleOption,
    int32_t reason)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("CheckPermission is fake.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is nullptr.");
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
                continue;
            }
            if (record->slot != nullptr) {
                if (record->slot->GetForceControl() && record->slot->GetEnable()) {
                    continue;
                }
            }
            if ((record->bundleOption->GetBundleName() == bundle->GetBundleName()) &&
                (record->bundleOption->GetUid() == bundle->GetUid())
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                && record->deviceId.empty()
#endif
                ) {
                ProcForDeleteLiveView(record);
                removeList.push_back(record);
            }
        }

        std::vector<sptr<Notification>> notifications;
        for (auto record : removeList) {
            notificationList_.remove(record);
            if (record->notification != nullptr) {
                ANS_LOGD("record->notification is not nullptr.");
                UpdateRecentNotification(record->notification, true, reason);
                notifications.emplace_back(record->notification);
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

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        std::vector<sptr<Notification>> notifications;
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
    }));
    notificationSvrQueue_->wait(handler);

    return ERR_OK;
}

ErrCode AdvancedNotificationService::RemoveNotificationBySlot(const sptr<NotificationBundleOption> &bundleOption,
    const sptr<NotificationSlot> &slot)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("CheckPermission is bogus.");
        return ERR_ANS_PERMISSION_DENIED;
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
            notification = (*it)->notification;
            notificationRequest = (*it)->request;

            ProcForDeleteLiveView(*it);
            it = notificationList_.erase(it);

            if (notification != nullptr) {
                UpdateRecentNotification(notification, true, NotificationConstant::DISABLE_SLOT_REASON_DELETE);
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

ErrCode AdvancedNotificationService::CancelGroup(const std::string &groupName)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (groupName.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
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
        for (auto record : removeList) {
            notificationList_.remove(record);
            if (record->notification != nullptr) {
                int32_t reason = NotificationConstant::APP_CANCEL_REASON_DELETE;
                UpdateRecentNotification(record->notification, true, reason);
                notifications.emplace_back(record->notification);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(record->deviceId, record->bundleName, record->notification);
#endif
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                std::vector<sptr<Notification>> currNotificationList = notifications;
                NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                    currNotificationList, nullptr, NotificationConstant::APP_CANCEL_REASON_DELETE);
                notifications.clear();
            }
        }

        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                notifications, nullptr, NotificationConstant::APP_CANCEL_REASON_DELETE);
        }
    }));
    notificationSvrQueue_->wait(handler);

    return ERR_OK;
}

ErrCode AdvancedNotificationService::RemoveGroupByBundle(
    const sptr<NotificationBundleOption> &bundleOption, const std::string &groupName)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (bundleOption == nullptr || groupName.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
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
        for (auto record : removeList) {
            notificationList_.remove(record);
            ProcForDeleteLiveView(record);

            if (record->notification != nullptr) {
                UpdateRecentNotification(record->notification, true, reason);
                notifications.emplace_back(record->notification);
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
    }));
    notificationSvrQueue_->wait(handler);

    return ERR_OK;
}

ErrCode AdvancedNotificationService::RemoveNotificationFromRecordList(
    const std::vector<std::shared_ptr<NotificationRecord>>& recordList)
{
    ErrCode result = ERR_OK;
        std::vector<sptr<Notification>> notifications;
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
        return result;
}

ErrCode AdvancedNotificationService::IsSpecialUserAllowedNotify(const int32_t &userId, bool &allowed)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
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
        result = NotificationPreferences::GetInstance().GetNotificationsEnabled(userId, allowed);
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

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is ineffectiveness.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance().SetNotificationsEnabled(userId, enabled);
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

    result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        sptr<NotificationSlot> slot;
        result = NotificationPreferences::GetInstance().GetNotificationSlot(bundle, slotType, slot);
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
                result = NotificationPreferences::GetInstance().AddNotificationSlots(bundle, slots);
                return;
            }
            NotificationPreferences::GetInstance().RemoveNotificationSlot(bundle, slotType);
        } else {
            ANS_LOGE("Set enable slot: GetNotificationSlot failed");
            return;
        }
        bool allowed = false;
        result = NotificationPreferences::GetInstance().GetNotificationsEnabledForBundle(bundle, allowed);
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
        result = NotificationPreferences::GetInstance().AddNotificationSlots(bundle, slots);
        if (result != ERR_OK) {
            ANS_LOGE("Set enable slot: AddNotificationSlot failed");
            return;
        }

        if (!slot->GetEnable()) {
            RemoveNotificationBySlot(bundle, slot);
        } else {
            if (!slot->GetForceControl() && !allowed) {
                RemoveNotificationBySlot(bundle, slot);
            }
        }

        PublishSlotChangeCommonEvent(bundle);
    }));
    notificationSvrQueue_->wait(handler);

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

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
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
        result = NotificationPreferences::GetInstance().GetNotificationSlot(bundle, slotType, slot);
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

void AdvancedNotificationService::UpdateUnifiedGroupInfo(std::string &key,
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

    int32_t uid = request->GetCreatorUid();
    if (request->IsAgentNotification()) {
        uid = request->GetOwnerUid();
    }
    if (uid <= 0) {
        ANS_LOGE("CreatorUid[%{public}d] error", uid);
        return ERR_ANS_INVALID_UID;
    }
    std::string bundle = "";
    ErrCode result = PrePublishNotificationBySa(request, uid, bundle);
    if (result != ERR_OK) {
        return result;
    }

    // SA not support sound
    if (!request->GetSound().empty()) {
        request->SetSound("");
    }
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = request;
    if (request->IsAgentNotification()) {
        record->bundleOption = new (std::nothrow) NotificationBundleOption("", request->GetCreatorUid());
    } else {
        record->bundleOption = new (std::nothrow) NotificationBundleOption(bundle, uid);
    }
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

        ChangeNotificationByControlFlags(record);
        if (IsSaCreateSystemLiveViewAsBundle(record, ipcUid)) {
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
        StartAutoDelete(record->notification->GetKey(),
            record->request->GetAutoDeletedTime(), NotificationConstant::APP_CANCEL_REASON_DELETE);
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetBadgeNumber(int32_t badgeNumber)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName = GetClientBundleName();
    sptr<BadgeNumberCallbackData> badgeData = new (std::nothrow) BadgeNumberCallbackData(
        bundleName, callingUid, badgeNumber);
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
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("Client is not a system app or subsystem.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    sptr<NotificationBundleOption> bundle = bundleOption;
    ErrCode result = CheckBundleOptionValid(bundle);
    if (result != ERR_OK) {
        ANS_LOGE("Input parameter bundle option is not correct.");
        return result;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER)) {
        std::string bundleName = GetClientBundleName();
        if (bundleName.empty()) {
            ANS_LOGE("Failed to get client bundle name.");
            return result;
        }
        bool isAgent = false;
        isAgent = IsAgentRelationship(bundleName, bundle->GetBundleName());
        if (!isAgent) {
            ANS_LOGE("The caller has no agent relationship with the specified bundle.");
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
        LivePublishProcess::GetInstance()->AddLiveViewSubscriber();
    }
    SendSubscribeHiSysEvent(IPCSkeleton::GetCallingPid(), IPCSkeleton::GetCallingUid(), info, errCode);
    return errCode;
}

ErrCode AdvancedNotificationService::SetDistributedEnabledByBundle(const sptr<NotificationBundleOption> &bundleOption,
    const std::string &deviceType, const bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("IsSystemApp is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("bundle is nullptr");
        return ERR_ANS_INVALID_BUNDLE;
    }

    return NotificationPreferences::GetInstance().SetDistributedEnabledByBundle(bundle, deviceType, enabled);
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

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("no permission");
        return ERR_ANS_PERMISSION_DENIED;
    }
    ANS_LOGE("no permission111");
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    ANS_LOGE("no permission1222");
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    return NotificationPreferences::GetInstance().IsDistributedEnabledByBundle(bundle, deviceType, enabled);
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

void AdvancedNotificationService::RemoveExpiredUniqueKey()
{
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    auto iter = uniqueKeyList_.begin();
    while (iter != uniqueKeyList_.end()) {
        if (abs(now - (*iter).first) > std::chrono::hours(HOURS_IN_ONE_DAY)) {
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
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("IsSystemApp is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }
    ErrCode result = NotificationPreferences::GetInstance().SetSmartReminderEnabled(deviceType, enabled);
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    ReminderSwingDecisionCenter::GetInstance().OnSmartReminderStatusChanged();
#endif
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

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("no permission");
        return ERR_ANS_PERMISSION_DENIED;
    }

    return NotificationPreferences::GetInstance().IsSmartReminderEnabled(deviceType, enabled);
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
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    ReminderSwingDecisionCenter::GetInstance().OnUpdateDeviceStatus(deviceType);
#endif
    ANS_LOGI("%{public}s device status update with %{public}u",
        deviceType.c_str(), DelayedSingleton<DistributedDeviceStatus>::GetInstance()->GetDeviceStatus(deviceType));
    return ret;
}
}  // namespace Notification
}  // namespace OHOS
