/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "errors.h"

#include "ipc_skeleton.h"
#include "notification_bundle_option.h"
#include "notification_constant.h"
#include "hitrace_meter_adapter.h"
#include "os_account_manager.h"
#include "distributed_screen_status_manager.h"
#include "notification_local_live_view_subscriber_manager.h"

#include "advanced_notification_inline.cpp"

namespace OHOS {
namespace Notification {

constexpr char FOUNDATION_BUNDLE_NAME[] = "ohos.global.systemres";

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
        result = RemoveAllNotifications(bundle);
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
    ANS_LOGD("%{public}s, uid = %{public}d", __FUNCTION__, request->GetCreatorUid());

    if (!request) {
        ANSR_LOGE("ReminderRequest object is nullptr");
        return ERR_ANS_INVALID_PARAM;
    }

    if (!CheckLocalLiveViewAllowed(request)) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckLocalLiveViewSubscribed(request)) {
        return ERR_ANS_INVALID_PARAM;
    }

    if (!request->IsRemoveAllowed()) {
        if (!CheckPermission(OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION)) {
            request->SetRemoveAllowed(true);
        }
    }

    ErrCode result = ERR_OK;
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (isSubsystem) {
        return PublishNotificationBySa(request);
    }

    do {
        if (request->GetReceiverUserId() != SUBSCRIBE_USER_INIT) {
            if (!AccessTokenHelper::IsSystemApp()) {
                result = ERR_ANS_NON_SYSTEM_APP;
                break;
            }
            if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
                result = ERR_ANS_PERMISSION_DENIED;
                break;
            }
        }

        // The third-party app needn't support in progress except for live view
        if (request->IsInProgress() &&
            !AccessTokenHelper::IsSystemApp() &&
            !request->IsCommonLiveView()) {
            request->SetInProgress(false);
        }

        Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
        if (AccessTokenHelper::IsDlpHap(callerToken)) {
            result = ERR_ANS_DLP_HAP;
            ANS_LOGE("DLP hap not allowed to send notifications");
            break;
        }

        sptr<NotificationBundleOption> bundleOption;
        result = PrepareNotificationInfo(request, bundleOption);
        if (result != ERR_OK) {
            break;
        }

        if (IsNeedPushCheck(request)) {
            result = PushCheck(request);
        }
        if (result != ERR_OK) {
            break;
        }
        result = PublishPreparedNotification(request, bundleOption);
        if (result != ERR_OK) {
            break;
        }
    } while (0);

    SendPublishHiSysEvent(request, result);
    return result;
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
    const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId)
{
    ANS_LOGD("%{public}s, uid = %{public}d", __FUNCTION__, bundleOption->GetUid());
    return ERR_INVALID_OPERATION;
}

ErrCode AdvancedNotificationService::CancelAsBundle(
    int32_t notificationId, const std::string &representativeBundle, int32_t userId)
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

    int32_t uid = -1;
    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager != nullptr) {
        uid = BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(representativeBundle, userId);
    }
    if (uid < 0) {
        return ERR_ANS_INVALID_UID;
    }
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(
        representativeBundle, uid);
    return CancelPreparedNotification(notificationId, "", bundleOption);
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
    ANS_LOGD("%{public}s", __FUNCTION__);

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
            result = NotificationPreferences::GetInstance().SetShowBadge(bundle, enabled);
            ANS_LOGD("ffrt enter!");
        }));
    notificationSvrQueue_->wait(handler);
    return result;
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
            result = RemoveAllNotifications(bundle);
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
                record->notification->SetEnableLight(false);
                record->notification->SetEnableSound(false);
                record->notification->SetEnableVibration(false);
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

ErrCode AdvancedNotificationService::RemoveSystemLiveViewNotifications(const std::string& bundleName)
{
    std::vector<std::shared_ptr<NotificationRecord>> recordList;
    EraseLiveViewSubsciber(bundleName);
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue is nullptr");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        if (GetTargetRecordList(bundleName,  NotificationConstant::SlotType::LIVE_VIEW,
            NotificationContent::Type::LOCAL_LIVE_VIEW, recordList) != ERR_OK) {
            ANS_LOGE("Get Target record list fail.");
            result = ERR_ANS_NOTIFICATION_NOT_EXISTS;
            return;
        }
        result = RemoveNotificationFromRecordList(recordList);
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

ErrCode AdvancedNotificationService::RemoveAllNotifications(const sptr<NotificationBundleOption> &bundleOption)
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
        int32_t reason = NotificationConstant::CANCEL_REASON_DELETE;
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

    for (auto record : notificationList_) {
        if ((record->bundleOption->GetBundleName() == bundle->GetBundleName()) &&
            (record->bundleOption->GetUid() == bundle->GetUid()) &&
            (record->request->GetSlotType() == slot->GetType())) {
            if (!record->notification->IsRemoveAllowed() || !record->request->IsCommonLiveView()) {
                continue;
            }

            notification = record->notification;
            notificationRequest = record->request;

            ProcForDeleteLiveView(record);
            notificationList_.remove(record);

            if (notification != nullptr) {
                UpdateRecentNotification(notification, true, NotificationConstant::CANCEL_REASON_DELETE);
                NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, nullptr,
                    NotificationConstant::CANCEL_REASON_DELETE);
            }

            TriggerRemoveWantAgent(notificationRequest);
            result = ERR_OK;
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
        } else if ((result == ERR_OK) && (slot != nullptr)) {
            if (slot->GetEnable() == enabled && slot->GetForceControl() == isForceControl) {
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
        if (!slot->GetEnable()) {
            RemoveNotificationBySlot(bundle, slot);
        } else {
            if (!slot->GetForceControl() && !allowed) {
                RemoveNotificationBySlot(bundle, slot);
            }
        }
        slot->SetEnable(enabled);
        slot->SetForceControl(isForceControl);
        std::vector<sptr<NotificationSlot>> slots;
        slots.push_back(slot);
        result = NotificationPreferences::GetInstance().AddNotificationSlots(bundle, slots);
        if (result != ERR_OK) {
            ANS_LOGE("Set enable slot: AddNotificationSlot failed");
            return;
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

ErrCode AdvancedNotificationService::PublishNotificationBySa(const sptr<NotificationRequest> &request)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    int32_t uid = request->GetCreatorUid();
    if (uid <= 0) {
        ANS_LOGE("CreatorUid[%{public}d] error", uid);
        return ERR_ANS_INVALID_UID;
    }
    std::string bundle = "";
    ErrCode result = PrePublishNotificationBySa(request, uid, bundle);
    if (result != ERR_OK) {
        return result;
    }

    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->bundleOption = new (std::nothrow) NotificationBundleOption(bundle, uid);
    if (record->bundleOption == nullptr) {
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
    ffrt::task_handle handler = notificationSvrQueue_->submit_h([this, &record]() {
        if (!record->bundleOption->GetBundleName().empty()) {
            ErrCode ret = AssignValidNotificationSlot(record);
            if (ret != ERR_OK) {
                ANS_LOGE("Can not assign valid slot!");
            }
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

    return result;
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

void AdvancedNotificationService::AddLiveViewSubscriber()
{
    std::string bundleName = GetClientBundleName();
    std::lock_guard<std::mutex> lock(liveViewMutext_);
    localLiveViewSubscribedList_.emplace(bundleName);
}

void AdvancedNotificationService::EraseLiveViewSubsciber(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(liveViewMutext_);
    localLiveViewSubscribedList_.erase(bundleName);
}

bool AdvancedNotificationService::GetLiveViewSubscribeState(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(liveViewMutext_);
    if (localLiveViewSubscribedList_.find(bundleName) == localLiveViewSubscribedList_.end()) {
        return false;
    }
    return true;
}

ErrCode AdvancedNotificationService::SubscribeLocalLiveView(
    const sptr<AnsSubscriberLocalLiveViewInterface> &subscriber, const sptr<NotificationSubscribeInfo> &info)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    ErrCode errCode = ERR_OK;
    do {
        if (subscriber == nullptr) {
            errCode = ERR_ANS_INVALID_PARAM;
            break;
        }

        bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
        if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
            ANS_LOGE("Client is not a system app or subsystem");
            errCode = ERR_ANS_NON_SYSTEM_APP;
            break;
        }

        errCode = NotificationLocalLiveViewSubscriberManager::GetInstance()->AddLocalLiveViewSubscriber(
            subscriber, info);
        if (errCode != ERR_OK) {
            break;
        }
    } while (0);
    if (errCode == ERR_OK) {
        AddLiveViewSubscriber();
    }
    SendSubscribeHiSysEvent(IPCSkeleton::GetCallingPid(), IPCSkeleton::GetCallingUid(), info, errCode);
    return errCode;
}
}  // namespace Notification
}  // namespace OHOS
