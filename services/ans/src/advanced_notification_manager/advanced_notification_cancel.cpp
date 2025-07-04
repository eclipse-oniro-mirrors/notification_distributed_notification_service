/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "ans_trace_wrapper.h"
#include "access_token_helper.h"
#include "ans_permission_def.h"
#include "bundle_manager_helper.h"
#include "ipc_skeleton.h"
#include "notification_analytics_util.h"
#include "notification_bundle_option.h"
#include "notification_constant.h"
#include "notification_local_live_view_content.h"
#include "notification_subscriber_manager.h"
#include "os_account_manager.h"

#include "../advanced_notification_inline.cpp"

namespace OHOS {
namespace Notification {
ErrCode AdvancedNotificationService::Cancel(int32_t notificationId,
    const std::string &label, const std::string &instanceKey)
{
    ANS_LOGD("called");

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
    ANS_LOGD("called");
    const int reason = NotificationConstant::APP_CANCEL_ALL_REASON_DELETE;
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    bundleOption->SetAppInstanceKey(instanceKey);

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("null notificationSvrQueue");
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
    ANS_LOGD("called");
    int32_t reason = NotificationConstant::APP_CANCEL_AS_BUNELE_REASON_DELETE;
    if (bundleOption == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    int32_t errCode = ValidRightsForCancelAsBundle(notificationId, reason);
    if (errCode != ERR_OK) {
        return errCode;
    }
    errCode = CheckUserIdParams(userId);
    if (errCode != ERR_OK) {
        std::string message = "userId:" + std::to_string(userId);
        HaMetaMessage haMateMessage = HaMetaMessage(EventSceneId::SCENE_13, EventBranchId::BRANCH_14)
            .ErrorCode(errCode).NotificationId(notificationId);
        ReportDeleteFailedEventPush(haMateMessage, reason, message);
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

ErrCode AdvancedNotificationService::ValidRightsForCancelAsBundle(int32_t notificationId, int32_t &reason)
{
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
    return ERR_OK;
}

ErrCode AdvancedNotificationService::CancelAsBundle(
    const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId)
{
    ANS_LOGD("uid = %{public}d", bundleOption->GetUid());
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
    ANS_LOGD("called");
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(
         representativeBundle, DEFAULT_UID);
    if (bundleOption == nullptr) {
        ANS_LOGE("null bundleOption");
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

ErrCode AdvancedNotificationService::CancelContinuousTaskNotification(const std::string &label, int32_t notificationId)
{
    ANS_LOGD("called");

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem) {
        return ERR_ANS_NOT_SYSTEM_SERVICE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("null notificationSvrQueue");
        return ERR_ANS_INVALID_PARAM;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("called");
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

ErrCode AdvancedNotificationService::RemoveNotification(const sptr<NotificationBundleOption> &bundleOption,
    int32_t notificationId, const std::string &label, int32_t removeReason)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("called");

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
        result = ExcuteRemoveNotification(bundle, notificationId, label, removeReason);
    }));
    notificationSvrQueue_->wait(handler);
    if (result != ERR_OK) {
        std::string message = "remove notificaiton error";
        ANS_LOGE("%{public}s %{public}d", message.c_str(), result);
    }
    SendRemoveHiSysEvent(notificationId, label, bundleOption, result);
    return result;
}

ErrCode AdvancedNotificationService::ExcuteRemoveNotification(const sptr<NotificationBundleOption> &bundle,
    int32_t notificationId, const std::string &label, int32_t &removeReason)
{
    ErrCode result = ERR_ANS_NOTIFICATION_NOT_EXISTS;
    ANS_LOGD("called");
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

            if (!IsReasonClickDelete(removeReason)) {
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
    if (!IsReasonClickDelete(removeReason)) {
        TriggerRemoveWantAgent(notificationRequest, removeReason, isThirdParty);
    }
    return result;
}

bool AdvancedNotificationService::IsReasonClickDelete(const int32_t removeReason)
{
    return removeReason == NotificationConstant::CLICK_REASON_DELETE ||
        removeReason == NotificationConstant::DISTRIBUTED_COLLABORATIVE_CLICK_DELETE;
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
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("called");

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
    if (callingUid != NotificationConstant::ANS_UID &&
        !AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
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
        ExcuteRemoveAllNotificationsInner(bundleOption, bundle, reason);
    }));
    notificationSvrQueue_->wait(handler);

    return ERR_OK;
}

void AdvancedNotificationService::ExcuteRemoveAllNotificationsInner(const sptr<NotificationBundleOption> &bundleOption,
    const sptr<NotificationBundleOption> &bundle, int32_t &reason)
{
    std::vector<std::shared_ptr<NotificationRecord>> removeList;
    ANS_LOGD("called");
    GetRemoveListForRemoveAll(bundleOption, bundle, removeList);
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
}

void AdvancedNotificationService::GetRemoveListForRemoveAll(const sptr<NotificationBundleOption> &bundleOption,
    const sptr<NotificationBundleOption> &bundle, std::vector<std::shared_ptr<NotificationRecord>> &removeList)
{
    for (auto record : notificationList_) {
        bool isAllowedNotification = true;
        if (IsAllowedNotifyForBundle(bundleOption, isAllowedNotification) != ERR_OK) {
            ANSR_LOGW("The application does not request enable notification.");
        }
        if (!record->notification->IsRemoveAllowed() && isAllowedNotification) {
            ANS_LOGI("BatchRemove-FILTER-RemoveNotAllowed-%{public}s", record->notification->GetKey().c_str());
            continue;
        }
        if (record->slot != nullptr && record->slot->GetForceControl() && record->slot->GetEnable()) {
            ANS_LOGI("BatchRemove-FILTER-ForceControl-%{public}s", record->notification->GetKey().c_str());
            continue;
        }
        if (record->bundleOption->GetBundleName() != bundle->GetBundleName() ||
            record->bundleOption->GetUid() != bundle->GetUid()
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            || !record->deviceId.empty()
#endif
            ) {
            continue;
        }
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

ErrCode AdvancedNotificationService::RemoveNotifications(
    const std::vector<std::string> &keys, int32_t removeReason)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("called");

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("null notificationSvrQueue");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ExcuteRemoveNotifications(keys, removeReason);
    }));
    notificationSvrQueue_->wait(handler);

    return ERR_OK;
}

void AdvancedNotificationService::ExcuteRemoveNotifications(const std::vector<std::string> &keys, int32_t removeReason)
{
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
}

ErrCode AdvancedNotificationService::RemoveNotificationBySlot(const sptr<NotificationBundleOption> &bundleOption,
    const sptr<NotificationSlot> &slot, const int reason)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("called");

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
    GetRemoveListForRemoveNtfBySlot(bundle, slot, removeList);

    std::vector<sptr<Notification>> notifications;
    std::vector<uint64_t> timerIds;
    for (auto record : removeList) {
        if (record == nullptr) {
            ANS_LOGE("null record");
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

void AdvancedNotificationService::GetRemoveListForRemoveNtfBySlot(const sptr<NotificationBundleOption> &bundle,
    const sptr<NotificationSlot> &slot, std::vector<std::shared_ptr<NotificationRecord>> &removeList)
{
    for (auto record : notificationList_) {
        if (record == nullptr) {
            ANS_LOGE("null record");
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

ErrCode AdvancedNotificationService::Delete(const std::string &key, int32_t removeReason)
{
    ANS_LOGD("called");
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
        ANS_LOGD("called");
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
    ANS_LOGD("called");

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
        ANS_LOGD("null bundle");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("null notificationSvrQueue");
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
    ANS_LOGD("called");

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
        ExcuteDeleteAll(result, reason);
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

void AdvancedNotificationService::ExcuteDeleteAll(ErrCode &result, const int32_t reason)
{
    ANS_LOGD("called");
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
}

ErrCode AdvancedNotificationService::RemoveDistributedNotifications(
    const std::vector<std::string>& hashcodes, const int32_t slotTypeInt,
    const int32_t deleteTypeInt, const int32_t removeReason)
{
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("IsSystemApp is false.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("app no controller");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("notificationSvrQueue is null");
        return ERR_ANS_INVALID_PARAM;
    }

    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(slotTypeInt);
    NotificationConstant::DistributedDeleteType deleteType =
        static_cast<NotificationConstant::DistributedDeleteType>(deleteTypeInt);
    
    switch (deleteType) {
        case NotificationConstant::DistributedDeleteType::ALL:
            return RemoveAllDistributedNotifications(removeReason);
        case NotificationConstant::DistributedDeleteType::SLOT:
        case NotificationConstant::DistributedDeleteType::EXCLUDE_ONE_SLOT:
            return RemoveDistributedNotifications(slotType, removeReason, deleteType);
        case NotificationConstant::DistributedDeleteType::HASHCODES:
            return RemoveDistributedNotifications(hashcodes, removeReason);
        default:
            ANS_LOGW("no deleteType");
            break;
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::RemoveDistributedNotifications(
    const std::vector<std::string>& hashcodes, const int32_t removeReason)
{
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([=]() {
        std::vector<sptr<Notification>> notifications;
        std::list<std::shared_ptr<NotificationRecord>> deleteRecords;
        for (auto record : notificationList_) {
            auto notification = record->notification;
            if (notification == nullptr) {
                continue;
            }

            auto key = notification->GetKey();
            if (std::find(hashcodes.begin(), hashcodes.end(), key) == hashcodes.end()) {
                continue;
            }
            if (ExecuteDeleteDistributedNotification(record, notifications, removeReason)) {
                deleteRecords.push_back(record);
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                std::vector<sptr<Notification>> currNotificationList = notifications;
                NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                    currNotificationList, nullptr, removeReason);
                notifications.clear();
            }
        }

        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                notifications, nullptr, removeReason);
        }
        for (auto deleteRecord : deleteRecords) {
            notificationList_.remove(deleteRecord);
        }
    }));
    return ERR_OK;
}

ErrCode AdvancedNotificationService::RemoveDistributedNotifications(
    const NotificationConstant::SlotType& slotType, const int32_t removeReason,
    const NotificationConstant::DistributedDeleteType& deleteType)
{
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([=]() {
        std::vector<sptr<Notification>> notifications;
        std::list<std::shared_ptr<NotificationRecord>> deleteRecords;
        for (auto record : notificationList_) {
            auto notification = record->notification;
            if (notification == nullptr) {
                continue;
            }
            auto request = notification->GetNotificationRequestPoint();
            if (request == nullptr) {
                continue;
            }
            if (deleteType == NotificationConstant::DistributedDeleteType::EXCLUDE_ONE_SLOT &&
                request->GetSlotType() == slotType) {
                ANS_LOGD("key:%{public}s,ty:%{public}d", request->GetKey().c_str(), request->GetSlotType());
                continue;
            }
            if (deleteType == NotificationConstant::DistributedDeleteType::SLOT &&
                request->GetSlotType() != slotType) {
                ANS_LOGD("key:%{public}s,ty:%{public}d", request->GetKey().c_str(), request->GetSlotType());
                continue;
            }

            if (ExecuteDeleteDistributedNotification(record, notifications, removeReason)) {
                deleteRecords.push_back(record);
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                std::vector<sptr<Notification>> currNotificationList = notifications;
                NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                    currNotificationList, nullptr, removeReason);
                notifications.clear();
            }
        }

        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                notifications, nullptr, removeReason);
        }
        for (auto deleteRecord : deleteRecords) {
            notificationList_.remove(deleteRecord);
        }
    }));
    return ERR_OK;
}

ErrCode AdvancedNotificationService::RemoveAllDistributedNotifications(
    const int32_t removeReason)
{
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([=]() {
        std::vector<sptr<Notification>> notifications;
        std::list<std::shared_ptr<NotificationRecord>> deleteRecords;
        for (auto record : notificationList_) {
            if (ExecuteDeleteDistributedNotification(record, notifications, removeReason)) {
                deleteRecords.push_back(record);
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                std::vector<sptr<Notification>> currNotificationList = notifications;
                NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                    currNotificationList, nullptr, removeReason);
                notifications.clear();
            }
        }

        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                notifications, nullptr, removeReason);
        }

        for (auto deleteRecord : deleteRecords) {
            notificationList_.remove(deleteRecord);
        }
    }));
    return ERR_OK;
}

bool AdvancedNotificationService::ExecuteDeleteDistributedNotification(
    std::shared_ptr<NotificationRecord>& record,
    std::vector<sptr<Notification>>& notifications,
    const int32_t removeReason)
{
    if (record == nullptr) {
        ANS_LOGE("delete record is null");
        return false;
    }

    auto notification = record->notification;
    if (notification == nullptr) {
        ANS_LOGE("delete notification is null");
        return false;
    }

    auto request = notification->GetNotificationRequestPoint();
    if (request == nullptr) {
        ANS_LOGE("delete request is null");
        return false;
    }
    if (IsDistributedNotification(request)) {
        notifications.emplace_back(notification);
        CancelTimer(notification->GetAutoDeletedTimer());
        ProcForDeleteLiveView(record);
        TriggerRemoveWantAgent(request, removeReason, record->isThirdparty);
        CancelWantAgent(notification);
        return true;
    }
    ANS_LOGD("delete not distributed, key:%{public}s", request->GetKey().c_str());
    return false;
}

bool AdvancedNotificationService::IsDistributedNotification(sptr<NotificationRequest> request)
{
    if (request == nullptr) {
        return false;
    }

    if (request->GetDistributedCollaborate()) {
        return true;
    }
    return false;
}
}  // namespace Notification
}  // namespace OHOS