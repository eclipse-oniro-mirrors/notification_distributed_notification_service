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

#include "advanced_notification_priority_helper.h"
#include "notification_ai_extension_wrapper.h"
#include "notification_preferences.h"
#include "notification_subscriber_manager.h"

namespace OHOS {
namespace Notification {
ErrCode AdvancedNotificationService::SetPriorityEnabled(const bool enabled)
{
    auto result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    return SetPriorityEnabledInner(enabled);
}

ErrCode AdvancedNotificationService::SetPriorityEnabledInner(const bool enabled)
{
    ErrCode result = ERR_OK;
    int32_t refreshResult = 0;
    auto submitResult = notificationSvrQueue_.SyncSubmit(std::bind([&]() {
        result = NotificationPreferences::GetInstance()->SetPriorityEnabled(
            enabled ? NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON
            : NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
        sptr<EnabledNotificationCallbackData> bundleData =
            new (std::nothrow) EnabledNotificationCallbackData("", DEFAULT_UID, enabled);
        if (bundleData == nullptr) {
            ANS_LOGE("Failed to create EnabledNotificationCallbackData instance");
            result = ERR_NO_MEMORY;
        } else {
            NotificationSubscriberManager::GetInstance()->NotifyEnabledPriorityChanged(bundleData);
        }
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
        if (result != ERR_OK || !enabled) {
            return;
        }
        std::vector<sptr<NotificationRequest>> requests;
        GetRequestsFromNotification(GetAllNotification(), requests);
        refreshResult = AdvancedNotificationPriorityHelper::GetInstance()->RefreshPriorityType(
            requests, NotificationAiExtensionWrapper::REFRESH_SWITCH_PRIORITY_TYPE);
#endif
    }));
    ANS_COND_DO_ERR(submitResult != ERR_OK, return submitResult, "Set priority enable.");
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_25);
    message.Message("en:" + std::to_string(enabled) + ", refreshResult:" + std::to_string(refreshResult));
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    ANS_LOGI("SetPriorityEnabled enabled: %{public}d, result: %{public}d, refreshResult: %{public}d",
        enabled, result, refreshResult);
    return result;
}

ErrCode AdvancedNotificationService::SetPriorityEnabledByBundle(
    const sptr<NotificationBundleOption> &bundleOption, const int32_t enableStatusInt)
{
    auto result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("bundle is nullptr");
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_26);
        message.Message("bundle: " + bundleOption->GetBundleName() + ", id: " +
            std::to_string(bundleOption->GetUid()) + ", en:" + std::to_string(enableStatusInt));
        message.ErrorCode(ERR_ANS_INVALID_BUNDLE);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_INVALID_BUNDLE;
    }
    if (enableStatusInt < static_cast<int32_t>(NotificationConstant::PriorityEnableStatus::DISABLE) ||
        enableStatusInt > static_cast<int32_t>(NotificationConstant::PriorityEnableStatus::ENABLE)) {
        ANS_LOGE("EnableStatus out of range %{public}d.", enableStatusInt);
        return ERR_ANS_INVALID_PARAM;
    }
    return SetPriorityEnabledByBundleInner(bundle, enableStatusInt);
}

ErrCode AdvancedNotificationService::SetPriorityEnabledByBundleInner(
    const sptr<NotificationBundleOption> &bundleOption, const int32_t enableStatusInt)
{
    ErrCode result = ERR_OK;
    int32_t refreshResult = 0;
    auto submitResult = notificationSvrQueue_.SyncSubmit(std::bind([&]() {
        result = NotificationPreferences::GetInstance()->SetPriorityEnabledByBundle(bundleOption,
            static_cast<NotificationConstant::PriorityEnableStatus>(enableStatusInt));
        sptr<EnabledPriorityNotificationByBundleCallbackData> bundleData =
            new (std::nothrow) EnabledPriorityNotificationByBundleCallbackData(bundleOption->GetBundleName(),
            bundleOption->GetUid(), static_cast<NotificationConstant::PriorityEnableStatus>(enableStatusInt));
        if (bundleData == nullptr) {
            ANS_LOGE("Failed to create EnabledPriorityNotificationByBundleCallbackData instance");
            result = ERR_NO_MEMORY;
        } else {
            NotificationSubscriberManager::GetInstance()->NotifyEnabledPriorityByBundleChanged(bundleData);
        }
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
        if (result != ERR_OK || enableStatusInt !=
            static_cast<int32_t>(NotificationConstant::PriorityEnableStatus::ENABLE_BY_INTELLIGENT)) {
            return;
        }
        std::vector<sptr<NotificationRequest>> requests;
        GetRequestsFromNotification(GetNotificationsByBundle(bundleOption), requests);
        refreshResult = AdvancedNotificationPriorityHelper::GetInstance()->RefreshPriorityType(
            requests, NotificationAiExtensionWrapper::REFRESH_SWITCH_PRIORITY_TYPE);
#endif
    }));
    ANS_COND_DO_ERR(submitResult != ERR_OK, return submitResult, "Set bundle priority enable.");
    ANS_LOGI("SetPriorityEnabledByBundle %{public}s_%{public}d, "
        "enableStatus: %{public}d, result: %{public}d, refreshResult: %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), enableStatusInt, result, refreshResult);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_26);
    message.Message("bundle: " + bundleOption->GetBundleName() + ", id: " + std::to_string(bundleOption->GetUid()) +
        ", en:" + std::to_string(enableStatusInt) + ", refreshResult:" + std::to_string(refreshResult));
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    return result;
}

ErrCode AdvancedNotificationService::IsPriorityEnabled(bool &enabled)
{
    auto result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
    result = NotificationPreferences::GetInstance()->IsPriorityEnabled(enableStatus);
    enabled = (enableStatus == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON ||
        enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    ANS_LOGI("IsPriorityEnabled enabled: %{public}d, result: %{public}d", enabled, result);
    return result;
}

ErrCode AdvancedNotificationService::IsPriorityEnabledByBundle(
    const sptr<NotificationBundleOption> &bundleOption, int32_t &enableStatusInt)
{
    auto result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("bundle is nullptr");
        return ERR_ANS_INVALID_BUNDLE;
    }
    NotificationConstant::PriorityEnableStatus enableStatus =
        NotificationConstant::PriorityEnableStatus::ENABLE_BY_INTELLIGENT;
    result = NotificationPreferences::GetInstance()->IsPriorityEnabledByBundle(bundle, enableStatus);
    enableStatusInt = static_cast<int32_t>(enableStatus);
    ANS_LOGI("IsPriorityEnabledByBundle %{public}s_%{public}d, enableStatus: %{public}d, result: %{public}d",
        bundle->GetBundleName().c_str(), bundle->GetUid(), enableStatusInt, result);
    return result;
}

ErrCode AdvancedNotificationService::TriggerUpdatePriorityType(const sptr<NotificationRequest> &request)
{
    auto result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    auto submitResult = notificationSvrQueue_.SyncSubmit(std::bind([&]() {
        auto record = GetFromNotificationList(request->GetBaseKey(""));
        if (record == nullptr) {
            ANS_LOGE("TriggerUpdatePriorityType fail, notification not exist");
            result = ERR_ANS_INVALID_PARAM;
            return;
        }
        auto cacheRequest = record->notification->GetNotificationRequestPoint();
        if (cacheRequest == nullptr) {
            ANS_LOGE("TriggerUpdatePriorityType fail, cache request not exist");
            result = ERR_ANS_INVALID_PARAM;
            return;
        }
        cacheRequest->SetInnerPriorityNotificationType(request->GetPriorityNotificationType());
        sptr<Notification> notification = new (std::nothrow) Notification(request);
        if (notification == nullptr) {
            ANS_LOGE("TriggerUpdatePriorityType fail, null notification");
            result = ERR_NO_MEMORY;
            return;
        }
        NotificationSubscriberManager::GetInstance()->NotifySystemUpdate(notification);
    }));
    ANS_COND_DO_ERR(submitResult != ERR_OK, return submitResult, "Trigger update priority.");
    ANS_LOGI("TriggerUpdatePriorityType key: %{public}s, result: %{public}d", request->GetKey().c_str(), result);
    return result;
}

ErrCode AdvancedNotificationService::SetBundlePriorityConfig(
    const sptr<NotificationBundleOption> &bundleOption, const std::string &value)
{
    ErrCode result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("bundle is nullptr");
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_28);
        message.Message("bundle: " + bundleOption->GetBundleName() + ", id: " + std::to_string(bundleOption->GetUid()));
        message.ErrorCode(ERR_ANS_INVALID_BUNDLE).Append(" bundle name is empty");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_INVALID_BUNDLE;
    }
    return SetBundlePriorityConfigInner(bundle, value);
}

ErrCode AdvancedNotificationService::SetBundlePriorityConfigInner(
    const sptr<NotificationBundleOption> &bundleOption, const std::string &value)
{
    ErrCode result = ERR_OK;
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_28);
    message.Message("bundle: " + bundleOption->GetBundleName() + ", id: " + std::to_string(bundleOption->GetUid()));
    int32_t refreshResult = 0;
    auto submitResult = notificationSvrQueue_.SyncSubmit(std::bind([&]() {
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
        int32_t aiResult = NOTIFICATION_AI_EXTENSION_WRAPPER->SyncBundleKeywords(bundleOption, value);
        ANS_LOGI("SyncBundleKeywords %{public}s_%{public}d result: %{public}d",
            bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), aiResult);
        if (aiResult == NOTIFICATION_AI_EXTENSION_WRAPPER->ErrorCode::ERR_FAIL) {
            result = ERR_ANS_SERVICE_NOT_READY;
            return;
        }
        result = NotificationPreferences::GetInstance()->SetBundlePriorityConfig(bundleOption, value);
        if (result != ERR_OK) {
            return;
        }
        std::vector<sptr<NotificationRequest>> requests;
        GetRequestsFromNotification(GetNotificationsByBundle(bundleOption), requests);
        refreshResult = AdvancedNotificationPriorityHelper::GetInstance()->RefreshPriorityType(
            requests, NotificationAiExtensionWrapper::REFRESH_KEYWORD_PRIORITY_TYPE);
#endif
    }));
    ANS_COND_DO_ERR(submitResult != ERR_OK, return submitResult, "Set priority config.");
    message.ErrorCode(result).Append(", refreshResult:" + std::to_string(refreshResult));
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    ANS_LOGI("SetBundlePriorityConfig %{public}s_%{public}d, result: %{public}d, refreshResult: %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), result, refreshResult);
    return result;
}

ErrCode AdvancedNotificationService::GetBundlePriorityConfig(
    const sptr<NotificationBundleOption> &bundleOption, std::string &value)
{
    ErrCode result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("bundle is nullptr");
        return ERR_ANS_INVALID_BUNDLE;
    }
    return NotificationPreferences::GetInstance()->GetBundlePriorityConfig(bundle, value);
}

void AdvancedNotificationService::GetRequestsFromNotification(
    const std::vector<sptr<Notification>> &notifications, std::vector<sptr<NotificationRequest>> &requests)
{
    for (const sptr<Notification> &notification : notifications) {
        if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr) {
            continue;
        }
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
        if (AdvancedNotificationPriorityHelper::GetInstance()->IsCollaborationNotification(
            notification->GetNotificationRequestPoint())) {
            continue;
        }
#endif
        MessageParcel parcel;
        if (!parcel.WriteParcelable(notification)) {
            ANS_LOGE("GetRequestsFromNotification writeParcelable failed.");
            continue;
        }
        sptr<Notification> newNotification = parcel.ReadParcelable<Notification>();
        if (newNotification == nullptr) {
            ANS_LOGE("GetRequestsFromNotification null notification");
            continue;
        }
        requests.push_back(newNotification->GetNotificationRequestPoint());
    }
}
}  // namespace Notification
}  // namespa OHOS