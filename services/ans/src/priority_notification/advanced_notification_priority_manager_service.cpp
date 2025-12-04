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
    auto result = NotificationPreferences::GetInstance()->SetPriorityEnabled(
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
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_25);
    message.Message("en:" + std::to_string(enabled));
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    ANS_LOGI("SetPriorityEnabled enabled: %{public}d, result: %{public}d", enabled, result);
    return result;
}

ErrCode AdvancedNotificationService::SetPriorityEnabledByBundle(
    const sptr<NotificationBundleOption> &bundleOption, const int32_t enableStatusInt)
{
    auto result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    return SetPriorityEnabledByBundleInner(bundleOption, enableStatusInt);
}

ErrCode AdvancedNotificationService::SetPriorityEnabledByBundleInner(
    const sptr<NotificationBundleOption> &bundleOption, const int32_t enableStatusInt)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_26);
    message.Message("bundle: " + bundleOption->GetBundleName() + ", id: " +
        std::to_string(bundleOption->GetUid()) + ", en:" + std::to_string(enableStatusInt));
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("bundle is nullptr");
        message.ErrorCode(ERR_ANS_INVALID_BUNDLE).Append(" bundle name is empty");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_INVALID_BUNDLE;
    }
    if (enableStatusInt < static_cast<int32_t>(NotificationConstant::PriorityEnableStatus::DISABLE) ||
        enableStatusInt > static_cast<int32_t>(NotificationConstant::PriorityEnableStatus::ENABLE)) {
        ANS_LOGE("EnableStatus out of range %{public}d.", enableStatusInt);
        return ERR_ANS_INVALID_PARAM;
    }
    auto result = NotificationPreferences::GetInstance()->SetPriorityEnabledByBundle(bundle,
        static_cast<NotificationConstant::PriorityEnableStatus>(enableStatusInt));
    sptr<EnabledPriorityNotificationByBundleCallbackData> bundleData =
        new (std::nothrow) EnabledPriorityNotificationByBundleCallbackData(bundle->GetBundleName(),
        bundle->GetUid(), static_cast<NotificationConstant::PriorityEnableStatus>(enableStatusInt));
    if (bundleData == nullptr) {
        ANS_LOGE("Failed to create EnabledPriorityNotificationByBundleCallbackData instance");
        result = ERR_NO_MEMORY;
    } else {
        NotificationSubscriberManager::GetInstance()->NotifyEnabledPriorityByBundleChanged(bundleData);
    }
    ANS_LOGI("SetPriorityEnabledByBundle %{public}s_%{public}d, enableStatus: %{public}d, result: %{public}d",
        bundle->GetBundleName().c_str(), bundle->GetUid(), enableStatusInt, result);
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

ErrCode AdvancedNotificationService::SetBundlePriorityConfig(
    const sptr<NotificationBundleOption> &bundleOption, const std::string &value)
{
    ErrCode result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    return SetBundlePriorityConfigInner(bundleOption, value);
}

ErrCode AdvancedNotificationService::SetBundlePriorityConfigInner(
    const sptr<NotificationBundleOption> &bundleOption, const std::string &value)
{
    ErrCode result = ERR_OK;
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_28);
    message.Message("bundle: " + bundleOption->GetBundleName() + ", id: " + std::to_string(bundleOption->GetUid()));
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("bundle is nullptr");
        message.ErrorCode(ERR_ANS_INVALID_BUNDLE).Append(" bundle name is empty");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_INVALID_BUNDLE;
    }
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
    int32_t aiResult = NOTIFICATION_AI_EXTENSION_WRAPPER->SyncBundleKeywords(bundle, value);
    ANS_LOGI("SyncBundleKeywords %{public}s_%{public}d result: %{public}d",
        bundle->GetBundleName().c_str(), bundle->GetUid(), aiResult);
    message.ErrorCode(aiResult).Append(" Sync keyword fail");
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    if (aiResult == NOTIFICATION_AI_EXTENSION_WRAPPER->ErrorCode::ERR_FAIL) {
        return ERR_ANS_SERVICE_NOT_READY;
    }
    if (aiResult != ERR_OK) {
        return ERR_ANS_INVALID_PARAM;
    }
    result = NotificationPreferences::GetInstance()->SetBundlePriorityConfig(bundle, value);
#endif
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
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
}  // namespace Notification
}  // namespa OHOS