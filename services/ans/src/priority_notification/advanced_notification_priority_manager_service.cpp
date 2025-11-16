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

#include "access_token_helper.h"
#include "ans_permission_def.h"
#include "bool_wrapper.h"
#include "ipc_skeleton.h"
#include "notification_ai_extension_wrapper.h"
#include "notification_preferences.h"
#include "notification_subscriber_manager.h"

namespace OHOS {
namespace Notification {
ErrCode AdvancedNotificationService::SetPriorityEnabled(const bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_25);
    message.Message(" en:" + std::to_string(enabled));
    auto result = SystemPermissionCheck();
    if (result != ERR_OK) {
        message.ErrorCode(result).Append(" Permission denied");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return result;
    }
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
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    ANS_LOGI("SetPriorityEnabled enabled: %{public}d, result: %{public}d", enabled, result);
    return result;
}

ErrCode AdvancedNotificationService::SetPriorityEnabledByBundle(
    const sptr<NotificationBundleOption> &bundleOption, const int32_t enableStatusInt)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_26);
    message.Message("bundle: " + bundleOption->GetBundleName() + ", id: " +
        std::to_string(bundleOption->GetUid()) + ", en:" + std::to_string(enableStatusInt));
    auto result = SystemPermissionCheck();
    if (result != ERR_OK) {
        message.ErrorCode(result).Append(" Permission denied");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return result;
    }
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
        message.ErrorCode(ERR_ANS_INVALID_PARAM).Append(" out of range");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_INVALID_PARAM;
    }
    result = NotificationPreferences::GetInstance()->SetPriorityEnabledByBundle(bundle,
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
    ANS_LOGI("SetPriorityEnabledByBundle %{public}s_%{public}d, enableStatus: %{public}d, result: %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), enableStatusInt, result);
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    return result;
}

ErrCode AdvancedNotificationService::IsPriorityEnabled(bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
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
    ANS_LOGD("%{public}s", __FUNCTION__);
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
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), enableStatusInt, result);
    return result;
}

ErrCode AdvancedNotificationService::SystemPermissionCheck()
{
    bool isSubSystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubSystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("Not system app or SA!");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("no permission");
        return ERR_ANS_PERMISSION_DENIED;
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetBundlePriorityConfig(
    const sptr<NotificationBundleOption> &bundleOption, const std::string &value)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_28);
    message.Message("bundle: " + bundleOption->GetBundleName() + ", id: " + std::to_string(bundleOption->GetUid()));
    ErrCode result = SystemPermissionCheck();
    if (result != ERR_OK) {
        message.ErrorCode(result).Append(" Permission denied");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return result;
    }
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("bundle is nullptr");
        message.ErrorCode(ERR_ANS_INVALID_BUNDLE).Append(" bundle name is empty");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_INVALID_BUNDLE;
    }
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
    int32_t aiResult = NOTIFICATION_AI_EXTENSION_WRAPPER->SyncBundleKeywords(bundleOption, value);
    ANS_LOGI("SyncBundleKeywords %{public}s_%{public}d result: %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), aiResult);
    if (aiResult == NOTIFICATION_AI_EXTENSION_WRAPPER->ErrorCode::ERR_FAIL) {
        message.ErrorCode(aiResult).Append(" Sync keyword fail");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_SERVICE_NOT_READY;
    }
    if (aiResult != ERR_OK) {
        message.ErrorCode(aiResult).Append(" Sync keyword fail");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_INVALID_PARAM;
    }
    result = NotificationPreferences::GetInstance()->SetBundlePriorityConfig(bundleOption, value);
#endif
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    return result;
}

ErrCode AdvancedNotificationService::GetBundlePriorityConfig(
    const sptr<NotificationBundleOption> &bundleOption, std::string &value)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    ErrCode result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("bundle is nullptr");
        return ERR_ANS_INVALID_BUNDLE;
    }
    return NotificationPreferences::GetInstance()->GetBundlePriorityConfig(bundleOption, value);
}

#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
void AdvancedNotificationService::UpdatePriorityType(const sptr<NotificationRequest> &request)
{
    if (request == nullptr) {
        ANS_LOGE("UpdatePriorityType request is nullptr");
        return;
    }
    ANS_LOGI("priorityNotificationType: %{public}s", request->GetPriorityNotificationType().c_str());
    if (!IsNeedUpdatePriorityType(request)) {
        return;
    }
    auto extendInfo = request->GetExtendInfo();
    if (extendInfo != nullptr) {
        bool delayUpdate = false;
        AAFwk::IBoolean* ao = AAFwk::IBoolean::Query(extendInfo->GetParam(DELAY_UPDATE_PRIORITY_KEY));
        if (ao != nullptr) {
            delayUpdate = AAFwk::Boolean::Unbox(ao);
        }
        if (delayUpdate) {
            ANS_LOGI("delay update priorityNotificationType");
            // publish by notification ai for delay updating priority
            return;
        }
    }
    std::unordered_map<std::string, sptr<IResult>> results;
    NOTIFICATION_AI_EXTENSION_WRAPPER->UpdateNotification(request, results);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_27);
    for (auto &iter : results) {
        ANS_LOGI("UpdateNotification cmd: %{public}s, \
            returnCode: %{public}d, type: %{public}d, priorityNotificationType: %{public}s", iter.first.c_str(),
            iter.second->returnCode, iter.second->type, request->GetPriorityNotificationType().c_str());
        if (iter.second->returnCode == NOTIFICATION_AI_EXTENSION_WRAPPER->ErrorCode::ERR_OK) {
            continue;
        }
        message.Message("cmd: " + iter.first);
        message.ErrorCode(iter.second->returnCode);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
    }
}

bool AdvancedNotificationService::IsNeedUpdatePriorityType(const sptr<NotificationRequest> &request)
{
    if (request->GetSlotType() == NotificationConstant::SlotType::LIVE_VIEW) {
        return false;
    }
    bool priorityEnabled = true;
    std::string strDisablePriority = NotificationConstant::PriorityNotificationType::OTHER;
    AdvancedNotificationService::GetInstance()->IsPriorityEnabled(priorityEnabled);
    if (!priorityEnabled) {
        ANS_LOGI("Priority enabled is disabled");
        request->SetInnerPriorityNotificationType(strDisablePriority);
        return false;
    }
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("UpdatePriorityType bundleOption null");
        return false;
    }
    if (request->GetOwnerBundleName().empty()) {
        bundleOption->SetBundleName(request->GetCreatorBundleName());
        bundleOption->SetUid(request->GetCreatorUid());
    } else {
        bundleOption->SetBundleName(request->GetOwnerBundleName());
        bundleOption->SetUid(request->GetOwnerUid());
    }
    NotificationConstant::PriorityEnableStatus enableStatus =
        NotificationConstant::PriorityEnableStatus::ENABLE_BY_INTELLIGENT;
    if (NotificationPreferences::GetInstance()->IsPriorityEnabledByBundle(bundleOption, enableStatus) != ERR_OK) {
        ANS_LOGI("GetPriorityEnabledByBundle Preferences fail");
        return false;
    }
    if (enableStatus == NotificationConstant::PriorityEnableStatus::ENABLE) {
        ANS_LOGI("Priority enabled for bundle is enabled");
        request->SetInnerPriorityNotificationType(strDisablePriority);
        return false;
    }
    if (enableStatus == NotificationConstant::PriorityEnableStatus::DISABLE) {
        ANS_LOGI("Priority enabled for bundle is disabled");
        request->SetInnerPriorityNotificationType(strDisablePriority);
        return false;
    }
    return true;
}
#endif
}  // namespace Notification
}  // namespa OHOS