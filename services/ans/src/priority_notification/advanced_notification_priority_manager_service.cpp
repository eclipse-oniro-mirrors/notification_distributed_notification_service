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

#include "access_token_helper.h"
#include "ans_permission_def.h"
#include "ipc_skeleton.h"
#include "notification_ai_extension_wrapper.h"
#include "notification_preferences.h"

namespace OHOS {
namespace Notification {
ErrCode AdvancedNotificationService::SetPriorityEnabled(const bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    auto result = SystemSwitchPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    result = NotificationPreferences::GetInstance()->SetPriorityEnabled(
        enabled ? NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON
        : NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);

    ANS_LOGI("SetPriorityEnabled enabled: %{public}d, result: %{public}d", enabled, result);
    return result;
}

ErrCode AdvancedNotificationService::SetPriorityEnabledByBundle(
    const sptr<NotificationBundleOption> &bundleOption, const bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    auto result = SystemSwitchPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("bundle is nullptr");
        return ERR_ANS_INVALID_BUNDLE;
    }
    result = NotificationPreferences::GetInstance()->SetPriorityEnabledByBundle(bundle,
        enabled ? NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON :
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
    ANS_LOGI("%{public}s_%{public}d, enabled: %{public}d, SetDistributedEnabledByBundle result: %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), enabled, result);
    return result;
}

ErrCode AdvancedNotificationService::IsPriorityEnabled(bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    auto result = SystemSwitchPermissionCheck();
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
    const sptr<NotificationBundleOption> &bundleOption, bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    auto result = SystemSwitchPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("bundle is nullptr");
        return ERR_ANS_INVALID_BUNDLE;
    }
    NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
    result = NotificationPreferences::GetInstance()->IsPriorityEnabledByBundle(bundle, enableStatus);
    enabled = (enableStatus == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON ||
        enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    ANS_LOGI("%{public}s_%{public}d, enabled: %{public}d, IsPriorityEnabledByBundle result: %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), enabled, result);
    return result;
}

ErrCode AdvancedNotificationService::SystemSwitchPermissionCheck()
{
    bool isSubSystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubSystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("Not system app or SA!");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("no permission");
        return ERR_ANS_PERMISSION_DENIED;
    }
    return ERR_OK;
}

#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
void AdvancedNotificationService::UpdatePriorityType(const sptr<NotificationRequest> &request)
{
    ANS_LOGI("priorityNotificationType: %{public}s", request->GetPriorityNotificationType().c_str());
    if (request->GetSlotType() == NotificationConstant::SlotType::LIVE_VIEW) {
        return;
    }
    bool priorityEnabled = true;
    AdvancedNotificationService::GetInstance()->IsPriorityEnabled(priorityEnabled);
    if (!priorityEnabled) {
        ANS_LOGI("Priority enabled is close");
        request->SetPriorityNotificationType(NotificationRequest::PriorityNotificationType::OTHER);
        return;
    }
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("UpdatePriorityType bundleOption null");
        return;
    }
    if (request->GetOwnerBundleName().empty()) {
        bundleOption->SetBundleName(request->GetCreatorBundleName());
        bundleOption->SetUid(request->GetCreatorUid());
    } else {
        bundleOption->SetBundleName(request->GetOwnerBundleName());
        bundleOption->SetUid(request->GetOwnerUid());
    }
    AdvancedNotificationService::GetInstance()->IsPriorityEnabledByBundle(bundleOption, priorityEnabled);
    if (!priorityEnabled) {
        ANS_LOGI("Priority enabled for bundle is close");
        request->SetPriorityNotificationType(NotificationRequest::PriorityNotificationType::OTHER);
        return;
    }
    std::unordered_map<std::string, sptr<IResult>> results;
    NOTIFICATION_AI_EXTENSION_WRAPPER->UpdateNotification(request, results);
    for (auto iter : results) {
        ANS_LOGI("UpdateNotification cmd: %{public}s, \
            returnCode: %{public}d, type: %{public}d, priorityNotificationType: %{public}s", iter.first.c_str(),
            iter.second->returnCode, iter.second->type, request->GetPriorityNotificationType().c_str());
    }
}
#endif
}  // namespace Notification
}  // namespa OHOS