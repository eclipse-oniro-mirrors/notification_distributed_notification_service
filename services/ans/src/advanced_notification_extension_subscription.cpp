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

#include "access_token_helper.h"
#include "advanced_notification_service.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_trace_wrapper.h"
#include "ans_permission_def.h"
#include "bundle_manager_helper.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "errors.h"
#include "ipc_skeleton.h"
#include "notification_preferences.h"
#include "os_account_manager_helper.h"

namespace OHOS {
namespace Notification {
namespace {
constexpr const char* ANS_EXTENSION_SERVICE_MODULE_NAME = "libans_extension_service.z.so";
}

bool AdvancedNotificationService::HasExtensionSubscriptionStateChanged(
    const sptr<NotificationBundleOption> &bundle, bool enabled)
{
    if (bundle == nullptr) {
        return true;
    }
    
    NotificationConstant::SWITCH_STATE state;
    ErrCode result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionEnabled(bundle, state);
    if (result != ERR_OK) {
        return true;
    }
    
    bool oldEnabled = (state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    
    if (state == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF) {
        return true;
    }
    
    return (oldEnabled != enabled);
}
ErrCode AdvancedNotificationService::IsUserGranted(bool& isEnabled)
{
    ANS_LOGD("AdvancedNotificationService::IsUserGranted");
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = AdvancedNotificationService::GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption");
        return ERR_ANS_NO_MEMORY;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    NotificationConstant::SWITCH_STATE state;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionEnabled(bundleOption, state);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to get user granted state for currentbundle ret: %{public}d", result);
            return;
        }
        isEnabled = ((state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) ? true : false);
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::GetUserGrantedState(
    const sptr<NotificationBundleOption>& targetBundle, bool& enabled)
{
    ANS_LOGD("AdvancedNotificationService::GetUserGrantedState");
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = AdvancedNotificationService::GenerateValidBundleOption(targetBundle);
    if (bundle == nullptr) {
        ANS_LOGE("Bundle is null.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    NotificationConstant::SWITCH_STATE state;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionEnabled(bundle, state);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to get user granted state for targetbundle: %{public}s, ret: %{public}d",
                targetBundle->GetBundleName().c_str(), result);
            return;
        }
        enabled = ((state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) ? true : false);
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::SetUserGrantedState(
    const sptr<NotificationBundleOption>& targetBundle, bool enabled)
{
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = AdvancedNotificationService::GenerateValidBundleOption(targetBundle);
    if (bundle == nullptr) {
        ANS_LOGE("Bundle is null.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }

    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        if (!HasExtensionSubscriptionStateChanged(bundle, enabled)) {
            ANS_LOGI("State change for bundle: %{public}s, update and publish.", bundle->GetBundleName().c_str());
        }
        AdvancedNotificationService::GetInstance()->
            PublishExtensionServiceStateChange(NotificationConstant::USER_GRANTED_STATE, bundle, enabled, {});
        NotificationConstant::SWITCH_STATE state = enabled ? NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON
            : NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
        result = NotificationPreferences::GetInstance()->SetExtensionSubscriptionEnabled(bundle, state);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to set user granted state for targetbundle: %{public}s, ret: %{public}d",
                bundle->GetBundleName().c_str(), result);
        }
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}
}  // namespace Notification
}  // namespace OHOS
