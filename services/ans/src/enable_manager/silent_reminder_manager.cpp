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

#include "advanced_notification_service.h"

#include "accesstoken_kit.h"
#include "access_token_helper.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_permission_def.h"

#include "bundle_manager_helper.h"
#include "ipc_skeleton.h"

#include "notification_preferences.h"
#include "notification_bundle_option.h"
#include "notification_analytics_util.h"
#include "os_account_manager_helper.h"
#include "notification_extension_wrapper.h"

namespace OHOS {
namespace Notification {

ErrCode AdvancedNotificationService::SetSilentReminderEnabled(const sptr<NotificationBundleOption> &bundleOption,
    const bool enabled)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_25, EventBranchId::BRANCH_0);
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr) {
        ANS_LOGE("BundleOption is null.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_INVALID_BUNDLE));
        return ERR_ANS_INVALID_BUNDLE;
    }
 
    message.Message(bundleOption->GetBundleName() + "_" + std::to_string(bundleOption->GetUid()) +
        " silentReminderEnabled:" + std::to_string(enabled));
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("IsSystemApp is false.");
        return ERR_ANS_NON_SYSTEM_APP;
    }
 
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission Denied.");
        return ERR_ANS_PERMISSION_DENIED;
    }
 
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("bundle is nullptr");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_INVALID_BUNDLE));
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        result = NotificationPreferences::GetInstance()->SetSilentReminderEnabled(bundle, enabled);
    }));
    notificationSvrQueue_->wait(handler);
    ANS_LOGI("%{public}s_%{public}d, enabled: %{public}s, "
        "SetSilentReminderEnabled result: %{public}d", bundleOption->GetBundleName().c_str(),
        bundleOption->GetUid(), std::to_string(enabled).c_str(), result);
    NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(result).BranchId(BRANCH_3));
 
    return result;
}
 
ErrCode AdvancedNotificationService::IsSilentReminderEnabled(const sptr<NotificationBundleOption> &bundleOption,
    int32_t &enableStatusInt)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr) {
        ANS_LOGE("BundleOption is null.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    NotificationConstant::SWITCH_STATE enableStatus;
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

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        result = NotificationPreferences::GetInstance()->IsSilentReminderEnabled(bundle, enableStatus);
        enableStatusInt = static_cast<int32_t>(enableStatus);
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

} // Notification
} // OHOS