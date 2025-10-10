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

#include "access_token_helper.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_trace_wrapper.h"
#include "ans_permission_def.h"
#include "ipc_skeleton.h"
#include "notification_constant.h"
#include "notification_preferences.h"

namespace OHOS {
namespace Notification {
ErrCode AdvancedNotificationService::SetRingtoneInfoByBundle(const sptr<NotificationBundleOption> &bundle,
    const sptr<NotificationRingtoneInfo> &ringtoneInfo)
{
    bool isSubSystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubSystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("Not system app or SA!");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Not have OHOS_PERMISSION_NOTIFICATION_CONTROLLER Permission!");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (ringtoneInfo == nullptr ||
        ringtoneInfo->GetRingtoneType() < NotificationConstant::RingtoneType::RINGTONE_TYPE_SYSTEM ||
        ringtoneInfo->GetRingtoneType() >= NotificationConstant::RingtoneType::RINGTONE_CUSTOM_BUTT) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (bundle->GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateValidBundleOption(bundle);
    if (bundleOption == nullptr) {
        ANS_LOGE("Bundle is null.");
        return ERR_ANS_SPECIFIED_BUNDLE_INVALID;
    }

    NotificationPreferences::GetInstance()->RemoveRingtoneInfoByBundle(bundleOption);

    return NotificationPreferences::GetInstance()->SetRingtoneInfoByBundle(bundleOption, ringtoneInfo);
}

ErrCode AdvancedNotificationService::GetRingtoneInfoByBundle(const sptr<NotificationBundleOption> &bundle,
    sptr<NotificationRingtoneInfo> &ringtoneInfo)
{
    bool isSubSystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubSystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("Not system app or SA!");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Not have OHOS_PERMISSION_NOTIFICATION_CONTROLLER Permission!");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (bundle->GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateValidBundleOption(bundle);
    if (bundleOption == nullptr) {
        ANS_LOGE("Bundle is null.");
        return ERR_ANS_SPECIFIED_BUNDLE_INVALID;
    }

    ringtoneInfo = new (std::nothrow) NotificationRingtoneInfo();
    return NotificationPreferences::GetInstance()->GetRingtoneInfoByBundle(bundleOption, ringtoneInfo);
}
}  // namespace Notification
}  // namespace OHOS
