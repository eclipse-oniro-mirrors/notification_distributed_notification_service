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
#include "os_account_manager_helper.h"
#include "system_sound_helper.h"

namespace {
static const uint64_t DEL_TASK_DELAY = 5 * 1000;
}
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
        ringtoneInfo->GetRingtoneType() >= NotificationConstant::RingtoneType::RINGTONE_TYPE_BUTT) {
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
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }

    NotificationPreferences::GetInstance()->RemoveRingtoneInfoByBundle(bundleOption);

    ReportRingtoneChanged(
        bundleOption, ringtoneInfo, NotificationConstant::RingtoneReportType::RINGTONE_UPDATE);

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
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }

    ClearOverTimeRingToneInfo();
    ringtoneInfo = new (std::nothrow) NotificationRingtoneInfo();
    return NotificationPreferences::GetInstance()->GetRingtoneInfoByBundle(bundleOption, ringtoneInfo);
}

void AdvancedNotificationService::ClearOverTimeRingToneInfo()
{
    int64_t curTime = NotificationAnalyticsUtil::GetCurrentTime();
    int64_t cloneTime = NotificationPreferences::GetInstance()->GetCloneTimeStamp();
    if (cloneTime != 0 && cloneTime < curTime && (curTime - cloneTime) >=
        NotificationConstant::MAX_CLONE_TIME) {
        if (notificationSvrQueue_ == nullptr) {
            ANS_LOGE("Invalid ffrt queue.");
            return;
        }
        ANS_LOGI("Start clear overtime ringinfo.");
        notificationSvrQueue_->submit_h(std::bind([&]() {
            int32_t userId = -1;
            if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
                ANS_LOGE("Failed to get active user id!");
                return;
            }
            std::vector<NotificationRingtoneInfo> cloneRingtoneInfos;
            NotificationPreferences::GetInstance()->GetAllCloneRingtoneInfo(userId, cloneRingtoneInfos);
            SystemSoundHelper::GetInstance()->RemoveCustomizedTones(cloneRingtoneInfos);
            NotificationPreferences::GetInstance()->DeleteAllCloneRingtoneInfo(userId);

            // clear dh data
            cloneRingtoneInfos.clear();
            NotificationPreferences::GetInstance()->GetAllCloneRingtoneInfo(ZERO_USERID, cloneRingtoneInfos);
            SystemSoundHelper::GetInstance()->RemoveCustomizedTones(cloneRingtoneInfos);
            NotificationPreferences::GetInstance()->DeleteAllCloneRingtoneInfo(ZERO_USERID);
            NotificationPreferences::GetInstance()->SetCloneTimeStamp(userId, 0);
            ANS_LOGI("Clear overtime ringinfo %{public}d", userId);
        }),
            ffrt::task_attr().name("ringtone").delay(DEL_TASK_DELAY));
    }
}
}  // namespace Notification
}  // namespace OHOS
