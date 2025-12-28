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

#include <functional>
#include <iomanip>
#include <sstream>

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "access_token_helper.h"
#include "ans_permission_def.h"
#include "bundle_manager_helper.h"
#include "notification_constant.h"
#include "errors.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"
#include "notification_bundle_option.h"
#include "notification_preferences.h"
#include "os_account_manager_helper.h"
#include "notification_do_not_disturb_date.h"
#include "notification_analytics_util.h"
#include "../advanced_notification_inline.cpp"

namespace OHOS {
namespace Notification {

ErrCode AdvancedNotificationService::GetDoNotDisturbDate(sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    return GetDoNotDisturbDateByUser(userId, date);
}

ErrCode AdvancedNotificationService::GetDoNotDisturbDate(int32_t userId,
    sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    return GetDoNotDisturbDateByUser(userId, date);
}

ErrCode AdvancedNotificationService::GetDoNotDisturbDateByUser(const int32_t &userId,
    sptr<NotificationDoNotDisturbDate> &date)
{
    ErrCode result = ERR_OK;
    auto submitResult = notificationSvrQueue_.SyncSubmit(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<NotificationDoNotDisturbDate> currentConfig = nullptr;
        result = NotificationPreferences::GetInstance()->GetDoNotDisturbDate(userId, currentConfig);
        if (result != ERR_OK) {
            return;
        }
        int64_t now = GetCurrentTime();
        switch (currentConfig->GetDoNotDisturbType()) {
            case NotificationConstant::DoNotDisturbType::CLEARLY:
            case NotificationConstant::DoNotDisturbType::ONCE:
                if (now >= currentConfig->GetEndDate()) {
                    date = new (std::nothrow) NotificationDoNotDisturbDate(
                        NotificationConstant::DoNotDisturbType::NONE, 0, 0);
                    if (date == nullptr) {
                        ANS_LOGE("Failed to create NotificationDoNotDisturbDate instance");
                        return;
                    }
                    NotificationPreferences::GetInstance()->SetDoNotDisturbDate(userId, date);
                    return;
                } else {
                    date = currentConfig;
                }
                break;
            default:
                date = currentConfig;
                break;
        }
    }));
    ANS_COND_DO_ERR(submitResult != ERR_OK, return submitResult, "Get donot disturb date by user.");
    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetDoNotDisturbDate(const sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("Not system app!");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Check permission denied!");
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGE("No active user found!");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    return SetDoNotDisturbDateByUser(userId, date);
}

ErrCode AdvancedNotificationService::SetDoNotDisturbDate(int32_t userId,
    const sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_14, EventBranchId::BRANCH_16);
    message.Message("userId:" + std::to_string(userId));
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalidity.");
        message.ErrorCode(ERR_ANS_INVALID_PARAM);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_INVALID_PARAM;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    return SetDoNotDisturbDateByUser(userId, date);
}

ErrCode AdvancedNotificationService::SetDoNotDisturbDateByUser(const int32_t &userId,
    const sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("%{public}s enter, userId = %{public}d", __FUNCTION__, userId);
    if (date == nullptr) {
        ANS_LOGE("Invalid date param");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;

    int64_t beginDate = ResetSeconds(date->GetBeginDate());
    int64_t endDate = ResetSeconds(date->GetEndDate());
    switch (date->GetDoNotDisturbType()) {
        case NotificationConstant::DoNotDisturbType::NONE:
            beginDate = 0;
            endDate = 0;
            break;
        case NotificationConstant::DoNotDisturbType::ONCE:
            AdjustDateForDndTypeOnce(beginDate, endDate);
            break;
        case NotificationConstant::DoNotDisturbType::CLEARLY:
            if (beginDate >= endDate) {
                return ERR_ANS_INVALID_PARAM;
            }
            break;
        default:
            break;
    }
    ANS_LOGD("Before set SetDoNotDisturbDate beginDate = %{public}" PRId64 ", endDate = %{public}" PRId64,
             beginDate, endDate);
    const sptr<NotificationDoNotDisturbDate> newConfig = new (std::nothrow) NotificationDoNotDisturbDate(
        date->GetDoNotDisturbType(),
        beginDate,
        endDate
    );
    if (newConfig == nullptr) {
        ANS_LOGE("Failed to create NotificationDoNotDisturbDate instance");
        return ERR_NO_MEMORY;
    }
    std::string bundle = GetClientBundleName();

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Generate invalid bundle option!");
        return ERR_ANS_INVALID_BUNDLE;
    }

    auto submitResult = notificationSvrQueue_.SyncSubmit(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->SetDoNotDisturbDate(userId, newConfig);
        if (result == ERR_OK) {
            NotificationSubscriberManager::GetInstance()->NotifyDoNotDisturbDateChanged(userId, newConfig, bundle);
        }
    }));
    ANS_COND_DO_ERR(submitResult != ERR_OK, return submitResult, "Set donot disturb date by user.");

    return ERR_OK;
}

ErrCode AdvancedNotificationService::AddDoNotDisturbProfilesInner(
    const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles, int32_t userId)
{
    ANS_LOGD("Called.");
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }
    auto submitResult = notificationSvrQueue_.SyncSubmit(
        std::bind([copyUserId = userId, copyProfiles = profiles]() {
            ANS_LOGD("The ffrt enter.");
            NotificationPreferences::GetInstance()->AddDoNotDisturbProfiles(copyUserId, copyProfiles);
        }));
    ANS_COND_DO_ERR(submitResult != ERR_OK, return submitResult, "Add donot disturb prifile.");
    return ERR_OK;
}

ErrCode AdvancedNotificationService::AddDoNotDisturbProfiles(
    const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGE("No active user found.");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }
    return AddDoNotDisturbProfilesInner(profiles, userId);
}

ErrCode AdvancedNotificationService::AddDoNotDisturbProfiles(
    const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles, const int32_t userId)
{
    ANS_LOGD("Called.");
    if (!OsAccountManagerHelper::GetInstance().CheckUserExists(userId)) {
        ANS_LOGE("Check user exists failed.");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }
    return AddDoNotDisturbProfilesInner(profiles, userId);
}

ErrCode AdvancedNotificationService::RemoveDoNotDisturbProfilesInner(
    const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles, const int32_t userId)
{
    ANS_LOGD("Called.");
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }
    auto submitResult = notificationSvrQueue_.SyncSubmit(
        std::bind([copyUserId = userId, copyProfiles = profiles]() {
            ANS_LOGD("The ffrt enter.");
            NotificationPreferences::GetInstance()->RemoveDoNotDisturbProfiles(copyUserId, copyProfiles);
        }));
    ANS_COND_DO_ERR(submitResult != ERR_OK, return submitResult, "Remove donot disturb prifile.");
    return ERR_OK;
}

ErrCode AdvancedNotificationService::RemoveDoNotDisturbProfiles(
    const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGE("No active user found.");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }
    return RemoveDoNotDisturbProfilesInner(profiles, userId);
}

ErrCode AdvancedNotificationService::RemoveDoNotDisturbProfiles(
    const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles, const int32_t userId)
{
    ANS_LOGD("Called.");
    if (!OsAccountManagerHelper::GetInstance().CheckUserExists(userId)) {
        ANS_LOGE("Check user exists failed.");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }
    return RemoveDoNotDisturbProfilesInner(profiles, userId);
}

ErrCode AdvancedNotificationService::GetDoNotDisturbProfileInner(
    int64_t id, sptr<NotificationDoNotDisturbProfile> &profile, const int32_t userId)
{
    ANS_LOGD("Called.");
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    ErrCode result = NotificationPreferences::GetInstance()->GetDoNotDisturbProfile(id, userId, profile);
    if (result != ERR_OK) {
        ANS_LOGE("profile failed id: %{public}s, userid: %{public}d", std::to_string(id).c_str(), userId);
    }
    return result;
}

ErrCode AdvancedNotificationService::GetDoNotDisturbProfile(int64_t id, sptr<NotificationDoNotDisturbProfile> &profile)
{
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGE("No active user found.");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }
    return GetDoNotDisturbProfileInner(id, profile, userId);
}

ErrCode AdvancedNotificationService::GetDoNotDisturbProfile(
    int64_t id, sptr<NotificationDoNotDisturbProfile> &profile, const int32_t userId)
{
    ANS_LOGD("Called.");
    if (!OsAccountManagerHelper::GetInstance().CheckUserExists(userId)) {
        ANS_LOGE("Check user exists failed.");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }
    return GetDoNotDisturbProfileInner(id, profile, userId);
}

ErrCode AdvancedNotificationService::DoesSupportDoNotDisturbMode(bool &doesSupport)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    doesSupport = SUPPORT_DO_NOT_DISTRUB;
    return ERR_OK;
}

}  // namespace Notification
}  // namespace OHOS
