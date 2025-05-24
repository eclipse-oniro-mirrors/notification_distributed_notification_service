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

#include "errors.h"
#include "ans_log_wrapper.h"
#include "access_token_helper.h"
#include "notification_preferences.h"
#include "notification_analytics_util.h"
#include "badge_number_callback_data.h"
#include "advanced_notification_inline.h"
#include "notification_subscriber_manager.h"
#include "enabled_notification_callback_data.h"

#include "ipc_skeleton.h"

namespace OHOS {
namespace Notification {

constexpr int32_t BADGE_NUM_LIMIT = 0;

ErrCode AdvancedNotificationService::SetNotificationBadgeNum(int32_t num)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGD("BundleOption is null.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(
        std::bind([&]() {
            ANS_LOGD("ffrt enter!");
            result = NotificationPreferences::GetInstance()->SetTotalBadgeNums(bundleOption, num);
        }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::SetShowBadgeEnabledForBundle(
    const sptr<NotificationBundleOption> &bundleOption, bool enabled)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_13, EventBranchId::BRANCH_0);
    if (bundleOption == nullptr) {
        ANS_LOGE("BundleOption is null.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_INVALID_BUNDLE));
        return ERR_ANS_INVALID_BUNDLE;
    }

    message.Message(bundleOption->GetBundleName() + "_" + std::to_string(bundleOption->GetUid()) +
        " en" + std::to_string(enabled));

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("IsSystemApp is false.");
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).BranchId(BRANCH_1);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission Denied.");
        message.ErrorCode(ERR_ANS_PERMISSION_DENIED).BranchId(BRANCH_2);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("Bundle is nullptr.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(
        std::bind([&]() {
            ANS_LOGD("ffrt enter!");
            result = NotificationPreferences::GetInstance()->SetShowBadge(bundle, enabled);
            if (result == ERR_OK) {
                HandleBadgeEnabledChanged(bundle, enabled);
            }
        }));
    notificationSvrQueue_->wait(handler);
    ANS_LOGI("%{public}s_%{public}d, enabled: %{public}s, Set show badge enabled for bundle result: %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), std::to_string(enabled).c_str(), result);
    message.ErrorCode(result).BranchId(BRANCH_3);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    return result;
}

void AdvancedNotificationService::HandleBadgeEnabledChanged(
    const sptr<NotificationBundleOption> &bundleOption, bool enabled)
{
    sptr<EnabledNotificationCallbackData> enabledData = new (std::nothrow)
        EnabledNotificationCallbackData(bundleOption->GetBundleName(), bundleOption->GetUid(), enabled);
    if (enabledData == nullptr) {
        ANS_LOGE("Failed to create badge enabled data object.");
        return;
    }

    NotificationSubscriberManager::GetInstance()->NotifyBadgeEnabledChanged(enabledData);
}

ErrCode AdvancedNotificationService::GetShowBadgeEnabledForBundle(
    const sptr<NotificationBundleOption> &bundleOption, bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("VerifyNativeToken is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGD("Failed to generateValidBundleOption.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->IsShowBadge(bundle, enabled);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            enabled = true;
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::GetShowBadgeEnabled(bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is ineffective.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->IsShowBadge(bundleOption, enabled);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            enabled = true;
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::SetBadgeNumber(int32_t badgeNumber, const std::string &instanceKey)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    std::string bundleName = GetClientBundleName();
    ANS_LOGD("SetBadgeNumber receive instanceKey:%{public}s", instanceKey.c_str());
    sptr<BadgeNumberCallbackData> badgeData = new (std::nothrow) BadgeNumberCallbackData(
        bundleName, instanceKey, callingUid, badgeNumber);
    if (badgeData == nullptr) {
        ANS_LOGE("Failed to create BadgeNumberCallbackData.");
        return ERR_ANS_NO_MEMORY;
    }

    ffrt::task_handle handler = notificationSvrQueue_->submit_h([&]() {
        ANS_LOGD("ffrt enter!");
        NotificationSubscriberManager::GetInstance()->SetBadgeNumber(badgeData);
    });
    notificationSvrQueue_->wait(handler);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetBadgeNumberForDhByBundle(
    const sptr<NotificationBundleOption> &bundleOption, int32_t badgeNumber)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("SetBadgeNumberForDhByBundle bundleOption is null");
        return ERR_ANS_INVALID_PARAM;
    }
    if (bundleOption->GetBundleName().empty()) {
        ANS_LOGE("SetBadgeNumberForDhByBundle Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }
    if (bundleOption->GetUid() <= DEFAULT_UID) {
        ANS_LOGE("SetBadgeNumberForDhByBundle invalid uid");
        return ERR_ANS_INVALID_PARAM;
    }
    if (badgeNumber < BADGE_NUM_LIMIT) {
        ANS_LOGE("SetBadgeNumberForDhByBundle invalid badgeNumber");
        return ERR_ANS_INVALID_PARAM;
    }
    ANS_LOGI("SetBadgeNumberForDhByBundle bundleName = %{public}s uid = %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid());
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_7, EventBranchId::BRANCH_6);
    message.Message(bundleOption->GetBundleName() + "_" +std::to_string(bundleOption->GetUid()) +
        " badgeNumber: " + std::to_string(badgeNumber));
    if (notificationSvrQueue_ == nullptr) {
        return ERR_ANS_INVALID_PARAM;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).Append(" Not system app.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("Not system app.");
        return ERR_ANS_NON_SYSTEM_APP;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<BadgeNumberCallbackData> badgeData = new (std::nothrow) BadgeNumberCallbackData(
            bundleOption->GetBundleName(), bundleOption->GetUid(), badgeNumber);
        if (badgeData == nullptr) {
            ANS_LOGE("Failed to create badge number callback data.");
            result = ERR_ANS_NO_MEMORY;
        }
        NotificationSubscriberManager::GetInstance()->SetBadgeNumber(badgeData);
    });
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::SetBadgeNumberByBundle(
    const sptr<NotificationBundleOption> &bundleOption, int32_t badgeNumber)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_7, EventBranchId::BRANCH_6);
    message.Message(bundleOption->GetBundleName() + "_" +std::to_string(bundleOption->GetUid()) +
        " badgeNumber: " + std::to_string(badgeNumber));
    if (notificationSvrQueue_ == nullptr) {
        return ERR_ANS_INVALID_PARAM;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).Append(" Not system app.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("Not system app.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    sptr<NotificationBundleOption> bundle = bundleOption;
    ErrCode result = CheckBundleOptionValid(bundle);
    if (result != ERR_OK) {
        ANS_LOGE("Bundle is invalid.");
        return result;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER)) {
        std::string bundleName = GetClientBundleName();
        if (bundleName.empty()) {
            ANS_LOGE("Failed to get client bundle name.");
            return result;
        }
        bool isAgent = false;
        isAgent = IsAgentRelationship(bundleName, bundle->GetBundleName());
        if (!isAgent) {
            message.ErrorCode(ERR_ANS_NO_AGENT_SETTING).Append(" No agent setting.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            ANS_LOGE("No agent setting.");
            return ERR_ANS_NO_AGENT_SETTING;
        }
    }

    ffrt::task_handle handler = notificationSvrQueue_->submit_h([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<BadgeNumberCallbackData> badgeData = new (std::nothrow) BadgeNumberCallbackData(
            bundle->GetBundleName(), bundle->GetUid(), badgeNumber);
        if (badgeData == nullptr) {
            ANS_LOGE("Failed to create badge number callback data.");
            result = ERR_ANS_NO_MEMORY;
        }
        NotificationSubscriberManager::GetInstance()->SetBadgeNumber(badgeData);
    });
    notificationSvrQueue_->wait(handler);
    return result;
}
} // Notification
} // OHOS