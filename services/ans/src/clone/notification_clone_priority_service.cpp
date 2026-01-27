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

#include "notification_clone_priority_service.h"

#include "advanced_notification_service.h"
#include "ans_const_define.h"
#include "ans_log_wrapper.h"
#include "notification_preferences.h"
#include "notification_clone_util.h"
#include "parameters.h"

namespace OHOS {
namespace Notification {
constexpr int32_t INVALID_APP_INDEX = -1;

std::shared_ptr<NotificationClonePriority> NotificationClonePriority::GetInstance()
{
    static std::shared_ptr<NotificationClonePriority> instance =
        std::make_shared<NotificationClonePriority>();
    return instance;
}

ErrCode NotificationClonePriority::OnBackup(nlohmann::json &jsonObject)
{
    bool isSupportPriority =
        (OHOS::system::GetParameter("const.systemui.priority_notification_enabled", "false") == "true");
    if (!isSupportPriority) {
        ANS_LOGI("OnBackup not support Priority.");
        return ERR_OK;
    }
    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    std::vector<NotificationClonePriorityInfo> cloneInfos;
    NotificationPreferences::GetInstance()->GetAllClonePriorityInfo(userId, cloneInfos);
    if (cloneInfos.empty()) {
        ANS_LOGI("Notification priority info is empty.");
        return ERR_OK;
    }
    jsonObject = nlohmann::json::array();
    for (auto &cloneInfo : cloneInfos) {
        nlohmann::json jsonNode;
        cloneInfo.ToJson(jsonNode);
        jsonObject.emplace_back(jsonNode);
        ANS_LOGD("backup clone info: %{public}s.", cloneInfo.Dump().c_str());
    }
    return ERR_OK;
}

void NotificationClonePriority::OnRestoreEnd(int32_t userId)
{
    std::unique_lock lock(lock_);
    if (!priorityInfo_.empty()) {
        NotificationPreferences::GetInstance()->DelClonePriorityInfos(userId, priorityInfo_);
        priorityInfo_.clear();
    }
    clonedSystemApps_.clear();
    coverdPriorityInfo_.clear();
    fromUnSupportPriority_ = false;
    ANS_LOGW("Priority on clear Restore");
}

void NotificationClonePriority::OnRestore(const nlohmann::json &jsonObject, std::set<std::string> systemApps)
{
    if (jsonObject.is_null() || !jsonObject.is_array()) {
        ANS_LOGI("Notification disturb profile list is null or not array.");
        IsFromUnSupportPriority(systemApps);
        return;
    }
    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    std::unique_lock lock(lock_);
    if (!priorityInfo_.empty()) {
        NotificationPreferences::GetInstance()->DelClonePriorityInfos(userId, priorityInfo_);
        priorityInfo_.clear();
    }
    for (const auto &jsonNode : jsonObject) {
        NotificationClonePriorityInfo cloneInfo;
        if (!cloneInfo.FromJson(jsonNode)) {
            continue;
        }
        priorityInfo_.emplace_back(cloneInfo);
    }
    ANS_LOGI("NotificationClonePriority OnRestore priorityInfo size %{public}zu.", priorityInfo_.size());
    if (IsFromUnSupportPriority(systemApps)) {
        return;
    }
    clonedSystemApps_.clear();
    BatchSetDefaultPriorityInfo(systemApps, userId);
    for (auto iter = priorityInfo_.begin(); iter != priorityInfo_.end();) {
        if (iter->GetClonePriorityType() == NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_ENABLE) {
            AdvancedNotificationService::GetInstance()->SetPriorityEnabledInner(
                iter->GetSwitchState() == static_cast<int32_t>(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) ||
                iter->GetSwitchState() == static_cast<int32_t>(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON));
            iter = priorityInfo_.erase(iter);
            continue;
        }
        if (systemApps.find(iter->GetBundleName()) == systemApps.end()) {
            iter++;
            continue;
        }
        int32_t uid = NotificationCloneUtil::GetBundleUid(iter->GetBundleName(), userId, iter->GetAppIndex());
        if (uid <= DEFAULT_UID) {
            ANS_LOGW("OnRestore systemApps priorityInfo fail, GetBundleUid fail");
            iter++;
            continue;
        }
        clonedSystemApps_.insert(iter->GetBundleName());
        RestoreBundlePriorityInfo(uid, *iter);
        iter = priorityInfo_.erase(iter);
    }
    NotificationPreferences::GetInstance()->UpdateClonePriorityInfos(userId, priorityInfo_);
}

void NotificationClonePriority::BatchSetDefaultPriorityInfo(
    const std::set<std::string> &bundleNames, const int32_t userId)
{
    for (std::string bundleName : bundleNames) {
        int32_t uid = NotificationCloneUtil::GetBundleUid(bundleName, userId, INVALID_APP_INDEX);
        if (uid <= DEFAULT_UID) {
            continue;
        }
        SetDefaultPriorityInfo(uid, bundleName);
    }
}

void NotificationClonePriority::SetDefaultPriorityInfo(const int32_t uid, const std::string &bundleName)
{
    sptr<NotificationBundleOption> bo = new (std::nothrow) NotificationBundleOption(bundleName, uid);
    if (bo == nullptr) {
        ANS_LOGW("null bundleOption");
        return;
    }
    // Only cloned from unsupport priority device need restore coverdInfo cause OnRestoreStart execute before OnRestore.
    if (priorityInfo_.empty()) {
        std::string configValue;
        NotificationPreferences::GetInstance()->GetBundlePriorityConfig(bo, configValue);
        NotificationConstant::PriorityEnableStatus enableStatus =
            NotificationConstant::PriorityEnableStatus::ENABLE_BY_INTELLIGENT;
        NotificationPreferences::GetInstance()->IsPriorityEnabledByBundle(bo, enableStatus);
        if (!configValue.empty()) {
            InsertCoverdInfo(uid, bundleName, configValue, enableStatus,
                NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_CONFIG);
        }
        if (enableStatus != NotificationConstant::PriorityEnableStatus::ENABLE_BY_INTELLIGENT) {
            InsertCoverdInfo(uid, bundleName, configValue, enableStatus,
                NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_ENABLE_FOR_BUNDLE);
        }
    }
    AdvancedNotificationService::GetInstance()->SetBundlePriorityConfigInner(bo, "");
    AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundleInner(
        bo, static_cast<int32_t>(NotificationConstant::PriorityEnableStatus::ENABLE_BY_INTELLIGENT));
}

void NotificationClonePriority::RestoreBundlePriorityInfo(
    const int32_t uid, const NotificationClonePriorityInfo &priorityInfo)
{
    sptr<NotificationBundleOption> bo = new (std::nothrow) NotificationBundleOption(priorityInfo.GetBundleName(), uid);
    if (bo == nullptr) {
        ANS_LOGW("null bundleOption");
        return;
    }
    if (priorityInfo.GetClonePriorityType() ==
        NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_ENABLE_FOR_BUNDLE) {
        AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundleInner(bo, priorityInfo.GetSwitchState());
    } else {
        AdvancedNotificationService::GetInstance()->SetBundlePriorityConfigInner(bo, priorityInfo.GetPriorityConfig());
    }
}

void NotificationClonePriority::OnRestoreStart(const std::string bundleName, int32_t appIndex,
    int32_t userId, int32_t uid)
{
    ANS_LOGI("Handle bundle event: %{public}s, %{public}d, %{public}d, %{public}d, priorityInfoSize: %{public}zu.",
        bundleName.c_str(), appIndex, userId, uid, priorityInfo_.size());
    std::unique_lock lock(lock_);
    if (!fromUnSupportPriority_ && clonedSystemApps_.find(bundleName) == clonedSystemApps_.end()) {
        SetDefaultPriorityInfo(uid, bundleName);
    }
    for (auto iter = priorityInfo_.begin(); iter != priorityInfo_.end();) {
        if (iter->GetClonePriorityType() == NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_ENABLE ||
            iter->GetBundleName() != bundleName || iter->GetAppIndex() != appIndex) {
            iter++;
            continue;
        }
        RestoreBundlePriorityInfo(uid, *iter);
        NotificationPreferences::GetInstance()->DelClonePriorityInfo(userId, *iter);
        iter = priorityInfo_.erase(iter);
    }
}

void NotificationClonePriority::OnUserSwitch(int32_t userId)
{
    std::unique_lock lock(lock_);
    priorityInfo_.clear();
    NotificationPreferences::GetInstance()->GetClonePriorityInfos(userId, priorityInfo_);
    ANS_LOGI("NotificationClonePriority OnUserSwitch priorityInfo size %{public}zu.", priorityInfo_.size());
}

bool NotificationClonePriority::IsFromUnSupportPriority(const std::set<std::string> &systemApps)
{
    fromUnSupportPriority_ = false;
    if (priorityInfo_.empty()) {
        fromUnSupportPriority_ = true;
        for (auto iter = coverdPriorityInfo_.begin(); iter != coverdPriorityInfo_.end();) {
            if (systemApps.find(iter->GetBundleName()) == systemApps.end()) {
                iter++;
                continue;
            }
            RestoreBundlePriorityInfo(iter->GetBundleUid(), *iter);
            iter = coverdPriorityInfo_.erase(iter);
        }
        ANS_LOGE("Clone priority is invalidated or empty.");
    }
    coverdPriorityInfo_.clear();
    return fromUnSupportPriority_;
}

void NotificationClonePriority::InsertCoverdInfo(const int32_t uid,
    const std::string &bundleName, const std::string configValue,
    const NotificationConstant::PriorityEnableStatus enableStatus,
    const NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE type)
{
    NotificationClonePriorityInfo priorityInfo;
    priorityInfo.SetBundleName(bundleName);
    priorityInfo.SetBundleUid(uid);
    priorityInfo.SetClonePriorityType(type);
    if (type == NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_ENABLE_FOR_BUNDLE) {
        priorityInfo.SetSwitchState(static_cast<int32_t>(enableStatus));
    } else {
        priorityInfo.SetPriorityConfig(configValue);
    }
    coverdPriorityInfo_.emplace_back(priorityInfo);
}
}
}
