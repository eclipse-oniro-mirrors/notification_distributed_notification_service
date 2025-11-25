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

#include "ans_const_define.h"
#include "ans_log_wrapper.h"
#include "notification_preferences.h"
#include "notification_clone_util.h"
#include "advanced_notification_service.h"

namespace OHOS {
namespace Notification {
std::shared_ptr<NotificationClonePriority> NotificationClonePriority::GetInstance()
{
    static std::shared_ptr<NotificationClonePriority> instance =
        std::make_shared<NotificationClonePriority>();
    return instance;
}

ErrCode NotificationClonePriority::OnBackup(nlohmann::json &jsonObject)
{
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

void NotificationClonePriority::OnRestore(const nlohmann::json &jsonObject, std::set<std::string> systemApps)
{
    if (jsonObject.is_null() || !jsonObject.is_array()) {
        ANS_LOGI("Notification disturb profile list is null or not array.");
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
        cloneInfo.FromJson(jsonNode);
        priorityInfo_.emplace_back(cloneInfo);
    }
    ANS_LOGI("NotificationClonePriority OnRestore priorityInfo size %{public}zu.", priorityInfo_.size());
    if (priorityInfo_.empty()) {
        ANS_LOGE("Clone priority is invalidated or empty.");
        return;
    }
    for (auto iter = priorityInfo_.begin(); iter != priorityInfo_.end();) {
        if (iter->GetClonePriorityType() == NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_ENABLE) {
            AdvancedNotificationService::GetInstance()->SetPriorityEnabledInner(
                iter->GetSwitchState() == static_cast<int32_t>(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) ||
                iter->GetSwitchState() == static_cast<int32_t>(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON));
            iter = priorityInfo_.erase(iter);
            continue;
        }
        int32_t uid = NotificationCloneUtil::GetBundleUid(iter->GetBundleName(), userId, iter->GetAppIndex());
        if (uid == INVALID_USER_ID) {
            iter++;
            continue;
        }
        sptr<NotificationBundleOption> bo = new (std::nothrow) NotificationBundleOption(iter->GetBundleName(), uid);
        if (bo == nullptr) {
            ANS_LOGE("null bundleOption");
            iter++;
            continue;
        }
        if (iter->GetClonePriorityType() ==
            NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_ENABLE_FOR_BUNDLE) {
            AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundleInner(bo, iter->GetSwitchState());
        } else {
            AdvancedNotificationService::GetInstance()->SetBundlePriorityConfigInner(bo, iter->GetPriorityConfig());
        }
        iter = priorityInfo_.erase(iter);
    }
    NotificationPreferences::GetInstance()->UpdateClonePriorityInfos(userId, priorityInfo_);
}

void NotificationClonePriority::OnRestoreStart(const std::string bundleName, int32_t appIndex,
    int32_t userId, int32_t uid)
{
    ANS_LOGI("Handle bundle event: %{public}s, %{public}d, %{public}d, %{public}d, priorityInfoSize: %{public}zu.",
        bundleName.c_str(), appIndex, userId, uid, priorityInfo_.size());
    std::unique_lock lock(lock_);
    for (auto iter = priorityInfo_.begin(); iter != priorityInfo_.end();) {
        if (iter->GetClonePriorityType() == NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_ENABLE ||
            iter->GetBundleName() != bundleName || iter->GetAppIndex() != appIndex) {
            iter++;
            continue;
        }
        sptr<NotificationBundleOption> bo = new (std::nothrow) NotificationBundleOption(iter->GetBundleName(), uid);
        if (bo == nullptr) {
            ANS_LOGE("null bundleOption");
            iter++;
            continue;
        }
        if (iter->GetClonePriorityType() ==
            NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_ENABLE_FOR_BUNDLE) {
            AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundleInner(bo, iter->GetSwitchState());
        } else {
            AdvancedNotificationService::GetInstance()->SetBundlePriorityConfigInner(bo, iter->GetPriorityConfig());
        }
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
}
}