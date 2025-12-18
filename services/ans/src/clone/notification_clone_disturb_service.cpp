/*
* Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "notification_clone_disturb_service.h"

#include "ans_log_wrapper.h"
#include "notification_preferences.h"
#include "notification_clone_util.h"

namespace OHOS {
namespace Notification {
std::shared_ptr<NotificationCloneDisturb> NotificationCloneDisturb::GetInstance()
{
    static std::shared_ptr<NotificationCloneDisturb> instance =
        std::make_shared<NotificationCloneDisturb>();
    return instance;
}

NotificationCloneDisturb::NotificationCloneDisturb()
{
    cloneDisturbQueue_ = std::make_shared<ffrt::queue>("NotificationCloneDisturbQueue");
    if (!cloneDisturbQueue_) {
        ANS_LOGE("ffrt create failed!");
        return;
    }
}

NotificationCloneDisturb::~NotificationCloneDisturb()
{
}

ErrCode NotificationCloneDisturb::OnBackup(nlohmann::json &jsonObject)
{
    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    NotificationPreferences::GetInstance()->GetDoNotDisturbProfileListByUserId(userId, profiles);

    if (profiles.empty()) {
        ANS_LOGI("Notification disturb profile list is empty.");
        return ERR_OK;
    }
    jsonObject = nlohmann::json::array();
    for (size_t index = 0; index < profiles.size(); index++) {
        nlohmann::json jsonNode;
        profiles[index]->GetProfileJson(jsonNode);
        jsonObject.emplace_back(jsonNode);
    }
    ANS_LOGD("Notification disturb profile list %{public}s", jsonObject.dump().c_str());
    return ERR_OK;
}

void NotificationCloneDisturb::OnRestoreEnd(int32_t userId)
{
    cloneDisturbQueue_->submit_h(std::bind([&, userId]() {
        if (!profiles_.empty()) {
            NotificationPreferences::GetInstance()->DelBatchCloneProfileInfo(userId, profiles_);
            profiles_.clear();
        }
        ANS_LOGW("Disturb on clear Restore");
    }));
}

void NotificationCloneDisturb::OnRestore(const nlohmann::json &jsonObject, std::set<std::string> systemApps)
{
    if (jsonObject.is_null() || !jsonObject.is_array()) {
        ANS_LOGI("Notification disturb profile list is null or not array.");
        return;
    }

    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    if (!profiles_.empty()) {
        NotificationPreferences::GetInstance()->DelBatchCloneProfileInfo(userId, profiles_);
        profiles_.clear();
    }
    for (const auto &profile : jsonObject) {
        sptr<NotificationDoNotDisturbProfile> item = new (std::nothrow) NotificationDoNotDisturbProfile();
        if (item == nullptr) {
            return;
        }
        item->FromJson(profile.dump());
        profiles_.push_back(item);
    }

    if (cloneDisturbQueue_ == nullptr || profiles_.empty()) {
        ANS_LOGE("Clone queue is invalidated or empty %{public}zu.", profiles_.size());
        return;
    }

    cloneDisturbQueue_->submit_h(std::bind([&, userId, systemApps]() {
        int64_t profileId = -1;
        std::string name;
        std::map<std::string, int32_t> uidMap;
        for (auto profile = profiles_.begin(); profile != profiles_.end();) {
            std::vector<NotificationBundleOption> exitBunldleList;
            std::vector<NotificationBundleOption> notExitBunldleList;
            name = (*profile)->GetProfileName();
            profileId = (*profile)->GetProfileId();
            ANS_LOGI("Disturb %{public}s.", std::to_string(profileId).c_str());
            GetProfileUid(userId, systemApps, (*profile)->GetProfileTrustList(), exitBunldleList, notExitBunldleList);
            NotificationPreferences::GetInstance()->UpdateDoNotDisturbProfiles(userId,
                profileId, name, exitBunldleList);
            if (notExitBunldleList.empty()) {
                profile = profiles_.erase(profile);
            } else {
                (*profile)->SetProfileTrustList(notExitBunldleList);
                profile++;
            }
            name.clear();
            profileId = -1;
        }

        NotificationPreferences::GetInstance()->UpdateBatchCloneProfileInfo(userId, profiles_);
        for (auto profile = profiles_.begin(); profile != profiles_.end(); profile++) {
            ANS_LOGI("Clone queue left %{public}s.", std::to_string((*profile)->GetProfileId()).c_str());
        }
    }));
}

void NotificationCloneDisturb::GetProfileUid(int32_t userId, const std::set<std::string>& systemApps,
    std::vector<NotificationBundleOption> trustList, std::vector<NotificationBundleOption>& exitBunldleList,
    std::vector<NotificationBundleOption>& notExitBunldleList)
{
    // get application uid with bundle name and appindex.
    for (auto& bundle : trustList) {
        if (systemApps.find(bundle.GetBundleName()) == systemApps.end()) {
            notExitBunldleList.push_back(bundle);
            continue;
        }
        int32_t uid = NotificationCloneUtil::GetBundleUid(bundle.GetBundleName(), userId, bundle.GetAppIndex());
        ANS_LOGI("Profile uid %{public}d %{public}s.", uid, bundle.GetBundleName().c_str());
        bundle.SetUid(uid);
        if (bundle.GetUid() == -1) {
            notExitBunldleList.push_back(bundle);
        } else {
            exitBunldleList.push_back(bundle);
        }
    }
}

void NotificationCloneDisturb::OnUserSwitch(int32_t userId)
{
    ANS_LOGD("Handler user switch %{public}d", userId);
    if (cloneDisturbQueue_ == nullptr) {
        ANS_LOGW("null cloneDisturbQueue");
        return;
    }
    cloneDisturbQueue_->submit_h(std::bind([&, userId]() {
        profiles_.clear();
        NotificationPreferences::GetInstance()->GetAllCloneProfileInfo(userId, profiles_);
        for (auto profile = profiles_.begin(); profile != profiles_.end(); profile++) {
            ANS_LOGI("Clone queue left %{public}s %{public}zu.", std::to_string((*profile)->GetProfileId()).c_str(),
                (*profile)->GetProfileTrustList().size());
        }
        ANS_LOGD("end");
    }));
}

void NotificationCloneDisturb::OnRestoreStart(const std::string bundleName, int32_t appIndex,
    int32_t userId, int32_t uid)
{
    ANS_LOGI("Handler bundle event %{public}s %{public}d %{public}d %{public}d %{public}zu.",
        bundleName.c_str(), appIndex, userId, uid, profiles_.size());
    if (profiles_.empty()) {
        return;
    }

    NotificationBundleOption bundle(bundleName, uid);
    bundle.SetAppIndex(appIndex);
    if (cloneDisturbQueue_ == nullptr) {
        ANS_LOGW("null cloneDisturbQueue");
        return;
    }
    cloneDisturbQueue_->submit_h(std::bind([&, bundle, userId]() {
        int64_t profileId = -1;
        std::string name;
        for (auto profile = profiles_.begin(); profile != profiles_.end();) {
            name = (*profile)->GetProfileName();
            profileId = (*profile)->GetProfileId();
            std::vector<NotificationBundleOption> bundleList;
            auto trustList = (*profile)->GetProfileTrustList();
            CheckBundleInfo(trustList, bundleList, bundle);
            NotificationPreferences::GetInstance()->UpdateDoNotDisturbProfiles(userId,
                profileId, name, bundleList);
            if (trustList.empty()) {
                NotificationPreferences::GetInstance()->DelCloneProfileInfo(userId, *profile);
                profile = profiles_.erase(profile);
            } else {
                (*profile)->SetProfileTrustList(trustList);
                profile++;
            }
            name.clear();
            profileId = -1;
        }
        NotificationPreferences::GetInstance()->UpdateBatchCloneProfileInfo(userId, profiles_);
        for (auto profile = profiles_.begin(); profile != profiles_.end(); profile++) {
            ANS_LOGI("Event queue left %{public}s %{public}zu.", std::to_string((*profile)->GetProfileId()).c_str(),
                (*profile)->GetProfileTrustList().size());
        }
    }));
}

void NotificationCloneDisturb::CheckBundleInfo(std::vector<NotificationBundleOption>& trustList,
    std::vector<NotificationBundleOption>& bundleList, const NotificationBundleOption& bundle)
{
    for (auto bundleItem = trustList.begin(); bundleItem != trustList.end(); bundleItem++) {
        if (bundleItem->GetBundleName() == bundle.GetBundleName() &&
            bundleItem->GetAppIndex() == bundle.GetAppIndex()) {
            bundleList.push_back(bundle);
            trustList.erase(bundleItem);
            break;
        }
    }
}
}
}
