/*
* Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "notification_clone_bundle_service.h"

#include "ans_log_wrapper.h"
#include "notification_preferences.h"
#include "notification_clone_util.h"
#include "notification_clone_bundle_info.h"
#include "os_account_manager_helper.h"
#include "advanced_notification_service.h"

namespace OHOS {
namespace Notification {
std::shared_ptr<NotificationCloneBundle> NotificationCloneBundle::GetInstance()
{
    static std::shared_ptr<NotificationCloneBundle> instance =
        std::make_shared<NotificationCloneBundle>();
    return instance;
}

NotificationCloneBundle::NotificationCloneBundle()
{
    cloneBundleQueue_ = std::make_shared<ffrt::queue>("NotificationCloneBundleQueue");
    if (!cloneBundleQueue_) {
        ANS_LOGE("ffrt create failed!");
        return;
    }
}

NotificationCloneBundle::~NotificationCloneBundle()
{
}

ErrCode NotificationCloneBundle::OnBackup(nlohmann::json &jsonObject)
{
    ANS_LOGI("NotificationCloneBundle OnBackup");
    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    std::vector<NotificationCloneBundleInfo> cloneBundles;
    NotificationPreferences::GetInstance()->GetAllCLoneBundlesInfo(userId, userId, cloneBundles);

    if (cloneBundles.empty()) {
        ANS_LOGI("Notification bundle list is empty.");
        return ERR_OK;
    }
    jsonObject = nlohmann::json::array();
    for (size_t index = 0; index < cloneBundles.size(); index++) {
        nlohmann::json jsonNode;
        cloneBundles[index].ToJson(jsonNode);
        jsonObject.emplace_back(jsonNode);
        ANS_LOGD("Event bundle backup %{public}s.", cloneBundles[index].Dump().c_str());
    }
    ANS_LOGD("Notification bundle list %{public}s", jsonObject.dump().c_str());
    return ERR_OK;
}

void NotificationCloneBundle::OnRestore(const nlohmann::json &jsonObject)
{
    ANS_LOGI("NotificationCloneBundle OnRestore");
    if (jsonObject.is_null() || !jsonObject.is_array()) {
        ANS_LOGI("Notification disturb profile list is null or not array.");
        return;
    }

    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    std::unique_lock lock(lock_);
    if (!bundlesInfo_.empty()) {
        NotificationPreferences::GetInstance()->DelBatchCloneBundleInfo(userId, bundlesInfo_);
        bundlesInfo_.clear();
    }
    for (const auto &profile : jsonObject) {
        NotificationCloneBundleInfo cloneBundleInfo;
        cloneBundleInfo.FromJson(profile);
        bundlesInfo_.emplace_back(cloneBundleInfo);
    }
    ANS_LOGI("Notification bundle list size %{public}zu.", bundlesInfo_.size());
    if (cloneBundleQueue_ == nullptr || bundlesInfo_.empty()) {
        ANS_LOGE("Clone bundle is invalidated or empty.");
        return;
    }

    for (auto bundle = bundlesInfo_.begin(); bundle != bundlesInfo_.end();) {
        int32_t uid = NotificationCloneUtil::GetBundleUid(bundle->GetBundleName(),
            userId, bundle->GetAppIndex());
        if (uid == -1) {
            bundle++;
            continue;
        }
        bundle->SetUid(uid);
        AdvancedNotificationService::GetInstance()->UpdateCloneBundleInfo(*bundle, userId);
        bundle = bundlesInfo_.erase(bundle);
    }

    NotificationPreferences::GetInstance()->UpdateBatchCloneBundleInfo(userId, bundlesInfo_);
    for (auto bundle = bundlesInfo_.begin(); bundle != bundlesInfo_.end(); bundle++) {
        NotificationPreferences::GetInstance()->UpdateCloneRingtoneInfo(userId, *bundle);
        ANS_LOGD("Event bundle left %{public}s.", bundle->Dump().c_str());
    }
    ANS_LOGD("end");
}

void NotificationCloneBundle::OnRestoreStart(const std::string bundleName, int32_t appIndex,
    int32_t userId, int32_t uid)
{
    ANS_LOGI("Handle bundle event %{public}s %{public}d %{public}d %{public}d %{public}zu.",
        bundleName.c_str(), appIndex, userId, uid, bundlesInfo_.size());
    std::unique_lock lock(lock_);
    if (bundlesInfo_.empty()) {
        return;
    }

    for (auto bundle = bundlesInfo_.begin(); bundle != bundlesInfo_.end();) {
        if (bundle->GetBundleName() == bundleName && bundle->GetAppIndex() == appIndex) {
            bundle->SetUid(uid);
            AdvancedNotificationService::GetInstance()->UpdateCloneBundleInfo(*bundle, userId);
            NotificationPreferences::GetInstance()->DelCloneBundleInfo(userId, *bundle);
            bundle = bundlesInfo_.erase(bundle);
            break;
        }
        bundle++;
    }
    ANS_LOGD("Event bundle left %{public}zu.", bundlesInfo_.size());
}

void NotificationCloneBundle::OnUserSwitch(int32_t userId)
{
    ANS_LOGI("Handler user switch %{public}d", userId);
    if (cloneBundleQueue_ == nullptr) {
        ANS_LOGW("null cloneBundleQueue");
        return;
    }
    cloneBundleQueue_->submit_h(std::bind([&, userId]() {
        std::unique_lock lock(lock_);
        bundlesInfo_.clear();
        NotificationPreferences::GetInstance()->GetAllCloneBundleInfo(userId, bundlesInfo_);
        for (auto bundle = bundlesInfo_.begin(); bundle != bundlesInfo_.end(); bundle++) {
            ANS_LOGD("Event bundle OnUserSwitch %{public}s.", bundle->Dump().c_str());
        }
    }));
}

}
}
