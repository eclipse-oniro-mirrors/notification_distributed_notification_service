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

#include "dh_notification_clone_bundle_service.h"

#include "ans_log_wrapper.h"
#include "notification_preferences.h"
#include "notification_clone_util.h"
#include "notification_clone_bundle_info.h"
#include "os_account_manager_helper.h"
#include "advanced_notification_service.h"

namespace OHOS {
namespace Notification {

std::shared_ptr<DhNotificationCloneBundle> DhNotificationCloneBundle::GetInstance()
{
    static std::shared_ptr<DhNotificationCloneBundle> instance =
        std::make_shared<DhNotificationCloneBundle>();
    return instance;
}

DhNotificationCloneBundle::DhNotificationCloneBundle()
{
    dhCloneBundleQueue_ = std::make_shared<ffrt::queue>("DhNotificationCloneBundleQueue");
    if (!dhCloneBundleQueue_) {
        ANS_LOGE("ffrt create failed!");
        return;
    }
}

DhNotificationCloneBundle::~DhNotificationCloneBundle()
{
}

ErrCode DhNotificationCloneBundle::OnBackup(nlohmann::json &jsonObject)
{
    ANS_LOGI("DhNotificationCloneBundle OnBackup");
    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    std::vector<NotificationCloneBundleInfo> cloneBundles;
    NotificationPreferences::GetInstance()->GetAllCLoneBundlesInfo(ZERO_USERID, userId, cloneBundles);

    if (cloneBundles.empty()) {
        ANS_LOGI("dh Notification bundle list is empty.");
        return ERR_OK;
    }
    jsonObject = nlohmann::json::array();
    for (size_t index = 0; index < cloneBundles.size(); index++) {
        nlohmann::json jsonNode;
        cloneBundles[index].ToJson(jsonNode);
        jsonObject.emplace_back(jsonNode);
        ANS_LOGD("Event dh bundle backup %{public}s.", cloneBundles[index].Dump().c_str());
    }
    ANS_LOGD("dh Notification bundle list %{public}s", jsonObject.dump().c_str());
    return ERR_OK;
}

void DhNotificationCloneBundle::OnRestore(const nlohmann::json &jsonObject)
{
    ANS_LOGI("DhNotificationCloneBundle OnRestore");
    if (jsonObject.is_null() || !jsonObject.is_array()) {
        ANS_LOGI("dh Notification bundle list is null or not array.");
        return;
    }

    std::unique_lock lock(lock_);
    if (!bundlesInfo_.empty()) {
        NotificationPreferences::GetInstance()->DelBatchCloneBundleInfo(ZERO_USERID, bundlesInfo_);
        bundlesInfo_.clear();
    }
    for (const auto &profile : jsonObject) {
        NotificationCloneBundleInfo cloneBundleInfo;
        cloneBundleInfo.FromJson(profile);
        bundlesInfo_.emplace_back(cloneBundleInfo);
    }
    ANS_LOGI("dh Notification bundle list size %{public}zu.", bundlesInfo_.size());
    if (dhCloneBundleQueue_ == nullptr || bundlesInfo_.empty()) {
        ANS_LOGE("Clone dh bundle is invalidated or empty.");
        return;
    }

    NotificationPreferences::GetInstance()->UpdateBatchCloneBundleInfo(ZERO_USERID, bundlesInfo_);
    for (auto bundle = bundlesInfo_.begin(); bundle != bundlesInfo_.end(); bundle++) {
        NotificationPreferences::GetInstance()->UpdateCloneRingtoneInfo(ZERO_USERID, *bundle);
        ANS_LOGD("Event dh bundle left %{public}s.", bundle->Dump().c_str());
    }
    ANS_LOGD("dh Notification bundle list on restore end.");
}

void DhNotificationCloneBundle::OnRestoreStart(const std::string bundleName, int32_t appIndex,
    int32_t userId, int32_t uid)
{
    ANS_LOGI("Handle dh bundle event %{public}s %{public}d %{public}zu.",
        bundleName.c_str(), uid, bundlesInfo_.size());
    std::unique_lock lock(lock_);
    if (bundlesInfo_.empty()) {
        return;
    }

    for (auto bundle = bundlesInfo_.begin(); bundle != bundlesInfo_.end();) {
        if (bundle->GetBundleName() == bundleName) {
            bundle->SetUid(uid);
            AdvancedNotificationService::GetInstance()->UpdateCloneBundleInfo(*bundle, ZERO_USERID);
            NotificationPreferences::GetInstance()->DelCloneBundleInfo(ZERO_USERID, *bundle);
            bundle = bundlesInfo_.erase(bundle);
            break;
        }
        bundle++;
    }
    ANS_LOGD("Event dh bundle left %{public}zu.", bundlesInfo_.size());
}

void DhNotificationCloneBundle::OnUserSwitch(int32_t userId)
{
    ANS_LOGI("Handler user switch %{public}d", userId);
    if (dhCloneBundleQueue_ == nullptr) {
        ANS_LOGW("null dhCloneBundleQueue");
        return;
    }
    dhCloneBundleQueue_->submit_h(std::bind([&]() {
        std::unique_lock lock(lock_);
        bundlesInfo_.clear();
        NotificationPreferences::GetInstance()->GetAllCloneBundleInfo(ZERO_USERID, bundlesInfo_);
        for (auto bundle = bundlesInfo_.begin(); bundle != bundlesInfo_.end(); bundle++) {
            ANS_LOGD("Event dh bundle OnUserSwitch %{public}s.", bundle->Dump().c_str());
        }
    }));
}

bool DhNotificationCloneBundle::isDhSource()
{
    return true;
}

}
}
