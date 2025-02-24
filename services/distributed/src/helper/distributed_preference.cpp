/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "distributed_preference.h"

#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
namespace {
const static std::string BUNDL_ICON_KEY_PREFIX = "dans_icon_";
}


DistributedPreferences::DistributedPreferences()
{
    DistributedRdbConfig rdbConfig;
    preferncesDB_ = std::make_shared<DistributedRdbHelper>(rdbConfig);
    preferncesDB_->Init();
    ANS_LOGD("Distributed Rdb is created");
}

DistributedPreferences& DistributedPreferences::GetInstance()
{
    static DistributedPreferences distributedPreferences;
    return distributedPreferences;
}

int32_t DistributedPreferences::InertBundleIcon(const std::string &bundleName, const std::string &icon)
{
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    if (preferncesDB_ == nullptr) {
        ANS_LOGW("Prefernces handler is nullptr.");
        return -1;
    }
    if (preferncesDB_->InsertData(BUNDL_ICON_KEY_PREFIX + bundleName, icon) != NativeRdb::E_OK) {
        ANS_LOGW("Prefernces Insert data failed %{public}s.", bundleName.c_str());
        return -1;
    }
    return 0;
}

int32_t DistributedPreferences::DeleteBundleIcon(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    if (preferncesDB_ == nullptr) {
        ANS_LOGW("Prefernces handler is nullptr.");
        return -1;
    }
    if (preferncesDB_->DeleteData(BUNDL_ICON_KEY_PREFIX + bundleName) != NativeRdb::E_OK) {
        ANS_LOGW("Prefernces delet data failed %{public}s.", bundleName.c_str());
        return -1;
    }
    return 0;
}

int32_t DistributedPreferences::InertBatchBundleIcons(std::unordered_map<std::string, std::string> &values)
{
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    if (preferncesDB_ == nullptr) {
        ANS_LOGW("Prefernces handler is nullptr.");
        return -1;
    }
    std::unordered_map<std::string, std::string> bundlesIcon;
    for (auto& item : values) {
        bundlesIcon.insert(std::make_pair(BUNDL_ICON_KEY_PREFIX + item.first, item.second));
    }
    if (preferncesDB_->InsertBatchData(bundlesIcon) != NativeRdb::E_OK) {
        ANS_LOGW("Prefernces Insert batch data failed.");
        return -1;
    }
    return 0;
}

int32_t DistributedPreferences::GetIconByBundleName(const std::string& bundleName, std::string &icon)
{
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    if (preferncesDB_ == nullptr) {
        ANS_LOGW("Prefernces handler is nullptr.");
        return -1;
    }
    if (preferncesDB_->QueryData(BUNDL_ICON_KEY_PREFIX + bundleName, icon) != NativeRdb::E_OK) {
        ANS_LOGW("Prefernces query data failed %{public}s.", bundleName.c_str());
        return -1;
    }
    return 0;
}

int32_t DistributedPreferences::GetSavedBundlesIcon(std::vector<std::string>& bundleNames)
{
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    if (preferncesDB_ == nullptr) {
        ANS_LOGW("Prefernces handler is nullptr.");
        return -1;
    }
    std::unordered_map<std::string, std::string> values;
    if (preferncesDB_->QueryDataBeginWithKey(BUNDL_ICON_KEY_PREFIX, values) != NativeRdb::E_OK) {
        ANS_LOGW("Prefernces saved data failed.");
        return -1;
    }
    int32_t prefixLength = BUNDL_ICON_KEY_PREFIX.size();
    for (auto item : values) {
        std::string bundleName = item.first.substr(prefixLength, item.first.size() - prefixLength);
        bundleNames.push_back(bundleName);
        ANS_LOGI("Prefernces saved data %{public}s %{public}u.", bundleName.c_str(), item.second.size());
    }
    return 0;
}
}
}
