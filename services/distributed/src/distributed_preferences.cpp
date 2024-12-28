/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "distributed_preferences.h"

#include <map>

#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
namespace {
const std::string DISTRIBUTED_LABEL = "distributed";
const std::string DELIMITER = "|";
const std::string MAIN_LABEL = "ans_main";
const std::string BUNDLE_LABEL = "bundle";
const std::string WITHOUT_APP = "without_app";
}  // namespace

inline bool GetBoolFromString(const std::string &str)
{
    return static_cast<bool>(atoi(str.data()));
}

DistributedPreferences::DistributedPreferences()
{
    database_ = std::make_unique<DistributedPreferencesDatabase>();
    preferencesInfo_ = std::make_unique<DistributedPreferencesInfo>();
    InitDistributedAllInfo();
}

DistributedPreferences::~DistributedPreferences()
{}

bool DistributedPreferences::InitDistributedAllInfo()
{
    std::vector<DistributedPreferencesDatabase::Entry> entries;
    if (!database_->GetEntriesFromDistributedDB(DISTRIBUTED_LABEL, entries)) {
        return false;
    }

    for (auto entry : entries) {
        if (!ResolveDistributedKey(entry)) {
            ANS_LOGE("key <%{public}s> is invalid.", entry.key.ToString().c_str());
        }
    }

    return true;
}

void DistributedPreferences::GetDistributedMainKey(std::string &key)
{
    key = DISTRIBUTED_LABEL + DELIMITER + MAIN_LABEL + DELIMITER;
}

void DistributedPreferences::GetDistributedBundleKey(
    const sptr<NotificationBundleOption> &bundleOption, std::string &key)
{
    if (bundleOption) {
        key = DISTRIBUTED_LABEL + DELIMITER + BUNDLE_LABEL + DELIMITER + bundleOption->GetBundleName() + DELIMITER +
            std::to_string(bundleOption->GetUid());
    }
}

bool DistributedPreferences::ResolveDistributedKey(const DistributedKv::Entry &entry)
{
    std::string key = entry.key.ToString();
    std::size_t distributedLabelPosition = 0;
    std::size_t distributedLabelEndPosition = key.find(DELIMITER, distributedLabelPosition);
    if (distributedLabelEndPosition == std::string::npos) {
        return false;
    }
    std::size_t typeLabelPosition = distributedLabelEndPosition + DELIMITER.size();
    std::size_t typeLabelEndPosition = key.find(DELIMITER, typeLabelPosition);
    if (typeLabelPosition == std::string::npos) {
        return false;
    }

    std::string sign = key.substr(typeLabelPosition, typeLabelEndPosition - typeLabelPosition);
    if (sign == MAIN_LABEL) {
        return ResolveDistributedEnable(entry.value.ToString());
    }
    if (sign == WITHOUT_APP) {
        return ResolveSyncWithoutAppEnable(key, typeLabelEndPosition, entry.value.ToString());
    }
    return ResolveDistributedBundleEnable(key, typeLabelEndPosition, entry.value.ToString());
}

bool DistributedPreferences::ResolveDistributedEnable(const std::string &value)
{
    int32_t enabled = atoi(value.data());
    preferencesInfo_->SetDistributedEnable(static_cast<bool>(enabled));

    return true;
}

bool DistributedPreferences::ResolveDistributedBundleEnable(const std::string &key,
    const int32_t startPos, const std::string &value)
{
    std::size_t bundleNamePosition = startPos + DELIMITER.size();
    std::size_t bundleNameEndPosition = key.find(DELIMITER, bundleNamePosition);
    if (bundleNameEndPosition == std::string::npos) {
        return false;
    }

    std::size_t uidPosition = key.find_last_of(DELIMITER) + DELIMITER.size();
    if (uidPosition < bundleNameEndPosition) {
        return false;
    }

    std::string bundleName = key.substr(bundleNamePosition, bundleNameEndPosition - bundleNamePosition);
    int32_t uid = atoi(&key[uidPosition]);
    preferencesInfo_->SetDistributedBundleEnable(bundleName, uid, GetBoolFromString(value));

    return true;
}

bool DistributedPreferences::ResolveSyncWithoutAppEnable(const std::string &key,
    const int32_t startPos, const std::string &value)
{
    std::size_t pos = startPos + DELIMITER.size();
    int32_t userId = atoi(&key[pos]);
    preferencesInfo_->SetSyncEnabledWithoutApp(userId, GetBoolFromString(value));

    return true;
}

ErrCode DistributedPreferences::SetDistributedEnable(bool isEnable)
{
    ANS_LOGI("start");
    std::string key;
    GetDistributedMainKey(key);

    if (!database_->PutToDistributedDB(key, std::to_string(isEnable))) {
        ANS_LOGE("put to distributed DB failed. key:%{public}s", key.c_str());
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    preferencesInfo_->SetDistributedEnable(isEnable);

    return ERR_OK;
}

ErrCode DistributedPreferences::GetDistributedEnable(bool &isEnable)
{
    ANS_LOGI("start");

    isEnable = preferencesInfo_->GetDistributedEnable();

    return ERR_OK;
}

ErrCode DistributedPreferences::SetDistributedBundleEnable(
    const sptr<NotificationBundleOption> &bundleOption, bool isEnable)
{
    ANS_LOGI("start");
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }

    std::string key;
    GetDistributedBundleKey(bundleOption, key);

    if (!database_->PutToDistributedDB(key, std::to_string(isEnable))) {
        ANS_LOGE("put to distributed DB failed. key:%{public}s", key.c_str());
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    preferencesInfo_->SetDistributedBundleEnable(bundleOption->GetBundleName(), bundleOption->GetUid(), isEnable);

    return ERR_OK;
}

ErrCode DistributedPreferences::GetDistributedBundleEnable(
    const sptr<NotificationBundleOption> &bundleOption, bool &isEnable)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (preferencesInfo_ == nullptr) {
        ANS_LOGE("preferencesInfo is nullptr");
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    isEnable = preferencesInfo_->GetDistributedBundleEnable(bundleOption->GetBundleName(), bundleOption->GetUid());

    return ERR_OK;
}

ErrCode DistributedPreferences::DeleteDistributedBundleInfo(const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (database_ == nullptr || preferencesInfo_ == nullptr) {
        ANS_LOGE("database or preferencesInfo is nullptr");
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    std::string key;
    GetDistributedBundleKey(bundleOption, key);

    if (!database_->DeleteToDistributedDB(key)) {
        ANS_LOGE("delete to distributed DB failed. key:%{public}s", key.c_str());
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    preferencesInfo_->DeleteDistributedBundleInfo(bundleOption->GetBundleName(), bundleOption->GetUid());

    return ERR_OK;
}

ErrCode DistributedPreferences::ClearDataInRestoreFactorySettings()
{
    if (database_ == nullptr) {
        ANS_LOGE("database is nullptr");
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    if (!database_->ClearDatabase()) {
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    SetDistributedEnable(false);

    preferencesInfo_ = std::make_unique<DistributedPreferencesInfo>();

    return ERR_OK;
}

void DistributedPreferences::GetEnabledWithoutApp(const int32_t userId, std::string &key)
{
    key = DISTRIBUTED_LABEL + DELIMITER + WITHOUT_APP + DELIMITER + std::to_string(userId) + DELIMITER;
}

ErrCode DistributedPreferences::SetSyncEnabledWithoutApp(const int32_t userId, const bool enabled)
{
    if (database_ == nullptr || preferencesInfo_ == nullptr) {
        ANS_LOGE("database or preferencesInfo is nullptr");
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    std::string key;
    GetEnabledWithoutApp(userId, key);
    if (!database_->PutToDistributedDB(key, std::to_string(enabled))) {
        ANS_LOGE("put to distributed DB failed. key:%{public}s", key.c_str());
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    preferencesInfo_->SetSyncEnabledWithoutApp(userId, enabled);
    return ERR_OK;
}

ErrCode DistributedPreferences::GetSyncEnabledWithoutApp(const int32_t userId, bool &enabled)
{
    return preferencesInfo_ == nullptr ?
        ERR_ANS_DISTRIBUTED_OPERATION_FAILED : preferencesInfo_->GetSyncEnabledWithoutApp(userId, enabled);
}
}  // namespace Notification
}  // namespace OHOS