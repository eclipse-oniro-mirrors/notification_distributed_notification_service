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

#include "notification_clone_priority_info.h"

#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
void NotificationClonePriorityInfo::SetBundleName(const std::string &name)
{
    bundleName_ = name;
}

std::string NotificationClonePriorityInfo::GetBundleName() const
{
    return bundleName_;
}

void NotificationClonePriorityInfo::SetBundleUid(const int32_t uid)
{
    uid_ = uid;
}

int32_t NotificationClonePriorityInfo::GetBundleUid() const
{
    return uid_;
}

void NotificationClonePriorityInfo::SetAppIndex(const int32_t appIndex)
{
    appIndex_ = appIndex;
}

int32_t NotificationClonePriorityInfo::GetAppIndex() const
{
    return appIndex_;
}

void NotificationClonePriorityInfo::SetSwitchState(const int32_t enableStatus)
{
    enableStatus_ = enableStatus;
}

int32_t NotificationClonePriorityInfo::GetSwitchState() const
{
    return enableStatus_;
}

void NotificationClonePriorityInfo::SetPriorityConfig(const std::string &config)
{
    config_ = config;
}

std::string NotificationClonePriorityInfo::GetPriorityConfig() const
{
    return config_;
}

void NotificationClonePriorityInfo::SetClonePriorityType(const NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE type)
{
    clonePriorityType_ = type;
}

NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE NotificationClonePriorityInfo::GetClonePriorityType() const
{
    return clonePriorityType_;
}

void NotificationClonePriorityInfo::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject[PRIORITY_CLONE_PRIORITY_TYPE] = static_cast<int32_t>(clonePriorityType_);
    jsonObject[PRIORITY_BUNDLE_INDEX] = appIndex_;
    jsonObject[PRIORITY_SWITCH_STATE] = enableStatus_;
    if (!bundleName_.empty()) {
        jsonObject[PRIORITY_BUNDLE_NAME] = bundleName_;
    }
    if (!config_.empty()) {
        jsonObject[PRIORITY_CLONE_CONFIG] = config_;
    }
}

bool NotificationClonePriorityInfo::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() || !jsonObject.is_object() || jsonObject.is_discarded()) {
        ANS_LOGE("Invalid priority info json object");
        return false;
    }
    if (jsonObject.contains(PRIORITY_CLONE_PRIORITY_TYPE) && jsonObject[PRIORITY_CLONE_PRIORITY_TYPE].is_number()) {
        clonePriorityType_ = static_cast<NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE>(
            jsonObject.at(PRIORITY_CLONE_PRIORITY_TYPE).get<int32_t>());
    } else {
        return false;
    }
    if (jsonObject.contains(PRIORITY_BUNDLE_NAME) && jsonObject[PRIORITY_BUNDLE_NAME].is_string()) {
        bundleName_ = jsonObject.at(PRIORITY_BUNDLE_NAME).get<std::string>();
    }
    if (jsonObject.contains(PRIORITY_BUNDLE_INDEX) && jsonObject[PRIORITY_BUNDLE_INDEX].is_number()) {
        appIndex_ = jsonObject.at(PRIORITY_BUNDLE_INDEX).get<int32_t>();
    }
    if (jsonObject.contains(PRIORITY_SWITCH_STATE) && jsonObject[PRIORITY_SWITCH_STATE].is_number()) {
        enableStatus_ = jsonObject.at(PRIORITY_SWITCH_STATE).get<int32_t>();
    }
    if (jsonObject.contains(PRIORITY_CLONE_CONFIG) && jsonObject[PRIORITY_CLONE_CONFIG].is_string()) {
        config_ = jsonObject.at(PRIORITY_CLONE_CONFIG).get<std::string>();
    }
    return true;
}

bool NotificationClonePriorityInfo::FromJson(const std::string &jsonStr)
{
    if (jsonStr.empty() || !nlohmann::json::accept(jsonStr)) {
        ANS_LOGE("Invalid clone priority json string");
        return false;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(jsonStr, nullptr, false);
    return FromJson(jsonObject);
}

std::string NotificationClonePriorityInfo::Dump() const
{
    return "ClonePriority { clonePriorityType = " + std::to_string(static_cast<int32_t>(clonePriorityType_)) +
        ", bundleName = " + bundleName_ +
        ", appIndex = " + std::to_string(appIndex_) +
        ", enableStatus = " + std::to_string(enableStatus_) +
        ", config size = " + std::to_string(config_.size()) +
        " }";
}
}
}