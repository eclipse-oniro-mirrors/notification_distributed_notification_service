/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "notification_disable.h"

#include "ans_const_define.h"
#include "ans_log_wrapper.h"
#include "nlohmann/json.hpp"
#include "parcel.h"

namespace OHOS {
namespace Notification {
namespace {
constexpr const char *DISABLED = "disabled";
constexpr const char *BUNDLELIST = "bundleList";
constexpr const char *USERID = "userId";
constexpr int32_t MAX_NOTIFICATION_DISABLE_NUM = 1000;
} // namespace
void NotificationDisable::SetDisabled(bool disabled)
{
    disabled_ = disabled;
}

void NotificationDisable::SetBundleList(const std::vector<std::string> &bundleList)
{
    bundleList_ = bundleList;
}

void NotificationDisable::SetUserId(int32_t userId)
{
    userId_ = userId;
}

bool NotificationDisable::GetDisabled() const
{
    return disabled_;
}

std::vector<std::string> NotificationDisable::GetBundleList() const
{
    return bundleList_;
}

int32_t NotificationDisable::GetUserId() const
{
    return userId_;
}

bool NotificationDisable::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteBool(disabled_)) {
        ANS_LOGE("Failed to write disabled");
        return false;
    }
    auto size = bundleList_.size();
    if (size > MAX_NOTIFICATION_DISABLE_NUM) {
        ANS_LOGE("Size exceeds the range");
        return false;
    }
    if (!parcel.WriteInt32(size)) {
        ANS_LOGE("Failed to write bundle list size");
        return false;
    }
    for (uint32_t index = 0; index < size; ++index) {
        if (!parcel.WriteString(bundleList_[index])) {
            ANS_LOGE("Failed to write bundle list");
            return false;
        }
    }
    if (!parcel.WriteInt32(userId_)) {
        ANS_LOGE("Failed to write userId");
        return false;
    }
    return true;
}

bool NotificationDisable::ReadFromParcel(Parcel &parcel)
{
    disabled_ = parcel.ReadBool();
    auto size = parcel.ReadUint32();
    if (size > MAX_NOTIFICATION_DISABLE_NUM) {
        ANS_LOGE("Size exceeds the range");
        return false;
    }
    bundleList_.resize(size);
    for (uint32_t index = 0; index < size; ++index) {
        if (!parcel.ReadString(bundleList_[index])) {
            ANS_LOGE("Failed to read bundle list");
            return false;
        }
    }
    userId_ = parcel.ReadInt32();
    return true;
}

NotificationDisable *NotificationDisable::Unmarshalling(Parcel &parcel)
{
    auto objptr = new (std::nothrow) NotificationDisable();
    if ((objptr != nullptr) && !objptr->ReadFromParcel(parcel)) {
        delete objptr;
        objptr = nullptr;
    }
    return objptr;
}

std::string NotificationDisable::ToJson()
{
    nlohmann::json jsonObject;
    jsonObject[DISABLED] = disabled_;
    jsonObject[BUNDLELIST] = nlohmann::json(bundleList_);
    jsonObject[USERID] = userId_;
    return jsonObject.dump();
}

void NotificationDisable::FromJson(const std::string &jsonObj)
{
    if (jsonObj.empty() || !nlohmann::json::accept(jsonObj)) {
        ANS_LOGE("Invalid json string");
        return;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(jsonObj, nullptr, false);
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return;
    }
    if (jsonObject.is_discarded()) {
        ANS_LOGE("Failed to parse json string");
        return;
    }
    const auto &jsonEnd = jsonObject.cend();
    if (jsonObject.find(DISABLED) != jsonEnd && jsonObject.at(DISABLED).is_boolean()) {
        disabled_ = jsonObject.at(DISABLED).get<bool>();
    }
    if (jsonObject.find(BUNDLELIST) != jsonEnd && jsonObject.at(BUNDLELIST).is_array()) {
        bundleList_ = jsonObject.at(BUNDLELIST).get<std::vector<std::string>>();
    }
    if (jsonObject.find(USERID) != jsonEnd && jsonObject.at(USERID).is_number_integer()) {
        userId_ = jsonObject.at(USERID).get<int32_t>();
    }
}
}
}