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

#include "notification_do_not_disturb_profile.h"

#include "ans_const_define.h"
#include "nlohmann/json.hpp"
#include <memory>

namespace OHOS {
namespace Notification {
namespace {
constexpr const char *DO_NOT_DISTURB_PROFILE_ID = "id";
constexpr const char *DO_NOT_DISTURB_PROFILE_NAME = "name";
constexpr const char *DO_NOT_DISTURB_PROFILE_TRUSTLIST = "trustlist";
} // namespace
NotificationDoNotDisturbProfile::NotificationDoNotDisturbProfile(
    int64_t id, const std::string &name, const std::vector<NotificationBundleOption> &trustList)
    : id_(id), name_(name), trustList_(trustList)
{}

void NotificationDoNotDisturbProfile::SetProfileId(int64_t id)
{
    id_ = id;
}

void NotificationDoNotDisturbProfile::SetProfileName(const std::string &name)
{
    name_ = name;
}

void NotificationDoNotDisturbProfile::SetProfileTrustList(const std::vector<NotificationBundleOption> &trustList)
{
    trustList_ = trustList;
}

int64_t NotificationDoNotDisturbProfile::GetProfileId() const
{
    return id_;
}

std::string NotificationDoNotDisturbProfile::GetProfileName() const
{
    return name_;
}

std::vector<NotificationBundleOption> NotificationDoNotDisturbProfile::GetProfileTrustList() const
{
    return trustList_;
}

bool NotificationDoNotDisturbProfile::Marshalling(Parcel &parcel) const
{
    auto size = trustList_.size();
    if (size > MAX_PARCELABLE_VECTOR_NUM) {
        ANS_LOGE("Size exceeds the range.");
        return false;
    }
    if (!parcel.WriteInt64(id_)) {
        ANS_LOGE("Failed to write do not disturb id.");
        return false;
    }
    if (!parcel.WriteString(name_)) {
        ANS_LOGE("Failed to write do not disturb name.");
        return false;
    }
    if (!parcel.WriteInt32(size)) {
        ANS_LOGE("Failed to write do not disturb trust list size.");
        return false;
    }
    for (uint32_t index = 0; index < size; ++index) {
        if (!parcel.WriteParcelable(&trustList_[index])) {
            ANS_LOGE("Failed to write do not disturb trust list.");
            return false;
        }
    }
    return true;
}

NotificationDoNotDisturbProfile *NotificationDoNotDisturbProfile::Unmarshalling(Parcel &parcel)
{
    auto objptr = new (std::nothrow) NotificationDoNotDisturbProfile();
    if ((objptr != nullptr) && !objptr->ReadFromParcel(parcel)) {
        delete objptr;
        objptr = nullptr;
    }
    return objptr;
}

bool NotificationDoNotDisturbProfile::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt64(id_)) {
        ANS_LOGE("ReadInt64 failed, function: %{public}s, field: %{public}s", __FUNCTION__, "id_");
        return false;
    }
    std::string name;
    if (!parcel.ReadString(name)) {
        ANS_LOGE("ReadString failed, function: %{public}s, field: %{public}s", __FUNCTION__, "name");
        return false;
    }
    name_ = name;
    uint32_t size = 0;
    if (!parcel.ReadUint32(size)) {
        ANS_LOGE("ReadUint32 failed, function: %{public}s, field: %{public}s", __FUNCTION__, "size");
        return false;
    }
    if (size > MAX_PARCELABLE_VECTOR_NUM) {
        ANS_LOGE("Size exceeds the range.");
        return false;
    }
    for (uint32_t index = 0; index < size; ++index) {
        sptr<NotificationBundleOption> bundleOption = parcel.ReadParcelable<NotificationBundleOption>();
        if (bundleOption == nullptr) {
            ANS_LOGE("null bundleOption");
            return false;
        }
        trustList_.emplace_back(*bundleOption);
    }
    return true;
}

std::string NotificationDoNotDisturbProfile::ToJson()
{
    nlohmann::json jsonObject;
    GetProfileJson(jsonObject);
    return jsonObject.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

void NotificationDoNotDisturbProfile::GetProfileJson(nlohmann::json &jsonObject) const
{
    nlohmann::json jsonNodes = nlohmann::json::array();
    for (size_t index = 0; index < trustList_.size(); index++) {
        nlohmann::json jsonNode;
        if (trustList_[index].ToJson(jsonNode)) {
            jsonNodes.emplace_back(jsonNode);
        }
    }

    jsonObject[DO_NOT_DISTURB_PROFILE_ID] =  id_;
    jsonObject[DO_NOT_DISTURB_PROFILE_NAME] =  name_;
    jsonObject[DO_NOT_DISTURB_PROFILE_TRUSTLIST] =  jsonNodes;
}

void NotificationDoNotDisturbProfile::FromJson(const std::string &jsonObj)
{
    nlohmann::json jsonObject = nlohmann::json::parse(jsonObj, nullptr, false);
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return;
    }
    if (jsonObject.is_discarded()) {
        ANS_LOGE("Failed to parse json string.");
        return;
    }
    if (jsonObject.contains(DO_NOT_DISTURB_PROFILE_ID) && jsonObject[DO_NOT_DISTURB_PROFILE_ID].is_number()) {
        id_ = jsonObject.at(DO_NOT_DISTURB_PROFILE_ID).get<int64_t>();
    }
    if (jsonObject.contains(DO_NOT_DISTURB_PROFILE_NAME) && jsonObject[DO_NOT_DISTURB_PROFILE_NAME].is_string()) {
        name_ = jsonObject.at(DO_NOT_DISTURB_PROFILE_NAME).get<std::string>();
    }
    if (jsonObject.contains(DO_NOT_DISTURB_PROFILE_TRUSTLIST) &&
        jsonObject[DO_NOT_DISTURB_PROFILE_TRUSTLIST].is_array()) {
        for (auto &trust : jsonObject.at(DO_NOT_DISTURB_PROFILE_TRUSTLIST)) {
            auto bundleOption = NotificationBundleOption::FromJson(trust);
            if (bundleOption == nullptr) {
                continue;
            }
            std::unique_ptr<NotificationBundleOption> bundleOptionGuard(bundleOption);
            trustList_.push_back(*bundleOption);
        }
    }
}
} // namespace Notification
} // namespace OHOS
