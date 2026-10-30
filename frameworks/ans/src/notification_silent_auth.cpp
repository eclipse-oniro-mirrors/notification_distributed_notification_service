/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "notification_silent_auth.h"

#include <cinttypes>

#include "ans_const_define.h"
#include "ans_log_wrapper.h"
#include "nlohmann/json.hpp"
#include "parcel.h"

namespace OHOS {
namespace Notification {
namespace {
constexpr const char *BUNDLELIST = "bundleList";
constexpr const char *USERID = "userId";
constexpr int32_t MAX_NOTIFICATION_SILENT_AUTH_NUM = 1000;
} // namespace

void NotificationSilentAuth::SetBundleList(const std::vector<std::string> &bundleList)
{
    bundleList_ = bundleList;
}

void NotificationSilentAuth::SetUserId(int32_t userId)
{
    userId_ = userId;
}

std::vector<std::string> NotificationSilentAuth::GetBundleList() const
{
    return bundleList_;
}

int32_t NotificationSilentAuth::GetUserId() const
{
    return userId_;
}

bool NotificationSilentAuth::Marshalling(Parcel &parcel) const
{
    auto size = bundleList_.size();
    if (size > static_cast<size_t>(MAX_NOTIFICATION_SILENT_AUTH_NUM)) {
        ANS_LOGE("Size exceeds the range");
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(size))) {
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

bool NotificationSilentAuth::ReadFromParcel(Parcel &parcel)
{
    uint32_t size = 0;
    if (!parcel.ReadUint32(size)) {
        ANS_LOGE("ReadUint32 failed, function: %{public}s, field: %{public}s", __FUNCTION__, "size");
        return false;
    }
    if (size > static_cast<uint32_t>(MAX_NOTIFICATION_SILENT_AUTH_NUM)) {
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

    int32_t userId = 0;
    if (!parcel.ReadInt32(userId)) {
        ANS_LOGE("ReadInt32 failed, function: %{public}s, field: %{public}s", __FUNCTION__, "userId");
        return false;
    }
    userId_ = userId;
    return true;
}

NotificationSilentAuth *NotificationSilentAuth::Unmarshalling(Parcel &parcel)
{
    auto objptr = new (std::nothrow) NotificationSilentAuth();
    if ((objptr != nullptr) && !objptr->ReadFromParcel(parcel)) {
        delete objptr;
        objptr = nullptr;
    }
    return objptr;
}

std::string NotificationSilentAuth::ToJson()
{
    nlohmann::json jsonObject;
    jsonObject[BUNDLELIST] = nlohmann::json(bundleList_);
    jsonObject[USERID] = userId_;
    return jsonObject.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

void NotificationSilentAuth::FromJson(const std::string &jsonObj)
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
    bundleList_.clear();
    const auto &jsonEnd = jsonObject.cend();
    if (jsonObject.find(BUNDLELIST) != jsonEnd && jsonObject.at(BUNDLELIST).is_array()) {
        auto bundleListJson = jsonObject.at(BUNDLELIST);
        if (bundleListJson.size() > static_cast<size_t>(MAX_NOTIFICATION_SILENT_AUTH_NUM)) {
            ANS_LOGE("bundleList size exceeds limit: %{public}zu", bundleListJson.size());
            return;
        }
        for (const auto &bundle : bundleListJson) {
            if (bundle.is_string()) {
                bundleList_.push_back(bundle.get<std::string>());
            }
        }
    }
    if (jsonObject.find(USERID) != jsonEnd && jsonObject.at(USERID).is_number_integer()) {
        int64_t val = jsonObject.at(USERID).get<int64_t>();
        if (val < INT32_MIN || val > INT32_MAX) {
            ANS_LOGE("userId out of range: %{public}" PRId64, val);
        } else {
            userId_ = static_cast<int32_t>(val);
        }
    }
}
}
}
