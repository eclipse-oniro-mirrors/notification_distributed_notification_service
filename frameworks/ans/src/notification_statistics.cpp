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

#include "notification_statistics.h"

#include <cstdint>
#include <string>
#include <memory>


#include "ans_log_wrapper.h"
#include "nlohmann/json.hpp"
#include "parcel.h"

namespace OHOS {
namespace Notification {

int64_t NotificationStatistics::GetLastTime() const
{
    return lastTime_;
}

void NotificationStatistics::SetLastTime(int64_t lastTime)
{
    lastTime_ = lastTime;
}

void NotificationStatistics::SetBundleOption(const NotificationBundleOption &bundle)
{
    bundle_ =  bundle;
}

const NotificationBundleOption& NotificationStatistics::GetBundleOption() const
{
    return bundle_;
}

int32_t NotificationStatistics::GetRecentCount() const
{
    return recentCount_;
}

void NotificationStatistics::SetRecentCount(int32_t recentCount)
{
    recentCount_ = recentCount;
}

std::string NotificationStatistics::Dump()
{
    return "Statistics{ "
            "bundle = " + bundle_.Dump() +
            ", lastTime = " + std::to_string(lastTime_) +
            ", recentCount = " + std::to_string(recentCount_) +
            " }";
}

bool NotificationStatistics::ToJson(nlohmann::json &jsonObject) const
{
    nlohmann::json bundleObj;
    if (!NotificationJsonConverter::ConvertToJson(&bundle_, bundleObj)) {
        ANS_LOGE("Cannot convert bundleOption to JSON");
        return false;
    }
    jsonObject["bundle"] = bundleObj;
    jsonObject["lastTime"] = lastTime_;
    jsonObject["recentCount"] = recentCount_;

    return true;
}

NotificationStatistics *NotificationStatistics::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    NotificationStatistics *statistics = new (std::nothrow) NotificationStatistics();
    if (statistics == nullptr) {
        ANS_LOGE("null statistics");
        return nullptr;
    }

    const auto &jsonEnd = jsonObject.cend();
    if (jsonObject.find("bundle") != jsonEnd) {
        auto bundleObj = jsonObject.at("bundle");
        auto pBundle = NotificationJsonConverter::ConvertFromJson<NotificationBundleOption>(bundleObj);
        if (pBundle != nullptr) {
            statistics->bundle_ = *pBundle;
            delete pBundle;
            pBundle = nullptr;
        }
    }

    if (jsonObject.find("lastTime") != jsonEnd && jsonObject.at("lastTime").is_number_integer()) {
        statistics->lastTime_ = jsonObject.at("lastTime").get<int64_t>();
    }

    if (jsonObject.find("recentCount") != jsonEnd && jsonObject.at("recentCount").is_number_integer()) {
        statistics->recentCount_ = jsonObject.at("recentCount").get<int32_t>();
    }

    return statistics;
}

bool NotificationStatistics::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteParcelable(&bundle_)) {
        ANS_LOGE("Failed to write bundle");
        return false;
    }

    if (!parcel.WriteInt64(lastTime_)) {
        ANS_LOGE("Failed to write lastTime");
        return false;
    }

    if (!parcel.WriteInt32(recentCount_)) {
        ANS_LOGE("Failed to write recentCount");
        return false;
    }

    return true;
}

bool NotificationStatistics::ReadFromParcel(Parcel &parcel)
{
    auto pBundle = parcel.ReadParcelable<NotificationBundleOption>();
    if (pBundle == nullptr) {
        ANS_LOGE("null BundleOption");
        return false;
    }
    bundle_ = *pBundle;
    delete pBundle;
    pBundle = nullptr;

    lastTime_ = parcel.ReadInt64();
    recentCount_ = parcel.ReadInt32();

    return true;
}

NotificationStatistics *NotificationStatistics::Unmarshalling(Parcel &parcel)
{
    NotificationStatistics *statistics = new (std::nothrow) NotificationStatistics();

    if (statistics && !statistics->ReadFromParcel(parcel)) {
        delete statistics;
        statistics = nullptr;
    }

    return statistics;
}
}  // namespace Notification
}  // namespace OHOS
