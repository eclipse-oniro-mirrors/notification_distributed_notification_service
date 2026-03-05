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

#include "notification_group_info.h"

#include <string>                        // for operator+, basic_string, to_...
#include "ans_log_wrapper.h"
#include "parcel.h"                      // for Parcel

namespace OHOS {
namespace Notification {

void NotificationGroupInfo::SetGroupTitle(const std::string &groupTitle)
{
    groupTitle_ = groupTitle;
}

std::string NotificationGroupInfo::GetGroupTitle() const
{
    return groupTitle_;
}

void NotificationGroupInfo::SetIsGroupIcon(const bool isGroupIcon)
{
    isGroupIcon_ = isGroupIcon;
}

bool NotificationGroupInfo::GetIsGroupIcon() const
{
    return isGroupIcon_;
}

std::string NotificationGroupInfo::Dump()
{
    return "NotificationGroupInfo{ "
            "isGroupIcon = " + std::to_string(isGroupIcon_) +
            ", groupTitle = " + groupTitle_ +
            " }";
}

bool NotificationGroupInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteBool(isGroupIcon_)) {
        ANS_LOGE("Failed to write isGroupIcon");
        return false;
    }

    if (!parcel.WriteString(groupTitle_)) {
        ANS_LOGE("Failed to write groupTitle");
        return false;
    }
    return true;
}

NotificationGroupInfo *NotificationGroupInfo::Unmarshalling(Parcel &parcel)
{
    auto groupInfo = new (std::nothrow) NotificationGroupInfo();
    if (groupInfo && !groupInfo->ReadFromParcel(parcel)) {
        delete groupInfo;
        groupInfo = nullptr;
    }

    return groupInfo;
}

bool NotificationGroupInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadBool(isGroupIcon_)) {
        ANS_LOGE("Failed to read isGroupIcon");
        return false;
    }

    if (!parcel.ReadString(groupTitle_)) {
        ANS_LOGE("Failed to read groupTitle");
        return false;
    }
    return true;
}

bool NotificationGroupInfo::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject["isGroupIcon"] = isGroupIcon_;
    jsonObject["groupTitle"] = groupTitle_;
    return true;
}

NotificationGroupInfo *NotificationGroupInfo::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    auto *pGroupInfo = new (std::nothrow) NotificationGroupInfo();
    if (pGroupInfo == nullptr) {
        ANS_LOGE("null pGroupInfo");
        return nullptr;
    }

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find("isGroupIcon") != jsonEnd && jsonObject.at("isGroupIcon").is_boolean()) {
        pGroupInfo->isGroupIcon_ = jsonObject.at("isGroupIcon").get<bool>();
    }

    if (jsonObject.find("groupTitle") != jsonEnd && jsonObject.at("groupTitle").is_string()) {
        pGroupInfo->groupTitle_ = jsonObject.at("groupTitle").get<std::string>();
    }
    return pGroupInfo;
}

}  // namespace Notification
}  // namespace OHOS
