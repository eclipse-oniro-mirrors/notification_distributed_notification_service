/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "notification_check_info.h"
#include "ans_log_wrapper.h"
#include "want_params_wrapper.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace Notification {

NotificationCheckInfo::NotificationCheckInfo(std::string pkgName, int32_t notifyId, int32_t contentType,
    int32_t creatorUserId, int32_t slotType, std::shared_ptr<AAFwk::WantParams> extraInfo)
    : pkgName_(pkgName), notifyId_(notifyId), contentType_(contentType),
    creatorUserId_(creatorUserId), slotType_(slotType), extraInfo_(extraInfo)
{}

NotificationCheckInfo::~NotificationCheckInfo()
{}

std::string NotificationCheckInfo::GetPkgName() const
{
    return pkgName_;
}

void NotificationCheckInfo::SetPkgName(std::string pkgName)
{
    pkgName_ = pkgName;
}

int32_t NotificationCheckInfo::GetNotifyId() const
{
    return notifyId_;
}

void NotificationCheckInfo::SetNotifyId(int32_t notifyId)
{
    notifyId_ = notifyId;
}


int32_t NotificationCheckInfo::GetContentType() const
{
    return contentType_;
}

void NotificationCheckInfo::SetContentType(int32_t contentType)
{
    contentType_ = contentType;
}


int32_t NotificationCheckInfo::GetCreatorUserId() const
{
    return creatorUserId_;
}

void NotificationCheckInfo::SetCreatorUserId(int32_t creatorUserId)
{
    creatorUserId_ = creatorUserId;
}

int32_t NotificationCheckInfo::GetSlotType() const
{
    return slotType_;
}

void NotificationCheckInfo::SetSlotType(int32_t slotType)
{
    slotType_ = slotType;
}

std::string NotificationCheckInfo::GetLabel() const
{
    return label_;
}

void NotificationCheckInfo::SetLabel(std::string label)
{
    label_ = label;
}

std::shared_ptr<AAFwk::WantParams> NotificationCheckInfo::GetExtraInfo() const
{
    return extraInfo_;
}

void NotificationCheckInfo::SetExtraInfo(std::shared_ptr<AAFwk::WantParams> extraInfo)
{
    extraInfo_ = extraInfo;
}

void NotificationCheckInfo::ConvertJsonExtraInfoToValue(nlohmann::json &jsonobj)
{
    const auto &jsonEnd = jsonobj.cend();
    if (jsonobj.find("extraInfo") == jsonEnd) {
        return;
    }

    if (!jsonobj.at("extraInfo").is_string()) {
        ANS_LOGE("Invalid JSON object extraInfo");
        return;
    }
    auto extraInfoStr = jsonobj.at("extraInfo").get<std::string>();
    if (!extraInfoStr.empty()) {
        AAFwk::WantParams params = AAFwk::WantParamWrapper::ParseWantParams(extraInfoStr);
        extraInfo_ = std::make_shared<AAFwk::WantParams>(params);
    }
}

void NotificationCheckInfo::ConvertJsonStringToValue(const std::string &notificationData)
{
    nlohmann::json jsonobj = nlohmann::json::parse(notificationData);
    if (jsonobj.is_null() || !jsonobj.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return;
    }

    const auto &jsonEnd = jsonobj.cend();
    if (jsonobj.find("pkgName") != jsonEnd && jsonobj.at("pkgName").is_string()) {
        pkgName_ = jsonobj.at("pkgName").get<std::string>();
    }
    if (jsonobj.find("notifyId") != jsonEnd && jsonobj.at("notifyId").is_number()) {
        notifyId_ = jsonobj.at("notifyId").get<int32_t>();
    }
    if (jsonobj.find("contentType") != jsonEnd && jsonobj.at("contentType").is_number()) {
        contentType_ = jsonobj.at("contentType").get<int32_t>();
    }
    if (jsonobj.find("creatorUserId") != jsonEnd && jsonobj.at("creatorUserId").is_number()) {
        creatorUserId_ = jsonobj.at("creatorUserId").get<int32_t>();
    }
    if (jsonobj.find("slotType") != jsonEnd && jsonobj.at("slotType").is_number()) {
        slotType_ = jsonobj.at("slotType").get<int32_t>();
    }
    if (jsonobj.find("label") != jsonEnd && jsonobj.at("label").is_string()) {
        label_ = jsonobj.at("label").get<std::string>();
    }
    ConvertJsonExtraInfoToValue(jsonobj);
}
}  // namespace Notification
}  // namespace OHOS
