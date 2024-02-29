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

#include "notification_unified_group_Info.h"

#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "errors.h"
#include "want_agent_helper.h"
#include "want_params_wrapper.h"
#include <memory>

namespace OHOS {
namespace Notification {
std::string NotificationUnifiedGroupInfo::GetKey() const
{
    return key_;
}

void NotificationUnifiedGroupInfo::SetKey(const std::string &key)
{
    key_ = key;
}

std::string NotificationUnifiedGroupInfo::GetTitle() const
{
    return title_;
}

void NotificationUnifiedGroupInfo::SetTitle(const std::string &title)
{
    title_ = title;
}

std::string NotificationUnifiedGroupInfo::GetContent() const
{
    return content_;
}

void NotificationUnifiedGroupInfo::SetContent(const std::string &content)
{
    content_ = content;
}

std::string NotificationUnifiedGroupInfo::GetSceneName() const
{
    return sceneName_;
}

void NotificationUnifiedGroupInfo::SetSceneName(const std::string &sceneName)
{
    sceneName_ = sceneName;
}


std::shared_ptr<AAFwk::WantParams> NotificationUnifiedGroupInfo::GetExtraInfo() const
{
    return extraInfo_;
}

void NotificationUnifiedGroupInfo::SetExtraInfo(const std::shared_ptr<AAFwk::WantParams> &extras)
{
    extraInfo_ = extras;
}

std::string NotificationUnifiedGroupInfo::Dump()
{
    std::string extraStr{"null"};
    if (extraInfo_ != nullptr) {
        AAFwk::WantParamWrapper wWrapper(*extraInfo_);
        extraStr = wWrapper.ToString();
    }

    return "NotificationUnifiedGroupInfo{ key = " + key_ + ", title = " + title_ + ", content = " + content_ +
            ", sceneName = " + sceneName_ + ", extraInfo = " + extraStr +" }";
}

bool NotificationUnifiedGroupInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(key_)) {
        ANS_LOGE("Failed to write key");
        return false;
    }

    if (!parcel.WriteString(title_)) {
        ANS_LOGE("Failed to write title");
        return false;
    }

    if (!parcel.WriteString(content_)) {
        ANS_LOGE("Failed to write content");
        return false;
    }

    if (!parcel.WriteString(sceneName_)) {
        ANS_LOGE("Failed to write sceneName");
        return false;
    }

    bool valid = extraInfo_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag which indicate whether extraInfo is null");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(extraInfo_.get())) {
            ANS_LOGE("Failed to write extraInfo");
            return false;
        }
    }

    return true;
}

NotificationUnifiedGroupInfo *NotificationUnifiedGroupInfo::Unmarshalling(Parcel &parcel)
{
    auto unifiedGroupInfo = new (std::nothrow) NotificationUnifiedGroupInfo();
    if ((unifiedGroupInfo != nullptr) && !unifiedGroupInfo->ReadFromParcel(parcel)) {
        delete unifiedGroupInfo;
        unifiedGroupInfo = nullptr;
    }

    return unifiedGroupInfo;
}

bool NotificationUnifiedGroupInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(key_)) {
        ANS_LOGE("Failed to read key");
        return false;
    }

    if (!parcel.ReadString(title_)) {
        ANS_LOGE("Failed to read title");
        return false;
    }

    if (!parcel.ReadString(content_)) {
        ANS_LOGE("Failed to read content");
        return false;
    }

    if (!parcel.ReadString(sceneName_)) {
        ANS_LOGE("Failed to read sceneName");
        return false;
    }

    auto valid = parcel.ReadBool();
    if (valid) {
        extraInfo_ = std::shared_ptr<AAFwk::WantParams>(parcel.ReadParcelable<AAFwk::WantParams>());
        if (!extraInfo_) {
            ANS_LOGE("Failed to read extraInfo");
            return false;
        }
    }

    return true;
}
}
}
