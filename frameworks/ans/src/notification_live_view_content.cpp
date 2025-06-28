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

#include "notification_live_view_content.h"
#include <string>
#include "ans_image_util.h"
#include "ans_ipc_common_utils.h"
#include "ans_log_wrapper.h"
#include "want_params_wrapper.h"
#include "want_agent_helper.h"
#include "ans_const_define.h"

namespace OHOS {
namespace Notification {
const uint32_t NotificationLiveViewContent::MAX_VERSION {0xffffffff};
void NotificationLiveViewContent::SetLiveViewStatus(const LiveViewStatus status)
{
    liveViewStatus_ = status;
}

NotificationLiveViewContent::LiveViewStatus NotificationLiveViewContent::GetLiveViewStatus() const
{
    return liveViewStatus_;
}

void NotificationLiveViewContent::SetVersion(uint32_t version)
{
    version_ = version;
}

uint32_t NotificationLiveViewContent::GetVersion() const
{
    return version_;
}

void NotificationLiveViewContent::SetExtraInfo(const std::shared_ptr<AAFwk::WantParams> &extras)
{
    extraInfo_ = extras;
}

std::shared_ptr<AAFwk::WantParams> NotificationLiveViewContent::GetExtraInfo() const
{
    return extraInfo_;
}

void NotificationLiveViewContent::SetPicture(const PictureMap &pictureMap)
{
    pictureMap_ = pictureMap;
}

PictureMap NotificationLiveViewContent::GetPicture() const
{
    return pictureMap_;
}

void NotificationLiveViewContent::SetIsOnlyLocalUpdate(const bool &isOnlyLocalUpdate)
{
    isOnlyLocalUpdate_ = isOnlyLocalUpdate;
}

bool NotificationLiveViewContent::GetIsOnlyLocalUpdate() const
{
    return isOnlyLocalUpdate_;
}

void NotificationLiveViewContent::SetExtensionWantAgent(
    const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> &wantAgent)
{
    extensionWantAgent_ = wantAgent;
}

const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> NotificationLiveViewContent::GetExtensionWantAgent() const
{
    return extensionWantAgent_;
}

void NotificationLiveViewContent::SetUid(const int32_t uid)
{
    uid_ = uid;
}

int32_t NotificationLiveViewContent::GetUid() const
{
    return uid_;
}

std::string NotificationLiveViewContent::Dump()
{
    std::string extraStr{"null"};
    if (extraInfo_ != nullptr) {
        AAFwk::WantParamWrapper wWrapper(*extraInfo_);
        extraStr = wWrapper.ToString();
    }

    std::string pictureStr {", pictureMap = {"};
    for (auto &picture : pictureMap_) {
        pictureStr += " { key = " + picture.first + ", value = " +
            (picture.second.empty() ? "empty" : "not empty") + " },";
    }
    if (pictureStr[pictureStr.length() - 1] == ',') {
        pictureStr[pictureStr.length() - 1] = ' ';
    }
    pictureStr += "}";

    return "NotificationLiveViewContent{ " + NotificationBasicContent::Dump() +
        ", status = " + std::to_string(static_cast<int32_t>(liveViewStatus_)) + ", version = " +
        std::to_string(static_cast<int32_t>(version_)) + ", extraInfo = " + extraStr +
        ", isOnlyLocalUpdate_ = " + (GetIsOnlyLocalUpdate()?"true":"false") + pictureStr +
        ", extensionWantAgent_ = " + (extensionWantAgent_ ? "not null" : "null") + "}";
}

bool NotificationLiveViewContent::PictureToJson(nlohmann::json &jsonObject) const
{
    nlohmann::json pixelMap;

    if (pictureMap_.empty()) {
        return true;
    }
    for (const auto &picture : pictureMap_) {
        nlohmann::json pixelRecordArr = nlohmann::json::array();
        for (const auto &pixelMap : picture.second) {
            pixelRecordArr.emplace_back(AnsImageUtil::PackImage(pixelMap));
        }
        pixelMap[picture.first] = pixelRecordArr;
    }
    jsonObject["pictureMap"] = pixelMap;
    return true;
}

bool NotificationLiveViewContent::ToJson(nlohmann::json &jsonObject) const
{
    if (!NotificationBasicContent::ToJson(jsonObject)) {
        ANS_LOGE("Cannot convert basicContent to JSON");
        return false;
    }

    jsonObject["status"] = static_cast<int32_t>(liveViewStatus_);
    jsonObject["version"] = version_;

    if (extraInfo_) {
        AAFwk::WantParamWrapper wWrapper(*extraInfo_);
        jsonObject["extraInfo"] = wWrapper.ToString();
    }

    jsonObject["isLocalUpdateOnly"] = isOnlyLocalUpdate_;
    if (extensionWantAgent_ != nullptr) {
        jsonObject["extensionWantAgent"] = AbilityRuntime::WantAgent::WantAgentHelper::ToString(extensionWantAgent_);
        jsonObject["uid"] = uid_;
    }

    return PictureToJson(jsonObject);
}

void NotificationLiveViewContent::ConvertPictureFromJson(const nlohmann::json &jsonObject)
{
    const auto &jsonEnd = jsonObject.cend();
    if ((jsonObject.find("pictureMap") != jsonEnd) && jsonObject.at("pictureMap").is_object()) {
        auto pictureMap = jsonObject.at("pictureMap").get<nlohmann::json>();
        for (auto it = pictureMap.begin(); it != pictureMap.end(); it++) {
            if (!it.value().is_array()) {
                continue;
            }
            auto pictureArray = it.value().get<std::vector<std::string>>();
            pictureMap_[it.key()] = std::vector<std::shared_ptr<Media::PixelMap>>();
            for (const auto &picture : pictureArray) {
                pictureMap_[it.key()].emplace_back(AnsImageUtil::UnPackImage(picture));
            }
        }
    }
}

NotificationLiveViewContent *NotificationLiveViewContent::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    auto *pContent = new (std::nothrow) NotificationLiveViewContent();
    if (pContent == nullptr) {
        ANS_LOGE("null pContent");
        return nullptr;
    }

    pContent->ReadFromJson(jsonObject);

    const auto &jsonEnd = jsonObject.cend();
    if (jsonObject.find("status") != jsonEnd && jsonObject.at("status").is_number_integer()) {
        auto statusValue = jsonObject.at("status").get<int32_t>();
        pContent->liveViewStatus_ = static_cast<NotificationLiveViewContent::LiveViewStatus>(statusValue);
    }

    if (jsonObject.find("version") != jsonEnd && jsonObject.at("version").is_number_integer()) {
        pContent->version_ = jsonObject.at("version").get<uint32_t>();
    }

    if (jsonObject.find("extraInfo") != jsonEnd && jsonObject.at("extraInfo").is_string()) {
        std::string extraInfoStr = jsonObject.at("extraInfo").get<std::string>();
        if (!extraInfoStr.empty()) {
            AAFwk::WantParams params = AAFwk::WantParamWrapper::ParseWantParamsWithBrackets(extraInfoStr);
            pContent->extraInfo_ = std::make_shared<AAFwk::WantParams>(params);
        }
    }
    if (jsonObject.find("isOnlyLocalUpdate") != jsonEnd && jsonObject.at("isOnlyLocalUpdate").is_boolean()) {
        pContent->isOnlyLocalUpdate_ = jsonObject.at("isOnlyLocalUpdate").get<bool>();
    }
    pContent->ConvertPictureFromJson(jsonObject);

    if (jsonObject.find("uid") != jsonEnd && jsonObject.at("uid").is_number_integer()) {
        pContent->uid_ =jsonObject.at("uid").get<int32_t>();
    }

    if (jsonObject.find("extensionWantAgent") != jsonEnd && jsonObject.at("extensionWantAgent").is_string()) {
        auto extensionWantAgentString  = jsonObject.at("extensionWantAgent").get<std::string>();
        pContent->extensionWantAgent_ = AbilityRuntime::WantAgent::WantAgentHelper::FromString(
            extensionWantAgentString, pContent->uid_);
    } else {
        ANS_LOGW("no want");
    }
    return pContent;
}

bool NotificationLiveViewContent::Marshalling(Parcel &parcel) const
{
    if (!NotificationBasicContent::Marshalling(parcel)) {
        ANS_LOGE("Failed to write basic");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(liveViewStatus_))) {
        ANS_LOGE("Failed to write liveView status");
        return false;
    }

    if (!parcel.WriteUint32(version_)) {
        ANS_LOGE("Failed to write version");
        return false;
    }

    bool valid{false};
    if (extraInfo_ != nullptr) {
        valid = true;
    }
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
    if (!parcel.WriteBool(isOnlyLocalUpdate_)) {
        ANS_LOGE("OnlyLocalUpdate is Failed to write.");
        return false;
    }
    if (!parcel.WriteUint64(pictureMap_.size())) {
        ANS_LOGE("Failed to write the size of pictureMap.");
        return false;
    }

    bool res = MarshallingPictureMap(parcel);
    if (!res) {
        return res;
    }
    return MarshallingExtensionWantAgent(parcel);
}

bool NotificationLiveViewContent::MarshallingExtensionWantAgent(Parcel &parcel) const
{
    bool valid{false};

    valid = extensionWantAgent_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag which indicate whether wantAgent is null");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(extensionWantAgent_.get())) {
            ANS_LOGE("Failed to write wantAgent");
            return false;
        }
    }
    return true;
}

NotificationLiveViewContent *NotificationLiveViewContent::Unmarshalling(Parcel &parcel)
{
    auto *pContent = new (std::nothrow) NotificationLiveViewContent();
    if ((pContent != nullptr) && !pContent->ReadFromParcel(parcel)) {
        delete pContent;
        pContent = nullptr;
    }

    return pContent;
}

bool NotificationLiveViewContent::ReadFromParcel(Parcel &parcel)
{
    if (!NotificationBasicContent::ReadFromParcel(parcel)) {
        ANS_LOGE("Failed to read basic");
        return false;
    }

    liveViewStatus_ = static_cast<NotificationLiveViewContent::LiveViewStatus>(parcel.ReadInt32());
    version_ = parcel.ReadUint32();

    bool valid = parcel.ReadBool();
    if (valid) {
        extraInfo_ = std::shared_ptr<AAFwk::WantParams>(parcel.ReadParcelable<AAFwk::WantParams>());
        if (!extraInfo_) {
            ANS_LOGE("Failed to read extraInfo.");
            return false;
        }
    }

    isOnlyLocalUpdate_ = parcel.ReadBool();

    uint64_t len = parcel.ReadUint64();
    if (len > MAX_PARCELABLE_VECTOR_NUM) {
        ANS_LOGE("Size exceeds the range.");
        return false;
    }
    for (uint64_t i = 0; i < len; i++) {
        auto key = parcel.ReadString();
        std::vector<std::shared_ptr<Media::PixelMap>> pixelMapVec;
        if (!AnsIpcCommonUtils::ReadParcelableVector(pixelMapVec, parcel)) {
            ANS_LOGE("Failed to read extraInfo vector string.");
            return false;
        }
        pictureMap_[key] = pixelMapVec;
    }

    valid = parcel.ReadBool();
    if (valid) {
        extensionWantAgent_ = std::shared_ptr<AbilityRuntime::WantAgent::WantAgent>(
            parcel.ReadParcelable<AbilityRuntime::WantAgent::WantAgent>());
        if (!extensionWantAgent_) {
            ANS_LOGE("null wantAgent");
            return false;
        }
    }
    return true;
}

bool NotificationLiveViewContent::MarshallingPictureMap(Parcel &parcel) const
{
    for (const auto &picture : pictureMap_) {
        if (!parcel.WriteString(picture.first)) {
            ANS_LOGE("Failed to write picture map key %{public}s.", picture.first.c_str());
            return false;
        }
        
        if (!AnsIpcCommonUtils::WriteParcelableVector(picture.second, parcel)) {
            ANS_LOGE("Failed to write picture vector of key %{public}s.", picture.first.c_str());
            return false;
        }
    }
    return true;
}

void NotificationLiveViewContent::ClearPictureMap()
{
    return pictureMap_.clear();
}

}  // namespace Notification
}  // namespace OHOS
