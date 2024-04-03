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
#include "ans_log_wrapper.h"
#include "want_params_wrapper.h"

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
        ", isOnlyLocalUpdate_ = " + (GetIsOnlyLocalUpdate()?"true":"false") + pictureStr + "}";
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
        ANS_LOGE("Failed to create liveViewContent instance");
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
            ANS_LOGE("Failed to write additionalParams");
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

    return MarshallingPictureMap(parcel);
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
    for (uint64_t i = 0; i < len; i++) {
        auto key = parcel.ReadString();
        std::vector<std::string> strVec;
        if (!parcel.ReadStringVector(&strVec)) {
            ANS_LOGE("Failed to read extraInfo vector string.");
            return false;
        }
        std::vector<std::shared_ptr<Media::PixelMap>> pixelMapVec;
        pixelMapVec.reserve(strVec.size());
        for (const auto &str : strVec) {
            pixelMapVec.emplace_back(AnsImageUtil::UnPackImage(str));
        }
        pictureMap_[key] = pixelMapVec;
    }

    return true;
}

bool NotificationLiveViewContent::MarshallingPictureMap(Parcel &parcel) const
{
    if (!pictureMarshallingMap_.empty()) {
        ANS_LOGD("Write pictureMap by pictureMarshallingMap.");
        for (const auto &picture : pictureMarshallingMap_) {
            if (!parcel.WriteString(picture.first)) {
                ANS_LOGE("Failed to write picture map key %{public}s.", picture.first.c_str());
                return false;
            }

            if (!parcel.WriteStringVector(picture.second)) {
                ANS_LOGE("Failed to write picture vector of key %{public}s.", picture.first.c_str());
                return false;
            }
        }
        return true;
    }

    for (const auto &picture : pictureMap_) {
        if (!parcel.WriteString(picture.first)) {
            ANS_LOGE("Failed to write picture map key %{public}s.", picture.first.c_str());
            return false;
        }
        std::vector<std::string> pixelVec;
        pixelVec.reserve(picture.second.size());
        for (const auto &pixel : picture.second) {
            pixelVec.emplace_back(AnsImageUtil::PackImage(pixel));
        }
        if (!parcel.WriteStringVector(pixelVec)) {
            ANS_LOGE("Failed to write picture vector of key %{public}s.", picture.first.c_str());
            return false;
        }
    }

    return true;
}

void NotificationLiveViewContent::FillPictureMarshallingMap()
{
    pictureMarshallingMap_.clear();
    for (const auto &picture : pictureMap_) {
        std::vector<std::string> pixelVec;
        pixelVec.reserve(picture.second.size());
        for (const auto &pixel : picture.second) {
            pixelVec.emplace_back(AnsImageUtil::PackImage(pixel));
        }
        pictureMarshallingMap_[picture.first] = pixelVec;
    }
}

void NotificationLiveViewContent::ClearPictureMarshallingMap()
{
    pictureMarshallingMap_.clear();
}

PictureMarshallingMap NotificationLiveViewContent::GetPictureMarshallingMap() const
{
    return pictureMarshallingMap_;
}

}  // namespace Notification
}  // namespace OHOS
