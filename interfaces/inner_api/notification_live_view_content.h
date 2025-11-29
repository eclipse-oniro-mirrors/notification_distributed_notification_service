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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_LIVE_VIEW_CONTENT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_LIVE_VIEW_CONTENT_H

#include "notification_basic_content.h"
#include "parcel.h"
#include "pixel_map.h"
#include "want_params.h"
#include "want_agent.h"

namespace OHOS {
namespace Notification {
using PictureMap = std::map<std::string, std::vector<std::shared_ptr<Media::PixelMap>>>;
using PictureMarshallingMap = std::map<std::string, std::vector<std::string>>;
class NotificationLiveViewContent : public NotificationBasicContent {
public:
    static const uint32_t MAX_VERSION;
    enum class LiveViewStatus {
        LIVE_VIEW_CREATE,
        LIVE_VIEW_INCREMENTAL_UPDATE,
        LIVE_VIEW_END,
        LIVE_VIEW_FULL_UPDATE,
        LIVE_VIEW_PENDING_CREATE = 4,
        LIVE_VIEW_PENDING_END = 6,
        LIVE_VIEW_BUTT = 255
    };

    NotificationLiveViewContent() = default;
    ~NotificationLiveViewContent() override = default;
    /**
     * @brief Set the status of the liveView notification.
     *
     * @param status Indicates the status of liveView notification.
     */
    void SetLiveViewStatus(const LiveViewStatus status);

    /**
     * @brief Obtains the status of the liveView notification.
     *
     * @return Returns the status that attached to this notification.
     */
    LiveViewStatus GetLiveViewStatus() const;

    /**
     * @brief Set the version of the liveView notification.
     *
     * @param status Indicates the version of liveView notification.
     */
    void SetVersion(uint32_t version);

    /**
     * @brief Obtains the version of the liveView notification.
     *
     * @return Returns the version that attached to this notification.
     */
    uint32_t GetVersion() const;

    /**
     * @brief Sets extra parameters that are stored as key-value pairs for the notification content.
     *
     * @param extras Indicates the WantParams object containing the extra parameters in key-value pair format.
     */
    void SetExtraInfo(const std::shared_ptr<AAFwk::WantParams> &extras);

    /**
     * @brief Obtains the WantParams object set in the notification content.
     *
     * @return Returns the WantParams object.
     */
    std::shared_ptr<AAFwk::WantParams> GetExtraInfo() const;

    /**
     * @brief Sets extra picture parameters that are stored as key-value pairs for the notification content.
     *
     * @param picture Indicates the picture object containing the extra picture parameters in key-value pair format.
     */
    void SetPicture(const PictureMap &pictureMap);

    /**
     * @brief Obtains the picture object map in the notification content.
     *
     * @return Returns the picture map object.
     */
    PictureMap GetPicture() const;

    /**
     * @brief Returns a string representation of the object.
     *
     * @return Returns a string representation of the object.
     */
    std::string Dump() override;

    /**
     * @brief Converts a NotificationLiveViewContent object into a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ToJson(nlohmann::json &jsonObject) const override;

    /**
     * @brief Creates a NotificationLiveViewContent object from a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns the NotificationLiveViewContent object.
     */
    static NotificationLiveViewContent *FromJson(const nlohmann::json &jsonObject);

    /**
     * @brief Creates a picture object from a Json.
     *
     * @param jsonObject Indicates the Json object.
     */
    void ConvertPictureFromJson(const nlohmann::json &jsonObject);

    /**
     * @brief Marshal a object into a Parcel.
     * @param parcel the object into the parcel.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshal object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns the NotificationLiveViewContent object.
     */
    static NotificationLiveViewContent *Unmarshalling(Parcel &parcel);

    bool MarshallingPictureMap(Parcel &parcel) const;

    void ClearPictureMap();

    void SetIsOnlyLocalUpdate(const bool &isOnlyLocalUpdate);

    bool GetIsOnlyLocalUpdate() const;

    void SetExtensionWantAgent(const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> &wantAgent);

    const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> GetExtensionWantAgent() const;

    void SetUid(const int32_t uid);

    int32_t GetUid() const;

    bool MarshallingExtensionWantAgent(Parcel &parcel) const;

protected:
    /**
     * @brief Read a NotificationLiveViewContent object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel) override;

private:
    bool PictureToJson(nlohmann::json &jsonObject) const;
    LiveViewStatus liveViewStatus_ {};
    uint32_t version_ {MAX_VERSION};
    std::shared_ptr<AAFwk::WantParams> extraInfo_ {};
    PictureMap pictureMap_ {};
    bool isOnlyLocalUpdate_ = false;
    int32_t uid_ = -1;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> extensionWantAgent_ {};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_LIVE_VIEW_CONTENT_H
