/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_LOCAL_LIVE_VIEW_BUTTON_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_LOCAL_LIVE_VIEW_BUTTON_H

#include "notification_button_option.h"
#include "pixel_map.h"
#include "message_user.h"
#include "notification_json_convert.h"
#include "parcel.h"
#include "uri.h"
#include <vector>
#include "resource_manager.h"

namespace OHOS {
namespace Notification {
using namespace Global::Resource;

class NotificationLocalLiveViewButton : public Parcelable, public NotificationJsonConvertionBase {
public:
    NotificationLocalLiveViewButton() = default;
    ~NotificationLocalLiveViewButton() = default;

    /**
     * @brief Obtains the text to be displayed as the content of this message.
     *
     * @return Returns the message content.
     */
    std::vector<std::string> GetAllButtonNames() const;

    void addSingleButtonName(const std::string &buttonName);

    /**
     * @brief Obtains the time when this message arrived.
     *
     * @return Returns the time when this message arrived.
     */
    std::vector<std::shared_ptr<Media::PixelMap>> GetAllButtonIcons() const;

    void addSingleButtonIcon(std::shared_ptr<Media::PixelMap> &icon);

    /**
     * @brief Obtains the buttion icon resource when this message arrived.
     *
     * @return Returns the buttion icon resource when this message arrived.
     */
    std::vector<std::shared_ptr<ResourceManager::Resource>> GetAllButtonIconResource() const;

    void addSingleButtonIconResource(std::shared_ptr<ResourceManager::Resource> &iconResource);

    /**
     * @brief Returns a string representation of the object.
     *
     * @return Returns a string representation of the object.
     */
    std::string Dump();

    /**
     * @brief Converts a NotificationConversationalMessage object into a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ToJson(nlohmann::json &jsonObject) const override;

    /**
     * @brief Creates a NotificationConversationalMessage object from a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns the NotificationConversationalMessage.
     */
    static NotificationLocalLiveViewButton *FromJson(const nlohmann::json &jsonObject);

    /**
     * @brief Marshal a object into a Parcel.
     *
     * @param parcel Indicates the object into the parcel.
     * @return Returns true if succeed; returns false otherwise.
     */
    virtual bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshal object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns the NotificationConversationalMessage.
     */
    static NotificationLocalLiveViewButton *Unmarshalling(Parcel &parcel);

    void ClearButtonIcons();

    void ClearButtonIconsResource();

private:
    /**
     * @brief Read a NotificationConversationalMessage object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel);
    static bool ResourceFromJson(const nlohmann::json &resource,
        std::shared_ptr<ResourceManager::Resource>& resourceObj);
    std::vector<std::string> buttonNames_ {};
    std::vector<std::shared_ptr<Media::PixelMap>> buttonIcons_ {};
    std::vector<std::shared_ptr<ResourceManager::Resource>> buttonIconsResource_ {};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_LOCAL_LIVE_VIEW_BUTTON_H
