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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_ICON_BUTTON_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_ICON_BUTTON_H

#include "notification_json_convert.h"
#include "resource_manager.h"
#include "parcel.h"
#include <string>
#include <vector>
#include "pixel_map.h"
namespace OHOS {
namespace Notification {
using namespace Global::Resource;
const uint32_t BUTTON_MAX_SIZE = 3;
const uint32_t CAPSULE_BTN_MAX_SIZE = 2;
const uint32_t BUTTON_RESOURCE_SIZE = 3;
const uint32_t RESOURCE_BUNDLENAME_INDEX = 0;
const uint32_t RESOURCE_MODULENAME_INDEX = 1;
const uint32_t RESOURCE_ID_INDEX = 2;

class NotificationIconButton : public Parcelable, public NotificationJsonConvertionBase {
public:
    NotificationIconButton() = default;
    ~NotificationIconButton() = default;

    NotificationIconButton(const NotificationIconButton &other);
    /**
     * @brief Obtains the icon of the notification capsule.
     *
     * @return Returns the icon of the notification capsule.
     */
    const std::shared_ptr<ResourceManager::Resource> GetIconResource() const;

    void SetIconResource(const std::shared_ptr<ResourceManager::Resource> &iconResource);

    const std::shared_ptr<Media::PixelMap> GetIconImage() const;

    void SetIconImage(const std::shared_ptr<Media::PixelMap> &iconImage);

    /**
     * @brief Obtains the text of the notification button.
     *
     * @return Returns the text of the notification button.
     */
    std::string GetText() const;

    void SetText(const std::string &text);

    /**
     * @brief Obtains the unqiue name of the notification button.
     *
     * @return Returns the unqiue name of the notification button.
     */
    std::string GetName() const;

    void SetName(const std::string &name);

    /**
     * @brief Obtains the hidePanel of the notification button.
     *
     * @return Returns the hidePanel of the notification button.
     */
    bool GetHidePanel() const;

    void SetHidePanel(bool hidePanel);

    /**
     * @brief Returns a string representation of the object.
     *
     * @return Returns a string representation of the object.
     */
    std::string Dump();

    /**
     * @brief Converts a notification capsule object into a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ToJson(nlohmann::json &jsonObject) const override;

    /**
     * @brief Creates a notification capsule object from a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns the notification capsule.
     */
    static NotificationIconButton *FromJson(const nlohmann::json &jsonObject);

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
     * @return Returns the notification capsule.
     */
    static NotificationIconButton *Unmarshalling(Parcel &parcel);

    void ClearButtonIconsResource();

    bool WriteIconToParcel(Parcel &parcel) const;

    bool ReadResourceFromParcel(Parcel &parcel, std::shared_ptr<ResourceManager::Resource> &resourceObj);
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
private:
    std::string text_ {};
    std::string name_ {};
    std::shared_ptr<ResourceManager::Resource> iconResource_ {};
    std::shared_ptr<Media::PixelMap> iconImage_ {};
    bool hidePanel_;
};
}  // namespace Notification
}  // namespace OHOS
#endif  //BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_ICON_BUTTON_H
