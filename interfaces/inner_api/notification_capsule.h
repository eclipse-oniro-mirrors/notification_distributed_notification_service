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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_CAPSULE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_CAPSULE_H

#include "pixel_map.h"
#include "notification_json_convert.h"
#include "parcel.h"
#include "notification_icon_button.h"
#include <string>

namespace OHOS {
namespace Notification {
class NotificationCapsule : public Parcelable, public NotificationJsonConvertionBase {
public:
    NotificationCapsule() = default;

    ~NotificationCapsule() = default;

    /**
     * @brief Obtains the title of the notification capsule.
     *
     * @return Returns the title of the notification capsule.
     */
    std::string GetTitle() const;

    void SetTitle(const std::string &title);

    /**
     * @brief Obtains the icon of the notification capsule.
     *
     * @return Returns the icon of the notification capsule.
     */
    const std::shared_ptr<Media::PixelMap> GetIcon() const;

    void SetIcon(const std::shared_ptr<Media::PixelMap> &icon);

    /**
     * @brief Obtains the backgroundcolor of the notification capsule.
     *
     * @return Returns the backgroundcolor of the notification capsule.
     */
    std::string GetBackgroundColor() const;

    void SetBackgroundColor(const std::string &color);

    /**
     * @brief Obtains the content of the notification capsule.
     *
     * @return Returns the content of the notification capsule.
     */
    std::string GetContent() const;

    void SetContent(const std::string &content);

    /**
     * @brief Obtains the button of the notification capsule.
     *
     * @return Returns the button of the notification capsule.
     */
    std::vector<NotificationIconButton> GetCapsuleButton() const;

    void SetCapsuleButton(const std::vector<NotificationIconButton> &buttons);

    /**
     * @brief Obtains the expire time of the notification capsule.
     *
     * @return Returns the expire time of the notification capsule.
     */
    int32_t GetTime() const;

    void SetTime(int32_t time);

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
    static NotificationCapsule *FromJson(const nlohmann::json &jsonObject);

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
    static NotificationCapsule *Unmarshalling(Parcel &parcel);

    void ResetIcon();

private:
    /**
     * @brief Read a NotificationConversationalMessage object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel);

private:
    std::string title_ {};
    std::string backgroundColor_ {};
    std::string content_ {};
    std::shared_ptr<Media::PixelMap> icon_ {};
    std::vector<NotificationIconButton> capsuleButton_;
    int32_t time_ {0};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_CAPSULE_H
