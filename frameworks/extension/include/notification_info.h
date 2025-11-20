/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORK_EXTENSION_OTIFICATION_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORK_EXTENSION_OTIFICATION_INFO_H

#include "notification_constant.h"
#include "notification_extension_content.h"
#include "notification_json_convert.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
class NotificationInfo : public Parcelable, public NotificationJsonConvertionBase {
public:
    void SetHashCode(const std::string& hashCode);
    std::string GetHashCode() const;

    void SetNotificationSlotType(NotificationConstant::SlotType notificationSlotType);
    NotificationConstant::SlotType GetNotificationSlotType() const;

    void SetNotificationExtensionContent(std::shared_ptr<NotificationExtensionContent> content);
    std::shared_ptr<NotificationExtensionContent> GetNotificationExtensionContent() const;

    void SetBundleName(const std::string& bundleName);
    std::string GetBundleName() const;

    void SetDeliveryTime(int64_t deliveryTime);
    int64_t GetDeliveryTime() const;

    void SetGroupName(const std::string& groupName);
    std::string GetGroupName() const;

    void SetAppName(const std::string& appName);
    std::string GetAppName() const;

    void SetAppIndex(int32_t appIndex);
    int32_t GetAppIndex() const;

    /**
     * @brief Returns a string representation of the object.
     *
     * @return Returns a string representation of the object.
     */
    virtual std::string Dump();

    /**
     * @brief Converts a NotificationInfo object into a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ToJson(nlohmann::json &jsonObject) const override;

    /**
     * @brief Marshal a object into a Parcel.
     *
     * @param parcel the object into the parcel.
     * @return Returns true if succeed; returns false otherwise.
     */
    virtual bool Marshalling(Parcel &parcel) const override;

    /**
     * Unmarshal object from a Parcel.
     * @return the NotificationInfo
     */
    static NotificationInfo *Unmarshalling(Parcel &parcel);

    /**
     * @brief Creates a NotificationInfo object from a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns the NotificationInfo object.
     */
    static NotificationInfo *FromJson(const nlohmann::json &jsonObject);

private:
    /**
     * @brief Read a NotificationInfo object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel);

private:
    std::string hashCode_ {};
    NotificationConstant::SlotType notificationSlotType_ {NotificationConstant::SlotType::ILLEGAL_TYPE};
    std::shared_ptr<NotificationExtensionContent> content_ {};
    std::string bundleName_ {};
    std::string appName_ {};
    int64_t deliveryTime_ = 0;
    std::string groupName_ {};
    int32_t appIndex_ = 0;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORK_EXTENSION_OTIFICATION_INFO_H