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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_CHECK_REQUEST_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_CHECK_REQUEST_H

#include "parcel.h"
#include "notification_content.h"
#include "notification_constant.h"

namespace OHOS {
namespace Notification {
class NotificationCheckRequest : public Parcelable {
public:
    NotificationCheckRequest() = default;

    /**
     * @brief A constructor used to create a NotificationCheckRequest instance based on the filter condition.
     *
     * @param contentType Indicates type of notification content.
     * @param SlotType Indicates type of slot.
     * @param extraInfoKeys Indicates keys of extra info that need to be filtered.
     */
    NotificationCheckRequest(NotificationContent::Type contentType, NotificationConstant::SlotType slotType,
        std::vector<std::string> extraInfoKeys);

    ~NotificationCheckRequest();

    /**
     * @brief Returns a string representation of the object.
     *
     * @return Returns a string representation of the object.
     */
    std::string Dump();

    /**
     * @brief Sets the content type of a notification check request.
     *
     * @param contentType Indicates the content type of the notification check request.
     */
    void SetContentType(NotificationContent::Type contentType);

    /**
     * @brief Obtains the content type of a notification check request.
     *
     * @return Returns the content type of a notification check request.
     */
    NotificationContent::Type GetContentType() const;

    /**
     * @brief Sets the slot type of a notification check request.
     *
     * @param slotType Indicates the slot type of the notification check request.
     */
    void SetSlotType(NotificationConstant::SlotType slotType);

    /**
     * @brief Obtains the slot type of a notification check request.
     *
     * @return Returns the slot type of a notification check request.
     */
    NotificationConstant::SlotType GetSlotType() const;

    /**
     * @brief Sets the extra info keys of a notification check request.
     *
     * @param extraKeys Indicates the extra info keys of the notification check request.
     */
    void SetExtraKeys(std::vector<std::string> extraKeys);

    /**
     * @brief Obtains the extra info keys of a notification check request.
     *
     * @return Returns the extra info keys of a notification check request.
     */
    std::vector<std::string> GetExtraKeys() const;

    /**
     * @brief Sets the creator uid.
     *
     * @param uid Indicates the creator uid.
     */
    void SetUid(const int32_t uid);

     /**
     * @brief Obtains the creator uid.
     *
     * @return Returns the creator uid.
     */
    int32_t GetUid() const;

    /**
     * @brief Marshal a object into a Parcel.
     *
     * @param parcel Indicates the object into the parcel
     * @return Returns true if succeed; returns false otherwise.
     */
    virtual bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshal object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns the NotificationBundleOption
     */
    static NotificationCheckRequest *Unmarshalling(Parcel &parcel);

    bool ReadFromParcel(Parcel &parcel);

private:
    NotificationContent::Type contentType_ {};
    NotificationConstant::SlotType slotType_ {};
    std::vector<std::string> extraKeys_ {};
    int32_t creatorUid_ {};
};
}  // namespace Notification
}  // namespace OHOS

#endif  //BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_CHECK_REQUEST_H
