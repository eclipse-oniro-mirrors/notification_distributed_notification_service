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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_INFO_H

#include <cstdint>
#include "parcel.h"
#include "notification_json_convert.h"
#include "notification_bundle_option.h"

namespace OHOS {
namespace Notification {
class NotificationReminderInfo : public Parcelable, public NotificationJsonConvertionBase {
public:
    NotificationReminderInfo() = default;
    ~NotificationReminderInfo() = default;

    /**
     * @brief Obtains the bundleOption of this reminderInfo.
     *
     * @return Returns the bundleOption.
     */
    const NotificationBundleOption& GetBundleOption() const;

    void SetBundleOption(NotificationBundleOption bundle);

    /**
     * @brief Obtains the reminder flags of this reminderInfo.
     *
     * @return Returns the reminder flags.
     */
    uint32_t GetReminderFlags() const;

    void SetReminderFlags(uint32_t reminderFlags);

    /**
     * @brief Obtains the silent reminder enable status of this reminderInfo.
     *
     * @return Returns the silent reminder enable status.
     */
    bool GetSilentReminderEnabled() const;

    void SetSilentReminderEnabled(bool silentReminderEnabled);

    /**
     * @brief Returns a string representation of the object.
     *
     * @return Returns a string representation of the object.
     */
    std::string Dump();

    /**
     * @brief Converts a NotificationReminderInfo object into a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ToJson(nlohmann::json &jsonObject) const override;

    /**
     * @brief Creates a NotificationReminderInfo object from a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns the NotificationConversationalMessage.
     */
    static NotificationReminderInfo *FromJson(const nlohmann::json &jsonObject);

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
    static NotificationReminderInfo *Unmarshalling(Parcel &parcel);

private:
    /**
     * @brief Read a NotificationReminderInfo object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel);

private:
    NotificationBundleOption bundle_;
    uint32_t reminderFlags_ {0};
    bool silentReminderEnabled_ {false};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_INFO_H
