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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_STATISTICS_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_STATISTICS_H

#include "notification_json_convert.h"
#include "notification_bundle_option.h"
#include "parcel.h"
#include <cstdint>

namespace OHOS {
namespace Notification {
class NotificationStatistics : public Parcelable, public NotificationJsonConvertionBase {
public:
    NotificationStatistics() = default;
    ~NotificationStatistics() = default;

    /**
     * @brief Whether the last notification sending time of the bundle.
     *
     * @return Returns the last notification sending time.
     */
    int64_t GetLastTime() const;

    void SetLastTime(int64_t lastTime);

    /**
     * @brief Sets the bundleOption of this notification.
     *
     * @param bundleOption Indicates the bundleOption of this notification.
     */
    void SetBundleOption(const NotificationBundleOption &bundle);

    /**
     * @brief Obtains the bundleOption of the notification.
     *
     * @return Returns the bundleOption of the notification.
     */
    const NotificationBundleOption& GetBundleOption() const;

    /**
     * @brief Obtains the count of notification which sending.
     *
     * @return Returns the count of notification which sending.
     */
    int32_t GetRecentCount() const;

    void SetRecentCount(int32_t recentCount);

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
    static NotificationStatistics *FromJson(const nlohmann::json &jsonObject);

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
    static NotificationStatistics *Unmarshalling(Parcel &parcel);

private:
    /**
     * @brief Read a NotificationConversationalMessage object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel);

private:
    int64_t lastTime_ {0};
    NotificationBundleOption bundle_ {};
    int32_t recentCount_ {0};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_STATISTICS_H