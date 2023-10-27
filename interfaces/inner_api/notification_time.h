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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_TIME_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_TIME_H

#include "notification_json_convert.h"
#include "parcel.h"
#include <cstdint>
#include <string>

namespace OHOS {
namespace Notification {
class NotificationTime : public Parcelable, public NotificationJsonConvertionBase {
public:
    NotificationTime() = default;

    ~NotificationTime() = default;

    /**
     * @brief Obtains the initialTime.
     *
     * @return Returns the initialTime.
     */
    int32_t GetInitialTime() const;

    void SetInitialTime(int32_t time);

    /**
     * @brief Obtains isCountDown flag.
     *
     * @return Returns the isCountDown flag.
     */
    bool GetIsCountDown() const;

    void SetIsCountDown(bool flag);

    /**
     * @brief Obtains isPaused flag.
     *
     * @return Returns the isPaused flag.
     */
    bool GetIsPaused() const;

    void SetIsPaused(bool flag);

    /**
     * @brief Obtains isInTitle flag.
     *
     * @return Returns the isInTitle flag.
     */
    bool GetIsInTitle() const;

    void SetIsInTitle(bool flag);

    /**
     * @brief Returns a string representation of the object.
     *
     * @return Returns a string representation of the object.
     */
    std::string Dump();

    /**
     * @brief Converts a NotificationTime object into a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ToJson(nlohmann::json &jsonObject) const override;

    /**
     * @brief Creates a NotificationTime object from a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns the NotificationConversationalMessage.
     */
    static NotificationTime *FromJson(const nlohmann::json &jsonObject);

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
     * @return Returns the NotificationTime.
     */
    static NotificationTime *Unmarshalling(Parcel &parcel);

private:
    /**
     * @brief Read a NotificationTime object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel);

private:
    int32_t initialTime_ {0};
    bool isCountDown_ {false};
    bool isPaused_ {false};
    bool isInTitle_ {false};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_TIME_H