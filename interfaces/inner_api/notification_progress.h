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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PROGRESS_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PROGRESS_H

#include "notification_json_convert.h"
#include "parcel.h"
#include <cstdint>

namespace OHOS {
namespace Notification {
class NotificationProgress : public Parcelable, public NotificationJsonConvertionBase {
public:
    NotificationProgress() = default;
    ~NotificationProgress() = default;

    /**
     * @brief Obtains the text to be displayed as the content of this message.
     *
     * @return Returns the message content.
     */
    int32_t GetMaxValue() const;

    void SetMaxValue(int32_t maxValue);

    /**
     * @brief Obtains the time when this message arrived.
     *
     * @return Returns the time when this message arrived.
     */
    int32_t GetCurrentValue() const;

    void SetCurrentValue(int32_t curValue);

    /**
     * @brief Obtains the sender of this message.
     *
     * @return Returns the message sender.
     */
    bool GetIsPercentage() const;

    void SetIsPercentage(bool isPercentage);

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
    static NotificationProgress *FromJson(const nlohmann::json &jsonObject);

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
    static NotificationProgress *Unmarshalling(Parcel &parcel);

private:
    /**
     * @brief Read a NotificationConversationalMessage object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel);

private:
    int32_t maxValue_ {0};
    int32_t currentValue_ {0};
    bool isPercentage_ {true};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PROGRESS_H