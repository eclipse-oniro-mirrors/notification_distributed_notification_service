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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_TRIGGER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_TRIGGER_H

#include "notification_constant.h"
#include "notification_geofence.h"
#include "notification_json_convert.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
class NotificationTrigger : public Parcelable, public NotificationJsonConvertionBase {
public:
    /**
     * Default constructor used to create a NotificationGeofence instance.
     */
    NotificationTrigger() = default;

    /**
     * A constructor used to create a NotificationTrigger instance with the input parameters passed.
     * @param type Indicates the trigger type to add.
     * @param configPath Indicates the config path to add.
     * @param condition Indicates the notification fence to add.
     * @param displayTime Indicates the display time to add.
     */
    NotificationTrigger(const NotificationConstant::TriggerType &type,
        const NotificationConstant::ConfigPath &configPath,
        const std::shared_ptr<NotificationGeofence> &condition, int32_t displayTime);

    /**
     * Default deconstructor used to deconstruct.
     */
    ~NotificationTrigger() = default;

    /**
     * Sets trigger type for this NotificationTrigger.
     * @param type Indicates the trigger type to add.
     * For available values, see NotificationConstant::TriggerType.
     */
    void SetTriggerType(NotificationConstant::TriggerType type);

    /**
     * Obtains the trigger type of this NotificationTrigger.
     * @return the trigger type of this NotificationTrigger,
     * as enumerated in NotificationConstant::TriggerType.
     */
    NotificationConstant::TriggerType GetTriggerType() const;

    /**
     * Sets config path for this NotificationTrigger.
     * @param configPath Indicates the config path to add.
     * For available values, see NotificationConstant::ConfigPath.
     */
    void SetConfigPath(NotificationConstant::ConfigPath configPath);

    /**
     * Obtains the config path of this NotificationTrigger.
     * @return the config path of this NotificationTrigger,
     * as enumerated in NotificationConstant::ConfigPath.
     */
    NotificationConstant::ConfigPath GetConfigPath() const;

    /**
     * Sets geo fence for this NotificationTrigger.
     * @param condition Indicates the geo fence to add.
     * For available values, see NotificationGeofence.
     */
    void SetGeofence(std::shared_ptr<NotificationGeofence> condition);

    /**
     * Obtains the geo fence of this NotificationTrigger.
     * @return the geo fence of this NotificationTrigger,
     * as class in NotificationGeofence.
     */
    std::shared_ptr<NotificationGeofence> GetGeofence() const;

    /**
     * Sets displayTime for this NotificationTrigger.
     * @param displayTime Indicates the displayTime to add.
     */
    void SetDisplayTime(int32_t displayTime);

    /**
     * Obtains the displayTime of this NotificationTrigger.
     * @return the displayTime of this NotificationTrigger.
     */
    int32_t GetDisplayTime() const;

    /**
     * Marshals a NotificationTrigger object into a Parcel object.
     *
     * @param parcel Indicates the Parcel object into which the NotificationTrigger object is marshaled.
     * @return true if the operation is successful; false otherwise.
     */
    bool Marshalling(Parcel &parcel) const override;

    /**
     * Unmarshals a NotificationTrigger object from a Parcel object.
     *
     * @param parcel Indicates the Parcel object from which the NotificationTrigger object is unmarshaled.
     * @return true if the operation is successful; false otherwise.
     */
    static NotificationTrigger *Unmarshalling(Parcel &parcel);

    /**
     * @brief Converts a NotificationTrigger object into a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ToJson(nlohmann::json &jsonObject) const override;

    /**
     * @brief Creates a NotificationTrigger object from a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns the NotificationTrigger.
     */
    static NotificationTrigger *FromJson(const nlohmann::json &jsonObject);

    /**
     * @brief Returns a string representation of the object.
     *
     * @return Returns a string representation of the object.
     */
    std::string Dump() const;

private:
    /**
     * Read a NotificationTrigger object from a Parcel.
     * @param parcel the parcel
     */
    bool ReadFromParcel(Parcel &parcel);
    static bool ConvertJsonToNotificationGeofence(NotificationTrigger *target, const nlohmann::json &jsonObject);

private:
    NotificationConstant::TriggerType type_;
    NotificationConstant::ConfigPath configPath_;
    std::shared_ptr<NotificationGeofence> condition_;
    int32_t displayTime_;
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_TRIGGER_H
