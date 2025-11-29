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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_GEOFENCE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_GEOFENCE_H

#include "notification_constant.h"
#include "notification_json_convert.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
class NotificationGeofence : public Parcelable, public NotificationJsonConvertionBase {
public:
    /**
     * Default constructor used to create a NotificationGeofence instance.
     */
    NotificationGeofence() = default;

    /**
     * A constructor used to create a NotificationGeofence instance with the input parameters passed.
     * @param longitude Indicates the longitude to add.
     * @param latitude Indicates the latitude to add.
     * @param radius Indicates the radius to add.
     * @param delayTime Indicates the delay time to add.
     * @param coordinateSystemType Indicates the coordinate system type to add.
     * @param monitorEvent Indicates the monitor event to add.
     */
    NotificationGeofence(double longitude, double latitude, double radius, int32_t delayTime,
        const NotificationConstant::CoordinateSystemType &coordinateSystemType,
        const NotificationConstant::MonitorEvent &monitorEvent);

    /**
     * Default deconstructor used to deconstruct.
     */
    ~NotificationGeofence() = default;

    /**
     * Sets longitude for this NotificationGeofence.
     * @param longitude Indicates the longitude to add.
     */
    void SetLongitude(double longitude);

    /**
     * Obtains the longitude of this NotificationGeofence.
     * @return the longitude of this NotificationGeofence.
     */
    double GetLongitude() const;

    /**
     * Sets latitude for this NotificationGeofence.
     * @param latitude Indicates the latitude to add.
     */
    void SetLatitude(double latitude);

    /**
     * Obtains the latitude of this NotificationGeofence.
     * @return the latitude of this NotificationGeofence.
     */
    double GetLatitude() const;

    /**
     * Sets radius for this NotificationGeofence.
     * @param radius Indicates the radius to add.
     */
    void SetRadius(double radius);

    /**
     * Obtains the radius of this NotificationGeofence.
     * @return the radius of this NotificationGeofence.
     */
    double GetRadius() const;

    /**
     * Sets delay time for this NotificationGeofence.
     * @param delayTime Indicates the delay time to add.
     */
    void SetDelayTime(int32_t delayTime);

    /**
     * Obtains the delay time of this NotificationGeofence.
     * @return the delay time of this NotificationGeofence.
     */
    int32_t GetDelayTime() const;

    /**
     * Sets coordinate system type for this NotificationGeofence.
     * @param coordinateSystemType Indicates the coordinate system type to add.
     * For available values, see NotificationConstant::CoordinateSystemType.
     */
    void SetCoordinateSystemType(const NotificationConstant::CoordinateSystemType &coordinateSystemType);

    /**
     * Obtains the coordinate system type of this NotificationGeofence.
     * @return the coordinate system type of this NotificationGeofence,
     * as enumerated in NotificationConstant::CoordinateSystemType.
     */
    NotificationConstant::CoordinateSystemType GetCoordinateSystemType() const;

    /**
     * Sets monitor event for this NotificationGeofence.
     * @param monitorEvent Indicates the monitor event to add.
     * For available values, see NotificationConstant::MonitorEvent.
     */
    void SetMonitorEvent(const NotificationConstant::MonitorEvent &monitorEvent);

    /**
     * Obtains the monitor event of this NotificationGeofence.
     * @return the monitor event of this NotificationGeofence,
     * as enumerated in NotificationConstant::MonitorEvent.
     */
    NotificationConstant::MonitorEvent GetMonitorEvent() const;

    /**
     * Marshals a NotificationGeofence object into a Parcel object.
     *
     * @param parcel Indicates the Parcel object into which the NotificationGeofence object is marshaled.
     * @return true if the operation is successful; false otherwise.
     */
    bool Marshalling(Parcel &parcel) const override;

    /**
     * Unmarshals a NotificationGeofence object from a Parcel object.
     *
     * @param parcel Indicates the Parcel object from which the NotificationGeofence object is unmarshaled.
     * @return true if the operation is successful; false otherwise.
     */
    static NotificationGeofence *Unmarshalling(Parcel &parcel);

    /**
     * @brief Converts a NotificationGeofence object into a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ToJson(nlohmann::json &jsonObject) const override;

    /**
     * @brief Creates a NotificationGeofence object from a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns the NotificationGeofence.
     */
    static NotificationGeofence *FromJson(const nlohmann::json &jsonObject);

    /**
     * @brief Returns a string representation of the object.
     *
     * @return Returns a string representation of the object.
     */
    std::string Dump() const;

private:
    /**
     * Read a NotificationGeofence object from a Parcel.
     * @param parcel the parcel
     */
    bool ReadFromParcel(Parcel &parcel);

private:
    double longitude_;
    double latitude_;
    double radius_;
    int32_t delayTime_;
    NotificationConstant::CoordinateSystemType coordinateSystemType_;
    NotificationConstant::MonitorEvent monitorEvent_;
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_GEOFENCE_H
