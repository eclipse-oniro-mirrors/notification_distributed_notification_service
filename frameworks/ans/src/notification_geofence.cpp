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

#include "notification_geofence.h"
#include "ans_log_wrapper.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace Notification {
namespace {
constexpr const char *FENCE_LONGITUDE = "fenceLongitude";
constexpr const char *FENCE_LATITUDE = "fenceLatitude";
constexpr const char *FENCE_RADIUS = "fenceRadius";
constexpr const char *FENCE_DELAY_TIME = "fenceDelayTime";
constexpr const char *FENCE_COORDINATE_SYSTEM_TYPE = "fenceCoordinateSystemType";
constexpr const char *FENCE_MONITOR_EVENT = "fenceMonitorEvent";
} // namespace
NotificationGeofence::NotificationGeofence(double longitude, double latitude, double radius, int32_t delayTime,
    const NotificationConstant::CoordinateSystemType &coordinateSystemType,
    const NotificationConstant::MonitorEvent &monitorEvent)
    : longitude_(longitude), latitude_(latitude), radius_(radius), delayTime_(delayTime),
    coordinateSystemType_(coordinateSystemType), monitorEvent_(monitorEvent)
{}

void NotificationGeofence::SetLongitude(double longitude)
{
    longitude_ = longitude;
}

double NotificationGeofence::GetLongitude() const
{
    return longitude_;
}

void NotificationGeofence::SetLatitude(double latitude)
{
    latitude_ = latitude;
}

double NotificationGeofence::GetLatitude() const
{
    return latitude_;
}

void NotificationGeofence::SetRadius(double radius)
{
    radius_ = radius;
}

double NotificationGeofence::GetRadius() const
{
    return radius_;
}

void NotificationGeofence::SetDelayTime(int32_t delayTime)
{
    delayTime_ = delayTime;
}

int32_t NotificationGeofence::GetDelayTime() const
{
    return delayTime_;
}

void NotificationGeofence::SetCoordinateSystemType(
    const NotificationConstant::CoordinateSystemType &coordinateSystemType)
{
    coordinateSystemType_ = coordinateSystemType;
}

NotificationConstant::CoordinateSystemType NotificationGeofence::GetCoordinateSystemType() const
{
    return coordinateSystemType_;
}

void NotificationGeofence::SetMonitorEvent(const NotificationConstant::MonitorEvent &monitorEvent)
{
    monitorEvent_ = monitorEvent;
}

NotificationConstant::MonitorEvent NotificationGeofence::GetMonitorEvent() const
{
    return monitorEvent_;
}

bool NotificationGeofence::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteDouble(longitude_)) {
        ANS_LOGE("Failed to write longitude");
        return false;
    }

    if (!parcel.WriteDouble(latitude_)) {
        ANS_LOGE("Failed to write latitude");
        return false;
    }

    if (!parcel.WriteDouble(radius_)) {
        ANS_LOGE("Failed to write radius");
        return false;
    }

    if (!parcel.WriteInt32(delayTime_)) {
        ANS_LOGE("Failed to write delay time");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(coordinateSystemType_))) {
        ANS_LOGE("Failed to write coordinate system type");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(monitorEvent_))) {
        ANS_LOGE("Failed to write monitor event");
        return false;
    }

    return true;
}

NotificationGeofence *NotificationGeofence::Unmarshalling(Parcel &parcel)
{
    auto objptr = new (std::nothrow) NotificationGeofence();
    if ((objptr != nullptr) && !objptr->ReadFromParcel(parcel)) {
        delete objptr;
        objptr = nullptr;
    }
    return objptr;
}

bool NotificationGeofence::ReadFromParcel(Parcel &parcel)
{
    longitude_ = parcel.ReadDouble();
    latitude_ = parcel.ReadDouble();
    radius_ = parcel.ReadDouble();
    delayTime_ = parcel.ReadInt32();
    coordinateSystemType_ = static_cast<NotificationConstant::CoordinateSystemType>(parcel.ReadInt32());
    monitorEvent_ = static_cast<NotificationConstant::MonitorEvent>(parcel.ReadInt32());
    return true;
}

bool NotificationGeofence::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject[FENCE_LONGITUDE] = longitude_;
    jsonObject[FENCE_LATITUDE] = latitude_;
    jsonObject[FENCE_RADIUS] = radius_;
    jsonObject[FENCE_DELAY_TIME] = delayTime_;
    jsonObject[FENCE_COORDINATE_SYSTEM_TYPE] = static_cast<int32_t>(coordinateSystemType_);
    jsonObject[FENCE_MONITOR_EVENT] = static_cast<int32_t>(monitorEvent_);
    return true;
}

NotificationGeofence *NotificationGeofence::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    auto pNotificationGeofence = new (std::nothrow) NotificationGeofence();
    if (pNotificationGeofence == nullptr) {
        ANS_LOGE("null pNotificationGeofence");
        return nullptr;
    }

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find(FENCE_LONGITUDE) != jsonEnd && jsonObject.at(FENCE_LONGITUDE).is_number()) {
        pNotificationGeofence->longitude_ = jsonObject.at(FENCE_LONGITUDE).get<double>();
    }

    if (jsonObject.find(FENCE_LATITUDE) != jsonEnd && jsonObject.at(FENCE_LATITUDE).is_number()) {
        pNotificationGeofence->latitude_ = jsonObject.at(FENCE_LATITUDE).get<double>();
    }

    if (jsonObject.find(FENCE_RADIUS) != jsonEnd && jsonObject.at(FENCE_RADIUS).is_number()) {
        pNotificationGeofence->radius_ = jsonObject.at(FENCE_RADIUS).get<double>();
    }

    if (jsonObject.find(FENCE_DELAY_TIME) != jsonEnd && jsonObject.at(FENCE_DELAY_TIME).is_number_integer()) {
        pNotificationGeofence->delayTime_ = jsonObject.at(FENCE_DELAY_TIME).get<int32_t>();
    }

    if (jsonObject.find(FENCE_COORDINATE_SYSTEM_TYPE) != jsonEnd &&
        jsonObject.at(FENCE_COORDINATE_SYSTEM_TYPE).is_number_integer()) {
        auto coordinateSystemType  = jsonObject.at(FENCE_COORDINATE_SYSTEM_TYPE).get<int32_t>();
        pNotificationGeofence->coordinateSystemType_ =
            static_cast<NotificationConstant::CoordinateSystemType>(coordinateSystemType);
    }

    if (jsonObject.find(FENCE_MONITOR_EVENT) != jsonEnd && jsonObject.at(FENCE_MONITOR_EVENT).is_number_integer()) {
        auto monitorEvent = jsonObject.at(FENCE_MONITOR_EVENT).get<int32_t>();
        pNotificationGeofence->monitorEvent_ = static_cast<NotificationConstant::MonitorEvent>(monitorEvent);
    }

    return pNotificationGeofence;
}

std::string NotificationGeofence::Dump() const
{
    return std::to_string(longitude_) + " " + std::to_string(latitude_) + " " + std::to_string(radius_) + " " +
        std::to_string(delayTime_) + " " + std::to_string(static_cast<int32_t>(coordinateSystemType_)) + " " +
        std::to_string(static_cast<int32_t>(monitorEvent_));
}
}  // namespace Notification
}  // namespace OHOS