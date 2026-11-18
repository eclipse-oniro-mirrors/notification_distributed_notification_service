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

#include "notificationgeofencetriggerHXF_fuzzer.h"
#include "notification_constant.h"
#include "notification_geofence.h"
#include "notification_trigger.h"
#include "parcel.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <memory>

namespace OHOS {
namespace {
constexpr uint16_t LONGITUDE_RANGE = 400;
constexpr uint16_t LATITUDE_RANGE = 200;
constexpr uint16_t RADIUS_RANGE = 4000;
constexpr uint16_t DELAY_RANGE = 600;
constexpr uint16_t DISPLAY_RANGE = 3600;
constexpr double LONGITUDE_OFFSET = 200.0;
constexpr double LATITUDE_OFFSET = 100.0;
constexpr int32_t DELAY_OFFSET = 10;
constexpr int32_t DISPLAY_OFFSET = 1;
constexpr uint8_t COORD_TYPE_CNT = 3;
constexpr uint8_t MONITOR_EVT_CNT = 3;
constexpr uint8_t TRIGGER_TYPE_CNT = 2;
constexpr uint8_t CONFIG_PATH_CNT = 3;

struct GeofenceFuzzData {
    double longitude;
    double latitude;
    double radius;
    int32_t delayTime;
    Notification::NotificationConstant::CoordinateSystemType coordType;
    Notification::NotificationConstant::MonitorEvent monitorEvent;
};

struct TriggerFuzzData {
    int32_t displayTime;
    Notification::NotificationConstant::TriggerType triggerType;
    Notification::NotificationConstant::ConfigPath configPath;
};

GeofenceFuzzData ConsumeGeofenceFuzzData(FuzzedDataProvider *fdp)
{
    GeofenceFuzzData fuzzData;
    fuzzData.longitude = static_cast<double>(fdp->ConsumeIntegral<uint16_t>() % LONGITUDE_RANGE) -
        LONGITUDE_OFFSET;
    fuzzData.latitude = static_cast<double>(fdp->ConsumeIntegral<uint16_t>() % LATITUDE_RANGE) - LATITUDE_OFFSET;
    fuzzData.radius = static_cast<double>(fdp->ConsumeIntegral<uint16_t>() % RADIUS_RANGE);
    fuzzData.delayTime = static_cast<int32_t>(fdp->ConsumeIntegral<uint16_t>() % DELAY_RANGE) - DELAY_OFFSET;

    uint8_t coordRaw = fdp->ConsumeIntegral<uint8_t>() % COORD_TYPE_CNT;
    fuzzData.coordType = static_cast<Notification::NotificationConstant::CoordinateSystemType>(coordRaw);
    uint8_t monitorRaw = fdp->ConsumeIntegral<uint8_t>() % MONITOR_EVT_CNT;
    fuzzData.monitorEvent = static_cast<Notification::NotificationConstant::MonitorEvent>(monitorRaw);
    return fuzzData;
}

TriggerFuzzData ConsumeTriggerFuzzData(FuzzedDataProvider *fdp)
{
    TriggerFuzzData fuzzData;
    uint8_t triggerTypeRaw = fdp->ConsumeIntegral<uint8_t>() % TRIGGER_TYPE_CNT;
    fuzzData.triggerType = static_cast<Notification::NotificationConstant::TriggerType>(triggerTypeRaw);
    uint8_t configPathRaw = fdp->ConsumeIntegral<uint8_t>() % CONFIG_PATH_CNT;
    fuzzData.configPath = static_cast<Notification::NotificationConstant::ConfigPath>(configPathRaw);
    fuzzData.displayTime = static_cast<int32_t>(fdp->ConsumeIntegral<uint16_t>() % DISPLAY_RANGE) - DISPLAY_OFFSET;
    return fuzzData;
}

Notification::NotificationGeofence BuildGeofence(const GeofenceFuzzData &fuzzData)
{
    Notification::NotificationGeofence geofence;
    geofence.SetLongitude(fuzzData.longitude);
    geofence.GetLongitude();
    geofence.SetLatitude(fuzzData.latitude);
    geofence.GetLatitude();
    geofence.SetRadius(fuzzData.radius);
    geofence.GetRadius();
    geofence.SetDelayTime(fuzzData.delayTime);
    geofence.GetDelayTime();
    geofence.SetCoordinateSystemType(fuzzData.coordType);
    geofence.GetCoordinateSystemType();
    geofence.SetMonitorEvent(fuzzData.monitorEvent);
    geofence.GetMonitorEvent();
    geofence.Dump();
    return geofence;
}

void FuzzGeofenceParcel(const Notification::NotificationGeofence &geofence)
{
    Parcel parcel;
    if (geofence.Marshalling(parcel)) {
        std::unique_ptr<Notification::NotificationGeofence> restored(
            Notification::NotificationGeofence::Unmarshalling(parcel));
    }
}

void FuzzGeofenceJson(const Notification::NotificationGeofence &geofence)
{
    nlohmann::json jsonObject;
    geofence.ToJson(jsonObject);
    std::unique_ptr<Notification::NotificationGeofence> restored(
        Notification::NotificationGeofence::FromJson(jsonObject));
}

void FuzzTriggerParcel(const Notification::NotificationTrigger &trigger)
{
    Parcel parcel;
    if (trigger.Marshalling(parcel)) {
        std::unique_ptr<Notification::NotificationTrigger> restored(
            Notification::NotificationTrigger::Unmarshalling(parcel));
    }
}

void FuzzTriggerJson(const Notification::NotificationTrigger &trigger)
{
    nlohmann::json jsonObject;
    trigger.ToJson(jsonObject);
    std::unique_ptr<Notification::NotificationTrigger> restored(
        Notification::NotificationTrigger::FromJson(jsonObject));
}

void ConfigureTrigger(Notification::NotificationTrigger &trigger, const TriggerFuzzData &fuzzData)
{
    trigger.SetTriggerType(fuzzData.triggerType);
    trigger.GetTriggerType();
    trigger.SetConfigPath(fuzzData.configPath);
    trigger.GetConfigPath();
    trigger.SetDisplayTime(fuzzData.displayTime);
    trigger.GetDisplayTime();
}

void FuzzTriggerWithCondition(const GeofenceFuzzData &geofenceData, const TriggerFuzzData &triggerData)
{
    auto geofenceCond = std::make_shared<Notification::NotificationGeofence>(geofenceData.longitude,
        geofenceData.latitude, geofenceData.radius, geofenceData.delayTime, geofenceData.coordType,
        geofenceData.monitorEvent);
    Notification::NotificationTrigger trigger;
    ConfigureTrigger(trigger, triggerData);
    trigger.SetGeofence(geofenceCond);
    trigger.GetGeofence();
    trigger.Dump();
    FuzzTriggerParcel(trigger);
    FuzzTriggerJson(trigger);
}

void FuzzTriggerWithoutCondition(const TriggerFuzzData &triggerData)
{
    Notification::NotificationTrigger trigger;
    ConfigureTrigger(trigger, triggerData);
    trigger.SetGeofence(nullptr);
    FuzzTriggerParcel(trigger);
}
}

bool test(FuzzedDataProvider *fdp)
{
    GeofenceFuzzData fuzzData = ConsumeGeofenceFuzzData(fdp);
    Notification::NotificationGeofence geofence = BuildGeofence(fuzzData);
    FuzzGeofenceParcel(geofence);
    FuzzGeofenceJson(geofence);
    TriggerFuzzData triggerData = ConsumeTriggerFuzzData(fdp);
    FuzzTriggerWithCondition(fuzzData, triggerData);
    FuzzTriggerWithoutCondition(triggerData);
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::test(&fdp);
    return 0;
}
