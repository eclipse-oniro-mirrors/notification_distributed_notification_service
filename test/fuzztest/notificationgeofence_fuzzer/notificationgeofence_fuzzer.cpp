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

#define private public
#define protected public
#include "notification_geofence.h"
#undef private
#undef protected
#include "notificationgeofence_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Notification {

constexpr uint8_t COORDINATE_TYPE_MAX = 3;
constexpr uint8_t MONITOR_EVENT_MAX = 3;

static void TestNotificationGeofence(FuzzedDataProvider *fuzzData)
{
    double longitude = fuzzData->ConsumeFloatingPoint<double>();
    double latitude = fuzzData->ConsumeFloatingPoint<double>();
    double radius = fuzzData->ConsumeFloatingPoint<double>();
    int32_t delayTime = fuzzData->ConsumeIntegral<int32_t>();
    uint8_t coordinateTypeValue = fuzzData->ConsumeIntegral<uint8_t>() % COORDINATE_TYPE_MAX;
    uint8_t monitorEventValue = fuzzData->ConsumeIntegral<uint8_t>() % MONITOR_EVENT_MAX;

    NotificationConstant::CoordinateSystemType coordinateType =
        static_cast<NotificationConstant::CoordinateSystemType>(coordinateTypeValue);
    NotificationConstant::MonitorEvent monitorEvent =
        static_cast<NotificationConstant::MonitorEvent>(monitorEventValue);

    NotificationGeofence geofence(longitude, latitude, radius, delayTime, coordinateType, monitorEvent);
    geofence.GetLongitude();
    geofence.GetLatitude();
    geofence.GetRadius();
    geofence.GetDelayTime();
    geofence.GetCoordinateSystemType();
    geofence.GetMonitorEvent();
    geofence.Dump();

    NotificationGeofence geofence2;
    geofence2.SetLongitude(longitude);
    geofence2.SetLatitude(latitude);
    geofence2.SetRadius(radius);
    geofence2.SetDelayTime(delayTime);
    geofence2.SetCoordinateSystemType(coordinateType);
    geofence2.SetMonitorEvent(monitorEvent);

    nlohmann::json jsonObject;
    geofence2.ToJson(jsonObject);
    NotificationGeofence::FromJson(jsonObject);

    Parcel parcel;
    geofence2.Marshalling(parcel);
    NotificationGeofence::Unmarshalling(parcel);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
{
    TestNotificationGeofence(fuzzData);
    return true;
}
}  // namespace Notification
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fuzzData(data, size);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fuzzData);
    return 0;
}
