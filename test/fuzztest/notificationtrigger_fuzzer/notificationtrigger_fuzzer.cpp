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

#define private public  // NOLINT
#define protected public  // NOLINT
#include "notification_trigger.h"
#include "notification_geofence.h"
#undef private
#undef protected
#include "notificationtrigger_fuzzer.h"

#include <memory>
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Notification {

constexpr uint8_t TRIGGER_TYPE_MAX = 3;
constexpr uint8_t CONFIG_PATH_MAX = 3;
constexpr uint8_t COORDINATE_TYPE_MAX = 3;
constexpr uint8_t MONITOR_EVENT_MAX = 3;

static void TestNotificationTrigger(FuzzedDataProvider *fuzzData)
{
    uint8_t triggerTypeValue = fuzzData->ConsumeIntegral<uint8_t>() % TRIGGER_TYPE_MAX;
    uint8_t configPathValue = fuzzData->ConsumeIntegral<uint8_t>() % CONFIG_PATH_MAX;
    NotificationConstant::TriggerType triggerType =
        static_cast<NotificationConstant::TriggerType>(triggerTypeValue);
    NotificationConstant::ConfigPath configPath =
        static_cast<NotificationConstant::ConfigPath>(configPathValue);

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

    auto geofence = std::make_shared<NotificationGeofence>(
        longitude, latitude, radius, delayTime, coordinateType, monitorEvent);
    int32_t displayTime = fuzzData->ConsumeIntegral<int32_t>();

    NotificationTrigger trigger(triggerType, configPath, geofence, displayTime);
    trigger.GetTriggerType();
    trigger.GetConfigPath();
    trigger.GetGeofence();
    trigger.GetDisplayTime();
    trigger.Dump();

    NotificationTrigger trigger2;
    trigger2.SetTriggerType(triggerType);
    trigger2.SetConfigPath(configPath);
    trigger2.SetGeofence(geofence);
    trigger2.SetDisplayTime(displayTime);

    nlohmann::json jsonObject;
    trigger2.ToJson(jsonObject);
    std::unique_ptr<NotificationTrigger> fromJsonTrigger(NotificationTrigger::FromJson(jsonObject));
    if (fromJsonTrigger != nullptr) {
        fromJsonTrigger->Dump();
    }

    Parcel parcel;
    if (!trigger2.Marshalling(parcel)) {
        return;
    }
    auto unmarshalledTrigger = std::unique_ptr<NotificationTrigger>(NotificationTrigger::Unmarshalling(parcel));
    if (unmarshalledTrigger != nullptr) {
        unmarshalledTrigger->Dump();
    }
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
{
    TestNotificationTrigger(fuzzData);
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
