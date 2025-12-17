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

#include "common.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "js_native_api.h"
#include "napi_common.h"
#include "napi_common_util.h"
#include "notification_constant.h"
#include "notification_geofence.h"
#include "notification_trigger.h"

namespace OHOS {
namespace NotificationNapi {
napi_value Common::GetNotificationTrigger(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("Called.");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "trigger", &hasProperty));
    if (hasProperty) {
        NAPI_CALL(env, napi_get_named_property(env, value, "trigger", &result));
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types. The type of trigger must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }

        std::shared_ptr<NotificationTrigger> trigger = std::make_shared<NotificationTrigger>();
        if (trigger == nullptr) {
            ANS_LOGE("The trigger is null.");
            return nullptr;
        }
        if (GetNotificationTrigger(env, result, trigger) == nullptr) {
            return nullptr;
        }

        request.SetNotificationTrigger(trigger);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationTrigger(const napi_env &env, const napi_value &value,
    std::shared_ptr<NotificationTrigger> &notificationTrigger)
{
    ANS_LOGD("called");

    bool hasProperty {false};
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;

    if (GetNotificationTriggerType(env, value, notificationTrigger) == nullptr) {
        return nullptr;
    }

    // condition: Geofence
    if (GetNotificationGeofence(env, value, notificationTrigger) == nullptr) {
        return nullptr;
    }

    if (GetNotificationTriggerDisplayTime(env, value, notificationTrigger) == nullptr) {
        return nullptr;
    }

    notificationTrigger->SetConfigPath(NotificationConstant::ConfigPath::CONFIG_PATH_CLOUD_CONFIG);
    return NapiGetNull(env);
}

napi_value Common::GetNotificationTriggerType(const napi_env &env, const napi_value &value,
    std::shared_ptr<NotificationTrigger> &notificationTrigger)
{
    ANS_LOGD("called");

    bool hasProperty {false};
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;

    // type: TriggerType
    NAPI_CALL(env, napi_has_named_property(env, value, "type", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property type expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_named_property(env, value, "type", &result));
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("type Wrong argument type. Number expected.");
        std::string msg = "Incorrect parameter types. The type of type must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    int32_t type = 0;
    napi_get_value_int32(env, result, &type);
    NotificationConstant::TriggerType cTriggerType;
    if (!AnsEnumUtil::TriggerTypeJSToC(static_cast<TriggerType>(type), cTriggerType)) {
        ANS_LOGE("type is invalid.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return nullptr;
    }
    notificationTrigger->SetTriggerType(cTriggerType);
    return NapiGetNull(env);
}

napi_value Common::GetNotificationTriggerDisplayTime(const napi_env &env, const napi_value &value,
    std::shared_ptr<NotificationTrigger> &notificationTrigger)
{
    ANS_LOGD("called");

    bool hasProperty {false};
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;

    // displayTime?: int
    NAPI_CALL(env, napi_has_named_property(env, value, "displayTime", &hasProperty));
    if (hasProperty) {
        NAPI_CALL(env, napi_get_named_property(env, value, "displayTime", &result));
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of displayTime must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        int32_t displayTime = NotificationConstant::MIN_GEOFENCE_DISPLAY_TIME_S - 1;
        napi_get_value_int32(env, result, &displayTime);
        if (displayTime < NotificationConstant::MIN_GEOFENCE_DISPLAY_TIME_S) {
            ANS_LOGE("displayTime is invalid.");
            std::string msg = std::string("Invalid displayTime. The displayTime must be in range ") +
                std::to_string(NotificationConstant::MIN_GEOFENCE_DISPLAY_TIME_S) + "s to " +
                std::to_string(NotificationConstant::MAX_GEOFENCE_DISPLAY_TIME_S) + "s.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        if (displayTime > NotificationConstant::MAX_GEOFENCE_DISPLAY_TIME_S) {
            ANS_LOGW("displayTime is invalid.");
            displayTime = NotificationConstant::MAX_GEOFENCE_DISPLAY_TIME_S;
        }
        notificationTrigger->SetDisplayTime(displayTime);
    } else {
        ANS_LOGD("Property displayTime expected.");
        notificationTrigger->SetDisplayTime(NotificationConstant::DEFAULT_GEOFENCE_DISPLAY_TIME_S);
    }
    return NapiGetNull(env);
}

napi_value Common::GetNotificationGeofence(const napi_env &env, const napi_value &value,
    std::shared_ptr<NotificationTrigger> &notificationTrigger)
{
    ANS_LOGD("called");

    bool hasProperty {false};
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;

    // condition: Geofence
    NAPI_CALL(env, napi_has_named_property(env, value, "condition", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property condition expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_named_property(env, value, "condition", &result));
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        std::string msg = "Incorrect parameter types. The type of condition must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    std::shared_ptr<NotificationGeofence> geofence = std::make_shared<NotificationGeofence>();
    if (geofence == nullptr) {
        ANS_LOGE("The geofence is null.");
        return nullptr;
    }
    if (GetNotificationGeofence(env, result, geofence) == nullptr) {
        return nullptr;
    }
    notificationTrigger->SetGeofence(geofence);

    return NapiGetNull(env);
}

napi_value Common::GetNotificationGeofence(const napi_env &env, const napi_value &value,
    std::shared_ptr<NotificationGeofence> &geofence)
{
    ANS_LOGD("called");

    if (GetNotificationGeofenceByDouble(env, value, geofence) == nullptr) {
        return nullptr;
    }
    if (GetNotificationGeofenceByNumber(env, value, geofence) == nullptr) {
        return nullptr;
    }
    if (GetNotificationGeofenceByEnum(env, value, geofence) == nullptr) {
        return nullptr;
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationGeofenceByDouble(const napi_env &env, const napi_value &value,
    std::shared_ptr<NotificationGeofence> &geofence)
{
    // longitude: double
    if (GetNotificationGeofenceByLongitude(env, value, geofence) == nullptr) {
        return nullptr;
    }

    // latitude: double
    if (GetNotificationGeofenceByLatitude(env, value, geofence) == nullptr) {
        return nullptr;
    }

    // radius: double
    if (GetNotificationGeofenceByRadius(env, value, geofence) == nullptr) {
        return nullptr;
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationGeofenceByLongitude(const napi_env &env, const napi_value &value,
    std::shared_ptr<NotificationGeofence> &geofence)
{
    bool hasProperty {false};
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;

    // longitude: double
    NAPI_CALL(env, napi_has_named_property(env, value, "longitude", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property longitude expected.");
        return nullptr;
    }
    double longitude = NotificationConstant::MIN_GEOFENCE_LONGITUDE - 1;
    NAPI_CALL(env, napi_get_named_property(env, value, "longitude", &result));
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Wrong argument type. Number expected.");
        std::string msg = "Incorrect parameter types. The type of longitude must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_value_double(env, result, &longitude);
    if (longitude < NotificationConstant::MIN_GEOFENCE_LONGITUDE ||
        longitude > NotificationConstant::MAX_GEOFENCE_LONGITUDE) {
        ANS_LOGE("longitude is invalid.");
        std::string msg = std::string("Invalid longitude. The longitude must be in range ") +
            std::to_string(NotificationConstant::MIN_GEOFENCE_LONGITUDE) + " to " +
            std::to_string(NotificationConstant::MAX_GEOFENCE_LONGITUDE) + ".";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    geofence->SetLongitude(longitude);

    return NapiGetNull(env);
}

napi_value Common::GetNotificationGeofenceByLatitude(const napi_env &env, const napi_value &value,
    std::shared_ptr<NotificationGeofence> &geofence)
{
    bool hasProperty {false};
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;

    // latitude: double
    NAPI_CALL(env, napi_has_named_property(env, value, "latitude", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property latitude expected.");
        return nullptr;
    }
    double latitude = NotificationConstant::MIN_GEOFENCE_LATITUDE - 1;
    NAPI_CALL(env, napi_get_named_property(env, value, "latitude", &result));
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Wrong argument type. Number expected.");
        std::string msg = "Incorrect parameter types. The type of latitude must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_value_double(env, result, &latitude);
    if (latitude < NotificationConstant::MIN_GEOFENCE_LATITUDE ||
        latitude > NotificationConstant::MAX_GEOFENCE_LATITUDE) {
        ANS_LOGE("latitude is invalid.");
        std::string msg = std::string("Invalid latitude. The latitude must be in range ") +
            std::to_string(NotificationConstant::MIN_GEOFENCE_LATITUDE) + " to " +
            std::to_string(NotificationConstant::MAX_GEOFENCE_LATITUDE) + ".";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    geofence->SetLatitude(latitude);

    return NapiGetNull(env);
}

napi_value Common::GetNotificationGeofenceByRadius(const napi_env &env, const napi_value &value,
    std::shared_ptr<NotificationGeofence> &geofence)
{
    bool hasProperty {false};
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;

    // radius: double
    NAPI_CALL(env, napi_has_named_property(env, value, "radius", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property radius expected.");
        return nullptr;
    }
    double radius = NotificationConstant::MIN_GEOFENCE_RADIUS - 1;
    NAPI_CALL(env, napi_get_named_property(env, value, "radius", &result));
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Wrong argument type. Number expected.");
        std::string msg = "Incorrect parameter types. The type of radius must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_value_double(env, result, &radius);
    if (radius < NotificationConstant::MIN_GEOFENCE_RADIUS ||
        radius > NotificationConstant::MAX_GEOFENCE_RADIUS) {
        ANS_LOGE("radius is invalid.");
        std::string msg = std::string("Invalid radius. The radius must be in range ") +
            std::to_string(NotificationConstant::MIN_GEOFENCE_RADIUS) + " to " +
            std::to_string(NotificationConstant::MAX_GEOFENCE_RADIUS) + ".";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    geofence->SetRadius(radius);

    return NapiGetNull(env);
}

napi_value Common::GetNotificationGeofenceByNumber(const napi_env &env, const napi_value &value,
    std::shared_ptr<NotificationGeofence> &geofence)
{
    bool hasProperty {false};
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;

    // delayTime?: int
    NAPI_CALL(env, napi_has_named_property(env, value, "delayTime", &hasProperty));
    if (hasProperty) {
        int32_t delayTime = NotificationConstant::MIN_GEOFENCE_DELAY_TIME_S - 1;
        NAPI_CALL(env, napi_get_named_property(env, value, "delayTime", &result));
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of delayTime must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int32(env, result, &delayTime);
        if (delayTime < NotificationConstant::MIN_GEOFENCE_DELAY_TIME_S ||
            delayTime > NotificationConstant::MAX_GEOFENCE_DELAY_TIME_S) {
            ANS_LOGE("delayTime is invalid.");
            std::string msg = std::string("Invalid delayTime. The delayTime must be in range ") +
                std::to_string(NotificationConstant::MIN_GEOFENCE_DELAY_TIME_S) + "s to " +
                std::to_string(NotificationConstant::MAX_GEOFENCE_DELAY_TIME_S) + "s.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        geofence->SetDelayTime(delayTime);
    } else {
        ANS_LOGD("Property delayTime expected.");
        geofence->SetDelayTime(NotificationConstant::DEFAULT_GEOFENCE_DELAY_TIME_S);
    }
    return NapiGetNull(env);
}

napi_value Common::GetNotificationGeofenceByEnum(const napi_env &env, const napi_value &value,
    std::shared_ptr<NotificationGeofence> &geofence)
{
    ANS_LOGD("called");
    // coordinateSystemType: CoordinateSystemType
    if (GetNotificationGeofenceByCoordinateSystemType(env, value, geofence) == nullptr) {
        return nullptr;
    }

    // monitorEvent: MonitorEvent
    if (GetNotificationGeofenceByMonitorEvent(env, value, geofence) == nullptr) {
        return nullptr;
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationGeofenceByCoordinateSystemType(const napi_env &env, const napi_value &value,
    std::shared_ptr<NotificationGeofence> &geofence)
{
    bool hasProperty {false};
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;

    // coordinateSystemType: CoordinateSystemType
    int32_t coordinateSystemType = 0;
    NAPI_CALL(env, napi_has_named_property(env, value, "coordinateSystemType", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property coordinateSystemType expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_named_property(env, value, "coordinateSystemType", &result));
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Wrong argument coordinateSystemType. Number expected.");
        std::string msg = "Incorrect parameter types. The type of coordinateSystemType must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_value_int32(env, result, &coordinateSystemType);
    NotificationConstant::CoordinateSystemType cCoordinateSystemType;
    if (!AnsEnumUtil::CoordinateSystemTypeJSToC(static_cast<CoordinateSystemType>(coordinateSystemType),
        cCoordinateSystemType)) {
        ANS_LOGE("coordinateSystemType is invalid.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return nullptr;
    }
    geofence->SetCoordinateSystemType(cCoordinateSystemType);

    return NapiGetNull(env);
}

napi_value Common::GetNotificationGeofenceByMonitorEvent(const napi_env &env, const napi_value &value,
    std::shared_ptr<NotificationGeofence> &geofence)
{
    bool hasProperty {false};
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;

    // monitorEvent: MonitorEvent
    int32_t monitorEvent = 0;
    NAPI_CALL(env, napi_has_named_property(env, value, "monitorEvent", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property monitorEvent expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_named_property(env, value, "monitorEvent", &result));
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Wrong argument type. Number expected.");
        std::string msg = "Incorrect parameter types. The type of monitorEvent must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_value_int32(env, result, &monitorEvent);
    NotificationConstant::MonitorEvent cMonitorEvent;
    if (!AnsEnumUtil::MonitorEventJSToC(static_cast<MonitorEvent>(monitorEvent), cMonitorEvent)) {
        ANS_LOGE("monitorEvent is invalid.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return nullptr;
    }
    geofence->SetMonitorEvent(cMonitorEvent);

    return NapiGetNull(env);
}

napi_value Common::SetNotificationTrigger(
    const napi_env &env, const std::shared_ptr<NotificationTrigger> &trigger, napi_value &result)
{
    ANS_LOGD("called");

    if (trigger == nullptr) {
        ANS_LOGE("null trigger");
        return NapiGetBoolean(env, false);
    }

    napi_value value = nullptr;
    // type: TriggerType
    if (napi_create_int32(env, static_cast<int32_t>(trigger->GetTriggerType()), &value) != napi_ok) {
        ANS_LOGE("Failed to create int32 for trigger type");
        return NapiGetBoolean(env, false);
    }
    napi_set_named_property(env, result, "type", value);

    // condition: Geofence
    std::shared_ptr<NotificationGeofence> condition = trigger->GetGeofence();
    if (condition) {
        napi_value conditionResult = nullptr;
        if (napi_create_object(env, &conditionResult) != napi_ok) {
            ANS_LOGE("Failed to create object for condition");
            return NapiGetBoolean(env, false);
        }
        if (!SetNotificationGeofence(env, condition, conditionResult)) {
            ANS_LOGE("SetNotificationGeofence call failed");
            napi_set_named_property(env, result, "condition", NapiGetNull(env));
            return NapiGetBoolean(env, false);
        }
        napi_set_named_property(env, result, "condition", conditionResult);
    } else {
        ANS_LOGE("null condition");
        return NapiGetBoolean(env, false);
    }

    // displayTime?: int
    if (napi_create_int32(env, trigger->GetDisplayTime(), &value) != napi_ok) {
        ANS_LOGE("Failed to create int32 for display time");
        return NapiGetBoolean(env, false);
    }
    napi_set_named_property(env, result, "displayTime", value);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotificationGeofence(
    const napi_env &env, const std::shared_ptr<NotificationGeofence> &condition, napi_value &result)
{
    ANS_LOGD("called");

    if (condition == nullptr) {
        ANS_LOGE("null trigger");
        return NapiGetBoolean(env, false);
    }

    napi_value value = nullptr;
    // longitude: double
    if (napi_create_double(env, condition->GetLongitude(), &value) != napi_ok) {
        ANS_LOGE("Failed to create double for longitude");
        return NapiGetBoolean(env, false);
    }
    napi_set_named_property(env, result, "longitude", value);

    // latitude: double
    if (napi_create_double(env, condition->GetLatitude(), &value) != napi_ok) {
        ANS_LOGE("Failed to create double for latitude");
        return NapiGetBoolean(env, false);
    }
    napi_set_named_property(env, result, "latitude", value);

    // radius: double
    if (napi_create_double(env, condition->GetRadius(), &value) != napi_ok) {
        ANS_LOGE("Failed to create double for radius");
        return NapiGetBoolean(env, false);
    }
    napi_set_named_property(env, result, "radius", value);

    // delayTime?: int
    if (napi_create_int32(env, condition->GetDelayTime(), &value) != napi_ok) {
        ANS_LOGE("Failed to create int32 for delay time");
        return NapiGetBoolean(env, false);
    }
    napi_set_named_property(env, result, "delayTime", value);

    // coordinateSystemType: CoordinateSystemType
    if (napi_create_int32(env, static_cast<int32_t>(condition->GetCoordinateSystemType()), &value) != napi_ok) {
        ANS_LOGE("Failed to create int32 for coordinate system type");
        return NapiGetBoolean(env, false);
    }
    napi_set_named_property(env, result, "coordinateSystemType", value);

    // monitorEvent: MonitorEvent
    if (napi_create_int32(env, static_cast<int32_t>(condition->GetMonitorEvent()), &value) != napi_ok) {
        ANS_LOGE("Failed to create int32 for monitor event");
        return NapiGetBoolean(env, false);
    }
    napi_set_named_property(env, result, "monitorEvent", value);

    return NapiGetBoolean(env, true);
}
}  // namespace NotificationNapi
}  // namespace OHOS