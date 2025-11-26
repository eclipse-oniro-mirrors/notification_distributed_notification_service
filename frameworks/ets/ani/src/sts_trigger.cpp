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
#include "sts_trigger.h"

#include "ans_log_wrapper.h"
#include "sts_common.h"

namespace OHOS {
namespace NotificationSts {
namespace {
constexpr const char *NOTIFICATION_REQUEST_TRIGGER_CLASSNAME = "notification.notificationRequest.TriggerInner";
constexpr const char *NOTIFICATION_REQUEST_GEOFENCE_CLASSNAME = "notification.notificationRequest.GeofenceInner";
constexpr const char *NOTIFICATION_MONITOR_EVENT_CLASSNAME = "notification.notificationRequest.MonitorEvent";
constexpr const char *NOTIFICATION_COORDINATESYSTEM_TYPE_CLASSNAME =
    "notification.notificationRequest.CoordinateSystemType";
constexpr const char *NOTIFICATION_TRIGGER_TYPE_CLASSNAME = "notification.notificationRequest.TriggerType";
}

bool MonitorEventCToSts(const NotificationConstant::MonitorEvent inType, STSMonitorEvent &outType)
{
    switch (inType) {
        case NotificationConstant::MonitorEvent::MONITOR_TYPE_ENTRY:
            outType = STSMonitorEvent::MONITOR_TYPE_ENTRY;
            break;
        case NotificationConstant::MonitorEvent::MONITOR_TYPE_LEAVE:
            outType = STSMonitorEvent::MONITOR_TYPE_LEAVE;
            break;
        default:
            ANS_LOGE("MonitorEvent %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool MonitorEventCToSts(ani_env *env, const NotificationConstant::MonitorEvent inType, ani_enum_item &enumItem)
{
    ANS_LOGD("MonitorEventCToSts call");
    STSMonitorEvent outType;
    if (!MonitorEventCToSts(inType, outType) ||
        !EnumConvertNativeToAni(env, NOTIFICATION_MONITOR_EVENT_CLASSNAME, outType, enumItem)) {
        ANS_LOGE("MonitorEventCToSts failed");
        return false;
    }
    return true;
}

bool MonitorEventStsToC(const STSMonitorEvent inType, NotificationConstant::MonitorEvent &outType)
{
    switch (inType) {
        case STSMonitorEvent::MONITOR_TYPE_ENTRY:
            outType = NotificationConstant::MonitorEvent::MONITOR_TYPE_ENTRY;
            break;
        case STSMonitorEvent::MONITOR_TYPE_LEAVE:
            outType = NotificationConstant::MonitorEvent::MONITOR_TYPE_LEAVE;
            break;
        default:
            ANS_LOGE("STSMonitorEvent %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool CoordinateSystemTypeCToSts(const NotificationConstant::CoordinateSystemType inType,
    STSCoordinateSystemType &outType)
{
    switch (inType) {
        case NotificationConstant::CoordinateSystemType::COORDINATE_TYPE_WGS84:
            outType = STSCoordinateSystemType::COORDINATE_TYPE_WGS84;
            break;
        case NotificationConstant::CoordinateSystemType::COORDINATE_TYPE_GCJ02:
            outType = STSCoordinateSystemType::COORDINATE_TYPE_GCJ02;
            break;
        default:
            ANS_LOGE("CoordinateSystemType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool CoordinateSystemTypeCToSts(ani_env *env, const NotificationConstant::CoordinateSystemType inType,
    ani_enum_item &enumItem)
{
    ANS_LOGD("CoordinateSystemTypeCToSts call");
    STSCoordinateSystemType outType;
    if (!CoordinateSystemTypeCToSts(inType, outType) ||
        !EnumConvertNativeToAni(env, NOTIFICATION_COORDINATESYSTEM_TYPE_CLASSNAME, outType, enumItem)) {
        ANS_LOGE("CoordinateSystemTypeCToSts failed");
        return false;
    }
    return true;
}

bool CoordinateSystemTypeStsToC(const STSCoordinateSystemType inType,
    NotificationConstant::CoordinateSystemType &outType)
{
    switch (inType) {
        case STSCoordinateSystemType::COORDINATE_TYPE_WGS84:
            outType = NotificationConstant::CoordinateSystemType::COORDINATE_TYPE_WGS84;
            break;
        case STSCoordinateSystemType::COORDINATE_TYPE_GCJ02:
            outType = NotificationConstant::CoordinateSystemType::COORDINATE_TYPE_GCJ02;
            break;
        default:
            ANS_LOGE("STSCoordinateSystemType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool TriggerTypeCToSts(const NotificationConstant::TriggerType inType, STSTriggerType &outType)
{
    switch (inType) {
        case NotificationConstant::TriggerType::TRIGGER_TYPE_FENCE:
            outType = STSTriggerType::TRIGGER_TYPE_FENCE;
            break;
        default:
            ANS_LOGE("TriggerType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool TriggerTypeCToSts(ani_env *env, const NotificationConstant::TriggerType inType, ani_enum_item &enumItem)
{
    ANS_LOGD("TriggerTypeCToSts call");
    STSTriggerType outType;
    if (!TriggerTypeCToSts(inType, outType) ||
        !EnumConvertNativeToAni(env, NOTIFICATION_TRIGGER_TYPE_CLASSNAME, outType, enumItem)) {
        ANS_LOGE("TriggerTypeCToSts failed");
        return false;
    }
    return true;
}

bool TriggerTypeStsToC(const STSTriggerType inType, NotificationConstant::TriggerType &outType)
{
    switch (inType) {
        case STSTriggerType::TRIGGER_TYPE_FENCE:
            outType = NotificationConstant::TriggerType::TRIGGER_TYPE_FENCE;
            break;
        default:
            ANS_LOGE("STSTriggerType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool UnwrapTriggerType(ani_env *env, ani_object object, NotificationTrigger &trigger)
{
    // type: TriggerType
    ani_status status = ANI_ERROR;
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref triggerTypeAniType = {};
    STSTriggerType stsTriggerType = STSTriggerType::TRIGGER_TYPE_FENCE;
    NotificationConstant::TriggerType triggerType = NotificationConstant::TriggerType::TRIGGER_TYPE_FENCE;
    status = GetPropertyRef(env, object, "type", isUndefined, triggerTypeAniType);
    if (status != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGE("UnwrapTrigger get triggerType failed. status %{public}d", status);
        return false;
    }
    if (triggerTypeAniType == nullptr ||
        !EnumConvertAniToNative(env, static_cast<ani_enum_item>(triggerTypeAniType), stsTriggerType)) {
        ANS_LOGE("EnumConvertAniToNative stsTriggerType failed");
        return false;
    }
    if (!TriggerTypeStsToC(stsTriggerType, triggerType)) {
        ANS_LOGE("TriggerTypeStsToC triggerType failed");
        return false;
    }
    trigger.SetTriggerType(triggerType);
    return true;
}

bool UnwrapTriggerCondition(ani_env *env, ani_object object, NotificationTrigger &trigger)
{
    // condition: Geofence
    ani_status status = ANI_ERROR;
    ani_ref conditionRef = {};
    ani_boolean isUndefined = ANI_TRUE;
    status = GetPropertyRef(env, object, "condition", isUndefined, conditionRef);
    if (status != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGE("Cannot get the value of condition. status %{public}d isUndefined %{public}d",
            status, isUndefined);
        return false;
    }
    OHOS::Notification::NotificationGeofence condition;
    if (!UnwrapGeofence(env, static_cast<ani_object>(conditionRef), condition)) {
        ANS_LOGE("UnwrapGeofence failed");
        return false;
    }
    trigger.SetGeofence(std::make_shared<OHOS::Notification::NotificationGeofence>(condition));
    return true;
}

bool UnwrapTriggerDisplayTime(ani_env *env, ani_object object, NotificationTrigger &trigger)
{
    // displayTime?:int;
    ani_status status = ANI_ERROR;
    ani_boolean isUndefined = ANI_TRUE;
    ani_int displayTime = 0;
    status = GetPropertyInt(env, object, "displayTime", isUndefined, displayTime);
    if (status != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGD("UnwrapGeofence get displayTime failed.");
        trigger.SetDisplayTime(NotificationConstant::DEFAULT_GEOFENCE_DISPLAY_TIME_S);
    }
    auto cDisplayTime = static_cast<int32_t>(displayTime);
    if (cDisplayTime <= NotificationConstant::MIN_GEOFENCE_DISPLAY_TIME_S ||
        cDisplayTime >= NotificationConstant::MAX_GEOFENCE_DISPLAY_TIME_S) {
        ANS_LOGE("UnwrapGeofence displayTime is invalid.");
        return false;
    }
    trigger.SetDisplayTime(cDisplayTime);
    return true;
}

bool UnwrapTrigger(ani_env *env, ani_object object, NotificationTrigger &trigger)
{
    ANS_LOGD("UnwrapTrigger call");
    if (env == nullptr || object == nullptr) {
        ANS_LOGE("UnwrapTrigger failed, has nullptr");
        return false;
    }

    if (!UnwrapTriggerType(env, object, trigger)) {
        ANS_LOGE("UnwrapTrigger: cover type failed");
        return false;
    }

    if (!UnwrapTriggerCondition(env, object, trigger)) {
        ANS_LOGE("UnwrapTrigger: set condition failed");
        return false;
    }
    if (!UnwrapTriggerDisplayTime(env, object, trigger)) {
        ANS_LOGE("UnwrapTrigger: set displayTime failed");
        return false;
    }

    trigger.SetConfigPath(NotificationConstant::ConfigPath::CONFIG_PATH_CLOUD_CONFIG);
    return true;
}

bool WrapTrigger(ani_env* env, const std::shared_ptr<NotificationTrigger> &trigger, ani_object &object)
{
    ANS_LOGD("WrapTrigger call");
    if (env == nullptr || trigger == nullptr) {
        ANS_LOGE("WrapTrigger failed, has nullptr");
        return false;
    }
    ani_class triggerClass = nullptr;
    if (!CreateClassObjByClassName(env, NOTIFICATION_REQUEST_TRIGGER_CLASSNAME, triggerClass, object)) {
        ANS_LOGE("WrapTrigger: create class failed");
        return false;
    }

    // type: TriggerType
    ani_enum_item triggerType {};
    if (!TriggerTypeCToSts(env, trigger->GetTriggerType(), triggerType)) {
        ANS_LOGE("WrapTrigger: cover type failed");
        return false;
    }
    if (!CallSetter(env, triggerClass, object, "type", triggerType)) {
        ANS_LOGE("WrapTrigger: Set type failed");
        return false;
    }

    // condition:Geofence
    std::shared_ptr<NotificationGeofence> condition = trigger->GetGeofence();
    if (condition == nullptr) {
        ANS_LOGE("condition is Undefine");
        return true;
    }
    ani_object conditionObject = nullptr;
    if (!WrapGeofence(env, condition, conditionObject) || conditionObject == nullptr) {
        ANS_LOGE("WrapTrigger: WrapGeofence failed");
        return false;
    }
    if (!SetPropertyByRef(env, object, "condition", conditionObject)) {
        ANS_LOGE("WrapTrigger: set condition failed");
        return false;
    }

    // displayTime?:int
    if (!SetPropertyOptionalByInt(env, object, "displayTime", trigger->GetDisplayTime())) {
        ANS_LOGD("WrapTrigger: set displayTime failed");
    }
    return true;
}

bool UnwrapGeofence(ani_env *env, ani_object object, NotificationGeofence &condition)
{
    if (env == nullptr || object == nullptr) {
        ANS_LOGE("UnWarpDistributedOptions failed, has nullptr");
        return false;
    }

    if (!UnwrapGeofenceLongitude(env, object, condition)) {
        ANS_LOGE("UnwrapGeofence, get longitude failed");
        return false;
    }

    if (!UnwrapGeofenceLatitude(env, object, condition)) {
        ANS_LOGE("UnwrapGeofence, get latitude failed");
        return false;
    }

    if (!UnwrapGeofenceRadius(env, object, condition)) {
        ANS_LOGE("UnwrapGeofence, get radius failed");
        return false;
    }

    if (!UnwrapGeofenceDelayTime(env, object, condition)) {
        ANS_LOGE("UnwrapGeofence failed, get delayTime failed");
        return false;
    }

    if (!UnwrapGeofenceCoordinateSystemType(env, object, condition)) {
        ANS_LOGE("UnwrapGeofence failed, get coordinateSystemType failed");
        return false;
    }

    if (!UnwrapGeofenceMonitorEvent(env, object, condition)) {
        ANS_LOGE("UnwrapGeofence failed, get unwrapGeofenceMonitorEvent failed");
        return false;
    }

    return true;
}

bool UnwrapGeofenceLongitude(ani_env *env, ani_object object, NotificationGeofence &condition)
{
    // longitude:double
    ani_status status = ANI_ERROR;
    double longitude = NotificationConstant::MIN_GEOFENCE_LONGITUDE - 1;
    status = GetPropertyValueDouble(env, object, "longitude", longitude);
    if (status != ANI_OK) {
        ANS_LOGE("UnwrapGeofence get longitude failed. status %{public}d", status);
        return false;
    }
    if (longitude <= NotificationConstant::MIN_GEOFENCE_LONGITUDE ||
        longitude >= NotificationConstant::MAX_GEOFENCE_LONGITUDE) {
        ANS_LOGE("UnwrapGeofence longitude is invalid.");
        return false;
    }
    condition.SetLongitude(longitude);
    return true;
}

bool UnwrapGeofenceLatitude(ani_env *env, ani_object object, NotificationGeofence &condition)
{
    // latitude:double
    ani_status status = ANI_ERROR;
    double latitude = NotificationConstant::MIN_GEOFENCE_LATITUDE - 1;
    status = GetPropertyValueDouble(env, object, "latitude", latitude);
    if (status != ANI_OK) {
        ANS_LOGE("UnwrapGeofence get latitude failed. status %{public}d", status);
        return false;
    }
    if (latitude <= NotificationConstant::MIN_GEOFENCE_LATITUDE ||
        latitude >= NotificationConstant::MAX_GEOFENCE_LATITUDE) {
        ANS_LOGE("UnwrapGeofence latitude is invalid.");
        return false;
    }
    condition.SetLatitude(latitude);
    return true;
}

bool UnwrapGeofenceRadius(ani_env *env, ani_object object, NotificationGeofence &condition)
{
    // radius:double
    ani_status status = ANI_ERROR;
    double radius = NotificationConstant::MIN_GEOFENCE_RADIUS - 1;
    status = GetPropertyValueDouble(env, object, "radius", radius);
    if (status != ANI_OK) {
        ANS_LOGE("UnwrapGeofence get radius failed. status %{public}d", status);
        return false;
    }
    if (radius <= NotificationConstant::MIN_GEOFENCE_RADIUS ||
        radius >= NotificationConstant::MAX_GEOFENCE_RADIUS) {
        ANS_LOGE("UnwrapGeofence radius is invalid.");
        return false;
    }
    condition.SetRadius(radius);
    return true;
}

bool UnwrapGeofenceDelayTime(ani_env *env, ani_object object, NotificationGeofence &condition)
{
    // delayTime?:int
    ani_status status = ANI_ERROR;
    ani_boolean isUndefined = ANI_TRUE;
    ani_int delayTime = 0;
    status = GetPropertyInt(env, object, "delayTime", isUndefined, delayTime);
    if (status != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGD("UnwrapGeofence get delayTime failed.");
        condition.SetDelayTime(NotificationConstant::DEFAULT_GEOFENCE_DELAY_TIME_S);
    }
    auto cDelayTime = static_cast<int32_t>(delayTime);
    if (cDelayTime <= NotificationConstant::MIN_GEOFENCE_DELAY_TIME_S ||
        cDelayTime >= NotificationConstant::MAX_GEOFENCE_DELAY_TIME_S) {
        ANS_LOGE("UnwrapGeofence delayTime is invalid.");
        return false;
    }
    condition.SetDelayTime(cDelayTime);
    return true;
}

bool UnwrapGeofenceMonitorEvent(ani_env *env, ani_object object, NotificationGeofence &condition)
{
   // coordinateSystemType:CoordinateSystemType
    ani_status status = ANI_ERROR;
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref coordinateSystemTypeAni = {};
    STSCoordinateSystemType stsCoordinateSystemType = STSCoordinateSystemType::COORDINATE_TYPE_WGS84;
    NotificationConstant::CoordinateSystemType coordinateSystemType =
        NotificationConstant::CoordinateSystemType::COORDINATE_TYPE_WGS84;
    status = GetPropertyRef(env, object, "coordinateSystemType", isUndefined, coordinateSystemTypeAni);
    if (status != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGE("UnwrapGeofence get coordinateSystemType failed. status %{public}d", status);
        return false;
    }
    if (coordinateSystemTypeAni == nullptr ||
        !EnumConvertAniToNative(env, static_cast<ani_enum_item>(coordinateSystemTypeAni), stsCoordinateSystemType)) {
        ANS_LOGE("EnumConvertAniToNative stsCoordinateSystemType failed");
        return false;
    }
    if (!CoordinateSystemTypeStsToC(stsCoordinateSystemType, coordinateSystemType)) {
        ANS_LOGE("CoordinateSystemTypeStsToC coordinateSystemType failed");
        return false;
    }
    condition.SetCoordinateSystemType(coordinateSystemType);
    return true;
}

bool UnwrapGeofenceCoordinateSystemType(ani_env *env, ani_object object, NotificationGeofence &condition)
{
    // monitorEvent:MonitorEvent
    ani_status status = ANI_ERROR;
    ani_boolean isUndefined = ANI_TRUE;
    ani_ref monitorEventAni = {};
    STSMonitorEvent stsMonitorEvent = STSMonitorEvent::MONITOR_TYPE_ENTRY;
    NotificationConstant::MonitorEvent monitorEvent =
        NotificationConstant::MonitorEvent::MONITOR_TYPE_ENTRY;
    status = GetPropertyRef(env, object, "monitorEvent", isUndefined, monitorEventAni);
    if (status != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGE("UnwrapGeofence get monitorEvent failed. status %{public}d", status);
        return false;
    }
    if (monitorEventAni == nullptr ||
        !EnumConvertAniToNative(env, static_cast<ani_enum_item>(monitorEventAni), stsMonitorEvent)) {
        ANS_LOGE("EnumConvertAniToNative stsMonitorEvent failed");
        return false;
    }
    if (!MonitorEventStsToC(stsMonitorEvent, monitorEvent)) {
        ANS_LOGE("MonitorEventStsToC monitorEvent failed");
        return false;
    }
    condition.SetMonitorEvent(monitorEvent);
    return true;
}

bool WrapGeofence(ani_env *env,
    const std::shared_ptr<NotificationGeofence> &geofence, ani_object &object)
{
    ANS_LOGD("WrapGeofence call");
    if (env == nullptr || geofence == nullptr) {
        ANS_LOGE("WrapGeofence failed, has nullptr");
        return false;
    }
    ani_class geofenceClass = nullptr;
    if (!CreateClassObjByClassName(env, NOTIFICATION_REQUEST_GEOFENCE_CLASSNAME, geofenceClass, object)) {
        ANS_LOGE("WrapGeofence: create class failed");
        return false;
    }

    // longitude:double
    if (!SetPropertyOptionalByDouble(env, object, "longitude", geofence->GetLongitude())) {
        ANS_LOGE("WrapGeofence: set longitude failed");
        return false;
    }
    // latitude:double
    if (!SetPropertyOptionalByDouble(env, object, "latitude", geofence->GetLatitude())) {
        ANS_LOGE("WrapGeofence: set latitude failed");
        return false;
    }
    // radius:double
    if (!SetPropertyOptionalByDouble(env, object, "radius", geofence->GetRadius())) {
        ANS_LOGE("WrapGeofence: set radius failed");
        return false;
    }
    // delayTime?:int
    if (!SetPropertyOptionalByInt(env, object, "delayTime", geofence->GetDelayTime())) {
        ANS_LOGD("WrapGeofence: set delayTime failed");
    }

    // coordinateSystemType:CoordinateSystemType
    ani_enum_item coordinateSystemType {};
    if (!CoordinateSystemTypeCToSts(env, geofence->GetCoordinateSystemType(), coordinateSystemType)) {
        ANS_LOGE("WrapGeofence: cover coordinateSystemType failed");
        return false;
    }
    if (!CallSetter(env, geofenceClass, object, "coordinateSystemType", coordinateSystemType)) {
        ANS_LOGE("WrapGeofence: Set coordinateSystemType failed");
        return false;
    }

    // monitorEvent:MonitorEvent
    ani_enum_item monitorEvent {};
    if (!MonitorEventCToSts(env, geofence->GetMonitorEvent(), monitorEvent)) {
        ANS_LOGE("WrapGeofence: cover monitorEvent failed");
        return false;
    }
    if (!CallSetter(env, geofenceClass, object, "monitorEvent", monitorEvent)) {
        ANS_LOGE("WrapGeofence: Set monitorEvent failed");
        return false;
    }

    return true;
}
}
}