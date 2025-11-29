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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_TRIGGER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_TRIGGER_H
#include "ani.h"
#include "notification_geofence.h"
#include "notification_trigger.h"

using NotificationTrigger = OHOS::Notification::NotificationTrigger;
using NotificationGeofence = OHOS::Notification::NotificationGeofence;
using NotificationConstant = OHOS::Notification::NotificationConstant;

namespace OHOS {
namespace NotificationSts {
bool UnwrapTrigger(ani_env *env, ani_object object, NotificationTrigger &trigger);
bool UnwrapTriggerType(ani_env *env, ani_object object, NotificationTrigger &trigger);
bool UnwrapTriggerCondition(ani_env *env, ani_object object, NotificationTrigger &trigger);
bool UnwrapTriggerDisplayTime(ani_env *env, ani_object object, NotificationTrigger &trigger);
bool WrapTrigger(ani_env *env, const std::shared_ptr<NotificationTrigger> &trigger, ani_object &object);

bool UnwrapGeofence(ani_env *env, ani_object object, NotificationGeofence &geofence);
bool UnwrapGeofenceLongitude(ani_env *env, ani_object object, NotificationGeofence &geofence);
bool UnwrapGeofenceLatitude(ani_env *env, ani_object object, NotificationGeofence &geofence);
bool UnwrapGeofenceRadius(ani_env *env, ani_object object, NotificationGeofence &geofence);
bool UnwrapGeofenceDelayTime(ani_env *env, ani_object object, NotificationGeofence &geofence);
bool UnwrapGeofenceCoordinateSystemType(ani_env *env, ani_object object, NotificationGeofence &geofence);
bool UnwrapGeofenceMonitorEvent(ani_env *env, ani_object object, NotificationGeofence &geofence);
bool WrapGeofence(ani_env *env, const std::shared_ptr<NotificationGeofence> &geofence, ani_object &object);

enum class STSMonitorEvent {
    MONITOR_TYPE_ENTRY = 1,
    MONITOR_TYPE_LEAVE = 2
};

enum class STSCoordinateSystemType {
    COORDINATE_TYPE_WGS84 = 1,
    COORDINATE_TYPE_GCJ02 = 2
};

enum class STSTriggerType {
    TRIGGER_TYPE_FENCE = 1
};
}
}
#endif