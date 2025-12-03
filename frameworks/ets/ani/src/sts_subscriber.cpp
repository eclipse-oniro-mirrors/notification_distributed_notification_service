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
#include "sts_subscriber.h"

#include "ans_log_wrapper.h"
#include "sts_common.h"
#include "sts_request.h"
#include "sts_sorting_map.h"

namespace OHOS {
namespace NotificationSts {
const int32_t NO_DELETE_REASON = -1;

bool SetNotificationRequest(ani_env *env, const std::shared_ptr<NotificationSts> &request, ani_object &outObj)
{
    ani_status status = ANI_OK;
    ani_object requestObj;
    ani_class requestCls;
    sptr<NotificationSts> notification = new (std::nothrow)NotificationSts(request->GetNotificationRequestPoint());
    if (!notification) {
        ANS_LOGE("new notification faild");
        return false;
    }
    if (!WarpNotification(env, notification, requestCls, requestObj) || requestObj == nullptr) {
        ANS_LOGE("WarpNotification faild");
        return false;
    }
    if (ANI_OK != (status = env->Object_SetPropertyByName_Ref(outObj, "request", requestObj))) {
        ANS_LOGE("set request faild. status %{public}d", status);
        return false;
    }
    return true;
}

bool SetNotificationSortingMap(
    ani_env *env, const std::shared_ptr<NotificationSortingMap> &sortingMap, ani_object &outObj)
{
    ani_status status = ANI_OK;
    ani_object sortingMapObj;
    if (!WarpNotificationSortingMap(env, sortingMap, sortingMapObj)) {
        ANS_LOGE("WarpNotificationSortingMap faild");
        return false;
    }
    if (ANI_OK != (status = env->Object_SetPropertyByName_Ref(outObj, "sortingMap", sortingMapObj))) {
        ANS_LOGE("set sortingMap faild. status %{public}d", status);
        return false;
    }
    return true;
}

bool SetReason(ani_env *env, const int32_t deleteReason, ani_object &outObj)
{
    ani_status status = ANI_OK;
    if (deleteReason != -1) {
        ani_object reason = CreateInt(env, deleteReason);
        if (reason == nullptr) {
            ANS_LOGE("reason Create faild");
            return false;
        }
        if (ANI_OK != (status = env->Object_SetPropertyByName_Ref(outObj, "reason", reason))) {
            ANS_LOGE("set reason faild. status %{public}d", status);
            return false;
        }
    }
    return true;
}

bool SetSound(ani_env *env, const std::shared_ptr<NotificationSts> &request, ani_object &outObj)
{
    ani_status status = ANI_OK;
    if (request->EnableSound()) {
        std::string sound = request->GetSound().ToString();
        ani_string soundObj;
        if (ANI_OK != GetAniStringByString(env, sound, soundObj) || soundObj == nullptr) {
            ANS_LOGE("sound create faild");
            return false;
        }
        if (ANI_OK != (status = env->Object_SetPropertyByName_Ref(outObj, "sound", soundObj))) {
            ANS_LOGE("set sound faild. status %{public}d", status);
        }
    }
    return true;
}

bool SetVibrationValues(ani_env *env, const std::shared_ptr<NotificationSts> &request, ani_object &outObj)
{
    ani_status status = ANI_OK;
    if (request->EnableVibrate()) {
        ani_array vibrationValuesObj;
        const std::vector<int64_t> vibrationValues = request->GetVibrationStyle();
        vibrationValuesObj = newArrayClass(env, vibrationValues.size());
        if (vibrationValuesObj == nullptr) {
            ANS_LOGE("CreateArray faild");
            return false;
        }
        for (size_t i = 0; i < vibrationValues.size(); i++) {
            ani_object longObj = CreateLong(env, vibrationValues[i]);
            if (longObj == nullptr) {
                ANS_LOGE("CreateLong faild null intObj");
                return false;
            }
            status = env->Array_Set(vibrationValuesObj, i, longObj);
            if (status != ANI_OK) {
                ANS_LOGE("faild. status : %{public}d", status);
                return false;
            }
        }
        if (ANI_OK != (status = env->Object_SetPropertyByName_Ref(outObj, "vibrationValues", vibrationValuesObj))) {
            ANS_LOGE("set vibrationValuesObj faild. status %{public}d", status);
            return false;
        }
    }
    return true;
}

bool WarpSubscribeCallbackData(
    ani_env *env,
    const std::shared_ptr<NotificationSts> &request,
    const std::shared_ptr<NotificationSortingMap> &sortingMap,
    int32_t deleteReason,
    ani_object &outObj)
{
    ANS_LOGD("enter");
    ani_class cls;
    if (env == nullptr || request == nullptr || sortingMap == nullptr) {
        ANS_LOGE("invalid parameter value");
        return false;
    }
    if (!CreateClassObjByClassName(
        env, "notification.notificationSubscriber.SubscribeCallbackDataInner", cls, outObj)) {
            ANS_LOGE("CreateClassObjByClassName faild");
            return false;
    }
    // request: NotificationRequest
    if (!SetNotificationRequest(env, request, outObj)) {
        ANS_LOGE("SetNotificationRequest faild");
        return false;
    }
    // sortingMap?: NotificationSortingMap
    if (!SetNotificationSortingMap(env, sortingMap, outObj)) {
        ANS_LOGE("SetNotificationSortingMap faild");
        return false;
    }
    // reason?: int
    if (deleteReason != NO_DELETE_REASON && !SetReason(env, deleteReason, outObj)) {
        ANS_LOGE("SetReason faild");
        return false;
    }
    // sound?: string
    if (!SetSound(env, request, outObj)) {
        ANS_LOGE("SetSound faild");
    }
    // vibrationValues?: Array<long>
    if (!SetVibrationValues(env, request, outObj)) {
        ANS_LOGE("SetSound faild");
    }
    return true;
}

bool WarpSubscribeCallbackDataArray(
    ani_env *env,
    const std::vector<std::shared_ptr<OHOS::Notification::Notification>> &requestList,
    const std::shared_ptr<NotificationSortingMap> &sortingMap,
    int32_t deleteReason,
    ani_array &outObj)
{
    ANS_LOGD("enter");
    if (env == nullptr || sortingMap == nullptr) {
        ANS_LOGE("invalid parameter value");
        return false;
    }
    ani_status status;
    if (env == nullptr) {
        ANS_LOGE("env is nullptr");
        return false;
    }
    outObj = newArrayClass(env, requestList.size());
    if (outObj == nullptr) {
        ANS_LOGE("CreateArray faild");
        return false;
    }
    for (size_t i = 0; i < requestList.size(); i++) {
        ani_object obj;
        if (!WarpSubscribeCallbackData(env, requestList[i], sortingMap, deleteReason, obj)) {
            ANS_LOGE("WarpSubscribeCallbackData faild");
            return false;
        }
        if (ANI_OK != (status = env->Array_Set(outObj, i, obj))) {
                ANS_LOGE("set object faild. status %{public}d", status);
                return false;
            }
    }
    return true;
}

bool WarpEnabledNotificationCallbackData(
    ani_env *env, const std::shared_ptr<EnabledNotificationCallbackData> &callbackData, ani_object &outObj)
{
    ANS_LOGD("enter");
    if (env == nullptr || callbackData == nullptr) {
        ANS_LOGE("invalid parameter value");
        return false;
    }
    ani_class cls;
    ani_status status;
    const char *className = "notification.notificationSubscriber.EnabledNotificationCallbackDataInner";
    if (!CreateClassObjByClassName(env, className, cls, outObj)) {
        ANS_LOGE("CreateClassObjByClassName faild");
        return false;
    }
    if (!SetFieldString(env, cls, outObj, "bundle", callbackData->GetBundle())) {
        ANS_LOGE("SetFieldString bundle faild");
        return false;
    }
    if (!CallSetter(env, cls, outObj, "uid", static_cast<ani_int>(callbackData->GetUid()))) {
        ANS_LOGE("uid set faild.");
        return false;
    }
    if (ANI_OK != (status = env->Object_SetPropertyByName_Boolean(
        outObj, "enable", BoolToAniBoolean(callbackData->GetEnable())))) {
            ANS_LOGE("set enable faild. status %{public}d", status);
            return false;
        }
    return true;
}

bool WrapEnabledPriorityNotificationCallbackData(
    ani_env *env, const std::shared_ptr<EnabledNotificationCallbackData> &callbackData, ani_object &outObj)
{
    if (env == nullptr || callbackData == nullptr) {
        ANS_LOGE("invalid parameter value");
        return false;
    }
    ani_class cls;
    ani_status status;
    const char *className = "notification.notificationSubscriber.EnabledPriorityNotificationCallbackDataInner";
    if (!CreateClassObjByClassName(env, className, cls, outObj)) {
        ANS_LOGE("CreateClassObjByClassName faild");
        return false;
    }
    status = env->Object_SetPropertyByName_Boolean(outObj, "enable", BoolToAniBoolean(callbackData->GetEnable()));
    if (status != ANI_OK) {
        ANS_LOGE("set enable faild. status %{public}d", status);
        return false;
    }
    return true;
}

bool WrapEnabledPriorityNotificationByBundleCallbackData(ani_env *env,
    const std::shared_ptr<EnabledPriorityNotificationByBundleCallbackData> &callbackData, ani_object &outObj)
{
    if (env == nullptr || callbackData == nullptr) {
        ANS_LOGE("invalid parameter value");
        return false;
    }
    ani_class cls;
    const char *className = "notification.notificationSubscriber.EnabledPriorityNotificationByBundleCallbackDataInner";
    if (!CreateClassObjByClassName(env, className, cls, outObj)) {
        ANS_LOGE("CreateClassObjByClassName faild");
        return false;
    }
    if (!SetFieldString(env, cls, outObj, "bundle", callbackData->GetBundle())) {
        ANS_LOGE("SetFieldString bundle faild");
        return false;
    }
    if (!CallSetter(env, cls, outObj, "uid", static_cast<ani_int>(callbackData->GetUid()))) {
        ANS_LOGE("uid set faild.");
        return false;
    }
    if (env->Object_SetPropertyByName_Int(
        outObj, "enableStatus", static_cast<int32_t>(callbackData->GetEnableStatus())) != ANI_OK) {
        ANS_LOGE("status set faild.");
        return false;
    }
    return true;
}

bool WarpBadgeNumberCallbackData(
    ani_env *env, const std::shared_ptr<BadgeNumberCallbackData> &badgeData, ani_object &outObj)
{
    ANS_LOGD("enter");
    if (env == nullptr || badgeData == nullptr) {
        ANS_LOGE("invalid parameter value");
        return false;
    }
    ani_class cls;
    ani_object instanceKeyObj;
    const char *className = "notification.notificationSubscriber.BadgeNumberCallbackDataInner";
    if (!CreateClassObjByClassName(env, className, cls, outObj)) {
        ANS_LOGE("CreateClassObjByClassName faild");
        return false;
    }
    if (!SetFieldString(env, cls, outObj, "bundle", badgeData->GetBundle())) {
        ANS_LOGE("SetFieldString bundle faild");
        return false;
    }
    if (!SetFieldInt(env, cls, outObj, "uid", badgeData->GetUid())) {
        ANS_LOGE("SetFieldInt uid faild");
        return false;
    }
    if (!SetFieldInt(env, cls, outObj, "badgeNumber", badgeData->GetBadgeNumber())) {
        ANS_LOGE("SetFieldInt badgeNumber faild");
        return false;
    }
    instanceKeyObj = CreateInt(env, static_cast<ani_int>(badgeData->GetInstanceKey()));
    if (instanceKeyObj != nullptr) {
        if (!CallSetter(env, cls, outObj, "instanceKey", instanceKeyObj)) {
            ANS_LOGE("instanceKey set faild.");
            return false;
        }
    }
    if (!SetFieldString(env, cls, outObj, "appInstanceKey", badgeData->GetAppInstanceKey())) {
        ANS_LOGD("SetFieldString appInstanceKey faild");
        return false;
    }
    return true;
}

} // namespace NotificationSts
} // OHOS
