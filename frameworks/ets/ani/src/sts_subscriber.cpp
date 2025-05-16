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
bool WarpSubscribeCallbackData(
    ani_env *env,
    const std::shared_ptr<NotificationSts> &request,
    const std::shared_ptr<NotificationSortingMap> &sortingMap,
    int32_t deleteReason,
    ani_object &outObj)
{
    ANS_LOGD("enter");
    ani_object sortingMapObj;
    ani_status status;
    ani_class cls;
    if (env == nullptr) {
        ANS_LOGD("env is nullptr");
        return false;
    }

    if (!CreateClassObjByClassName(
        env, "Lnotification/notificationSubscriber/SubscribeCallbackDataInner;", cls, outObj)) {
            ANS_LOGD("CreateClassObjByClassName faild");
            return false;
    }

    // request: NotificationRequest
    // TODO
    // Warp NotificationRequest
    ani_object requestObj;
    ani_class requestCls;
    if (!WarpNotificationRequest(env, request->GetNotificationRequestPoint().GetRefPtr(), requestCls, requestObj)) {
        return false;
    }
    if (requestObj == nullptr) {
        ANS_LOGD("WarpNotificationRequest faild");
        return false;
    }

    // for test
    // if (!CreateClassObjByClassName(
    //     env, "Lnotification/notificationRequest/NotificationRequestInner;", requestCls, requestObj)) {
    //         ANS_LOGD("create NotificationRequest faild.");
    //         return false;
    //     }

    if (ANI_OK != (status = env->Object_SetPropertyByName_Ref(outObj, "request", requestObj))) {
        ANS_LOGD("set request faild. status %{public}d", status);
        return false;
    }

    // sortingMap?: NotificationSortingMap
    if (!WarpNotificationSortingMap(env, sortingMap, sortingMapObj)) {
        ANS_LOGD("WarpNotificationSortingMap faild");
        return false;
    }
    if (ANI_OK != (status = env->Object_SetPropertyByName_Ref(outObj, "sortingMap", sortingMapObj))) {
        ANS_LOGD("set sortingMap faild. status %{public}d", status);
        return false;
    }

    // reason?: number
    if (deleteReason != -1) {
        ani_object reason = CreateDouble(env, static_cast<ani_double>(deleteReason));
        if (reason == nullptr) {
            ANS_LOGD("reason Create faild");
            return false;
        }
        if (ANI_OK != (status = env->Object_SetPropertyByName_Ref(outObj, "reason", reason))) {
            ANS_LOGD("set reason faild. status %{public}d", status);
            return false;
        }
    }

    // sound?: string
    if (request->EnableSound()) {
        std::string sound = request->GetSound().ToString();
        ani_string soundObj;
        if (ANI_OK != GetAniStringByString(env, sound, soundObj) || soundObj == nullptr) {
            ANS_LOGD("sound create faild");
            return false;
        }
        if (ANI_OK != (status = env->Object_SetPropertyByName_Ref(outObj, "sound", soundObj))) {
            ANS_LOGD("set sound faild. status %{public}d", status);
        }
    }

    // vibrationValues?: Array<number>
    if (request->EnableVibrate()) {
        ani_object vibrationValuesObj;
        const std::vector<int64_t> vibrationValues = request->GetVibrationStyle();
        vibrationValuesObj = newArrayClass(env, vibrationValues.size());
        if (vibrationValuesObj == nullptr) {
            ANS_LOGD("CreateArray faild");
            return false;
        }
        for (size_t i = 0; i < vibrationValues.size(); i++) {
            status = env->Object_CallMethodByName_Void(vibrationValuesObj, "$_set", "ID:V", i, static_cast<ani_double>(vibrationValues[i]));
            if (status != ANI_OK) {
                ANS_LOGD("faild. status : %{public}d", status);
                return false;
            }
        }

        if (ANI_OK != (status = env->Object_SetPropertyByName_Ref(outObj, "vibrationValues", vibrationValuesObj))) {
            ANS_LOGD("set vibrationValuesObj faild. status %{public}d", status);
            return false;
        }
    }
    return true;
}

bool WarpSubscribeCallbackDataArray(
    ani_env *env,
    const std::vector<std::shared_ptr<OHOS::Notification::Notification>> &requestList,
    const std::shared_ptr<NotificationSortingMap> &sortingMap,
    int32_t deleteReason,
    ani_object &outObj)
{
    ANS_LOGD("enter");
    ani_status status;
    
    if (env == nullptr) {
        ANS_LOGD("env is nullptr");
        return false;
    }
    outObj = newArrayClass(env, requestList.size());
    if (outObj == nullptr) {
        ANS_LOGD("CreateArray faild");
        return false;
    }
    for (size_t i = 0; i < requestList.size(); i++) {
        ani_object obj;
        if (!WarpSubscribeCallbackData(env, requestList[i], sortingMap, deleteReason, obj)) {
            ANS_LOGD("WarpSubscribeCallbackData faild");
            return false;
        }
        if (ANI_OK != (status = env->Object_CallMethodByName_Void(
            outObj, "$_set", "ILstd/core/Object;:V", i, obj))) {
                ANS_LOGD("set object faild. index %{public}d status %{public}d", i, status);
                return false;
            }
    }
    return true;
}

bool WarpEnabledNotificationCallbackData(ani_env *env, const std::shared_ptr<EnabledNotificationCallbackData> &callbackData, ani_object &outObj)
{
    ANS_LOGD("enter");
    ani_class cls;
    ani_status status;
    const char *className = "Lnotification/notificationSubscriber/EnabledNotificationCallbackDataInner;";
    if (!CreateClassObjByClassName(env, className, cls, outObj)) {
        ANS_LOGD("CreateClassObjByClassName faild");
        return false;
    }
    if (!SetFieldString(env, cls, outObj, "bundle", callbackData->GetBundle())) {
        ANS_LOGD("SetFieldString bundle faild");
        return false;
    }
    if (!CallSetter(env, cls, outObj, "uid", static_cast<ani_double>(callbackData->GetUid()))) {
        ANS_LOGD("uid set faild.");
        return false;
    }
    if (ANI_OK != (status = env->Object_SetPropertyByName_Boolean(
        outObj, "enable", BoolToAniBoolean(callbackData->GetEnable())))) {
            ANS_LOGD("set enable faild. status %{public}d", status);
            return false;
        }
    return true;
}

bool WarpBadgeNumberCallbackData(ani_env *env, const std::shared_ptr<BadgeNumberCallbackData> &badgeData, ani_object &outObj)
{
    ANS_LOGD("enter");
    ani_class cls;
    ani_object instanceKeyObj;
    const char *className = "Lnotification/notificationSubscriber/BadgeNumberCallbackDataInner;";
    if (!CreateClassObjByClassName(env, className, cls, outObj)) {
        ANS_LOGD("CreateClassObjByClassName faild");
        return false;
    }
    if (!SetFieldString(env, cls, outObj, "bundle", badgeData->GetBundle())) {
        ANS_LOGD("SetFieldString bundle faild");
        return false;
    }
    if (!CallSetter(env, cls, outObj, "uid", static_cast<ani_double>(badgeData->GetUid()))) {
        ANS_LOGD("uid set faild.");
        return false;
    }
    if (!CallSetter(env, cls, outObj, "badgeNumber", static_cast<ani_double>(badgeData->GetBadgeNumber()))) {
        ANS_LOGD("badgeNumber set faild");
        return false;
    }
    instanceKeyObj = CreateDouble(env, static_cast<ani_double>(badgeData->GetInstanceKey()));
    if (instanceKeyObj != nullptr) {
        if (!CallSetter(env, cls, outObj, "instanceKey", instanceKeyObj)) {
            ANS_LOGD("instanceKey set faild.");
            return false;
        }
    } else {
        ANS_LOGD("instanceKeyObj createDouble faild");
    }
    if (!SetFieldString(env, cls, outObj, "appInstanceKey", badgeData->GetAppInstanceKey())) {
        ANS_LOGD("SetFieldString appInstanceKey faild");
        return false;
    }
    return true;
}

} // namespace NotificationSts
} // OHOS
