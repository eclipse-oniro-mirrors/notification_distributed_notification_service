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
#include "sts_sorting_map.h"

#include "sts_common.h"
#include "sts_sorting.h"

namespace OHOS {
namespace NotificationSts {
bool GetKeySToRecode(ani_env *env,
    const std::shared_ptr<NotificationSortingMap> &sortingMap, ani_object &recordObj, ani_method &recordSetMethod)
{
    ani_status status = ANI_ERROR;
    std::vector<std::string> keys = sortingMap->GetKey();
    ANS_LOGD("GetKeySToRecode sortingMap size:%{public}d", keys.size());
    for (auto &it : keys) {
        Notification::NotificationSorting sorting;
        if (!sortingMap->GetNotificationSorting(it, sorting)) {
            ANS_LOGE("GetNotificationSorting faild.");
            return false;
        }
        ani_string keyString;
        if (ANI_OK != GetAniStringByString(env, it, keyString)) {
            ANS_LOGE("GetAniStringByString faild. key: %{public}s", it.c_str());
            return false;
        }
        ani_object sortingObj;
        if (!WarpNotificationSorting(env, sorting, sortingObj)) {
            ANS_LOGE("WarpNotificationSorting faild. key: %{public}s", it.c_str());
            return false;
        }
        if (keyString == nullptr) {
            ANS_LOGE("GetAniString faild. key: %{public}s", it.c_str());
            return false;
        }
        if (ANI_OK != (status = env->Object_CallMethod_Void(recordObj, recordSetMethod, keyString, sortingObj))) {
            ANS_LOGE("set key value faild. key: %{public}s status %{public}d", it.c_str(), status);
            return false;
        }
    }
    ANS_LOGD("GetKeySToRecode end");
    return true;
}

bool WarpNotificationSortingMap(ani_env *env,
    const std::shared_ptr<NotificationSortingMap> &sortingMap, ani_object &outObj)
{
    ani_class cls;
    ani_object recordObj;
    ani_class recordCls;
    ani_status status;
    if (sortingMap == nullptr || env == nullptr) {
        ANS_LOGE("invalid parameter value");
        return false;
    }

    if (!CreateClassObjByClassName(env,
        "notification.notificationSortingMap.NotificationSortingMapInner", cls, outObj)) {
        ANS_LOGE("CreateClassObjByClassName faild.");
        return false;
    }

    if (!CreateClassObjByClassName(env, "escompat.Record", recordCls, recordObj) || recordObj == nullptr) {
        ANS_LOGE("Create recordObj faild.");
        return false;
    }
    ani_method recordSetMethod = nullptr;
    if (ANI_OK != (status = env->Class_FindMethod(recordCls, "$_set", nullptr, &recordSetMethod))) {
        ANS_LOGE("Find recordObj setMethod faild.");
        return false;
    }
    if (!GetKeySToRecode(env, sortingMap, recordObj, recordSetMethod, recordSetMethod)) {
        ANS_LOGE("GetKeySToRecode failed.");
        return false;
    }
    if (ANI_OK != (status = env->Object_SetPropertyByName_Ref(outObj, "sortings", recordObj))) {
        ANS_LOGE("Object_SetPropertyByName_Ref sortings faild. status %{public}d", status);
        return false;
    }
    std::vector<std::string> keys = sortingMap->GetKey();
    if (!keys.empty()) {
        ani_object arrayObj = GetAniStringArrayByVectorString(env, keys);
        if (arrayObj == nullptr) {
            ANS_LOGE("WarpVectorStringToSts sortedHashCode faild");
            return false;
        }
        if (ANI_OK != (status = env->Object_SetPropertyByName_Ref(outObj, "sortedHashCode", arrayObj))) {
            ANS_LOGE("Object_SetPropertyByName_Ref sortedHashCode faild. status %{public}d", status);
            return false;
        }
    }
    return true;
}
} // namespace NotificationSts
} // OHOS
