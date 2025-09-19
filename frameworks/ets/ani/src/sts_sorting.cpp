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
#include "sts_sorting.h"

#include "ans_log_wrapper.h"
#include "sts_common.h"
#include "sts_slot.h"

namespace OHOS {
namespace NotificationSts {
bool WarpNotificationSorting(ani_env *env, Notification::NotificationSorting &sorting, ani_object &outObj)
{
    ani_class cls;
    ani_object obj;
    ani_object slotObj;
    ani_status status;
    ani_string hashCodeObj;
    std::string hashCode;
    if (env == nullptr) {
        ANS_LOGE("env is null");
        return false;
    }
    if (!CreateClassObjByClassName(env, "notification.notificationSorting.NotificationSortingInner", cls, obj)) {
        ANS_LOGE("Create NotificationSortingInner ClassObj faild");
        return false;
    }
    // readonly slot: NotificationSlot
    if (!WrapNotificationSlot(env, sorting.GetSlot(), slotObj)) {
        ANS_LOGE("WrapNotificationSlot faild");
        return false;
    }
    if (ANI_OK != (status = env->Object_SetPropertyByName_Ref(obj, "slot", slotObj))) {
        ANS_LOGE("set slot faild. status %{public}d", status);
        return false;
    }
    hashCode = sorting.GetGroupKeyOverride();
    if (ANI_OK != GetAniStringByString(env, hashCode, hashCodeObj) || hashCodeObj == nullptr) {
        ANS_LOGE("GetAniStringByString hashCode faild");
        return false;
    }
    // readonly hashCode: string;
    if (ANI_OK != (status = env->Object_SetPropertyByName_Ref(obj, "hashCode", hashCodeObj))) {
        ANS_LOGE("set hashCode faild. status %{public}d", status);
        return false;
    }
    // readonly ranking: long;
    if (ANI_OK != (status = env->Object_SetPropertyByName_Long(
        obj, "ranking", static_cast<ani_long>(sorting.GetRanking())))) {
        ANS_LOGE("set ranking faild. status %{public}d", status);
        return false;
    }
    outObj = obj;
    return true;
}
} // namespace NotificationSts
} // OHOS
