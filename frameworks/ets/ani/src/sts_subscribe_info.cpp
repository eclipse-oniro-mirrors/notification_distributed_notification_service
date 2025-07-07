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
#include "sts_subscribe_info.h"

#include "sts_common.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace NotificationSts {
bool UnwarpNotificationSubscribeInfo(ani_env *env, ani_object value, NotificationSubscribeInfo &info)
{
    ANS_LOGD("enter");
    if (env == nullptr || value == nullptr) {
        ANS_LOGE("invalid parameter value");
        return false;
    }
    std::vector<std::string> res = {};
    ani_double userId = 0.0;
    ani_double filterLimit = 0.0;
    std::string deviceType;
    ani_boolean isUndefined = ANI_TRUE;
    if (ANI_OK != GetPropertyStringArray(env, value, "bundleNames", isUndefined, res)
        || isUndefined == ANI_TRUE
        || res.empty()) {
        ANS_LOGE("UnWarpStringArrayOrUndefinedByProperty faild");
    }
    std::vector<std::string> bundleNames = {};
    for (auto bundleName : res) {
        bundleNames.emplace_back(GetResizeStr(bundleName, STR_MAX_SIZE));
    }
    if (ANI_OK != GetPropertyDouble(env, value, "userId", isUndefined, userId) || isUndefined == ANI_TRUE) {
        ANS_LOGE("GetDoubleOrUndefined faild");
    }
    if (ANI_OK != GetPropertyString(env, value, "deviceType", isUndefined, deviceType) || isUndefined == ANI_TRUE) {
        ANS_LOGE("GetStringOrUndefined faild");
    }
    if (ANI_OK != GetPropertyDouble(env, value, "filterLimit", isUndefined, filterLimit) || isUndefined == ANI_TRUE) {
        ANS_LOGE("GetDoubleOrUndefined faild");
    }
    info.AddAppNames(bundleNames);
    info.AddAppUserId(static_cast<int32_t>(userId));
    info.SetFilterType(static_cast<int32_t>(filterLimit));
    info.AddDeviceType(GetResizeStr(deviceType, STR_MAX_SIZE));
    ANS_LOGD("userId %{public}d deviceType %{public}s filterLimit %{public}d",
        info.GetAppUserId(), info.GetDeviceType().c_str(), info.GetFilterType());
    return true;
}

} // namespace NotificationSts
} // OHOS
