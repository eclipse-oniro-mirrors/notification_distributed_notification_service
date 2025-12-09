/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#include "js_native_api_types.h"
#include "napi_common.h"
#include "napi_common_util.h"

namespace OHOS {
namespace NotificationNapi {

napi_value Common::GetNotificationFlagsStatus(const napi_env &env, const napi_value &value, const char* name,
    NotificationConstant::FlagStatus &flag)
{
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, value, name, &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, name, &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of FlagStatus must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        int32_t tempFlag = 0;
        NAPI_CALL(env, napi_get_value_int32(env, result, &tempFlag));
        if (tempFlag < 0 || tempFlag > FLAG_STATUS_MAX_TYPE) {
            ANS_LOGE("Wrong argument type. The number is out of range.");
            std::string msg = "Incorrect parameter types. The FlagStatus value can only be 0, 1, or 2.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        flag = NotificationConstant::FlagStatus(tempFlag);
    }
    return NapiGetNull(env);
}

napi_value Common::GetNotificationFlagsInfo(const napi_env &env, const napi_value &value,
    std::shared_ptr<NotificationFlags> &result)
{
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, value, "soundEnabled", &hasProperty));
    if (hasProperty) {
        NotificationConstant::FlagStatus soundEnabled = NotificationConstant::FlagStatus::NONE;
        GetNotificationFlagsStatus(env, value, "soundEnabled", soundEnabled);
        if (soundEnabled == NotificationConstant::FlagStatus::CLOSE) {
            result->SetSoundEnabled(soundEnabled);
        }
    }
    NAPI_CALL(env, napi_has_named_property(env, value, "vibrationEnabled", &hasProperty));
    if (hasProperty) {
        NotificationConstant::FlagStatus vibrationEnabled = NotificationConstant::FlagStatus::NONE;
        GetNotificationFlagsStatus(env, value, "vibrationEnabled", vibrationEnabled);
        if (vibrationEnabled == NotificationConstant::FlagStatus::CLOSE) {
            result->SetVibrationEnabled(vibrationEnabled);
        }
    }
    NAPI_CALL(env, napi_has_named_property(env, value, "bannerEnabled", &hasProperty));
    if (hasProperty) {
        NotificationConstant::FlagStatus bannerEnabled = NotificationConstant::FlagStatus::NONE;
        GetNotificationFlagsStatus(env, value, "bannerEnabled", bannerEnabled);
        if (bannerEnabled == NotificationConstant::FlagStatus::CLOSE) {
            result->SetBannerEnabled(bannerEnabled);
        }
    }
    NAPI_CALL(env, napi_has_named_property(env, value, "lockScreenEnabled", &hasProperty));
    if (hasProperty) {
        NotificationConstant::FlagStatus lockScreenEnabled = NotificationConstant::FlagStatus::NONE;
        GetNotificationFlagsStatus(env, value, "lockScreenEnabled", lockScreenEnabled);
        if (lockScreenEnabled == NotificationConstant::FlagStatus::CLOSE) {
            result->SetLockScreenEnabled(lockScreenEnabled);
        }
    }
    return NapiGetNull(env);
}

napi_value Common::GetNotificationFlags(const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "notificationFlags", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "notificationFlags", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types. The type of notificationFlags must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }

        std::shared_ptr<NotificationFlags> flags = std::make_shared<NotificationFlags>();
        if (flags == nullptr) {
            ANS_LOGE("flags is null");
            return nullptr;
        }

        if (GetNotificationFlagsInfo(env, result, flags) == nullptr) {
            return nullptr;
        }
        request.SetFlags(flags);
    }

    return NapiGetNull(env);
}
}  // namespace NotificationNapi
}  // namespace OHOS