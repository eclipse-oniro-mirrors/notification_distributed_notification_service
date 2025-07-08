/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "disable_notification.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace NotificationNapi {
constexpr int8_t DISABLE_MAX_PARA = 3;
constexpr int8_t DISABLE_MIN_PARA = 2;
constexpr int32_t MAX_USER_ID = 10736;

bool ParseDisabledParameters(const napi_env &env, const napi_value &value, bool &disabled)
{
    ANS_LOGD("called");
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valuetype), false);
    if (valuetype != napi_boolean) {
        ANS_LOGE("wrong argument type. Bool expected");
        std::string msg = "Incorrect parameter types.The type of disabled must be boolean.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return false;
    }
    napi_get_value_bool(env, value, &disabled);
    return true;
}

bool ParseBundleListParameters(const napi_env &env, const napi_value &value, std::vector<std::string> &bundleList)
{
    ANS_LOGD("called");
    bool isArray = false;
    napi_is_array(env, value, &isArray);
    if (!isArray) {
        ANS_LOGE("wrong argument type. Array expected");
        std::string msg = "Incorrect parameter types.The type of bundle list must be array.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return false;
    }
    uint32_t length = 0;
    napi_get_array_length(env, value, &length);
    if (length == 0) {
        ANS_LOGE("the bundle list length is zero");
        std::string msg = "Mandatory parameters are left unspecified. The bundle list length is zero.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return false;
    }
    napi_valuetype valuetype = napi_undefined;
    for (size_t index = 0; index < length; index++) {
        napi_value nBundle = nullptr;
        napi_get_element(env, value, index, &nBundle);
        NAPI_CALL_BASE(env, napi_typeof(env, nBundle, &valuetype), false);
        if (valuetype != napi_string) {
            ANS_LOGE("wrong bundle name type");
            std::string msg = "Incorrect parameter types.The type of bundle name must be string.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return false;
        }
        char str[STR_MAX_SIZE] = {0};
        size_t strLen = 0;
        napi_get_value_string_utf8(env, nBundle, str, STR_MAX_SIZE - 1, &strLen);
        if (std::strlen(str) == 0) {
            ANS_LOGE("bundle name length is zero");
            std::string msg = "Mandatory parameters are left unspecified.The bundle name length is zero.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return false;
        }
        bundleList.emplace_back(str);
    }
    return true;
}

bool ParseUserIdParameters(const napi_env &env, const napi_value &value, int32_t &userId)
{
    napi_status status = napi_get_value_int32(env, value, &userId);
    if (status != napi_ok) {
        ANS_LOGE("Failed to parse the third parameter as number");
        std::string msg = "Third argument must be a number";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return false;
    }
    if (userId < 0 || userId > MAX_USER_ID) {
        ANS_LOGE("Invalid userId");
        std::string msg = "UserId must be a non-negative integer and less than " + std::to_string(MAX_USER_ID);
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return false;
    }
    return true;
}

bool ParseDisableNotificationParameters(
    const napi_env &env, const napi_callback_info &info, NotificationDisable &param)
{
    ANS_LOGD("called");
    size_t argc = DISABLE_MAX_PARA;
    napi_value argv[DISABLE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL), false);
    if (argc > DISABLE_MAX_PARA || argc < DISABLE_MIN_PARA) {
        ANS_LOGE("wrong number of arguments");
        std::string msg =
            "Wrong number of arguments. Expected 2 or 3, but get " + std::to_string(argc);
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return false;
    }
    // argv[0]: disabled
    bool disabled = false;
    if (!ParseDisabledParameters(env, argv[PARAM0], disabled)) {
        return false;
    }
    param.SetDisabled(disabled);
    std::vector<std::string> bundleList;
    if (!ParseBundleListParameters(env, argv[PARAM1], bundleList)) {
        return false;
    }
    param.SetBundleList(bundleList);

    if (argc == DISABLE_MAX_PARA) {
        int32_t userId = SUBSCRIBE_USER_INIT;
        if (!ParseUserIdParameters(env, argv[PARAM2], userId)) {
            return false;
        }
        param.SetUserId(userId);
    }
    return true;
}
}
}