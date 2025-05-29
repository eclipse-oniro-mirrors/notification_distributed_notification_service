/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "napi_sync_config.h"
#include "common.h"
#include "napi_common_util.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace NotificationNapi {
namespace {
    constexpr int8_t SETADDITION_CONFIG_NUM = 2;
    constexpr char KEY_NAME[] = "AGGREGATE_CONFIG";
    constexpr char RING_LIST_KEY_NAME[] = "RING_TRUSTLIST_PKG";
    constexpr char CTRL_LIST_KEY_NAME[] = "NOTIFICATION_CTL_LIST_PKG";
    constexpr char CAMPAIGN_NOTIFICATION_SWITCH_LIST_PKG[] = "CAMPAIGN_NOTIFICATION_SWITCH_LIST_PKG";
}

struct ConfigParams {
    std::string key = "";
    std::string value = "";
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoConfig {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    ConfigParams params;
    CallbackPromiseInfo info;
};

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, ConfigParams &params)
{
    ANS_LOGD("enter");

    size_t argc = SETADDITION_CONFIG_NUM;
    napi_value argv[SETADDITION_CONFIG_NUM] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < SETADDITION_CONFIG_NUM) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    // argv[0]: key: string
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Argument type error. String expected.");
        std::string msg = "Incorrect parameter types.The type of param must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    char keyStr[STR_MAX_SIZE] = {0};
    size_t keyStrLen = 0;
    NAPI_CALL(env, napi_get_value_string_utf8(env, argv[PARAM0], keyStr, STR_MAX_SIZE - 1, &keyStrLen));
    params.key = keyStr;
    if (std::strlen(keyStr) == 0 ||
        (strcmp(keyStr, KEY_NAME) != 0 && strcmp(keyStr, RING_LIST_KEY_NAME) != 0
            && strcmp(keyStr, CTRL_LIST_KEY_NAME) != 0 && strcmp(keyStr, CAMPAIGN_NOTIFICATION_SWITCH_LIST_PKG) != 0)) {
        ANS_LOGE("Argument type error. String expected.");
        std::string msg = "Incorrect parameter types.The type of param must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    // argv[1]: value: string
    NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Argument type error. String expected.");
        std::string msg = "Incorrect parameter types.The type of param must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    char valueStr[LONG_LONG_STR_MAX_SIZE] = {0};
    size_t valStrLen = 0;
    NAPI_CALL(env, napi_get_value_string_utf8(env, argv[PARAM1], valueStr, LONG_LONG_STR_MAX_SIZE - 1, &valStrLen));
    params.value = valueStr;

    return Common::NapiGetNull(env);
}

void AsyncSetConfigComplete(napi_env env, napi_status status, void *data)
{
    ANS_LOGI("NapiSetAdditionConfig work complete.");
    AsyncCallbackInfoConfig *asynccallbackinfo = static_cast<AsyncCallbackInfoConfig *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        napi_create_int32(env, asynccallbackinfo->info.errorCode, &result);
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete NapiSetAdditionConfig callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
    ANS_LOGD("NapiSetAdditionConfig work complete end.");
}
napi_value NapiSetAdditionConfig(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    ConfigParams paras {};
    if (ParseParameters(env, info, paras) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoConfig *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoConfig {
        .env = env,
        .asyncWork = nullptr,
        .params = paras
    };
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, paras.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, paras.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setAdditionConfig", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("NapiSetAdditionConfig work excute.");
            AsyncCallbackInfoConfig *asynccallbackinfo = static_cast<AsyncCallbackInfoConfig *>(data);
            if (asynccallbackinfo) {
                    asynccallbackinfo->info.errorCode = NotificationHelper::SetAdditionConfig(
                        asynccallbackinfo->params.key, asynccallbackinfo->params.value);
            }
        }, AsyncSetConfigComplete, (void *)asynccallbackinfo, &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("NapiSetAdditionConfig callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}
}  // namespace NotificationNapi
}  // namespace OHOS
