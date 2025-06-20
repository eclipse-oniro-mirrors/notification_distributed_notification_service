/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "ans_template.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace NotificationNapi {
const int IS_TEMPLATE_MAX_PARA = 2;

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, TemplateName& params)
{
    ANS_LOGD("called");

    size_t argc = IS_TEMPLATE_MAX_PARA;
    napi_value argv[IS_TEMPLATE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < IS_TEMPLATE_MAX_PARA - 1) {
        ANS_LOGE("Wrong number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    // argv[0]: name: string
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype != napi_string && valuetype != napi_number && valuetype != napi_boolean) {
        ANS_LOGE("Wrong argument type. String number boolean expected.");
        std::string msg = "Incorrect parameter types.The type of param must be string or number or boolean.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    if (valuetype == napi_string) {
        char str[STR_MAX_SIZE] = {0};
        size_t strLen = 0;
        NAPI_CALL(env, napi_get_value_string_utf8(env, argv[0], str, STR_MAX_SIZE - 1, &strLen));
        params.templateName = str;
    } else if (valuetype == napi_number) {
        int64_t number = 0;
        NAPI_CALL(env, napi_get_value_int64(env, argv[0], &number));
        params.templateName = std::to_string(number);
    } else {
        bool result = false;
        NAPI_CALL(env, napi_get_value_bool(env, argv[0], &result));
        params.templateName = std::to_string(result);
    }

    // argv[1]: callback
    if (argc >= IS_TEMPLATE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[1], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value IsSupportTemplate(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    TemplateName params;
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoTemplate *asyncCallbackinfo = new (std::nothrow)
        AsyncCallbackInfoTemplate {.env = env, .asyncWork = nullptr, .params = params};
    if (!asyncCallbackinfo) {
        ANS_LOGD("null asyncCallbackinfo");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asyncCallbackinfo->info, promise);

    ANS_LOGD("Create isSupportTemplate string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "IsSupportTemplate", NAPI_AUTO_LENGTH, &resourceName);
    // Async function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("Excute create async IsSupportTemplate");
            AsyncCallbackInfoTemplate *asyncCallbackinfo = static_cast<AsyncCallbackInfoTemplate *>(data);

            if (asyncCallbackinfo) {
                asyncCallbackinfo->info.errorCode = NotificationHelper::IsSupportTemplate(
                    asyncCallbackinfo->params.templateName, asyncCallbackinfo->params.support);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("Complete create async IsSupportTemplate");
            AsyncCallbackInfoTemplate *asyncCallbackinfo = static_cast<AsyncCallbackInfoTemplate *>(data);
            if (asyncCallbackinfo) {
                napi_value result = nullptr;
                napi_get_boolean(env, asyncCallbackinfo->params.support, &result);
                Common::ReturnCallbackPromise(env, asyncCallbackinfo->info, result);
                if (asyncCallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete isSupportTemplate callback reference.");
                    napi_delete_reference(env, asyncCallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackinfo->asyncWork);
                delete asyncCallbackinfo;
                asyncCallbackinfo = nullptr;
            }
        },
        (void *)asyncCallbackinfo,
        &asyncCallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asyncCallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asyncCallbackinfo->info.isCallback) {
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}
}  // namespace NotificationNapi
}  // namespace OHOS