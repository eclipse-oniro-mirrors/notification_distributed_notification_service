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

#include "napi_template.h"

#include "ans_inner_errors.h"
#include "ans_template.h"

namespace OHOS {
namespace NotificationNapi {
napi_value NapiIsSupportTemplate(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    TemplateName params;
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoTemplate *asyncCallbackinfo = new (std::nothrow)
        AsyncCallbackInfoTemplate {.env = env, .asyncWork = nullptr, .params = params};
    if (!asyncCallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asyncCallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "IsSupportTemplate", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiIsSupportTemplate work excute.");
            AsyncCallbackInfoTemplate *asyncCallbackinfo = static_cast<AsyncCallbackInfoTemplate *>(data);

            if (asyncCallbackinfo) {
                asyncCallbackinfo->info.errorCode = NotificationHelper::IsSupportTemplate(
                    asyncCallbackinfo->params.templateName, asyncCallbackinfo->params.support);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiIsSupportTemplate work complete.");
            AsyncCallbackInfoTemplate *asyncCallbackinfo = static_cast<AsyncCallbackInfoTemplate *>(data);
            if (asyncCallbackinfo) {
                napi_value result = nullptr;
                napi_get_boolean(env, asyncCallbackinfo->params.support, &result);
                Common::CreateReturnValue(env, asyncCallbackinfo->info, result);
                if (asyncCallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("null callback");
                    napi_delete_reference(env, asyncCallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asyncCallbackinfo->asyncWork);
                delete asyncCallbackinfo;
                asyncCallbackinfo = nullptr;
            }
        },
        (void *)asyncCallbackinfo,
        &asyncCallbackinfo->asyncWork);

    bool isCallback = asyncCallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asyncCallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}
}  // namespace NotificationNapi
}  // namespace OHOS
