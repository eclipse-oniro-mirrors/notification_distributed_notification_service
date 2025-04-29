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

#include "napi_disable_notification.h"

#include "ans_inner_errors.h"
#include "disable_notification.h"

namespace OHOS {
namespace NotificationNapi {
napi_value NapiDisableNotificationFeature(napi_env env, napi_callback_info info)
{
#ifdef DISABLE_NOTIFICATION_FEATURE_ENABLE
    ANS_LOGD("enter NapiDisableNotificationFeature");
    NotificationDisable paras;
    if (!ParseDisableNotificationParameters(env, info, paras)) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoDisableNotification *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoDisableNotification {
        .env = env, .asyncWork = nullptr, .disableNotification = paras
    };
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "disableNotificationFeature", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr, resourceName, [](napi_env env, void *data) {
            ANS_LOGD("Napi disable notification Feature work excute.");
            AsyncCallbackInfoDisableNotification *asynccallbackinfo =
                static_cast<AsyncCallbackInfoDisableNotification *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::DisableNotificationFeature(asynccallbackinfo->disableNotification);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("Napi disable notification Feature work complete.");
            AsyncCallbackInfoDisableNotification *asynccallbackinfo =
                static_cast<AsyncCallbackInfoDisableNotification *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
#else
    Common::NapiThrow(env, ERROR_SYSTEM_CAP_ERROR);
    return Common::NapiGetUndefined(env);
#endif
}
}
}