/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "napi_get_notification_parameters.h"

#include "ans_inner_errors.h"
#include "notification_helper.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include <memory>

namespace OHOS {
namespace NotificationNapi {
namespace {
constexpr int32_t GET_NOTIFICATION_PARAMS_MAX_PARAM = 2;
constexpr int32_t GET_NOTIFICATION_PARAMS_MIN_PARAM = 1;

void AsyncCompleteCallbackNapiGetNotificationParameters(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }

    auto asynccallbackinfo = static_cast<AsyncCallbackInfoNotificationParameters *>(data);
    if (asynccallbackinfo == nullptr) {
        return;
    }

    napi_value result = Common::NapiGetNull(env);
    if (asynccallbackinfo->info.errorCode == ERR_OK && asynccallbackinfo->parameters) {
        napi_create_object(env, &result);
        // Set C++ to JS
        Common::SetNotificationParameters(env, asynccallbackinfo->parameters, result);
    }
    Common::CreateReturnValue(env, asynccallbackinfo->info, result);
    napi_delete_async_work(env, asynccallbackinfo->asyncWork);
    delete asynccallbackinfo;
    asynccallbackinfo = nullptr;
}

napi_value ParseParameters(napi_env env, napi_callback_info info, int32_t &notificationId, std::string &label)
{
    ANS_LOGD("called");
    size_t argc = GET_NOTIFICATION_PARAMS_MAX_PARAM;
    napi_value argv[GET_NOTIFICATION_PARAMS_MAX_PARAM] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));

    if (argc < GET_NOTIFICATION_PARAMS_MIN_PARAM) {
        ANS_LOGE("Wrong number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype == napi_number) {
        NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM0], &notificationId));
    } else {
        ANS_LOGE("Wrong argument type. Notification id should be number");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
        return nullptr;
    }

    if (argc == GET_NOTIFICATION_PARAMS_MAX_PARAM) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype == napi_string) {
            char str[STR_MAX_SIZE] = {0};
            size_t strLen = 0;
            NAPI_CALL(env, napi_get_value_string_utf8(env, argv[PARAM1], str, STR_MAX_SIZE - 1, &strLen));
            label = str;
        }
    }
    return Common::NapiGetNull(env);
}
}

napi_value NapiGetNotificationParameters(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    int32_t notificationId = 0;
    std::string label = "";
    if (ParseParameters(env, info, notificationId, label) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoNotificationParameters {
        .env = env, .asyncWork = nullptr, .notificationId = notificationId, .label = label};
    if (!asynccallbackinfo) {
        ANS_LOGE("Failed to create AsyncCallbackInfoNotificationParameters");
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }

    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getNotificationParameters", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiGetNotificationParameters work execute.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoNotificationParameters *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetNotificationParameters(
                    asynccallbackinfo->notificationId,
                    asynccallbackinfo->label,
                    asynccallbackinfo->parameters);
            }
        },
        AsyncCompleteCallbackNapiGetNotificationParameters,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    return promise;
}

}  // namespace NotificationNapi
}  // namespace OHOS