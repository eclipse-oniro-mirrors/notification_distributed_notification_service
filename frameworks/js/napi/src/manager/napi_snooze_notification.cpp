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

#include "napi_snooze_notification.h"

#include "ans_service_errors.h"
#include "ans_inner_errors.h"
#include "ans_notification.h"
#include "singleton.h"
#include "js_native_api.h"
#include "js_native_api_types.h"

namespace OHOS {
namespace NotificationNapi {
using OHOS::Notification::AnsNotification;
const int GET_SNOOZE_MAX_PARA = 2;
const int MAX_DELAY_TIME_S = 24 * 3600;

static napi_value ParseSnoozeParameters(const napi_env &env, const napi_callback_info &info,
    std::string &hashCode, int64_t &delayTime)
{
    ANS_LOGD("ParseParameters bundles");
    size_t argc = GET_SNOOZE_MAX_PARA;
    napi_value argv[GET_SNOOZE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc != GET_SNOOZE_MAX_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERR_ANS_INNER_INVALID_PARAM, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    // argv[0]: hashCode: string
    NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Parameter type error. string expected.");
        std::string msg = "Incorrect parameter types.The type of param must be string.";
        Common::NapiThrow(env, ERR_ANS_INNER_INVALID_PARAM, msg);
        return nullptr;
    }
    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    NAPI_CALL(env, napi_get_value_string_utf8(env, argv[0], str, STR_MAX_SIZE - 1, &strLen));
    hashCode = str;
    if (hashCode.empty()) {
        ANS_LOGE("hashCode is invalid.");
        Common::NapiThrow(env, ERR_ANS_INNER_INVALID_PARAM);
        return nullptr;
    }

    // argv[0]: delayTime: long
    NAPI_CALL(env, napi_typeof(env, argv[1], &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of delayTime must be number.";
        Common::NapiThrow(env, ERR_ANS_INNER_INVALID_PARAM, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_int64(env, argv[1], &delayTime));
    if (delayTime <= 0 || delayTime > MAX_DELAY_TIME_S) {
        ANS_LOGE("delayTime is invalid.");
        Common::NapiThrow(env, ERR_ANS_INNER_INVALID_PARAM);
        return nullptr;
    }
    return Common::NapiGetNull(env);
}

void AsyncCompleteNapiSnoozeNotification(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("AsyncCompleteCallbackNapiSnoozeNotification");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    napi_value result = Common::NapiGetNull(env);
    AsyncCallbackInfoSnooze *asynccallbackinfo = static_cast<AsyncCallbackInfoSnooze*>(data);
    if (asynccallbackinfo == nullptr) {
        ANS_LOGE("null asynccallbackinfo");
        return;
    }
    Common::CreateReturnValue(env, asynccallbackinfo->info, result);
    napi_delete_async_work(env, asynccallbackinfo->asyncWork);
    delete asynccallbackinfo;
    asynccallbackinfo = nullptr;
    return;
}

napi_value NapiSnoozeNotification(napi_env env, napi_callback_info info)
{
    ANS_LOGD("NapiGetNotificationStatisticsByBundle");
    std::string hashCode = "";
    int64_t delayTime = 0;
    if (ParseSnoozeParameters(env, info, hashCode, delayTime) == nullptr) {
        Common::NapiThrow(env, ERR_ANS_INNER_INVALID_PARAM);
        return Common::NapiRejectError(env, ERR_ANS_INNER_INVALID_PARAM);
    }
    AsyncCallbackInfoSnooze *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoSnooze {
            .env = env, .asyncWork = nullptr, .hashCode = hashCode, .delayTime = delayTime,
        };
    if (!asynccallbackinfo) {
        return Common::NapiRejectError(env, ERR_ANS_INNER_TASK_ERR);
    }

    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "NapiSnoozeNotification", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("Napi set snooze delay time work excute.");
            AsyncCallbackInfoSnooze *asynccallbackinfo =
                static_cast<AsyncCallbackInfoSnooze *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->SnoozeNotification(
                        asynccallbackinfo->hashCode, asynccallbackinfo->delayTime);
            }
        },
        AsyncCompleteNapiSnoozeNotification,
        static_cast<void*>(asynccallbackinfo),
        &asynccallbackinfo->asyncWork);
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}
}
}
