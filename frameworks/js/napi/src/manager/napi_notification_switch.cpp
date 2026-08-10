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

#include "napi_notification_switch.h"
#include "ans_service_errors.h"

#include "ans_inner_errors.h"
#include "ans_notification.h"
#include "singleton.h"
#include "js_native_api.h"
#include "js_native_api_types.h"

namespace OHOS {
namespace NotificationNapi {
using OHOS::Notification::AnsNotification;
namespace {
constexpr size_t SET_NOTIFICATION_SWITCH_MIN_PARA = 3;
constexpr size_t SET_NOTIFICATION_SWITCH_MAX_PARA = 3;
constexpr size_t GET_NOTIFICATION_SWITCH_MIN_PARA = 2;
constexpr size_t GET_NOTIFICATION_SWITCH_MAX_PARA = 2;

void CleanupAsyncCallback(napi_env env, AsyncCallbackNotificationClassificationSwitch *&asyncCallbackInfo)
{
    if (asyncCallbackInfo == nullptr) {
        return;
    }

    if (asyncCallbackInfo->info.callback != nullptr) {
        napi_delete_reference(env, asyncCallbackInfo->info.callback);
    }
    if (asyncCallbackInfo->asyncWork != nullptr) {
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    }
    delete asyncCallbackInfo;
    asyncCallbackInfo = nullptr;
}

napi_value HandleAsyncWorkFailure(
    napi_env env, AsyncCallbackNotificationClassificationSwitch *&asyncCallbackInfo, napi_value promise)
{
    if (asyncCallbackInfo == nullptr) {
        return Common::NapiRejectError(env, ERR_ANS_INNER_TASK_ERR);
    }

    asyncCallbackInfo->info.errorCode = ERR_ANS_INNER_TASK_ERR;
    Common::CreateReturnValue(env, asyncCallbackInfo->info, Common::NapiGetNull(env));
    CleanupAsyncCallback(env, asyncCallbackInfo);
    return promise;
}

napi_value ParseSwitchNameParameter(const napi_env &env, napi_value value, std::string &switchName)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, value, &valueType));
    if (valueType != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        std::string msg = "Incorrect parameter types.The type of switchName must be string.";
        Common::NapiThrow(env, ERR_ANS_INNER_INVALID_PARAM, msg);
        return nullptr;
    }

    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    NAPI_CALL(env, napi_get_value_string_utf8(env, value, str, STR_MAX_SIZE - 1, &strLen));
    switchName = str;
    return Common::NapiGetNull(env);
}

napi_value ParseSwitchStateParameter(const napi_env &env, napi_value value, bool &switchState)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, value, &valueType));
    if (valueType != napi_boolean) {
        ANS_LOGE("Wrong argument type. Bool expected.");
        std::string msg = "Incorrect parameter types.The type of switchState must be boolean.";
        Common::NapiThrow(env, ERR_ANS_INNER_INVALID_PARAM, msg);
        return nullptr;
    }

    NAPI_CALL(env, napi_get_value_bool(env, value, &switchState));
    return Common::NapiGetNull(env);
}

napi_value ParseUserIdParameter(const napi_env &env, napi_value value, int32_t &userId)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, value, &valueType));
    if (valueType != napi_number) {
        ANS_LOGE("Wrong argument type. Number expected.");
        std::string msg = "Incorrect parameter types.The type of userId must be number.";
        Common::NapiThrow(env, ERR_ANS_INNER_INVALID_PARAM, msg);
        return nullptr;
    }

    NAPI_CALL(env, napi_get_value_int32(env, value, &userId));
    return Common::NapiGetNull(env);
}

napi_value ParseSetNotificationSwitchParameters(
    const napi_env &env, const napi_callback_info &info, NotificationClassificationSwitchParams &params)
{
    size_t argc = SET_NOTIFICATION_SWITCH_MAX_PARA;
    napi_value argv[SET_NOTIFICATION_SWITCH_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    if (argc < SET_NOTIFICATION_SWITCH_MIN_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERR_ANS_INNER_INVALID_PARAM, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    if (ParseSwitchNameParameter(env, argv[PARAM0], params.switchName) == nullptr ||
        ParseSwitchStateParameter(env, argv[PARAM1], params.switchState) == nullptr ||
        ParseUserIdParameter(env, argv[PARAM2], params.userId) == nullptr) {
        return nullptr;
    }

    return Common::NapiGetNull(env);
}

napi_value ParseGetNotificationSwitchParameters(
    const napi_env &env, const napi_callback_info &info, NotificationClassificationSwitchParams &params)
{
    size_t argc = GET_NOTIFICATION_SWITCH_MAX_PARA;
    napi_value argv[GET_NOTIFICATION_SWITCH_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    if (argc < GET_NOTIFICATION_SWITCH_MIN_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERR_ANS_INNER_INVALID_PARAM, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    if (ParseSwitchNameParameter(env, argv[PARAM0], params.switchName) == nullptr ||
        ParseUserIdParameter(env, argv[PARAM1], params.userId) == nullptr) {
        return nullptr;
    }

    return Common::NapiGetNull(env);
}

void AsyncCompleteCallbackNapiSetNotificationSwitch(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (data == nullptr) {
        ANS_LOGE("Invalid async callback data");
        return;
    }

    auto *asyncCallbackInfo = static_cast<AsyncCallbackNotificationClassificationSwitch *>(data);
    Common::CreateReturnValue(env, asyncCallbackInfo->info, Common::NapiGetNull(env));
    CleanupAsyncCallback(env, asyncCallbackInfo);
}

void AsyncCompleteCallbackNapiGetNotificationSwitch(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (data == nullptr) {
        ANS_LOGE("Invalid async callback data");
        return;
    }

    auto *asyncCallbackInfo = static_cast<AsyncCallbackNotificationClassificationSwitch *>(data);
    napi_value result = nullptr;
    if (asyncCallbackInfo->info.errorCode != ERR_OK) {
        result = Common::NapiGetNull(env);
    } else {
        napi_create_int32(env, static_cast<int32_t>(asyncCallbackInfo->params.enableStatus), &result);
    }
    Common::CreateReturnValue(env, asyncCallbackInfo->info, result);
    CleanupAsyncCallback(env, asyncCallbackInfo);
}
}  // namespace

napi_value NapiSetNotificationSwitch(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    NotificationClassificationSwitchParams params {};
    if (ParseSetNotificationSwitchParameters(env, info, params) == nullptr) {
        return Common::NapiRejectError(env, ERR_ANS_INNER_INVALID_PARAM);
    }

    auto *asyncCallbackInfo = new (std::nothrow) AsyncCallbackNotificationClassificationSwitch {
        .env = env, .asyncWork = nullptr, .params = params
    };
    if (asyncCallbackInfo == nullptr) {
        return Common::NapiRejectError(env, ERR_ANS_INNER_NO_MEMORY);
    }

    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asyncCallbackInfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setNotificationSwitch", NAPI_AUTO_LENGTH, &resourceName);
    napi_status status = napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiSetNotificationSwitch work execute.");
            auto *asyncCallbackInfo = static_cast<AsyncCallbackNotificationClassificationSwitch *>(data);
            if (asyncCallbackInfo != nullptr) {
                asyncCallbackInfo->info.errorCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->SetNotificationSwitch(
                        asyncCallbackInfo->params.switchName, asyncCallbackInfo->params.switchState,
                        asyncCallbackInfo->params.userId);
                ANS_LOGI("SetNotificationSwitch result=%{public}d", asyncCallbackInfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackNapiSetNotificationSwitch,
        static_cast<void *>(asyncCallbackInfo),
        &asyncCallbackInfo->asyncWork);
    if (status != napi_ok) {
        ANS_LOGE("Create setNotificationSwitch async work failed.");
        return HandleAsyncWorkFailure(env, asyncCallbackInfo, promise);
    }

    status = napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated);
    if (status != napi_ok) {
        ANS_LOGE("Queue setNotificationSwitch async work failed.");
        return HandleAsyncWorkFailure(env, asyncCallbackInfo, promise);
    }

    return promise;
}

napi_value NapiGetNotificationSwitch(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    NotificationClassificationSwitchParams params {};
    if (ParseGetNotificationSwitchParameters(env, info, params) == nullptr) {
        return Common::NapiRejectError(env, ERR_ANS_INNER_INVALID_PARAM);
    }

    auto *asyncCallbackInfo = new (std::nothrow) AsyncCallbackNotificationClassificationSwitch {
        .env = env, .asyncWork = nullptr, .params = params
    };
    if (asyncCallbackInfo == nullptr) {
        return Common::NapiRejectError(env, ERR_ANS_INNER_NO_MEMORY);
    }

    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asyncCallbackInfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getNotificationSwitch", NAPI_AUTO_LENGTH, &resourceName);
    napi_status status = napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiGetNotificationSwitch work execute.");
            auto *asyncCallbackInfo = static_cast<AsyncCallbackNotificationClassificationSwitch *>(data);
            if (asyncCallbackInfo != nullptr) {
                asyncCallbackInfo->info.errorCode =
                    DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationSwitch(
                        asyncCallbackInfo->params.switchName, asyncCallbackInfo->params.userId,
                        asyncCallbackInfo->params.enableStatus);
            }
        },
        AsyncCompleteCallbackNapiGetNotificationSwitch,
        static_cast<void *>(asyncCallbackInfo),
        &asyncCallbackInfo->asyncWork);
    if (status != napi_ok) {
        ANS_LOGE("Create getNotificationSwitch async work failed.");
        return HandleAsyncWorkFailure(env, asyncCallbackInfo, promise);
    }

    status = napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_user_initiated);
    if (status != napi_ok) {
        ANS_LOGE("Queue getNotificationSwitch async work failed.");
        return HandleAsyncWorkFailure(env, asyncCallbackInfo, promise);
    }

    return promise;
}
}  // namespace NotificationNapi
}  // namespace OHOS
