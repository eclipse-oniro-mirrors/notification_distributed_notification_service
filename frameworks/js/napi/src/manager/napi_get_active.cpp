/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "napi_get_active.h"

#include "ans_inner_errors.h"
#include "get_active.h"

namespace OHOS {
namespace NotificationNapi {
void AsyncCompleteCallbackNapiGetAllActiveNotifications(napi_env env, napi_status status, void *data)
{
    ANS_LOGI("GetAllActiveNotifications callback");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }

    auto asynccallbackinfo = static_cast<AsyncCallbackInfoActive *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_value arr = nullptr;
            int32_t count = 0;
            napi_create_array(env, &arr);
            for (auto vec : asynccallbackinfo->notifications) {
                if (!vec) {
                    ANS_LOGW("Invalid Notification object ptr");
                    continue;
                }
                napi_value notificationResult = nullptr;
                napi_create_object(env, &notificationResult);
                if (!Common::SetNotification(env, vec.GetRefPtr(), notificationResult)) {
                    ANS_LOGW("Set Notification object failed");
                    continue;
                }
                napi_set_element(env, arr, count, notificationResult);
                count++;
            }
            ANS_LOGI("GetAllActiveNotifications count = %{public}d", count);
            result = arr;
            if ((count == 0) && (asynccallbackinfo->notifications.size() > 0)) {
                asynccallbackinfo->info.errorCode = ERROR;
                result = Common::NapiGetNull(env);
            }
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiGetAllActiveNotifications(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");
    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoActive {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getAllActiveNotifications", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("GetAllActiveNotifications napi_create_async_work start");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoActive *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::GetAllActiveNotifications(asynccallbackinfo->notifications);
            }
        },
        AsyncCompleteCallbackNapiGetAllActiveNotifications,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_status status = napi_queue_async_work(env, asynccallbackinfo->asyncWork);
    if (status != napi_ok) {
        ANS_LOGE("napi_queue_async_work failed return: %{public}d", status);
        asynccallbackinfo->info.errorCode = ERROR_INTERNAL_ERROR;
        Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }

    if (isCallback) {
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackNapiGetActiveNotifications(napi_env env, napi_status status, void *data)
{
    ANS_LOGI("GetActiveNotifications callback");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }

    auto asynccallbackinfo = static_cast<AsyncCallbackInfoActive *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_value arr = nullptr;
            int32_t count = 0;
            napi_create_array(env, &arr);
            for (auto vec : asynccallbackinfo->requests) {
                if (!vec) {
                    ANS_LOGW("Invalid NotificationRequest object ptr");
                    continue;
                }
                napi_value requestResult = nullptr;
                napi_create_object(env, &requestResult);
                if (!Common::SetNotificationRequest(env, vec.GetRefPtr(), requestResult)) {
                    ANS_LOGW("Set NotificationRequest object failed");
                    continue;
                }
                napi_set_element(env, arr, count, requestResult);
                count++;
            }
            ANS_LOGI("GetActiveNotifications count = %{public}d", count);
            result = arr;
            if ((count == 0) && (asynccallbackinfo->requests.size() > 0)) {
                asynccallbackinfo->info.errorCode = ERROR;
                result = Common::NapiGetNull(env);
            }
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiGetActiveNotifications(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");
    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoActive {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getActiveNotifications", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("GetActiveNotifications napi_create_async_work start");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoActive *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::GetActiveNotifications(asynccallbackinfo->requests);
            }
        },
        AsyncCompleteCallbackNapiGetActiveNotifications,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_status status = napi_queue_async_work(env, asynccallbackinfo->asyncWork);
    if (status != napi_ok) {
        ANS_LOGE("napi_queue_async_work failed return: %{public}d", status);
        asynccallbackinfo->info.errorCode = ERROR_INTERNAL_ERROR;
        Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }

    if (isCallback) {
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackNapiGetActiveNotificationCount(napi_env env, napi_status status, void *data)
{
    ANS_LOGI("GetActiveNotificationCount callback");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }

    auto asynccallbackinfo = static_cast<AsyncCallbackInfoActive *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_create_uint32(env, asynccallbackinfo->num, &result);
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiGetActiveNotificationCount(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");
    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoActive {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getActiveNotificationCount", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("GetActiveNotificationCount napi_create_async_work start");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoActive *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetActiveNotificationNums(
                    asynccallbackinfo->num);
                ANS_LOGI("GetActiveNotificationCount count = %{public}" PRIu64 "", asynccallbackinfo->num);
            }
        },
        AsyncCompleteCallbackNapiGetActiveNotificationCount,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_status status = napi_queue_async_work(env, asynccallbackinfo->asyncWork);
    if (status != napi_ok) {
        ANS_LOGE("napi_queue_async_work failed return: %{public}d", status);
        asynccallbackinfo->info.errorCode = ERROR_INTERNAL_ERROR;
        Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }

    if (isCallback) {
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}
}  // namespace NotificationNapi
}  // namespace OHOS