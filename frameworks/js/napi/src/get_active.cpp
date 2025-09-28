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

#include "get_active.h"

namespace OHOS {
namespace NotificationNapi {
void AsyncCompleteCallbackGetAllActiveNotifications(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("GetAllActiveNotifications napi_create_async_work end");

    if (!data) {
        ANS_LOGE("Invalidity async callback data.");
        return;
    }

    auto asynccallbackinfo = static_cast<AsyncCallbackInfoActive *>(data);
    if (asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is not nullptr.");
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_value arr = nullptr;
            int32_t count = 0;
            napi_create_array(env, &arr);
            for (auto vec : asynccallbackinfo->notifications) {
                if (!vec) {
                    ANS_LOGW("Invalid Notification object ptr.");
                    continue;
                }
                napi_value notificationResult = nullptr;
                napi_create_object(env, &notificationResult);
                if (!Common::SetNotification(env, vec.GetRefPtr(), notificationResult)) {
                    ANS_LOGW("Set Notification object failed.");
                    continue;
                }
                napi_set_element(env, arr, count, notificationResult);
                count++;
            }
            ANS_LOGD("count = %{public}d", count);
            result = arr;
            if ((count == 0) && (asynccallbackinfo->notifications.size() > 0)) {
                asynccallbackinfo->info.errorCode = ERROR;
                result = Common::NapiGetNull(env);
            }
        }
        Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete getAllActiveNotifications callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value GetAllActiveNotifications(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoActive {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        ANS_LOGD("Create asynccallbackinfo failed.");
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create getAllActiveNotifications string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getAllActiveNotifications", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("GetAllActiveNotifications work excute.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoActive *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::GetAllActiveNotifications(asynccallbackinfo->notifications);
            }
        },
        AsyncCompleteCallbackGetAllActiveNotifications,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("getAllActiveNotifications callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackGetActiveNotifications(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");

    if (!data) {
        ANS_LOGE("Async callback invalidity data.");
        return;
    }

    auto asynccallbackinfo = static_cast<AsyncCallbackInfoActive *>(data);
    if (asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is not null.");
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_value arr = nullptr;
            int32_t count = 0;
            napi_create_array(env, &arr);
            for (auto vec : asynccallbackinfo->requests) {
                if (!vec) {
                    ANS_LOGW("Invalid NotificationRequest object ptr.");
                    continue;
                }
                napi_value requestResult = nullptr;
                napi_create_object(env, &requestResult);
                if (!Common::SetNotificationRequest(env, vec.GetRefPtr(), requestResult)) {
                    ANS_LOGW("Set NotificationRequest object failed.");
                    continue;
                }
                napi_set_element(env, arr, count, requestResult);
                count++;
            }
            ANS_LOGD("count = %{public}d", count);
            result = arr;
            if ((count == 0) && (asynccallbackinfo->requests.size() > 0)) {
                asynccallbackinfo->info.errorCode = ERROR;
                result = Common::NapiGetNull(env);
            }
        }
        Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete asyncGetActiveNotifications callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value GetActiveNotifications(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoActive {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        ANS_LOGD("AsyncCallbackinfo invalid.");
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create getActiveNotifications string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getActiveNotifications", NAPI_AUTO_LENGTH, &resourceName);
    // Async function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("GetActiveNotifications work excute.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoActive *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::GetActiveNotifications(asynccallbackinfo->requests);
            }
        },
        AsyncCompleteCallbackGetActiveNotifications,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("getActiveNotifications callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackGetActiveNotificationCount(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");

    if (!data) {
        ANS_LOGE("Invalidated async callback data.");
        return;
    }

    auto asynccallbackinfo = static_cast<AsyncCallbackInfoActive *>(data);
    if (asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is not nullptr.");
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_create_uint32(env, asynccallbackinfo->num, &result);
        }
        Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete getActiveNotifications callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value GetActiveNotificationCount(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoActive {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        ANS_LOGD("AsyncCallbackinfo is nullptr.");
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create getActiveNotificationCount string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getActiveNotificationCount", NAPI_AUTO_LENGTH, &resourceName);
    // Async function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("GetActiveNotificationCount work excute.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoActive *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::GetActiveNotificationNums(asynccallbackinfo->num);
                ANS_LOGI("Get active notification count,count:%{public}" PRIu64 "", asynccallbackinfo->num);
            }
        },
        AsyncCompleteCallbackGetActiveNotificationCount,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("getActiveNotificationCount callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}
}  // namespace NotificationNapi
}  // namespace OHOS
