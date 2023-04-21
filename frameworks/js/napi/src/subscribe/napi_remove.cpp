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
#include "napi_remove.h"

#include "ans_inner_errors.h"
#include <optional>
#include "remove.h"

namespace OHOS {
namespace NotificationNapi {
void NapiRemoveExecuteCallback(napi_env env, void *data)
{
    ANS_LOGI("Remove napi_create_async_work start");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    auto removeInfo = static_cast<AsyncCallbackInfoRemove *>(data);
    if (removeInfo) {
        if (removeInfo->params.hashcode.has_value()) {
            removeInfo->info.errorCode = NotificationHelper::RemoveNotification(removeInfo->params.hashcode.value(),
                removeInfo->params.removeReason);
        } else if (removeInfo->params.bundleAndKeyInfo.has_value()) {
            auto &infos = removeInfo->params.bundleAndKeyInfo.value();
            removeInfo->info.errorCode = NotificationHelper::RemoveNotification(infos.option,
                infos.key.id, infos.key.label, removeInfo->params.removeReason);
        }
    }
}

void NapiRemoveCompleteCallback(napi_env env, napi_status status, void *data)
{
    ANS_LOGI("Remove napi_create_async_work end");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    auto removeInfo = static_cast<AsyncCallbackInfoRemove *>(data);
    if (removeInfo) {
        Common::CreateReturnValue(env, removeInfo->info, Common::NapiGetNull(env));
        if (removeInfo->info.callback != nullptr) {
            napi_delete_reference(env, removeInfo->info.callback);
        }
        napi_delete_async_work(env, removeInfo->asyncWork);
        delete removeInfo;
        removeInfo = nullptr;
    }
}

napi_value NapiRemove(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");
    RemoveParams params {};
    if (!ParseParameters(env, info, params)) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }
    auto removeInfo = new (std::nothrow) AsyncCallbackInfoRemove {.env = env, .asyncWork = nullptr, .params = params};
    if (!removeInfo) {
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, removeInfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "remove", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env, nullptr, resourceName, NapiRemoveExecuteCallback, NapiRemoveCompleteCallback,
        (void *)removeInfo, &removeInfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, removeInfo->asyncWork));
    if (removeInfo->info.isCallback) {
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiRemoveAll(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");
    RemoveParams params {};
    if (ParseParametersByRemoveAll(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoRemove *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoRemove {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "removeAll", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("RemoveAll napi_create_async_work start");
            AsyncCallbackInfoRemove *asynccallbackinfo = static_cast<AsyncCallbackInfoRemove *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->params.bundleAndKeyInfo.has_value()) {
                    auto &infos = asynccallbackinfo->params.bundleAndKeyInfo.value();
                    asynccallbackinfo->info.errorCode = NotificationHelper::RemoveAllNotifications(infos.option);
                } else if (asynccallbackinfo->params.hasUserId) {
                    asynccallbackinfo->info.errorCode = NotificationHelper::RemoveNotifications(
                        asynccallbackinfo->params.userId);
                } else {
                    asynccallbackinfo->info.errorCode = NotificationHelper::RemoveNotifications();
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("RemoveAll napi_create_async_work end");
            AsyncCallbackInfoRemove *asynccallbackinfo = static_cast<AsyncCallbackInfoRemove *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
        },
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