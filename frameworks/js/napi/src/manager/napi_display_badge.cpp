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

#include "napi_display_badge.h"

#include "ans_inner_errors.h"
#include "display_badge.h"

namespace OHOS {
namespace NotificationNapi {
napi_value NapiDisplayBadge(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");
    EnableBadgeParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoEnableBadge *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnableBadge {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "DisplayBadge", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("DisplayBadge napi_create_async_work start");
            AsyncCallbackInfoEnableBadge *asynccallbackinfo = static_cast<AsyncCallbackInfoEnableBadge *>(data);
            if (asynccallbackinfo) {
                ANS_LOGI("option.bundle = %{public}s option.uid = %{public}d enable = %{public}d",
                    asynccallbackinfo->params.option.GetBundleName().c_str(),
                    asynccallbackinfo->params.option.GetUid(),
                    asynccallbackinfo->params.enable);
                asynccallbackinfo->info.errorCode = NotificationHelper::SetShowBadgeEnabledForBundle(
                    asynccallbackinfo->params.option, asynccallbackinfo->params.enable);
                ANS_LOGI("asynccallbackinfo->info.errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("DisplayBadge napi_create_async_work end");
            AsyncCallbackInfoEnableBadge *asynccallbackinfo = static_cast<AsyncCallbackInfoEnableBadge *>(data);
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

void AsyncCompleteCallbackNapiIsBadgeDisplayed(napi_env env, napi_status status, void *data)
{
    ANS_LOGI("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackInfoIsDisplayBadge *asynccallbackinfo = static_cast<AsyncCallbackInfoIsDisplayBadge *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        napi_get_boolean(env, asynccallbackinfo->enabled, &result);
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiIsBadgeDisplayed(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");
    IsDisplayBadgeParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        ANS_LOGE("Failed to parse params!");
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoIsDisplayBadge *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoIsDisplayBadge {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "IsBadgeDisplayed", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("IsBadgeDisplayed napi_create_async_work start");
            AsyncCallbackInfoIsDisplayBadge *asynccallbackinfo = static_cast<AsyncCallbackInfoIsDisplayBadge *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->params.hasBundleOption) {
                    ANS_LOGI("option.bundle = %{public}s option.uid = %{public}d",
                        asynccallbackinfo->params.option.GetBundleName().c_str(),
                        asynccallbackinfo->params.option.GetUid());
                    asynccallbackinfo->info.errorCode = NotificationHelper::GetShowBadgeEnabledForBundle(
                        asynccallbackinfo->params.option, asynccallbackinfo->enabled);
                } else {
                    asynccallbackinfo->info.errorCode = NotificationHelper::GetShowBadgeEnabled(
                        asynccallbackinfo->enabled);
                }
                ANS_LOGI("asynccallbackinfo->info.errorCode = %{public}d, enabled = %{public}d",
                    asynccallbackinfo->info.errorCode, asynccallbackinfo->enabled);
            }
        },
        AsyncCompleteCallbackNapiIsBadgeDisplayed,
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