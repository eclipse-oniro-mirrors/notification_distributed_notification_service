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

#include "napi_publish.h"

#include "ans_inner_errors.h"
#include "publish.h"

namespace OHOS {
namespace NotificationNapi {

napi_value NapiPublish(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    ParametersInfoPublish params;
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    napi_value promise = nullptr;
    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoPublish {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        ANS_LOGD("asynccallbackinfo is nullptr.");
        return Common::JSParaError(env, params.callback);
    }
    asynccallbackinfo->request = params.request;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create NapiPublish string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "publish", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("NapiPublish work excute.");
            AsyncCallbackInfoPublish *asynccallbackinfo = static_cast<AsyncCallbackInfoPublish *>(data);
            if (asynccallbackinfo) {
                ANS_LOGI("notificationId : %{public}d, contentType : "
                        "%{public}d",
                    asynccallbackinfo->request.GetNotificationId(),
                    asynccallbackinfo->request.GetContent()->GetContentType());

                asynccallbackinfo->info.errorCode =
                    NotificationHelper::PublishNotification(asynccallbackinfo->request);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("NapiPublish work complete.");
            AsyncCallbackInfoPublish *asynccallbackinfo = static_cast<AsyncCallbackInfoPublish *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiPublish callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGI("Publish napi_create_async_work complete end");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiPublish callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiShowNotification(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    ParametersInfoPublish params;
    if (ParseShowOptions(env, info, params) == nullptr) {
        ANS_LOGW("parse showOptions failed");
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoPublish {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        ANS_LOGW("failed to create asynccallbackinfo");
        return Common::JSParaError(env, params.callback);
    }
    asynccallbackinfo->request = params.request;

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "show", NAPI_AUTO_LENGTH, &resourceName);

    ANS_LOGI("before napi_create_async_work");
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            AsyncCallbackInfoPublish *asynccallbackinfo = static_cast<AsyncCallbackInfoPublish *>(data);
            if (asynccallbackinfo) {
                ANS_LOGI("NapiShowNotification work excute notificationId = %{public}d, contentType = "
                        "%{public}d",
                    asynccallbackinfo->request.GetNotificationId(),
                    asynccallbackinfo->request.GetContent()->GetContentType());

                asynccallbackinfo->info.errorCode =
                    NotificationHelper::PublishNotification(asynccallbackinfo->request);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("NapiShowNotification word complete.");
            AsyncCallbackInfoPublish *asynccallbackinfo = static_cast<AsyncCallbackInfoPublish *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->info.callback != nullptr) {
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGI("napi_create_async_work complete end");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    return nullptr;
}

napi_value NapiPublishAsBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    ParametersInfoPublish params;
    if (ParsePublishAsBundleParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    napi_value promise = nullptr;
    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoPublish {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }

    asynccallbackinfo->request = params.request;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "publishasbundle", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("NapiPublishAsBundle work excute.");
            AsyncCallbackInfoPublish *asynccallbackinfo = static_cast<AsyncCallbackInfoPublish *>(data);
            if (asynccallbackinfo) {
                ANS_LOGI("notificationId = %{public}d, contentType = "
                        "%{public}d",
                    asynccallbackinfo->request.GetNotificationId(),
                    asynccallbackinfo->request.GetContent()->GetContentType());

                asynccallbackinfo->info.errorCode =
                    NotificationHelper::PublishNotification(asynccallbackinfo->request);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("NapiPublishAsBundle work complete.");
            AsyncCallbackInfoPublish *asynccallbackinfo = static_cast<AsyncCallbackInfoPublish *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiPublishAsBundle callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGI("PublishAsBundle napi_create_async_work complete end");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiPublishAsBundle callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}
}  // namespace NotificationNapi
}  // namespace OHOS