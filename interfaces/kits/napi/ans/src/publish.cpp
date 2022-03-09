/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "publish.h"

namespace OHOS {
namespace NotificationNapi {
static const int32_t PUBLISH_NOTIFICATION_MAX = 3;

struct AsyncCallbackInfoPublish {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    NotificationRequest request;
    CallbackPromiseInfo info;
};

struct ParametersInfoPublish {
    NotificationRequest request;
    napi_ref callback = nullptr;
};

napi_value GetCallback(const napi_env &env, const napi_value &value, ParametersInfoPublish &params)
{
    ANS_LOGI("enter");

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, value, &valuetype));
    if (valuetype != napi_function) {
        ANS_LOGW("Wrong argument type. Function expected.");
        return nullptr;
    }
    napi_create_reference(env, value, 1, &params.callback);
    ANS_LOGI("end");
    return Common::NapiGetNull(env);
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, ParametersInfoPublish &params)
{
    ANS_LOGI("enter");

    size_t argc = PUBLISH_NOTIFICATION_MAX;
    napi_value argv[PUBLISH_NOTIFICATION_MAX] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) {
        ANS_LOGW("Wrong argument type. Function expected.");
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGW("Wrong argument type. Object expected.");
        return nullptr;
    }

    // argv[0] : NotificationRequest
    if (Common::GetNotificationRequest(env, argv[PARAM0], params.request) == nullptr) {
        return nullptr;
    }

    // argv[1] : userId / callback
    if (argc >= PUBLISH_NOTIFICATION_MAX - 1) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if ((valuetype != napi_number) && (valuetype != napi_function)) {
            ANS_LOGW("Wrong argument type. Function or object expected.");
            return nullptr;
        }

        if (valuetype == napi_number) {
            int32_t recvUserId = SUBSCRIBE_USER_INIT;
            NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM1], &recvUserId));
            params.request.SetReceiverUserId(recvUserId);
        } else {
            napi_create_reference(env, argv[PARAM1], 1, &params.callback);
        }
    }

    // argv[2] : callback
    if (argc >= PUBLISH_NOTIFICATION_MAX) {
        if (GetCallback(env, argv[PARAM2], params) == nullptr) {
            return nullptr;
        }
    }

    ANS_LOGI("end");
    return Common::NapiGetNull(env);
}

napi_value Publish(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");

    ParametersInfoPublish params;
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    napi_value promise = nullptr;
    AsyncCallbackInfoPublish *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoPublish {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }

    asynccallbackinfo->request = params.request;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "publish", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("Publish napi_create_async_work start");
            AsyncCallbackInfoPublish *asynccallbackinfo = (AsyncCallbackInfoPublish *)data;
            ANS_LOGI("Publish napi_create_async_work start notificationId = %{public}d, contentType = "
                     "%{public}d",
                asynccallbackinfo->request.GetNotificationId(),
                asynccallbackinfo->request.GetContent()->GetContentType());

            asynccallbackinfo->info.errorCode =
                NotificationHelper::PublishNotification(asynccallbackinfo->request);
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("Publish napi_create_async_work complete start");
            AsyncCallbackInfoPublish *asynccallbackinfo = (AsyncCallbackInfoPublish *)data;
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
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

    NAPI_CALL(env, napi_queue_async_work(env, asynccallbackinfo->asyncWork));

    if (asynccallbackinfo->info.isCallback) {
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value ShowNotification(napi_env env, napi_callback_info info)
{
    ANS_LOGI("ShowNotification enter");
    return Common::NapiGetNull(env);
}
}  // namespace NotificationNapi
}  // namespace OHOS