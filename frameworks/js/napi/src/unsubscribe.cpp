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

#include "unsubscribe.h"

#include "ans_inner_errors.h"

namespace OHOS {
namespace NotificationNapi {
const int UNSUBSCRIBE_MAX_PARA = 2;

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, ParametersInfoUnsubscribe &paras)
{
    ANS_LOGD("called");

    size_t argc = UNSUBSCRIBE_MAX_PARA;
    napi_value argv[UNSUBSCRIBE_MAX_PARA] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) {
        ANS_LOGE("Wrong number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    // argv[0]:subscriber
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    SubscriberInstancesInfo subscriberInstancesInfo;
    if (!HasNotificationSubscriber(env, argv[PARAM0], subscriberInstancesInfo)) {
        ANS_LOGW("Subscriber not found");
    }
    paras.objectInfo = subscriberInstancesInfo.subscriber;

    // argv[1]:callback
    if (argc >= UNSUBSCRIBE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &paras.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value Unsubscribe(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    ParametersInfoUnsubscribe paras;
    if (ParseParameters(env, info, paras) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoUnsubscribe *asynccallbackinfo = new (std::nothrow)
        AsyncCallbackInfoUnsubscribe {.env = env, .asyncWork = nullptr, .objectInfo = paras.objectInfo};
    if (!asynccallbackinfo) {
        ANS_LOGD("null asynccallbackinfo");
        return Common::JSParaError(env, paras.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, paras.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create unsubscribe string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "unsubscribe", NAPI_AUTO_LENGTH, &resourceName);

    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("Unsubscribe work excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoUnsubscribe *>(data);

            if (asynccallbackinfo->objectInfo == nullptr) {
                ANS_LOGE("invalidated object info");
                asynccallbackinfo->info.errorCode = ERR_ANS_INVALID_PARAM;
                return;
            }

            bool ret = AddDeletingSubscriber(asynccallbackinfo->objectInfo);
            if (ret) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::UnSubscribeNotification(asynccallbackinfo->objectInfo);
                if (asynccallbackinfo->info.errorCode != ERR_OK) {
                    ANS_LOGD("errorCode is not ERR_OK.");
                    DelDeletingSubscriber(asynccallbackinfo->objectInfo);
                }
            } else {
                asynccallbackinfo->info.errorCode = ERR_ANS_SUBSCRIBER_IS_DELETING;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("Unsubscribe work complete.");
            AsyncCallbackInfoUnsubscribe *asynccallbackinfo = static_cast<AsyncCallbackInfoUnsubscribe *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete unsubscribe callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("Unsubscribe work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGE("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}
}  // namespace NotificationNapi
}  // namespace OHOS
