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

#include "napi_local_live_view.h"
#include "local_live_view_subscribe.h"
#include "ans_inner_errors.h"
#include "common.h"

namespace OHOS {
namespace NotificationNapi {
const int32_t TRIGGER_PARA = 3;

napi_value NapiSubscriteLocalAcitvity(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    napi_ref callback = nullptr;
    LocalLiveViewSubscriberInstance *objectInfo = nullptr;
    if (ParseParameters(env, info, objectInfo, callback) == nullptr) {
        if (objectInfo) {
            delete objectInfo;
            objectInfo = nullptr;
        }
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoSubscribeLocalLiveView *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoSubscribeLocalLiveView {
            .env = env, .asyncWork = nullptr, .objectInfo = objectInfo
    };
    if (!asynccallbackinfo) {
        if (objectInfo) {
            delete objectInfo;
            objectInfo = nullptr;
        }
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "subscribeLocalLiveViewNotification", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiSubscribeLocalLiveView work excute.");
            if (!data) {
                ANS_LOGE("Invalid asynccallbackinfo!");
                return;
            }
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoSubscribeLocalLiveView *>(data);

            asynccallbackinfo->info.errorCode =
                NotificationHelper::SubscribeLocalLiveViewNotification(*(asynccallbackinfo->objectInfo), false);
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiSubscribeLocalLiveView work complete.");
            if (!data) {
                ANS_LOGE("Invalid asynccallbackinfo!");
                return;
            }
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoSubscribeLocalLiveView *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiSubscribeLocalLiveView callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiSubscribeLocalLiveView work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiSubscribeLocalLiveView callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiUnsubscriteLocalLiveView(napi_env env, napi_callback_info info)
{
    return nullptr;
}

napi_value ParseTriggerParameters(const napi_env &env, const napi_callback_info &info,
    AsyncCallbackInfoSubscribeLocalLiveView *asynccallbackinfo, napi_ref &callback)
{
    ANS_LOGD("enter");

    size_t argc = TRIGGER_PARA;
    napi_value argv[TRIGGER_PARA] = {nullptr, nullptr};
    napi_value thisVar = nullptr;

    int32_t notificationId = -1;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc != TRIGGER_PARA) {
        ANS_LOGE("Wrong number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;

    // argv[0]:BundleOption
    auto retValue = Common::GetBundleOption(env, argv[PARAM0], asynccallbackinfo->bundleOption);
    if (retValue == nullptr) {
        ANS_LOGE("GetBundleOption failed");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
        return nullptr;
    }

    // argv[1]:notificationId
    NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Wrong argument type. Number expected.");
        std::string msg = "Incorrect parameter types.The type of param must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_value_int32(env, argv[PARAM1], &notificationId);
    ANS_LOGI("notificationId = %{public}d", notificationId);
    asynccallbackinfo->notificationId = notificationId;

    // argv[2]:buttonOption
    retValue = Common::GetButtonOption(env, argv[PARAM2], asynccallbackinfo->buttonOption);
    if (retValue == nullptr) {
        ANS_LOGE("GetButtonOption failed");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
        return nullptr;
    }
    return Common::NapiGetNull(env);
}

napi_value NapiTriggerLocalLiveView(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    napi_ref callback = nullptr;

    AsyncCallbackInfoSubscribeLocalLiveView *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoSubscribeLocalLiveView {
            .env = env, .asyncWork = nullptr,
    };
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, callback);
    }

    if (ParseTriggerParameters(env, info, asynccallbackinfo, callback) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        delete asynccallbackinfo;
        return Common::NapiGetUndefined(env);
    }

    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "triggerLocalLiveView", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiTriggerLocalLiveView work excute.");
            if (!data) {
                ANS_LOGE("Invalid asynccallbackinfo!");
                return;
            }
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoSubscribeLocalLiveView *>(data);

            asynccallbackinfo->info.errorCode =
                NotificationHelper::TriggerLocalLiveView(asynccallbackinfo->bundleOption,
                    asynccallbackinfo->notificationId, asynccallbackinfo->buttonOption);
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiSubscribeLocalLiveView work complete.");
            if (!data) {
                ANS_LOGE("Invalid asynccallbackinfo!");
                return;
            }
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoSubscribeLocalLiveView *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiSubscribeLocalLiveView callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiSubscribeLocalLiveView work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiSubscribeLocalLiveView callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

}  // namespace NotificationNapi
}  // namespace OHOS
