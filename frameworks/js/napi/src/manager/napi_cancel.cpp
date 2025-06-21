/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "napi_cancel.h"

#include "ans_inner_errors.h"
#include "cancel.h"

namespace OHOS {
namespace NotificationNapi {
napi_value NapiCancel(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    ParametersInfoCancel paras;
    if (ParseParameters(env, info, paras) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoCancel *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoCancel {
        .env = env,
        .asyncWork = nullptr,
        .id = paras.id,
        .label = paras.label,
        .option = paras.option,
        .hasOption = paras.hasOption
    };
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, paras.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, paras.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "cancel", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiCancel work excute.");
            AsyncCallbackInfoCancel *asynccallbackinfo = static_cast<AsyncCallbackInfoCancel *>(data);

            if (asynccallbackinfo) {
                if (asynccallbackinfo->hasOption) {
                    asynccallbackinfo->info.errorCode = NotificationHelper::CancelAsBundleWithAgent(
                        asynccallbackinfo->option, asynccallbackinfo->id);
                } else {
                    std::string instanceKey = Common::GetAppInstanceKey();
                    asynccallbackinfo->info.errorCode = NotificationHelper::CancelNotification(
                        asynccallbackinfo->label, asynccallbackinfo->id, instanceKey);
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiCancel work complete.");
            AsyncCallbackInfoCancel *asynccallbackinfo = static_cast<AsyncCallbackInfoCancel *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiCancel callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiCancel work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiCancelAll(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoCancel {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "cancelAll", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiCancelAll work excute.");
            AsyncCallbackInfoCancel *asynccallbackinfo = static_cast<AsyncCallbackInfoCancel *>(data);
            if (asynccallbackinfo) {
                std::string instanceKey = Common::GetAppInstanceKey();
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::CancelAllNotifications(instanceKey);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiCancelAll work complete.");
            AsyncCallbackInfoCancel *asynccallbackinfo = static_cast<AsyncCallbackInfoCancel *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiCancelAll callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiCancelAll work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiCancelGroup(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    ParametersInfoCancelGroup params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoCancelGroup *asynccallbackinfo = new (std::nothrow)
        AsyncCallbackInfoCancelGroup {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "cancelGroup", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiCancelGroup work excute.");
            AsyncCallbackInfoCancelGroup *asynccallbackinfo = static_cast<AsyncCallbackInfoCancelGroup *>(data);
            if (asynccallbackinfo) {
                ANS_LOGI("asynccallbackinfo->params.groupName = %{public}s",
                    asynccallbackinfo->params.groupName.c_str());
                std::string instanceKey = Common::GetAppInstanceKey();
                asynccallbackinfo->info.errorCode = NotificationHelper::CancelGroup(
                    asynccallbackinfo->params.groupName, instanceKey);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiCancelGroup work complete.");
            AsyncCallbackInfoCancelGroup *asynccallbackinfo = static_cast<AsyncCallbackInfoCancelGroup *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiCancelGroup callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiCancelGroup work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiCancelAsBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    ParametersInfoCancelAsBundle paras;
    if (ParseParameters(env, info, paras) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoCancelAsBundle *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoCancelAsBundle {
        .env = env, .asyncWork = nullptr,
        .id = paras.id,
        .representativeBundle = paras.representativeBundle,
        .userId = paras.userId,
        .option = paras.option,
        .hasOption = paras.hasOption
    };
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, paras.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, paras.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "cancelasbundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiCancelAsBundle work excute.");
            AsyncCallbackInfoCancelAsBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoCancelAsBundle *>(data);

            if (asynccallbackinfo) {
                if (asynccallbackinfo->hasOption) {
                    asynccallbackinfo->info.errorCode = NotificationHelper::CancelAsBundle(
                        asynccallbackinfo->option, asynccallbackinfo->id);
                } else {
                    asynccallbackinfo->info.errorCode = NotificationHelper::CancelAsBundle(
                        asynccallbackinfo->id, asynccallbackinfo->representativeBundle, asynccallbackinfo->userId);
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiCancelAsBundle work complete.");
            AsyncCallbackInfoCancelAsBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoCancelAsBundle *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiCancelAsBundle callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiCancelAsBundle work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}
}  // namespace NotificationNapi
}  // namespace OHOS
