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

#include "napi_distributed.h"

#include "ans_inner_errors.h"
#include "distributed.h"

namespace OHOS {
namespace NotificationNapi {
void AsyncCompleteCallbackNapiIsDistributedEnabled(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    ANS_LOGI("IsDistributedEnabled napi_create_async_work end");
    AsyncCallbackInfoIsEnabled *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnabled *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_get_boolean(env, asynccallbackinfo->enable, &result);
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete napiIsDistributedEnabled callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiIsDistributedEnabled(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoIsEnabled {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "isDistributedEnabled", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiIsDistributedEnabled work excute.");
            AsyncCallbackInfoIsEnabled *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnabled *>(data);

            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::IsDistributedEnabled(asynccallbackinfo->enable);
                ANS_LOGI("IsDistributedEnabled enable = %{public}d", asynccallbackinfo->enable);
            }
        },
        AsyncCompleteCallbackNapiIsDistributedEnabled,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiIsDistributedEnabled callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiEnableDistributed(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    EnabledParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        ANS_LOGD("ParseParameters is nullptr.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoEnabled *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnabled {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Create asyncCallbackinfo fail.");
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "enableDistributed", NAPI_AUTO_LENGTH, &resourceName);
    // Async function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiEnableDistributed work excute.");
            AsyncCallbackInfoEnabled *asynccallbackinfo = static_cast<AsyncCallbackInfoEnabled *>(data);

            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::EnableDistributed(asynccallbackinfo->params.enable);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiEnableDistributed work complete.");
            AsyncCallbackInfoEnabled *asynccallbackinfo = static_cast<AsyncCallbackInfoEnabled *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiEnableDistributed callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiEnableDistributed work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiEnableDistributed callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiEnableDistributedByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    EnabledByBundleParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoEnabledByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnabledByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "enableDistributedByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiEnableDistributedByBundle work excute.");
            AsyncCallbackInfoEnabledByBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoEnabledByBundle *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::EnableDistributedByBundle(
                    asynccallbackinfo->params.option, asynccallbackinfo->params.enable);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiEnableDistributedByBundle work complete.");
            AsyncCallbackInfoEnabledByBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoEnabledByBundle *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiEnableDistributedByBundle callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiEnableDistributedByBundle work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiEnableDistributedByBundle callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiEnableDistributedSelf(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    EnabledParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoEnabled *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnabled {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Fail to create asyncCallbackinfo.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "enableDistributedSelf", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiEnableDistributedSelf work excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoEnabled *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::EnableDistributedSelf(asynccallbackinfo->params.enable);
                ANS_LOGI("enable = %{public}d", asynccallbackinfo->params.enable);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiEnableDistributedSelf work complete.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoEnabled *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiEnableDistributedSelf callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiEnableDistributedSelf work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiEnableDistributedSelf callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackNapiIsDistributedEnableByBundle(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    ANS_LOGI("IsDistributedEnableByBundle napi_create_async_work end");
    AsyncCallbackInfoIsEnabledByBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnabledByBundle *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_get_boolean(env, asynccallbackinfo->enable, &result);
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete napiIsDistributedEnableByBundle callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiIsDistributedEnableByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    IsEnabledByBundleParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoIsEnabledByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoIsEnabledByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "isDistributedEnableByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiIsDistributedEnableByBundle work excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoIsEnabledByBundle *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->params.hasDeviceType) {
                    std::string deviceType = asynccallbackinfo->params.deviceType;
                    asynccallbackinfo->info.errorCode = NotificationHelper::IsDistributedEnabledByBundle(
                        asynccallbackinfo->params.option, deviceType, asynccallbackinfo->enable);
                    ANS_LOGI("has deviceType errorCode = %{public}d", asynccallbackinfo->info.errorCode);
                } else {
                    asynccallbackinfo->info.errorCode = NotificationHelper::IsDistributedEnableByBundle(
                        asynccallbackinfo->params.option, asynccallbackinfo->enable);
                }
            }
        },
        AsyncCompleteCallbackNapiIsDistributedEnableByBundle,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiIsDistributedEnableByBundle callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackNapiGetDeviceRemindType(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    ANS_LOGI("GetDeviceRemindType napi_create_async_work end");
    AsyncCallbackInfoGetRemindType *asynccallbackinfo = static_cast<AsyncCallbackInfoGetRemindType *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            DeviceRemindType outType = DeviceRemindType::IDLE_DONOT_REMIND;
            if (!AnsEnumUtil::DeviceRemindTypeCToJS(asynccallbackinfo->remindType, outType)) {
                asynccallbackinfo->info.errorCode = ERROR;
                result = Common::NapiGetNull(env);
            }
            napi_create_int32(env, (int32_t)outType, &result);
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete napiGetDeviceRemindType callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiGetDeviceRemindType(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoGetRemindType {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getDeviceRemindType", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiGetDeviceRemindType work excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoGetRemindType *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::GetDeviceRemindType(asynccallbackinfo->remindType);
            }
        },
        AsyncCompleteCallbackNapiGetDeviceRemindType,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiGetDeviceRemindType callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiSetSyncNotificationEnabledWithoutApp(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    EnabledWithoutAppParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::JSParaError(env, params.callback);
    }

    AsyncCallbackInfoEnabledWithoutApp *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnabledWithoutApp {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "SetSyncNotificationEnabledWithoutApp", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiSetSyncNotificationEnabledWithoutApp work excute.");
            AsyncCallbackInfoEnabledWithoutApp *asynccallbackinfo =
                static_cast<AsyncCallbackInfoEnabledWithoutApp *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::SetSyncNotificationEnabledWithoutApp(
                    asynccallbackinfo->params.userId, asynccallbackinfo->params.enable);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiSetSyncNotificationEnabledWithoutApp work complete.");
            AsyncCallbackInfoEnabledWithoutApp *asynccallbackinfo =
                static_cast<AsyncCallbackInfoEnabledWithoutApp *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiSetSyncNotificationEnabledWithoutApp callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiSetSyncNotificationEnabledWithoutApp work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiSetSyncNotificationEnabledWithoutApp callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiGetSyncNotificationEnabledWithoutApp(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    GetEnabledWithoutAppParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::JSParaError(env, params.callback);
    }

    AsyncCallbackInfoGetEnabledWithoutApp *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoGetEnabledWithoutApp {
        .env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "GetSyncNotificationEnabledWithoutApp", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiGetSyncNotificationEnabledWithoutApp work excute.");
            AsyncCallbackInfoGetEnabledWithoutApp *asynccallbackinfo =
                static_cast<AsyncCallbackInfoGetEnabledWithoutApp *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetSyncNotificationEnabledWithoutApp(
                    asynccallbackinfo->params.userId, asynccallbackinfo->enable);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiGetSyncNotificationEnabledWithoutApp work complete.");
            AsyncCallbackInfoGetEnabledWithoutApp *asynccallbackinfo =
                static_cast<AsyncCallbackInfoGetEnabledWithoutApp *>(data);
            if (asynccallbackinfo) {
                napi_value result = nullptr;
                if (asynccallbackinfo->info.errorCode != ERR_OK) {
                    result = Common::NapiGetNull(env);
                } else {
                    napi_get_boolean(env, asynccallbackinfo->enable, &result);
                }
                Common::CreateReturnValue(env, asynccallbackinfo->info, result);
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiGetSyncNotificationEnabledWithoutApp callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiGetSyncNotificationEnabledWithoutApp work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiGetSyncNotificationEnabledWithoutApp callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiSetTargetDeviceStatus(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    DeviceStatus paras;
    if (ParseParameters(env, info, paras) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsynDeviceStatusConfig *asynccallbackinfo = new (std::nothrow) AsynDeviceStatusConfig {
        .env = env, .asyncWork = nullptr, .deviceStatus = paras
    };
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, paras.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, paras.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setTargetDeviceStatus", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("NapiSetTargetDeviceStatus work excute.");
            AsynDeviceStatusConfig *asynccallbackinfo = static_cast<AsynDeviceStatusConfig *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::SetTargetDeviceStatus(
                    asynccallbackinfo->deviceStatus.deviceType, asynccallbackinfo->deviceStatus.status,
                    DISTURB_DEFAULT_FLAG);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("Napi add do not disturb profiles work complete.");
            AsynDeviceStatusConfig *asynccallbackinfo = static_cast<AsynDeviceStatusConfig *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
        }, (void *)asynccallbackinfo, &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("NapiSetTargetDeviceStatus callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}
}  // namespace NotificationNapi
}  // namespace OHOS
