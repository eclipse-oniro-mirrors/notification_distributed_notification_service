/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "cancel.h"
#include "js_native_api_types.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace NotificationNapi {
constexpr int8_t CANCEL_MAX_PARA = 3;
constexpr int8_t CANCEL_GROUP_MAX_PARA = 2;
constexpr int8_t CANCEL_GROUP_MIN_PARA = 1;
constexpr int8_t CANCEL_AS_BUNDLE_MAX_PARA = 4;
constexpr int8_t CANCEL_AS_BUNDLEOPTION_MAX_PARA = 2;

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, ParametersInfoCancel &paras)
{
    ANS_LOGD("called");

    size_t argc = CANCEL_MAX_PARA;
    napi_value argv[CANCEL_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < 1) {
        ANS_LOGE("Wrong number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    // argv[0]: id: number / representativeBundle: BundleOption
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_number && valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Number object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be number or object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    if (valuetype == napi_number) {
        NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM0], &paras.id));
    } else {
        auto retValue = Common::GetBundleOption(env, argv[PARAM0], paras.option);
        if (retValue == nullptr) {
            ANS_LOGE("null retValue");
            Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
            return nullptr;
        }
        paras.hasOption = true;
    }

    // argv[1]: label: string / callback / id : number
    if (argc >= CANCEL_MAX_PARA - 1 && !paras.hasOption) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype == napi_undefined || valuetype == napi_null) {
            return Common::NapiGetNull(env);
        }
        if (valuetype != napi_number && valuetype != napi_boolean &&
            valuetype != napi_string && valuetype != napi_function) {
            ANS_LOGE("Wrong argument type. String or function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be string or function.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        if (valuetype == napi_number) {
            int64_t number = 0;
            NAPI_CALL(env, napi_get_value_int64(env, argv[PARAM1], &number));
            paras.label = std::to_string(number);
        } else if (valuetype == napi_boolean) {
            bool result = false;
            NAPI_CALL(env, napi_get_value_bool(env, argv[PARAM1], &result));
            paras.label = std::to_string(result);
        } else if (valuetype == napi_string) {
            char str[STR_MAX_SIZE] = {0};
            size_t strLen = 0;
            NAPI_CALL(env, napi_get_value_string_utf8(env, argv[PARAM1], str, STR_MAX_SIZE - 1, &strLen));
            paras.label = str;
        } else {
            napi_create_reference(env, argv[PARAM1], 1, &paras.callback);
        }
    } else if (argc >= CANCEL_MAX_PARA - 1 && paras.hasOption) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types.The type of param must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM1], &paras.id));
    }

    // argv[2]: callback
    if (argc >= CANCEL_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM2], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM2], 1, &paras.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, ParametersInfoCancelGroup &paras)
{
    ANS_LOGD("called");

    size_t argc = CANCEL_GROUP_MAX_PARA;
    napi_value argv[CANCEL_GROUP_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < CANCEL_GROUP_MIN_PARA) {
        ANS_LOGE("Wrong number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    // argv[0]: groupName: string
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_string && valuetype != napi_number && valuetype != napi_boolean) {
        ANS_LOGE("Wrong argument type. String number boolean expected.");
        std::string msg = "Incorrect parameter types.The type of param must be number or string or boolean.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    if (valuetype == napi_string) {
        char str[STR_MAX_SIZE] = {0};
        size_t strLen = 0;
        NAPI_CALL(env, napi_get_value_string_utf8(env, argv[PARAM0], str, STR_MAX_SIZE - 1, &strLen));
        paras.groupName = str;
    } else if (valuetype == napi_number) {
        int64_t number = 0;
        NAPI_CALL(env, napi_get_value_int64(env, argv[PARAM0], &number));
        paras.groupName = std::to_string(number);
    } else {
        bool result = false;
        NAPI_CALL(env, napi_get_value_bool(env, argv[PARAM0], &result));
        paras.groupName = std::to_string(result);
    }

    // argv[1]: callback
    if (argc >= CANCEL_GROUP_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &paras.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value Cancel(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    ParametersInfoCancel paras;
    if (ParseParameters(env, info, paras) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoCancel *asynccallbackinfo = new (std::nothrow)
        AsyncCallbackInfoCancel {.env = env, .asyncWork = nullptr, .id = paras.id, .label = paras.label};
    if (!asynccallbackinfo) {
        ANS_LOGD("null asyncCallbackinfo");
        return Common::JSParaError(env, paras.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, paras.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create cancel string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "cancel", NAPI_AUTO_LENGTH, &resourceName);
    // Async function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("Cancel work excute.");
            AsyncCallbackInfoCancel *asynccallbackinfo = static_cast<AsyncCallbackInfoCancel *>(data);

            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::CancelNotification(asynccallbackinfo->label, asynccallbackinfo->id);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("Cancel work complete.");
            AsyncCallbackInfoCancel *asynccallbackinfo = static_cast<AsyncCallbackInfoCancel *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete cancel callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("Cancel work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value CancelAll(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoCancel {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        ANS_LOGD("null asynccallbackinfo");
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create cancelAll string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "cancelAll", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("CancelAll work excute.");
            AsyncCallbackInfoCancel *asynccallbackinfo = static_cast<AsyncCallbackInfoCancel *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::CancelAllNotifications();
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("CancelAll work complete.");
            AsyncCallbackInfoCancel *asynccallbackinfo = static_cast<AsyncCallbackInfoCancel *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete CancelAll callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("CancelAll work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value CancelGroup(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    ParametersInfoCancelGroup params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoCancelGroup *asynccallbackinfo = new (std::nothrow)
        AsyncCallbackInfoCancelGroup {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Create asynccallbackinfo fail.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create cancelGroup string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "cancelGroup", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("CancelGroup work excute.");
            AsyncCallbackInfoCancelGroup *asynccallbackinfo = static_cast<AsyncCallbackInfoCancelGroup *>(data);
            if (asynccallbackinfo) {
                ANS_LOGD("asynccallbackinfo->params.groupName = %{public}s",
                    asynccallbackinfo->params.groupName.c_str());
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::CancelGroup(asynccallbackinfo->params.groupName);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("CancelGroup work complete.");
            AsyncCallbackInfoCancelGroup *asynccallbackinfo = static_cast<AsyncCallbackInfoCancelGroup *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete CancelGroup callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("CancelGroup work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, ParametersInfoCancelAsBundle &paras)
{
    ANS_LOGD("called");

    size_t argc = CANCEL_AS_BUNDLE_MAX_PARA;
    napi_value argv[CANCEL_AS_BUNDLE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < 1) {
        ANS_LOGD("Wrong number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    // argv[0]: id: number / bundleOption
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_number && valuetype != napi_object) {
        ANS_LOGD("Wrong argument type. Number object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    if (argc > CANCEL_AS_BUNDLEOPTION_MAX_PARA) {
        NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM0], &paras.id));
    } else {
        auto retValue = Common::GetBundleOption(env, argv[PARAM0], paras.option);
        if (retValue == nullptr) {
            ANS_LOGE("GetBundleOption failed.");
            Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
            return nullptr;
        }
        paras.hasOption = true;
    }
    // argv[1]: representativeBundle: string / id
    NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
    if (valuetype != napi_string && valuetype != napi_number && valuetype != napi_boolean) {
        ANS_LOGD("Wrong argument type. String number boolean expected.");
        std::string msg = "Incorrect parameter types.The type of param must be number or string or boolean.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    if (argc > CANCEL_AS_BUNDLEOPTION_MAX_PARA) {
        if (valuetype == napi_string) {
            char str[STR_MAX_SIZE] = {0};
            size_t strLen = 0;
            napi_get_value_string_utf8(env, argv[PARAM1], str, STR_MAX_SIZE - 1, &strLen);
            paras.representativeBundle = str;
        } else if (valuetype == napi_number) {
            int64_t number = 0;
            NAPI_CALL(env, napi_get_value_int64(env, argv[PARAM1], &number));
            paras.representativeBundle = std::to_string(number);
        } else {
            bool result = false;
            NAPI_CALL(env, napi_get_value_bool(env, argv[PARAM1], &result));
            paras.representativeBundle = std::to_string(result);
        }
    } else {
        NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM1], &paras.id));
    }

    // argv[2] : userId
    if (argc > CANCEL_AS_BUNDLEOPTION_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM2], &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types.The type of param must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int32(env, argv[PARAM2], &paras.userId);
    }
    // argv[3]: callback
    if (argc >= CANCEL_AS_BUNDLE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM3], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM3], 1, &paras.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value CancelAsBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    ParametersInfoCancelAsBundle paras;
    if (ParseParameters(env, info, paras) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoCancelAsBundle *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoCancelAsBundle {
        .env = env, .asyncWork = nullptr,
        .id = paras.id,
        .representativeBundle = paras.representativeBundle,
        .userId = paras.userId
    };
    if (!asynccallbackinfo) {
        ANS_LOGD("null asyncCallbackinfo");
        return Common::JSParaError(env, paras.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, paras.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create cancelasbundle string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "cancelasbundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("CancelAsBundle work excute.");
            AsyncCallbackInfoCancelAsBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoCancelAsBundle *>(data);

            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::CancelAsBundle(
                    asynccallbackinfo->id, asynccallbackinfo->representativeBundle, asynccallbackinfo->userId);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("CancelAsBundle work complete");
            AsyncCallbackInfoCancelAsBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoCancelAsBundle *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete CancelAsBundle callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("CancelAsBundle work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}
}  // namespace NotificationNapi
}  // namespace OHOS
