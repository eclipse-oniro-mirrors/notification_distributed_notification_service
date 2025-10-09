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

#include <optional>
#include "remove.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace NotificationNapi {
const int REMOVE_MIN_PARA = 2;
const int REMOVE_OR_BUNDLE_MAX_PARA = 3;

const int REMOVE_ALL_MAX_PARA = 2;

const int REMOVE_BY_BUNDLE_AND_KEY_MIN_PARA = 3;
const int REMOVE_BY_BUNDLE_AND_KEY_MAX_PARA = 4;

const int REMOVE_GROUP_BY_BUNDLE_MIN_PARA = 2;
const int REMOVE_GROUP_BY_BUNDLE_MAX_PARA = 3;

bool ParseRemoveReason(const napi_env &env, const napi_value &value, RemoveParams &params)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valueType), false);
    if (valueType != napi_number) {
        ANS_LOGE("RemoveReason valueType unexpected.");
        return false;
    }
    int32_t removeReason = 0;
    napi_get_value_int32(env, value, &removeReason);
    if (!Common::IsValidRemoveReason(removeReason)) {
        ANS_LOGE("RemoveReason value unexpected.");
        return false;
    }
    params.removeReason = removeReason;
    return true;
}

bool ParseCallbackFunc(const napi_env &env, const napi_value &value,
    RemoveParams &params)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valueType), false);
    if (valueType != napi_function) {
        ANS_LOGE("Callback is not function excute promise.");
        return true;
    }
    napi_create_reference(env, value, 1, &params.callback);
    return true;
}

bool ParseHashcodeTypeParams(
    const napi_env &env, napi_value* argv, size_t argc, napi_valuetype valueType, RemoveParams &params)
{
    // argv[0]: hashCode
    bool isArray = false;
    napi_is_array(env, argv[PARAM0], &isArray);
    if (isArray) {
        std::vector<std::string> hashcodes;
        auto retValue = Common::GetHashCodes(env, argv[PARAM0], hashcodes);
        if (retValue == nullptr) {
            ANS_LOGE("GetHashCodes failed.");
            return false;
        }
        params.hashcodes = hashcodes;
    } else if (valueType == napi_string) {
        size_t strLen = 0;
        char str[STR_MAX_SIZE] = {0};
        NAPI_CALL_BASE(env, napi_get_value_string_utf8(env, argv[PARAM0], str, STR_MAX_SIZE - 1, &strLen), false);
        params.hashcode = str;
    } else if (valueType == napi_number) {
        int64_t number = 0;
        NAPI_CALL_BASE(env, napi_get_value_int64(env, argv[PARAM0], &number), false);
        params.hashcode = std::to_string(number);
    } else {
        bool result = false;
        NAPI_CALL_BASE(env, napi_get_value_bool(env, argv[PARAM0], &result), false);
        params.hashcode = std::to_string(result);
    }
    // argv[1]:removeReason
    if (!ParseRemoveReason(env, argv[PARAM1], params)) {
        return false;
    }
    // argv[2]:callback
    if (argc >= REMOVE_OR_BUNDLE_MAX_PARA) {
        if (!ParseCallbackFunc(env, argv[PARAM2], params)) {
            return false;
        }
    }
    return true;
}

bool ParseBundleOptionTypeParams(const napi_env &env, napi_value* argv, size_t argc, RemoveParams &params)
{
    if (argc < REMOVE_BY_BUNDLE_AND_KEY_MIN_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        return false;
    }
    BundleAndKeyInfo bundleInfo {};
    // argv[0]: BundleOption  argv[1]: NotificationKey
    if (Common::GetBundleOption(env, argv[PARAM0], bundleInfo.option) == nullptr ||
        Common::GetNotificationKey(env, argv[PARAM1], bundleInfo.key) == nullptr) {
        ANS_LOGE("GetBundleOption failed.");
        return false;
    }
    params.bundleAndKeyInfo = bundleInfo;
    // argv[2]:removeReason
    if (!ParseRemoveReason(env, argv[PARAM2], params)) {
        return false;
    }
    // argv[3]:callback
    if (argc >= REMOVE_BY_BUNDLE_AND_KEY_MAX_PARA) {
        if (!ParseCallbackFunc(env, argv[PARAM3], params)) {
            return false;
        }
    }
    return true;
}

bool ParseParameters(const napi_env &env, const napi_callback_info &info, RemoveParams &params)
{
    ANS_LOGD("enter");
    size_t argc = REMOVE_BY_BUNDLE_AND_KEY_MAX_PARA;
    napi_value argv[REMOVE_BY_BUNDLE_AND_KEY_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL), false);
    if (argc < REMOVE_MIN_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return false;
    }
    bool isArray = false;
    napi_is_array(env, argv[PARAM0], &isArray);
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, argv[PARAM0], &valueType), false);
    if ((valueType != napi_string) && (valueType != napi_object) &&
        (valueType != napi_number) && (valueType != napi_boolean) && !isArray) {
        ANS_LOGE("Wrong argument type. String or object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be object or string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return false;
    }
    if ((valueType == napi_string) || (valueType == napi_number) || (valueType == napi_boolean) || isArray) {
        return ParseHashcodeTypeParams(env, argv, argc, valueType, params);
    }
    return ParseBundleOptionTypeParams(env, argv, argc, params);
}

napi_value ParseParametersByRemoveAll(const napi_env &env, const napi_callback_info &info, RemoveParams &params)
{
    ANS_LOGD("enter");

    size_t argc = REMOVE_ALL_MAX_PARA;
    napi_value argv[REMOVE_ALL_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    if (argc == 0) {
        return Common::NapiGetNull(env);
    }

    // argv[0]: bundle / userId / callback
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if ((valuetype != napi_object) && (valuetype != napi_number) && (valuetype != napi_function)) {
        ANS_LOGE("Wrong argument type. Function or object expected. Excute promise.");
        return Common::NapiGetNull(env);
    }
    if (valuetype == napi_object) {
        BundleAndKeyInfo bundleandKeyInfo {};
        auto retValue = Common::GetBundleOption(env, argv[PARAM0], bundleandKeyInfo.option);
        if (retValue == nullptr) {
            ANS_LOGE("GetBundleOption failed.");
            Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
            return nullptr;
        }
        params.bundleAndKeyInfo = bundleandKeyInfo;
    } else if (valuetype == napi_number) {
        NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM0], &params.userId));
        params.hasUserId = true;
    } else {
        napi_create_reference(env, argv[PARAM0], 1, &params.callback);
    }

    // argv[1]:callback
    if (argc >= REMOVE_ALL_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value ParseParameters(
    const napi_env &env, const napi_callback_info &info, RemoveParamsGroupByBundle &params)
{
    ANS_LOGD("enter");

    size_t argc = REMOVE_GROUP_BY_BUNDLE_MAX_PARA;
    napi_value argv[REMOVE_GROUP_BY_BUNDLE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < REMOVE_GROUP_BY_BUNDLE_MIN_PARA) {
        ANS_LOGE("Error number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[0]: bundle
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Valuetype is not object.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
    if (retValue == nullptr) {
        ANS_LOGE("GetBundleOption failed.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
        return nullptr;
    }

    // argv[1]: groupName: string
    NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
    if (valuetype != napi_string && valuetype != napi_number && valuetype != napi_boolean) {
        ANS_LOGE("Error argument type. String number boolean anticipate.");
        std::string msg = "Incorrect parameter types.The type of param must be string or number or boolean.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    if (valuetype == napi_string) {
        char str[STR_MAX_SIZE] = {0};
        size_t strLen = 0;
        NAPI_CALL(env, napi_get_value_string_utf8(env, argv[PARAM1], str, STR_MAX_SIZE - 1, &strLen));
        params.groupName = str;
    } else if (valuetype == napi_number) {
        ANS_LOGD("valuetype is number.");
        int64_t number = 0;
        NAPI_CALL(env, napi_get_value_int64(env, argv[PARAM1], &number));
        params.groupName = std::to_string(number);
    } else {
        ANS_LOGD("valuetype is other types.");
        bool result = false;
        NAPI_CALL(env, napi_get_value_bool(env, argv[PARAM1], &result));
        params.groupName = std::to_string(result);
    }
    // argv[2]:callback
    if (argc >= REMOVE_GROUP_BY_BUNDLE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM2], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGW("Callback is not function.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM2], 1, &params.callback);
    }
    return Common::NapiGetNull(env);
}

void RemoveExecuteCallback(napi_env env, void *data)
{
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

void RemoveCompleteCallback(napi_env env, napi_status status, void *data)
{
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    auto removeInfo = static_cast<AsyncCallbackInfoRemove *>(data);
    if (removeInfo) {
        Common::ReturnCallbackPromise(env, removeInfo->info, Common::NapiGetNull(env));
        if (removeInfo->info.callback != nullptr) {
            napi_delete_reference(env, removeInfo->info.callback);
        }
        napi_delete_async_work(env, removeInfo->asyncWork);
        delete removeInfo;
        removeInfo = nullptr;
    }
}

napi_value Remove(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    RemoveParams params {};
    if (!ParseParameters(env, info, params)) {
        return Common::NapiGetUndefined(env);
    }
    auto removeInfo = new (std::nothrow) AsyncCallbackInfoRemove {.env = env, .asyncWork = nullptr, .params = params};
    if (!removeInfo) {
        ANS_LOGD("RemoveInfo is nullptr.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, removeInfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "remove", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env, nullptr, resourceName, RemoveExecuteCallback, RemoveCompleteCallback,
        (void *)removeInfo, &removeInfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, removeInfo->asyncWork, napi_qos_user_initiated));
    if (removeInfo->info.isCallback) {
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value RemoveAll(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    RemoveParams params {};
    if (ParseParametersByRemoveAll(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoRemove *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoRemove {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is nullptr.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create removeAll string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "removeAll", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("RemoveAll napi_create_async_work start");
            AsyncCallbackInfoRemove *asynccallbackinfo = static_cast<AsyncCallbackInfoRemove *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->params.bundleAndKeyInfo.has_value()) {
                    auto &infos = asynccallbackinfo->params.bundleAndKeyInfo.value();
                    asynccallbackinfo->info.errorCode = NotificationHelper::RemoveAllNotifications(infos.option);
                } else if (asynccallbackinfo->params.hasUserId) {
                    ANS_LOGD("hasUserId is true.");
                    asynccallbackinfo->info.errorCode = NotificationHelper::RemoveNotifications(
                        asynccallbackinfo->params.userId);
                } else {
                    asynccallbackinfo->info.errorCode = NotificationHelper::RemoveNotifications();
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("RemoveAll napi_create_async_work end");
            AsyncCallbackInfoRemove *asynccallbackinfo = static_cast<AsyncCallbackInfoRemove *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete removeAll callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("RemoveAll work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("removeAll callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackRemoveGroupByBundle(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackInfoRemoveGroupByBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoRemoveGroupByBundle *>(data);
    if (asynccallbackinfo) {
        Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value RemoveGroupByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    RemoveParamsGroupByBundle params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoRemoveGroupByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoRemoveGroupByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Create asynccallbackinfo failed.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create removeGroupByBundle string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "removeGroupByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("RemoveGroupByBundle napi_create_async_work start");
            AsyncCallbackInfoRemoveGroupByBundle *asynccallbackinfo =
                static_cast<AsyncCallbackInfoRemoveGroupByBundle *>(data);
            if (asynccallbackinfo) {
                ANS_LOGI("removeGroup bundle=%{public}s,uid=%{public}d,groupName=%{public}s",
                    asynccallbackinfo->params.option.GetBundleName().c_str(),
                    asynccallbackinfo->params.option.GetUid(),
                    asynccallbackinfo->params.groupName.c_str());
                asynccallbackinfo->info.errorCode = NotificationHelper::RemoveGroupByBundle(
                    asynccallbackinfo->params.option, asynccallbackinfo->params.groupName);
            }
        },
        AsyncCompleteCallbackRemoveGroupByBundle,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("removeGroupByBundle callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}
}  // namespace NotificationNapi
}  // namespace OHOS