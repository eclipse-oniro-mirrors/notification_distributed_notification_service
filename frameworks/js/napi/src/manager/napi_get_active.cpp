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

#include "napi_get_active.h"

#include "ans_inner_errors.h"
#include "get_active.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include <memory>

namespace OHOS {
namespace NotificationNapi {
void AsyncCompleteCallbackNapiGetAllActiveNotifications(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("Invalid async callback data.");
        return;
    }

    auto asynccallbackinfo = static_cast<AsyncCallbackInfoActive *>(data);
    if (asynccallbackinfo) {
        ANS_LOGD("Conversion data is success.");
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_value arr = nullptr;
            int32_t count = 0;
            napi_create_array(env, &arr);
            for (auto vec : asynccallbackinfo->notifications) {
                if (!vec) {
                    ANS_LOGW("Invalid Notification object ptr");
                    continue;
                }
                napi_value notificationResult = nullptr;
                napi_create_object(env, &notificationResult);
                if (!Common::SetNotification(env, vec.GetRefPtr(), notificationResult)) {
                    ANS_LOGW("Set Notification object failed");
                    continue;
                }
                napi_set_element(env, arr, count, notificationResult);
                count++;
            }
            ANS_LOGD("getAllActiveNotifications count=%{public}d", count);
            result = arr;
            if ((count == 0) && (asynccallbackinfo->notifications.size() > 0)) {
                asynccallbackinfo->info.errorCode = ERROR;
                result = Common::NapiGetNull(env);
            }
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete NapiGetAllActiveNotifications callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiGetAllActiveNotifications(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        ANS_LOGD("null ParseParaOnlyCallback");
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoActive {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        ANS_LOGD("null asynccallbackinfo");
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getAllActiveNotifications", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiGetAllActiveNotifications work excute.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoActive *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::GetAllActiveNotifications(asynccallbackinfo->notifications);
            }
        },
        AsyncCompleteCallbackNapiGetAllActiveNotifications,
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

void AsyncCompleteCallbackNapiGetActiveNotifications(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("Ineffective async callback data.");
        return;
    }

    auto asynccallbackinfo = static_cast<AsyncCallbackInfoActive *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_value arr = nullptr;
            int32_t count = 0;
            napi_create_array(env, &arr);
            for (auto vec : asynccallbackinfo->requests) {
                if (!vec) {
                    ANS_LOGW("Invalid NotificationRequest object ptr");
                    continue;
                }
                napi_value requestResult = nullptr;
                napi_create_object(env, &requestResult);
                if (!Common::SetNotificationRequest(env, vec.GetRefPtr(), requestResult)) {
                    ANS_LOGW("Set NotificationRequest object failed");
                    continue;
                }
                napi_set_element(env, arr, count, requestResult);
                count++;
            }
            ANS_LOGD("getActiveNotifications count=%{public}d", count);
            result = arr;
            if ((count == 0) && (asynccallbackinfo->requests.size() > 0)) {
                asynccallbackinfo->info.errorCode = ERROR;
                result = Common::NapiGetNull(env);
            }
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete napiGetActiveNotifications callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiGetActiveNotifications(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        ANS_LOGD("null ParseParaOnlyCallback");
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoActive {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        ANS_LOGD("Create asynccallbackinfo failed.");
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getActiveNotifications", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiGetActiveNotifications work excute.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoActive *>(data);
            if (asynccallbackinfo) {
                std::string instanceKey = Common::GetAppInstanceKey();
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::GetActiveNotifications(
                        asynccallbackinfo->requests, instanceKey);
            }
        },
        AsyncCompleteCallbackNapiGetActiveNotifications,
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

void AsyncCompleteCallbackNapiGetActiveNotificationCount(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("Async callback ineffective data.");
        return;
    }

    auto asynccallbackinfo = static_cast<AsyncCallbackInfoActive *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_create_uint32(env, asynccallbackinfo->num, &result);
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete napiGetActiveNotificationCount callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiGetActiveNotificationCount(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoActive {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getActiveNotificationCount", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiGetActiveNotificationCount work excute.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoActive *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::GetActiveNotificationNums(asynccallbackinfo->num);
                ANS_LOGD("getActiveNotificationCount count=%{public}" PRIu64 "", asynccallbackinfo->num);
            }
        },
        AsyncCompleteCallbackNapiGetActiveNotificationCount,
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

napi_value ParseGetLiveViewFilter(const napi_env &env, const napi_value &obj, LiveViewFilter &filter)
{
    // bundle
    napi_value result = AppExecFwk::GetPropertyValueByPropertyName(env, obj, "bundle", napi_object);
    if (result == nullptr) {
        ANS_LOGE("null result");
        return nullptr;
    }
    auto retValue = Common::GetBundleOption(env, result, filter.bundle);
    if (retValue == nullptr) {
        ANS_LOGE("null retValue");
        return nullptr;
    }

    // notificationKey
    result = AppExecFwk::GetPropertyValueByPropertyName(env, obj, "notificationKey", napi_object);
    if (result == nullptr) {
        ANS_LOGE("null result");
        return nullptr;
    }
    retValue = Common::GetNotificationKey(env, result, filter.notificationKey);
    if (retValue == nullptr) {
        ANS_LOGE("null retValue");
        return nullptr;
    }

    // extraInfoKeys
    if (AppExecFwk::IsExistsByPropertyName(env, obj, "extraInfoKeys") == false) {
        ANS_LOGW("No extraInfoKeys in filter");
        return Common::NapiGetNull(env);
    }

    if (!AppExecFwk::UnwrapStringArrayByPropertyName(env, obj, "extraInfoKeys", filter.extraInfoKeys)) {
        ANS_LOGE("GetExtraInfoKeys failed.");
        return nullptr;
    }

    return Common::NapiGetNull(env);
}

napi_value ParseGetLiveViewParams(const napi_env &env, const napi_callback_info &info,
    LiveViewFilter &filter, napi_ref &callback)
{
    ANS_LOGD("start");

    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < ARGS_ONE) {
        ANS_LOGE("Wrong number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[0] : filter
    if (!AppExecFwk::IsTypeForNapiValue(env, argv[0], napi_object)) {
        ANS_LOGE("Wrong filter type. Object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    if (ParseGetLiveViewFilter(env, argv[0], filter) == nullptr) {
        ANS_LOGE("Parse filter from param failed.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
        return nullptr;
    }

    // argv[1] : callback
    if (argc > ARGS_ONE) {
        if (!AppExecFwk::IsTypeForNapiValue(env, argv[1], napi_function)) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[1], 1, &callback);
    }

    ANS_LOGD("end");
    return Common::NapiGetNull(env);
}

void AsyncGetLiveViewExecute(napi_env env, void *data)
{
    ANS_LOGD("called");

    auto asyncLiveViewCallBackInfo = static_cast<AsyncLiveViewCallBackInfo *>(data);
    if (asyncLiveViewCallBackInfo) {
        asyncLiveViewCallBackInfo->info.errorCode = NotificationHelper::GetActiveNotificationByFilter(
            asyncLiveViewCallBackInfo->filter, asyncLiveViewCallBackInfo->notificationRequest);
    }
}

void AsyncGetLiveViewComplete(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");

    auto asyncCallbackinfo = static_cast<AsyncLiveViewCallBackInfo *>(data);
    if (asyncCallbackinfo == nullptr) {
        ANS_LOGE("null asyncCallbackinfo");
        return;
    }

    ANS_LOGD("Conversion data is success.");
    napi_value result = nullptr;
    if (asyncCallbackinfo->info.errorCode != ERR_OK) {
        result = Common::NapiGetNull(env);
    } else {
        if (asyncCallbackinfo->notificationRequest == nullptr) {
            result = Common::NapiGetNull(env);
        } else {
            napi_create_object(env, &result);
            if (!Common::SetNotificationRequest(env, asyncCallbackinfo->notificationRequest, result)) {
                result = Common::NapiGetNull(env);
            }
        }
    }

    Common::CreateReturnValue(env, asyncCallbackinfo->info, result);
    if (asyncCallbackinfo->info.callback != nullptr) {
        ANS_LOGD("Delete NapiGetActiveNotificationByFilter callback reference.");
        napi_delete_reference(env, asyncCallbackinfo->info.callback);
    }
    napi_delete_async_work(env, asyncCallbackinfo->asyncWork);
    delete asyncCallbackinfo;
    asyncCallbackinfo = nullptr;
}

napi_value NapiGetActiveNotificationByFilter(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    auto asyncLiveViewCallBackInfo = new (std::nothrow) AsyncLiveViewCallBackInfo {.env = env, .asyncWork = nullptr};
    if (asyncLiveViewCallBackInfo == nullptr) {
        ANS_LOGE("null asyncLiveViewCallBackInfo");
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }
    napi_ref callback = nullptr;
    if (ParseGetLiveViewParams(env, info, asyncLiveViewCallBackInfo->filter, callback) == nullptr) {
        ANS_LOGE("null ParseGetLiveViewParams");
        delete asyncLiveViewCallBackInfo;
        asyncLiveViewCallBackInfo = nullptr;
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asyncLiveViewCallBackInfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getActiveNotificationByFilter", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(env, nullptr, resourceName,
        AsyncGetLiveViewExecute, AsyncGetLiveViewComplete,
        (void *)asyncLiveViewCallBackInfo, &asyncLiveViewCallBackInfo->asyncWork);

    bool isCallback = asyncLiveViewCallBackInfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asyncLiveViewCallBackInfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    }

    return promise;
}
}  // namespace NotificationNapi
}  // namespace OHOS
