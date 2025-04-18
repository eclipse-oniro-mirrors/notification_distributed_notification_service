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

#include "napi_subscribe.h"

#include "ans_inner_errors.h"
#include "subscribe.h"
#include "unsubscribe.h"
#include <memory>
#include <new>
#include "distributed_operation_callback.h"
#include "notification_operation_info.h"

namespace OHOS {
namespace NotificationNapi {
void NapiDistributeOperationExecuteCallback(napi_env env, void *data)
{
    ANS_LOGI("DistributeOperation napi_create_async_work start");
    auto asyncCallbackInfo = static_cast<AsyncOperationCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        ANS_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    sptr<DistributedOperationCallback> callback = new (std::nothrow) DistributedOperationCallback(*asyncCallbackInfo);
    if (callback == nullptr) {
        ANS_LOGE("NAPI_Lock create callback object fail");
        return;
    }

    sptr<NotificationOperationInfo> operationInfo = new (std::nothrow) NotificationOperationInfo();
    if (operationInfo == nullptr) {
        ANS_LOGE("create operationInfo failed");
        return;
    }
    operationInfo->SetHashCode(asyncCallbackInfo->hashCode);
    if (asyncCallbackInfo->operationInfo.withOperationInfo) {
        operationInfo->SetOperationType(OperationType::DISTRIBUTE_OPERATION_REPLY);
        operationInfo->SetActionName(asyncCallbackInfo->operationInfo.actionName);
        operationInfo->SetUserInput(asyncCallbackInfo->operationInfo.userInput);
    } else {
        operationInfo->SetOperationType(OperationType::DISTRIBUTE_OPERATION_JUMP);
    }
    int32_t result = NotificationHelper::DistributeOperation(operationInfo, callback);
    if (result != ERR_OK || !asyncCallbackInfo->operationInfo.withOperationInfo) {
        callback->OnOperationCallback(result);
    }
}

void NapiDistributeOperationCompleteCallback(napi_env env, napi_status status, void *data)
{
    ANS_LOGI("DistributeOperation napi_create_async_work end");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    auto distributeOperationInfo = static_cast<AsyncOperationCallbackInfo *>(data);
    if (distributeOperationInfo) {
        napi_delete_async_work(env, distributeOperationInfo->asyncWork);
        delete distributeOperationInfo;
        distributeOperationInfo = nullptr;
    }
}

napi_value NapiSubscribe(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    napi_ref callback = nullptr;
    std::shared_ptr<SubscriberInstance> objectInfo = nullptr;
    NotificationSubscribeInfo subscriberInfo;
    if (ParseParameters(env, info, subscriberInfo, objectInfo, callback) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoSubscribe *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoSubscribe {
        .env = env, .asyncWork = nullptr, .objectInfo = objectInfo, .subscriberInfo = subscriberInfo
    };
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "subscribeNotification", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiSubscribe work excute.");
            if (!data) {
                ANS_LOGE("Invalid asynccallbackinfo!");
                return;
            }
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoSubscribe *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->subscriberInfo.hasSubscribeInfo) {
                    ANS_LOGI("Subscribe with NotificationSubscribeInfo");
                    sptr<OHOS::Notification::NotificationSubscribeInfo> subscribeInfo =
                        new (std::nothrow) OHOS::Notification::NotificationSubscribeInfo();
                    if (subscribeInfo == nullptr) {
                        ANS_LOGE("Invalid subscribeInfo!");
                        asynccallbackinfo->info.errorCode = OHOS::Notification::ErrorCode::ERR_ANS_NO_MEMORY;
                        return;
                    }
                    subscribeInfo->AddAppNames(asynccallbackinfo->subscriberInfo.bundleNames);
                    subscribeInfo->AddAppUserId(asynccallbackinfo->subscriberInfo.userId);
                    subscribeInfo->AddDeviceType(asynccallbackinfo->subscriberInfo.deviceType);
                    subscribeInfo->SetFilterType(asynccallbackinfo->subscriberInfo.filterType);
                    subscribeInfo->SetSlotTypes(asynccallbackinfo->subscriberInfo.slotTypes);
                    asynccallbackinfo->info.errorCode =
                        NotificationHelper::SubscribeNotification(asynccallbackinfo->objectInfo, subscribeInfo);
                } else {
                    asynccallbackinfo->info.errorCode =
                        NotificationHelper::SubscribeNotification(asynccallbackinfo->objectInfo);
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiSubscribe work complete.");
            if (!data) {
                ANS_LOGE("Invalid asynccallbackinfo!");
                return;
            }
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoSubscribe *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiSubscribe callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiSubscribe work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiSubscribe callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiSubscribeSelf(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    napi_ref callback = nullptr;
    std::shared_ptr<SubscriberInstance> objectInfo = nullptr;
    NotificationSubscribeInfo subscriberInfo;
    if (ParseParameters(env, info, subscriberInfo, objectInfo, callback) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoSubscribe *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoSubscribe {
        .env = env, .asyncWork = nullptr, .objectInfo = objectInfo, .subscriberInfo = subscriberInfo
    };
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "subscribeNotificationSelf", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiSubscribeSelf work excute.");
            if (!data) {
                ANS_LOGE("Invalid asynccallbackinfo!");
                return;
            }
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoSubscribe *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::SubscribeNotificationSelf(asynccallbackinfo->objectInfo);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiSubscribeSelf work complete.");
            if (!data) {
                ANS_LOGE("Invalid asynccallbackinfo!");
                return;
            }
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoSubscribe *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiSubscribeSelf callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiSubscribeSelf work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("NapiSubscribeSelf callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiUnsubscribe(napi_env env, napi_callback_info info)
{
    ANS_LOGI("Unsubscribe start");
    ParametersInfoUnsubscribe paras;
    if (ParseParameters(env, info, paras) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoUnsubscribe *asynccallbackinfo = new (std::nothrow)
        AsyncCallbackInfoUnsubscribe {.env = env, .asyncWork = nullptr, .objectInfo = paras.objectInfo};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, paras.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, paras.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "unsubscribe", NAPI_AUTO_LENGTH, &resourceName);

    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiUnsubscribe work excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoUnsubscribe *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->objectInfo == nullptr) {
                    ANS_LOGE("invalid object info");
                    asynccallbackinfo->info.errorCode = ERR_ANS_INVALID_PARAM;
                    return;
                }

                bool ret = AddDeletingSubscriber(asynccallbackinfo->objectInfo);
                if (ret) {
                    asynccallbackinfo->info.errorCode =
                        NotificationHelper::UnSubscribeNotification(asynccallbackinfo->objectInfo);
                    if (asynccallbackinfo->info.errorCode != ERR_OK) {
                        DelDeletingSubscriber(asynccallbackinfo->objectInfo);
                    }
                } else {
                    asynccallbackinfo->info.errorCode = ERR_ANS_SUBSCRIBER_IS_DELETING;
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiUnsubscribe work complete.");
            AsyncCallbackInfoUnsubscribe *asynccallbackinfo = static_cast<AsyncCallbackInfoUnsubscribe *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiUnsubscribe callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiUnsubscribe work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("napiUnsubscribe callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncDistributeOperationCall(napi_env env, AsyncOperationCallbackInfo* distributeOperationInfo)
{
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "distributeOperation", NAPI_AUTO_LENGTH, &resourceName);

    // Asynchronous function call
    napi_create_async_work(env, nullptr, resourceName, NapiDistributeOperationExecuteCallback,
        NapiDistributeOperationCompleteCallback, (void *)distributeOperationInfo, &distributeOperationInfo->asyncWork);
    auto result = napi_queue_async_work_with_qos(env, distributeOperationInfo->asyncWork, napi_qos_user_initiated);
    if (result != napi_ok) {
        NapiDistributeOperationCompleteCallback(env, result, distributeOperationInfo);
        NAPI_CALL_RETURN_VOID(env, result);
    }
}

napi_value NapiDistributeOperation(napi_env env, napi_callback_info info)
{
    ANS_LOGI("Distribute operation called");
    std::string hashCode;
    napi_value thisVar = nullptr;
    OperationInfo operationInfo;
    if (ParseParameters(env, info, hashCode, thisVar, operationInfo) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    napi_value ret = nullptr;
    napi_deferred deferred;
    napi_create_promise(env, &deferred, &ret);
    auto distributeOperationInfo = new (std::nothrow) AsyncOperationCallbackInfo {.env = env,
        .thisVar = thisVar, .deferred = deferred, .hashCode = hashCode, .operationInfo = operationInfo};
    if (distributeOperationInfo == nullptr) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::NapiGetNull(env);
    }

    AsyncDistributeOperationCall(env, distributeOperationInfo);
    return ret;
}
}  // namespace NotificationNapi
}  // namespace OHOS
