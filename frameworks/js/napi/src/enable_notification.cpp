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

#include <uv.h>
#include "enable_notification.h"
#include "ability_manager_client.h"

namespace OHOS {
namespace NotificationNapi {
const int ENABLE_NOTIFICATION_MAX_PARA = 3;
const int ENABLE_NOTIFICATION_MIN_PARA = 2;
const int IS_NOTIFICATION_ENABLE_MAX_PARA = 2;

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, EnableParams &params)
{
    ANS_LOGI("enter");

    size_t argc = ENABLE_NOTIFICATION_MAX_PARA;
    napi_value argv[ENABLE_NOTIFICATION_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < ENABLE_NOTIFICATION_MIN_PARA) {
        ANS_LOGW("Wrong number of arguments.");
        return nullptr;
    }

    // argv[0]: bundle
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGW("Wrong argument type. Object expected.");
        return nullptr;
    }
    auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
    if (retValue == nullptr) {
        ANS_LOGE("GetBundleOption failed.");
        return nullptr;
    }

    // argv[1]: enable
    NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
    if (valuetype != napi_boolean) {
        ANS_LOGW("Wrong argument type. Bool expected.");
        return nullptr;
    }
    napi_get_value_bool(env, argv[PARAM1], &params.enable);

    // argv[2]:callback
    if (argc >= ENABLE_NOTIFICATION_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM2], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGW("Wrong argument type. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[PARAM2], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, IsEnableParams &params)
{
    ANS_LOGI("enter");

    size_t argc = IS_NOTIFICATION_ENABLE_MAX_PARA;
    napi_value argv[IS_NOTIFICATION_ENABLE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    if (argc == 0) {
        return Common::NapiGetNull(env);
    }

    // argv[0]: bundle / userId / callback
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if ((valuetype != napi_object) && (valuetype != napi_number) && (valuetype != napi_function)) {
        ANS_LOGW("Wrong argument type. Function or object expected.");
        return nullptr;
    }
    if (valuetype == napi_object) {
        auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
        if (retValue == nullptr) {
            ANS_LOGE("GetBundleOption failed.");
            return nullptr;
        }
        params.hasBundleOption = true;
    } else if (valuetype == napi_number) {
        NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM0], &params.userId));
        params.hasUserId = true;
    } else {
        napi_create_reference(env, argv[PARAM0], 1, &params.callback);
    }

    // argv[1]:callback
    if (argc >= IS_NOTIFICATION_ENABLE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGW("Wrong argument type. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[PARAM1], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

void AsyncCompleteCallbackEnableNotification(napi_env env, napi_status status, void *data)
{
    ANS_LOGI("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackInfoEnable *asynccallbackinfo = static_cast<AsyncCallbackInfoEnable *>(data);
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

napi_value EnableNotification(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");

    EnableParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoEnable *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoEnable {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "enableNotification", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("EnableNotification napi_create_async_work start");
            AsyncCallbackInfoEnable *asynccallbackinfo = static_cast<AsyncCallbackInfoEnable *>(data);
            if (asynccallbackinfo) {
                std::string deviceId {""};
                asynccallbackinfo->info.errorCode = NotificationHelper::SetNotificationsEnabledForSpecifiedBundle(
                    asynccallbackinfo->params.option, deviceId, asynccallbackinfo->params.enable);
                ANS_LOGI("asynccallbackinfo->info.errorCode = %{public}d", asynccallbackinfo->info.errorCode);
            }
        },
        AsyncCompleteCallbackEnableNotification,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work(env, asynccallbackinfo->asyncWork));

    if (asynccallbackinfo->info.isCallback) {
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackIsNotificationEnabled(napi_env env, napi_status status, void *data)
{
    ANS_LOGI("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackInfoIsEnable *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnable *>(data);
    if (asynccallbackinfo) {
        napi_value result = nullptr;
        napi_get_boolean(env, asynccallbackinfo->allowed, &result);
        if (asynccallbackinfo->newInterface) {
            Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        } else {
            Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
        }
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value IsNotificationEnabled(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");

    IsEnableParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoIsEnable *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoIsEnable {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "isNotificationEnabled", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("IsNotificationEnabled napi_create_async_work start");
            AsyncCallbackInfoIsEnable *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnable *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->params.hasBundleOption) {
                    ANS_LOGI("option.bundle = %{public}s option.uid = %{public}d",
                        asynccallbackinfo->params.option.GetBundleName().c_str(),
                        asynccallbackinfo->params.option.GetUid());
                    asynccallbackinfo->info.errorCode = NotificationHelper::IsAllowedNotify(
                        asynccallbackinfo->params.option, asynccallbackinfo->allowed);
                } else if (asynccallbackinfo->params.hasUserId) {
                    ANS_LOGI("userId = %{public}d", asynccallbackinfo->params.userId);
                    asynccallbackinfo->info.errorCode = NotificationHelper::IsAllowedNotify(
                        asynccallbackinfo->params.userId, asynccallbackinfo->allowed);
                } else {
                    asynccallbackinfo->info.errorCode = NotificationHelper::IsAllowedNotify(
                        asynccallbackinfo->allowed);
                }
                ANS_LOGI("asynccallbackinfo->info.errorCode = %{public}d, allowed = %{public}d",
                    asynccallbackinfo->info.errorCode, asynccallbackinfo->allowed);
            }
        },
        AsyncCompleteCallbackIsNotificationEnabled,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work(env, asynccallbackinfo->asyncWork));

    if (asynccallbackinfo->info.isCallback) {
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value IsNotificationEnabledSelf(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");

    IsEnableParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoIsEnable *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoIsEnable {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "IsNotificationEnabledSelf", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("IsNotificationEnabledSelf napi_create_async_work start");
            AsyncCallbackInfoIsEnable *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnable *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->params.hasBundleOption) {
                    ANS_LOGE("Not allowed to query another application");
                } else {
                    asynccallbackinfo->info.errorCode = NotificationHelper::IsAllowedNotifySelf(asynccallbackinfo->allowed);
                }
                ANS_LOGI("asynccallbackinfo->info.errorCode = %{public}d, allowed = %{public}d",
                    asynccallbackinfo->info.errorCode, asynccallbackinfo->allowed);
            }
        },
        AsyncCompleteCallbackIsNotificationEnabled,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    NAPI_CALL(env, napi_queue_async_work(env, asynccallbackinfo->asyncWork));

    if (asynccallbackinfo->info.isCallback) {
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value RequestEnableNotification(napi_env env, napi_callback_info info)
{
    ANS_LOGI("enter");

    IsEnableParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoIsEnable *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoIsEnable {.env = env, .asyncWork = nullptr, .params = params};

    if (!asynccallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "RequestEnableNotification", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            AsyncCallbackInfoIsEnable *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnable *>(data);
            if (asynccallbackinfo) {
                std::string deviceId {""};
                bool popFlag = false;
                asynccallbackinfo->info.errorCode = NotificationHelper::RequestEnableNotification(deviceId, popFlag);
                asynccallbackinfo->params.allowToPop = popFlag;
                ANS_LOGI("errorCode = %{public}d, allowToPop = %{public}d",
                        asynccallbackinfo->info.errorCode, asynccallbackinfo->params.allowToPop);
                if (asynccallbackinfo->info.errorCode == ERR_OK && asynccallbackinfo->params.allowToPop) {
                    ANS_LOGI("Begin to start notification dialog");
                    auto *callbackInfo = static_cast<AsyncCallbackInfoIsEnable *>(data);
                    StartNotificationDialog(callbackInfo);
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            AsyncCallbackInfoIsEnable *asynccallbackinfo = static_cast<AsyncCallbackInfoIsEnable *>(data);
            if (asynccallbackinfo) {
                if (!(asynccallbackinfo->info.errorCode == ERR_OK && asynccallbackinfo->params.allowToPop)) {
                    AsyncCompleteCallbackIsNotificationEnabled(env, status, data);
                }
            }
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

void StartNotificationDialog(AsyncCallbackInfoIsEnable *callbackInfo)
{
    ANS_LOGD("%{public}s, Begin Calling StartNotificationDialog.", __func__);
    if (CreateCallbackStubImpl(callbackInfo)) {
        sptr<IRemoteObject> token;
        auto result = AAFwk::AbilityManagerClient::GetInstance()->GetTopAbility(token);
        if (result == ERR_OK) {
            AAFwk::Want want;
            want.SetElementName("com.ohos.amsdialog", "EnableNotificationDialog");
            want.SetParam("callbackStubImpl_", callbackStubImpl_);
            want.SetParam("tokenId", token);
            want.SetParam("from", AAFwk::AbilityManagerClient::GetInstance()->GetTopAbility().GetBundleName());
            ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, token, -1);
            ANS_LOGD("%{public}s, End Calling StartNotificationDialog. ret=%{public}d", __func__, err);
        } else {
            ANS_LOGE("%{public}s, show notification dialog failed", __func__);
            ResetCallbackStubImpl();
        }
    }
}

bool CreateCallbackStubImpl(AsyncCallbackInfoIsEnable *callbackInfo)
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (callbackStubImpl_ != nullptr) {
        return false;
    }
    callbackStubImpl_ = new (std::nothrow) CallbackStubImpl(callbackInfo);
    return true;
}

void ResetCallbackStubImpl()
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    callbackStubImpl_ = nullptr;
}

bool CallbackStubImpl::OnEnableNotification(bool isAllow)
{
    ANS_LOGI("isAllow: %{public}d", isAllow);
    if (!task_ || !task_->env) {
        ANS_LOGW("invalid task.");
        return false;
    }

    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(task_->env, &loop);
    if (!loop) {
        ANS_LOGW("failed to get loop from env.");
        delete task_;
        task_ = nullptr;
        return false;
    }

    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        ANS_LOGW("uv_work_t instance is nullptr");
        delete task_;
        task_ = nullptr;
        return false;
    }

    task_->allowed = isAllow;
    work->data = reinterpret_cast<void *>(task_);
    int ret = uv_queue_work(loop, work, [](uv_work_t *work) {},
        [](uv_work_t *work, int status) {
            auto task_ = static_cast<AsyncCallbackInfoIsEnable*>(work->data);
            napi_value result = nullptr;
            napi_get_boolean(task_->env, task_->allowed, &result);
            if (task_->newInterface) {
                Common::CreateReturnValue(task_->env, task_->info, result);
            } else {
                Common::ReturnCallbackPromise(task_->env, task_->info, result);
            }
            if (task_->info.callback != nullptr) {
                napi_delete_reference(task_->env, task_->info.callback);
            }
            napi_delete_async_work(task_->env, task_->asyncWork);
            delete task_;
            task_ = nullptr;
            delete work;
            work = nullptr;
        });
    if (ret != 0) {
        ANS_LOGW("failed to insert work into queue");
        delete task_;
        task_ = nullptr;
        delete work;
        work = nullptr;
        return false;
    }
    return true;
}

}  // namespace NotificationNapi
}  // namespace OHOS
