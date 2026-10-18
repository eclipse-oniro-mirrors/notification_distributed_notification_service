/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "distributed_operation_callback.h"
#include "ans_inner_errors.h"
#include "uv_queue.h"

namespace OHOS {
namespace NotificationNapi {
namespace {
struct OperationRejectWorkData {
    napi_env env = nullptr;
    napi_deferred deferred = nullptr;
    napi_async_work asyncWork = nullptr;
};

// Fallback for the case where the handle scope cannot be opened in the uv after callback:
// settle the promise via a new async work (rejected with 1600001) instead of leaving it
// pending forever.
void RejectPromiseByAsyncWork(napi_env env, napi_deferred deferred)
{
    if (env == nullptr || deferred == nullptr) {
        ANS_LOGE("invalid env or deferred");
        return;
    }
    auto *data = new (std::nothrow) OperationRejectWorkData();
    if (data == nullptr) {
        ANS_LOGE("null OperationRejectWorkData");
        return;
    }
    data->env = env;
    data->deferred = deferred;
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "OperationCallbackReject", NAPI_AUTO_LENGTH, &resourceName);
    napi_status status = napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {},
        [](napi_env env, napi_status status, void *data) {
            auto *rejectData = static_cast<OperationRejectWorkData *>(data);
            if (rejectData == nullptr) {
                return;
            }
            if (env != nullptr && status == napi_ok) {
                if (rejectData->deferred != nullptr) {
                    Common::SetPromise(env, rejectData->deferred, ERROR_INTERNAL_ERROR,
                        Common::NapiGetNull(env), false);
                }
            } else {
                // Env destroyed or work cancelled (typically during env teardown): any JS
                // operation would crash, skip the promise settlement and only clean up.
                ANS_LOGW("skip promise settle, env: %{public}p, status: %{public}d",
                    env, static_cast<int32_t>(status));
            }
            if (env != nullptr && rejectData->asyncWork != nullptr) {
                napi_delete_async_work(env, rejectData->asyncWork);
            }
            delete rejectData;
        },
        data, &data->asyncWork);
    if (status != napi_ok) {
        ANS_LOGE("create reject async work failed: %{public}d", status);
        delete data;
        return;
    }
    status = napi_queue_async_work(env, data->asyncWork);
    if (status != napi_ok) {
        ANS_LOGE("queue reject async work failed: %{public}d", status);
        napi_delete_async_work(env, data->asyncWork);
        delete data;
        return;
    }
}
}  // namespace

DistributedOperationCallback::DistributedOperationCallback(const AsyncOperationCallbackInfo &asyncCallbackInfo)
{
    asyncCallbackInfo_ = asyncCallbackInfo;
}

DistributedOperationCallback::~DistributedOperationCallback()
{
}

ErrCode DistributedOperationCallback::OnOperationCallback(const int32_t operationResult)
{
    OperationOnCallBack *operationOnCallBack = new (std::nothrow) OperationOnCallBack();
    if (operationOnCallBack == nullptr) {
        ANS_LOGE("null operationOnCallBack");
        return ERR_INVALID_DATA;
    }

    if (operationResult != ERR_OK) {
        operationOnCallBack->operationResult =
            OHOS::Notification::NativeErrorToExternal(static_cast<uint32_t>(operationResult));
    } else {
        operationOnCallBack->operationResult = operationResult;
    }
    operationOnCallBack->env = asyncCallbackInfo_.env;
    operationOnCallBack->deferred = asyncCallbackInfo_.deferred;
    bool bRet = UvQueue::Call(asyncCallbackInfo_.env, operationOnCallBack, UvWorkOnCallBack);
    if (!bRet) {
        ANS_LOGE("OnCallBack failed");
    }
    return ERR_OK;
}

void DistributedOperationCallback::UvWorkOnCallBack(uv_work_t *work, int32_t status)
{
    if (work == nullptr) {
        ANS_LOGE("null work");
        return;
    }
    OperationOnCallBack *callBackPtr = static_cast<OperationOnCallBack *>(work->data);
    if (callBackPtr == nullptr) {
        ANS_LOGE("null callBackPtr");
        if (work != nullptr) {
            delete work;
            work = nullptr;
        }
        return;
    }

    napi_handle_scope scope = nullptr;
    auto retStatus = napi_open_handle_scope(callBackPtr->env, &scope);
    if (retStatus != napi_ok || scope == nullptr) {
        ANS_LOGE("status: %{public}d", retStatus);
        RejectPromiseByAsyncWork(callBackPtr->env, callBackPtr->deferred);
        delete callBackPtr;
        callBackPtr = nullptr;
        delete work;
        work = nullptr;
        return;
    }

    if (callBackPtr->deferred) {
        Common::SetPromise(callBackPtr->env, callBackPtr->deferred, callBackPtr->operationResult,
            Common::NapiGetNull(callBackPtr->env), false);
    }
    napi_close_handle_scope(callBackPtr->env, scope);
    if (callBackPtr != nullptr) {
        delete callBackPtr;
        callBackPtr = nullptr;
    }
    if (work != nullptr) {
        delete work;
        work = nullptr;
    }
    ANS_LOGD("end");
}
}  // namespace NotificationNapi
}  // namespace OHOS
