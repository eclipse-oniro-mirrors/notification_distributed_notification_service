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
        operationOnCallBack->operationResult = OHOS::Notification::ErrorToExternal(operationResult);
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
    napi_open_handle_scope(callBackPtr->env, &scope);
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
