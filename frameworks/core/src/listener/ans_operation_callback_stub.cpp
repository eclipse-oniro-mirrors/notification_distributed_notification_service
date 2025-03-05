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

#include "ans_operation_callback_stub.h"

#include "ans_log_wrapper.h"
#include "ans_inner_errors.h"

namespace OHOS::Notification {

void OperationCallbackStub::OnOperationCallback(int32_t operationResult)
{
}

int32_t OperationCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    auto descriptorToken = data.ReadInterfaceToken();
    if (descriptorToken != GetDescriptor()) {
        ANS_LOGE("Remote descriptor not the same as local descriptor.");
        return ERR_INVALID_STATE;
    }
    switch (code) {
        case ON_DISTRIBUTED_OPERATION_CALLBACK: {
            int32_t resultCode = 0;
            if (!data.ReadInt32(resultCode)) {
                ANS_LOGE("read result failed.");
                return ERR_ANS_PARCELABLE_FAILED;
            }
            OnOperationCallback(resultCode);
            break;
        }
        default: {
            return ERR_INVALID_STATE;
        }
    }
    return ERR_NONE;
}
} // namespace OHOS::Notification
