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

#include "ans_operation_callback_proxy.h"

#include "ans_log_wrapper.h"

namespace OHOS::Notification {
void OperationCallbackProxy::OnOperationCallback(int32_t operationResult)
{
    ANS_LOGD("enter");
    MessageParcel data;
    if (!data.WriteInterfaceToken(OperationCallbackProxy::GetDescriptor())) {
        ANS_LOGE("Write interface token failed.");
        return;
    }
    if (!data.WriteInt32(operationResult)) {
        ANS_LOGE("Write statusData failed.");
        return;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ANS_LOGE("Remote is NULL");
        return;
    }

    MessageParcel reply;
    MessageOption option;
    int error = remote->SendRequest(ON_DISTRIBUTED_OPERATION_CALLBACK, data, reply, option);
    if (error != ERR_OK) {
        ANS_LOGE("SendRequest fail, error: %{public}d", error);
    }
}
} // namespace OHOS::Notification

