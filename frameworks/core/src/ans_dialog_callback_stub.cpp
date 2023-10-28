/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "ans_dialog_callback_stub.h"

#include "ans_log_wrapper.h"

namespace OHOS::Notification {
int32_t AnsDialogCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    if (code != AnsDialogCallback::ON_DIALOG_STATUS_CHANGED ||
        data.ReadInterfaceToken() != AnsDialogCallback::GetDescriptor()) {
        ANS_LOGE("Invalid request.");
        return ERR_INVALID_STATE;
    }

    std::unique_ptr<DialogStatusData> result(data.ReadParcelable<DialogStatusData>());
    if (result == nullptr) {
        ANS_LOGE("DialogStatusData is nullptr");
        return ERR_INVALID_STATE;
    }
    OnDialogStatusChanged(*result);
    return ERR_NONE;
}
} // namespace OHOS::Notification
