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

#include "reminder_state_callback_proxy_ext.h"

namespace OHOS::Notification {
ErrCode ReminderStateCallbackProxyExt::OnReminderState(const std::vector<ReminderState>& states)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC | MessageOption::TF_ASYNC_WAKEUP_LATER);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_INVALID_VALUE;
    }
    if (states.size() > static_cast<size_t>(VECTOR_MAX_SIZE)) {
        return ERR_INVALID_DATA;
    }
    data.WriteInt32(states.size());
    for (auto it = states.begin(); it != states.end(); ++it) {
        if (!data.WriteParcelable(&(*it))) {
            return ERR_INVALID_DATA;
        }
    }

    sptr<IRemoteObject> remote = Remote();
    if (!remote) {
        return ERR_INVALID_DATA;
    }
    int32_t result = remote->SendRequest(
        static_cast<uint32_t>(IReminderStateCallbackIpcCode::COMMAND_ON_REMINDER_STATE), data, reply, option);
    if (FAILED(result)) {
        return result;
    }
    return ERR_OK;
}
}  // namespace OHOS::Notification