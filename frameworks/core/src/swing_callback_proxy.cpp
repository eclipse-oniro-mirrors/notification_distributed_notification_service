/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include "swing_callback_proxy.h"

#include "ans_log_wrapper.h"
#include "event_handler.h"
#include "ipc_types.h"
#include "message_parcel.h"
#include "singleton.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace Notification {
int32_t SwingCallBackProxy::OnUpdateStatus(bool isEnable, int triggerMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(SwingCallBackProxy::GetDescriptor())) {
        ANS_LOGE("Write interface token failed.");
        return false;
    }

    if (!data.WriteInt8(static_cast<int8_t>(isEnable))) {
        ANS_LOGE("Connect done element error.");
        return false;
    }

    if (!data.WriteInt32(static_cast<int32_t>(triggerMode))) {
        ANS_LOGE("Connect done element error.");
        return false;
    }
    
    auto remote = Remote();
    if (remote == nullptr) {
        ANS_LOGE("Get Remote fail.");
        return false;
    }
    int error = remote->SendRequest(static_cast<uint32_t>(NotificationInterfaceCode::ON_UPDATE_STATUS),
        data, reply, option);
    if (error != NO_ERROR) {
        ANS_LOGE("Connect done fail, error: %{public}d", error);
        return false;
    }
    return reply.ReadInt32();
}
}
}
#endif