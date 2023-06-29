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

#include "push_callback_stub.h"

#include "ans_log_wrapper.h"
#include "ipc_types.h"
#include "message_parcel.h"
#include "push_callback_proxy.h"
#include "singleton.h"

namespace OHOS {
namespace Notification {
PushCallBackStub::PushCallBackStub() {}

PushCallBackStub::~PushCallBackStub() {}

int PushCallBackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ANS_LOGD("called.");
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ANS_LOGE("local descriptor is not equal to remote");
        return ERR_INVALID_STATE;
    }
    switch (code) {
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_CHECK_NOTIFICATION): {
            auto notificationData = data.ReadString();
            bool ret = OnCheckNotification(notificationData);
            ANS_LOGI("ret:%{public}d", ret);
            if (!reply.WriteBool(ret)) {
                ANS_LOGE("Failed to write reply ");
                return ERR_INVALID_REPLY;
            }
            return NO_ERROR;
        }
        default: {
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
}

bool PushCallBackProxy::OnCheckNotification(const std::string &notificationData)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(PushCallBackProxy::GetDescriptor())) {
        ANS_LOGE("Write interface token failed.");
        return false;
    }

    if (!data.WriteString(notificationData)) {
        ANS_LOGE("Connect done element error.");
        return false;
    }

    auto remote = Remote();
    if (remote == nullptr) {
        ANS_LOGE("Get Remote fail.");
        return false;
    }

    int error = remote->SendRequest(static_cast<uint32_t>(NotificationInterfaceCode::ON_CHECK_NOTIFICATION), data, reply, option);
    if (error != NO_ERROR) {
        ANS_LOGE("Connect done fail, error: %{public}d", error);
        return false;
    }

    return reply.ReadBool();
}
} // namespace Notification
} // namespace OHOS
