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

namespace OHOS {
namespace Notification {

PushCallBackStub::PushCallBackStub() {}

PushCallBackStub::~PushCallBackStub() {}

int PushCallBackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ANS_LOGI("PushCallBackStub::OnRemoteRequest called.");
    std::u16string descriptor = PushCallBackStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        ANS_LOGI("Local descriptor is not equal to remote");
        return ERR_INVALID_STATE;
    }
    switch (code) {
        case IPushCallBack::ON_CHECK_NOTIFICATION: {
            auto notificationData = data.ReadString();
            bool ret = OnCheckNotification(notificationData);
ANS_LOGI("PushCallBackStub::OnRemoteRequest ret:%{public}d", ret);
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

bool PushCallBackProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(PushCallBackProxy::GetDescriptor())) {
        ANS_LOGE("Write interface token failed.");
        return false;
    }
    return true;
}

bool PushCallBackProxy::OnCheckNotification(const std::string &notificationData)
{
    int error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
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

    error = remote->SendRequest(IPushCallBack::ON_CHECK_NOTIFICATION, data, reply, option);
    if (error != NO_ERROR) {
        ANS_LOGE("Connect done fail, error: %{public}d", error);
        return false;
    }

    return reply.ReadBool();
}

void PushCallbackRecipient::OnRemoteDied(const wptr<IRemoteObject> &__attribute__((unused)) remote)
{
    ANS_LOGE("On remote died.");
    if (handler_) {
        handler_(remote);
    }
}

PushCallbackRecipient::PushCallbackRecipient(RemoteDiedHandler handler) : handler_(handler) {}

PushCallbackRecipient::~PushCallbackRecipient() {}
} // namespace Notification
} // namespace OHOS
