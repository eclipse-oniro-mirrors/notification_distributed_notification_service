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

#include "ans_subscriber_local_live_view_proxy.h"

#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "message_option.h"
#include "message_parcel.h"

namespace OHOS {
namespace Notification {
AnsSubscriberLocalLiveViewProxy::AnsSubscriberLocalLiveViewProxy(
    const sptr<IRemoteObject> &impl) : IRemoteProxy<AnsSubscriberLocalLiveViewInterface>(impl)
{}

AnsSubscriberLocalLiveViewProxy::~AnsSubscriberLocalLiveViewProxy()
{}

ErrCode AnsSubscriberLocalLiveViewProxy::InnerTransact(
    NotificationInterfaceCode code, MessageOption &flags, MessageParcel &data, MessageParcel &reply)
{
    auto remote = Remote();
    if (remote == nullptr) {
        ANS_LOGE("[InnerTransact] fail: get Remote fail code %{public}u", code);
        return ERR_DEAD_OBJECT;
    }

    int32_t err = remote->SendRequest(static_cast<uint32_t>(code), data, reply, flags);
    switch (err) {
        case NO_ERROR: {
            return ERR_OK;
        }
        case DEAD_OBJECT: {
            ANS_LOGE("[InnerTransact] fail: ipcErr=%{public}d code %{public}d", err, code);
            return ERR_DEAD_OBJECT;
        }
        default: {
            ANS_LOGE("[InnerTransact] fail: ipcErr=%{public}d code %{public}d", err, code);
            return ERR_ANS_TRANSACT_FAILED;
        }
    }
}

void AnsSubscriberLocalLiveViewProxy::OnConnected()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsSubscriberLocalLiveViewProxy::GetDescriptor())) {
        ANS_LOGE("[OnConnected] fail: write interface token failed.");
        return;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_ASYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ON_CONNECTED, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[OnConnected] fail: transact ErrCode=ERR_ANS_TRANSACT_FAILED");
        return;
    }
}

void AnsSubscriberLocalLiveViewProxy::OnDisconnected()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsSubscriberLocalLiveViewProxy::GetDescriptor())) {
        ANS_LOGE("[OnDisconnected] fail: write interface token failed.");
        return;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_ASYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ON_DISCONNECTED, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[OnDisconnected] fail: transact ErrCode=ERR_ANS_TRANSACT_FAILED");
        return;
    }
}


void AnsSubscriberLocalLiveViewProxy::OnResponse(int32_t notificationId, sptr<NotificationButtonOption> buttonOption)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsSubscriberLocalLiveViewProxy::GetDescriptor())) {
        ANS_LOGE("[OnResponse] fail: write interface token failed.");
        return;
    }

    if (!data.WriteInt32(notificationId)) {
        ANS_LOGE("[OnResponse] fail: write notificationId failed");
        return;
    }

    if (!data.WriteParcelable(buttonOption)) {
        ANS_LOGE("[OnResponse] fail: write buttonName failed");
        return;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_ASYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ON_RESPONSE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[OnResponse] fail: transact ErrCode=ERR_ANS_TRANSACT_FAILED");
        return;
    }
}
}  // namespace Notification
}  // namespace OHOS
