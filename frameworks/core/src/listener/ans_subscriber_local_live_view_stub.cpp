/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ans_subscriber_local_live_view_stub.h"

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "message_option.h"
#include "message_parcel.h"
#include "notification_bundle_option.h"
#include "notification_button_option.h"
#include "parcel.h"
#include "refbase.h"
#include <string>

namespace OHOS {
namespace Notification {
AnsSubscriberLocalLiveViewStub::AnsSubscriberLocalLiveViewStub() {}

AnsSubscriberLocalLiveViewStub::~AnsSubscriberLocalLiveViewStub() {}

int32_t AnsSubscriberLocalLiveViewStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &flags)
{
    std::u16string descriptor = AnsSubscriberLocalLiveViewStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        ANS_LOGW("[OnRemoteRequest] fail: invalid interface token!");
        return OBJECT_NULL;
    }
    ErrCode result = NO_ERROR;
    switch (code) {
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_CONNECTED): {
            result = HandleOnConnected(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_DISCONNECTED): {
            result = HandleOnDisconnected(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_RESPONSE): {
            result = HandleOnResponse(data, reply);
            break;
        }
        default: {
            ANS_LOGE("[OnRemoteRequest] fail: unknown code!");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, flags);
        }
    }
    return result;
}

ErrCode AnsSubscriberLocalLiveViewStub::HandleOnConnected(MessageParcel &data, MessageParcel &reply)
{
    OnConnected();
    return ERR_OK;
}

ErrCode AnsSubscriberLocalLiveViewStub::HandleOnDisconnected(MessageParcel &data, MessageParcel &reply)
{
    OnDisconnected();
    return ERR_OK;
}

template <typename T>
bool AnsSubscriberLocalLiveViewStub::ReadParcelableVector(std::vector<sptr<T>> &parcelableInfos, MessageParcel &data)
{
    int32_t infoSize = 0;
    if (!data.ReadInt32(infoSize)) {
        ANS_LOGE("read Parcelable size failed.");
        return false;
    }

    parcelableInfos.clear();
    infoSize = (infoSize < MAX_PARCELABLE_VECTOR_NUM) ? infoSize : MAX_PARCELABLE_VECTOR_NUM;
    for (int32_t index = 0; index < infoSize; index++) {
        sptr<T> info = data.ReadStrongParcelable<T>();
        if (info == nullptr) {
            ANS_LOGE("read Parcelable infos failed.");
            return false;
        }
        parcelableInfos.emplace_back(info);
    }

    return true;
}

ErrCode AnsSubscriberLocalLiveViewStub::HandleOnResponse(MessageParcel &data, MessageParcel &reply)
{
    int32_t notificationId = 0;
    if (!data.ReadInt32(notificationId)) {
        ANS_LOGE("[HandleOnResponse] fail : read notificationId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    sptr<NotificationButtonOption> buttonOption = nullptr;
    buttonOption = data.ReadParcelable<NotificationButtonOption>();
    if (buttonOption == nullptr) {
        ANS_LOGE("[HandleOnResponse] fail : read buttonOption failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    OnResponse(notificationId, buttonOption);
    return ERR_OK;
}

void AnsSubscriberLocalLiveViewStub::OnConnected() {}

void AnsSubscriberLocalLiveViewStub::OnDisconnected() {}

void AnsSubscriberLocalLiveViewStub::OnResponse(int32_t notificationId, sptr<NotificationButtonOption> buttonOption) {}
} // namespace Notification
} // namespace OHOS
