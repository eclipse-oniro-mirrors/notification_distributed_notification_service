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

#ifndef BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_SUBSCRIBER_LOCAL_LIVE_VIEW_STUB_H
#define BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_SUBSCRIBER_LOCAL_LIVE_VIEW_STUB_H

#include "ans_subscriber_local_live_view_interface.h"
#include "distributed_notification_service_ipc_interface_code.h"
#include "iremote_stub.h"

namespace OHOS {
namespace Notification {
class AnsSubscriberLocalLiveViewStub : public IRemoteStub<AnsSubscriberLocalLiveViewInterface> {
public:
    AnsSubscriberLocalLiveViewStub();
    ~AnsSubscriberLocalLiveViewStub() override;
    DISALLOW_COPY_AND_MOVE(AnsSubscriberLocalLiveViewStub);

    /**
     * @brief Handle remote request.
     *
     * @param data Indicates the input parcel.
     * @param reply Indicates the output parcel.
     * @param option Indicates the message option.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    /**
     * @brief The callback function for the subscriber to establish a connection.
     */
    void OnConnected() override;

    /**
     * @brief The callback function for subscriber disconnected.
     */
    void OnDisconnected() override;

    void OnResponse(int32_t notificationId, sptr<NotificationButtonOption> buttonOption) override;

private:

    ErrCode HandleOnConnected(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleOnDisconnected(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleOnResponse(MessageParcel &data, MessageParcel &reply);

    template<typename T>
    bool ReadParcelableVector(std::vector<sptr<T>> &parcelableInfos, MessageParcel &data);
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_SUBSCRIBER_LOCAL_LIVE_VIEW_STUB_H
