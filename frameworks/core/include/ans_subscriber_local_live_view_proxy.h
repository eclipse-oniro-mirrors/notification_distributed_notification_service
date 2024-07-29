/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_SUBSCRIBER_LOCAL_LIVE_VIEW_PROXY_H
#define BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_SUBSCRIBER_LOCAL_LIVE_VIEW_PROXY_H

#include "ans_subscriber_local_live_view_interface.h"
#include "distributed_notification_service_ipc_interface_code.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace Notification {
class AnsSubscriberLocalLiveViewProxy : public IRemoteProxy<AnsSubscriberLocalLiveViewInterface> {
public:
    AnsSubscriberLocalLiveViewProxy() = delete;
    explicit AnsSubscriberLocalLiveViewProxy(const sptr<IRemoteObject> &impl);
    ~AnsSubscriberLocalLiveViewProxy() override;
    DISALLOW_COPY_AND_MOVE(AnsSubscriberLocalLiveViewProxy);

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
    ErrCode InnerTransact(NotificationInterfaceCode code,
        MessageOption &flags, MessageParcel &data, MessageParcel &reply);
    static inline BrokerDelegator<AnsSubscriberLocalLiveViewProxy> delegator_;

    template<typename T>
    bool WriteParcelableVector(const std::vector<sptr<T>> &parcelableVector, MessageParcel &data)
    {
        if (!data.WriteInt32(parcelableVector.size())) {
            ANS_LOGE("write ParcelableVector size failed");
            return false;
        }

        for (auto &parcelable : parcelableVector) {
            if (!data.WriteStrongParcelable(parcelable)) {
                ANS_LOGE("write ParcelableVector failed");
                return false;
            }
        }
        return true;
    }
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_SUBSCRIBER_LOCAL_LIVE_VIEW_PROXY_H
