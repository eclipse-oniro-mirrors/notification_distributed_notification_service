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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_SWING_CALLBACK_PROXY_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_SWING_CALLBACK_PROXY_H
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED

#include "distributed_notification_service_ipc_interface_code.h"
#include "swing_callback_interface.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace Notification {
/**
 * @class SwingCallBackProxy
 * SwingCallBack proxy.
 */
class SwingCallBackProxy : public IRemoteProxy<ISwingCallBack> {
public:
    explicit SwingCallBackProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<ISwingCallBack>(impl)
    {}

    virtual ~SwingCallBackProxy()
    {}

    /**
     * OnUpdateStatus, update status.
     *
     * @param isEnable enable swing.
     * @param triggerMode trigger mode.
     * @return Returns true success, false fail.
     */
    int32_t OnUpdateStatus(bool isEnable, int triggerMode) override;

private:
    static inline BrokerDelegator<SwingCallBackProxy> delegator_;
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_SWING_CALLBACK_PROXY_H
#endif