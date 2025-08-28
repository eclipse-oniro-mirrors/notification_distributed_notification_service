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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PUSH_CALLBACK_PROXY_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PUSH_CALLBACK_PROXY_H

#include "push_callback_interface.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace Notification {
/**
 * @class PushCallBackProxy
 * PushCallBackProxy proxy.
 */
class PushCallBackProxy : public IRemoteProxy<IPushCallBack> {
public:
    explicit PushCallBackProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IPushCallBack>(impl)
    {}

    virtual ~PushCallBackProxy()
    {}

    /**
     * OnCheckNotification, check notification.
     *
     * @param notificationData notification data.
     * @return Returns true display, false no display.
     */
    int32_t OnCheckNotification(
        const std::string &notificationData, const std::shared_ptr<PushCallBackParam> &pushCallBackParam) override;

    int32_t OnCheckLiveView(const std::string& requestId, const std::vector<std::string>& bundles) override;

    void HandleEventControl(std::string eventControl, const std::shared_ptr<PushCallBackParam> &pushCallBackParam);
private:
    static inline BrokerDelegator<PushCallBackProxy> delegator_;
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PUSH_CALLBACK_PROXY_H
