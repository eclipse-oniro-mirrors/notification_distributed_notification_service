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

#ifndef BASE_NOTIFICATION_ANS_DISTRIBUTED_OPERATION_CALLBACK_PROXY_H
#define BASE_NOTIFICATION_ANS_DISTRIBUTED_OPERATION_CALLBACK_PROXY_H

#include "ans_operation_callback_interface.h"

#include "iremote_proxy.h"

namespace OHOS::Notification {
class OperationCallbackProxy : public IRemoteProxy<OperationCallbackInterface> {
public:
    explicit OperationCallbackProxy(const sptr<IRemoteObject> &impl)
        : IRemoteProxy<OperationCallbackInterface>(impl) {}
    ~OperationCallbackProxy() override = default;
    DISALLOW_COPY_AND_MOVE(OperationCallbackProxy);
    void OnOperationCallback(int32_t operationResult) override;

private:
    static inline BrokerDelegator<OperationCallbackProxy> delegator_;
};
} // namespace OHOS::Notification

#endif // BASE_NOTIFICATION_ANS_DISTRIBUTED_OPERATION_CALLBACK_PROXY_H
