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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PUSH_CALLBACK_STUB_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PUSH_CALLBACK_STUB_H

#include <iremote_object.h>
#include <iremote_stub.h>

#include "distributed_notification_service_ipc_interface_code.h"
#include "push_callback_interface.h"
#include "nocopyable.h"

namespace OHOS {
namespace Notification {
/**
 * @class PushCallBackStub
 * PushCallBack Stub.
 */
class PushCallBackStub : public IRemoteStub<IPushCallBack> {
public:
    PushCallBackStub();
    virtual ~PushCallBackStub();

    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    int OnCheckLiveView(const std::string& requestId, const std::vector<std::string>& bundles) override { return 0; }
    ErrCode ConvertPushCheckCodeToErrCode(int32_t pushCheckCode);

private:
    DISALLOW_COPY_AND_MOVE(PushCallBackStub);
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PUSH_CALLBACK_STUB_H
