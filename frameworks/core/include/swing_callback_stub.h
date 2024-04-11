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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_SWING_CALLBACK_STUB_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_SWING_CALLBACK_STUB_H
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED

#include <iremote_object.h>
#include <iremote_stub.h>

#include "distributed_notification_service_ipc_interface_code.h"
#include "swing_callback_interface.h"
#include "swing_callback_stub.h"

namespace OHOS {
namespace Notification {
/**
 * @class SwingCallBackStub
 * SwingCallBack Stub.
 */
class SwingCallBackStub : public IRemoteStub<ISwingCallBack> {
public:
    SwingCallBackStub(std::function<void(bool, int)> swingCallback);
    SwingCallBackStub();
    virtual ~SwingCallBackStub();

    /**
     * OnUpdateStatus, update status.
     *
     * @param isEnable enable swing.
     * @param triggerMode trigger mode.
     * @return Returns true success, false fail.
     */
    int32_t OnUpdateStatus(bool isEnable, int triggerMode) override;

    /**
     * OnUpdateStatus, update status.
     *
     * @param isEnable enable swing.
     * @param triggerMode trigger mode.
     * @return Returns true success, false fail.
     */
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    std::function<void(bool, int)> swingCallback_;
    DISALLOW_COPY_AND_MOVE(SwingCallBackStub);
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_SWING_CALLBACK_STUB_H
#endif