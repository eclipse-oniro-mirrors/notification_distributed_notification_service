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
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include "swing_callback_stub.h"

#include "ans_log_wrapper.h"
#include "event_handler.h"
#include "ipc_types.h"
#include "message_parcel.h"
#include "singleton.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace Notification {
SwingCallBackStub::SwingCallBackStub() {}
SwingCallBackStub::SwingCallBackStub(std::function<void(bool, int)> swingCallback) : swingCallback_(swingCallback) {}
SwingCallBackStub::~SwingCallBackStub() {}
int32_t SwingCallBackStub::OnUpdateStatus(bool isEnable, int triggerMode)
{
    return ERR_OK;
}
int SwingCallBackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ANS_LOGD("called.");
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ANS_LOGE("local descriptor is not equal to remote");
        return ERR_INVALID_STATE;
    }
    switch (code) {
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_UPDATE_STATUS): {
            bool isEnable = static_cast<bool>(data.ReadInt8());
            int triggerMode = static_cast<int>(data.ReadInt32());
            if (swingCallback_) {
                ANS_LOGI("swingCallback(isEnable: %{public}d, triggerMode: %{public}d)", isEnable, triggerMode);
                swingCallback_(isEnable, triggerMode);
                return NO_ERROR;
            }
            return ERR_UNKNOWN_OBJECT;
        }
        default:
            return ERR_INVALID_STATE;
    }
}
}
}
#endif