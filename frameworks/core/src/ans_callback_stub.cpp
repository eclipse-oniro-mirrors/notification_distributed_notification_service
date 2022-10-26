/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "ans_callback_stub.h"

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "message_option.h"
#include "message_parcel.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
int32_t AnsCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &flags)
{
    ANS_LOGI("enter");
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != AnsCallbackStub::GetDescriptor()) {
        ANS_LOGW("[OnRemoteRequest] fail: invalid interface token!");
        return OBJECT_NULL;
    }

    if (InterfaceCode::ON_ENABLE_NOTIFICATION_CALLBACK == code) {
        bool result = false;
        if (!data.ReadBool(result)) {
            ANS_LOGE("Notification not allowed by user.");
            return ERR_ANS_PERMISSION_DENIED;
        }
        ANS_LOGD("result =  %{public}d", result);
        OnEnableNotification(result);
    } else {
        ANS_LOGW("[OnRemoteRequest] fail: unknown code! %{public}d", code);
        return IRemoteStub<AnsCallbackInterface>::OnRemoteRequest(code, data, reply, flags);
    }
    return NO_ERROR;
}
}  // namespace Notification
}  // namespace OHOS
