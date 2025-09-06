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

#include "distributed_operation_connection.h"

#include "ans_log_wrapper.h"
#include "ability_manager_helper.h"

namespace OHOS {
namespace Notification {

constexpr int32_t EVENT_CALL_NOTIFY = 1;

void DistributedOperationConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    ANS_LOGI("Operation on connection %{public}s, %{public}s, %{public}s", element.GetAbilityName().c_str(),
        element.GetBundleName().c_str(), eventId_.c_str());
    if (remoteObject == nullptr) {
        AbilityManagerHelper::GetInstance().DisconnectServiceAbility(eventId_, element);
        return;
    }
    do {
        MessageParcel data;
        if (!data.WriteString16(to_utf16("com.ohos.notification_service.sendReply"))) {
            ANS_LOGE("OnAbilityConnectDone fail:: write inputKey failed");
            break;
        }
        if (!data.WriteString16(to_utf16(inputKey_))) {
            ANS_LOGE("OnAbilityConnectDone fail:: write inputKey failed");
            break;
        }
        if (!data.WriteString16(to_utf16(userInput_))) {
            ANS_LOGE("OnAbilityConnectDone fail:: write userInput failed");
            break;
        }
        MessageParcel reply;
        MessageOption option;
        int32_t result = remoteObject->SendRequest(EVENT_CALL_NOTIFY, data, reply, option);
        ANS_LOGI("Send call notify %{public}s %{public}s %{public}d", eventId_.c_str(), inputKey_.c_str(), result);
    } while (0);
    AbilityManagerHelper::GetInstance().DisconnectServiceAbility(eventId_, element);
}

void DistributedOperationConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    ANS_LOGI("Operation disconnection %{public}s, %{public}s, %{public}s", element.GetAbilityName().c_str(),
        element.GetBundleName().c_str(), eventId_.c_str());
}
}
}

