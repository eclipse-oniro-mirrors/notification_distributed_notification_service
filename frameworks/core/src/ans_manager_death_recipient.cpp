/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <unistd.h>

#include "ans_const_define.h"
#include "ans_log_wrapper.h"
#include "ans_notification.h"
#include "hisysevent.h"
#include "singleton.h"
#include "ans_manager_death_recipient.h"

namespace OHOS {
namespace Notification {
void AnsManagerDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    std::string eventType = "ANS_SERVICE_DIED";
    int32_t res = OHOS::HiviewDFX::HiSysEvent::Write(
        HiviewDFX::HiSysEvent::Domain::NOTIFICATION, eventType,
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "UID", getuid(),
        "PID", getpid());
    if (res != DH_ANS_SUCCESS) {
        ANS_LOGE("Write HiSysEvent error, res:%d", res);
    }
    ANS_LOGE("Ans service died");
    DelayedSingleton<AnsNotification>::GetInstance()->ResetAnsManagerProxy();
}
}  // namespace Notification
}  // namespace OHOS
