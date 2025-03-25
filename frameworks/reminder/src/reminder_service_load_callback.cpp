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

#include "reminder_service_load_callback.h"

#include "ans_log_wrapper.h"
#include "reminder_request_client.h"
#include "singleton.h"

namespace OHOS { class IRemoteObject; }
namespace OHOS {
namespace Notification {

void ReminderServiceCallback::OnLoadSystemAbilitySuccess(
    int32_t systemAbilityId, const sptr<IRemoteObject> &remoteObject)
{
    DelayedSingleton<ReminderRequestClient>::GetInstance()->LoadSystemAbilitySuccess(remoteObject);
    ANS_LOGI("on load system ability success!");
}

void ReminderServiceCallback::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    DelayedSingleton<ReminderRequestClient>::GetInstance()->LoadSystemAbilityFail();
    ANS_LOGE("on load system ability failed!");
}
}
}