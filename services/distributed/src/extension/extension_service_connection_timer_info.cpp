/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "extension_service_connection_timer_info.h"

namespace OHOS {
namespace Notification {
void ExtensionServiceConnectionTimerInfo::SetType(const int &_type)
{
    type = _type;
}

void ExtensionServiceConnectionTimerInfo::SetRepeat(bool _repeat)
{
    repeat = _repeat;
}

void ExtensionServiceConnectionTimerInfo::SetInterval(const uint64_t &_interval)
{
    interval = _interval;
}

void ExtensionServiceConnectionTimerInfo::SetWantAgent(
    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> _wantAgent)
{
    wantAgent = _wantAgent;
}

void ExtensionServiceConnectionTimerInfo::OnTrigger()
{
    if (callback_ != nullptr) {
        callback_();
    }
}
}
}
