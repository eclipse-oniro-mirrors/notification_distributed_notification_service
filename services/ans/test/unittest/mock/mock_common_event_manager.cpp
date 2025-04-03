/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "mock_common_event_manager.h"

#include "common_event_manager.h"

namespace OHOS {
namespace Notification {
namespace {
bool g_publishCommonEventResult = true;
}

void MockPublishCommonEventResult(bool result)
{
    g_publishCommonEventResult = result;
}
} // Notification

namespace EventFwk {
bool CommonEventManager::PublishCommonEvent(const CommonEventData &data, const CommonEventPublishInfo &publishInfo)
{
    return Notification::g_publishCommonEventResult;
}
} // EventFwk
} // OHOS