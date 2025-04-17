/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "mock_time_service_client.h"
#include "time_service_client.h"

namespace OHOS {
namespace Notification {
namespace {
bool g_mockCreateTimerFailed = false;
}

void MockCreateTimerFailed(bool mockCreateTimerFailed)
{
    g_mockCreateTimerFailed = mockCreateTimerFailed;
}

} // namespace Notification
} // namespace OHOS

namespace OHOS {
namespace MiscServices {

uint64_t TimeServiceClient::CreateTimer(std::shared_ptr<ITimerInfo> timerOptions)
{
    if (Notification::g_mockCreateTimerFailed) {
        return 0;
    }

    return 1;
}

} // namespace MiscServices
} // namespace OHOS