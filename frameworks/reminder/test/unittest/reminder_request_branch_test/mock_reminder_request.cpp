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

#include "reminder_request.h"

namespace {
    bool g_mockNowInstantMilliRet = true;
    uint64_t g_mockNumber = 1675876480000;
}

void MockNowInstantMilli(bool mockRet)
{
    g_mockNowInstantMilliRet = mockRet;
}

namespace OHOS {
namespace Notification {
uint64_t ReminderRequest::GetNowInstantMilli() const
{
    if (g_mockNowInstantMilliRet == false) {
        return 0;
    }
    return g_mockNumber;
}
}  // namespace Notification
}  // namespace OHOS