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

#include "notification.h"

namespace {
    bool g_mockGetUserIdRet = true;
    bool g_mockGetBundleNameRet = true;
}

void MockGetUserId(bool mockRet)
{
    g_mockGetUserIdRet = mockRet;
}

void MockGetBundleName(bool mockRet)
{
    g_mockGetBundleNameRet = mockRet;
}

namespace OHOS {
namespace Notification {
int32_t Notification::GetUserId() const
{
    if (g_mockGetUserIdRet == false) {
        return -1;
    }
    return 1;
}

std::string Notification::GetBundleName() const
{
    if (g_mockGetBundleNameRet == false) {
        return "";
    }
    return "<bundle>";
}
}  // namespace Notification
}  // namespace OHOS