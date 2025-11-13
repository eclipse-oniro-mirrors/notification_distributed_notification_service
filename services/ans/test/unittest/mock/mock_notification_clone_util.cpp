/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "mock_notification_clone_util.h"

#include "notification_clone_util.h"
#include "ans_ut_constant.h"
namespace OHOS {
namespace Notification {

int32_t g_MockActiveUserId = 100;
int32_t g_MockUid = NON_SYSTEM_APP_UID;
bool g_funcGetActiveUserIdIsCalled = false;
bool g_funcGetBundleUidIsCalled = false;

void MockSetActiveUserIdForClone(int32_t userId)
{
    g_MockActiveUserId = userId;
}

void MockSetBundleUidForClone(int32_t uid)
{
    g_MockUid = uid;
}

void SetFuncGetActiveUserIdIsCalled(bool funcGetActiveUserIdIsCalled)
{
    g_funcGetActiveUserIdIsCalled = funcGetActiveUserIdIsCalled;
}

bool GetFuncGetActiveUserIdIsCalled()
{
    return g_funcGetActiveUserIdIsCalled;
}

void SetFuncGetBundleUidIsCalled(bool funcGetBundleUidIsCalled)
{
    g_funcGetBundleUidIsCalled = funcGetBundleUidIsCalled;
}

bool GetFuncGetBundleUidIsCalled()
{
    return g_funcGetBundleUidIsCalled;
}

int32_t NotificationCloneUtil::GetActiveUserId()
{
    g_funcGetActiveUserIdIsCalled = true;
    return g_MockActiveUserId;
}

int32_t NotificationCloneUtil::GetBundleUid(const std::string bundleName, int32_t userId, int32_t appIndex)
{
    g_funcGetBundleUidIsCalled = true;
    return g_MockUid;
}
}  // namespace Notification
}  // namespace OHOS
