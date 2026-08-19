/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "mock_ipc_skeleton.h"

namespace OHOS {
static pid_t g_mockUid = 1;
static pid_t g_mockPid = 1;
static Security::AccessToken::AccessTokenID g_mockCallerToken = 0;

pid_t IPCSkeleton::GetCallingUid()
{
    return g_mockUid;
}

pid_t IPCSkeleton::GetCallingPid()
{
    return g_mockPid;
}

Security::AccessToken::AccessTokenID IPCSkeleton::GetCallingTokenID()
{
    return g_mockCallerToken;
}

void IPCSkeleton::SetCallingUid(pid_t uid)
{
    g_mockUid = uid;
}

void IPCSkeleton::SetCallingPid(pid_t pid)
{
    g_mockPid = pid;
}

void IPCSkeleton::SetCallingTokenID(Security::AccessToken::AccessTokenID callerToken)
{
    g_mockCallerToken = callerToken;
}
}  // namespace OHOS
