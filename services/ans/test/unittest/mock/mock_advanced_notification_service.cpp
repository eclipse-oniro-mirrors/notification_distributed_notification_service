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

#include "advanced_notification_service.h"
#include "ans_inner_errors.h"

namespace {
    bool g_mockGetDistributedEnableInApplicationInfoRet = true;
    bool g_mockAppInfoEnableRet = true;
}

void MockGetDistributedEnableInApplicationInfo(bool mockRet, uint8_t mockCase = 0)
{
    g_mockGetDistributedEnableInApplicationInfoRet = mockRet;
    switch (mockCase) {
        case 1: { // mock for appInfoEnable
            g_mockAppInfoEnableRet = true;
            break;
        }
        default:{
            g_mockAppInfoEnableRet = false;
            break;
        }
    }
}

namespace OHOS {
namespace Notification {
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
ErrCode AdvancedNotificationService::GetDistributedEnableInApplicationInfo(
    const sptr<NotificationBundleOption> bundleOption, bool &enable)
{
    enable = g_mockAppInfoEnableRet;
    if (g_mockGetDistributedEnableInApplicationInfoRet == false) {
        return ERR_ANS_INVALID_PARAM;
    }
    return ERR_OK;
}
#endif
}  // namespace Notification
}  // namespace OHOS
