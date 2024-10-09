/*
* Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "notification_clone_util.h"

#include "bundle_manager_helper.h"
#include "os_account_manager.h"
#include "os_account_manager_helper.h"

namespace OHOS {
namespace Notification {

constexpr int32_t MAIN_USER_ID = 100;
int32_t NotificationCloneUtil::GetActiveUserId()
{
    int32_t userId = MAIN_USER_ID;
    OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    return userId;
}

int32_t NotificationCloneUtil::GetBundleUid(const std::string bundleName, int32_t userId, int32_t appIndex)
{
    if (appIndex == -1) {
        return BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(bundleName, userId);
    }
    return BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(bundleName, userId, appIndex);
}
}
}
