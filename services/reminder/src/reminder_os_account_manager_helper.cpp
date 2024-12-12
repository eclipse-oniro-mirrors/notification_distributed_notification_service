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

#include "reminder_os_account_manager_helper.h"
#include "ans_log_wrapper.h"
#include "ans_inner_errors.h"
#include "errors.h"
#include "ipc_skeleton.h"

#include "os_account_constants.h"
#include "os_account_info.h"
#include "os_account_manager.h"
#include <vector>

namespace OHOS {
namespace Notification {
ReminderOsAccountManagerHelper &ReminderOsAccountManagerHelper::GetInstance()
{
    return DelayedRefSingleton<ReminderOsAccountManagerHelper>::GetInstance();
}
ErrCode ReminderOsAccountManagerHelper::GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &userId)
{
    int32_t ret = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    if (ret != ERR_OK) {
        ANS_LOGE("Get userId failed, uid = <%{public}d>, code is %{public}d", uid, ret);
        return ret;
    }
    ANS_LOGD("Get userId Success, uid = <%{public}d> userId = <%{public}d>", uid, userId);
    return ret;
}

ErrCode ReminderOsAccountManagerHelper::GetCurrentActiveUserId(int32_t &id)
{
    int32_t ret = OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(id);
    if (ret != ERR_OK) {
        ANS_LOGE("Failed to call OsAccountManager::GetForegroundOsAccountLocalId, code is %{public}d", ret);
    }
    return ret;
}
}
}
