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

#ifndef DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_OS_ACCOUNT_MANAGER_HELPER_H
#define DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_OS_ACCOUNT_MANAGER_HELPER_H

#include "errors.h"
#include "singleton.h"
#include <vector>

namespace OHOS {
namespace Notification {
class ReminderOsAccountManagerHelper : public DelayedSingleton<ReminderOsAccountManagerHelper> {
public:
    
    ReminderOsAccountManagerHelper() = default;
    ~ReminderOsAccountManagerHelper() = default;

    /**
     * @brief Get OsAccountManagerHelper instance object.
     */
    static ReminderOsAccountManagerHelper &GetInstance();

    /**
     * Gets operating system account local ID from uid.
     *
     * @param uid Indicates the uid.
     * @param id Indicates the account ID.
     * @return Returns result code.
     */
    ErrCode GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &id);

    /**
     * Gets operating system account local ID from current active.
     *
     * @param id Indicates the current active account ID.
     * @return Returns result code.
     */
    ErrCode GetCurrentActiveUserId(int32_t &id);
};
} // namespace OHOS
} // namespace Notification
#endif  // DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_OS_ACCOUNT_MANAGER_HELPER_H