/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_OS_ACCOUNT_MANAGER_HELPER_H
#define BASE_NOTIFICATION_OS_ACCOUNT_MANAGER_HELPER_H

#include "errors.h"
#include "singleton.h"

namespace OHOS {
namespace Notification {
class OsAccountManagerHelper : public DelayedSingleton<OsAccountManagerHelper> {
public:
    
    OsAccountManagerHelper() = default;
    ~OsAccountManagerHelper() = default;

    /**
     * @brief Get OsAccountManagerHelper instance object.
     */
    static OsAccountManagerHelper &GetInstance();

    /**
     * Gets operating system account local ID from uid.
     *
     * @param uid Indicates the uid.
     * @param ids Indicates the account ID.
     * @return Returns result code.
     */
    ErrCode GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &id);

    /**
     * Gets operating system account local ID from current calling.
     *
     * @param uid Indicates the uid.
     * @param ids Indicates the account ID.
     * @return Returns result code.
     */
    ErrCode GetCurrentCallingUserId(int32_t &id);
};
} // namespace OHOS
} // namespace Notification
#endif  // BASE_NOTIFICATION_OS_ACCOUNT_MANAGER_HELPER_H