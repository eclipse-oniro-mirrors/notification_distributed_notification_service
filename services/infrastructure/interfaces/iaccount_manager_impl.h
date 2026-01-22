/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef INFRASTRUCTURE_ANS_IACCOUNT_MANAGER_IMPL_H
#define INFRASTRUCTURE_ANS_IACCOUNT_MANAGER_IMPL_H

#include <vector>
#include "ans_inner_errors.h"

namespace OHOS {
namespace Notification {
namespace Infra {

class IAccountManagerImpl {
public:
    static constexpr int32_t INVALID_USER_ID = -1;
    static constexpr int32_t DEFAULT_USER_ID = 100;
    static constexpr int32_t ZERO_USER_ID = 0;
public:
    /**
    * @brief check is system account
    */
    static bool IsSystemAccount(int32_t userId);

    /**
     * Gets operating system account local ID from uid.
     *
     * @param uid Indicates the uid.
     * @param id Indicates the account ID.
     * @return Returns result code.
     */
    static ErrCode GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &id);

    /**
     * Gets operating system account local ID from uid.
     *
     * @param uid Indicates the uid.
     * @return Returns result code.
     */
    static int32_t GetOsAccountLocalIdFromUid(const int32_t uid);

    /**
     * Gets operating system account local ID from current calling.
     *
     * @param id Indicates the current calling account ID.
     * @return Returns result code.
     */
    static ErrCode GetCurrentCallingUserId(int32_t &id);

    /**
     * Gets operating system account local ID from current active.
     *
     * @param id Indicates the current active account ID.
     * @return Returns result code.
     */
    static ErrCode GetCurrentActiveUserId(int32_t &id);

    /**
     * Gets operating system account local ID with default value from current active.
     */
    static int32_t GetCurrentActiveUserIdWithDefault(int32_t defaultUserId);

    /**
     * Check the userId whether exists in OsAccount service.
     *
     * @param userId Indicates the current active account ID.
     * @return Returns result.
     */
    static bool CheckUserIdExists(const int32_t &userId, bool defaultValue = false);

    /**
     * Get All os account userIds.
     *
     * @param userIds Indicates the current created account ID.
     * @return Returns result.
     */
    static ErrCode GetAllOsAccount(std::vector<int32_t> &userIds);

    /**
     * Get All active account userIds.
     *
     * @param userIds Indicates the current active account ID.
     * @return Returns result.
     */
    static ErrCode GetAllActiveOsAccount(std::vector<int32_t> &userIds);

    /**
     * Get private status from osAccount.
     */
    static ErrCode GetOsAccountPrivateStatus(bool &isPrivate);

    /**
     * Check user id is verified.
     */
    static bool IsOsAccountVerified(int32_t userId, bool defaultValue = false);

    /**
     * Get foreground user id.
     */
    static ErrCode GetForegroundUserIds(std::vector<int32_t> &foregroundUserIds);
};
} // namespace Infra
} // namespace Notification
} // namespace OHOS
#endif
