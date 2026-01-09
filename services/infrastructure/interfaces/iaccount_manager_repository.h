/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef ANS_IACCOUNT_MANAGER_REPOSITORY_H
#define ANS_IACCOUNT_MANAGER_REPOSITORY_H

#include <vector>
#include "ans_inner_errors.h"

namespace OHOS {
namespace Notification {
namespace Infra {

class IAccountManagerRepository {
public:
    virtual ~IAccountManagerRepository() = default;

    /**
    * @brief check is system account
    */
    virtual bool IsSystemAccount(int32_t userId) = 0;

    /**
     * Gets operating system account local ID from uid.
     *
     * @param uid Indicates the uid.
     * @param id Indicates the account ID.
     * @return Returns result code.
     */
    virtual ErrCode GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &id) = 0;

    /**
     * Gets operating system account local ID from current calling.
     *
     * @param id Indicates the current calling account ID.
     * @return Returns result code.
     */
    virtual ErrCode GetCurrentCallingUserId(int32_t &id) = 0;

    /**
     * Gets operating system account local ID from current active.
     *
     * @param id Indicates the current active account ID.
     * @return Returns result code.
     */
    virtual ErrCode GetCurrentActiveUserId(int32_t &id) = 0;

    /**
     * Gets operating system account local ID with default value from current active.
     */
    virtual int32_t GetCurrentActiveUserIdWithDefault(int32_t defaultUserId) = 0;

    /**
     * Check the userId whether exists in OsAccount service.
     *
     * @param userId Indicates the current active account ID.
     * @return Returns result.
     */
    virtual bool CheckUserIdExists(const int32_t &userId, bool defaultValue = false) = 0;

    /**
     * Get All os account userIds.
     *
     * @param userIds Indicates the current created account ID.
     * @return Returns result.
     */
    virtual ErrCode GetAllOsAccount(std::vector<int32_t> &userIds) = 0;

    /**
     * Get All active account userIds.
     *
     * @param userIds Indicates the current active account ID.
     * @return Returns result.
     */
    virtual ErrCode GetAllActiveOsAccount(std::vector<int32_t> &userIds) = 0;

    /**
     * Get private status from osAccount.
     */
    virtual ErrCode GetOsAccountPrivateStatus(bool &isPrivate) = 0;

    /**
     * Check user id is verified.
     */
    virtual bool IsOsAccountVerified(int32_t userId, bool defaultValue = false) = 0;
};
} // namespace Infra
} // namespace Notification
} // namespace OHOS
#endif
