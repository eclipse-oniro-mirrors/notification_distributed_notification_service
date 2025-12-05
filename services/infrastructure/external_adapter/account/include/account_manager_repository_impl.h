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

#ifndef ANS_ACCOUNT_MANAGER_REPOSITORY_IMPL_H
#define ANS_ACCOUNT_MANAGER_REPOSITORY_IMPL_H

#include "iaccount_manager_repository.h"

namespace OHOS {
namespace Notification {
namespace Infra {
class AccountManagerRepositoryImpl : public Domain::IAccountManagerRepository {
/**
    * @brief check is system account
    */
    bool IsSystemAccount(int32_t userId) override;

    /**
     * Gets operating system account local ID from uid.
     *
     * @param uid Indicates the uid.
     * @param id Indicates the account ID.
     * @return Returns result code.
     */
    ErrCode GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &id) override;

    /**
     * Gets operating system account local ID from current calling.
     *
     * @param id Indicates the current calling account ID.
     * @return Returns result code.
     */
    ErrCode GetCurrentCallingUserId(int32_t &id) override;

    /**
     * Gets operating system account local ID from current active.
     *
     * @param id Indicates the current active account ID.
     * @return Returns result code.
     */
    ErrCode GetCurrentActiveUserId(int32_t &id) override;

    /**
     * Check the userId whether exists in OsAccount service.
     *
     * @param userId Indicates the current active account ID.
     * @return Returns result.
     */
    bool CheckUserExists(const int32_t &userId) override;

    /**
     * Get All os account userIds.
     *
     * @param userIds Indicates the current created account ID.
     * @return Returns result.
     */
    ErrCode GetAllOsAccount(std::vector<int32_t> &userIds) override;

    /**
     * Get All active account userIds.
     *
     * @param userIds Indicates the current active account ID.
     * @return Returns result.
     */
    ErrCode GetAllActiveOsAccount(std::vector<int32_t> &userIds) override;

    /**
     * Get private status from osAccount.
     */
    ErrCode GetOsAccountPrivateStatus(bool &isPrivate) override;
};
} // namespace Infra
} // namespace Notification
} // namespace OHOS
#endif
