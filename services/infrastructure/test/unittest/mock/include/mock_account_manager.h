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

#ifndef INFRASTRUCTURE_TEST_UNITTEST_MOCK_INCLUDE_MOCK_ACCOUNT_MANAGER_H
#define INFRASTRUCTURE_TEST_UNITTEST_MOCK_INCLUDE_MOCK_ACCOUNT_MANAGER_H

#include "gmock/gmock.h"
#include "iaccount_manager_repository.h"

namespace OHOS {
namespace Notification {
namespace Infra {
class MockAccountMgr : public IAccountManagerRepository {
public:
    MOCK_METHOD(bool, IsSystemAccount, (int32_t userId), (override));
    MOCK_METHOD(ErrCode, GetOsAccountLocalIdFromUid, (const int32_t uid, int32_t &id), (override));
    MOCK_METHOD(ErrCode, GetCurrentCallingUserId, (int32_t &id), (override));
    MOCK_METHOD(ErrCode, GetCurrentActiveUserId, (int32_t &id), (override));
    MOCK_METHOD(int32_t, GetCurrentActiveUserIdWithDefault, (int32_t defaultUserId), (override));
    MOCK_METHOD(bool, CheckUserIdExists, (const int32_t &userId, bool defaultValue), (override));
    MOCK_METHOD(ErrCode, GetAllOsAccount, (std::vector<int32_t> &userIds), (override));
    MOCK_METHOD(ErrCode, GetAllActiveOsAccount, (std::vector<int32_t> &userIds), (override));
    MOCK_METHOD(ErrCode, GetOsAccountPrivateStatus, (bool &isPrivate), (override));
    MOCK_METHOD(bool, IsOsAccountVerified, (int32_t userId, bool defaultValue), (override));
};
}  // namespace Infra
}  // namespace Notification
}  // namespace OHOS

#endif  // INFRASTRUCTURE_TEST_UNITTEST_MOCK_INCLUDE_MOCK_ACCOUNT_MANAGER_H
