/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <functional>
#include <gtest/gtest.h>

#include "os_account_manager_helper.h"
#include "accesstoken_kit.h"


using namespace testing::ext;
namespace OHOS {
namespace Notification {
class OsAccountManagerHelperTest : public testing::Test {
public:
    static void SetUpTestSuite() {};
    static void TearDownTestSuite() {};
    void SetUp() override {};
    void TearDown() override {};
};

/**
 * @tc.number    : GetCurrentCallingUserId_00100
 * @tc.name      : GetCurrentCallingUserId_00100
 * @tc.desc      : test GetCurrentCallingUserId function
 */
HWTEST_F(OsAccountManagerHelperTest, GetCurrentCallingUserId_00100, Function | SmallTest | Level1)
{
    int32_t userId = -1;
    ASSERT_EQ(ERR_OK, OsAccountManagerHelper::GetInstance().GetCurrentCallingUserId(userId));
}

/**
 * @tc.number    : GetOsAccountLocalIdFromUid_00100
 * @tc.name      : GetOsAccountLocalIdFromUid_00100
 * @tc.desc      : test GetOsAccountLocalIdFromUid function
 */
HWTEST_F(OsAccountManagerHelperTest, GetOsAccountLocalIdFromUid_00100, Function | SmallTest | Level1)
{
    int32_t userId = -1;
    const int uid = 0;
    ASSERT_EQ(ERR_OK, OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(uid, userId));
}

/**
 * @tc.number    : GetCurrentActiveUserId_00100
 * @tc.name      : GetCurrentActiveUserId_00100
 * @tc.desc      : test GetCurrentActiveUserId function
 */
HWTEST_F(OsAccountManagerHelperTest, GetCurrentActiveUserId_00100, Function | SmallTest | Level1)
{
    int32_t userId = -1;
    ASSERT_EQ(ERR_OK, OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId));
}

/**
 * @tc.number    : CheckUserExists_00100
 * @tc.name      : CheckUserExists_00100
 * @tc.desc      : test CheckUserExists function
 */
HWTEST_F(OsAccountManagerHelperTest, CheckUserExists_00100, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    ASSERT_EQ(true, OsAccountManagerHelper::GetInstance().CheckUserExists(userId));
}

/**
 * @tc.number    : CheckUserExists_00200
 * @tc.name      : CheckUserExists_00200
 * @tc.desc      : test CheckUserExists function
 */
HWTEST_F(OsAccountManagerHelperTest, CheckUserExists_00200, Function | SmallTest | Level1)
{
    int32_t userId = 1099;
    ASSERT_EQ(false, OsAccountManagerHelper::GetInstance().CheckUserExists(userId));
}

/**
 * @tc.number    : IsSystemAccount_0100
 * @tc.name      : IsSystemAccount_0100
 * @tc.desc      : test IsSystemAccount function, 100 is true(100 <= userId <= 10736)
 */
HWTEST_F(OsAccountManagerHelperTest, IsSystemAccount_0100, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    ASSERT_EQ(true, OsAccountManagerHelper::IsSystemAccount(userId));
}

/**
 * @tc.number    : IsSystemAccount_0200
 * @tc.name      : IsSystemAccount_0200
 * @tc.desc      : test IsSystemAccount function, 1100 is false(100 <= userId <= 10736)
 */
HWTEST_F(OsAccountManagerHelperTest, IsSystemAccount_0200, Function | SmallTest | Level1)
{
    int32_t userId = 10737;
    ASSERT_EQ(false, OsAccountManagerHelper::IsSystemAccount(userId));
}

/**
 * @tc.number    : IsSystemAccount_0300
 * @tc.name      : IsSystemAccount_0300
 * @tc.desc      : test IsSystemAccount function, 0 is false(100 <= userId <= 10736)
 */
HWTEST_F(OsAccountManagerHelperTest, IsSystemAccount_0300, Function | SmallTest | Level1)
{
    int32_t userId = 0;
    ASSERT_EQ(false, OsAccountManagerHelper::IsSystemAccount(userId));
}

/**
 * @tc.number    : IsSystemAccount_0400
 * @tc.name      : IsSystemAccount_0400
 * @tc.desc      : test IsSystemAccount function, 1099 is true(100 <= userId <= 10736)
 */
HWTEST_F(OsAccountManagerHelperTest, IsSystemAccount_0400, Function | SmallTest | Level1)
{
    int32_t userId = 10736;
    ASSERT_EQ(true, OsAccountManagerHelper::IsSystemAccount(userId));
}
}
}