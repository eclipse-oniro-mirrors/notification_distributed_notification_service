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

#include "reminder_os_account_manager_helper.h"
#include "accesstoken_kit.h"


using namespace testing::ext;
namespace OHOS {
namespace Notification {
class ReminderOsAccountManagerHelperTest : public testing::Test {
public:
    static void SetUpTestSuite() {};
    static void TearDownTestSuite() {};
    void SetUp() override {};
    void TearDown() override {};
};

/**
 * @tc.number    : GetOsAccountLocalIdFromUid_00100
 * @tc.name      : GetOsAccountLocalIdFromUid_00100
 * @tc.desc      : test GetOsAccountLocalIdFromUid function
 */
HWTEST_F(ReminderOsAccountManagerHelperTest, GetOsAccountLocalIdFromUid_00100, Function | SmallTest | Level1)
{
    int32_t userId = -1;
    const int uid = 0;
    ASSERT_EQ(ERR_OK, ReminderOsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(uid, userId));
}

/**
 * @tc.number    : GetCurrentActiveUserId_00100
 * @tc.name      : GetCurrentActiveUserId_00100
 * @tc.desc      : test GetCurrentActiveUserId function
 */
HWTEST_F(ReminderOsAccountManagerHelperTest, GetCurrentActiveUserId_00100, Function | SmallTest | Level1)
{
    int32_t userId = -1;
    ASSERT_EQ(ERR_OK, ReminderOsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId));
}
}
}