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

#include <functional>
#include <gtest/gtest.h>
#include "accesstoken_kit.h"
#include "reminder_access_token_helper.h"
#include "ans_log_wrapper.h"
#include "ipc_skeleton.h"
#include "mock_accesstoken_kit.h"
using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {
class AccessTokenHelperTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<ReminderAccessTokenHelper> stub_;
};

void AccessTokenHelperTest::SetUpTestCase()
{
}

void AccessTokenHelperTest::TearDownTestCase()
{
}

void AccessTokenHelperTest::SetUp()
{
    stub_ = std::make_shared<ReminderAccessTokenHelper>();
}

void AccessTokenHelperTest::TearDown()
{
}

/**
 * @tc.number    : AccessTokenHelperTest
 * @tc.name      : VerifyNativeToken_00100
 * @tc.desc      : VerifyNativeToken success
 */
HWTEST_F(AccessTokenHelperTest, VerifyNativeToken_00100, Function | SmallTest | Level1)
{
    AccessTokenID tokenID = 0;
    MockAccesstokenKit::MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_TRUE(stub_->VerifyNativeToken(tokenID));
}

/**
 * @tc.number    : AccessTokenHelperTest
 * @tc.name      : IsSystemApp_00100
 * @tc.desc      : IsSystemApp Token Type TOKEN_NATIVE
 */
HWTEST_F(AccessTokenHelperTest, IsSystemApp_00100, Function | SmallTest | Level1)
{
    MockAccesstokenKit::MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_FALSE(stub_->IsSystemApp());
}

/**
 * @tc.number    : AccessTokenHelperTest
 * @tc.name      : IsSystemApp_00200
 * @tc.desc      : IsSystemApp Token Type TOKEN_HAP
 */
HWTEST_F(AccessTokenHelperTest, IsSystemApp_00200, Function | SmallTest | Level1)
{
    MockAccesstokenKit::MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    EXPECT_TRUE(stub_->IsSystemApp());
}

}  // namespace Notification
}  // namespace OHOS
