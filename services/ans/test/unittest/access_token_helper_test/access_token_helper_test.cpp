/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#define private public
#define protected public
#include "access_token_helper.h"
#include "ans_log_wrapper.h"
#include "ipc_skeleton.h"
#undef private
#undef protected
using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {

extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);
extern void MockDlpType(DlpType mockRet);
extern void MockApl(ATokenAplEnum mockRet);
class AccessTokenHelperTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<AccessTokenHelper> stub_;
};

void AccessTokenHelperTest::SetUpTestCase()
{
}

void AccessTokenHelperTest::TearDownTestCase()
{
}

void AccessTokenHelperTest::SetUp()
{
    stub_ = std::make_shared<AccessTokenHelper>();
}

void AccessTokenHelperTest::TearDown()
{
}

/**
 * @tc.number    : AccessTokenHelperTest
 * @tc.name      : VerifyCallerPermission_00100
 * @tc.desc      : VerifyCallerPermission success
 */
HWTEST_F(AccessTokenHelperTest, VerifyCallerPermission_00100, Function | SmallTest | Level1)
{
    AccessTokenID tokenID = 0;
    string permission;
    EXPECT_TRUE(stub_->VerifyCallerPermission(tokenID, permission));
}

/**
 * @tc.number    : AccessTokenHelperTest
 * @tc.name      : VerifyNativeToken_00100
 * @tc.desc      : VerifyNativeToken success
 */
HWTEST_F(AccessTokenHelperTest, VerifyNativeToken_00100, Function | SmallTest | Level1)
{
    AccessTokenID tokenID = 0;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_TRUE(stub_->VerifyNativeToken(tokenID));
}

/**
 * @tc.number    : AccessTokenHelperTest
 * @tc.name      : IsSystemApp_00100
 * @tc.desc      : IsSystemApp Token Type TOKEN_NATIVE
 */
HWTEST_F(AccessTokenHelperTest, IsSystemApp_00100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_FALSE(stub_->IsSystemApp());
}

/**
 * @tc.number    : AccessTokenHelperTest
 * @tc.name      : IsSystemApp_00200
 * @tc.desc      : IsSystemApp Token Type TOKEN_HAP
 */
HWTEST_F(AccessTokenHelperTest, IsSystemApp_00200, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    EXPECT_TRUE(stub_->IsSystemApp());
}

/**
 * @tc.number    : AccessTokenHelperTest
 * @tc.name      : IsDlpHap_00100
 * @tc.desc      : IsDlpHap Token Type TOKEN_HAP
 */
HWTEST_F(AccessTokenHelperTest, IsDlpHap_00100, Function | SmallTest | Level1)
{
    AccessTokenID tokenID = 0;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockDlpType(DlpType::DLP_READ);
    EXPECT_TRUE(stub_->IsDlpHap(tokenID));
}

/**
 * @tc.number    : AccessTokenHelperTest
 * @tc.name      : IsDlpHap_00200
 * @tc.desc      : IsDlpHap Token Type TOKEN_NATIVE
 */
HWTEST_F(AccessTokenHelperTest, IsDlpHap_00200, Function | SmallTest | Level1)
{
    AccessTokenID tokenID = 0; 
    MockDlpType(DlpType::DLP_COMMON);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_FALSE(stub_->IsDlpHap(tokenID));
}


/**
 * @tc.number  : AdvancedNotificationService_01300
 * @tc.name    : AdvancedNotificationService_01300
 * @tc.desc    : Test CheckPermission function and result is false
 */
HWTEST_F(AccessTokenHelperTest, CheckPermission_00100, Function | SmallTest | Level1)
{
    std::string permission = "<permission>";
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    ASSERT_EQ(stub_->CheckPermission(permission), true);
}
}  // namespace Notification
}  // namespace OHOS
