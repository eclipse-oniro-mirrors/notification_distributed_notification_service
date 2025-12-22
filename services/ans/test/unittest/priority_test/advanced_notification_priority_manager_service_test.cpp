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

#include <gtest/gtest.h>
#include <iostream>

#define private public
#define protected public
#include "advanced_notification_service.h"
#undef private
#undef protected
#include "ans_inner_errors.h"
#include "mock_accesstoken_kit.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace Notification {
class PriorityManagerServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: SetPriorityEnabled_0100
 * @tc.desc: Test SetNotificationButtons success.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityEnabled_0100, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    AdvancedNotificationService::GetInstance()->SetPriorityEnabled(false);
    bool enable = true;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->IsPriorityEnabled(enable), ERR_OK);
    EXPECT_FALSE(enable);
}

/**
 * @tc.name: SetPriorityEnabledByBundle_0100
 * @tc.desc: Test SetPriorityEnabledByBundle success.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityEnabledByBundle_0100, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundleName", 200202);
    AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundle(bundleOption, 2);
    int32_t enableStatusInt = 1;
    EXPECT_EQ(
        AdvancedNotificationService::GetInstance()->IsPriorityEnabledByBundle(bundleOption, enableStatusInt), ERR_OK);
    EXPECT_EQ(enableStatusInt, 2);
}

/**
 * @tc.name: SetBundlePriorityConfig_0100
 * @tc.desc: Test SetBundlePriorityConfig success.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetBundlePriorityConfig_0100, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundleName", 200202);
    AdvancedNotificationService::GetInstance()->SetBundlePriorityConfig(bundleOption, "keyword1\nkeyword2");
    std::string value;
    EXPECT_EQ(
        AdvancedNotificationService::GetInstance()->GetBundlePriorityConfig(bundleOption, value), ERR_OK);
    EXPECT_EQ(value, "");
}
}
}