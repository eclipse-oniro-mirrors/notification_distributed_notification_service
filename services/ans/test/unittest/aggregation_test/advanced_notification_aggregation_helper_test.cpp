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

#include <gtest/gtest.h>
#include <string>

#define private public
#define protected public
#include "advanced_notification_aggregation_helper.h"
#undef protected
#undef private

#include "ans_inner_errors.h"
#include "notification_constant.h"
#include "notification_preferences.h"
#include "notification_request.h"
#include "nlohmann/json.hpp"

extern void MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase);

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace Notification {

class AdvancedNotificationAggregationHelperTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() override {};
    void TearDown() override {};
};

#ifdef ANS_FEATURE_AGGREGATION_NOTIFICATION
/**
 * @tc.name: BuildAggregationCommand_0100
 * @tc.desc: Test BuildAggregationCommand when no aggregation subscriber is registered,
 *           command should remain empty and method returns early
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationHelperTest, BuildAggregationCommand_0100, Function | SmallTest | Level1)
{
    // Pass hasAggregationSubscriber=false to verify early return without populating command
    std::string cmdType = NotificationConstant::AggregationType::DEAL;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetReceiverUserId(100);
    nlohmann::json command;

    AdvancedNotificationAggregationHelper::GetInstance()->BuildAggregationCommand(cmdType, request, command, false);

    // When no aggregation subscriber is registered, command should not contain cmdType key
    EXPECT_FALSE(command.contains(cmdType));
}

/**
 * @tc.name: BuildAggregationCommand_0200
 * @tc.desc: Test BuildAggregationCommand with valid subscriber count and
 *           switches enabled, command should contain dealSwitch and logisticsSwitch
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationHelperTest, BuildAggregationCommand_0200, Function | SmallTest | Level1)
{
    // Set up active user ID mock to return userId 100
    MockQueryForgroundOsAccountId(true, 0);

    // Set DEAL and LOGISTICS switches to USER_MODIFIED_ON for userId 100
    NotificationPreferences::GetInstance()->SetNotificationSwitch(
        NotificationConstant::NotificationSwitch::DEAL,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON, 100);
    NotificationPreferences::GetInstance()->SetNotificationSwitch(
        NotificationConstant::NotificationSwitch::LOGISTICS,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON, 100);

    std::string cmdType = NotificationConstant::AggregationType::DEAL;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetReceiverUserId(100);
    nlohmann::json command;

    AdvancedNotificationAggregationHelper::GetInstance()->BuildAggregationCommand(
        cmdType, request, command, true);

    // Command should contain cmdType key with dealSwitch and logisticsSwitch both true
    EXPECT_TRUE(command.contains(cmdType));
    EXPECT_TRUE(command[cmdType].contains("dealSwitch"));
    EXPECT_TRUE(command[cmdType].contains("logisticsSwitch"));
    EXPECT_EQ(command[cmdType]["dealSwitch"].get<bool>(), true);
    EXPECT_EQ(command[cmdType]["logisticsSwitch"].get<bool>(), true);
}

/**
 * @tc.name: BuildAggregationCommand_0300
 * @tc.desc: Test BuildAggregationCommand when both switches are OFF,
 *           command should remain empty and method returns early
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationHelperTest, BuildAggregationCommand_0300, Function | SmallTest | Level1)
{
    // Set up active user ID mock to return userId 100
    MockQueryForgroundOsAccountId(true, 0);

    // Set both switches to USER_MODIFIED_OFF for userId 100
    NotificationPreferences::GetInstance()->SetNotificationSwitch(
        NotificationConstant::NotificationSwitch::DEAL,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF, 100);
    NotificationPreferences::GetInstance()->SetNotificationSwitch(
        NotificationConstant::NotificationSwitch::LOGISTICS,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF, 100);

    std::string cmdType = NotificationConstant::AggregationType::DEAL;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetReceiverUserId(100);
    nlohmann::json command;

    AdvancedNotificationAggregationHelper::GetInstance()->BuildAggregationCommand(
        cmdType, request, command, true);

    // When both switches are OFF, command should not contain cmdType key
    EXPECT_FALSE(command.contains(cmdType));
}

/**
 * @tc.name: BuildAggregationCommand_0400
 * @tc.desc: Test BuildAggregationCommand with negative userId,
 *           should use OsAccountManagerHelper to get active userId
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationHelperTest, BuildAggregationCommand_0400, Function | SmallTest | Level1)
{
    // Set up active user ID mock to return userId 100
    MockQueryForgroundOsAccountId(true, 0);

    // Set DEAL switch ON and LOGISTICS switch OFF for userId 100 (the active user)
    NotificationPreferences::GetInstance()->SetNotificationSwitch(
        NotificationConstant::NotificationSwitch::DEAL,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON, 100);
    NotificationPreferences::GetInstance()->SetNotificationSwitch(
        NotificationConstant::NotificationSwitch::LOGISTICS,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF, 100);

    std::string cmdType = NotificationConstant::AggregationType::DEAL;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    // Set negative userId to trigger OsAccountManagerHelper fallback
    request->SetReceiverUserId(-1);
    nlohmann::json command;

    AdvancedNotificationAggregationHelper::GetInstance()->BuildAggregationCommand(
        cmdType, request, command, true);

    // Command should contain cmdType key with dealSwitch=true, logisticsSwitch=false
    EXPECT_TRUE(command.contains(cmdType));
    EXPECT_TRUE(command[cmdType].contains("dealSwitch"));
    EXPECT_TRUE(command[cmdType].contains("logisticsSwitch"));
    EXPECT_EQ(command[cmdType]["dealSwitch"].get<bool>(), true);
    EXPECT_EQ(command[cmdType]["logisticsSwitch"].get<bool>(), false);
}
#endif // ANS_FEATURE_AGGREGATION_NOTIFICATION

}  // namespace Notification
}  // namespace OHOS