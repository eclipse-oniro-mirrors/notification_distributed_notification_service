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

#include <algorithm>
#include <gtest/gtest.h>

#include "notification_constant.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationConstantTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: AggregationType_00001
 * @tc.desc: Test AggregationType constant values OTHER, DEAL and LOGISTICS.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConstantTest, AggregationType_00001, Function | SmallTest | Level1)
{
    EXPECT_EQ(std::string(NotificationConstant::AggregationType::OTHER), "OTHER");
    EXPECT_EQ(std::string(NotificationConstant::AggregationType::DEAL), "DEAL");
    EXPECT_EQ(std::string(NotificationConstant::AggregationType::LOGISTICS), "LOGISTICS");
}

/**
 * @tc.name: AggregationType_00002
 * @tc.desc: Test VALID_AGGREGATION_TYPE_LIST contains all valid aggregation types.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConstantTest, AggregationType_00002, Function | SmallTest | Level1)
{
    const auto& list = NotificationConstant::AggregationType::VALID_AGGREGATION_TYPE_LIST;
    EXPECT_EQ(list.size(), 3);
    EXPECT_NE(std::find(list.begin(), list.end(), std::string("OTHER")), list.end());
    EXPECT_NE(std::find(list.begin(), list.end(), std::string("DEAL")), list.end());
    EXPECT_NE(std::find(list.begin(), list.end(), std::string("LOGISTICS")), list.end());
}

/**
 * @tc.name: NotificationSwitch_00001
 * @tc.desc: Test NotificationSwitch constant values INVALID, DEAL and LOGISTICS.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConstantTest, NotificationSwitch_00001, Function | SmallTest | Level1)
{
    EXPECT_EQ(std::string(NotificationConstant::NotificationSwitch::INVALID), "INVALID");
    EXPECT_EQ(std::string(NotificationConstant::NotificationSwitch::DEAL), "DEAL");
    EXPECT_EQ(std::string(NotificationConstant::NotificationSwitch::LOGISTICS), "LOGISTICS");
}

/**
 * @tc.name: NotificationSwitch_00002
 * @tc.desc: Test VALID_NOTIFICATION_SWITCH_SET contains DEAL and LOGISTICS but not INVALID.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConstantTest, NotificationSwitch_00002, Function | SmallTest | Level1)
{
    const auto& validSet = NotificationConstant::NotificationSwitch::VALID_NOTIFICATION_SWITCH_SET;
    EXPECT_EQ(validSet.size(), 2);
    EXPECT_TRUE(validSet.find(std::string("DEAL")) != validSet.end());
    EXPECT_TRUE(validSet.find(std::string("LOGISTICS")) != validSet.end());
    EXPECT_TRUE(validSet.find(std::string("INVALID")) == validSet.end());
}

/**
 * @tc.name: IsValidNotificationSwitch_00001
 * @tc.desc: Test IsValidNotificationSwitch returns true for valid switch names.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConstantTest, IsValidNotificationSwitch_00001, Function | SmallTest | Level1)
{
    EXPECT_TRUE(NotificationConstant::NotificationSwitch::IsValidNotificationSwitch("DEAL"));
    EXPECT_TRUE(NotificationConstant::NotificationSwitch::IsValidNotificationSwitch("LOGISTICS"));
}

/**
 * @tc.name: IsValidNotificationSwitch_00002
 * @tc.desc: Test IsValidNotificationSwitch returns false for invalid switch names.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConstantTest, IsValidNotificationSwitch_00002, Function | SmallTest | Level1)
{
    EXPECT_FALSE(NotificationConstant::NotificationSwitch::IsValidNotificationSwitch("INVALID"));
    EXPECT_FALSE(NotificationConstant::NotificationSwitch::IsValidNotificationSwitch("OTHER"));
    EXPECT_FALSE(NotificationConstant::NotificationSwitch::IsValidNotificationSwitch(""));
    EXPECT_FALSE(NotificationConstant::NotificationSwitch::IsValidNotificationSwitch("random_string"));
}

/**
 * @tc.name: PriorityNotificationType_00001
 * @tc.desc: Test E_COMMERCE_LOGISTICS constant value.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConstantTest, PriorityNotificationType_00001, Function | SmallTest | Level1)
{
    EXPECT_EQ(std::string(NotificationConstant::PriorityNotificationType::E_COMMERCE_LOGISTICS),
        "E_COMMERCE_LOGISTICS");
}
}  // namespace Notification
}  // namespace OHOS