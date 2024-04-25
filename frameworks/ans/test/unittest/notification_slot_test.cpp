/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "notification_slot.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
class NotificationSlotTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: SetType_0100
 * @tc.desc: Set LiveView Type
 * @tc.type: FUNC
 * @tc.require: issueI5RW70
 */
HWTEST_F(NotificationSlotTest, SetType_0100, Level1)
{
    NotificationSlot notificationSlot(NotificationConstant::SlotType::LIVE_VIEW);

    EXPECT_EQ(notificationSlot.GetForceControl(), false);
    EXPECT_EQ(notificationSlot.GetLockScreenVisibleness(), NotificationConstant::VisiblenessType::PUBLIC);
    EXPECT_EQ(notificationSlot.GetName(), "LIVE_VIEW");
    EXPECT_EQ(notificationSlot.GetLevel(), NotificationSlot::LEVEL_DEFAULT);
}

/**
 * @tc.name: SetType_0200
 * @tc.desc: Set CUSTOMER_SERVICE Type
 * @tc.type: FUNC
 * @tc.require: issueI5RW70
 */
HWTEST_F(NotificationSlotTest, SetType_0200, Level1)
{
    NotificationSlot notificationSlot(NotificationConstant::SlotType::CUSTOMER_SERVICE);

    EXPECT_EQ(notificationSlot.GetForceControl(), false);
    EXPECT_EQ(notificationSlot.GetLockScreenVisibleness(), NotificationConstant::VisiblenessType::SECRET);
    EXPECT_EQ(notificationSlot.GetName(), "CUSTOMER_SERVICE");
    EXPECT_EQ(notificationSlot.GetLevel(), NotificationSlot::LEVEL_LOW);
}

/**
 * @tc.name: SetType_0300
 * @tc.desc: Set EMERGENCY_INFORMATION Type
 * @tc.type: FUNC
 * @tc.require: issueI5RW70
 */
HWTEST_F(NotificationSlotTest, SetType_0300, Level1)
{
    NotificationSlot notificationSlot(NotificationConstant::SlotType::EMERGENCY_INFORMATION);

    EXPECT_EQ(notificationSlot.GetForceControl(), false);
    EXPECT_EQ(notificationSlot.GetLockScreenVisibleness(), NotificationConstant::VisiblenessType::PUBLIC);
    EXPECT_EQ(notificationSlot.GetName(), "EMERGENCY_INFORMATION");
    EXPECT_EQ(notificationSlot.GetLevel(), NotificationSlot::LEVEL_HIGH);
}
}
}