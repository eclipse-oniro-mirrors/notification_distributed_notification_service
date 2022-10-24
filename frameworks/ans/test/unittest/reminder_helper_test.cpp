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

#include <gtest/gtest.h>

#define private public
#define protected public
#include "reminder_request.h"
#undef private
#undef protected

#include "ans_inner_errors.h"
#include "reminder_helper.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class ReminderHelperTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: PublishReminder_00001
 * @tc.desc: Test PublishReminder parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ReminderHelperTest, PublishReminder_00001, Function | SmallTest | Level1)
{
    ReminderRequest reminder;
    ReminderHelper reminderHelper;
    ErrCode ret = reminderHelper.PublishReminder(reminder);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: CancelReminder_00001
 * @tc.desc: Test CancelReminder parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ReminderHelperTest, CancelReminder_00001, Function | SmallTest | Level1)
{
    int32_t reminderId = 10;
    ReminderHelper reminderHelper;
    ErrCode ret = reminderHelper.CancelReminder(reminderId);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: CancelAllReminders_00001
 * @tc.desc: Test CancelAllReminders parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ReminderHelperTest, CancelAllReminders_00001, Function | SmallTest | Level1)
{
    ReminderHelper reminderHelper;
    ErrCode ret = reminderHelper.CancelAllReminders();
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: GetValidReminders_00001
 * @tc.desc: Test GetValidReminders parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ReminderHelperTest, GetValidReminders_00001, Function | SmallTest | Level1)
{
    std::vector<sptr<ReminderRequest>> validReminders;
    ReminderHelper reminderHelper;
    ErrCode ret = reminderHelper.GetValidReminders(validReminders);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: AddNotificationSlot_00001
 * @tc.desc: Test AddNotificationSlot parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ReminderHelperTest, AddNotificationSlot_00001, Function | SmallTest | Level1)
{
    NotificationSlot slot;
    ReminderHelper reminderHelper;
    ErrCode ret = reminderHelper.AddNotificationSlot(slot);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: RemoveNotificationSlot_00001
 * @tc.desc: Test RemoveNotificationSlot parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ReminderHelperTest, RemoveNotificationSlot_00001, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SERVICE_REMINDER;
    ReminderHelper reminderHelper;
    ErrCode ret = reminderHelper.RemoveNotificationSlot(slotType);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}
}
}