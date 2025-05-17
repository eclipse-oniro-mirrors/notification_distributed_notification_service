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

#include "reminder_request.h"
#include "reminder_request_adaptation.h"

#include "ans_inner_errors.h"
#include "reminder_helper.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class ReminderHelperTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        const char **perms = new const char *[1];
        perms[0] = "ohos.permission.NOTIFICATION_CONTROLLER";
        NativeTokenInfoParams infoInstance = {
            .dcapsNum = 0,
            .permsNum = 1,
            .aclsNum = 0,
            .dcaps = nullptr,
            .perms = perms,
            .acls = nullptr,
            .aplStr = "system_basic",
        };

        uint64_t tokenId;
        infoInstance.processName = "reminder_unit_test";
        tokenId = GetAccessTokenId(&infoInstance);
        SetSelfTokenID(tokenId);
        delete[] perms;
    }
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
    int32_t reminderId = -1;
    ErrCode ret = reminderHelper.PublishReminder(reminder, reminderId);
    EXPECT_NE(ret, (int)ERR_OK);
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
    EXPECT_NE(ret, (int)ERR_OK);
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
    EXPECT_NE(ret, (int)ERR_OK);
}

/**
 * @tc.name: GetValidReminders_00001
 * @tc.desc: Test GetValidReminders parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ReminderHelperTest, GetValidReminders_00001, Function | SmallTest | Level1)
{
    std::vector<ReminderRequestAdaptation> validReminders;
    ReminderHelper reminderHelper;
    ErrCode ret = reminderHelper.GetValidReminders(validReminders);
    EXPECT_NE(ret, (int)ERR_OK);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: AddExcludeDate_00001
 * @tc.desc: Test AddExcludeDate parameters.
 * @tc.type: FUNC
 * @tc.require: issue#I9F24R
 */
HWTEST_F(ReminderHelperTest, AddExcludeDate_00001, Function | SmallTest | Level1)
{
    int32_t reminderId = 1;
    uint64_t date = 1713196800000;
    ReminderHelper reminderHelper;
    ErrCode ret = reminderHelper.AddExcludeDate(reminderId, date);
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: DelExcludeDates_00001
 * @tc.desc: Test DelExcludeDates parameters.
 * @tc.type: FUNC
 * @tc.require: issue#I9F24R
 */
HWTEST_F(ReminderHelperTest, DelExcludeDates_00001, Function | SmallTest | Level1)
{
    int32_t reminderId = 1;
    ReminderHelper reminderHelper;
    ErrCode ret = reminderHelper.DelExcludeDates(reminderId);
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: GetExcludeDates_00001
 * @tc.desc: Test GetExcludeDates parameters.
 * @tc.type: FUNC
 * @tc.require: issue#I9F24R
 */
HWTEST_F(ReminderHelperTest, GetExcludeDates_00001, Function | SmallTest | Level1)
{
    int32_t reminderId = 1;
    std::vector<int64_t> dates;
    ReminderHelper reminderHelper;
    ErrCode ret = reminderHelper.GetExcludeDates(reminderId, dates);
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: UpdateReminder_00001
 * @tc.desc: Test UpdateReminder parameters.
 * @tc.type: FUNC
 * @tc.require: issue#I9F24R
 */
HWTEST_F(ReminderHelperTest, UpdateReminder_00001, Function | SmallTest | Level1)
{
    ReminderRequest reminder;
    ReminderHelper reminderHelper;
    int32_t reminderId = 1;
    ErrCode ret = reminderHelper.UpdateReminder(reminderId, reminder);
    EXPECT_NE(ret, (int)ERR_OK);
}
}
}
