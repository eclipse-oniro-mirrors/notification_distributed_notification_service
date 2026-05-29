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

#include "ans_log_wrapper.h"
#include "reminder_request_timer.h"
#include "reminder_helper.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class ReminderRequestTimerTest : public testing::Test {
public:
    void SetUp() {}
    void TearDown()
    {
        ReminderHelper::CancelAllReminders();
    }
    static void SetUpTestCase()
    {
        ReminderHelper::CancelAllReminders();
    }
    static void TearDownTestCase() {}
};

/**
 * @tc.name: initCountDownTime_00100
 * @tc.desc: set countDownTime with normal value.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRC AR000GH8E8
 */
HWTEST_F(ReminderRequestTimerTest, initCountDownTime_00100, Function | SmallTest | Level1)
{
    uint64_t countDownTimeInSeconds = 1;
    auto rrc = std::make_shared<ReminderRequestTimer>(countDownTimeInSeconds);
    EXPECT_TRUE(rrc->GetInitInfo() == 1) << "countDownTime is not 1";

    countDownTimeInSeconds = 10;
    auto rrc2 = std::make_shared<ReminderRequestTimer>(countDownTimeInSeconds);
    EXPECT_TRUE(rrc2->GetInitInfo() == 10) << "countDownTime is not 10";

    countDownTimeInSeconds = 100;
    auto rrc3 = std::make_shared<ReminderRequestTimer>(countDownTimeInSeconds);
    EXPECT_TRUE(rrc3->GetInitInfo() == 100) << "countDownTime is not 1";
}

/**
 * @tc.number    : ANS_OnDateTimeChange_01000
 * @tc.name      : OnDateTimeChange01000
 * @tc.type      : FUNC
 * @tc.require   : issueI5R30Z
 */
HWTEST_F(ReminderRequestTimerTest, OnDateTimeChange_00100, Function | SmallTest | Level1)
{
    uint64_t countDownTimeInSeconds = 1;
    auto rrc = std::make_shared<ReminderRequestTimer>(countDownTimeInSeconds);
    auto result = rrc->OnDateTimeChange();
    EXPECT_EQ(result, false);
}

/**
 * @tc.number    : ANS_OnTimeZoneChange_01000
 * @tc.name      : OnTimeZoneChange01000
 * @tc.type      : FUNC
 * @tc.require   : issueI5R30Z
 */
HWTEST_F(ReminderRequestTimerTest, OnTimeZoneChange_00100, Function | SmallTest | Level1)
{
    uint64_t countDownTimeInSeconds = 1;
    auto rrc = std::make_shared<ReminderRequestTimer>(countDownTimeInSeconds);
    auto result = rrc->OnTimeZoneChange();
    EXPECT_EQ(result, false);
}

/**
 * @tc.number    : ANS_Marshalling_01000
 * @tc.name      : Marshalling01000
 * @tc.type      : FUNC
 * @tc.require   : issueI5R30Z
 */
HWTEST_F(ReminderRequestTimerTest, Marshalling_00100, Function | SmallTest | Level1)
{
    uint64_t countDownTimeInSeconds = 1;
    Parcel parcel;
    auto rrc = std::make_shared<ReminderRequestTimer>(countDownTimeInSeconds);
    auto result = rrc->Marshalling(parcel);
    EXPECT_EQ(result, true);
}

/**
 * @tc.number    : ANS_ReadFromParcel_01000
 * @tc.name      : ReadFromParcel01000
 * @tc.type      : FUNC
 * @tc.require   : issueI5R30Z
 */
HWTEST_F(ReminderRequestTimerTest, ReadFromParcel_00100, Function | SmallTest | Level1)
{
    uint64_t countDownTimeInSeconds = 1;
    Parcel parcel;
    auto rrc = std::make_shared<ReminderRequestTimer>(countDownTimeInSeconds);
    auto result = rrc->ReadFromParcel(parcel);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: SetHour_001
 * @tc.desc: Test SetHour parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestTimerTest, SetInitInfo_001, Function | SmallTest | Level1)
{
    ReminderRequestTimer timer(1);
    EXPECT_EQ(timer.GetInitInfo(), 0);

    timer.SetInitInfo(120);
    EXPECT_EQ(timer.GetInitInfo(), 120);
}

/**
 * @tc.name: UpdateNextReminder_001
 * @tc.desc: Test UpdateNextReminder parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestTimerTest, UpdateNextReminder_001, Function | SmallTest | Level1)
{
    ReminderRequestTimer timer(1);
    uint64_t now = timer.GetNowInstantMilli();
    timer.SetTriggerTimeInMilli(now + 2000 * ReminderRequest::MILLI_SECONDS);
    EXPECT_EQ(timer.UpdateNextReminder(), true);
    timer.SetTriggerTimeInMilli(now - 2000 * ReminderRequest::MILLI_SECONDS);
    EXPECT_EQ(timer.UpdateNextReminder(), false);
    timer.SetRepeatInfo(500, 0);
    EXPECT_EQ(timer.UpdateNextReminder(), true);
    timer.SetRepeatInfo(500, 10);
    EXPECT_EQ(timer.UpdateNextReminder(), true);
    timer.SetTriggerTimeInMilli(now - 2000 * ReminderRequest::MILLI_SECONDS);
    timer.SetRepeatInfo(500, 10, -2);
    EXPECT_EQ(timer.UpdateNextReminder(), false);
}

/**
 * @tc.name: PreGetNextTriggerTimeIgnoreSnooze_001
 * @tc.desc: Test PreGetNextTriggerTimeIgnoreSnooze parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestTimerTest, PreGetNextTriggerTimeIgnoreSnooze_001, Function | SmallTest | Level1)
{
    ReminderRequestTimer timer(1);
    timer.SetTriggerTimeInMilli(5000);
    EXPECT_EQ(timer.PreGetNextTriggerTimeIgnoreSnooze(true, true), ReminderRequest::INVALID_LONG_LONG_VALUE);
    timer.SetRepeatInfo(500, 0, 0);
    EXPECT_EQ(timer.PreGetNextTriggerTimeIgnoreSnooze(true, true), 5000);
    timer.SetRepeatInfo(500, 10, 1);
    EXPECT_EQ(timer.PreGetNextTriggerTimeIgnoreSnooze(true, true), 5000);
    timer.SetRepeatInfo(500, 10, -2);
    EXPECT_EQ(timer.PreGetNextTriggerTimeIgnoreSnooze(true, true), ReminderRequest::INVALID_LONG_LONG_VALUE);
}

/**
 * @tc.name: Construct_001
 * @tc.desc: Test Construct parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestTimerTest, Construct_001, Function | SmallTest | Level1)
{
    ReminderRequestTimer timer1(35);
    EXPECT_EQ(timer1.GetReminderId(), 35);

    ReminderRequestTimer timer2((uint64_t)60);
    EXPECT_EQ(timer2.GetInitInfo(), 60);

    ReminderRequestTimer timer3(timer2);
    EXPECT_EQ(timer3.GetInitInfo(), 60);

    ReminderRequestTimer timer4;
    EXPECT_EQ(timer4.GetReminderId(), -1);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderRequestTimerTest, ReminderRequestTimerTest_002, Function | SmallTest | Level1)
{
    ReminderRequestTimer timer(35);
    Parcel parcel;
    bool result = false;
    if (nullptr == timer.Unmarshalling(parcel)) {
        result = true;
    }
    EXPECT_EQ(true, result);
}
}
}