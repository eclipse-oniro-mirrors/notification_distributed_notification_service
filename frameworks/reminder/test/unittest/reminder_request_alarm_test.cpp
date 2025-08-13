/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "reminder_request_alarm.h"

#include "ans_log_wrapper.h"
#include "reminder_helper.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class ReminderRequestAlarmTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown()
    {
        ReminderHelper::CancelAllReminders();
    }
};

/**
 * @tc.name: initHour_00100
 * @tc.desc: test set edge value of hour (0 and 23).
 * @tc.type: FUNC
 * @tc.require: SR000GGTRC AR000GH8E8
 */
HWTEST_F(ReminderRequestAlarmTest, initHour_00100, Function | SmallTest | Level1)
{
    std::vector<uint8_t> daysOfWeek;
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 1, daysOfWeek);
    EXPECT_TRUE(rrc->GetHour() == 0) << "hour should be 0";

    auto rrcB = std::make_shared<ReminderRequestAlarm>(23, 1, daysOfWeek);
    EXPECT_TRUE(rrcB->GetHour() == 23) << "hour should be 23";

    auto rrcC = std::make_shared<ReminderRequestAlarm>(1, 1, daysOfWeek);
    EXPECT_TRUE(rrcC->GetHour() == 1) << "hour should be 1";

    auto rrcD = std::make_shared<ReminderRequestAlarm>(22, 1, daysOfWeek);
    EXPECT_TRUE(rrcD->GetHour() == 22) << "hour should be 22";

    auto rrcE = std::make_shared<ReminderRequestAlarm>(12, 1, daysOfWeek);
    EXPECT_TRUE(rrcE->GetHour() == 12) << "hour should be 12";
}

/**
 * @tc.name: initHour_00200
 * @tc.desc: test set edge value of minute (0 and 59).
 * @tc.type: FUNC
 * @tc.require: SR000GGTRC AR000GH8E8
 */
HWTEST_F(ReminderRequestAlarmTest, initHour_00200, Function | SmallTest | Level1)
{
    std::vector<uint8_t> daysOfWeek;
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 0, daysOfWeek);
    EXPECT_TRUE(rrc->GetMinute() == 0) << "minute should be 0";

    auto rrcB = std::make_shared<ReminderRequestAlarm>(23, 59, daysOfWeek);
    EXPECT_TRUE(rrcB->GetMinute() == 59) << "minute should be 59";
}

/**
 * @tc.name: initDaysOfWeek_00100
 * @tc.desc: test set daysOfWeek with normal value.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRC AR000GH8E8
 */
HWTEST_F(ReminderRequestAlarmTest, initDaysOfWeek_00100, Function | SmallTest | Level1)
{
    uint8_t arr[] = {1, 2, 3};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 0, daysOfWeek);
    uint8_t expectedVal = 7;
    EXPECT_TRUE(rrc->GetRepeatDaysOfWeek() == expectedVal) << "repeatDays (1, 2, 3) should be 7";
}

/**
 * @tc.name: initDaysOfWeek_00200
 * @tc.desc: test set daysOfWeek with edge value.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRC AR000GH8E8
 */
HWTEST_F(ReminderRequestAlarmTest, initDaysOfWeek_00200, Function | SmallTest | Level1)
{
    uint8_t arr[] = {1, 7};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 0, daysOfWeek);
    EXPECT_TRUE(rrc->GetRepeatDaysOfWeek() == 65) << "repeatDays (1, 12) should be 65";
}

/**
 * @tc.name: initDaysOfWeek_00300
 * @tc.desc: test set daysOfWeek with duplicate value.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRC AR000GH8E8
 */
HWTEST_F(ReminderRequestAlarmTest, initDaysOfWeek_00300, Function | SmallTest | Level1)
{
    uint8_t arr[] = {1, 1, 5, 5, 7, 7, 7};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 0, daysOfWeek);
    EXPECT_TRUE(rrc->GetRepeatDaysOfWeek() == 81) << "repeatDays (1, 1, 5 12) should be 81";
}

/**
 * @tc.name: initDaysOfWeek_00400
 * @tc.desc: test set daysOfWeek with null value.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRC AR000GH8E8
 */
HWTEST_F(ReminderRequestAlarmTest, initDaysOfWeek_00400, Function | SmallTest | Level1)
{
    uint8_t arr[] = {};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 0, daysOfWeek);
    uint8_t expectedVal = 0;
    EXPECT_TRUE(rrc->GetRepeatDaysOfWeek() == expectedVal) << "repeatDays () should be 0";
}

/**
 * @tc.name: IsRepeatReminder_00100
 * @tc.desc: Test IsRepeatReminder parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, IsRepeatReminder_00100, Function | SmallTest | Level1)
{
    uint8_t arr[] = {};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 0, daysOfWeek);
    EXPECT_EQ(rrc->IsRepeatReminder(), false);
    EXPECT_EQ(rrc->UpdateNextReminder(), false);
}

/**
 * @tc.name: IsRepeatReminder_00200
 * @tc.desc: Test IsRepeatReminder parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, IsRepeatReminder_00200, Function | SmallTest | Level1)
{
    uint8_t arr[] = {1, 1, 5, 5, 7, 7, 7};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 1, daysOfWeek);
    EXPECT_EQ(rrc->IsRepeatReminder(), true);
    EXPECT_EQ(rrc->UpdateNextReminder(), true);
}

/**
 * @tc.name: IsRepeatReminder_00300
 * @tc.desc: Test IsRepeatReminder parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, IsRepeatReminder_00300, Function | SmallTest | Level1)
{
    uint8_t arr[] = {1, 1, 5, 5, 7, 7, 7};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 1, daysOfWeek);

    auto ret = std::make_shared<ReminderRequest>();
    ret->SetSnoozeTimes(1);
    EXPECT_EQ(ret->GetSnoozeTimes(), 1);

    uint32_t minTimeIntervalInSecond = ReminderRequest::MIN_TIME_INTERVAL_IN_MILLI / ReminderRequest::MILLI_SECONDS;
    ret->SetTimeInterval(1);
    EXPECT_EQ(ret->GetTimeInterval(), minTimeIntervalInSecond);
    EXPECT_EQ(rrc->IsRepeatReminder(), true);
}

/**
 * @tc.name: IsRepeatReminder_00400
 * @tc.desc: Test IsRepeatReminder parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, IsRepeatReminder_00400, Function | SmallTest | Level1)
{
    uint8_t arr[] = {1, 1, 5, 5, 7, 7, 7};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 1, daysOfWeek);

    auto ret = std::make_shared<ReminderRequest>();
    ret->SetSnoozeTimes(0);
    EXPECT_EQ(ret->GetSnoozeTimes(), 0);

    uint32_t minTimeIntervalInSecond = ReminderRequest::MIN_TIME_INTERVAL_IN_MILLI / ReminderRequest::MILLI_SECONDS;
    ret->SetTimeInterval(1);
    EXPECT_EQ(ret->GetTimeInterval(), minTimeIntervalInSecond);
    EXPECT_EQ(rrc->IsRepeatReminder(), true);
}

/**
 * @tc.name: IsRepeatReminder_00500
 * @tc.desc: Test IsRepeatReminder parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, IsRepeatReminder_00500, Function | SmallTest | Level1)
{
    uint8_t arr[] = {1, 1, 5, 5, 7, 7, 7};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 1, daysOfWeek);

    auto ret = std::make_shared<ReminderRequest>();
    ret->SetSnoozeTimes(1);
    EXPECT_EQ(ret->GetSnoozeTimes(), 1);

    uint32_t minTimeIntervalInSecond = 0;
    ret->SetTimeInterval(0);
    EXPECT_EQ(ret->GetTimeInterval(), minTimeIntervalInSecond);
    EXPECT_EQ(rrc->IsRepeatReminder(), true);
}

/**
 * @tc.name: IsRepeatReminder_00600
 * @tc.desc: Test IsRepeatReminder parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, IsRepeatReminder_00600, Function | SmallTest | Level1)
{
    uint8_t arr[] = {};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 0, daysOfWeek);

    auto ret = std::make_shared<ReminderRequest>();
    ret->SetSnoozeTimes(1);
    EXPECT_EQ(ret->GetSnoozeTimes(), 1);

    uint32_t minTimeIntervalInSecond = ReminderRequest::MIN_TIME_INTERVAL_IN_MILLI / ReminderRequest::MILLI_SECONDS;
    rrc->SetTimeInterval(1);
    EXPECT_EQ(rrc->GetTimeInterval(), minTimeIntervalInSecond);
    EXPECT_EQ(rrc->IsRepeatReminder(), true);
}

/**
 * @tc.name: PreGetNextTriggerTimeIgnoreSnooze_00100
 * @tc.desc: Test PreGetNextTriggerTimeIgnoreSnooze parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, PreGetNextTriggerTimeIgnoreSnooze_00100, Function | SmallTest | Level1)
{
    bool ignoreRepeat = true;
    bool forceToGetNext = true;
    uint8_t arr[] = {1, 1, 5, 5, 7, 7, 7};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 1, daysOfWeek);
    rrc->PreGetNextTriggerTimeIgnoreSnooze(ignoreRepeat, forceToGetNext);
    EXPECT_EQ(rrc->GetNextTriggerTime(forceToGetNext),
    rrc->PreGetNextTriggerTimeIgnoreSnooze(ignoreRepeat, forceToGetNext));
}

/**
 * @tc.name: PreGetNextTriggerTimeIgnoreSnooze_00200
 * @tc.desc: Test PreGetNextTriggerTimeIgnoreSnooze parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, PreGetNextTriggerTimeIgnoreSnooze_00200, Function | SmallTest | Level1)
{
    uint8_t arr[] = {};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 0, daysOfWeek);
    
    bool ignoreRepeat = false;
    bool forceToGetNext = false;
    uint64_t result = rrc->PreGetNextTriggerTimeIgnoreSnooze(ignoreRepeat, forceToGetNext);
    EXPECT_EQ(result, ReminderRequest::INVALID_LONG_LONG_VALUE);
}

/**
 * @tc.name: PreGetNextTriggerTimeIgnoreSnooze_00300
 * @tc.desc: Test PreGetNextTriggerTimeIgnoreSnooze parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, PreGetNextTriggerTimeIgnoreSnooze_00300, Function | SmallTest | Level1)
{
    bool ignoreRepeat = true;
    bool forceToGetNext = true;
    uint8_t arr[] = {};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 0, daysOfWeek);

    rrc->PreGetNextTriggerTimeIgnoreSnooze(ignoreRepeat, forceToGetNext);
    EXPECT_EQ(rrc->GetNextTriggerTime(forceToGetNext),
    rrc->PreGetNextTriggerTimeIgnoreSnooze(ignoreRepeat, forceToGetNext));
}

/**
 * @tc.name: GetDaysOfWeek_00100
 * @tc.desc: Test GetDaysOfWeek parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, GetDaysOfWeek_00100, Function | SmallTest | Level1)
{
    uint8_t arr[] = {};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 0, daysOfWeek);
    auto ret = rrc->GetDaysOfWeek();
    EXPECT_EQ(ret.size(), 0);
}

/**
 * @tc.name: OnDateTimeChange_00100
 * @tc.desc: Test OnDateTimeChange parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, OnDateTimeChange_00100, Function | SmallTest | Level1)
{
    uint8_t arr[] = {};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 0, daysOfWeek);
    EXPECT_EQ(rrc->OnDateTimeChange(), false);
}

/**
 * @tc.name: RecoverFromDb_00100
 * @tc.desc: Test RecoverFromDb parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, RecoverFromDb_00100, Function | SmallTest | Level1)
{
    uint8_t arr[] = {};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 0, daysOfWeek);
    uint8_t ret = rrc->GetRepeatDaysOfWeek();
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    uint8_t arr[] = {};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 0, daysOfWeek);
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    uint8_t arr[] = {};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    std::shared_ptr<ReminderRequestAlarm> result =
    std::make_shared<ReminderRequestAlarm>(0, 0, daysOfWeek);
    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, false);
}

/**
 * @tc.name: ReadFromParcel_00001
 * @tc.desc: Test ReadFromParcel parameters.
 * @tc.type: FUNC
 * @tc.require: issueI
 */
HWTEST_F(ReminderRequestAlarmTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    uint8_t arr[] = {};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 0, daysOfWeek);
    EXPECT_EQ(rrc->ReadFromParcel(parcel), false);
}

/**
 * @tc.name: CheckParamValid_00100
 * @tc.desc: Test CheckParamValid parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, CheckParamValid_00100, Function | SmallTest | Level1)
{
    uint8_t arr[] = {};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(25, 0, daysOfWeek);

    rrc->CheckParamValid();
    uint8_t ret = 25;
    EXPECT_EQ(rrc->GetHour(), ret);
}

/**
 * @tc.name: CheckParamValid_00200
 * @tc.desc: Test CheckParamValid parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, CheckParamValid_00200, Function | SmallTest | Level1)
{
    uint8_t arr[] = {};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(2, 61, daysOfWeek);

    rrc->CheckParamValid();
    uint8_t ret = 61;
    EXPECT_EQ(rrc->GetMinute(), ret);
}

/**
 * @tc.name: SetDaysOfWeek_00100
 * @tc.desc: Test SetRepeatDaysOfWeek parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, SetDaysOfWeek_00100, Function | SmallTest | Level1)
{
    uint8_t arr[] = {1, 1, 5, 5, 7, 7, 7, 8};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(1, 1, daysOfWeek);

    bool set = true;
    rrc->SetRepeatDaysOfWeek(set, daysOfWeek);
    std::vector<int32_t> result = rrc->GetDaysOfWeek();
    EXPECT_EQ(result.size(), 0);
}

/**
 * @tc.name: SetDaysOfWeek_00200
 * @tc.desc: Test SetRepeatDaysOfWeek parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, SetDaysOfWeek_00200, Function | SmallTest | Level1)
{
    uint8_t arr[] = {1, 1, 5, 5, 7, 7, 7};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(1, 1, daysOfWeek);

    bool set = false;
    rrc->SetRepeatDaysOfWeek(set, daysOfWeek);
    std::vector<int32_t> result = rrc->GetDaysOfWeek();
    EXPECT_EQ(result.size(), 0);
}

/**
 * @tc.name: UpdateNextReminder_00100
 * @tc.desc: Test UpdateNextReminder parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, UpdateNextReminder_00100, Function | SmallTest | Level1)
{
    uint8_t arr[] = {1, 1, 5, 5, 7, 7, 7};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 1, daysOfWeek);
    EXPECT_EQ(rrc->IsRepeatReminder(), true);

    auto ret = std::make_shared<ReminderRequest>();
    ret->SetSnoozeTimesDynamic(1);
    EXPECT_EQ(ret->GetSnoozeTimesDynamic(), 1);
    uint32_t minTimeIntervalInSecond = ReminderRequest::MIN_TIME_INTERVAL_IN_MILLI / ReminderRequest::MILLI_SECONDS;
    ret->SetTimeInterval(1);
    EXPECT_EQ(ret->GetTimeInterval(), minTimeIntervalInSecond);
    EXPECT_EQ(rrc->UpdateNextReminder(), true);
}

/**
 * @tc.name: UpdateNextReminder_00200
 * @tc.desc: Test UpdateNextReminder parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestAlarmTest, UpdateNextReminder_00200, Function | SmallTest | Level1)
{
    uint8_t arr[] = {};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto reminderRequestAlarm = std::make_shared<ReminderRequestAlarm>(0, 0, daysOfWeek);

    auto ret = std::make_shared<ReminderRequest>();
    ret->SetSnoozeTimes(1);
    EXPECT_EQ(ret->GetSnoozeTimes(), 1);

    uint32_t minTimeIntervalInSecond = ReminderRequest::MIN_TIME_INTERVAL_IN_MILLI / ReminderRequest::MILLI_SECONDS;
    reminderRequestAlarm->SetTimeInterval(1);
    EXPECT_EQ(reminderRequestAlarm->GetTimeInterval(), minTimeIntervalInSecond);

    ret->SetSnoozeTimesDynamic(0);
    EXPECT_EQ(ret->GetSnoozeTimesDynamic(), 0);
    uint8_t result = reminderRequestAlarm->GetRepeatDaysOfWeek();
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reminderRequestAlarm->IsRepeatReminder(), true);
    EXPECT_EQ(reminderRequestAlarm->UpdateNextReminder(), true);
}

/**
 * @tc.name: RecoverFromOldVersion_00001
 * @tc.desc: Test RecoverFromDb parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderRequestAlarmTest, RecoverFromOldVersion_00001, Function | SmallTest | Level1)
{
    uint8_t arr[] = {};
    std::vector<uint8_t> daysOfWeek (arr, arr + sizeof(arr) / sizeof(uint8_t));
    auto rrc = std::make_shared<ReminderRequestAlarm>(0, 0, daysOfWeek);
    uint8_t ret = rrc->GetRepeatDaysOfWeek();
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: SetMinute_001
 * @tc.desc: Test SetMinute parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestAlarmTest, SetMinute_001, Function | SmallTest | Level1)
{
    ReminderRequestAlarm alarm(1);
    EXPECT_EQ(alarm.GetMinute(), 0);

    alarm.SetMinute(19);
    EXPECT_EQ(alarm.GetMinute(), 19);
}

/**
 * @tc.name: SetHour_001
 * @tc.desc: Test SetHour parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestAlarmTest, SetHour_001, Function | SmallTest | Level1)
{
    ReminderRequestAlarm alarm(1);
    EXPECT_EQ(alarm.GetHour(), 0);

    alarm.SetHour(19);
    EXPECT_EQ(alarm.GetHour(), 19);
}

/**
 * @tc.name: Construct_001
 * @tc.desc: Test Construct parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestAlarmTest, Construct_001, Function | SmallTest | Level1)
{
    ReminderRequestAlarm alarm1(35);
    EXPECT_EQ(alarm1.GetReminderId(), 35);

    ReminderRequestAlarm alarm2(12, 12, std::vector<uint8_t>());
    EXPECT_EQ(alarm2.GetHour(), 12);
    EXPECT_EQ(alarm2.GetMinute(), 12);

    ReminderRequestAlarm alarm3(alarm2);
    EXPECT_EQ(alarm3.GetHour(), 12);
    EXPECT_EQ(alarm3.GetMinute(), 12);

    ReminderRequestAlarm alarm4;
    EXPECT_EQ(alarm4.GetReminderId(), -1);
}

/**
 * @tc.name: ReminderRequestAlarmTest_001
 * @tc.desc: Test UpdateNextReminder parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestAlarmTest, ReminderRequestAlarmTest_001, Function | SmallTest | Level1)
{
    ReminderRequestAlarm alarm;
    alarm.timeIntervalInMilli_ = 1000;
    alarm.snoozeTimes_ = 1;
    alarm.snoozeTimesDynamic_ = 0;
    alarm.UpdateNextReminder();
    EXPECT_EQ(alarm.IsExpired(), true);
}

/**
 * @tc.name: ReminderRequestAlarmTest_002
 * @tc.desc: Test PreGetNextTriggerTimeIgnoreSnooze parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestAlarmTest, ReminderRequestAlarmTest_002, Function | SmallTest | Level1)
{
    ReminderRequestAlarm alarm;
    alarm.repeatDaysOfWeek_ = 0;
    uint64_t ret = alarm.PreGetNextTriggerTimeIgnoreSnooze(true, false);
    EXPECT_GE(ret, ReminderRequest::INVALID_LONG_LONG_VALUE);
    alarm.repeatDaysOfWeek_ = 1;
    ret = alarm.PreGetNextTriggerTimeIgnoreSnooze(false, false);
    EXPECT_GE(ret, ReminderRequest::INVALID_LONG_LONG_VALUE);
    alarm.repeatDaysOfWeek_ = 0;
    ret = alarm.PreGetNextTriggerTimeIgnoreSnooze(false, false);
    EXPECT_EQ(ret, ReminderRequest::INVALID_LONG_LONG_VALUE);
}
}
}