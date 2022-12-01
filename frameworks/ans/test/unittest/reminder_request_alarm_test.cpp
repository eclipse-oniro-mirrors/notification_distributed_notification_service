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

#define private public
#define protected public
#include "reminder_request_alarm.h"
#undef private
#undef protected

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
    EXPECT_TRUE(rrc->GetRepeatDay() == expectedVal) << "repeatDays (1, 2, 3) should be 7";
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
    EXPECT_TRUE(rrc->GetRepeatDay() == 65) << "repeatDays (1, 12) should be 65";
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
    EXPECT_TRUE(rrc->GetRepeatDay() == 81) << "repeatDays (1, 1, 5 12) should be 81";
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
    EXPECT_TRUE(rrc->GetRepeatDay() == expectedVal) << "repeatDays () should be 0";
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
    std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = nullptr;
    rrc->RecoverFromDb(resultSet);
    uint8_t ret = rrc->GetRepeatDay();
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
}
}