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
#include "reminder_request_calendar.h"
#undef private
#undef protected

#include "ans_log_wrapper.h"
#include "reminder_helper.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class ReminderRequestCalendarTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        ReminderHelper::CancelAllReminders();
    }
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown()
    {
        ReminderHelper::CancelAllReminders();
    }

    std::shared_ptr<ReminderRequestCalendar> CreateCalendar(tm &nowTime)
    {
        time_t now;
        (void)time(&now);  // unit is seconds.
        tm *tmp = localtime(&now);
        if (tmp == nullptr) {
            return nullptr;
        }
        nowTime = *tmp;
        nowTime.tm_year = 0;
        nowTime.tm_mon = 0;
        nowTime.tm_mday = 1;
        nowTime.tm_hour = 1;
        nowTime.tm_min = 1;
        std::vector<uint8_t> repeatMonths;
        std::vector<uint8_t> repeatDays;
        repeatMonths.push_back(1);
        repeatDays.push_back(1);
        auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays);
        calendar->SetNextTriggerTime();
        return calendar;
    }

    bool IsVectorEqual(std::vector<uint8_t> &vectorA, std::vector<uint8_t> &vectorB)
    {
        if (vectorA.size() != vectorB.size()) {
            return false;
        }
        if (vectorA.size() == 0) {
            return true;
        }
        auto vitA = vectorA.begin();
        auto vitB = vectorB.begin();
        while (vitA != vectorA.end()) {
            if (*vitA != *vitB) {
                return false;
            }
            ++vitA;
            ++vitB;
        }
        return true;
    }
};

/**
 * @tc.name: initDateTime_00100
 * @tc.desc: Check firstDesignateYear set successfully.
 * @tc.type: FUNC
 * @tc.require: SR000GN4CU AR000GNF1V
 */
HWTEST_F(ReminderRequestCalendarTest, initDateTime_00100, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    int32_t firstDesignateYear = calendar->GetActualTime(ReminderRequest::TimeTransferType::YEAR, nowTime.tm_year);
    EXPECT_TRUE(firstDesignateYear == calendar->GetFirstDesignateYear()) << "Set first designate year error.";
}

/**
 * @tc.name: initDateTime_00200
 * @tc.desc: Check firstDesignateMonth set successfully.
 * @tc.type: FUNC
 * @tc.require: SR000GN4CU AR000GNF1V
 */
HWTEST_F(ReminderRequestCalendarTest, initDateTime_00200, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    int firstDesignateMonth = calendar->GetActualTime(ReminderRequest::TimeTransferType::MONTH, nowTime.tm_mon);
    EXPECT_TRUE(firstDesignateMonth == calendar->GetFirstDesignageMonth()) << "Set first designate month error.";
}

/**
 * @tc.name: initDateTime_00300
 * @tc.desc: Check firstDesignateDay set successfully.
 * @tc.type: FUNC
 * @tc.require: SR000GN4CU AR000GNF1V
 */
HWTEST_F(ReminderRequestCalendarTest, initDateTime_00300, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    int firstDesignateDay = nowTime.tm_mday;
    EXPECT_TRUE(firstDesignateDay == calendar->GetFirstDesignateDay()) << "Set first designate day error.";
}

/**
 * @tc.name: initDateTime_00400
 * @tc.desc: Check repeatMonth set with normal value successfully.
 * @tc.type: FUNC
 * @tc.require: SR000GN4CU AR000GNF1V
 */
HWTEST_F(ReminderRequestCalendarTest, initDateTime_00400, Function | SmallTest | Level1)
{
    time_t now;
    (void)time(&now);  // unit is seconds.
    tm *tmp = localtime(&now);
    EXPECT_NE(nullptr, tmp);
    struct tm nowTime = *tmp;

    std::vector<uint8_t> repeatMonths;
    std::vector<uint8_t> repeatDays;
    repeatMonths.push_back(1);
    repeatDays.push_back(1);
    auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays);
    calendar->SetNextTriggerTime();
    std::vector<uint8_t> actualRepeatMonths = calendar->GetRepeatMonths();
    EXPECT_TRUE(ReminderRequestCalendarTest::IsVectorEqual(repeatMonths, actualRepeatMonths))
        << "Set repeat month with 1 error.";

    repeatMonths.clear();
    repeatMonths.push_back(12);
    calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays);
    calendar->SetNextTriggerTime();
    actualRepeatMonths = calendar->GetRepeatMonths();
    EXPECT_TRUE(ReminderRequestCalendarTest::IsVectorEqual(repeatMonths, actualRepeatMonths))
        << "Set repeat month with 12 error.";

    repeatMonths.clear();
    for (uint8_t i = 1; i <= 12; i++) {
        repeatMonths.push_back(i);
    }
    calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays);
    calendar->SetNextTriggerTime();
    actualRepeatMonths = calendar->GetRepeatMonths();
    EXPECT_TRUE(ReminderRequestCalendarTest::IsVectorEqual(repeatMonths, actualRepeatMonths))
        << "Set repeat month with 1~12 error.";
}

/**
 * @tc.name: initDateTime_00500
 * @tc.desc: Check repeatMonth set with exception value successfully.
 * @tc.type: FUNC
 * @tc.require: SR000GN4CU AR000GNF1V
 */
HWTEST_F(ReminderRequestCalendarTest, initDateTime_00500, Function | SmallTest | Level1)
{
    time_t now;
    time(&now);  // unit is seconds.
    tm *tmp = localtime(&now);
    EXPECT_NE(nullptr, tmp);
    tm nowTime = *tmp;
    nowTime.tm_year += 1;
    std::vector<uint8_t> repeatMonths;
    std::vector<uint8_t> repeatDays;
    repeatMonths.push_back(-1);
    repeatDays.push_back(1);
    auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays);
    calendar->SetNextTriggerTime();
    std::vector<uint8_t> actualRepeatMonths = calendar->GetRepeatMonths();
    EXPECT_TRUE(actualRepeatMonths.size() == 0) << "Set repeat month with -1 error.";

    repeatMonths.clear();
    repeatMonths.push_back(13);
    calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays);
    calendar->SetNextTriggerTime();
    actualRepeatMonths = calendar->GetRepeatMonths();
    EXPECT_TRUE(actualRepeatMonths.size() == 0) << "Set repeat month with 13 error.";
}

/**
 * @tc.name: initDateTime_00600
 * @tc.desc: Check repeatDay set with nomal value successfully.
 * @tc.type: FUNC
 * @tc.require: SR000GN4CU AR000GNF1V
 */
HWTEST_F(ReminderRequestCalendarTest, initDateTime_00600, Function | SmallTest | Level1)
{
    time_t now;
    (void)time(&now);  // unit is seconds.
    tm *tmp = localtime(&now);
    EXPECT_NE(nullptr, tmp);
    tm nowTime = *tmp;
    std::vector<uint8_t> repeatMonths;
    std::vector<uint8_t> repeatDays;
    repeatMonths.push_back(1);
    repeatDays.push_back(1);
    auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays);
    calendar->SetNextTriggerTime();
    std::vector<uint8_t> actualRepeatDays = calendar->GetRepeatDays();
    EXPECT_TRUE(ReminderRequestCalendarTest::IsVectorEqual(repeatDays, actualRepeatDays))
        << "Set repeat day with 1 error.";

    repeatDays.clear();
    repeatDays.push_back(31);
    calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays);
    calendar->SetNextTriggerTime();
    actualRepeatDays = calendar->GetRepeatDays();
    EXPECT_TRUE(ReminderRequestCalendarTest::IsVectorEqual(repeatDays, actualRepeatDays))
        << "Set repeat day with 31 error.";

    repeatDays.clear();
    for (uint8_t i = 1; i <= 31; i++) {
        repeatDays.push_back(i);
    }
    calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays);
    calendar->SetNextTriggerTime();
    actualRepeatDays = calendar->GetRepeatDays();
    EXPECT_TRUE(ReminderRequestCalendarTest::IsVectorEqual(repeatDays, actualRepeatDays))
        << "Set repeat day with 1~31 error.";
}

/**
 * @tc.name: initDateTime_00700
 * @tc.desc: Check repeatDay set with exception value successfully.
 * @tc.type: FUNC
 * @tc.require: SR000GN4CU AR000GNF1V
 */
HWTEST_F(ReminderRequestCalendarTest, initDateTime_00700, Function | SmallTest | Level1)
{
    time_t now;
    (void)time(&now);  // unit is seconds.
    tm *tmp = localtime(&now);
    EXPECT_NE(nullptr, tmp);
    tm nowTime = *tmp;
    nowTime.tm_year += 1;
    std::vector<uint8_t> repeatMonths;
    std::vector<uint8_t> repeatDays;
    repeatMonths.push_back(-1);
    repeatDays.push_back(-1);
    auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays);
    calendar->SetNextTriggerTime();
    std::vector<uint8_t> actualRepeatDays = calendar->GetRepeatDays();
    EXPECT_TRUE(actualRepeatDays.size() == 0) << "Set repeat day with -1 error.";

    repeatDays.clear();
    repeatDays.push_back(32);
    calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays);
    calendar->SetNextTriggerTime();
    actualRepeatDays = calendar->GetRepeatDays();
    EXPECT_TRUE(actualRepeatDays.size() == 0) << "Set repeat day with 32 error.";
}

/**
 * @tc.name: initDateTime_00800
 * @tc.desc: Check hour set successfully.
 * @tc.type: FUNC
 * @tc.require: SR000GN4CU AR000GNF1V
 */
HWTEST_F(ReminderRequestCalendarTest, initDateTime_00800, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    EXPECT_TRUE(1 == calendar->GetHour()) << "Set hour error.";
}

/**
 * @tc.name: initDateTime_00900
 * @tc.desc: Check minut set successfully.
 * @tc.type: FUNC
 * @tc.require: SR000GN4CU AR000GNF1V
 */
HWTEST_F(ReminderRequestCalendarTest, initDateTime_00900, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    EXPECT_TRUE(1 == calendar->GetMinute()) << "Set minute error.";
    EXPECT_TRUE(0 == calendar->GetSecond()) << "Set seconds error.";
}

/**
 * @tc.name: initDateTime_01000
 * @tc.desc: Test InitDateTime parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, initDateTime_01000, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    calendar->InitDateTime();
    EXPECT_EQ(calendar->IsRepeatReminder(), true);
}

/**
 * @tc.name: OnDateTimeChange_01000
 * @tc.desc: Test OnDateTimeChange parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, OnDateTimeChange_01000, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    EXPECT_EQ(calendar->OnDateTimeChange(), false);
}

/**
 * @tc.name: OnTimeZoneChange_01000
 * @tc.desc: Test OnTimeZoneChange parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, OnTimeZoneChange_01000, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    EXPECT_EQ(calendar->OnTimeZoneChange(), false);
}

/**
 * @tc.name: UpdateNextReminder_01000
 * @tc.desc: Test UpdateNextReminder parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, UpdateNextReminder_01000, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    EXPECT_EQ(calendar->UpdateNextReminder(), true);
}

/**
 * @tc.name: PreGetNextTriggerTimeIgnoreSnooze_01000
 * @tc.desc: Test PreGetNextTriggerTimeIgnoreSnooze parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, PreGetNextTriggerTimeIgnoreSnooze_01000, Function | SmallTest | Level1)
{
    bool ignoreRepeat = true;
    bool forceToGetNext = true;
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    EXPECT_EQ(calendar->PreGetNextTriggerTimeIgnoreSnooze(ignoreRepeat, forceToGetNext),
    calendar->GetNextTriggerTime());
}

/**
 * @tc.name: PreGetNextTriggerTimeIgnoreSnooze_02000
 * @tc.desc: Test PreGetNextTriggerTimeIgnoreSnooze parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, PreGetNextTriggerTimeIgnoreSnooze_02000, Function | SmallTest | Level1)
{
    bool ignoreRepeat = false;
    bool forceToGetNext = true;
    time_t now;
    time(&now);  // unit is seconds.
    tm *tmp = localtime(&now);
    EXPECT_NE(nullptr, tmp);
    tm nowTime = *tmp;
    nowTime.tm_year += 1;
    std::vector<uint8_t> repeatMonths;
    std::vector<uint8_t> repeatDays;
    repeatMonths.push_back(-1);
    repeatDays.push_back(1);
    auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays);
    EXPECT_EQ(calendar->PreGetNextTriggerTimeIgnoreSnooze(ignoreRepeat, forceToGetNext), 0);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    EXPECT_EQ(calendar->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    if (nullptr != calendar) {
        if (nullptr == calendar->Unmarshalling(parcel)) {
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
HWTEST_F(ReminderRequestCalendarTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    EXPECT_EQ(calendar->ReadFromParcel(parcel), false);
}

/**
 * @tc.name: GetDaysOfMonth_00001
 * @tc.desc: Test GetDaysOfMonth parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, GetDaysOfMonth_00001, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);

    uint16_t year = 1;
    uint8_t month = 2;
    uint8_t result = calendar->GetDaysOfMonth(year, month);
    uint8_t ret = 28;
    EXPECT_EQ(result, ret);
}

/**
 * @tc.name: SetDay_00001
 * @tc.desc: Test SetDay parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, SetDay_00001, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);

    uint8_t day = -1;
    bool isSet = false;
    calendar->SetDay(day, isSet);
    bool result = calendar->IsRepeatDay(day);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: SetMonth_00001
 * @tc.desc: Test SetMonth parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, SetMonth_00001, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);

    uint8_t month = -1;
    bool isSet = false;
    calendar->SetMonth(month, isSet);
    bool result = calendar->IsRepeatMonth(month);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: SetRepeatDaysOfMonth_00001
 * @tc.desc: Test SetRepeatDaysOfMonth parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, SetRepeatDaysOfMonth_00001, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);

    std::vector<uint8_t> repeatDays;
    repeatDays.emplace_back(1);
    repeatDays.emplace_back(2);
    repeatDays.emplace_back(3);
    repeatDays.emplace_back(4);
    repeatDays.emplace_back(5);
    repeatDays.emplace_back(6);
    repeatDays.emplace_back(7);
    repeatDays.emplace_back(8);
    repeatDays.emplace_back(9);
    repeatDays.emplace_back(10);
    repeatDays.emplace_back(11);
    repeatDays.emplace_back(12);
    repeatDays.emplace_back(13);
    repeatDays.emplace_back(14);
    repeatDays.emplace_back(15);
    repeatDays.emplace_back(16);
    repeatDays.emplace_back(17);
    repeatDays.emplace_back(18);
    repeatDays.emplace_back(19);
    repeatDays.emplace_back(20);
    repeatDays.emplace_back(21);
    repeatDays.emplace_back(22);
    repeatDays.emplace_back(23);
    repeatDays.emplace_back(24);
    repeatDays.emplace_back(25);
    repeatDays.emplace_back(26);
    repeatDays.emplace_back(27);
    repeatDays.emplace_back(28);
    repeatDays.emplace_back(29);
    repeatDays.emplace_back(30);
    repeatDays.emplace_back(31);
    repeatDays.emplace_back(32);
    EXPECT_EQ(repeatDays.size(), 32);

    calendar->SetRepeatDaysOfMonth(repeatDays);
    std::vector<uint8_t> result = calendar->GetRepeatMonths();
    EXPECT_EQ(result.size(), 1);
}

/**
 * @tc.name: UpdateNextReminder_00001
 * @tc.desc: Test UpdateNextReminder parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, UpdateNextReminder_00001, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);

    uint8_t day = 1;
    bool isSet = false;
    calendar->SetDay(day, isSet);

    uint8_t month = 1;
    calendar->SetMonth(month, isSet);

    auto rrc = std::make_shared<ReminderRequest>();
    rrc->SetSnoozeTimes(0);
    EXPECT_EQ(rrc->GetSnoozeTimes(), 0) << "Get snoozeTimes not 1";

    uint32_t minTimeIntervalInSecond = 0;
    rrc->SetTimeInterval(0);
    EXPECT_EQ(rrc->GetTimeInterval(), minTimeIntervalInSecond);

    bool result2 = calendar->IsRepeatReminder();
    EXPECT_EQ(result2, false);

    uint32_t ret = calendar->GetRepeatDay();
    uint16_t ret2 = calendar->GetRepeatMonth();
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(ret2, 0);

    bool result3 = calendar->UpdateNextReminder();
    EXPECT_EQ(result3, false);
}

/**
 * @tc.name: UpdateNextReminder_00002
 * @tc.desc: Test UpdateNextReminder parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, UpdateNextReminder_00002, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);

    uint8_t day = 2;
    bool isSet = true;
    calendar->SetDay(day, isSet);
    bool result = calendar->IsRepeatDay(day);
    EXPECT_EQ(result, true);

    uint8_t month = 2;
    calendar->SetMonth(month, isSet);
    bool result1 = calendar->IsRepeatMonth(month);
    EXPECT_EQ(result1, true);

    bool result2 = calendar->IsRepeatReminder();
    EXPECT_EQ(result2, true);

    auto rrc = std::make_shared<ReminderRequest>();
    rrc->SetSnoozeTimes(1);
    EXPECT_EQ(rrc->GetSnoozeTimes(), 1) << "Get snoozeTimes not 1";
    EXPECT_EQ(rrc->GetSnoozeTimesDynamic(), 1) << "Get snoozeTimesDynamic not 1";

    uint32_t minTimeIntervalInSecond = 5 * 60;
    rrc->SetTimeInterval(1);
    EXPECT_EQ(rrc->GetTimeInterval(), minTimeIntervalInSecond);

    bool result3 = calendar->UpdateNextReminder();
    EXPECT_EQ(result3, true);
}

/**
 * @tc.name: UpdateNextReminder_00003
 * @tc.desc: Test UpdateNextReminder parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, UpdateNextReminder_00003, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);

    uint8_t day = 1;
    bool isSet = false;
    calendar->SetDay(day, isSet);

    uint8_t month = 2;
    bool isSet1 = true;
    calendar->SetMonth(month, isSet1);

    auto rrc = std::make_shared<ReminderRequest>();
    rrc->SetSnoozeTimesDynamic(0);
    EXPECT_EQ(rrc->GetSnoozeTimesDynamic(), 0);

    rrc->SetSnoozeTimes(1);
    EXPECT_EQ(rrc->GetSnoozeTimes(), 1);
    uint32_t minTimeIntervalInSecond = 5 * 60;
    rrc->SetTimeInterval(1);
    EXPECT_EQ(rrc->GetTimeInterval(), minTimeIntervalInSecond);

    uint32_t ret = calendar->GetRepeatDay();
    uint16_t ret2 = calendar->GetRepeatMonth();
    uint16_t ret3 = 3;
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(ret2, ret3);

    bool result3 = calendar->UpdateNextReminder();
    EXPECT_EQ(result3, false);
}

/**
 * @tc.name: UpdateNextReminder_00004
 * @tc.desc: Test UpdateNextReminder parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, UpdateNextReminder_00004, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);

    uint8_t day = 1;
    bool isSet = false;
    calendar->SetDay(day, isSet);
    bool result = calendar->IsRepeatDay(day);
    EXPECT_EQ(result, false);

    uint8_t month = 1;
    calendar->SetMonth(month, isSet);
    bool result1 = calendar->IsRepeatMonth(month);
    EXPECT_EQ(result1, false);

    auto rrc = std::make_shared<ReminderRequest>();
    rrc->SetSnoozeTimes(1);
    EXPECT_EQ(rrc->GetSnoozeTimes(), 1) << "Get snoozeTimes not 1";

    rrc->SetSnoozeTimesDynamic(0);
    EXPECT_EQ(rrc->GetSnoozeTimesDynamic(), 0) << "Get snoozeTimesDynamic not 1";

    uint32_t minTimeIntervalInSecond = 5 * 60;
    rrc->SetTimeInterval(1);
    EXPECT_EQ(rrc->GetTimeInterval(), minTimeIntervalInSecond);

    bool result3 = calendar->UpdateNextReminder();
    EXPECT_EQ(result3, false);
}

/**
 * @tc.name: UpdateNextReminder_00005
 * @tc.desc: Test UpdateNextReminder parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, UpdateNextReminder_00005, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);

    uint8_t day = 2;
    bool isSet = true;
    calendar->SetDay(day, isSet);
    bool result = calendar->IsRepeatDay(day);
    EXPECT_EQ(result, true);

    uint8_t month = 1;
    bool isSet1 = false;
    calendar->SetMonth(month, isSet1);
    bool result1 = calendar->IsRepeatMonth(month);
    EXPECT_EQ(result1, false);

    auto rrc = std::make_shared<ReminderRequest>();
    rrc->SetSnoozeTimes(1);
    EXPECT_EQ(rrc->GetSnoozeTimes(), 1) << "Get snoozeTimes not 1";

    rrc->SetSnoozeTimesDynamic(0);
    EXPECT_EQ(rrc->GetSnoozeTimesDynamic(), 0) << "Get snoozeTimesDynamic not 1";

    uint32_t minTimeIntervalInSecond = 5 * 60;
    rrc->SetTimeInterval(1);
    EXPECT_EQ(rrc->GetTimeInterval(), minTimeIntervalInSecond);

    bool result3 = calendar->UpdateNextReminder();
    EXPECT_EQ(result3, false);
}
}
}