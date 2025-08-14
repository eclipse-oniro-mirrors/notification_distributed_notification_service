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

#include "reminder_request_calendar.h"
#include "reminder_table.h"

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
    void SetUp() {}
    static void TearDownTestCase() {}
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
        std::vector<uint8_t> daysOfWeek;
        repeatMonths.push_back(1);
        repeatDays.push_back(1);
        daysOfWeek.push_back(1);
        auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
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
    std::vector<uint8_t> daysOfWeek;
    daysOfWeek.push_back(1);
    repeatMonths.push_back(1);
    repeatDays.push_back(1);
    auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
    calendar->SetNextTriggerTime();
    std::vector<uint8_t> actualRepeatMonths = calendar->GetRepeatMonths();
    EXPECT_TRUE(ReminderRequestCalendarTest::IsVectorEqual(repeatMonths, actualRepeatMonths))
        << "Set repeat month with 1 error.";

    repeatMonths.clear();
    repeatMonths.push_back(12);
    calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
    calendar->SetNextTriggerTime();
    actualRepeatMonths = calendar->GetRepeatMonths();
    EXPECT_TRUE(ReminderRequestCalendarTest::IsVectorEqual(repeatMonths, actualRepeatMonths))
        << "Set repeat month with 12 error.";

    repeatMonths.clear();
    for (uint8_t i = 1; i <= 12; i++) {
        repeatMonths.push_back(i);
    }
    calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
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
    std::vector<uint8_t> repeatMonth;
    std::vector<uint8_t> repeatDay;
    std::vector<uint8_t> daysOfWeek;
    daysOfWeek.push_back(1);
    repeatMonth.push_back(-1);
    repeatDay.push_back(1);
    auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonth, repeatDay, daysOfWeek);
    calendar->SetNextTriggerTime();
    std::vector<uint8_t> actualRepeatMonths = calendar->GetRepeatMonths();
    EXPECT_TRUE(actualRepeatMonths.size() == 0) << "Set repeat month with -1 error.";

    repeatMonth.clear();
    repeatMonth.push_back(13);
    calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonth, repeatDay, daysOfWeek);
    calendar->SetNextTriggerTime();
    actualRepeatMonths = calendar->GetRepeatMonths();
    EXPECT_TRUE(actualRepeatMonths.size() == 0) << "Set repeat month with 13 error.";
}

namespace {
    bool g_mockNowInstantMilliRet = true;
    uint64_t g_mockNumber = 1675876480000;
}

void MockNowInstantMilli(bool mockRet)
{
    g_mockNowInstantMilliRet = mockRet;
}

uint64_t ReminderRequest::GetNowInstantMilli() const
{
    if (g_mockNowInstantMilliRet == false) {
        return 0;
    }
    return g_mockNumber;
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
    std::vector<uint8_t> daysOfWeek;
    daysOfWeek.push_back(1);
    repeatMonths.push_back(1);
    repeatDays.push_back(1);
    auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
    calendar->SetNextTriggerTime();
    std::vector<uint8_t> actualRepeatDays = calendar->GetRepeatDays();
    EXPECT_TRUE(ReminderRequestCalendarTest::IsVectorEqual(repeatDays, actualRepeatDays))
        << "Set repeat day with 1 error.";

    repeatDays.clear();
    repeatDays.push_back(31);
    calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
    calendar->SetNextTriggerTime();
    actualRepeatDays = calendar->GetRepeatDays();
    EXPECT_TRUE(ReminderRequestCalendarTest::IsVectorEqual(repeatDays, actualRepeatDays))
        << "Set repeat day with 31 error.";

    repeatDays.clear();
    for (uint8_t i = 1; i <= 31; i++) {
        repeatDays.push_back(i);
    }
    calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
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
    std::vector<uint8_t> daysOfWeek;
    daysOfWeek.push_back(-1);
    repeatMonths.push_back(-1);
    repeatDays.push_back(-1);
    auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
    calendar->SetNextTriggerTime();
    std::vector<uint8_t> actualRepeatDays = calendar->GetRepeatDays();
    EXPECT_TRUE(actualRepeatDays.size() == 0) << "Set repeat day with -1 error.";

    repeatDays.clear();
    repeatDays.push_back(32);
    calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
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
 * @tc.name: PreGetNextTriggerTimeIgnoreSnooze_03000
 * @tc.desc: Test PreGetNextTriggerTimeIgnoreSnooze parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, PreGetNextTriggerTimeIgnoreSnooze_03000, Function | SmallTest | Level1)
{
    bool ignoreRepeat = false;
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
    std::vector<uint8_t> daysOfWeek;
    daysOfWeek.push_back(-1);
    repeatMonths.push_back(-1);
    repeatDays.push_back(-1);
    auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
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
 * @tc.name: SetDay_00002
 * @tc.desc: Test SetDay parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, SetDay_00002, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);

    uint8_t day = 32;
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
 * @tc.name: SetMonth_00002
 * @tc.desc: Test SetMonth parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, SetMonth_00002, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);

    uint8_t month = 13;
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

    std::vector<uint8_t> repeatDaysOfWeek;
    repeatDaysOfWeek.push_back(1);
    calendar->SetRepeatDaysOfWeek(isSet, repeatDaysOfWeek);

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
    uint8_t ret3 = calendar->GetRepeatMonth();
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(ret2, 0);
    EXPECT_EQ(ret3, 0);

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

    uint32_t minTimeIntervalInSecond = ReminderRequest::MIN_TIME_INTERVAL_IN_MILLI / ReminderRequest::MILLI_SECONDS;
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

    std::vector<uint8_t> daysOfWeek;
    daysOfWeek.push_back(1);
    calendar->SetRepeatDaysOfWeek(isSet, daysOfWeek);

    auto rrc = std::make_shared<ReminderRequest>();
    rrc->SetSnoozeTimesDynamic(0);
    EXPECT_EQ(rrc->GetSnoozeTimesDynamic(), 0);

    rrc->SetSnoozeTimes(1);
    EXPECT_EQ(rrc->GetSnoozeTimes(), 1);
    uint32_t minTimeIntervalInSecond = ReminderRequest::MIN_TIME_INTERVAL_IN_MILLI / ReminderRequest::MILLI_SECONDS;
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
    bool result7 = calendar->IsRepeatMonth(month);
    EXPECT_EQ(result7, false);

    std::vector<uint8_t> daysOfWeek;
    daysOfWeek.push_back(1);
    calendar->SetRepeatDaysOfWeek(isSet, daysOfWeek);
    bool result2 = calendar->IsRepeatDaysOfWeek(1);
    EXPECT_EQ(result2, false);

    auto reminderRequest = std::make_shared<ReminderRequest>();
    reminderRequest->SetSnoozeTimes(1);
    EXPECT_EQ(reminderRequest->GetSnoozeTimes(), 1) << "Get snoozeTimes not 1";

    reminderRequest->SetSnoozeTimesDynamic(0);
    EXPECT_EQ(reminderRequest->GetSnoozeTimesDynamic(), 0) << "Get snoozeTimesDynamic not 1";

    uint32_t minTimeIntervalInSecond = ReminderRequest::MIN_TIME_INTERVAL_IN_MILLI / ReminderRequest::MILLI_SECONDS;
    reminderRequest->SetTimeInterval(1);
    EXPECT_EQ(reminderRequest->GetTimeInterval(), minTimeIntervalInSecond);

    bool result6 = calendar->UpdateNextReminder();
    EXPECT_EQ(result6, false);
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

    std::vector<uint8_t> daysOfWeek;
    daysOfWeek.push_back(1);
    calendar->SetRepeatDaysOfWeek(isSet1, daysOfWeek);

    auto rrc = std::make_shared<ReminderRequest>();
    rrc->SetSnoozeTimes(1);
    EXPECT_EQ(rrc->GetSnoozeTimes(), 1) << "Get snoozeTimes not 1";

    rrc->SetSnoozeTimesDynamic(0);
    EXPECT_EQ(rrc->GetSnoozeTimesDynamic(), 0) << "Get snoozeTimesDynamic not 1";

    uint32_t minTimeIntervalInSecond = ReminderRequest::MIN_TIME_INTERVAL_IN_MILLI / ReminderRequest::MILLI_SECONDS;
    rrc->SetTimeInterval(1);
    EXPECT_EQ(rrc->GetTimeInterval(), minTimeIntervalInSecond);

    bool result3 = calendar->UpdateNextReminder();
    EXPECT_EQ(result3, false);
}

/**
 * @tc.name: UpdateNextReminder_00006
 * @tc.desc: Test UpdateNextReminder parameters.
 * @tc.type: FUNC
 * @tc.require: I8CZ6P
 */
HWTEST_F(ReminderRequestCalendarTest, UpdateNextReminder_00006, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);

    uint8_t day = 2;
    bool isSet = false;
    bool isSet1 = true;
    calendar->SetDay(day, isSet);
    bool result = calendar->IsRepeatDay(day);
    EXPECT_EQ(result, false);

    uint8_t month = 2;
    calendar->SetMonth(month, isSet);
    bool result1 = calendar->IsRepeatMonth(month);
    EXPECT_EQ(result1, false);

    std::vector<uint8_t> daysOfWeek;
    daysOfWeek.push_back(1);
    daysOfWeek.push_back(3);
    daysOfWeek.push_back(4);
    daysOfWeek.push_back(5);
    daysOfWeek.push_back(6);
    calendar->SetRepeatDaysOfWeek(isSet1, daysOfWeek);

    bool result2 = calendar->IsRepeatDaysOfWeek(1);
    EXPECT_EQ(result2, true);

    bool result3 = calendar->IsRepeatReminder();
    EXPECT_EQ(result3, true);

    auto rrc = std::make_shared<ReminderRequest>();
    rrc->SetSnoozeTimes(1);
    EXPECT_EQ(rrc->GetSnoozeTimes(), 1) << "Get snoozeTimes not 1";
    EXPECT_EQ(rrc->GetSnoozeTimesDynamic(), 1) << "Get snoozeTimesDynamic not 1";

    uint32_t minTimeIntervalInSecond = ReminderRequest::MIN_TIME_INTERVAL_IN_MILLI / ReminderRequest::MILLI_SECONDS;
    rrc->SetTimeInterval(1);
    EXPECT_EQ(rrc->GetTimeInterval(), minTimeIntervalInSecond);

    bool result4 = calendar->UpdateNextReminder();
    EXPECT_EQ(result4, true);

    uint16_t ret2 = calendar->GetRepeatDaysOfWeek();
    uint16_t ret3 = 61;
    EXPECT_EQ(ret2, ret3);
}

/**
 * @tc.name: SetRepeatMonths_00001
 * @tc.desc: Test SetRepeatMonths parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, SetRepeatMonths_00001, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);

    uint8_t arr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
    std::vector<uint8_t> repeatMonths (arr, arr + sizeof(arr) / sizeof(uint8_t));
    calendar->SetRepeatMonths(repeatMonths);
    uint8_t ret = 13;
    EXPECT_EQ(repeatMonths.size(), ret);
}

/**
 * @tc.name: RecoverFromDb_00001
 * @tc.desc: Test RecoverFromDb parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestCalendarTest, RecoverFromDb_00001, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);

    bool result = calendar->IsRepeatDay(1);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: CheckCalenderIsExpired_00001
 * @tc.desc: Test CheckCalenderIsExpired parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, CheckCalenderIsExpired_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestCalendar>();
    rrc->startDateTime_ = 1675876470000;
    rrc->endDateTime_ = 1675876480005;
    uint64_t now = 1675876480005;
    EXPECT_EQ(rrc->CheckCalenderIsExpired(now), true);
}

/**
 * @tc.name: CheckCalenderIsExpired_00002
 * @tc.desc: Test CheckCalenderIsExpired parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, CheckCalenderIsExpired_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestCalendar>();
    uint64_t now = 1675876480005;
    EXPECT_EQ(rrc->CheckCalenderIsExpired(now), false);
}

/**
 * @tc.name: CheckCalenderIsExpired_00003
 * @tc.desc: Test CheckCalenderIsExpired parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, CheckCalenderIsExpired_00003, Function | SmallTest | Level1)
{
    time_t now;
    (void)time(&now);  // unit is seconds.
    struct tm nowTime;
    (void)localtime_r(&now, &nowTime);
    std::vector<uint8_t> repeatMonths;
    std::vector<uint8_t> repeatDays;
    std::vector<uint8_t> daysOfWeek;
    auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
    EXPECT_NE(nullptr, calendar);

    calendar->AddExcludeDate(static_cast<uint64_t>(now) * 1000);
    EXPECT_EQ(calendar->excludeDates_.size(), 1);

    EXPECT_EQ(calendar->IsInExcludeDate(), true);
    EXPECT_EQ(calendar->CheckCalenderIsExpired(static_cast<uint64_t>(now) * 1000), false);
}

/**
 * @tc.name: OnDateTimeChange_00001
 * @tc.desc: Test OnDateTimeChange parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, OnDateTimeChange_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestCalendar>();
    EXPECT_NE(rrc, nullptr);
    rrc->SetExpired(true);
    EXPECT_EQ(rrc->OnDateTimeChange(), false);
}

/**
 * @tc.name: OnDateTimeChange_00002
 * @tc.desc: Test OnDateTimeChange parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, OnDateTimeChange_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestCalendar>();
    EXPECT_NE(rrc, nullptr);
    rrc->SetExpired(false);
    EXPECT_EQ(rrc->OnDateTimeChange(), false);
}

/**
 * @tc.name: OnDateTimeChange_00003
 * @tc.desc: Test OnDateTimeChange parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, OnDateTimeChange_00003, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestCalendar>();
    EXPECT_NE(rrc, nullptr);
    rrc->SetExpired(false);
    rrc->startDateTime_ = 1675876470000;
    rrc->endDateTime_ = 1901086458000;
    EXPECT_EQ(rrc->OnDateTimeChange(), true);
}

/**
 * @tc.name: RecoverFromDb_00001
 * @tc.desc: Test RecoverFromDb parameters.
 * @tc.type: FUNC
 * @tc.require: I92G9T
 */
HWTEST_F(ReminderRequestCalendarTest, RRuleWantAgentInfo_00001, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    auto wantInfo = std::make_shared<ReminderRequest::WantAgentInfo>();
    wantInfo->pkgName = "testing service";
    wantInfo->abilityName = "testing ability";
    calendar->SetRRuleWantAgentInfo(wantInfo);
    EXPECT_EQ(calendar->GetRRuleWantAgentInfo(), wantInfo);
}

/**
 * @tc.name: RecoverFromOldVersion_00001
 * @tc.desc: Test RecoverFromOldVersion parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderRequestCalendarTest, RecoverFromOldVersion_00001, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);

    bool result = calendar->IsRepeatDay(1);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: SetDateTime_00001
 * @tc.desc: Test SetDateTime parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderRequestCalendarTest, SetDateTime_00001, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    calendar->SetDateTime(0);
    EXPECT_EQ(calendar->GetDateTime(), 0);
}

/**
 * @tc.name: SetEndDateTime_00001
 * @tc.desc: Test SetEndDateTime parameters.
 * @tc.type: FUNC
 * @tc.require: I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, SetEndDateTime_00001, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    EXPECT_EQ(calendar->SetEndDateTime(0), false);
    EXPECT_NE(calendar->GetEndDateTime(), 0);
}

/**
 * @tc.name: SetEndDateTime_00002
 * @tc.desc: Test SetEndDateTime parameters.
 * @tc.type: FUNC
 * @tc.require: I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, SetEndDateTime_00002, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    calendar->startDateTime_ = 5;
    EXPECT_EQ(calendar->SetEndDateTime(0), false);
    EXPECT_NE(calendar->GetEndDateTime(), 0);
}

/**
 * @tc.name: SerializationRRule_00001
 * @tc.desc: Test SerializationRRule parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderRequestCalendarTest, SerializationRRule_00001, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    std::string result = calendar->SerializationRRule();
    EXPECT_EQ(result.size(), 0);
}

/**
 * @tc.name: SerializationRRule_00002
 * @tc.desc: Test SerializationRRule parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderRequestCalendarTest, SerializationRRule_00002, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    calendar->rruleWantAgentInfo_ = std::make_shared<ReminderRequest::WantAgentInfo>();
    calendar->rruleWantAgentInfo_->pkgName = "com.example.myapplication";
    calendar->rruleWantAgentInfo_->abilityName = "MainAbility";
    calendar->rruleWantAgentInfo_->uri = "test";
    std::string result = calendar->SerializationRRule();
    EXPECT_NE(result.find("com.example.myapplication"), std::string::npos);
    EXPECT_NE(result.find("MainAbility"), std::string::npos);
    EXPECT_NE(result.find("test"), std::string::npos);
}

/**
 * @tc.name: DeserializationRRule_00001
 * @tc.desc: Test DeserializationRRule parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderRequestCalendarTest, DeserializationRRule_00001, Function | SmallTest | Level1)
{
    struct tm nowTime;
    auto calendar = ReminderRequestCalendarTest::CreateCalendar(nowTime);
    EXPECT_NE(nullptr, calendar);
    std::string str;
    calendar->DeserializationRRule(str);
    EXPECT_EQ(calendar->rruleWantAgentInfo_, nullptr);

    str = "asdfwsbsdf";
    calendar->DeserializationRRule(str);
    EXPECT_EQ(calendar->rruleWantAgentInfo_, nullptr);

    // pkgName
    str = "{}";
    calendar->DeserializationRRule(str);
    EXPECT_EQ(calendar->rruleWantAgentInfo_, nullptr);

    str = R"({"pkgName":1})";
    calendar->DeserializationRRule(str);
    EXPECT_EQ(calendar->rruleWantAgentInfo_, nullptr);

    // abilityName
    str = R"({"pkgName":"com.example.myapplication"})";
    calendar->DeserializationRRule(str);
    EXPECT_EQ(calendar->rruleWantAgentInfo_, nullptr);

    str = R"({"pkgName":"com.example.myapplication","abilityName":1})";
    calendar->DeserializationRRule(str);
    EXPECT_EQ(calendar->rruleWantAgentInfo_, nullptr);

    // uri
    str = R"({"pkgName":"com.example.myapplication","abilityName":"MainAbility"})";
    calendar->DeserializationRRule(str);
    EXPECT_EQ(calendar->rruleWantAgentInfo_, nullptr);

    str = R"({"pkgName":"com.example.myapplication","abilityName":"MainAbility","uri":1})";
    calendar->DeserializationRRule(str);
    EXPECT_EQ(calendar->rruleWantAgentInfo_, nullptr);

    str = R"({"pkgName":"com.example.myapplication","abilityName":"MainAbility","uri":"uri"})";
    calendar->DeserializationRRule(str);
    EXPECT_EQ(calendar->rruleWantAgentInfo_->pkgName, "com.example.myapplication");
    EXPECT_EQ(calendar->rruleWantAgentInfo_->abilityName, "MainAbility");
    EXPECT_EQ(calendar->rruleWantAgentInfo_->uri, "uri");
}

/**
 * @tc.name: ExcludeDate_00001
 * @tc.desc: Test InitTriggerTime parameters.
 * @tc.type: FUNC
 * @tc.require: issue#I9F24R
 */
HWTEST_F(ReminderRequestCalendarTest, ExcludeDate_00001, Function | SmallTest | Level1)
{
    time_t now;
    (void)time(&now);  // unit is seconds.
    struct tm nowTime;
    (void)localtime_r(&now, &nowTime);
    std::vector<uint8_t> repeatMonths;
    std::vector<uint8_t> repeatDays;
    std::vector<uint8_t> daysOfWeek;
    auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
    EXPECT_NE(nullptr, calendar);

    calendar->AddExcludeDate(static_cast<uint64_t>(now) * 1000);
    EXPECT_EQ(calendar->excludeDates_.size(), 1);

    calendar->AddExcludeDate(static_cast<uint64_t>(now) * 1000);
    EXPECT_EQ(calendar->excludeDates_.size(), 1);

    calendar->AddExcludeDate((static_cast<uint64_t>(now) + 24 * 60 * 60) * 1000);
    EXPECT_EQ(calendar->excludeDates_.size(), 2);

    auto dates = calendar->GetExcludeDates();
    EXPECT_EQ(dates.size(), 2);

    calendar->DelExcludeDates();
    EXPECT_EQ(calendar->excludeDates_.size(), 0);
    dates = calendar->GetExcludeDates();
    EXPECT_EQ(dates.size(), 0);
}

/**
 * @tc.name: IsInExcludeDate_00002
 * @tc.desc: Test IsInExcludeDate.
 * @tc.type: FUNC
 * @tc.require: issue#I9F24R
 */
HWTEST_F(ReminderRequestCalendarTest, IsInExcludeDate_00001, Function | SmallTest | Level1)
{
    time_t now;
    (void)time(&now);  // unit is seconds.
    struct tm nowTime;
    (void)localtime_r(&now, &nowTime);
    std::vector<uint8_t> repeatMonths;
    std::vector<uint8_t> repeatDays;
    std::vector<uint8_t> daysOfWeek;
    auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
    EXPECT_NE(nullptr, calendar);

    calendar->AddExcludeDate(static_cast<uint64_t>(now) * 1000);
    EXPECT_EQ(calendar->excludeDates_.size(), 1);

    EXPECT_EQ(calendar->IsInExcludeDate(), true);

    calendar->DelExcludeDates();
    calendar->AddExcludeDate((static_cast<uint64_t>(now) + 24 * 60 * 60) * 1000);
    EXPECT_EQ(calendar->excludeDates_.size(), 1);
    EXPECT_EQ(calendar->IsInExcludeDate(), false);
}

/**
 * @tc.name: IsRepeat_00001
 * @tc.desc: Test IsRepeat parameters.
 * @tc.type: FUNC
 * @tc.require: issue#I9F24R
 */
HWTEST_F(ReminderRequestCalendarTest, IsRepeat_00001, Function | SmallTest | Level1)
{
    time_t now;
    (void)time(&now);  // unit is seconds.
    struct tm nowTime;
    (void)localtime_r(&now, &nowTime);

    {
        std::vector<uint8_t> repeatMonths;
        std::vector<uint8_t> repeatDays;
        std::vector<uint8_t> daysOfWeek;
        auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
        EXPECT_NE(nullptr, calendar);
        EXPECT_EQ(calendar->IsRepeat(), false);
    }

    {
        std::vector<uint8_t> repeatMonths{ 1 };
        std::vector<uint8_t> repeatDays{ 1 };
        std::vector<uint8_t> daysOfWeek;
        auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
        EXPECT_NE(nullptr, calendar);
        EXPECT_EQ(calendar->IsRepeat(), true);
    }

    {
        std::vector<uint8_t> repeatMonths{ 1 };
        std::vector<uint8_t> repeatDays{ 1 };
        std::vector<uint8_t> daysOfWeek;
        auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
        EXPECT_NE(nullptr, calendar);
        EXPECT_EQ(calendar->IsRepeat(), true);
    }

    {
        std::vector<uint8_t> repeatMonths;
        std::vector<uint8_t> repeatDays;
        std::vector<uint8_t> daysOfWeek{ 1 };
        auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
        EXPECT_NE(nullptr, calendar);
        EXPECT_EQ(calendar->IsRepeat(), true);
    }
}

/**
 * @tc.name: CheckExcludeDate_00001
 * @tc.desc: Test CheckExcludeDate parameters.
 * @tc.type: FUNC
 * @tc.require: issue#I9F24R
 */
HWTEST_F(ReminderRequestCalendarTest, CheckExcludeDate_00001, Function | SmallTest | Level1)
{
    time_t now;
    (void)time(&now);  // unit is seconds.
    struct tm nowTime;
    (void)localtime_r(&now, &nowTime);

    {
        std::vector<uint8_t> repeatMonths;
        std::vector<uint8_t> repeatDays;
        std::vector<uint8_t> daysOfWeek;
        auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
        EXPECT_NE(nullptr, calendar);
        EXPECT_EQ(calendar->IsRepeat(), false);
        EXPECT_EQ(calendar->CheckExcludeDate(), false);
    }

    {
        std::vector<uint8_t> repeatMonths;
        std::vector<uint8_t> repeatDays;
        std::vector<uint8_t> daysOfWeek{ 1, 2, 3, 4, 5, 6, 7};
        auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
        EXPECT_NE(nullptr, calendar);
        EXPECT_EQ(calendar->IsRepeat(), true);
        EXPECT_EQ(calendar->CheckExcludeDate(), false);
    }

    {
        std::vector<uint8_t> repeatMonths;
        std::vector<uint8_t> repeatDays;
        std::vector<uint8_t> daysOfWeek{ 1, 2, 3, 4, 5, 6, 7};
        auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
        calendar->AddExcludeDate(static_cast<uint64_t>(now) * 1000);
        EXPECT_NE(nullptr, calendar);
        EXPECT_EQ(calendar->IsRepeat(), true);
        EXPECT_EQ(calendar->CheckExcludeDate(), true);
    }
}

/**
 * @tc.name: SerializationExcludeDates_00001
 * @tc.desc: Test SerializationExcludeDates parameters.
 * @tc.type: FUNC
 * @tc.require: issue#I9F24R
 */
HWTEST_F(ReminderRequestCalendarTest, SerializationExcludeDates_00001, Function | SmallTest | Level1)
{
    time_t now;
    (void)time(&now);  // unit is seconds.
    struct tm nowTime;
    (void)localtime_r(&now, &nowTime);

    std::vector<uint8_t> repeatMonths;
    std::vector<uint8_t> repeatDays;
    std::vector<uint8_t> daysOfWeek;
    auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
    EXPECT_NE(nullptr, calendar);

    std::string str = calendar->SerializationExcludeDates();
    EXPECT_NE(str.find("[]"), std::string::npos);

    calendar->AddExcludeDate(static_cast<uint64_t>(now) * 1000);
    EXPECT_EQ(calendar->excludeDates_.size(), 1);

    uint64_t date = *calendar->excludeDates_.begin();
    str = calendar->SerializationExcludeDates();
    EXPECT_NE(str.find(std::to_string(date)), std::string::npos);
}

/**
 * @tc.name: DeserializationExcludeDates_00001
 * @tc.desc: Test DeserializationExcludeDates parameters.
 * @tc.type: FUNC
 * @tc.require: issue#I9F24R
 */
HWTEST_F(ReminderRequestCalendarTest, DeserializationExcludeDates_00001, Function | SmallTest | Level1)
{
    time_t now;
    (void)time(&now);  // unit is seconds.
    struct tm nowTime;
    (void)localtime_r(&now, &nowTime);

    std::vector<uint8_t> repeatMonths;
    std::vector<uint8_t> repeatDays;
    std::vector<uint8_t> daysOfWeek;
    auto calendar = std::make_shared<ReminderRequestCalendar>(nowTime, repeatMonths, repeatDays, daysOfWeek);
    EXPECT_NE(nullptr, calendar);

    calendar->AddExcludeDate(static_cast<uint64_t>(now) * 1000);
    EXPECT_EQ(calendar->excludeDates_.size(), 1);

    calendar->DeserializationExcludeDates("");
    EXPECT_EQ(calendar->excludeDates_.size(), 1);

    calendar->DeserializationExcludeDates("saeawefs");
    EXPECT_EQ(calendar->excludeDates_.size(), 1);

    calendar->DeserializationExcludeDates(R"({"pkgName":"com.example.myapplication"})");
    EXPECT_EQ(calendar->excludeDates_.size(), 1);

    calendar->DeserializationExcludeDates(R"({"excludeDates":"com.example.myapplication"})");
    EXPECT_EQ(calendar->excludeDates_.size(), 1);

    calendar->DeserializationExcludeDates(R"({"excludeDates":[]})");
    EXPECT_EQ(calendar->excludeDates_.size(), 0);

    calendar->DeserializationExcludeDates(R"({"excludeDates":["a"]})");
    EXPECT_EQ(calendar->excludeDates_.size(), 0);

    calendar->DeserializationExcludeDates(R"({"excludeDates":["a", 1713110400000]})");
    EXPECT_EQ(calendar->excludeDates_.size(), 1);
    EXPECT_NE(calendar->excludeDates_.find(1713110400000), calendar->excludeDates_.end());

    calendar->DeserializationExcludeDates(R"({"excludeDates":[1713196800000, 1713110400000]})");
    EXPECT_EQ(calendar->excludeDates_.size(), 2);
    EXPECT_NE(calendar->excludeDates_.find(1713196800000), calendar->excludeDates_.end());
}

/**
 * @tc.name: AppendValuesBucket_00001
 * @tc.desc: Test AppendValuesBucket parameters.
 * @tc.type: FUNC
 * @tc.require: issue#I9F24R
 */
HWTEST_F(ReminderRequestCalendarTest, AppendValuesBucket_00001, Function | SmallTest | Level1)
{
    time_t now;
    (void)time(&now);  // unit is seconds.
    struct tm nowTime;
    (void)localtime_r(&now, &nowTime);

    std::vector<uint8_t> repeatMonths;
    std::vector<uint8_t> repeatDays;
    std::vector<uint8_t> daysOfWeek;
    sptr<ReminderRequest> calendar = new ReminderRequestCalendar(nowTime, repeatMonths, repeatDays, daysOfWeek);
    EXPECT_NE(nullptr, calendar);
}

/**
 * @tc.name: IsPullUpService_00001
 * @tc.desc: Test IsPullUpService parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, IsPullUpService_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestCalendar>();
    rrc->startDateTime_ = 1675876470000;
    EXPECT_EQ(rrc->IsPullUpService(), false);

    rrc->rruleWantAgentInfo_ = std::make_shared<ReminderRequest::WantAgentInfo>();
    EXPECT_EQ(rrc->IsPullUpService(), true);

    rrc->startDateTime_ = 1874643293000;
    EXPECT_EQ(rrc->IsPullUpService(), false);
}

/**
 * @tc.name: IsNeedNotification_00001
 * @tc.desc: Test IsNeedNotification parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, IsNeedNotification_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestCalendar>();
    uint64_t now = rrc->GetNowInstantMilli();
    rrc->startDateTime_ = now - 5 * 60 * 1000;
    rrc->endDateTime_ = now + 5 * 60 * 1000;
    EXPECT_EQ(rrc->IsNeedNotification(), true);

    rrc->startDateTime_ = now + 10 * 60 * 1000;
    rrc->endDateTime_ = now + 20 * 60 * 1000;
    EXPECT_EQ(rrc->IsNeedNotification(), false);
}

/**
 * @tc.name: Set_Get_Year_001
 * @tc.desc: Test Set/GetYear parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, Set_Get_Year_001, Function | SmallTest | Level1)
{
    ReminderRequestCalendar calendar(1);
    EXPECT_EQ(calendar.GetYear(), 1);

    calendar.SetYear(2024);
    EXPECT_EQ(calendar.GetYear(), 2024);
}

/**
 * @tc.name: Set_Get_Month_001
 * @tc.desc: Test Set/GetMonth parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, Set_Get_Month_001, Function | SmallTest | Level1)
{
    ReminderRequestCalendar calendar(1);
    EXPECT_EQ(calendar.GetMonth(), 1);

    calendar.SetMonth(11);
    EXPECT_EQ(calendar.GetMonth(), 11);
}

/**
 * @tc.name: Set_Get_Day_001
 * @tc.desc: Test Set/GetDay parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, Set_Get_Day_001, Function | SmallTest | Level1)
{
    ReminderRequestCalendar calendar(1);
    EXPECT_EQ(calendar.GetDay(), 1);

    calendar.SetDay(21);
    EXPECT_EQ(calendar.GetDay(), 21);
}

/**
 * @tc.name: Set_Get_Hour_001
 * @tc.desc: Test Set/GetHour parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, Set_Get_Hour_001, Function | SmallTest | Level1)
{
    ReminderRequestCalendar calendar(1);
    EXPECT_EQ(calendar.GetHour(), 1);

    calendar.SetHour(19);
    EXPECT_EQ(calendar.GetHour(), 19);
}

/**
 * @tc.name: Set_Get_Minute_001
 * @tc.desc: Test Set/GetMinute parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, Set_Get_Minute_001, Function | SmallTest | Level1)
{
    ReminderRequestCalendar calendar(1);
    EXPECT_EQ(calendar.GetMinute(), 1);

    calendar.SetMinute(14);
    EXPECT_EQ(calendar.GetMinute(), 14);
}

/**
 * @tc.name: SetRepeatDay_001
 * @tc.desc: Test SetRepeatDay parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, SetRepeatDay_001, Function | SmallTest | Level1)
{
    ReminderRequestCalendar calendar(1);
    EXPECT_EQ(calendar.GetRepeatDay(), 0);

    calendar.SetRepeatDay(19);
    EXPECT_EQ(calendar.GetRepeatDay(), 19);
}

/**
 * @tc.name: SetRepeatMonth_001
 * @tc.desc: Test SetRepeatMonth parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, SetRepeatMonth_001, Function | SmallTest | Level1)
{
    ReminderRequestCalendar calendar(1);
    EXPECT_EQ(calendar.GetRepeatMonth(), 0);

    calendar.SetRepeatMonth(19);
    EXPECT_EQ(calendar.GetRepeatMonth(), 19);
}

/**
 * @tc.name: SetFirstDesignateYear_001
 * @tc.desc: Test SetFirstDesignateYear parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, SetFirstDesignateYear_001, Function | SmallTest | Level1)
{
    ReminderRequestCalendar calendar(1);
    EXPECT_EQ(calendar.GetFirstDesignateYear(), 1);

    calendar.SetFirstDesignateYear(19);
    EXPECT_EQ(calendar.GetFirstDesignateYear(), 19);
}

/**
 * @tc.name: SetFirstDesignageMonth_001
 * @tc.desc: Test SetFirstDesignageMonth parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, SetFirstDesignageMonth_001, Function | SmallTest | Level1)
{
    ReminderRequestCalendar calendar(1);
    EXPECT_EQ(calendar.GetFirstDesignageMonth(), 1);

    calendar.SetFirstDesignageMonth(19);
    EXPECT_EQ(calendar.GetFirstDesignageMonth(), 19);
}

/**
 * @tc.name: SetFirstDesignateDay_001
 * @tc.desc: Test SetFirstDesignateDay parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, SetFirstDesignateDay_001, Function | SmallTest | Level1)
{
    ReminderRequestCalendar calendar(1);
    EXPECT_EQ(calendar.GetFirstDesignateDay(), 1);

    calendar.SetFirstDesignateDay(19);
    EXPECT_EQ(calendar.GetFirstDesignateDay(), 19);
}

/**
 * @tc.name: InitTriggerTime_001
 * @tc.desc: Test InitTriggerTime parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, InitTriggerTime_001, Function | SmallTest | Level1)
{
    time_t now;
    (void)time(&now);
    uint64_t nowMilli = ReminderRequest::GetDurationSinceEpochInMilli(now);

    // startTime < nowMilli < endTime
    ReminderRequestCalendar calendar(1);
    calendar.startDateTime_ = nowMilli - 60 * 1000;
    calendar.endDateTime_ = nowMilli + 60 * 1000;
    EXPECT_EQ(calendar.InitTriggerTime(), true);
    EXPECT_NE(calendar.GetTriggerTimeInMilli(), nowMilli);

    // nowMilli < startTime
    calendar.startDateTime_ = nowMilli + 2 * 60 * 1000;
    calendar.endDateTime_ = nowMilli + 4 * 60 * 1000;
    EXPECT_EQ(calendar.InitTriggerTime(), true);
    EXPECT_EQ(calendar.GetTriggerTimeInMilli(), calendar.startDateTime_);

    // nowMilli > endTime and not repeat
    calendar.startDateTime_ = 1673198080000;
    calendar.endDateTime_ = 1673219680000;
    EXPECT_EQ(calendar.InitTriggerTime(), false);

    // nowMilli > endTime and repeat
    calendar.startDateTime_ = nowMilli - 4 * 60 * 60 * 1000;
    calendar.endDateTime_ = nowMilli - 2 * 60 * 60 * 1000;
    calendar.repeatDaysOfWeek_ = 1;
    EXPECT_EQ(calendar.InitTriggerTime(), true);
}

/**
 * @tc.name: Copy_001
 * @tc.desc: Test Copy parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, Copy_001, Function | SmallTest | Level1)
{
    sptr<ReminderRequest> reminder1 = new ReminderRequestCalendar(1);
    reminder1->SetTitle("test_reminder1");
    sptr<ReminderRequest> reminder2 = new ReminderRequestCalendar(1);
    reminder2->SetTitle("test_reminder2");

    ReminderRequestCalendar* calendar = static_cast<ReminderRequestCalendar*>(reminder1.GetRefPtr());
    calendar->Copy(nullptr);
    EXPECT_EQ(reminder1->GetTitle(), "test_reminder1");
    calendar->Copy(reminder2);
    EXPECT_EQ(reminder1->GetTitle(), "test_reminder1");
    reminder1->SetShare(true);
    calendar->Copy(reminder2);
    EXPECT_EQ(reminder1->GetTitle(), "test_reminder1");
    reminder2->SetShare(true);
    calendar->Copy(reminder2);
    EXPECT_EQ(reminder1->GetTitle(), "test_reminder2");
    reminder2->SetTriggerTimeInMilli(100);
    reminder1->SetTriggerTimeInMilli(200);
    calendar->Copy(reminder2);
    EXPECT_EQ(reminder1->GetTriggerTimeInMilli(), 200);
    reminder1->SetTriggerTimeInMilli(50);
    calendar->Copy(reminder2);
    EXPECT_EQ(reminder1->GetTriggerTimeInMilli(), 100);
}

/**
 * @tc.name: ReminderRequestCalendarTest_001
 * @tc.desc: Test InitTriggerTime parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, ReminderRequestCalendarTest_001, Function | SmallTest | Level1)
{
    ReminderRequestCalendar calendar;
    uint64_t now = calendar.GetNowInstantMilli();
    calendar.startDateTime_ = now - 10 * 60 * 1000;
    calendar.endDateTime_ = now + 10 * 60 * 1000;
    EXPECT_EQ(calendar.InitTriggerTime(), true);

    calendar.startDateTime_ = now + 10 * 60 * 1000;
    calendar.endDateTime_ = now + 20 * 60 * 1000;
    EXPECT_EQ(calendar.InitTriggerTime(), true);

    calendar.startDateTime_ = now - 20 * 60 * 1000;
    calendar.endDateTime_ = now - 10 * 60 * 1000;
    EXPECT_EQ(calendar.InitTriggerTime(), false);

    calendar.startDateTime_ = now - 20 * 60 * 1000;
    calendar.endDateTime_ = now - 10 * 60 * 1000;
    calendar.repeatDaysOfWeek_ = 1;
    EXPECT_EQ(calendar.InitTriggerTime(), true);
}

/**
 * @tc.name: ReminderRequestCalendarTest_002
 * @tc.desc: Test CheckCalenderIsExpired parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, ReminderRequestCalendarTest_002, Function | SmallTest | Level1)
{
    ReminderRequestCalendar calendar;
    uint64_t now = calendar.GetNowInstantMilli();
    calendar.lastStartDateTime_ = now - 10 * 60 * 1000;
    calendar.durationTime_ = 30 * 60 * 1000;
    EXPECT_EQ(calendar.CheckCalenderIsExpired(now), true);

    calendar.startDateTime_ = now - 20 * 60 * 1000;
    calendar.endDateTime_ = now - 10 * 60 * 1000;
    calendar.lastStartDateTime_ = now + 30 * 60 * 1000;
    EXPECT_EQ(calendar.OnDateTimeChange(), false);

    calendar.endDateTime_ = calendar.startDateTime_;
    EXPECT_EQ(calendar.IsNeedNotification(), true);
}

/**
 * @tc.name: ReminderRequestCalendarTest_003
 * @tc.desc: Test UpdateNextReminder parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, ReminderRequestCalendarTest_003, Function | SmallTest | Level1)
{
    ReminderRequestCalendar calendar;
    uint64_t now = calendar.GetNowInstantMilli();
    calendar.timeIntervalInMilli_ = 60 * 1000;
    calendar.snoozeTimes_ = 3;
    calendar.snoozeTimesDynamic_ = 1;
    EXPECT_EQ(calendar.UpdateNextReminder(), true);

    calendar.startDateTime_ = now;
    calendar.endDateTime_ = now;
    EXPECT_EQ(calendar.UpdateNextReminder(), false);
    EXPECT_EQ(calendar.IsExpired(), true);

    calendar.startDateTime_ = now - 60 * 1000;
    calendar.endDateTime_ = now;
    calendar.snoozeTimesDynamic_ = 0;
    calendar.SetExpired(false);
    EXPECT_EQ(calendar.IsExpired(), false);
    EXPECT_EQ(calendar.UpdateNextReminder(), false);
}

/**
 * @tc.name: ReminderRequestCalendarTest_004
 * @tc.desc: Test Copy parameters.
 * @tc.type: FUNC
 * @tc.require:I9BM6I
 */
HWTEST_F(ReminderRequestCalendarTest, ReminderRequestCalendarTest_004, Function | SmallTest | Level1)
{
    ReminderRequestCalendar calendar;
    calendar.SetShare(true);
    sptr<ReminderRequest> reminder = new ReminderRequestCalendar();

    calendar.Copy(nullptr);
    EXPECT_EQ(calendar.IsShare(), true);

    reminder->reminderType_ = ReminderRequest::ReminderType::TIMER;
    calendar.Copy(reminder);
    EXPECT_EQ(calendar.IsShare(), true);

    reminder->reminderType_ = ReminderRequest::ReminderType::CALENDAR;
    calendar.SetShare(false);
    calendar.Copy(reminder);
    EXPECT_EQ(calendar.IsShare(), false);

    calendar.SetShare(true);
    reminder->SetShare(false);
    calendar.Copy(reminder);
    EXPECT_EQ(calendar.IsShare(), true);

    reminder->SetTitle("test");
    reminder->SetShare(true);
    calendar.Copy(reminder);
    EXPECT_EQ(calendar.GetTitle(), "test");
}
}
}