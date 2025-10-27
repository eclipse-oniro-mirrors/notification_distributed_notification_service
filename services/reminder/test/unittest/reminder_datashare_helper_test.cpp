/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "reminder_data_manager.h"
#include "reminder_request_calendar.h"
#include "reminder_datashare_helper.h"
#include "reminder_calendar_share_table.h"

#include "mock_service_registry.h"
#include "mock_datashare_helper.h"
#include "mock_reminder_data_manager.h"

using namespace testing::ext;
namespace OHOS::Notification {
class ReminderDataShareHelperTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: ReminderDataShareHelper_001
 * @tc.desc: test ReminderDataShareHelper::RegisterObserver function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_001, Level1)
{
    MockDataShareHelper* mockHelper = new MockDataShareHelper;
    ReminderDataManager::InitInstance();

    MockDataShareHelper::MockCreate(-1, nullptr);
    bool ret = ReminderDataShareHelper::GetInstance().RegisterObserver();
    EXPECT_EQ(ret, false);

    std::shared_ptr<DataShare::DataShareHelper> helper;
    helper.reset(mockHelper);
    MockDataShareHelper::MockCreate(0, helper);
    EXPECT_CALL(*helper, Release()).Times(1).WillOnce(testing::Return(true));
    ret = ReminderDataShareHelper::GetInstance().RegisterObserver();
    EXPECT_EQ(ret, true);
    MockDataShareHelper::MockCreate(-1, nullptr);
}

/**
 * @tc.name: ReminderDataShareHelper_012
 * @tc.desc: test ReminderDataShareHelper::GetColumns function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_012, Level1)
{
    ReminderDataShareHelper::GetInstance().rdbVersion_ = 1;
    auto result = ReminderDataShareHelper::GetInstance().GetColumns();
    EXPECT_EQ(result.size(), 19);
    ReminderDataShareHelper::GetInstance().rdbVersion_ = 0;
    result = ReminderDataShareHelper::GetInstance().GetColumns();
    EXPECT_EQ(result.size(), 11);
}

/**
 * @tc.name: ReminderDataShareHelper_014
 * @tc.desc: test ReminderDataShareHelper::CreateReminder function
 * DataShare::DataShareObserver::ChangeInfo
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_014, Level1)
{
    DataShare::DataShareObserver::ChangeInfo info;
    auto result = ReminderDataShareHelper::GetInstance().CreateReminder(info);
    EXPECT_EQ(result.size(), 0);

    ReminderDataShareHelper::GetInstance().rdbVersion_ = 0;
    info.valueBuckets_.resize(1);
    result = ReminderDataShareHelper::GetInstance().CreateReminder(info);
    EXPECT_EQ(result.size(), 1);

    DataShare::DataShareObserver::ChangeInfo::Value alarmTime = static_cast<double>(1761374864000);
    info.valueBuckets_[0][ReminderCalendarShareTable::ALARM_TIME] = alarmTime;
    DataShare::DataShareObserver::ChangeInfo::Value ends = static_cast<double>(1761378464000);
    info.valueBuckets_[0][ReminderCalendarShareTable::END] = ends;
    result = ReminderDataShareHelper::GetInstance().CreateReminder(info);
    EXPECT_EQ(result.size(), 1);
    for (auto& [key, value] : result) {
        EXPECT_EQ(value->GetTriggerTimeInMilli(), 1761374864000);
        EXPECT_EQ(value->GetAutoDeletedTime(), 1761378464000);
        break;
    }
}

/**
 * @tc.name: ReminderDataShareHelper_015
 * @tc.desc: test ReminderDataShareHelper::InitBaseInfo function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_015, Level1)
{
    sptr<ReminderRequest> reminder = sptr<ReminderRequestCalendar>::MakeSptr();
    DataShare::DataShareObserver::ChangeInfo info;
    info.valueBuckets_.resize(1);
    ReminderDataShareHelper::GetInstance().InitBaseInfo(info.valueBuckets_[0], reminder);
    EXPECT_EQ(reminder->GetIdentifier(), "");

    DataShare::DataShareObserver::ChangeInfo::Value id = static_cast<double>(15);
    info.valueBuckets_[0][ReminderCalendarShareTable::ID] = id;
    DataShare::DataShareObserver::ChangeInfo::Value eventId = static_cast<double>(15);
    info.valueBuckets_[0][ReminderCalendarShareTable::EVENT_ID] = eventId;
    DataShare::DataShareObserver::ChangeInfo::Value slotType = static_cast<double>(0);
    info.valueBuckets_[0][ReminderCalendarShareTable::SLOT_TYPE] = slotType;
    DataShare::DataShareObserver::ChangeInfo::Value title = std::string("test");
    info.valueBuckets_[0][ReminderCalendarShareTable::TITLE] = title;
    DataShare::DataShareObserver::ChangeInfo::Value content = std::string("InitBaseInfo");
    info.valueBuckets_[0][ReminderCalendarShareTable::CONTENT] = content;
    DataShare::DataShareObserver::ChangeInfo::Value buttons = std::string("");
    info.valueBuckets_[0][ReminderCalendarShareTable::BUTTONS] = buttons;
    DataShare::DataShareObserver::ChangeInfo::Value wantAgent = std::string("");
    info.valueBuckets_[0][ReminderCalendarShareTable::WANT_AGENT] = wantAgent;
    DataShare::DataShareObserver::ChangeInfo::Value identifier = std::string("test_015_InitBaseInfo");
    info.valueBuckets_[0][ReminderCalendarShareTable::IDENTIFIER] = identifier;
    ReminderDataShareHelper::GetInstance().InitBaseInfo(info.valueBuckets_[0], reminder);
    EXPECT_EQ(reminder->GetReminderId(), 15);
    EXPECT_EQ(reminder->GetNotificationId(), 15);
    EXPECT_EQ(reminder->GetTitle(), "test");
    EXPECT_EQ(reminder->GetContent(), "InitBaseInfo");
    EXPECT_EQ(reminder->GetIdentifier(), "test_015_InitBaseInfo");
}

/**
 * @tc.name: ReminderDataShareHelper_017
 * @tc.desc: test ReminderDataShareHelper::BuildReminderV1 function
 * DataShare::DataShareObserver::ChangeInfo::VBucket
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_017, Level1)
{
    sptr<ReminderRequest> reminder = sptr<ReminderRequestCalendar>::MakeSptr();
    DataShare::DataShareObserver::ChangeInfo info;
    info.valueBuckets_.resize(1);

    ReminderDataShareHelper::GetInstance().rdbVersion_ = 0;
    ReminderDataShareHelper::GetInstance().BuildReminderV1(info.valueBuckets_[0], reminder);
    EXPECT_EQ(reminder->GetSnoozeContent(), "");

    ReminderDataShareHelper::GetInstance().rdbVersion_ = 1;
    ReminderDataShareHelper::GetInstance().BuildReminderV1(info.valueBuckets_[0], reminder);
    EXPECT_EQ(reminder->GetSnoozeContent(), "");

    DataShare::DataShareObserver::ChangeInfo::Value timeInterval = static_cast<double>(600);
    info.valueBuckets_[0][ReminderCalendarShareTable::TIME_INTERVAL] = timeInterval;
    DataShare::DataShareObserver::ChangeInfo::Value snoozeTimes = static_cast<double>(10);
    info.valueBuckets_[0][ReminderCalendarShareTable::SNOOZE_TIMES] = snoozeTimes;
    DataShare::DataShareObserver::ChangeInfo::Value ringDuration = static_cast<double>(10);
    info.valueBuckets_[0][ReminderCalendarShareTable::RING_DURATION] = ringDuration;
    DataShare::DataShareObserver::ChangeInfo::Value type = static_cast<double>(1);
    info.valueBuckets_[0][ReminderCalendarShareTable::SNOOZE_SLOT_TYPE] = type;
    DataShare::DataShareObserver::ChangeInfo::Value snoozeContent = "snooze BuildReminderV1";
    info.valueBuckets_[0][ReminderCalendarShareTable::SNOOZE_CONTENT] = snoozeContent;
    DataShare::DataShareObserver::ChangeInfo::Value expiredContent = "expired BuildReminderV1";
    info.valueBuckets_[0][ReminderCalendarShareTable::EXPIRED_CONTENT] = expiredContent;
    std::string value = R"({"pkgName": "com.aaa.aaa", "abilityName": "Entry"})";
    DataShare::DataShareObserver::ChangeInfo::Value wantAgent = value;
    info.valueBuckets_[0][ReminderCalendarShareTable::MAX_SCREEN_WANT_AGENT] = wantAgent;
    DataShare::DataShareObserver::ChangeInfo::Value uri = "ring";
    info.valueBuckets_[0][ReminderCalendarShareTable::CUSTOM_RING_URI] = uri;
    ReminderDataShareHelper::GetInstance().BuildReminderV1(info.valueBuckets_[0], reminder);
    EXPECT_EQ(reminder->GetTimeInterval(), 600);
    EXPECT_EQ(reminder->GetSnoozeTimes(), 10);
    EXPECT_EQ(reminder->GetRingDuration(), 10);
    int32_t result = static_cast<int32_t>(reminder->GetSnoozeSlotType());
    EXPECT_EQ(result, 1);
    EXPECT_EQ(reminder->GetSnoozeContent(), "snooze BuildReminderV1");
    EXPECT_EQ(reminder->GetExpiredContent(), "expired BuildReminderV1");
    EXPECT_EQ(reminder->GetCustomRingUri(), "ring");
    EXPECT_EQ(reminder->maxScreenWantAgentInfo_->pkgName, "com.aaa.aaa");
    EXPECT_EQ(reminder->maxScreenWantAgentInfo_->abilityName, "Entry");
}
}