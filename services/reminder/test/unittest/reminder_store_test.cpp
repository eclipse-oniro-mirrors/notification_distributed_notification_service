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

#include "reminder_store.h"
#include "reminder_table.h"
#include "reminder_table_old.h"
#include "reminder_request_alarm.h"
#include "reminder_request_calendar.h"
#include "reminder_request_timer.h"
#include "reminder_helper.h"
#include "reminder_store_strategy.h"
#include "abs_shared_result_set.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
namespace {
    constexpr int32_t NON_SYSTEM_APP_UID = 1000;
    const std::string TEST_DEFUALT_BUNDLE = "bundleName";
    const int32_t STATE_FAIL = -1;
}
class ReminderStoreTest : public testing::Test {
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
        NativeRdb::RdbHelper::DeleteRdbStore(ReminderStore::REMINDER_DB_DIR + ReminderStore::REMINDER_DB_NAME);
    }

    void InitStore(ReminderStore& store)
    {
        std::string dbConfig = ReminderStore::REMINDER_DB_DIR + "notification_test.db";
        NativeRdb::RdbStoreConfig config(dbConfig);
        config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
        {
            ReminderStore::ReminderStoreDataCallBack rdbDataCallBack;
            int32_t errCode = STATE_FAIL;
            constexpr int32_t version = 7;
            store.rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(config, version, rdbDataCallBack, errCode);
        }
    }

    void ClearStore()
    {
        NativeRdb::RdbHelper::ClearCache();
        NativeRdb::RdbHelper::DeleteRdbStore(ReminderStore::REMINDER_DB_DIR + "notification_test.db");
    }
};


/**
 * @tc.name: Init_00001
 * @tc.desc: Test Init parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Init_00001, Function | SmallTest | Level1)
{
    ReminderStore reminderStore;
    int32_t ret = reminderStore.Init();
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: InitData_00001
 * @tc.desc: Test InitData parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, InitData_00001, Function | SmallTest | Level1)
{
    ReminderStore reminderStore;
    int32_t ret = reminderStore.InitData();
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: Delete_00001
 * @tc.desc: Test Delete parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Delete_00001, Function | SmallTest | Level1)
{
    int32_t reminderId = 1;
    ReminderStore reminderStore;
    int32_t ret = reminderStore.Delete(reminderId);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: Delete_00002
 * @tc.desc: Test Delete parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Delete_00002, Function | SmallTest | Level1)
{
    int32_t userId = 1;
    ReminderStore reminderStore;
    int32_t ret = reminderStore.Delete("", userId, -1);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: Delete_00003
 * @tc.desc: Test Delete parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Delete_00003, Function | SmallTest | Level1)
{
    std::string deleteCondition = "deleteCondition";
    ReminderStore reminderStore;
    int32_t ret = reminderStore.DeleteBase(deleteCondition);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: Insert_00001
 * @tc.desc: Test Insert parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Insert_00001, Function | SmallTest | Level1)
{
    sptr<ReminderRequest> reminder = nullptr;
    ReminderStore reminderStore;
    int64_t ret = reminderStore.Insert(reminder);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: Update_00001
 * @tc.desc: Test Update parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Update_00001, Function | SmallTest | Level1)
{
    sptr<ReminderRequest> reminder = nullptr;
    ReminderStore reminderStore;
    int64_t ret = reminderStore.Update(reminder);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: Query_00001
 * @tc.desc: Test Query parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Query_00001, Function | SmallTest | Level1)
{
    std::string queryCondition = "queryCondition";
    std::string name = "it";
    ReminderStore reminderStore;
    std::shared_ptr<NativeRdb::ResultSet> ret = reminderStore.Query(queryCondition);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: GetMaxId_00001
 * @tc.desc: Test GetMaxId parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, GetMaxId_00001, Function | SmallTest | Level1)
{
    ReminderStore reminderStore;
    int32_t ret = reminderStore.GetMaxId();
    EXPECT_EQ(ret, STATE_FAIL);
}

/**
 * @tc.name: GetAllValidReminders_00001
 * @tc.desc: Test GetAllValidReminders parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, GetAllValidReminders_00001, Function | SmallTest | Level1)
{
    ReminderStore reminderStore;
    std::vector<sptr<ReminderRequest>> ret = reminderStore.GetAllValidReminders();
    EXPECT_EQ(ret.size(), 0);
}

/**
 * @tc.name: GetReminders_00001
 * @tc.desc: Test GetReminders parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, GetReminders_00001, Function | SmallTest | Level1)
{
    std::string queryCondition = "queryCondition";
    ReminderStore reminderStore;
    std::vector<sptr<ReminderRequest>> ret = reminderStore.GetReminders(queryCondition);
    EXPECT_EQ(ret.size(), 0);
}

/**
 * @tc.name: Query_00002
 * @tc.desc: Test Query parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderStoreTest, Query_00002, Function | SmallTest | Level1)
{
    std::string tableName = "reminder_base";
    std::string colums = "reminder_type";
    int32_t reminderId = 0;
    ReminderStore reminderStore;
    std::shared_ptr<NativeRdb::ResultSet> ret = reminderStore.Query(tableName,
        colums, reminderId);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: Delete_00004
 * @tc.desc: Test Delete parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderStoreTest, Delete_00004, Function | SmallTest | Level1)
{
    std::string conditiont1 = "deleteCondition1";
    std::string conditiont2 = "deleteCondition2";
    ReminderStore reminderStore;
    int32_t ret = reminderStore.Delete(conditiont1, conditiont2);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: DeleteUser_00004
 * @tc.desc: Test DeleteUser parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderStoreTest, DeleteUser_00004, Function | SmallTest | Level1)
{
    int32_t userId = 0;
    ReminderStore reminderStore;
    int32_t ret = reminderStore.DeleteUser(userId);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: UpdateOrInsert_00001
 * @tc.desc: Test UpdateOrInsert parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderStoreTest, UpdateOrInsert_00001, Function | SmallTest | Level1)
{
    sptr<ReminderRequest> reminder = nullptr;
    ReminderStore reminderStore;
    int64_t ret = reminderStore.UpdateOrInsert(reminder);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: OnCreate_00001
 * @tc.desc: Test OnCreate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderStoreTest, OnCreate_00001, Function | SmallTest | Level1)
{
    std::string dbConfig = ReminderStore::REMINDER_DB_DIR + "notification_test.db";
    NativeRdb::RdbStoreConfig config(dbConfig);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    {
        ReminderStore::ReminderStoreDataCallBack rdbDataCallBack;
        int32_t errCode = STATE_FAIL;
        auto rdbStore = NativeRdb::RdbHelper::GetRdbStore(config, 5, rdbDataCallBack, errCode);
        EXPECT_NE(rdbStore, nullptr);
    }
    NativeRdb::RdbHelper::ClearCache();
    NativeRdb::RdbHelper::DeleteRdbStore(ReminderStore::REMINDER_DB_DIR + "notification_test.db");
}

/**
 * @tc.name: Delete_00005
 * @tc.desc: Test OnCreate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderStoreTest, Delete_00005, Function | SmallTest | Level1)
{
    ReminderStore reminderStore;
    int32_t ret = reminderStore.Delete("com.example.simple", 100, 20020152);
    EXPECT_EQ(ret, -1);

    ret = reminderStore.Delete("com.example.simple", 100, -1);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: ReminderStrategyTest_00001
 * @tc.desc: Test OnCreate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderStoreTest, ReminderTimerStrategyTest_00001, Function | SmallTest | Level1)
{
    ReminderStore reminderStore;
    InitStore(reminderStore);
    sptr<ReminderRequest> reminder = new ReminderRequestTimer();
    reminder->reminderId_ = 999;
    reminder->bundleName_ = "ReminderTimerStrategyTest_00001";
    reminder->userId_ = 998;
    reminder->uid_ = 997;
    reminder->isSystemApp_ = true;
    reminder->reminderType_ = ReminderRequest::ReminderType::TIMER;
    reminder->reminderTimeInMilli_ = 123456789;
    reminder->triggerTimeInMilli_ = 987654321;
    reminder->SetTimeInterval(100);
    reminder->snoozeTimes_ = 10;
    reminder->snoozeTimesDynamic_ = 9;
    reminder->SetRingDuration(500);
    reminder->isExpired_ = false;
    reminder->state_ = 123;
    ReminderRequestTimer* timer = static_cast<ReminderRequestTimer*>(reminder.GetRefPtr());
    timer->countDownTimeInSeconds_ = 10001;

    reminderStore.UpdateOrInsert(reminder);
    auto reminders = reminderStore.GetAllValidReminders();
    bool succeed = false;
    for (auto each : reminders) {
        if (each->reminderId_ != reminder->reminderId_) {
            continue;
        }

        EXPECT_EQ(reminder->bundleName_, each->bundleName_);
        EXPECT_EQ(reminder->userId_, each->userId_);
        EXPECT_EQ(reminder->uid_, each->uid_);
        EXPECT_EQ(reminder->isSystemApp_, each->isSystemApp_);
        EXPECT_EQ(reminder->reminderType_, each->reminderType_);
        EXPECT_EQ(reminder->reminderTimeInMilli_, each->reminderTimeInMilli_);
        EXPECT_EQ(reminder->triggerTimeInMilli_, each->triggerTimeInMilli_);
        EXPECT_EQ(reminder->GetTimeInterval(), each->GetTimeInterval());
        EXPECT_EQ(reminder->snoozeTimes_, each->snoozeTimes_);
        EXPECT_EQ(reminder->snoozeTimesDynamic_, each->snoozeTimesDynamic_);
        EXPECT_EQ(reminder->GetRingDuration(), each->GetRingDuration());
        EXPECT_EQ(reminder->isExpired_, each->isExpired_);
        EXPECT_EQ(reminder->state_, each->state_);
        ReminderRequestTimer* timer1 = static_cast<ReminderRequestTimer*>(each.GetRefPtr());
        EXPECT_EQ(timer1->countDownTimeInSeconds_, timer->countDownTimeInSeconds_);
        succeed = true;
        break;
    }
    reminderStore.Delete(reminder->reminderId_);
    EXPECT_EQ(succeed, true);
    ClearStore();
}

/**
 * @tc.name: ReminderTimerStrategyTest_00002
 * @tc.desc: Test OnCreate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderStoreTest, ReminderTimerStrategyTest_00002, Function | SmallTest | Level1)
{
    ReminderStore reminderStore;
    InitStore(reminderStore);
    sptr<ReminderRequest> reminder = new ReminderRequestTimer();
    reminder->reminderId_ = 999;
    reminder->reminderType_ = ReminderRequest::ReminderType::TIMER;
    reminder->slotType_ = static_cast<NotificationConstant::SlotType>(1);
    reminder->snoozeSlotType_ = static_cast<NotificationConstant::SlotType>(1);
    reminder->notificationId_ = 123;
    reminder->title_ = "title_";
    reminder->content_ = "content_";
    reminder->snoozeContent_ = "snoozeContent_";
    reminder->expiredContent_ = "expiredContent_";
    reminder->tapDismissed_ = false;
    reminder->autoDeletedTime_ = 666;
    reminder->groupId_ = "groupId_";
    reminder->customRingUri_ = "customRingUri_";
    reminder->creatorBundleName_ = "creatorBundleName_";
    reminder->creatorUid_ = 101;
    ReminderRequestTimer* timer = static_cast<ReminderRequestTimer*>(reminder.GetRefPtr());
    timer->countDownTimeInSeconds_ = 10001;

    reminderStore.UpdateOrInsert(reminder);
    auto reminders = reminderStore.GetAllValidReminders();
    bool succeed = false;
    for (auto each : reminders) {
        if (each->reminderId_ != reminder->reminderId_) {
            continue;
        }

        EXPECT_EQ(reminder->slotType_, each->slotType_);
        EXPECT_EQ(reminder->snoozeSlotType_, each->snoozeSlotType_);
        EXPECT_EQ(reminder->notificationId_, each->notificationId_);
        EXPECT_EQ(reminder->title_, each->title_);
        EXPECT_EQ(reminder->content_, each->content_);
        EXPECT_EQ(reminder->snoozeContent_, each->snoozeContent_);
        EXPECT_EQ(reminder->expiredContent_, each->expiredContent_);
        EXPECT_EQ(reminder->tapDismissed_, each->tapDismissed_);
        EXPECT_EQ(reminder->autoDeletedTime_, each->autoDeletedTime_);
        EXPECT_EQ(reminder->groupId_, each->groupId_);
        EXPECT_EQ(reminder->customRingUri_, each->customRingUri_);
        EXPECT_EQ(reminder->creatorBundleName_, each->creatorBundleName_);
        EXPECT_EQ(reminder->creatorUid_, each->creatorUid_);
        succeed = true;
        break;
    }
    reminderStore.Delete(reminder->reminderId_);
    EXPECT_EQ(succeed, true);
    ClearStore();
}

/**
 * @tc.name: ReminderTimerStrategyTest_00003
 * @tc.desc: Test OnCreate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderStoreTest, ReminderTimerStrategyTest_00003, Function | SmallTest | Level1)
{
    ReminderStore reminderStore;
    InitStore(reminderStore);
    sptr<ReminderRequest> reminder = new ReminderRequestTimer();
    reminder->reminderId_ = 999;
    reminder->reminderType_ = ReminderRequest::ReminderType::TIMER;
    reminder->customButtonUri_ = "customButtonUri_";
    if (reminder->wantAgentInfo_ == nullptr) {
        reminder->InitServerObj();
    }
    reminder->wantAgentInfo_->pkgName = "pkgName";
    reminder->wantAgentInfo_->abilityName = "abilityName";
    reminder->wantAgentInfo_->uri = "uri";
    reminder->maxScreenWantAgentInfo_->pkgName = "pkgName1";
    reminder->maxScreenWantAgentInfo_->abilityName = "abilityName1";
    ReminderRequestTimer* timer = static_cast<ReminderRequestTimer*>(reminder.GetRefPtr());
    timer->countDownTimeInSeconds_ = 10001;

    reminderStore.UpdateOrInsert(reminder);
    auto reminders = reminderStore.GetAllValidReminders();
    bool succeed = false;
    for (auto each : reminders) {
        if (each->reminderId_ != reminder->reminderId_) {
            continue;
        }

        EXPECT_EQ(reminder->customButtonUri_, each->customButtonUri_);
        EXPECT_EQ(reminder->wantAgentInfo_->pkgName, each->wantAgentInfo_->pkgName);
        EXPECT_EQ(reminder->wantAgentInfo_->abilityName, each->wantAgentInfo_->abilityName);
        EXPECT_EQ(reminder->wantAgentInfo_->uri, each->wantAgentInfo_->uri);
        EXPECT_EQ(reminder->maxScreenWantAgentInfo_->pkgName, each->maxScreenWantAgentInfo_->pkgName);
        EXPECT_EQ(reminder->maxScreenWantAgentInfo_->abilityName, each->maxScreenWantAgentInfo_->abilityName);
        succeed = true;
        break;
    }
    reminderStore.Delete(reminder->reminderId_);
    EXPECT_EQ(succeed, true);
    ClearStore();
}

/**
 * @tc.name: ReminderAlarmStrategyTest_00001
 * @tc.desc: Test OnCreate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderStoreTest, ReminderAlarmStrategyTest_00001, Function | SmallTest | Level1)
{
    ReminderStore reminderStore;
    InitStore(reminderStore);
    sptr<ReminderRequest> reminder = new ReminderRequestAlarm();
    reminder->reminderId_ = 999;
    reminder->reminderType_ = ReminderRequest::ReminderType::ALARM;
    reminder->repeatDaysOfWeek_ = 55;
    ReminderRequestAlarm* alarm = static_cast<ReminderRequestAlarm*>(reminder.GetRefPtr());
    alarm->hour_ = 12;
    alarm->minute_ = 30;

    reminderStore.UpdateOrInsert(reminder);
    auto reminders = reminderStore.GetAllValidReminders();
    bool succeed = false;
    for (auto each : reminders) {
        if (each->reminderId_ != reminder->reminderId_) {
            continue;
        }

        EXPECT_EQ(reminder->repeatDaysOfWeek_, each->repeatDaysOfWeek_);
        ReminderRequestAlarm* alarm1 = static_cast<ReminderRequestAlarm*>(each.GetRefPtr());
        EXPECT_EQ(alarm->hour_, alarm1->hour_);
        EXPECT_EQ(alarm->minute_, alarm1->minute_);
        succeed = true;
        break;
    }
    reminderStore.Delete(reminder->reminderId_);
    EXPECT_EQ(succeed, true);
    ClearStore();
}

/**
 * @tc.name: ReminderCalendarStrategyTest_00001
 * @tc.desc: Test OnCreate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderStoreTest, ReminderCalendarStrategyTest_00001, Function | SmallTest | Level1)
{
    ReminderStore reminderStore;
    InitStore(reminderStore);
    time_t t;
    (void)time(&t);  // unit is seconds.
    uint64_t ts = t * 1000;  // ms

    sptr<ReminderRequest> reminder = new ReminderRequestCalendar();
    reminder->reminderId_ = 999;
    reminder->reminderType_ = ReminderRequest::ReminderType::CALENDAR;
    ReminderRequestCalendar* calendar = static_cast<ReminderRequestCalendar*>(reminder.GetRefPtr());
    calendar->firstDesignateYear_ = 2006;
    calendar->firstDesignateMonth_ = 6;
    calendar->firstDesignateDay_ = 6;
    calendar->SetDateTime(ts);
    calendar->SetEndDateTime(ts + 60 * 1000);
    calendar->SetLastStartDateTime(ts + 10 * 1000);
    calendar->repeatDay_ = 12;
    calendar->repeatMonth_ = 13;
    calendar->AddExcludeDate(ts);

    reminderStore.UpdateOrInsert(reminder);
    auto reminders = reminderStore.GetAllValidReminders();
    bool succeed = false;
    for (auto each : reminders) {
        if (each->reminderId_ != reminder->reminderId_) {
            continue;
        }

        ReminderRequestCalendar* calendar1 = static_cast<ReminderRequestCalendar*>(each.GetRefPtr());
        EXPECT_EQ(calendar1->firstDesignateYear_, calendar->firstDesignateYear_);
        EXPECT_EQ(calendar1->firstDesignateMonth_, calendar->firstDesignateMonth_);
        EXPECT_EQ(calendar1->firstDesignateDay_, calendar->firstDesignateDay_);
        EXPECT_EQ(calendar1->repeatDay_, calendar->repeatDay_);
        EXPECT_EQ(calendar1->repeatMonth_, calendar->repeatMonth_);
        EXPECT_EQ(calendar1->GetDateTime(), calendar->GetDateTime());
        EXPECT_EQ(calendar1->GetEndDateTime(), calendar->GetEndDateTime());
        EXPECT_EQ(calendar1->GetLastStartDateTime(), calendar->GetLastStartDateTime());
        EXPECT_EQ(calendar1->SerializationExcludeDates(), calendar->SerializationExcludeDates());
        EXPECT_EQ(calendar1->SerializationRRule(), calendar->SerializationRRule());
        succeed = true;
        break;
    }
    reminderStore.Delete(reminder->reminderId_);
    EXPECT_EQ(succeed, true);
    ClearStore();
}

/**
 * @tc.name: ReminderCalendarStrategyTest_00002
 * @tc.desc: Test OnCreate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderStoreTest, ReminderCalendarStrategyTest_00002, Function | SmallTest | Level1)
{
    ReminderStore reminderStore;
    InitStore(reminderStore);
    time_t t;
    (void)time(&t);  // unit is seconds.
    uint64_t ts = t * 1000;  // ms

    sptr<ReminderRequest> reminder = new ReminderRequestCalendar();
    reminder->reminderId_ = 999;
    reminder->reminderType_ = ReminderRequest::ReminderType::CALENDAR;
    reminder->repeatDaysOfWeek_ = 55;
    ReminderRequestCalendar* calendar = static_cast<ReminderRequestCalendar*>(reminder.GetRefPtr());
    calendar->SetDateTime(ts);
    calendar->rruleWantAgentInfo_ = std::make_shared<ReminderRequest::WantAgentInfo>();
    calendar->rruleWantAgentInfo_->pkgName = "pkgName";
    calendar->rruleWantAgentInfo_->abilityName = "abilityName";
    calendar->rruleWantAgentInfo_->uri = "uri";

    reminderStore.UpdateOrInsert(reminder);
    auto reminders = reminderStore.GetAllValidReminders();
    bool succeed = false;
    for (auto each : reminders) {
        if (each->reminderId_ != reminder->reminderId_) {
            continue;
        }

        EXPECT_EQ(reminder->repeatDaysOfWeek_, each->repeatDaysOfWeek_);
        ReminderRequestCalendar* calendar1 = static_cast<ReminderRequestCalendar*>(each.GetRefPtr());
        EXPECT_EQ(calendar1->GetDateTime(), calendar->GetDateTime());
        EXPECT_EQ(calendar1->GetEndDateTime(), calendar->GetDateTime());
        EXPECT_EQ(calendar1->GetLastStartDateTime(), calendar->GetDateTime());
        EXPECT_EQ(calendar1->SerializationRRule(), calendar->SerializationRRule());
        succeed = true;
        break;
    }
    reminderStore.Delete(reminder->reminderId_);
    EXPECT_EQ(succeed, true);
    ClearStore();
}

/**
 * @tc.name: ReminderCalendarStrategyTest_00003
 * @tc.desc: Test OnCreate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderStoreTest, ReminderCalendarStrategyTest_00003, Function | SmallTest | Level1)
{
    ReminderStrategy base;
    sptr<ReminderRequest> calendar = new ReminderRequestCalendar();
    calendar->reminderType_ = ReminderRequest::ReminderType::CALENDAR;
    sptr<ReminderRequest> alarm = new ReminderRequestAlarm();
    alarm->reminderType_ = ReminderRequest::ReminderType::ALARM;
    sptr<ReminderRequest> timer = new ReminderRequestTimer();
    timer->reminderType_ = ReminderRequest::ReminderType::TIMER;
    NativeRdb::ValuesBucket values;
    base.AppendValuesBucket(calendar, values, true);

    std::shared_ptr<NativeRdb::ResultSet> result = std::make_shared<NativeRdb::AbsSharedResultSet>();
    sptr<ReminderRequest> nullReminder;
    base.RecoverFromOldVersion(nullReminder, result);
    base.RecoverFromOldVersion(calendar, nullptr);
    base.RecoverFromOldVersion(calendar, result);

    base.RecoverFromDb(nullReminder, result);
    base.RecoverFromDb(calendar, nullptr);
    base.RecoverFromDb(calendar, result);

    ReminderTimerStrategy timerStrategy;
    timerStrategy.RecoverFromOldVersion(nullReminder, result);
    timerStrategy.RecoverFromOldVersion(calendar, nullptr);
    timerStrategy.RecoverFromOldVersion(timer, result);

    std::shared_ptr<NativeRdb::ResultSet> baseResult = std::make_shared<NativeRdb::AbsSharedResultSet>();

    timerStrategy.RecoverFromDb(nullReminder, result, baseResult);
    timerStrategy.RecoverFromDb(calendar, nullptr, baseResult);
    timerStrategy.RecoverFromDb(calendar, result, nullptr);
    timerStrategy.RecoverFromDb(timer, result, baseResult);

    ReminderAlarmStrategy alarmStrategy;
    alarmStrategy.RecoverFromOldVersion(nullReminder, result);
    alarmStrategy.RecoverFromOldVersion(calendar, nullptr);
    alarmStrategy.RecoverFromOldVersion(alarm, result);

    alarmStrategy.RecoverFromDb(nullReminder, result, baseResult);
    alarmStrategy.RecoverFromDb(calendar, nullptr, baseResult);
    alarmStrategy.RecoverFromDb(calendar, result, nullptr);
    alarmStrategy.RecoverFromDb(alarm, result, baseResult);

    ReminderCalendarStrategy calendarStrategy;
    calendarStrategy.RecoverFromOldVersion(nullReminder, result);
    calendarStrategy.RecoverFromOldVersion(alarm, nullptr);
    calendarStrategy.RecoverFromOldVersion(calendar, result);

    calendarStrategy.RecoverFromDb(nullReminder, result, baseResult);
    calendarStrategy.RecoverFromDb(alarm, nullptr, baseResult);
    calendarStrategy.RecoverFromDb(alarm, result, nullptr);
    calendarStrategy.RecoverFromDb(calendar, result, baseResult);
    EXPECT_EQ(alarm->reminderId_, 0);
}
}
}