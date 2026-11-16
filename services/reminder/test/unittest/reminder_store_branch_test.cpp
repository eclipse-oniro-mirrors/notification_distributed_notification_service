/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <chrono>
#include <fstream>

#include <gtest/gtest.h>

#include "abs_shared_result_set.h"
#include "reminder_request_alarm.h"
#include "reminder_request_calendar.h"
#include "reminder_request_timer.h"
#include "reminder_store.h"
#include "reminder_store_strategy.h"
#include "reminder_store_test_common.h"
#include "reminder_table.h"
#include "reminder_table_old.h"
#include "rdb_store.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {

// ---- Helpers for the branch coverage tests below ----

// Replace a table with a plain view so that INSERT/UPDATE/DELETE on it always fail.
void ReplaceTableWithView(NativeRdb::RdbStore& store, const std::string& tableName)
{
    store.ExecuteSql("DROP TABLE IF EXISTS " + tableName + ";");
    store.ExecuteSql("CREATE VIEW " + tableName + " AS SELECT 1;");
}

// Restore a table that was dropped or replaced by a view.
void RestoreTable(NativeRdb::RdbStore& store, const std::string& tableName, const std::string& addColumns)
{
    store.ExecuteSql("DROP VIEW IF EXISTS " + tableName + ";");
    store.ExecuteSql("DROP TABLE IF EXISTS " + tableName + ";");
    store.ExecuteSql("CREATE TABLE IF NOT EXISTS " + tableName + " (" + addColumns + ")");
}

// Insert an old-version reminder row with all NOT NULL columns filled so the insert really happens.
void InsertOldReminderFull(NativeRdb::RdbStore& store, int32_t id, int32_t type,
    const std::string& sysApp = "false", const std::string& isExpired = "false",
    const std::string& tapDismissed = "false")
{
    // Arbitrary distinct time values (in ms) just to fill the row, one per time column.
    constexpr int64_t reminderTime = 1000;
    constexpr int64_t triggerTime = 2000;
    constexpr int64_t rtcTriggerTime = 3000;
    NativeRdb::ValuesBucket values;
    values.PutInt(ReminderTable::REMINDER_ID, id);
    values.PutString(ReminderTable::PKG_NAME, "com.example.old");
    values.PutInt(ReminderTable::USER_ID, 1);
    values.PutInt(ReminderTable::UID, 1);
    values.PutString(ReminderTable::SYS_APP, sysApp);
    values.PutInt(ReminderTable::REMINDER_TYPE, type);
    values.PutLong(ReminderTable::REMINDER_TIME, reminderTime);
    values.PutLong(ReminderTable::TRIGGER_TIME, triggerTime);
    values.PutLong(ReminderTable::RTC_TRIGGER_TIME, rtcTriggerTime);
    values.PutLong(ReminderTable::TIME_INTERVAL, 0);
    values.PutInt(ReminderTable::SNOOZE_TIMES, 0);
    values.PutInt(ReminderTable::DYNAMIC_SNOOZE_TIMES, 0);
    values.PutLong(ReminderTable::RING_DURATION, 0);
    values.PutString(ReminderTable::IS_EXPIRED, isExpired);
    values.PutString(ReminderTable::IS_ACTIVE, "true");
    values.PutInt(ReminderTable::STATE, 1);
    values.PutInt(ReminderTable::NOTIFICATION_ID, -1);
    values.PutString(ReminderTable::TAP_DISMISSED, tapDismissed);
    int64_t rowId = 0;
    store.Insert(rowId, ReminderTable::TABLE_NAME, values);
}

// Run a scalar SQL query and return the first integer value, or -1 when the query fails.
int32_t QueryIntScalar(NativeRdb::RdbStore& store, const std::string& sql)
{
    auto resultSet = store.QuerySql(sql, std::vector<std::string>());
    if (resultSet == nullptr) {
        return -1;
    }
    int32_t value = -1;
    if (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        resultSet->GetInt(0, value);
    }
    resultSet->Close();
    return value;
}

/**
 * @tc.name: OnCreate_00002_AllFailBranches
 * @tc.desc: Test OnCreate returns error when each of its three table creations fails.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, OnCreate_00002_AllFailBranches, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);
    ReminderStore::ReminderStoreDataCallBack rdbDataCallBack;
    auto& rdbStore = *store.rdbStore_;

    // 1. CreateTable fails: reminder_base is missing and the connection is read-only.
    rdbStore.ExecuteSql("DROP TABLE IF EXISTS " + ReminderBaseTable::TABLE_NAME + ";");
    rdbStore.ExecuteSql("PRAGMA query_only = 1;");
    EXPECT_EQ(rdbDataCallBack.OnCreate(rdbStore), NativeRdb::E_SQLITE_READONLY);
    rdbStore.ExecuteSql("PRAGMA query_only = 0;");
    rdbDataCallBack.CreateTable(rdbStore);

    // 2. CreateStateTable fails: reminder_state is missing and the connection is read-only.
    rdbStore.ExecuteSql("DROP TABLE IF EXISTS " + std::string(ReminderStateTable::TABLE_NAME) + ";");
    rdbStore.ExecuteSql("PRAGMA query_only = 1;");
    EXPECT_EQ(rdbDataCallBack.OnCreate(rdbStore), NativeRdb::E_SQLITE_READONLY);
    rdbStore.ExecuteSql("PRAGMA query_only = 0;");
    rdbDataCallBack.CreateStateTable(rdbStore);

    // 3. CreateConfigTable fails: reminder_config is missing and the connection is read-only.
    rdbStore.ExecuteSql("DROP TABLE IF EXISTS " + std::string(ReminderConfigTable::TABLE_NAME) + ";");
    rdbStore.ExecuteSql("PRAGMA query_only = 1;");
    EXPECT_EQ(rdbDataCallBack.OnCreate(rdbStore), NativeRdb::E_SQLITE_READONLY);
    ClearStore();
}

/**
 * @tc.name: OnUpgrade_00003_InvalidOldVersion
 * @tc.desc: Test OnUpgrade returns STATE_FAIL when oldVersion is not positive.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, OnUpgrade_00003_InvalidOldVersion, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);
    ReminderStore::ReminderStoreDataCallBack rdbDataCallBack;

    EXPECT_EQ(rdbDataCallBack.OnUpgrade(*store.rdbStore_, 0, 14), ReminderStore::STATE_FAIL);
    EXPECT_EQ(rdbDataCallBack.OnUpgrade(*store.rdbStore_, -1, 14), ReminderStore::STATE_FAIL);
    ClearStore();
}

/**
 * @tc.name: OnUpgrade_00004_UpgradeSkippedForMismatch
 * @tc.desc: Test OnUpgrade skips the upgrade list when the version pair does not match.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, OnUpgrade_00004_UpgradeSkippedForMismatch, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);
    ReminderStore::ReminderStoreDataCallBack rdbDataCallBack;

    // newVersion is not the current rdb version: the upgrade list is skipped.
    EXPECT_EQ(rdbDataCallBack.OnUpgrade(*store.rdbStore_, 1, 9), NativeRdb::E_OK);
    // oldVersion is not smaller than newVersion: the upgrade list is skipped.
    EXPECT_EQ(rdbDataCallBack.OnUpgrade(*store.rdbStore_, 14, 14), NativeRdb::E_OK);
    int32_t version = 0;
    store.rdbStore_->GetVersion(version);
    EXPECT_EQ(version, 14);
    ClearStore();
}

/**
 * @tc.name: OnUpgrade_00005_FullUpgradeFromV1
 * @tc.desc: Test a real upgrade from version 1 to 14 runs UpgradeV1..V13 and sets version 14.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, OnUpgrade_00005_FullUpgradeFromV1, Function | SmallTest | Level1)
{
    std::string dbConfig = ReminderStore::REMINDER_DB_DIR + "notification_test.db";
    NativeRdb::RdbStoreConfig config(dbConfig);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    int32_t errCode = STATE_FAIL;
    ReminderStore::ReminderStoreDataCallBack rdbDataCallBack;

    // 1. Create a version-1 database file and keep it on disk.
    auto rdbStore = NativeRdb::RdbHelper::GetRdbStore(config, 1, rdbDataCallBack, errCode);
    ASSERT_NE(rdbStore, nullptr);
    NativeRdb::RdbHelper::ClearCache();

    // 2. Reopen with the current version: OnUpgrade(1, 14) runs and sets version 14.
    auto upgraded = NativeRdb::RdbHelper::GetRdbStore(config, 14, rdbDataCallBack, errCode);
    ASSERT_NE(upgraded, nullptr);
    int32_t version = 0;
    upgraded->GetVersion(version);
    EXPECT_EQ(version, 14);
    ClearStore();
}

/**
 * @tc.name: OnDowngrade_00002_CreateOldTable
 * @tc.desc: Test OnDowngrade creates the old reminder table when targetVersion is not above V4.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, OnDowngrade_00002_CreateOldTable, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);
    ReminderStore::ReminderStoreDataCallBack rdbDataCallBack;

    // currentVersion > targetVersion and targetVersion <= V4: the old table is created.
    EXPECT_EQ(rdbDataCallBack.OnDowngrade(*store.rdbStore_, 14, 4), NativeRdb::E_OK);
    std::string checkSql = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = '"
        + ReminderTable::TABLE_NAME + "'";
    EXPECT_EQ(QueryIntScalar(*store.rdbStore_, checkSql), 1);
    ClearStore();
}

/**
 * @tc.name: OnDowngrade_00003_SetTargetVersionWhenAboveV4
 * @tc.desc: Test OnDowngrade sets the target version without creating the old table above V4.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, OnDowngrade_00003_SetTargetVersionWhenAboveV4, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);
    ReminderStore::ReminderStoreDataCallBack rdbDataCallBack;

    // targetVersion > V4: no old table is created and the target version is set.
    EXPECT_EQ(rdbDataCallBack.OnDowngrade(*store.rdbStore_, 14, 5), NativeRdb::E_OK);
    int32_t version = 0;
    store.rdbStore_->GetVersion(version);
    EXPECT_EQ(version, 5);
    ClearStore();
}

/**
 * @tc.name: OnDowngrade_00004_CreateOldTableFail
 * @tc.desc: Test OnDowngrade returns the error when creating the old table fails.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, OnDowngrade_00004_CreateOldTableFail, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);
    ReminderStore::ReminderStoreDataCallBack rdbDataCallBack;

    // The old table is missing and the connection is read-only, so creating it fails.
    store.rdbStore_->ExecuteSql("DROP TABLE IF EXISTS " + ReminderTable::TABLE_NAME + ";");
    store.rdbStore_->ExecuteSql("PRAGMA query_only = 1;");
    EXPECT_EQ(rdbDataCallBack.OnDowngrade(*store.rdbStore_, 14, 4), NativeRdb::E_SQLITE_READONLY);
    ClearStore();
}

/**
 * @tc.name: AddRdbColum_00001_SuccessAndFail
 * @tc.desc: Test AddRdbColum succeeds for a new column and fails for an existing column.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, AddRdbColum_00001_SuccessAndFail, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);
    ReminderStore::ReminderStoreDataCallBack rdbDataCallBack;

    // 1. Adding a brand-new column succeeds (-1 would mean the column is still missing).
    rdbDataCallBack.AddRdbColum(*store.rdbStore_, ReminderBaseTable::TABLE_NAME, "test_new_col", "TEXT", "''");
    std::string checkSql = "SELECT COUNT(test_new_col) FROM " + ReminderBaseTable::TABLE_NAME;
    EXPECT_EQ(QueryIntScalar(*store.rdbStore_, checkSql), 0);

    // 2. Adding an existing column fails and the column is not duplicated.
    rdbDataCallBack.AddRdbColum(*store.rdbStore_, ReminderBaseTable::TABLE_NAME, "test_new_col", "TEXT", "''");
    EXPECT_EQ(QueryIntScalar(*store.rdbStore_, checkSql), 0);
    ClearStore();
}

/**
 * @tc.name: CopyData_005_InvalidOldReminderType
 * @tc.desc: Test CopyData skips old rows whose reminder type is invalid.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, CopyData_005_InvalidOldReminderType, Function | SmallTest | Level1)
{
    ReminderStore::ReminderStoreDataCallBack rdbDataCallBack;
    std::string dbConfig = ReminderStore::REMINDER_DB_DIR + "notification_test.db";
    NativeRdb::RdbStoreConfig config(dbConfig);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    int32_t errCode = STATE_FAIL;

    // 1. Setup: new tables, old table with one valid and one invalid type row.
    ReminderStore::EnsureDbColumnsInitialized();
    auto rdbStore = NativeRdb::RdbHelper::GetRdbStore(config, 9, rdbDataCallBack, errCode);
    ASSERT_NE(rdbStore, nullptr);
    CreateOldTable(*rdbStore);
    InsertOldReminderFull(*rdbStore, 101, static_cast<int32_t>(ReminderRequest::ReminderType::TIMER));
    InsertOldReminderFull(*rdbStore, 104, 99); // invalid type

    // 2. Execute CopyData.
    EXPECT_EQ(rdbDataCallBack.CopyData(*rdbStore), NativeRdb::E_OK);

    // 3. Verify: only the valid reminder is migrated.
    std::string checkSql = "SELECT COUNT(*) FROM " + ReminderBaseTable::TABLE_NAME + " WHERE "
        + ReminderBaseTable::REMINDER_ID + " = ";
    EXPECT_EQ(QueryIntScalar(*rdbStore, checkSql + "104"), 0);
    EXPECT_EQ(QueryIntScalar(*rdbStore, checkSql + "101"), 1);
    ClearStore();
}

/**
 * @tc.name: CopyData_006_TypeTableInsertFail
 * @tc.desc: Test CopyData rolls back when inserting into the type table fails.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, CopyData_006_TypeTableInsertFail, Function | SmallTest | Level1)
{
    ReminderStore::ReminderStoreDataCallBack rdbDataCallBack;
    std::string dbConfig = ReminderStore::REMINDER_DB_DIR + "notification_test.db";
    NativeRdb::RdbStoreConfig config(dbConfig);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    int32_t errCode = STATE_FAIL;

    // 1. Setup: an old timer row plus a read-only view occupying reminder_timer.
    ReminderStore::EnsureDbColumnsInitialized();
    auto rdbStore = NativeRdb::RdbHelper::GetRdbStore(config, 9, rdbDataCallBack, errCode);
    ASSERT_NE(rdbStore, nullptr);
    CreateOldTable(*rdbStore);
    InsertOldReminderFull(*rdbStore, 105, static_cast<int32_t>(ReminderRequest::ReminderType::TIMER));
    ReplaceTableWithView(*rdbStore, ReminderTimerTable::TABLE_NAME);

    // 2. CopyData tolerates the failure and the transaction is rolled back.
    EXPECT_EQ(rdbDataCallBack.CopyData(*rdbStore), NativeRdb::E_OK);
    std::string checkSql = "SELECT COUNT(*) FROM " + ReminderBaseTable::TABLE_NAME + " WHERE "
        + ReminderBaseTable::REMINDER_ID + " = 105";
    EXPECT_EQ(QueryIntScalar(*rdbStore, checkSql), 0);
    ClearStore();
}

/**
 * @tc.name: CopyData_007_OldTableBoolFlags
 * @tc.desc: Test CopyData recovers the true bool flags stored in the old table.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, CopyData_007_OldTableBoolFlags, Function | SmallTest | Level1)
{
    ReminderStore::ReminderStoreDataCallBack rdbDataCallBack;
    std::string dbConfig = ReminderStore::REMINDER_DB_DIR + "notification_test.db";
    NativeRdb::RdbStoreConfig config(dbConfig);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    int32_t errCode = STATE_FAIL;

    // 1. Setup: an old timer row with all bool flags set to true.
    ReminderStore::EnsureDbColumnsInitialized();
    auto rdbStore = NativeRdb::RdbHelper::GetRdbStore(config, 9, rdbDataCallBack, errCode);
    ASSERT_NE(rdbStore, nullptr);
    CreateOldTable(*rdbStore);
    InsertOldReminderFull(*rdbStore, 106, static_cast<int32_t>(ReminderRequest::ReminderType::TIMER),
        "true", "true", "true");
    EXPECT_EQ(rdbDataCallBack.CopyData(*rdbStore), NativeRdb::E_OK);

    // 2. Verify: the migrated reminder keeps every true flag.
    ReminderStore store;
    store.rdbStore_ = rdbStore;
    auto reminders = store.GetReminders("SELECT * FROM " + ReminderBaseTable::TABLE_NAME);
    ASSERT_EQ(reminders.size(), 1);
    EXPECT_EQ(reminders[0]->GetReminderId(), 106);
    EXPECT_TRUE(reminders[0]->IsSystemApp());
    EXPECT_TRUE(reminders[0]->IsExpired());
    EXPECT_TRUE(reminders[0]->IsTapDismissed());
    ClearStore();
}

/**
 * @tc.name: Insert_00003_TableFailBranches
 * @tc.desc: Test Insert fails and rolls back when each involved table cannot be written.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Insert_00003_TableFailBranches, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    sptr<ReminderRequest> timer = new ReminderRequestTimer();
    timer->SetReminderId(201);
    timer->reminderType_ = ReminderRequest::ReminderType::TIMER;
    sptr<ReminderRequest> alarm = new ReminderRequestAlarm();
    alarm->SetReminderId(202);
    alarm->reminderType_ = ReminderRequest::ReminderType::ALARM;
    sptr<ReminderRequest> calendar = new ReminderRequestCalendar();
    calendar->SetReminderId(203);
    calendar->reminderType_ = ReminderRequest::ReminderType::CALENDAR;

    // 1. reminder_base insert fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderBaseTable::TABLE_NAME);
    EXPECT_EQ(store.Insert(timer), ReminderStore::STATE_FAIL);
    RestoreTable(*store.rdbStore_, ReminderBaseTable::TABLE_NAME, ReminderBaseTable::ADD_COLUMNS);

    // 2. reminder_timer insert fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderTimerTable::TABLE_NAME);
    EXPECT_EQ(store.Insert(timer), ReminderStore::STATE_FAIL);
    RestoreTable(*store.rdbStore_, ReminderTimerTable::TABLE_NAME, ReminderTimerTable::ADD_COLUMNS);

    // 3. reminder_alarm insert fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderAlarmTable::TABLE_NAME);
    EXPECT_EQ(store.Insert(alarm), ReminderStore::STATE_FAIL);
    RestoreTable(*store.rdbStore_, ReminderAlarmTable::TABLE_NAME, ReminderAlarmTable::ADD_COLUMNS);

    // 4. reminder_calendar insert fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderCalendarTable::TABLE_NAME);
    EXPECT_EQ(store.Insert(calendar), ReminderStore::STATE_FAIL);
    ClearStore();
}

/**
 * @tc.name: Update_00004_TableFailBranches
 * @tc.desc: Test Update fails and rolls back when each involved table cannot be written.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Update_00004_TableFailBranches, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    sptr<ReminderRequest> timer = new ReminderRequestTimer();
    timer->SetReminderId(211);
    timer->reminderType_ = ReminderRequest::ReminderType::TIMER;
    sptr<ReminderRequest> alarm = new ReminderRequestAlarm();
    alarm->SetReminderId(213);
    alarm->reminderType_ = ReminderRequest::ReminderType::ALARM;
    sptr<ReminderRequest> calendar = new ReminderRequestCalendar();
    calendar->SetReminderId(212);
    calendar->reminderType_ = ReminderRequest::ReminderType::CALENDAR;

    // 1. reminder_base update fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderBaseTable::TABLE_NAME);
    EXPECT_EQ(store.Update(timer), ReminderStore::STATE_FAIL);
    RestoreTable(*store.rdbStore_, ReminderBaseTable::TABLE_NAME, ReminderBaseTable::ADD_COLUMNS);

    // 2. reminder_calendar update fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderCalendarTable::TABLE_NAME);
    EXPECT_EQ(store.Update(calendar), ReminderStore::STATE_FAIL);
    RestoreTable(*store.rdbStore_, ReminderCalendarTable::TABLE_NAME, ReminderCalendarTable::ADD_COLUMNS);

    // 3. reminder_alarm update fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderAlarmTable::TABLE_NAME);
    EXPECT_EQ(store.Update(alarm), ReminderStore::STATE_FAIL);
    RestoreTable(*store.rdbStore_, ReminderAlarmTable::TABLE_NAME, ReminderAlarmTable::ADD_COLUMNS);

    // 4. reminder_timer update fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderTimerTable::TABLE_NAME);
    EXPECT_EQ(store.Update(timer), ReminderStore::STATE_FAIL);
    ClearStore();
}

/**
 * @tc.name: Delete_00006_TableFailBranches
 * @tc.desc: Test Delete by reminderId fails and rolls back when each involved table cannot be written.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Delete_00006_TableFailBranches, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    // 1. reminder_base delete fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderBaseTable::TABLE_NAME);
    EXPECT_EQ(store.Delete(221), ReminderStore::STATE_FAIL);
    RestoreTable(*store.rdbStore_, ReminderBaseTable::TABLE_NAME, ReminderBaseTable::ADD_COLUMNS);

    // 2. reminder_alarm delete fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderAlarmTable::TABLE_NAME);
    EXPECT_EQ(store.Delete(221), ReminderStore::STATE_FAIL);
    RestoreTable(*store.rdbStore_, ReminderAlarmTable::TABLE_NAME, ReminderAlarmTable::ADD_COLUMNS);

    // 3. reminder_calendar delete fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderCalendarTable::TABLE_NAME);
    EXPECT_EQ(store.Delete(221), ReminderStore::STATE_FAIL);
    RestoreTable(*store.rdbStore_, ReminderCalendarTable::TABLE_NAME, ReminderCalendarTable::ADD_COLUMNS);

    // 4. reminder_timer delete fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderTimerTable::TABLE_NAME);
    EXPECT_EQ(store.Delete(221), ReminderStore::STATE_FAIL);
    ClearStore();
}

/**
 * @tc.name: Delete_00007_AssociatedTableFailBranches
 * @tc.desc: Test Delete with base and associated conditions fails when each table cannot be written.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Delete_00007_AssociatedTableFailBranches, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    std::string baseCondition = ReminderBaseTable::REMINDER_ID + " = 231";
    std::string assoCondition = "(SELECT " + ReminderBaseTable::REMINDER_ID + " FROM "
        + ReminderBaseTable::TABLE_NAME + " WHERE " + ReminderBaseTable::REMINDER_ID + " = 231)";

    // 1. reminder_calendar delete fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderCalendarTable::TABLE_NAME);
    EXPECT_EQ(store.Delete(baseCondition, assoCondition), ReminderStore::STATE_FAIL);
    RestoreTable(*store.rdbStore_, ReminderCalendarTable::TABLE_NAME, ReminderCalendarTable::ADD_COLUMNS);

    // 2. reminder_alarm delete fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderAlarmTable::TABLE_NAME);
    EXPECT_EQ(store.Delete(baseCondition, assoCondition), ReminderStore::STATE_FAIL);
    RestoreTable(*store.rdbStore_, ReminderAlarmTable::TABLE_NAME, ReminderAlarmTable::ADD_COLUMNS);

    // 3. reminder_timer delete fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderTimerTable::TABLE_NAME);
    EXPECT_EQ(store.Delete(baseCondition, assoCondition), ReminderStore::STATE_FAIL);
    RestoreTable(*store.rdbStore_, ReminderTimerTable::TABLE_NAME, ReminderTimerTable::ADD_COLUMNS);

    // 4. reminder_base delete fails; the view keeps a reminder_id column so the subquery stays valid.
    store.rdbStore_->ExecuteSql("DROP TABLE IF EXISTS " + ReminderBaseTable::TABLE_NAME + ";");
    store.rdbStore_->ExecuteSql("CREATE VIEW " + ReminderBaseTable::TABLE_NAME + " AS SELECT 1 AS "
        + ReminderBaseTable::REMINDER_ID + ";");
    EXPECT_EQ(store.Delete(baseCondition, assoCondition), ReminderStore::STATE_FAIL);
    ClearStore();
}

/**
 * @tc.name: DeleteAllData_00008_TableFailBranches
 * @tc.desc: Test DeleteAllData fails and rolls back when each involved table cannot be written.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, DeleteAllData_00008_TableFailBranches, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    // 1. reminder_calendar delete fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderCalendarTable::TABLE_NAME);
    EXPECT_EQ(store.DeleteAllData(), ReminderStore::STATE_FAIL);
    RestoreTable(*store.rdbStore_, ReminderCalendarTable::TABLE_NAME, ReminderCalendarTable::ADD_COLUMNS);

    // 2. reminder_alarm delete fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderAlarmTable::TABLE_NAME);
    EXPECT_EQ(store.DeleteAllData(), ReminderStore::STATE_FAIL);
    RestoreTable(*store.rdbStore_, ReminderAlarmTable::TABLE_NAME, ReminderAlarmTable::ADD_COLUMNS);

    // 3. reminder_timer delete fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderTimerTable::TABLE_NAME);
    EXPECT_EQ(store.DeleteAllData(), ReminderStore::STATE_FAIL);
    RestoreTable(*store.rdbStore_, ReminderTimerTable::TABLE_NAME, ReminderTimerTable::ADD_COLUMNS);

    // 4. reminder_base delete fails.
    ReplaceTableWithView(*store.rdbStore_, ReminderBaseTable::TABLE_NAME);
    EXPECT_EQ(store.DeleteAllData(), ReminderStore::STATE_FAIL);
    ClearStore();
}

/**
 * @tc.name: DeleteBase_00003_DeleteFail
 * @tc.desc: Test DeleteBase returns STATE_FAIL when the delete operation fails.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, DeleteBase_00003_DeleteFail, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    ReplaceTableWithView(*store.rdbStore_, ReminderBaseTable::TABLE_NAME);
    EXPECT_EQ(store.DeleteBase(ReminderBaseTable::IS_EXPIRED + " is true"), ReminderStore::STATE_FAIL);
    ClearStore();
}

/**
 * @tc.name: InitData_00003_UpdateFail
 * @tc.desc: Test InitData returns STATE_FAIL when updating the state column fails.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, InitData_00003_UpdateFail, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    ReplaceTableWithView(*store.rdbStore_, ReminderBaseTable::TABLE_NAME);
    EXPECT_EQ(store.InitData(), ReminderStore::STATE_FAIL);
    ClearStore();
}

/**
 * @tc.name: Init_00004_InitDataFailNoCloseTask
 * @tc.desc: Test Init returns STATE_FAIL without posting the idle close task when InitData fails.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Init_00004_InitDataFailNoCloseTask, Function | SmallTest | Level1)
{
    // 1. Create a valid notification.db, then make its reminder_base table unwritable.
    ReminderStore prepare;
    ASSERT_EQ(prepare.Init(), 0);
    prepare.rdbStore_->ExecuteSql("DROP TABLE IF EXISTS " + ReminderBaseTable::TABLE_NAME + ";");
    prepare.rdbStore_->ExecuteSql("CREATE VIEW " + ReminderBaseTable::TABLE_NAME + " AS SELECT 1;");
    NativeRdb::RdbHelper::ClearCache();

    // 2. Init reopens the db but InitData fails, so no idle close task is posted.
    ReminderStore reminderStore;
    EXPECT_EQ(reminderStore.Init(), ReminderStore::STATE_FAIL);
    EXPECT_EQ(reminderStore.closeTaskGeneration_, static_cast<uint64_t>(0));
}

/**
 * @tc.name: UpdateOrInsert_00002_UpdateExisting
 * @tc.desc: Test UpdateOrInsert takes the update branch when the reminder already exists.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, UpdateOrInsert_00002_UpdateExisting, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    sptr<ReminderRequest> reminder = new ReminderRequestTimer();
    reminder->SetReminderId(301);
    reminder->reminderType_ = ReminderRequest::ReminderType::TIMER;
    reminder->SetTitle("before");
    EXPECT_EQ(store.UpdateOrInsert(reminder), ReminderStore::STATE_OK);

    reminder->SetTitle("after");
    EXPECT_EQ(store.UpdateOrInsert(reminder), ReminderStore::STATE_OK);

    auto reminders = store.GetReminders("SELECT * FROM " + ReminderBaseTable::TABLE_NAME + " WHERE "
        + ReminderBaseTable::REMINDER_ID + " = 301");
    ASSERT_EQ(reminders.size(), 1);
    EXPECT_EQ(reminders[0]->GetTitle(), "after");
    ClearStore();
}

/**
 * @tc.name: EnsureOpenFail_00002_AllEntryPoints
 * @tc.desc: Test every remaining entry point handles EnsureOpen failure gracefully.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, EnsureOpenFail_00002_AllEntryPoints, Function | SmallTest | Level1)
{
    NativeRdb::RdbHelper::ClearCache();
    NativeRdb::RdbHelper::DeleteRdbStore(ReminderStore::REMINDER_DB_DIR + ReminderStore::REMINDER_DB_NAME);
    {
        std::string dbPath = ReminderStore::REMINDER_DB_DIR + ReminderStore::REMINDER_DB_NAME;
        std::ofstream dbFile(dbPath, std::ios::out | std::ios::trunc);
        dbFile << "not a sqlite database";
    }
    ReminderStore reminderStore;
    ReminderState state;
    state.reminderId_ = 1;

    EXPECT_EQ(reminderStore.Delete("com.example.test", 100, -1), ReminderStore::STATE_FAIL);
    EXPECT_EQ(reminderStore.DeleteUser(100), ReminderStore::STATE_FAIL);
    EXPECT_FALSE(reminderStore.IsReminderExist(1, 1));
    EXPECT_EQ(reminderStore.QueryActiveReminderCount(), 0);
    EXPECT_EQ(reminderStore.GetHalfHourReminders().size(), 0);
    EXPECT_EQ(reminderStore.QueryState(1).size(), 0);
    EXPECT_EQ(reminderStore.DeleteState(1), ReminderStore::STATE_FAIL);
}

/**
 * @tc.name: InsertState_00001_InsertFail
 * @tc.desc: Test InsertState returns the rdb error when inserting into reminder_state fails.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, InsertState_00001_InsertFail, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    ReplaceTableWithView(*store.rdbStore_, ReminderStateTable::TABLE_NAME);
    ReminderState state;
    state.reminderId_ = 1;
    EXPECT_EQ(store.InsertState(1, state), NativeRdb::E_SQLITE_ERROR);
    ClearStore();
}

/**
 * @tc.name: DeleteState_00001_ByTimestamp
 * @tc.desc: Test DeleteState removes rows with an earlier timestamp when a timestamp is given.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, DeleteState_00001_ByTimestamp, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    ReminderState state;
    state.reminderId_ = 401;
    state.buttonType_ = ReminderRequest::ActionButtonType::SNOOZE;
    state.isResend_ = true;
    EXPECT_EQ(store.InsertState(1, state), NativeRdb::E_OK);
    EXPECT_EQ(store.QueryState(1).size(), 1);

    // Rows written now have a timestamp smaller than any future boundary.
    int64_t futureTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() + 60000;
    EXPECT_EQ(store.DeleteState(1, futureTimestamp), NativeRdb::E_OK);
    EXPECT_EQ(store.QueryState(1).size(), 0);
    ClearStore();
}

/**
 * @tc.name: DeleteState_00002_DeleteFail
 * @tc.desc: Test DeleteState returns the rdb error when deleting from reminder_state fails.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, DeleteState_00002_DeleteFail, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    ReplaceTableWithView(*store.rdbStore_, ReminderStateTable::TABLE_NAME);
    EXPECT_EQ(store.DeleteState(1), NativeRdb::E_SQLITE_ERROR);
    ClearStore();
}

/**
 * @tc.name: QueryState_00001_RoundTrip
 * @tc.desc: Test QueryState returns the states inserted for the given uid with all fields.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, QueryState_00001_RoundTrip, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    ReminderState first;
    first.reminderId_ = 501;
    first.buttonType_ = ReminderRequest::ActionButtonType::SNOOZE;
    first.isResend_ = true;
    EXPECT_EQ(store.InsertState(1, first), NativeRdb::E_OK);

    ReminderState second;
    second.reminderId_ = 502;
    second.buttonType_ = ReminderRequest::ActionButtonType::CUSTOM;
    second.isResend_ = false;
    EXPECT_EQ(store.InsertState(1, second), NativeRdb::E_OK);

    auto states = store.QueryState(1);
    ASSERT_EQ(states.size(), 2);
    EXPECT_EQ(states[0].reminderId_, 501);
    EXPECT_EQ(states[0].buttonType_, ReminderRequest::ActionButtonType::SNOOZE);
    EXPECT_TRUE(states[0].isResend_);
    EXPECT_EQ(states[1].reminderId_, 502);
    EXPECT_EQ(states[1].buttonType_, ReminderRequest::ActionButtonType::CUSTOM);
    EXPECT_FALSE(states[1].isResend_);
    ClearStore();
}

/**
 * @tc.name: GetConfigValue_00006_TableMissing
 * @tc.desc: Test GetConfigValue returns STATE_FAIL when the config table is missing.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, GetConfigValue_00006_TableMissing, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    store.rdbStore_->ExecuteSql("DROP TABLE IF EXISTS " + std::string(ReminderConfigTable::TABLE_NAME) + ";");
    int32_t value = 5;
    EXPECT_EQ(store.GetConfigValue("test_key", value), ReminderStore::STATE_FAIL);
    EXPECT_EQ(value, 5);
    ClearStore();
}

/**
 * @tc.name: SetConfigValue_00006_FailBranches
 * @tc.desc: Test SetConfigValue fails on insert, update and missing table respectively.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, SetConfigValue_00006_FailBranches, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    // A view with the real column names: SELECT succeeds, writes fail.
    store.rdbStore_->ExecuteSql("DROP TABLE IF EXISTS " + std::string(ReminderConfigTable::TABLE_NAME) + ";");
    store.rdbStore_->ExecuteSql("CREATE VIEW " + std::string(ReminderConfigTable::TABLE_NAME)
        + " AS SELECT 'k' AS " + std::string(ReminderConfigTable::KEY)
        + ", 'v' AS " + std::string(ReminderConfigTable::VALUE) + ";");

    // No row matches the key: the INSERT into the view fails.
    EXPECT_EQ(store.SetConfigValue("other_key", 1), ReminderStore::STATE_FAIL);
    // One row matches the key: the UPDATE on the view fails.
    EXPECT_EQ(store.SetConfigValue("k", 2), ReminderStore::STATE_FAIL);

    // Table missing entirely: the SELECT fails.
    store.rdbStore_->ExecuteSql("DROP VIEW IF EXISTS " + std::string(ReminderConfigTable::TABLE_NAME) + ";");
    EXPECT_EQ(store.SetConfigValue("test_key", 3), ReminderStore::STATE_FAIL);
    ClearStore();
}

/**
 * @tc.name: GetMaxId_00002_MissingTable
 * @tc.desc: Test GetMaxId returns STATE_FAIL when the base table is missing.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, GetMaxId_00002_MissingTable, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    store.rdbStore_->ExecuteSql("DROP TABLE IF EXISTS " + ReminderBaseTable::TABLE_NAME + ";");
    EXPECT_EQ(store.GetMaxId(), ReminderStore::STATE_FAIL);
    ClearStore();
}

/**
 * @tc.name: GetReminders_00003_QueryFail
 * @tc.desc: Test GetReminders returns an empty vector when the query fails.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, GetReminders_00003_QueryFail, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    auto reminders = store.GetReminders("SELECT * FROM table_does_not_exist");
    EXPECT_EQ(reminders.size(), 0);
    ClearStore();
}

/**
 * @tc.name: GetValue_003_Int64AndStringVal
 * @tc.desc: Test GetInt64Val, GetUInt64Val and GetStringVal for success and missing columns.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, GetValue_003_Int64AndStringVal, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    store.rdbStore_->ExecuteSql("DROP TABLE IF EXISTS test_value_table;");
    store.rdbStore_->ExecuteSql("CREATE TABLE test_value_table (big_col BIGINT, text_col TEXT);");
    NativeRdb::ValuesBucket values;
    values.PutLong("big_col", 1234567890123);
    values.PutString("text_col", "str_value");
    int64_t rowId = 0;
    ASSERT_EQ(store.rdbStore_->Insert(rowId, "test_value_table", values), NativeRdb::E_OK);
    auto resultSet = store.rdbStore_->QuerySql("SELECT * FROM test_value_table", std::vector<std::string>());
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToNextRow(), NativeRdb::E_OK);

    // 1. GetInt64Val and GetUInt64Val succeed and report missing columns as 0.
    int64_t int64Val = -1;
    store.GetInt64Val(resultSet, "big_col", int64Val);
    EXPECT_EQ(int64Val, 1234567890123);
    store.GetInt64Val(resultSet, "fake_col", int64Val);
    EXPECT_EQ(int64Val, 0);
    uint64_t uint64Val = 1;
    store.GetUInt64Val(resultSet, "big_col", uint64Val);
    EXPECT_EQ(uint64Val, static_cast<uint64_t>(1234567890123));
    store.GetUInt64Val(resultSet, "fake_col", uint64Val);
    EXPECT_EQ(uint64Val, static_cast<uint64_t>(0));

    // 2. GetStringVal succeeds and leaves the value untouched for missing columns.
    std::string strVal = "untouched";
    store.GetStringVal(resultSet, "text_col", strVal);
    EXPECT_EQ(strVal, "str_value");
    store.GetStringVal(resultSet, "fake_col", strVal);
    EXPECT_EQ(strVal, "str_value");
    resultSet->Close();
    ClearStore();
}

/**
 * @tc.name: ReminderStrategyAppend_00001_MismatchedType
 * @tc.desc: Test each type strategy keeps default values when the reminder type does not match.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderStoreTest, ReminderStrategyAppend_00001_MismatchedType, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    sptr<ReminderRequest> alarm = new ReminderRequestAlarm();
    alarm->SetReminderId(601);
    alarm->reminderType_ = ReminderRequest::ReminderType::ALARM;
    sptr<ReminderRequest> timer = new ReminderRequestTimer();
    timer->SetReminderId(602);
    timer->reminderType_ = ReminderRequest::ReminderType::TIMER;

    // 1. Timer strategy with an alarm reminder: the type-specific values stay 0.
    NativeRdb::ValuesBucket timerValues;
    ReminderTimerStrategy::AppendValuesBucket(alarm, timerValues);
    int64_t rowId = 0;
    ASSERT_EQ(store.rdbStore_->Insert(rowId, ReminderTimerTable::TABLE_NAME, timerValues), NativeRdb::E_OK);
    std::string timerCheck = "SELECT " + std::string(ReminderTimerTable::TRIGGER_SECOND)
        + " FROM " + ReminderTimerTable::TABLE_NAME + " WHERE "
        + std::string(ReminderTimerTable::REMINDER_ID) + " = 601";
    EXPECT_EQ(QueryIntScalar(*store.rdbStore_, timerCheck), 0);

    // 2. Alarm strategy with a timer reminder: the type-specific values stay 0.
    NativeRdb::ValuesBucket alarmValues;
    ReminderAlarmStrategy::AppendValuesBucket(timer, alarmValues);
    ASSERT_EQ(store.rdbStore_->Insert(rowId, ReminderAlarmTable::TABLE_NAME, alarmValues), NativeRdb::E_OK);
    std::string alarmCheck = "SELECT " + ReminderAlarmTable::ALARM_HOUR
        + " FROM " + ReminderAlarmTable::TABLE_NAME + " WHERE "
        + ReminderAlarmTable::REMINDER_ID + " = 602";
    EXPECT_EQ(QueryIntScalar(*store.rdbStore_, alarmCheck), 0);

    // 3. Calendar strategy with a timer reminder: the type-specific values stay 0.
    NativeRdb::ValuesBucket calendarValues;
    ReminderCalendarStrategy::AppendValuesBucket(timer, calendarValues);
    ASSERT_EQ(store.rdbStore_->Insert(rowId, ReminderCalendarTable::TABLE_NAME, calendarValues), NativeRdb::E_OK);
    std::string calendarCheck = "SELECT " + ReminderCalendarTable::CALENDAR_DATE_TIME
        + " FROM " + ReminderCalendarTable::TABLE_NAME + " WHERE "
        + ReminderCalendarTable::REMINDER_ID + " = 602";
    EXPECT_EQ(QueryIntScalar(*store.rdbStore_, calendarCheck), 0);
    ClearStore();
}

/**
 * @tc.name: ReminderCalendarStrategyTest_00005_EndBeforeStart
 * @tc.desc: Test RecoverTime falls back to the start time when the stored end time is earlier.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderStoreTest, ReminderCalendarStrategyTest_00005_EndBeforeStart, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    // 1. Insert a calendar reminder with a normal end time.
    uint64_t dateTime = 2000000000000;
    sptr<ReminderRequest> reminder = new ReminderRequestCalendar();
    reminder->SetReminderId(801);
    reminder->reminderType_ = ReminderRequest::ReminderType::CALENDAR;
    ReminderRequestCalendar* calendar = static_cast<ReminderRequestCalendar*>(reminder.GetRefPtr());
    calendar->SetDateTime(dateTime);
    calendar->SetEndDateTime(dateTime + 60000);
    EXPECT_EQ(store.Insert(reminder), ReminderStore::STATE_OK);

    // 2. Corrupt the stored end time so that it is earlier than the start time.
    std::string updateSql = "UPDATE " + ReminderCalendarTable::TABLE_NAME + " SET "
        + ReminderCalendarTable::CALENDAR_END_DATE_TIME + " = " + std::to_string(dateTime - 60000)
        + " WHERE " + ReminderCalendarTable::REMINDER_ID + " = 801";
    ASSERT_EQ(store.rdbStore_->ExecuteSql(updateSql), NativeRdb::E_OK);

    // 3. Recover: endDateTime < dateTime, so the end time falls back to the start time.
    auto reminders = store.GetReminders("SELECT * FROM " + ReminderBaseTable::TABLE_NAME + " WHERE "
        + ReminderBaseTable::REMINDER_ID + " = 801");
    ASSERT_EQ(reminders.size(), 1);
    ReminderRequestCalendar* recovered = static_cast<ReminderRequestCalendar*>(reminders[0].GetRefPtr());
    EXPECT_EQ(recovered->GetEndDateTime(), dateTime);
    ClearStore();
}

/**
 * @tc.name: ReminderStrategyTest_00001_RoundTripBoolFlags
 * @tc.desc: Test the true branches of the bool flag ternaries survive an insert-recover round trip.
 * @tc.type: FUNC
 * @tc.require: issueI92BU9
 */
HWTEST_F(ReminderStoreTest, ReminderStrategyTest_00001_RoundTripBoolFlags, Function | SmallTest | Level1)
{
    ReminderStore store;
    InitStore(store);
    ASSERT_NE(store.rdbStore_, nullptr);

    sptr<ReminderRequest> timer = new ReminderRequestTimer();
    timer->SetReminderId(901);
    timer->reminderType_ = ReminderRequest::ReminderType::TIMER;
    timer->SetExpired(false);
    timer->SetTapDismissed(true);
    timer->SetForceDistributed(true);
    timer->SetNotDistributed(true);
    EXPECT_EQ(store.Insert(timer), ReminderStore::STATE_OK);

    auto reminders = store.GetReminders("SELECT * FROM " + ReminderBaseTable::TABLE_NAME + " WHERE "
        + ReminderBaseTable::REMINDER_ID + " = 901");
    ASSERT_EQ(reminders.size(), 1);
    EXPECT_TRUE(reminders[0]->IsTapDismissed());
    EXPECT_TRUE(reminders[0]->IsForceDistributed());
    EXPECT_TRUE(reminders[0]->IsNotDistributed());
    ClearStore();
}
}
}
