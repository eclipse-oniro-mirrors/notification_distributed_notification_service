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

#include "reminder_store.h"

#include <filesystem>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

#include "ability_context.h"
#include "ans_log_wrapper.h"
#include "reminder_table.h"
#include "reminder_table_old.h"
#include "reminder_request_alarm.h"
#include "reminder_request_timer.h"
#include "reminder_request_calendar.h"

namespace OHOS {
namespace Notification {
namespace {
const int32_t REMINDER_RDB_VERSION_V1 = 1;
const int32_t REMINDER_RDB_VERSION_V2 = 2;
const int32_t REMINDER_RDB_VERSION_V3 = 3;
const int32_t REMINDER_RDB_VERSION_V4 = 4;
const int32_t REMINDER_RDB_VERSION = 5;
}

const int32_t ReminderStore::STATE_OK = 0;
const int32_t ReminderStore::STATE_FAIL = -1;
const std::string ReminderStore::REMINDER_DB_DIR = "/data/service/el1/public/notification/";
const std::string ReminderStore::REMINDER_DB_NAME = "notification.db";

int32_t ReminderStore::ReminderStoreDataCallBack::OnCreate(NativeRdb::RdbStore& store)
{
    ANSR_LOGI("Create table");
    return CreateTable(store);
}

int32_t ReminderStore::ReminderStoreDataCallBack::OnUpgrade(
    NativeRdb::RdbStore& store, int32_t oldVersion, int32_t newVersion)
{
    ANSR_LOGI("OnUpgrade oldVersion is %{public}d, newVersion is %{public}d", oldVersion, newVersion);
    if (oldVersion < newVersion && newVersion == REMINDER_RDB_VERSION) {
        switch (oldVersion) {
            case REMINDER_RDB_VERSION_V1:
                AddRdbColum(store, ReminderTable::TABLE_NAME, "groupId", "TEXT");
                [[fallthrough]];
            case REMINDER_RDB_VERSION_V2:
                AddRdbColum(store, ReminderTable::TABLE_NAME, "custom_ring_uri", "TEXT");
                AddRdbColum(store, ReminderTable::TABLE_NAME, "snooze_slot_id", "INT");
                [[fallthrough]];
            case REMINDER_RDB_VERSION_V3:
                AddRdbColum(store, ReminderTable::TABLE_NAME, "creator_bundle_name", "TEXT");
                [[fallthrough]];
            case REMINDER_RDB_VERSION_V4:
                CreateTable(store);
                CopyData(store);
                [[fallthrough]];
            default:
                break;
        }
    }
    store.SetVersion(newVersion);
    return NativeRdb::E_OK;
}

int32_t ReminderStore::ReminderStoreDataCallBack::OnDowngrade(
    NativeRdb::RdbStore& store, int32_t currentVersion, int32_t targetVersion)
{
    ANSR_LOGI("OnDowngrade currentVersion is %{public}d, targetVersion is %{public}d", currentVersion, targetVersion);
    if (currentVersion > targetVersion && targetVersion <= REMINDER_RDB_VERSION_V4) {
        std::string createSql = "CREATE TABLE IF NOT EXISTS " + ReminderTable::TABLE_NAME + " ("
            + ReminderTable::ADD_COLUMNS + ")";
        int32_t ret = store.ExecuteSql(createSql);
        if (ret != NativeRdb::E_OK) {
            ANSR_LOGE("Create reminder table failed:%{public}d", ret);
        }
        return ret;
    }
    store.SetVersion(targetVersion);
    return NativeRdb::E_OK;
}

int32_t ReminderStore::ReminderStoreDataCallBack::CreateTable(NativeRdb::RdbStore& store)
{
    std::string createSql = "CREATE TABLE IF NOT EXISTS " + ReminderBaseTable::TABLE_NAME + " ("
        + ReminderBaseTable::ADD_COLUMNS + ")";
    int32_t ret = store.ExecuteSql(createSql);
    if (ret != NativeRdb::E_OK) {
        ANSR_LOGE("Create reminder_base table failed:%{public}d", ret);
        return ret;
    }

    createSql = "CREATE TABLE IF NOT EXISTS " + ReminderAlarmTable::TABLE_NAME + " ("
        + ReminderAlarmTable::ADD_COLUMNS + ")";
    ret = store.ExecuteSql(createSql);
    if (ret != NativeRdb::E_OK) {
        ANSR_LOGE("Create reminder_alarm table failed:%{public}d", ret);
        return ret;
    }

    createSql = "CREATE TABLE IF NOT EXISTS " + ReminderCalendarTable::TABLE_NAME + " ("
        + ReminderCalendarTable::ADD_COLUMNS + ")";
    ret = store.ExecuteSql(createSql);
    if (ret != NativeRdb::E_OK) {
        ANSR_LOGE("Create reminder_calendar table failed:%{public}d", ret);
        return ret;
    }

    createSql = "CREATE TABLE IF NOT EXISTS " + ReminderTimerTable::TABLE_NAME + " ("
        + ReminderTimerTable::ADD_COLUMNS + ")";
    ret = store.ExecuteSql(createSql);
    if (ret != NativeRdb::E_OK) {
        ANSR_LOGE("Create reminder_timer table failed:%{public}d", ret);
        return ret;
    }
    return ret;
}

int32_t ReminderStore::ReminderStoreDataCallBack::CopyData(NativeRdb::RdbStore& store)
{
    // select old data
    auto reminders = GetOldReminders(store);
    // insert new data
    if (!reminders.empty()) {
        InsertNewReminders(store, reminders);
    }
    // delete old table
    std::string sql = "DELETE FROM " + ReminderTable::TABLE_NAME;
    store.ExecuteSql(sql);
    return NativeRdb::E_OK;
}

std::vector<sptr<ReminderRequest>> ReminderStore::ReminderStoreDataCallBack::GetOldReminders(NativeRdb::RdbStore& store)
{
    std::string sql = "SELECT " + ReminderTable::SELECT_COLUMNS + " FROM "
        + ReminderTable::TABLE_NAME;
    std::vector<sptr<ReminderRequest>> reminders;
    std::vector<std::string> whereArgs;
    auto queryResultSet = store.QuerySql(sql, whereArgs);
    if (queryResultSet == nullptr) {
        return reminders;
    }

    bool isAtLastRow = false;
    queryResultSet->IsAtLastRow(isAtLastRow);
    while (!isAtLastRow) {
        queryResultSet->GoToNextRow();
        int32_t reminderId;
        int32_t reminderType;
        GetInt32Val(queryResultSet, ReminderTable::REMINDER_ID, reminderId);
        GetInt32Val(queryResultSet, ReminderTable::REMINDER_TYPE, reminderType);

        sptr<ReminderRequest> reminder = nullptr;
        switch (reminderType) {
            case (static_cast<int32_t>(ReminderRequest::ReminderType::TIMER)): {
                reminder = new (std::nothrow) ReminderRequestTimer(reminderId);
                break;
            }
            case (static_cast<int32_t>(ReminderRequest::ReminderType::CALENDAR)): {
                reminder = new (std::nothrow) ReminderRequestCalendar(reminderId);
                break;
            }
            case (static_cast<int32_t>(ReminderRequest::ReminderType::ALARM)): {
                reminder = new (std::nothrow) ReminderRequestAlarm(reminderId);
                break;
            }
            default: {
                break;
            }
        }
        if (reminder != nullptr) {
            reminder->RecoverFromOldVersion(queryResultSet);
            reminders.push_back(reminder);
        }
        queryResultSet->IsAtLastRow(isAtLastRow);
    }
    return reminders;
}

void ReminderStore::ReminderStoreDataCallBack::InsertNewReminders(NativeRdb::RdbStore& store,
    const std::vector<sptr<ReminderRequest>>& reminders)
{
    for (auto reminder : reminders) {
        int64_t rowId = STATE_FAIL;
        sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
        if (bundleOption == nullptr) {
            continue;
        }
        bundleOption->SetBundleName(reminder->GetBundleName());
        NativeRdb::ValuesBucket baseValues;
        ReminderRequest::AppendValuesBucket(reminder, bundleOption, baseValues, true);

        store.BeginTransaction();
        // insert reminder_base
        int32_t ret = store.Insert(rowId, ReminderBaseTable::TABLE_NAME, baseValues);
        if (ret != NativeRdb::E_OK) {
            ANSR_LOGE("Insert reminder_base operation failed, result: %{public}d, reminderId=%{public}d.",
                ret, reminder->GetReminderId());
            store.RollBack();
            continue;
        }

        // insert reminder_alarm or reminder_calendar
        NativeRdb::ValuesBucket values;
        rowId = STATE_FAIL;
        switch (reminder->GetReminderType()) {
            case ReminderRequest::ReminderType::CALENDAR:
                ReminderRequestCalendar::AppendValuesBucket(reminder, bundleOption, values);
                ret = store.Insert(rowId, ReminderCalendarTable::TABLE_NAME, values);
                break;
            case ReminderRequest::ReminderType::ALARM:
                ReminderRequestAlarm::AppendValuesBucket(reminder, bundleOption, values);
                ret = store.Insert(rowId, ReminderAlarmTable::TABLE_NAME, values);
                break;
            case ReminderRequest::ReminderType::TIMER:
                ReminderRequestTimer::AppendValuesBucket(reminder, bundleOption, values);
                ret = store.Insert(rowId, ReminderTimerTable::TABLE_NAME, values);
                break;
            default:
                ANSR_LOGE("Insert reminder_base operation failed, unkown type.");
                ret = STATE_FAIL;
                break;
        }
        if (ret != NativeRdb::E_OK) {
            ANSR_LOGE("Insert operation failed, result: %{public}d, reminderId=%{public}d.",
                ret, reminder->GetReminderId());
            store.RollBack();
            continue;
        }
        store.Commit();
        ANSR_LOGD("Insert successfully, reminderId=%{public}d.", reminder->GetReminderId());
    }
}

void ReminderStore::ReminderStoreDataCallBack::AddRdbColum(NativeRdb::RdbStore& store, const std::string& tableName,
    const std::string& columnName, const std::string& columnType)
{
    std::string sqlStr = "";
    if (columnType == "TEXT") {
        sqlStr = "ALTER TABLE " + tableName + " ADD " + columnName + " " + columnType + " DEFAULT '';";
    } else if (columnType == "INT") {
        //3 is meaning others
        sqlStr = "ALTER TABLE " + tableName + " ADD " + columnName + " " + columnType + " DEFAULT 3;";
    }
    ANSR_LOGD("AddRdbColum sqlStr = %{public}s", sqlStr.c_str());
    int errorCode = store.ExecuteSql(sqlStr);
    if (errorCode != NativeRdb::E_OK) {
        ANSR_LOGE("AddRdbColum error,errorCode is = %{public}d", errorCode);
    }
}

__attribute__((no_sanitize("cfi"))) int32_t ReminderStore::Init()
{
    ANSR_LOGD("Reminder store init.");
    if (access(REMINDER_DB_DIR.c_str(), F_OK) != 0) {
        int createDir = mkdir(REMINDER_DB_DIR.c_str(), S_IRWXU);
        if (createDir != 0) {
            ANSR_LOGE("Failed to create directory %{private}s", REMINDER_DB_DIR.c_str());
            return STATE_FAIL;
        }
    }
	
    ReminderTable::InitDbColumns();
    ReminderBaseTable::InitDbColumns();
    ReminderTimerTable::InitDbColumns();
    ReminderAlarmTable::InitDbColumns();
    ReminderCalendarTable::InitDbColumns();

    std::string dbConfig = REMINDER_DB_DIR + REMINDER_DB_NAME;
    NativeRdb::RdbStoreConfig config(dbConfig);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);

    ReminderStoreDataCallBack rdbDataCallBack;
    int32_t errCode = STATE_FAIL;
    rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(config, REMINDER_RDB_VERSION, rdbDataCallBack, errCode);
    if (rdbStore_ == nullptr) {
        ANSR_LOGE("ReminderStore init fail, errCode %{public}d.", errCode);
        return STATE_FAIL;
    }
    return InitData();
}

__attribute__((no_sanitize("cfi"))) int32_t ReminderStore::Delete(const int32_t reminderId)
{
    if (rdbStore_ == nullptr) {
        ANSR_LOGE("Rdb store is not initialized.");
        return STATE_FAIL;
    }
    std::string condition = ReminderBaseTable::REMINDER_ID + " = " + std::to_string(reminderId);
    rdbStore_->BeginTransaction();
    int32_t delRows = STATE_FAIL;
    std::vector<std::string> whereArgs;
    int32_t ret = rdbStore_->Delete(delRows, ReminderBaseTable::TABLE_NAME, condition, whereArgs);
    if (ret != NativeRdb::E_OK) {
        ANSR_LOGE("Delete from %{public}s failed, reminderId = %{public}d",
            ReminderBaseTable::TABLE_NAME.c_str(), reminderId);
        rdbStore_->RollBack();
        return STATE_FAIL;
    }
    delRows = STATE_FAIL;
    ret = rdbStore_->Delete(delRows, ReminderAlarmTable::TABLE_NAME, condition, whereArgs);
    if (ret != NativeRdb::E_OK) {
        ANSR_LOGE("Delete from %{public}s failed, reminderId = %{public}d",
            ReminderAlarmTable::TABLE_NAME.c_str(), reminderId);
        rdbStore_->RollBack();
        return STATE_FAIL;
    }
    delRows = STATE_FAIL;
    ret = rdbStore_->Delete(delRows, ReminderCalendarTable::TABLE_NAME, condition, whereArgs);
    if (ret != NativeRdb::E_OK) {
        ANSR_LOGE("Delete from %{public}s failed, reminderId = %{public}d",
            ReminderCalendarTable::TABLE_NAME.c_str(), reminderId);
        rdbStore_->RollBack();
        return STATE_FAIL;
    }
    delRows = STATE_FAIL;
    ret = rdbStore_->Delete(delRows, ReminderTimerTable::TABLE_NAME, condition, whereArgs);
    if (ret != NativeRdb::E_OK) {
        ANSR_LOGE("Delete from %{public}s failed, reminderId = %{public}d",
            ReminderTimerTable::TABLE_NAME.c_str(), reminderId);
        rdbStore_->RollBack();
        return STATE_FAIL;
    }
    rdbStore_->Commit();
    return STATE_OK;
}

__attribute__((no_sanitize("cfi"))) int32_t ReminderStore::Delete(const std::string& pkg, const int32_t userId)
{
    std::string assoConditon = "(SELECT " + ReminderBaseTable::REMINDER_ID + " FROM " + ReminderBaseTable::TABLE_NAME
        + " WHERE " + ReminderBaseTable::TABLE_NAME + "." + ReminderBaseTable::PACKAGE_NAME + " = '" + pkg
        + "' AND " + ReminderBaseTable::TABLE_NAME + "." + ReminderBaseTable::USER_ID + " = " + std::to_string(userId)
        + ")";

    std::string baseCondtion = ReminderBaseTable::PACKAGE_NAME + " = '" + pkg + "' AND "
        + ReminderBaseTable::USER_ID + " = " + std::to_string(userId);
    return Delete(baseCondtion, assoConditon);
}

__attribute__((no_sanitize("cfi"))) int32_t ReminderStore::DeleteUser(const int32_t userId)
{
    std::string assoConditon = "(SELECT " + ReminderBaseTable::REMINDER_ID + " FROM " + ReminderBaseTable::TABLE_NAME
        + " WHERE " + ReminderBaseTable::TABLE_NAME + "." + ReminderBaseTable::USER_ID + " = "
        + std::to_string(userId) + ")";

    std::string baseCondtion = ReminderBaseTable::USER_ID + " = " + std::to_string(userId);
    return Delete(baseCondtion, assoConditon);
}

int32_t ReminderStore::UpdateOrInsert(
    const sptr<ReminderRequest>& reminder, const sptr<NotificationBundleOption>& bundleOption)
{
    if (rdbStore_ == nullptr) {
        ANSR_LOGE("Rdb store is not initialized.");
        return STATE_FAIL;
    }
    if (bundleOption == nullptr) {
        ANSR_LOGE("BundleOption is null.");
        return STATE_FAIL;
    }
    if (IsReminderExist(reminder)) {
        return Update(reminder, bundleOption);
    } else {
        return Insert(reminder, bundleOption);
    }
}

int32_t ReminderStore::GetMaxId()
{
    if (rdbStore_ == nullptr) {
        ANSR_LOGE("Rdb store is not initialized.");
        return STATE_FAIL;
    }
    std::string queryCondition = "SELECT " + ReminderBaseTable::REMINDER_ID
        + " FROM " + ReminderBaseTable::TABLE_NAME + " ORDER BY "
        + ReminderBaseTable::REMINDER_ID + " DESC";
    auto queryResultSet = Query(queryCondition);
    if (queryResultSet == nullptr) {
        ANSR_LOGE("QueryResultSet is null.");
        return STATE_FAIL;
    }
    int32_t resultNum = 0;
    queryResultSet->GetRowCount(resultNum);
    if (resultNum == 0) {
        ANSR_LOGI("QueryResultSet is zero.");
        return STATE_FAIL;
    }
    queryResultSet->GoToNextRow();
    int32_t maxId = STATE_FAIL;
    int32_t result = queryResultSet->GetInt(0, maxId);
    if (result != NativeRdb::E_OK) {
        ANSR_LOGE("Query operation failed, result %{public}d.", result);
    }
    ANSR_LOGD("MaxId: %{public}d.", maxId);
    return maxId;
}

__attribute__((no_sanitize("cfi"))) std::vector<sptr<ReminderRequest>> ReminderStore::GetAllValidReminders()
{
    std::string sql = "SELECT " + ReminderBaseTable::SELECT_COLUMNS + " FROM "
        + ReminderBaseTable::TABLE_NAME + " WHERE "
        + ReminderBaseTable::IS_EXPIRED + " = 'false' ORDER BY "
        + ReminderBaseTable::TRIGGER_TIME + " ASC";
    ANSR_LOGD("GetAllValidReminders sql =%{public}s", sql.c_str());
    return GetReminders(sql);
}

void ReminderStore::GetUInt8Val(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
    const std::string& name, uint8_t& value)
{
    int32_t val;
    GetInt32Val(resultSet, name, val);
    value = static_cast<uint8_t>(val);
}

void ReminderStore::GetUInt16Val(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
    const std::string& name, uint16_t& value)
{
    int32_t val;
    GetInt32Val(resultSet, name, val);
    value = static_cast<uint16_t>(val);
}

void ReminderStore::GetInt32Val(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
    const std::string& name, int32_t& value)
{
    value = 0;
    int32_t columnIndex = -1;
    resultSet->GetColumnIndex(name, columnIndex);
    if (columnIndex == -1) {
        ANSR_LOGE("the column %{public}s does not exsit.", name.c_str());
        return;
    }
    resultSet->GetInt(columnIndex, value);
}

void ReminderStore::GetInt64Val(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
    const std::string& name, int64_t& value)
{
    value = 0;
    int32_t columnIndex = -1;
    resultSet->GetColumnIndex(name, columnIndex);
    if (columnIndex == -1) {
        ANSR_LOGE("the column %{public}s does not exsit.", name.c_str());
        return;
    }
    resultSet->GetLong(columnIndex, value);
}

void ReminderStore::GetUInt64Val(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
    const std::string& name, uint64_t& value)
{
    int64_t val;
    GetInt64Val(resultSet, name, val);
    value = static_cast<uint64_t>(val);
}

void ReminderStore::GetStringVal(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
    const std::string& name, std::string& value)
{
    int32_t columnIndex = -1;
    resultSet->GetColumnIndex(name, columnIndex);
    if (columnIndex == -1) {
        ANSR_LOGE("the column %{public}s does not exsit.", name.c_str());
        return;
    }
    resultSet->GetString(columnIndex, value);
}

__attribute__((no_sanitize("cfi"))) int32_t ReminderStore::InitData()
{
    ANSR_LOGD("Reminder data init.");
    if (rdbStore_ == nullptr) {
        ANSR_LOGE("Rdb store is not initialized.");
        return STATE_FAIL;
    }
    // delete all the reminders which IS_EXPIRED is true.
    std::string deleteCondition = ReminderBaseTable::IS_EXPIRED + " is true";
    DeleteBase(deleteCondition);

    // set all the value of STATE to ReminderRequest::REMINDER_STATUS_INACTIVE
    NativeRdb::ValuesBucket statusValues;
    statusValues.PutInt(ReminderBaseTable::STATE, ReminderRequest::REMINDER_STATUS_INACTIVE);
    int32_t statusChangedRows = STATE_FAIL;
    int32_t ret = rdbStore_->Update(statusChangedRows, ReminderBaseTable::TABLE_NAME, statusValues);
    ANSR_LOGD("Change status to inactive, changed rows: %{public}d.", statusChangedRows);
    if (ret != NativeRdb::E_OK) {
        ANSR_LOGE("Init data failed.");
        return STATE_FAIL;
    }
    return STATE_OK;
}

__attribute__((no_sanitize("cfi"))) int32_t ReminderStore::DeleteBase(const std::string& deleteCondition)
{
    if (rdbStore_ == nullptr) {
        ANSR_LOGE("Rdb store is not initialized.");
        return STATE_FAIL;
    }
    int32_t deletedRows = STATE_FAIL;
    std::vector<std::string> whereArgs;
    int32_t ret = rdbStore_->Delete(deletedRows, ReminderBaseTable::TABLE_NAME, deleteCondition, whereArgs);
    if (ret != NativeRdb::E_OK) {
        ANSR_LOGE("Delete operation failed, deleteConditon: %{public}s," \
            "result: %{public}d.", deleteCondition.c_str(), ret);
    }
    ANSR_LOGD("Delete operation done, deleteConditon: %{public}s," \
        "deleted rows: %{public}d.", deleteCondition.c_str(), deletedRows);
    return deletedRows;
}

__attribute__((no_sanitize("cfi"))) int32_t ReminderStore::Delete(const std::string& baseCondition,
    const std::string& assoConditon)
{
    if (rdbStore_ == nullptr) {
        ANSR_LOGE("Rdb store is not initialized.");
        return STATE_FAIL;
    }
    rdbStore_->BeginTransaction();
    // delete reminder_calendar
    std::string sql = "DELETE FROM " + ReminderCalendarTable::TABLE_NAME + " WHERE "
        + ReminderCalendarTable::TABLE_NAME + "." + ReminderCalendarTable::REMINDER_ID
        + " IN " + assoConditon;
    int32_t ret = rdbStore_->ExecuteSql(sql);
    if (ret != NativeRdb::E_OK) {
        ANSR_LOGE("Delete from %{public}s failed", ReminderCalendarTable::TABLE_NAME.c_str());
        rdbStore_->RollBack();
        return STATE_FAIL;
    }

    // delete reminder_alarm
    sql = "DELETE FROM " + ReminderAlarmTable::TABLE_NAME + " WHERE "
        + ReminderAlarmTable::TABLE_NAME + "." + ReminderAlarmTable::REMINDER_ID
        + " IN " + assoConditon;
    ret = rdbStore_->ExecuteSql(sql);
    if (ret != NativeRdb::E_OK) {
        ANSR_LOGE("Delete from %{public}s failed", ReminderCalendarTable::TABLE_NAME.c_str());
        rdbStore_->RollBack();
        return STATE_FAIL;
    }

    // delete reminder_timer
    sql = "DELETE FROM " + ReminderTimerTable::TABLE_NAME + " WHERE "
        + ReminderTimerTable::TABLE_NAME + "." + ReminderTimerTable::REMINDER_ID
        + " IN " + assoConditon;
    ret = rdbStore_->ExecuteSql(sql);
    if (ret != NativeRdb::E_OK) {
        ANSR_LOGE("Delete from %{public}s failed", ReminderTimerTable::TABLE_NAME.c_str());
        rdbStore_->RollBack();
        return STATE_FAIL;
    }

    // delete reminder_base
    sql = "DELETE FROM " + ReminderBaseTable::TABLE_NAME + " WHERE " + baseCondition;
    ret = rdbStore_->ExecuteSql(sql);
    if (ret != NativeRdb::E_OK) {
        ANSR_LOGE("Delete from %{public}s failed", ReminderCalendarTable::TABLE_NAME.c_str());
        rdbStore_->RollBack();
        return STATE_FAIL;
    }
    rdbStore_->Commit();
    return STATE_OK;
}

int32_t ReminderStore::Insert(
    const sptr<ReminderRequest>& reminder, const sptr<NotificationBundleOption>& bundleOption)
{
    if (rdbStore_ == nullptr) {
        ANSR_LOGE("Rdb store is not initialized.");
        return STATE_FAIL;
    }
    int64_t rowId = STATE_FAIL;
    NativeRdb::ValuesBucket baseValues;
    ReminderRequest::AppendValuesBucket(reminder, bundleOption, baseValues);
    
    rdbStore_->BeginTransaction();
    // insert reminder_base
    int32_t ret = rdbStore_->Insert(rowId, ReminderBaseTable::TABLE_NAME, baseValues);
    if (ret != NativeRdb::E_OK) {
        ANSR_LOGE("Insert reminder_base operation failed, result: %{public}d, reminderId=%{public}d.",
            ret, reminder->GetReminderId());
        rdbStore_->RollBack();
        return STATE_FAIL;
    }

    // insert reminder_alarm or reminder_calendar
    NativeRdb::ValuesBucket values;
    rowId = STATE_FAIL;
    switch (reminder->GetReminderType()) {
        case ReminderRequest::ReminderType::CALENDAR: {
            ReminderRequestCalendar::AppendValuesBucket(reminder, bundleOption, values);
            ret = rdbStore_->Insert(rowId, ReminderCalendarTable::TABLE_NAME, values);
            break;
        }
        case ReminderRequest::ReminderType::ALARM: {
            ReminderRequestAlarm::AppendValuesBucket(reminder, bundleOption, values);
            ret = rdbStore_->Insert(rowId, ReminderAlarmTable::TABLE_NAME, values);
            break;
        }
        case ReminderRequest::ReminderType::TIMER: {
            ReminderRequestTimer::AppendValuesBucket(reminder, bundleOption, values);
            ret = rdbStore_->Insert(rowId, ReminderTimerTable::TABLE_NAME, values);
            break;
        }
        default: {
            ANSR_LOGE("Insert reminder_base operation failed, unkown type.");
            ret = STATE_FAIL;
            break;
        }
    }
    if (ret != NativeRdb::E_OK) {
        ANSR_LOGE("Insert operation failed, result: %{public}d, reminderId=%{public}d.",
            ret, reminder->GetReminderId());
        rdbStore_->RollBack();
        return STATE_FAIL;
    }
    rdbStore_->Commit();
    ANSR_LOGD("Insert successfully, reminderId=%{public}d.", reminder->GetReminderId());
    return STATE_OK;
}

int32_t ReminderStore::Update(
    const sptr<ReminderRequest>& reminder, const sptr<NotificationBundleOption>& bundleOption)
{
    if (rdbStore_ == nullptr) {
        ANSR_LOGE("Rdb store is not initialized.");
        return STATE_FAIL;
    }
    int32_t rowId = STATE_FAIL;
    NativeRdb::ValuesBucket baseValues;
    ReminderRequest::AppendValuesBucket(reminder, bundleOption, baseValues);

    std::string updateCondition = ReminderBaseTable::REMINDER_ID
        + " = " + std::to_string(reminder->GetReminderId());

    rdbStore_->BeginTransaction();
    // update reminder_base
    std::vector<std::string> whereArgs;
    int32_t ret = rdbStore_->Update(rowId, ReminderBaseTable::TABLE_NAME, baseValues, updateCondition, whereArgs);
    if (ret != NativeRdb::E_OK) {
        ANSR_LOGE("Update reminder_base operation failed, result: %{public}d, reminderId=%{public}d.",
            ret, reminder->GetReminderId());
        rdbStore_->RollBack();
        return STATE_FAIL;
    }

    // update reminder_alarm or reminder_calendar
    NativeRdb::ValuesBucket values;
    rowId = STATE_FAIL;
    switch (reminder->GetReminderType()) {
        case ReminderRequest::ReminderType::CALENDAR:
            ReminderRequestCalendar::AppendValuesBucket(reminder, bundleOption, values);
            ret = rdbStore_->Update(rowId, ReminderCalendarTable::TABLE_NAME, values, updateCondition, whereArgs);
            break;
        case ReminderRequest::ReminderType::ALARM:
            ReminderRequestAlarm::AppendValuesBucket(reminder, bundleOption, values);
            ret = rdbStore_->Update(rowId, ReminderAlarmTable::TABLE_NAME, values, updateCondition, whereArgs);
            break;
        case ReminderRequest::ReminderType::TIMER:
            ReminderRequestTimer::AppendValuesBucket(reminder, bundleOption, values);
            ret = rdbStore_->Update(rowId, ReminderTimerTable::TABLE_NAME, values, updateCondition, whereArgs);
            break;
        default:
            ANSR_LOGE("Insert reminder_base operation failed, unkown type.");
            ret = STATE_FAIL;
            break;
    }
    if (ret != NativeRdb::E_OK) {
        ANSR_LOGE("Update operation failed, result: %{public}d, reminderId=%{public}d.",
            ret, reminder->GetReminderId());
        rdbStore_->RollBack();
        return STATE_FAIL;
    }
    rdbStore_->Commit();
    ANSR_LOGD("Update successfully, reminderId=%{public}d.", reminder->GetReminderId());
    return STATE_OK;
}

bool ReminderStore::IsReminderExist(const sptr<ReminderRequest>& reminder)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(ReminderBaseTable::TABLE_NAME);
    absRdbPredicates.EqualTo(ReminderBaseTable::REMINDER_ID, std::to_string(reminder->GetReminderId()));
    auto queryResultSet = rdbStore_->Query(absRdbPredicates, std::vector<std::string>());
    if (queryResultSet == nullptr) {
        ANSR_LOGE("QueryResultSet is null.");
        return false;
    }
    int32_t resultNum;
    queryResultSet->GetRowCount(resultNum);
    return resultNum != 0;
}

std::vector<sptr<ReminderRequest>> ReminderStore::GetReminders(const std::string& queryCondition)
{
    std::vector<sptr<ReminderRequest>> reminders;
    if (rdbStore_ == nullptr) {
        ANSR_LOGE("Rdb store is not initialized.");
        return reminders;
    }
    auto queryResultSet = Query(queryCondition);
    if (queryResultSet == nullptr) {
        return reminders;
    }
    bool isAtLastRow = false;
    queryResultSet->IsAtLastRow(isAtLastRow);
    while (!isAtLastRow) {
        queryResultSet->GoToNextRow();
        sptr<ReminderRequest> reminder = BuildReminder(queryResultSet);
        if (reminder != nullptr) {
            reminders.push_back(reminder);
        }
        queryResultSet->IsAtLastRow(isAtLastRow);
    }
    ANSR_LOGD("Size=%{public}zu", reminders.size());
    return reminders;
}

sptr<ReminderRequest> ReminderStore::BuildReminder(const std::shared_ptr<NativeRdb::ResultSet>& resultBase)
{
    int32_t reminderId;
    int32_t reminderType;
    GetInt32Val(resultBase, ReminderBaseTable::REMINDER_ID, reminderId);
    GetInt32Val(resultBase, ReminderBaseTable::REMINDER_TYPE, reminderType);

    sptr<ReminderRequest> reminder = nullptr;
    std::shared_ptr<NativeRdb::ResultSet> resultSet;
    switch (reminderType) {
        case (static_cast<int32_t>(ReminderRequest::ReminderType::TIMER)): {
            reminder = new (std::nothrow) ReminderRequestTimer(reminderId);
            resultSet = Query(ReminderTimerTable::TABLE_NAME, ReminderTimerTable::SELECT_COLUMNS, reminderId);
            break;
        }
        case (static_cast<int32_t>(ReminderRequest::ReminderType::CALENDAR)): {
            reminder = new (std::nothrow) ReminderRequestCalendar(reminderId);
            resultSet = Query(ReminderCalendarTable::TABLE_NAME, ReminderCalendarTable::SELECT_COLUMNS, reminderId);
            break;
        }
        case (static_cast<int32_t>(ReminderRequest::ReminderType::ALARM)): {
            reminder = new (std::nothrow) ReminderRequestAlarm(reminderId);
            resultSet = Query(ReminderAlarmTable::TABLE_NAME, ReminderAlarmTable::SELECT_COLUMNS, reminderId);
            break;
        }
        default: {
            ANSR_LOGE("ReminderType from database is error, reminderType %{public}d.", reminderType);
            break;
        }
    }
    if (reminder != nullptr) {
        reminder->RecoverFromDbBase(resultBase);
        reminder->RecoverFromDb(resultSet);
        ANSR_LOGI("BuildReminder success.");
    } else {
        ANSR_LOGW("BuildReminder fail.");
    }
    return reminder;
}

std::shared_ptr<NativeRdb::ResultSet> ReminderStore::Query(const std::string& tableName, const std::string& colums,
    const int32_t reminderId)
{
    if (rdbStore_ == nullptr) {
        ANSR_LOGE("Rdb store is not initialized.");
        return nullptr;
    }
    std::string queryCondition = "SELECT " + colums + " FROM " + tableName
        + " WHERE " + ReminderBaseTable::REMINDER_ID + " = " + std::to_string(reminderId);
    auto queryResultSet = Query(queryCondition);
    if (queryResultSet == nullptr) {
        return nullptr;
    }
    int32_t resultNum = 0;
    queryResultSet->GetRowCount(resultNum);
    if (resultNum == 0) {
        return nullptr;
    }
    queryResultSet->GoToNextRow();
    return queryResultSet;
}

std::shared_ptr<NativeRdb::ResultSet> ReminderStore::Query(const std::string& queryCondition) const
{
    if (rdbStore_ == nullptr) {
        ANSR_LOGE("Rdb store is not initialized.");
        return nullptr;
    }
    std::vector<std::string> whereArgs;
    return rdbStore_->QuerySql(queryCondition, whereArgs);
}
}  // namespace Notification
}  // namespace OHOS
