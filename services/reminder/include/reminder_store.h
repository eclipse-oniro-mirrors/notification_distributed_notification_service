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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_STORE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_STORE_H

#include <vector>
#include <mutex>

#include "notification_bundle_option.h"
#include "reminder_request.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store_config.h"

namespace OHOS {
namespace Notification {
class ReminderStore {
public:
    ReminderStore() {};
    virtual ~ReminderStore() {};

public:
    int32_t Init();
    int32_t Delete(const int32_t reminderId);
    int32_t Delete(const std::string& pkg, const int32_t userId, const int32_t uid);
    int32_t DeleteUser(const int32_t userId);
    int32_t UpdateOrInsert(const sptr<ReminderRequest>& reminder);
    int32_t GetMaxId();
    int32_t QueryActiveReminderCount();
    std::vector<sptr<ReminderRequest>> GetHalfHourReminders();
    std::vector<sptr<ReminderRequest>> GetAllValidReminders();

public:
    static void GetUInt8Val(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
        const std::string& name, uint8_t& value);
    static void GetUInt16Val(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
        const std::string& name, uint16_t& value);
    static void GetInt32Val(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
        const std::string& name, int32_t& value);
    static void GetInt64Val(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
        const std::string& name, int64_t& value);
    static void GetUInt64Val(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
        const std::string& name, uint64_t& value);
    static void GetStringVal(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
        const std::string& name, std::string& value);

    static const int32_t STATE_OK;
    static const int32_t STATE_FAIL;

    static const std::string REMINDER_DB_DIR;
    static const std::string REMINDER_DB_NAME;
    static const std::string REMINDER_DB_TABLE;

private:
    /**
     * @brief Inits the data in database when system boot on or proxy process reboot on.
     *
     * 1. Deletes all the reminders which IS_EXPIRED is true.
     * 2. Sets all the value of STATE to ReminderRequest::REMINDER_STATUS_INACTIVE
     *
     * @return int32_t result code.
     */
    int32_t InitData();
    int32_t DeleteBase(const std::string& deleteCondition);
    int32_t Delete(const std::string& baseCondition, const std::string& assoConditon);
    int32_t Insert(const sptr<ReminderRequest>& reminder);
    int32_t Update(const sptr<ReminderRequest>& reminder);

    bool IsReminderExist(const sptr<ReminderRequest>& reminder);
    std::vector<sptr<ReminderRequest>> GetReminders(const std::string& queryCondition);
    sptr<ReminderRequest> BuildReminder(const std::shared_ptr<NativeRdb::ResultSet>& resultBase);
    
    std::shared_ptr<NativeRdb::ResultSet> Query(const std::string& tableName, const std::string& colums,
        const int32_t reminderId);
    std::shared_ptr<NativeRdb::ResultSet> Query(const std::string& queryCondition) const;

private:
    std::shared_ptr<NativeRdb::RdbStore> rdbStore_ = nullptr;

    std::mutex initMutex_;

private:
class ReminderStoreDataCallBack : public NativeRdb::RdbOpenCallback {
public:
    int32_t OnCreate(NativeRdb::RdbStore& store) override;
    int32_t OnUpgrade(NativeRdb::RdbStore& store, int32_t oldVersion, int32_t newVersion) override;
    int32_t OnDowngrade(NativeRdb::RdbStore& store, int32_t currentVersion, int32_t targetVersion) override;

private:
    int32_t CreateTable(NativeRdb::RdbStore& store);
    int32_t CopyData(NativeRdb::RdbStore& store);
    std::vector<sptr<ReminderRequest>> GetOldReminders(NativeRdb::RdbStore& store);
    void InsertNewReminders(NativeRdb::RdbStore& store, const std::vector<sptr<ReminderRequest>>& reminders);
    void AddRdbColum(NativeRdb::RdbStore& store, const std::string& tableName,
        const std::string& columnName, const std::string& columnType, const std::string& defValue);
};
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_STORE_H