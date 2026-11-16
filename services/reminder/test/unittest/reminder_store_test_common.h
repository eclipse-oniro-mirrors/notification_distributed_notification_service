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

#ifndef BASE_NOTIFICATION_ANS_STANDARD_SERVICES_REMINDER_TEST_UNITTEST_REMINDER_STORE_TEST_COMMON_H
#define BASE_NOTIFICATION_ANS_STANDARD_SERVICES_REMINDER_TEST_UNITTEST_REMINDER_STORE_TEST_COMMON_H

#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "reminder_helper.h"
#include "reminder_store.h"
#include "reminder_table_old.h"
#include "rdb_store.h"

namespace OHOS {
namespace Notification {
// Error code shared by the reminder store test files.
constexpr int32_t STATE_FAIL = -1;

// Create the old-version reminder table so CopyData tests have a source table to migrate.
inline void CreateOldTable(NativeRdb::RdbStore& store)
{
    std::string createSql = "CREATE TABLE IF NOT EXISTS " + ReminderTable::TABLE_NAME + " ("
        + ReminderTable::ADD_COLUMNS + ")";
    store.ExecuteSql(createSql);
}

// Fixture shared by reminder_store_test.cpp and reminder_store_branch_test.cpp.
class ReminderStoreTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        ReminderStore::EnsureDbColumnsInitialized();
        ReminderHelper::CancelAllReminders();
    }
    static void TearDownTestCase() {}
    void SetUp()
    {
        std::string dir = ReminderStore::REMINDER_DB_DIR;
        for (size_t pos = 1; pos < dir.size(); ++pos) {
            if (dir[pos] == '/') {
                std::string sub = dir.substr(0, pos);
                if (access(sub.c_str(), F_OK) != 0) {
                    mkdir(sub.c_str(), S_IRWXU);
                }
            }
        }
        if (access(dir.c_str(), F_OK) != 0) {
            mkdir(dir.c_str(), S_IRWXU);
        }
    }
    void TearDown()
    {
        ReminderHelper::CancelAllReminders();
        NativeRdb::RdbHelper::ClearCache();
        NativeRdb::RdbHelper::DeleteRdbStore(ReminderStore::REMINDER_DB_DIR + "notification_test.db");
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
            constexpr int32_t version = 14;
            store.rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(config, version, rdbDataCallBack, errCode);
        }
    }

    void ClearStore()
    {
        NativeRdb::RdbHelper::ClearCache();
        NativeRdb::RdbHelper::DeleteRdbStore(ReminderStore::REMINDER_DB_DIR + "notification_test.db");
    }
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_STANDARD_SERVICES_REMINDER_TEST_UNITTEST_REMINDER_STORE_TEST_COMMON_H
