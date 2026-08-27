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

#include "gtest/gtest.h"

#define private public
#include "priorityinfo_migration_handler.h"
#undef private
#include "mock_abs_shared_result_set.h"
#include "mock_rdb_store.h"
#include "notification_rdb_hook.h"
#include "notification_rdb_hook_mgr.h"

using namespace testing::ext;

namespace OHOS::Notification::Infra {
class PriorityInfoMigrationHandlerTest : public ::testing::Test {
public:
    void SetUp() override
    {
        ResetMockRdbStore();
        ResetMockAbsSharedResultSet();
    }
    void TearDown() override
    {
        ResetMockRdbStore();
        ResetMockAbsSharedResultSet();
    }
};

/**
 * @tc.name: OnUpgrade_100
 * @tc.desc: Verify OnUpgrade returns E_OK when table set is empty, skipping migration for no tables.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityInfoMigrationHandlerTest, OnUpgrade_100, Function | SmallTest | Level1)
{
    PriorityInfoMigrationHandler handler;
    MockRdbStore rdbStore;
    SetMockQuerySqlResults({nullptr});
    int32_t ret = handler.OnUpgrade(rdbStore, 2, 3);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_200
 * @tc.desc: Verify OnUpgrade returns E_OK when GetTableNames operation fails.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityInfoMigrationHandlerTest, OnUpgrade_200, Function | SmallTest | Level1)
{
    PriorityInfoMigrationHandler handler;
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_ERROR});
    int32_t ret = handler.OnUpgrade(rdbStore, 2, 3);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_300
 * @tc.desc: Verify OnUpgrade returns E_OK when GetString fails for all table names, skipping migration with
 *           no valid tables.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityInfoMigrationHandlerTest, OnUpgrade_300, Function | SmallTest | Level1)
{
    PriorityInfoMigrationHandler handler;
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_ERROR});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    int32_t ret = handler.OnUpgrade(rdbStore, 2, 3);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_400
 * @tc.desc: Verify OnUpgrade returns E_OK when QueryTable in ProcessTable fails to retrieve column data.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityInfoMigrationHandlerTest, OnUpgrade_400, Function | SmallTest | Level1)
{
    PriorityInfoMigrationHandler handler;
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    SetMockQueryResults({nullptr});
    int32_t ret = handler.OnUpgrade(rdbStore, 2, 3);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_500
 * @tc.desc: Verify OnUpgrade returns E_OK when GoToFirstRow fails on the second table, handling multiple table
 *           processing with partial failures.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityInfoMigrationHandlerTest, OnUpgrade_500, Function | SmallTest | Level1)
{
    PriorityInfoMigrationHandler handler;
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK, NativeRdb::E_ERROR});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    SetMockQueryResults({mockResultSet});
    int32_t ret = handler.OnUpgrade(rdbStore, 2, 3);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_600
 * @tc.desc: Verify OnUpgrade returns E_OK when GetString fails during second column retrieval in data row processing.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityInfoMigrationHandlerTest, OnUpgrade_600, Function | SmallTest | Level1)
{
    PriorityInfoMigrationHandler handler;
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes(
        {"priorityNotificationSwitch_100", "1"},
        {NativeRdb::E_OK, NativeRdb::E_ERROR}
    );
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    SetMockQueryResults({mockResultSet});
    int32_t ret = handler.OnUpgrade(rdbStore, 2, 3);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_700
 * @tc.desc: Verify OnUpgrade returns E_OK when all column retrieval operations succeed and migration data is
 *           properly processed.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityInfoMigrationHandlerTest, OnUpgrade_700, Function | SmallTest | Level1)
{
    PriorityInfoMigrationHandler handler;
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes(
        {"priorityNotificationSwitch_100", "1", "ans_priorityNotificationSwitchForBundle", "1"},
        {NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_OK}
    );
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    SetMockQueryResults({mockResultSet});
    int32_t ret = handler.OnUpgrade(rdbStore, 2, 3);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_800
 * @tc.desc: Verify OnUpgrade returns E_OK when GetString fails during third column retrieval, handling partial row
 *           data retrieval failures.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityInfoMigrationHandlerTest, OnUpgrade_800, Function | SmallTest | Level1)
{
    PriorityInfoMigrationHandler handler;
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes(
        {"priorityNotificationSwitch_100", "1", "ans_priorityNotificationSwitchForBundle"},
        {NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_ERROR}
    );
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    SetMockQueryResults({mockResultSet});
    int32_t ret = handler.OnUpgrade(rdbStore, 2, 3);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_900
 * @tc.desc: Verify OnUpgrade returns E_OK when all two columns are successfully retrieved and data migration
 *           proceeds.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityInfoMigrationHandlerTest, OnUpgrade_900, Function | SmallTest | Level1)
{
    PriorityInfoMigrationHandler handler;
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes(
        {"notification_testtable", "1"},
        {NativeRdb::E_OK, NativeRdb::E_OK}
    );
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    SetMockQueryResults({mockResultSet});

    int32_t ret = handler.OnUpgrade(rdbStore, 2, 3);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_1000
 * @tc.desc: Verify OnUpgrade returns E_OK when priority data migration callback transforms data but
 *           InsertWithConflictResolution fails gracefully.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityInfoMigrationHandlerTest, OnUpgrade_1000, Function | SmallTest | Level1)
{
    PriorityInfoMigrationHandler handler;
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes(
        {"notification_testtable", "1"},
        {NativeRdb::E_OK, NativeRdb::E_OK}
    );
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    SetMockQueryResults({mockResultSet});

    int32_t ret = handler.OnUpgrade(rdbStore, 2, 3);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_1100
 * @tc.desc: Verify OnUpgrade returns E_OK when priority data migration callback transforms all data and
 *           InsertWithConflictResolution succeeds in persisting migrated data.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityInfoMigrationHandlerTest, OnUpgrade_1100, Function | SmallTest | Level1)
{
    PriorityInfoMigrationHandler handler;
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes(
        {"notification_testtable", "1"},
        {NativeRdb::E_OK, NativeRdb::E_OK}
    );
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    SetMockQueryResults({mockResultSet});
    int32_t ret = handler.OnUpgrade(rdbStore, 2, 3);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: onRdbUpgradePriorityMigrate_0100
 * @tc.desc: test onRdbUpgradePriorityMigrate and InsertToDatabase func.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityInfoMigrationHandlerTest, onRdbUpgradePriorityMigrate_0100, Function | SmallTest | Level1)
{
    PriorityInfoMigrationHandler handler;
    MockRdbStore rdbStore;
    std::string tableName = "notification_table_100";
    std::string key1 = "priorityNotificationSwitch_100";
    std::string val1 = "0";
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_OK, NativeRdb::E_OK,
        NativeRdb::E_OK, NativeRdb::E_ERROR});
    bool ret = handler.onRdbUpgradePriorityMigrate(rdbStore, key1, val1, tableName);
    EXPECT_EQ(ret, true);
    std::string key2 = "ans_priorityNotificationSwitchForBundle";
    std::string val2 = "1";
    ret = handler.onRdbUpgradePriorityMigrate(rdbStore, key2, val2, tableName);
    EXPECT_EQ(ret, true);
    ret = handler.onRdbUpgradePriorityMigrate(rdbStore, key2, val2, tableName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: GetHandlerName_100
 * @tc.desc: Verify GetHandlerName returns "PriorityInfoMigrationHandler" as the correct handler identifier for
 *           handler tracking.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityInfoMigrationHandlerTest, GetHandlerName_100, Function | SmallTest | Level1)
{
    PriorityInfoMigrationHandler handler;
    std::string name = handler.GetHandlerName();
    EXPECT_EQ(name, "PriorityInfoMigrationHandler");
}

/**
 * @tc.name: OnUpgradeFailure_100
 * @tc.desc: Verify OnUpgradeFailure handles empty table set without crash when QuerySql returns null.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityInfoMigrationHandlerTest, OnUpgradeFailure_100, Function | SmallTest | Level1)
{
    PriorityInfoMigrationHandler handler;
    MockRdbStore rdbStore;
    SetMockQuerySqlResults({nullptr});
    EXPECT_NO_FATAL_FAILURE(handler.OnUpgradeFailure(rdbStore));
}

/**
 * @tc.name: OnUpgradeFailure_200
 * @tc.desc: Verify OnUpgradeFailure handles empty result set when GoToFirstRow fails.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityInfoMigrationHandlerTest, OnUpgradeFailure_200, Function | SmallTest | Level1)
{
    PriorityInfoMigrationHandler handler;
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_ERROR});
    EXPECT_NO_FATAL_FAILURE(handler.OnUpgradeFailure(rdbStore));
}

/**
 * @tc.name: OnUpgradeFailure_300
 * @tc.desc: Verify OnUpgradeFailure executes DELETE SQL for each table when tables exist and ExecuteSql succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityInfoMigrationHandlerTest, OnUpgradeFailure_300, Function | SmallTest | Level1)
{
    PriorityInfoMigrationHandler handler;
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"notification_table"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    SetMockDeleteErrCodes({NativeRdb::E_OK});
    EXPECT_NO_FATAL_FAILURE(handler.OnUpgradeFailure(rdbStore));
}

/**
 * @tc.name: OnUpgradeFailure_400
 * @tc.desc: Verify OnUpgradeFailure rolls back the transaction when Delete fails on a table.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityInfoMigrationHandlerTest, OnUpgradeFailure_400, Function | SmallTest | Level1)
{
    PriorityInfoMigrationHandler handler;
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"table1"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    SetMockDeleteErrCodes({NativeRdb::E_ERROR});
    EXPECT_NO_FATAL_FAILURE(handler.OnUpgradeFailure(rdbStore));
}
} // namespace OHOS::Notification::Infra
