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

#include "live_view_migration_handler.h"
#include "mock_abs_shared_result_set.h"
#include "mock_rdb_store.h"
#include "notification_rdb_hook.h"
#include "notification_rdb_hook_mgr.h"

using namespace testing::ext;

namespace OHOS::Notification::Infra {
class LiveViewMigrationHandlerTest : public ::testing::Test {
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
HWTEST_F(LiveViewMigrationHandlerTest, OnUpgrade_100, Function | SmallTest | Level1)
{
    NtfRdbHook hooks;
    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    LiveViewMigrationHandler handler(hookMgr);
    MockRdbStore rdbStore;
    SetMockQuerySqlResults({nullptr});
    int32_t ret = handler.OnUpgrade(rdbStore, 1, 2);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_200
 * @tc.desc: Verify OnUpgrade returns E_OK when GetTableNames operation fails.
 * @tc.type: FUNC
 */
HWTEST_F(LiveViewMigrationHandlerTest, OnUpgrade_200, Function | SmallTest | Level1)
{
    NtfRdbHook hooks;
    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    LiveViewMigrationHandler handler(hookMgr);
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_ERROR});
    int32_t ret = handler.OnUpgrade(rdbStore, 1, 2);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_300
 * @tc.desc: Verify OnUpgrade returns E_OK when GetString fails for all table names, skipping migration with
 *           no valid tables.
 * @tc.type: FUNC
 */
HWTEST_F(LiveViewMigrationHandlerTest, OnUpgrade_300, Function | SmallTest | Level1)
{
    NtfRdbHook hooks;
    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    LiveViewMigrationHandler handler(hookMgr);
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_ERROR});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    int32_t ret = handler.OnUpgrade(rdbStore, 1, 2);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_400
 * @tc.desc: Verify OnUpgrade returns E_OK when QueryTable in ProcessTable fails to retrieve column data.
 * @tc.type: FUNC
 */
HWTEST_F(LiveViewMigrationHandlerTest, OnUpgrade_400, Function | SmallTest | Level1)
{
    NtfRdbHook hooks;
    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    LiveViewMigrationHandler handler(hookMgr);
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    SetMockQueryResults({nullptr});
    int32_t ret = handler.OnUpgrade(rdbStore, 1, 2);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_500
 * @tc.desc: Verify OnUpgrade returns E_OK when GoToFirstRow fails on the second table, handling multiple table
 *           processing with partial failures.
 * @tc.type: FUNC
 */
HWTEST_F(LiveViewMigrationHandlerTest, OnUpgrade_500, Function | SmallTest | Level1)
{
    NtfRdbHook hooks;
    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    LiveViewMigrationHandler handler(hookMgr);
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK, NativeRdb::E_ERROR});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    SetMockQueryResults({mockResultSet});
    int32_t ret = handler.OnUpgrade(rdbStore, 1, 2);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_600
 * @tc.desc: Verify OnUpgrade returns E_OK when GetString fails during second column retrieval in data row processing.
 * @tc.type: FUNC
 */
HWTEST_F(LiveViewMigrationHandlerTest, OnUpgrade_600, Function | SmallTest | Level1)
{
    NtfRdbHook hooks;
    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    LiveViewMigrationHandler handler(hookMgr);
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes(
        {"testValue", "testValue2"},
        {NativeRdb::E_OK, NativeRdb::E_ERROR}
    );
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    SetMockQueryResults({mockResultSet});
    int32_t ret = handler.OnUpgrade(rdbStore, 1, 2);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_700
 * @tc.desc: Verify OnUpgrade returns E_OK when all column retrieval operations succeed and migration data is
 *           properly processed.
 * @tc.type: FUNC
 */
HWTEST_F(LiveViewMigrationHandlerTest, OnUpgrade_700, Function | SmallTest | Level1)
{
    NtfRdbHook hooks;
    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    LiveViewMigrationHandler handler(hookMgr);
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes(
        {"testValue", "testValue2"},
        {NativeRdb::E_OK, NativeRdb::E_OK}
    );
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    SetMockQueryResults({mockResultSet});
    int32_t ret = handler.OnUpgrade(rdbStore, 1, 2);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_800
 * @tc.desc: Verify OnUpgrade returns E_OK when GetString fails during third column retrieval, handling partial row
 *           data retrieval failures.
 * @tc.type: FUNC
 */
HWTEST_F(LiveViewMigrationHandlerTest, OnUpgrade_800, Function | SmallTest | Level1)
{
    NtfRdbHook hooks;
    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    LiveViewMigrationHandler handler(hookMgr);
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes(
        {"testValue", "testValue2", "testValue3"},
        {NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_ERROR}
    );
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    SetMockQueryResults({mockResultSet});
    int32_t ret = handler.OnUpgrade(rdbStore, 1, 2);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_900
 * @tc.desc: Verify OnUpgrade returns E_OK when all three columns are successfully retrieved and data migration
 *           proceeds.
 * @tc.type: FUNC
 */
HWTEST_F(LiveViewMigrationHandlerTest, OnUpgrade_900, Function | SmallTest | Level1)
{
    NtfRdbHook hooks;
    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    LiveViewMigrationHandler handler(hookMgr);
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes(
        {"testValue", "testValue2", "testValue3"},
        {NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_OK}
    );
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    SetMockQueryResults({mockResultSet});

    int32_t ret = handler.OnUpgrade(rdbStore, 1, 2);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_1000
 * @tc.desc: Verify OnUpgrade returns E_OK when live data migration callback transforms data but
 *           InsertWithConflictResolution fails gracefully.
 * @tc.type: FUNC
 */
HWTEST_F(LiveViewMigrationHandlerTest, OnUpgrade_1000, Function | SmallTest | Level1)
{
    NtfRdbHook hooks;
    hooks.OnRdbUpgradeLiveviewMigrate = [](const std::string &oldValue, std::string &newValue) {
        newValue = "migratedValue";
        return true;
    };

    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    LiveViewMigrationHandler handler(hookMgr);
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes(
        {"testValue", "testValue2", "testValue3"},
        {NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_OK}
    );
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    SetMockQueryResults({mockResultSet});

    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_ERROR});
    int32_t ret = handler.OnUpgrade(rdbStore, 1, 2);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_1100
 * @tc.desc: Verify OnUpgrade returns E_OK when live data migration callback transforms all data and
 *           InsertWithConflictResolution succeeds in persisting migrated data.
 * @tc.type: FUNC
 */
HWTEST_F(LiveViewMigrationHandlerTest, OnUpgrade_1100, Function | SmallTest | Level1)
{
    NtfRdbHook hooks;
    hooks.OnRdbUpgradeLiveviewMigrate = [](const std::string &oldValue, std::string &newValue) {
        newValue = "migratedValue";
        return true;
    };

    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    LiveViewMigrationHandler handler(hookMgr);
    MockRdbStore rdbStore;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes(
        {"testValue", "testValue2", "testValue3"},
        {NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_OK}
    );
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    SetMockQueryResults({mockResultSet});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_OK});
    int32_t ret = handler.OnUpgrade(rdbStore, 1, 2);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: GetHandlerName_100
 * @tc.desc: Verify GetHandlerName returns "LiveViewMigrationHandler" as the correct handler identifier for handler
 *           tracking.
 * @tc.type: FUNC
 */
HWTEST_F(LiveViewMigrationHandlerTest, GetHandlerName_100, Function | SmallTest | Level1)
{
    NtfRdbHook hooks;
    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    LiveViewMigrationHandler handler(hookMgr);
    std::string name = handler.GetHandlerName();
    EXPECT_EQ(name, "LiveViewMigrationHandler");
}
} // namespace OHOS::Notification::Infra