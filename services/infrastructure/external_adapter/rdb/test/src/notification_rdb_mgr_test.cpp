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
#include "notification_rdb_mgr.h"
#include "mock_rdb_helper.h"
#include "mock_rdb_store.h"
#include "mock_abs_shared_result_set.h"

using namespace testing::ext;

namespace OHOS::Notification::Infra {

class NotificationRdbMgrTest : public ::testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override;
    void TearDown() override;
};

void NotificationRdbMgrTest::SetUp()
{
    // Reset mock error code before each test
    ResetMockRdbHelper();
    ResetMockAbsSharedResultSet();
    ResetMockRdbStore();
}

void NotificationRdbMgrTest::TearDown()
{
    // Reset mock error code after each test
    ResetMockRdbHelper();
    ResetMockAbsSharedResultSet();
    ResetMockRdbStore();
}

/**
 * @tc.name: Init_100
 * @tc.desc: Verify Init returns E_OK when RdbHelper::GetRdbHelper succeeds and rdbStore_ is properly initialized.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrTest, Init_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: Destroy_100
 * @tc.desc: Verify Destroy returns E_OK when rdbStore_ is successfully deleted after successful initialization.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrTest, Destroy_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    ret = rdbMgr.Destroy();
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: InsertData_Str_100
 * @tc.desc: Verify InsertData with string value returns E_OK when all operations succeed for a non-system user
 *           (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrTest, InsertData_Str_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::string value = "value";
    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_OK});
    ret = rdbMgr.InsertData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: InsertData_Blob_100
 * @tc.desc: Verify InsertData with blob value returns E_OK when all operations succeed for a non-system user
 *           (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrTest, InsertData_Blob_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::vector<uint8_t> value = { 'v', 'a', 'l', 'u', 'e' };
    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_OK});
    ret = rdbMgr.InsertData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: InsertData_Batch_100
 * @tc.desc: Verify InsertData with batch map returns E_OK when all operations succeed for a non-system user
 *           (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrTest, InsertData_Batch_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::unordered_map<std::string, std::string> values = {
        { "key1", "value1" },
        { "key2", "value2" }
    };
    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});
    SetMockBatchInsertErrCodes({NativeRdb::E_OK});
    ret = rdbMgr.InsertBatchData(values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: DeleteData_100
 * @tc.desc: Verify DeleteData returns E_OK when Delete operation succeeds for a non-system user (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrTest, DeleteData_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    int32_t nonSystemUserId = 100;
    SetMockDeleteErrCodes({NativeRdb::E_OK});
    ret = rdbMgr.DeleteData(key, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: DeleteBatchData_100
 * @tc.desc: Verify DeleteBatchData returns E_OK when batch delete operation succeeds for multiple keys.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrTest, DeleteBatchData_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::vector<std::string> keys = { "key1", "key2" };
    int32_t nonSystemUserId = 100;
    ret = rdbMgr.DeleteBatchData(keys, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: DropUserTable_100_Success
 * @tc.desc: Verify DropUserTable returns E_OK when drop table operation succeeds for a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrTest, DropUserTable_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    ret = rdbMgr.DropUserTable(nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: QueryData_Str_100
 * @tc.desc: Verify QueryData with string value returns E_OK when all query operations succeed and
 *           data is retrieved for a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrTest, QueryData_Str_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::string value;
    int32_t nonSystemUserId = 100;

    SetMockQueryResults({mockResultSet});
    ret = rdbMgr.QueryData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: QueryData_Blob_100
 * @tc.desc: Verify QueryData with blob value returns E_OK when all query operations succeed and
 *           binary data is retrieved.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrTest, QueryData_Blob_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::vector<uint8_t> value;
    int32_t nonSystemUserId = 100;

    SetMockQueryResults({mockResultSet});
    ret = rdbMgr.QueryData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: QueryDataBeginWithKey_100
 * @tc.desc: Verify QueryDataBeginWithKey returns E_OK when result set contains matching key-value pairs and
 *           iteration succeeds.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrTest, QueryDataBeginWithKey_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;

    SetMockQueryResults({mockResultSet});
    ret = rdbMgr.QueryDataBeginWithKey(key, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: QueryDataContainsWithKey_100
 * @tc.desc: Verify QueryDataContainsWithKey returns E_OK when result set contains matching records and iteration
 *           succeeds.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrTest, QueryDataContainsWithKey_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;

    SetMockQueryResults({mockResultSet});
    ret = rdbMgr.QueryDataContainsWithKey(key, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: QueryAllData_100
 * @tc.desc: Verify QueryAllData returns E_OK when all records are successfully retrieved and populated into
 *           result map.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrTest, QueryAllData_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;

    SetMockQueryResults({mockResultSet});
    ret = rdbMgr.QueryAllData(values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}
} // OHOS::Notification::Infra