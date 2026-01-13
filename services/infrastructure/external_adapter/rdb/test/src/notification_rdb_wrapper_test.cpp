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
#include "rdb_store_wrapper.h"
#include "mock_rdb_helper.h"
#include "mock_rdb_store.h"
#include "mock_abs_shared_result_set.h"

using namespace testing::ext;

namespace OHOS::Notification::Infra {

class NtfRdbStoreWrapperTest : public ::testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override;
    void TearDown() override;
};

void NtfRdbStoreWrapperTest::SetUp()
{
    // Reset mock error code before each test
    ResetMockRdbHelper();
    ResetMockAbsSharedResultSet();
    ResetMockRdbStore();
}

void NtfRdbStoreWrapperTest::TearDown()
{
    // Reset mock error code after each test
    ResetMockRdbHelper();
    ResetMockAbsSharedResultSet();
    ResetMockRdbStore();
}

/**
 * @tc.name: Init_100
 * @tc.desc: Verify Init returns E_ERROR when RdbHelper::GetRdbHelper fails with SQLITE_CORRUPT error and rdbStore_
 *           remains null.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, Init_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    // Set mock to simulate RdbHelper::GetRdbHelper failure
    SetMockGetRdbHelperErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: Init_200
 * @tc.desc: Verify Init returns NativeRdb::E_ERROR when RdbHelper::GetRdbHelper succeeds and rdbStore_ is
 *           properly initialized but Init table failed.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, Init_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    int32_t ret = rdbWrapper.Init();

    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: Init_300
 * @tc.desc: Verify Init is idempotent by invoking it twice and confirming E_OK is returned both times without side
 *           effects.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, Init_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: Init_400
 * @tc.desc: Verify Init returns E_EMPTY_VALUES_BUCKET when QuerySql returns an empty result set with no rows.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, Init_400, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    // Simulate QuerySql returning empty result set
    SetMockGoToFirstRowErrCodes({NativeRdb::E_EMPTY_VALUES_BUCKET});
    auto ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_EMPTY_VALUES_BUCKET);
}

/**
 * @tc.name: Init_500
 * @tc.desc: Verify Init returns E_ERROR when result set exists but GetString operation fails on retrieving column
 *           values.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, Init_500, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    // Simulate QuerySql returning result set but GetString fails
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_ERROR});
    auto ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: Init_600
 * @tc.desc: Verify Init returns E_OK when QuerySql returns result set and all column operations succeed with data
 *           retrieval.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, Init_600, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    auto ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: Destroy_100
 * @tc.desc: Verify Destroy returns E_ERROR when rdbStore_ is null due to initialization failure.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, Destroy_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);

    ret = rdbWrapper.Destroy();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: Destroy_200
 * @tc.desc: Verify Destroy returns E_ERROR when DeleteRdbStore operation fails even after successful initialization.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, Destroy_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    SetMockDeleteRdbStoreErrCodes({NativeRdb::E_ERROR});
    ret = rdbWrapper.Destroy();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: Destroy_300
 * @tc.desc: Verify Destroy returns E_OK when rdbStore_ is successfully deleted after successful initialization.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, Destroy_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    ret = rdbWrapper.Destroy();
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: InsertData_Str_100
 * @tc.desc: Verify InsertData with string value returns E_ERROR when rdbStore_ is null for a non-system user
 *           (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, InsertData_Str_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);

    std::string key = "key";
    std::string value = "value";
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.InsertData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: InsertData_Str_200
 * @tc.desc: Verify InsertData with string value returns E_ERROR when ExecuteSql fails for a non-system user after
 *           initialization.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, InsertData_Str_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::string value = "value";
    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_ERROR});
    ret = rdbWrapper.InsertData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: InsertData_Str_300
 * @tc.desc: Verify InsertData with string value returns E_ERROR when InsertWithConflictResolution fails due to
 *           SQLITE_CORRUPT for a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, InsertData_Str_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::string value = "value";
    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    SetMockReStoreErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    ret = rdbWrapper.InsertData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: InsertData_Str_400
 * @tc.desc: Verify InsertData with string value returns E_OK when all operations succeed for a non-system user
 *           (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, InsertData_Str_400, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::string value = "value";
    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_OK});
    ret = rdbWrapper.InsertData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: InsertData_Blob_100
 * @tc.desc: Verify InsertData with blob value returns E_ERROR when rdbStore_ is null for a non-system user
 *           (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, InsertData_Blob_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);

    std::string key = "key";
    std::vector<uint8_t> value = { 'v', 'a', 'l', 'u', 'e' };
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.InsertData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: InsertData_Blob_200
 * @tc.desc: Verify InsertData with blob value returns E_ERROR when ExecuteSql fails for a non-system user after
 *           initialization.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, InsertData_Blob_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::vector<uint8_t> value = { 'v', 'a', 'l', 'u', 'e' };
    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_ERROR});
    ret = rdbWrapper.InsertData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: InsertData_Blob_300
 * @tc.desc: Verify InsertData with blob value returns E_ERROR when InsertWithConflictResolution fails due to
 *           SQLITE_CORRUPT for a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, InsertData_Blob_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::vector<uint8_t> value = { 'v', 'a', 'l', 'u', 'e' };
    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    SetMockReStoreErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    ret = rdbWrapper.InsertData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: InsertData_Blob_400
 * @tc.desc: Verify InsertData with blob value returns E_OK when all operations succeed for a non-system user
 *           (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, InsertData_Blob_400, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::vector<uint8_t> value = { 'v', 'a', 'l', 'u', 'e' };
    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_OK});
    ret = rdbWrapper.InsertData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: InsertData_Batch_100
 * @tc.desc: Verify InsertData with batch map returns E_ERROR when rdbStore_ is null for a non-system user
 *           (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, InsertData_Batch_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);

    std::unordered_map<std::string, std::string> values = {
        { "key1", "value1" },
        { "key2", "value2" }
    };
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.InsertBatchData(values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: InsertData_Batch_200
 * @tc.desc: Verify InsertData with batch map returns E_ERROR when ExecuteSql fails for a non-system user after
 *           initialization.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, InsertData_Batch_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::unordered_map<std::string, std::string> values = {
        { "key1", "value1" },
        { "key2", "value2" }
    };
    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_ERROR});
    ret = rdbWrapper.InsertBatchData(values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: InsertData_Batch_300
 * @tc.desc: Verify InsertData with batch map returns E_ERROR when InsertWithConflictResolution fails due to
 *           SQLITE_CORRUPT for a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, InsertData_Batch_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::unordered_map<std::string, std::string> values = {
        { "key1", "value1" },
        { "key2", "value2" }
    };
    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});
    SetMockBatchInsertErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    SetMockReStoreErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    ret = rdbWrapper.InsertBatchData(values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: InsertData_Batch_400
 * @tc.desc: Verify InsertData with batch map returns E_OK when all operations succeed for a non-system user
 *           (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, InsertData_Batch_400, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::unordered_map<std::string, std::string> values = {
        { "key1", "value1" },
        { "key2", "value2" }
    };
    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});
    SetMockBatchInsertErrCodes({NativeRdb::E_OK});
    ret = rdbWrapper.InsertBatchData(values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: DeleteData_100
 * @tc.desc: Verify DeleteData returns E_ERROR when rdbStore_ is null due to initialization failure for a
 *           non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, DeleteData_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);

    std::string key = "key";
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.DeleteData(key, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: DeleteData_200
 * @tc.desc: Verify DeleteData returns E_ERROR when Delete operation fails for a non-system user after initialization.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, DeleteData_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    int32_t nonSystemUserId = 100;
    SetMockDeleteErrCodes({NativeRdb::E_ERROR});
    ret = rdbWrapper.DeleteData(key, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: DeleteData_300
 * @tc.desc: Verify DeleteData returns SQLITE_CORRUPT error code when Delete operation fails with SQLITE_CORRUPT
 *           for a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, DeleteData_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    int32_t nonSystemUserId = 100;
    SetMockDeleteErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    SetMockReStoreErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    ret = rdbWrapper.DeleteData(key, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: DeleteData_400
 * @tc.desc: Verify DeleteData returns E_OK when Delete operation succeeds for a non-system user (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, DeleteData_400, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    int32_t nonSystemUserId = 100;
    SetMockDeleteErrCodes({NativeRdb::E_OK});
    ret = rdbWrapper.DeleteData(key, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: DeleteBatchData_100
 * @tc.desc: Verify DeleteBatchData returns E_OK when keys vector is empty, providing idempotent delete behavior.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, DeleteBatchData_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::vector<std::string> keys = {};
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.DeleteBatchData(keys, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: DeleteBatchData_200
 * @tc.desc: Verify DeleteBatchData returns E_ERROR when rdbStore_ is null due to initialization failure for
 *           batch deletion.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, DeleteBatchData_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);

    std::vector<std::string> keys = { "key1", "key2" };
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.DeleteBatchData(keys, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: DeleteBatchData_300
 * @tc.desc: Verify DeleteBatchData returns E_ERROR when batch delete operation fails for multiple keys.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, DeleteBatchData_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::vector<std::string> keys = { "key1", "key2" };
    int32_t nonSystemUserId = 100;
    SetMockDeleteErrCodes({NativeRdb::E_ERROR});
    ret = rdbWrapper.DeleteBatchData(keys, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: DeleteBatchData_400
 * @tc.desc: Verify DeleteBatchData returns E_ERROR when batch delete operation fails due to SQLITE_CORRUPT for
 *           multiple keys.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, DeleteBatchData_400, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::vector<std::string> keys = { "key1", "key2" };
    int32_t nonSystemUserId = 100;
    SetMockDeleteErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    SetMockReStoreErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    ret = rdbWrapper.DeleteBatchData(keys, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: DeleteBatchData_500
 * @tc.desc: Verify DeleteBatchData returns E_OK when batch delete operation succeeds for multiple keys.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, DeleteBatchData_500, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::vector<std::string> keys = { "key1", "key2" };
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.DeleteBatchData(keys, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: DropUserTable_100
 * @tc.desc: Verify DropUserTable returns E_ERROR when rdbStore_ is null due to initialization failure for
 *           a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, DropUserTable_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);

    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.DropUserTable(nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: DropUserTable_200_Success
 * @tc.desc: Verify DropUserTable returns E_OK when drop table operation succeeds for a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, DropUserTable_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.DropUserTable(nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: DropUserTable_300_Fail
 * @tc.desc: Verify DropUserTable returns E_ERROR when ExecuteSql fails during table drop operation for a non-system
 *           user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, DropUserTable_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_ERROR});
    ret = rdbWrapper.DropUserTable(nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryData_Str_100
 * @tc.desc: Verify QueryData with string value returns E_ERROR when rdbStore_ is null for a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryData_Str_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);

    std::string key = "key";
    std::string value;
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.QueryData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryData_Str_200
 * @tc.desc: Verify QueryData with string value returns E_ERROR when Query operation fails after initialization for
 *           a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryData_Str_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::string value;
    int32_t nonSystemUserId = 100;

    ret = rdbWrapper.QueryData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryData_Str_300
 * @tc.desc: Verify QueryData with string value returns E_ERROR when GoToFirstRow fails on result set for
 *           a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryData_Str_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::string value;
    int32_t nonSystemUserId = 100;

    ret = rdbWrapper.QueryData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryData_Str_400
 * @tc.desc: Verify QueryData with string value returns SQLITE_CORRUPT when GoToFirstRow fails with database
 *           corruption for a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryData_Str_400, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::string value;
    int32_t nonSystemUserId = 100;

    SetMockGoToFirstRowErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    SetMockReStoreErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    ret = rdbWrapper.QueryData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryData_Str_500
 * @tc.desc: Verify QueryData with string value returns SQLITE_CORRUPT when GetString fails with database
 *           corruption during value retrieval.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryData_Str_500, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::string value;
    int32_t nonSystemUserId = 100;

    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_SQLITE_CORRUPT});
    SetMockReStoreErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    ret = rdbWrapper.QueryData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryData_Str_600
 * @tc.desc: Verify QueryData with string value returns E_OK when all query operations succeed and data is retrieved
 *           for a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryData_Str_600, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::string value;
    int32_t nonSystemUserId = 100;

    SetMockQueryResults({mockResultSet});
    ret = rdbWrapper.QueryData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: QueryData_Blob_100
 * @tc.desc: Verify QueryData with blob value returns E_ERROR when rdbStore_ is null for a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryData_Blob_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);

    std::string key = "key";
    std::vector<uint8_t> value;
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.QueryData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryData_Blob_200
 * @tc.desc: Verify QueryData with blob value returns E_ERROR when Query operation fails after initialization for a
 *           non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryData_Blob_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::vector<uint8_t> value;
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.QueryData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryData_Blob_300
 * @tc.desc: Verify QueryData with blob value returns E_ERROR when GoToFirstRow fails on result set for
 *           a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryData_Blob_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::vector<uint8_t> value;
    int32_t nonSystemUserId = 100;
    SetMockGoToFirstRowErrCodes({NativeRdb::E_ERROR});
    ret = rdbWrapper.QueryData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryData_Blob_400
 * @tc.desc: Verify QueryData with blob value returns SQLITE_CORRUPT when GoToFirstRow fails with database corruption.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryData_Blob_400, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::vector<uint8_t> value;
    int32_t nonSystemUserId = 100;
    SetMockGoToFirstRowErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    SetMockReStoreErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    ret = rdbWrapper.QueryData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryData_Blob_500
 * @tc.desc: Verify QueryData with blob value returns SQLITE_CORRUPT when GetBlob fails with database corruption during
 *           value retrieval.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryData_Blob_500, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::vector<uint8_t> value;
    int32_t nonSystemUserId = 100;

    SetMockGetBlobValuesAndErrCodes({{'b', 'l', 'o', 'b'}}, {NativeRdb::E_SQLITE_CORRUPT});
    SetMockReStoreErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    ret = rdbWrapper.QueryData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryData_Blob_600
 * @tc.desc: Verify QueryData with blob value returns E_OK when all query operations succeed and binary data is
 *           retrieved.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryData_Blob_600, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::vector<uint8_t> value;
    int32_t nonSystemUserId = 100;

    SetMockQueryResults({mockResultSet});
    ret = rdbWrapper.QueryData(key, value, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: QueryDataBeginWithKey_100
 * @tc.desc: Verify QueryDataBeginWithKey returns E_ERROR when rdbStore_ is null for a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryDataBeginWithKey_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);

    std::string key = "key";
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.QueryDataBeginWithKey(key, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryDataBeginWithKey_200
 * @tc.desc: Verify QueryDataBeginWithKey returns E_ERROR when Query operation fails to retrieve records matching
 *           prefix key.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryDataBeginWithKey_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.QueryDataBeginWithKey(key, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryDataBeginWithKey_300
 * @tc.desc: Verify QueryDataBeginWithKey returns E_ERROR when GoToFirstRow fails to position at first result row.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryDataBeginWithKey_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    SetMockGoToFirstRowErrCodes({NativeRdb::E_ERROR});
    ret = rdbWrapper.QueryDataBeginWithKey(key, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryDataBeginWithKey_400
 * @tc.desc: Verify QueryDataBeginWithKey returns E_ERROR when GoToFirstRow fails with database corruption preventing
 *           result retrieval.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryDataBeginWithKey_400, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;

    SetMockGoToFirstRowErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    SetMockReStoreErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    ret = rdbWrapper.QueryDataBeginWithKey(key, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryDataBeginWithKey_500
 * @tc.desc: Verify QueryDataBeginWithKey returns E_ERROR when GetString fails with database corruption during
 *           key-value retrieval.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryDataBeginWithKey_500, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_SQLITE_CORRUPT});
    SetMockReStoreErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    ret = rdbWrapper.QueryDataBeginWithKey(key, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryDataBeginWithKey_600
 * @tc.desc: Verify QueryDataBeginWithKey returns E_EMPTY_VALUES_BUCKET when no matching records found for prefix key.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryDataBeginWithKey_600, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;

    SetMockQueryResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_EMPTY_VALUES_BUCKET});
    ret = rdbWrapper.QueryDataBeginWithKey(key, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_EMPTY_VALUES_BUCKET);
}

/**
 * @tc.name: QueryDataBeginWithKey_700
 * @tc.desc: Verify QueryDataBeginWithKey returns E_OK when result set contains matching key-value pairs and iteration
 *           succeeds.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryDataBeginWithKey_700, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;

    SetMockQueryResults({mockResultSet});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    ret = rdbWrapper.QueryDataBeginWithKey(key, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: QueryDataContainsWithKey_100
 * @tc.desc: Verify QueryDataContainsWithKey returns E_ERROR when rdbStore_ is null for a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryDataContainsWithKey_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);

    std::string key = "key";
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.QueryDataContainsWithKey(key, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryDataContainsWithKey_200
 * @tc.desc: Verify QueryDataContainsWithKey returns E_ERROR when Query operation fails to find records containing
 *           key substring.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryDataContainsWithKey_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.QueryDataContainsWithKey(key, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryDataContainsWithKey_300
 * @tc.desc: Verify QueryDataContainsWithKey returns E_ERROR when GoToFirstRow fails to position at first matching
 *           result.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryDataContainsWithKey_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    SetMockGoToFirstRowErrCodes({NativeRdb::E_ERROR});
    ret = rdbWrapper.QueryDataContainsWithKey(key, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryDataContainsWithKey_400
 * @tc.desc: Verify QueryDataContainsWithKey returns E_ERROR when GoToFirstRow fails with database corruption
 *           preventing data access.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryDataContainsWithKey_400, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    SetMockGoToFirstRowErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    SetMockReStoreErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    ret = rdbWrapper.QueryDataContainsWithKey(key, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryDataContainsWithKey_500
 * @tc.desc: Verify QueryDataContainsWithKey returns E_ERROR when GetString fails with database corruption during
 *           value retrieval.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryDataContainsWithKey_500, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_SQLITE_CORRUPT});
    SetMockReStoreErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    ret = rdbWrapper.QueryDataContainsWithKey(key, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryDataContainsWithKey_600
 * @tc.desc: Verify QueryDataContainsWithKey returns E_EMPTY_VALUES_BUCKET when no records contain the key substring.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryDataContainsWithKey_600, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;

    SetMockQueryResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_EMPTY_VALUES_BUCKET});
    ret = rdbWrapper.QueryDataContainsWithKey(key, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_EMPTY_VALUES_BUCKET);
}

/**
 * @tc.name: QueryDataContainsWithKey_700
 * @tc.desc: Verify QueryDataContainsWithKey returns E_OK when result set contains matching records and iteration
 *           succeeds.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryDataContainsWithKey_700, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;

    SetMockQueryResults({mockResultSet});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    ret = rdbWrapper.QueryDataContainsWithKey(key, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: QueryAllData_100
 * @tc.desc: Verify QueryAllData returns E_ERROR when rdbStore_ is null for a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryAllData_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);

    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.QueryAllData(values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryAllData_200
 * @tc.desc: Verify QueryAllData returns E_ERROR when Query operation fails to retrieve all records from database.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryAllData_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.QueryAllData(values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryAllData_300
 * @tc.desc: Verify QueryAllData returns E_ERROR when GoToFirstRow fails to position at first record.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryAllData_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    SetMockGoToFirstRowErrCodes({NativeRdb::E_ERROR});
    ret = rdbWrapper.QueryAllData(values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryAllData_400
 * @tc.desc: Verify QueryAllData returns E_ERROR when GoToFirstRow fails with database corruption preventing data
 *           access.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryAllData_400, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    SetMockGoToFirstRowErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    SetMockReStoreErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    ret = rdbWrapper.QueryAllData(values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryAllData_500
 * @tc.desc: Verify QueryAllData returns E_ERROR when GetString fails with database corruption during key-value
 *           retrieval.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryAllData_500, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_SQLITE_CORRUPT});
    SetMockReStoreErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    ret = rdbWrapper.QueryAllData(values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryAllData_600
 * @tc.desc: Verify QueryAllData returns E_EMPTY_VALUES_BUCKET when database contains no records for a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryAllData_600, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;

    SetMockQueryResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_EMPTY_VALUES_BUCKET});
    ret = rdbWrapper.QueryAllData(values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_EMPTY_VALUES_BUCKET);
}

/**
 * @tc.name: QueryAllData_700
 * @tc.desc: Verify QueryAllData returns E_OK when all records are successfully retrieved and populated into
 *           result map.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperTest, QueryAllData_700, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    // Simulate QuerySql returning result set
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    std::string key = "key";
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;

    SetMockQueryResults({mockResultSet});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    ret = rdbWrapper.QueryAllData(values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}
} // OHOS::Notification::Infra