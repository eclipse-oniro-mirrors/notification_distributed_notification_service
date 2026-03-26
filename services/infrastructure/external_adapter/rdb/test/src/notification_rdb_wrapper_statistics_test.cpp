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

class NtfRdbStoreWrapperStatisticsTest : public ::testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override;
    void TearDown() override;
};

void NtfRdbStoreWrapperStatisticsTest::SetUp()
{
    // Reset mock error code before each test
    ResetMockRdbHelper();
    ResetMockAbsSharedResultSet();
    ResetMockRdbStore();
}

void NtfRdbStoreWrapperStatisticsTest::TearDown()
{
    // Reset mock error code after each test
    ResetMockRdbHelper();
    ResetMockAbsSharedResultSet();
    ResetMockRdbStore();
}

/**
 * @tc.name: InsertData_Statistics_100
 * @tc.desc: Verify InsertStatisticsData with Statistics value returns E_ERROR
 *           when rdbStore_ is null for a non-system user (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, InsertData_Statistics_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);

    StatisticsWrapperInfo info {0, "", 0, "1"};
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.InsertStatisticsData(nonSystemUserId, info);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: InsertData_Statistics_200
 * @tc.desc: Verify InsertStatisticsData with Statistics value returns E_ERROR
 *           when ExecuteSql fails for a non-system user after initialization.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, InsertData_Statistics_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    StatisticsWrapperInfo info {0, "", 0, "1"};
    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_ERROR});
    ret = rdbWrapper.InsertStatisticsData(nonSystemUserId, info);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: InsertData_Statistics_300
 * @tc.desc: Verify InsertData with Statistics value returns E_ERROR when InsertWithConflictResolution fails due to
 *           SQLITE_CORRUPT for a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, InsertData_Statistics_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    StatisticsWrapperInfo info {0, "", 0, "1"};
    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    SetMockReStoreErrCodes({NativeRdb::E_SQLITE_CORRUPT});

    ret = rdbWrapper.InsertStatisticsData(nonSystemUserId, info);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: InsertData_Statistics_400
 * @tc.desc: Verify InsertData with Statistics value returns E_OK when all operations succeed for a non-system user
 *           (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, InsertData_Statistics_400, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    StatisticsWrapperInfo info {0, "", 0, "1"};
    int32_t nonSystemUserId = 80;
    
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_OK});

    ret = rdbWrapper.InsertStatisticsData(nonSystemUserId, info);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: InsertData_Statistics_500
 * @tc.desc: Verify InsertData with Statistics value returns E_OK when all operations succeed for a non-system user
 *           (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, InsertData_Statistics_500, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    StatisticsWrapperInfo info {0, "", 0, "1"};
    int32_t nonSystemUserId = 100;
    
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_OK});

    ret = rdbWrapper.InsertStatisticsData(nonSystemUserId, info);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: CleanExperData_Statistics_100
 * @tc.desc: Verify CleanExperData return{ok}
 *
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, CleanExperData_Statistics_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_OK});
    SetMockGetIntValuesAndErrCodes({150001}, {NativeRdb::E_OK});
    ret = rdbWrapper.CleanExperData(nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: CleanExperData_Statistics_200
 * @tc.desc: Verify CleanExperData return{error} when rdbStore_ is null for a non-system user
 *           (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, CleanExperData_Statistics_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_ERROR});
    SetMockGoToNextRowErrCodes({NativeRdb::E_OK});
    SetMockGetIntValuesAndErrCodes({150001}, {NativeRdb::E_OK});

    ret = rdbWrapper.CleanExperData(nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: CleanExperData_Statistics_300
 * @tc.desc: Verify CleanExperData return{E_ERROR}
 *
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, CleanExperData_Statistics_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    SetMockRdbStoreResults({nullptr});
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);

    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.CleanExperData(nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: CleanExperData_Statistics_400
 * @tc.desc: Verify CleanExperData return{E_ERROR}
 *
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, CleanExperData_Statistics_400, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});
    SetMockQuerySqlResults({nullptr});
    ret = rdbWrapper.CleanExperData(nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: DeleteStatisticsByBundle_Statistics_100
 * @tc.desc: Verify DeleteStatisticsByBundle return{error}
 *
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, DeleteStatisticsByBundle_Statistics_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    SetMockDeleteRdbStoreErrCodes({NativeRdb::E_ERROR});

    ret = rdbWrapper.DeleteStatisticsByBundle(nonSystemUserId, "com.example.myapplication", 20010044);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: DeleteStatisticsByBundle_Statistics_200
 * @tc.desc: Verify DeleteStatisticsByBundle return{ok}
 *
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, DeleteStatisticsByBundle_Statistics_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    SetMockDeleteRdbStoreErrCodes({NativeRdb::E_OK});

    ret = rdbWrapper.DeleteStatisticsByBundle(nonSystemUserId, "com.example.myapplication", 20010044);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: DeleteStatisticsByBundle_Statistics_300
 * @tc.desc: Verify DeleteStatisticsByBundle return{error} when rdbStore_ is null for a non-system user
 *           (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, DeleteStatisticsByBundle_Statistics_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    SetMockDeleteErrCodes({NativeRdb::E_ERROR});

    ret = rdbWrapper.DeleteStatisticsByBundle(nonSystemUserId, "com.example.myapplication", 20010044);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: DeleteStatisticsByBundle_Statistics_400
 * @tc.desc: Verify DeleteStatisticsByBundle return{error} when rdbStore_ is null for a non-system user
 *           (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, DeleteStatisticsByBundle_Statistics_400, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    SetMockRdbStoreResults({nullptr});
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);

    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.DeleteStatisticsByBundle(nonSystemUserId, "com.example.myapplication", 20010044);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: CleanExperDataTimer_Statistics_100
 * @tc.desc: Verify CleanExperDataTimer delete return{error}
 *
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, CleanExperDataTimer_Statistics_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    SetMockDeleteRdbStoreErrCodes({NativeRdb::E_ERROR});

    ret = rdbWrapper.CleanExperDataTimer(std::vector<int>{nonSystemUserId});
    EXPECT_EQ(ret, NativeRdb::E_OK);
}


/**
 * @tc.name: CleanExperDataTimer_Statistics_200
 * @tc.desc: Verify CleanExperDataTimer delete return{ok}
 *
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, CleanExperDataTimer_Statistics_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    SetMockDeleteRdbStoreErrCodes({NativeRdb::E_OK});

    ret = rdbWrapper.CleanExperDataTimer(std::vector<int>{nonSystemUserId});
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: CleanExperDataTimer_Statistics_300
 * @tc.desc: Verify CleanExperDataTimer return{error} when rdbStore_ is null for a non-system user
 *           (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, CleanExperDataTimer_Statistics_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);
    int32_t nonSystemUserId = 100;
    SetMockDeleteErrCodes({NativeRdb::E_ERROR});

    ret = rdbWrapper.CleanExperDataTimer(std::vector<int>{nonSystemUserId});
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: CleanExperDataTimer_Statistics_400
 * @tc.desc: Verify CleanExperDataTimer return{error} when rdbStore_ is null for a non-system user
 *           (userId 100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, CleanExperDataTimer_Statistics_400, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    SetMockRdbStoreResults({nullptr});
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);

    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.CleanExperDataTimer(std::vector<int>{nonSystemUserId});
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryStatisticsInfosByBundle_Statistics_100
 * @tc.desc: Verify QueryStatisticsInfosByBundle return{ok}
 *
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, QueryStatisticsInfosByBundle_Statistics_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    int32_t uid = 20010044;
    int32_t totalCount = 0;
    int64_t lastTime = 0;
    int64_t beginTime = 1767196800000;
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});

    ret = rdbWrapper.QueryStatisticsInfosByBundle(uid, nonSystemUserId, beginTime, totalCount, lastTime);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: QueryStatisticsInfosByBundle_Statistics_200
 * @tc.desc: Verify QueryStatisticsInfosByBundle return{error} when rdbStore_ is null due to initialization failure for
 *           a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, QueryStatisticsInfosByBundle_Statistics_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});

    int32_t nonSystemUserId = 100;
    int32_t uid = 20010044;
    int32_t totalCount = 0;
    int64_t lastTime = 0;
    int64_t beginTime = 1767196800000;
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    int32_t ret = rdbWrapper.QueryStatisticsInfosByBundle(uid, nonSystemUserId, beginTime, totalCount, lastTime);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: UpdateStatisticsTimeStamp_Statistics_100
 * @tc.desc: Verify UpdateStatisticsTimeStamp return{ok}
 *
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, UpdateStatisticsTimeStamp_Statistics_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});

    ret = rdbWrapper.UpdateStatisticsTimeStamp(nonSystemUserId, 1);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: UpdateStatisticsTimeStamp_Statistics_200
 * @tc.desc: Verify UpdateStatisticsTimeStamp return{error}
 *
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, UpdateStatisticsTimeStamp_Statistics_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);
    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_ERROR});
    ret = rdbWrapper.UpdateStatisticsTimeStamp(nonSystemUserId, 1);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: UpdateStatisticsTimeStamp_Statistics_300
 * @tc.desc: Verify UpdateStatisticsTimeStamp return{error} when rdbStore_ is null due to initialization failure for
 *           a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, UpdateStatisticsTimeStamp_Statistics_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    int32_t nonSystemUserId = 100;
    int32_t uid = 20010044;
    int32_t totalCount = 0;
    int64_t lastTime = 0;
    SetMockExecuteSqlErrCodes({NativeRdb::E_ERROR});
    int32_t ret = rdbWrapper.UpdateStatisticsTimeStamp(nonSystemUserId, 1);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: DropStatisticsTable_Statistics_100
 * @tc.desc: Verify DropStatisticsTable return{error} when rdbStore_ is null due to initialization failure for
 *           a non-system user.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, DropStatisticsTable_Statistics_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_ERROR});
    ret = rdbWrapper.DropStatisticsTable(nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: DropStatisticsTable_Statistics_200
 * @tc.desc: Verify DropStatisticsTable return { error }
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, DropStatisticsTable_Statistics_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});       // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);
    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_ERROR});
    ret = rdbWrapper.DropStatisticsTable(nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: DropStatisticsTable_Statistics_300
 * @tc.desc: Verify DropStatisticsTable return { ok }
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, DropStatisticsTable_Statistics_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});       // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);
    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});
    ret = rdbWrapper.DropStatisticsTable(nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: GetStatisticsInfos_100
 * @tc.desc: GetStatisticsInfos while QuerySql return is nullptr
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, GetStatisticsInfos_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});       // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    ResetMockAbsSharedResultSet();
    SetMockQuerySqlResults({nullptr});
    int32_t nonSystemUserId = 100;
    int32_t uid = 20010044;
    int32_t totalCount = 0;
    int64_t lastTime = 0;
    ret = rdbWrapper.GetStatisticsInfos(0, uid, "", totalCount, lastTime);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: GetStatisticsInfos_101
 * @tc.desc: GetStatisticsInfos while All return is E_OK
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, GetStatisticsInfos_101, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});       // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    ResetMockAbsSharedResultSet();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToNextRowErrCodes({NativeRdb::E_OK});
    SetMockGetColumnIndexValuesAndErrCodes({999, 999}, {NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGetIntValuesAndErrCodes({999}, {NativeRdb::E_OK});
    SetMockGetLongValuesAndErrCodes({999}, {NativeRdb::E_OK});
    int32_t nonSystemUserId = 100;
    int32_t uid = 20010044;
    int32_t totalCount = 0;
    int64_t lastTime = 0;
    ret = rdbWrapper.GetStatisticsInfos(0, uid, "", totalCount, lastTime);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: GetStatisticsInfos_102
 * @tc.desc: GetStatisticsInfos while GetInt & GetLong is E_ERROR
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, GetStatisticsInfos_102, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});       // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    ResetMockAbsSharedResultSet();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToNextRowErrCodes({NativeRdb::E_OK});
    SetMockGetColumnIndexValuesAndErrCodes({999, 999}, {NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGetIntValuesAndErrCodes({999}, {NativeRdb::E_ERROR});
    SetMockGetLongValuesAndErrCodes({999}, {NativeRdb::E_ERROR});
    int32_t nonSystemUserId = 100;
    int32_t uid = 20010044;
    int32_t totalCount = 0;
    int64_t lastTime = 0;
    ret = rdbWrapper.GetStatisticsInfos(0, uid, "", totalCount, lastTime);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: GetStatisticsInfos_103
 * @tc.desc: GetStatisticsInfos while GetColumnIndex return is E_ERROR;
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperStatisticsTest, GetStatisticsInfos_103, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = NOTIFICATION_STATISTICS_TABLENAME;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});       // Only one row
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    ResetMockAbsSharedResultSet();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToNextRowErrCodes({NativeRdb::E_OK});
    SetMockGetColumnIndexValuesAndErrCodes({999, 999}, {NativeRdb::E_ERROR, NativeRdb::E_ERROR});
    int32_t nonSystemUserId = 100;
    int32_t uid = 20010044;
    int32_t totalCount = 0;
    int64_t lastTime = 0;
    ret = rdbWrapper.GetStatisticsInfos(0, uid, "", totalCount, lastTime);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}
} // OHOS::Notification::Infra
