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

class NotificationRdbMgrStatisticsTest : public ::testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override;
    void TearDown() override;
};

void NotificationRdbMgrStatisticsTest::SetUp()
{
    // Reset mock error code before each test
    ResetMockRdbHelper();
    ResetMockAbsSharedResultSet();
    ResetMockRdbStore();
}

void NotificationRdbMgrStatisticsTest::TearDown()
{
    // Reset mock error code after each test
    ResetMockRdbHelper();
    ResetMockAbsSharedResultSet();
    ResetMockRdbStore();
}

/**
 * @tc.name: CleanStatisticsExperData_100
 * @tc.desc: Verify CleanStatisticsExperData returns E_OK
 *
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrStatisticsTest, CleanStatisticsExperData_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    SetMockQueryResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});

    ret = rdbMgr.CleanStatisticsExperData(nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: DeleteStatisticsByBundle_100
 * @tc.desc: Verify DeleteStatisticsByBundle returns E_OK
 *
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrStatisticsTest, DeleteStatisticsByBundle_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    SetMockDeleteRdbStoreErrCodes({NativeRdb::E_OK});

    ret = rdbMgr.DeleteStatisticsByBundle(nonSystemUserId, "bundleName", 20010044);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: CleanStatisticsExperDataTimer_100
 * @tc.desc: Verify CleanStatisticsExperDataTimer returns E_OK
 *
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrStatisticsTest, CleanStatisticsExperDataTimer_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    SetMockDeleteRdbStoreErrCodes({NativeRdb::E_OK});

    ret = rdbMgr.CleanStatisticsExperDataTimer({nonSystemUserId});
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: InsertStatisticsData_100
 * @tc.desc: Verify InsertStatisticsData returns E_OK
 *
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrStatisticsTest, InsertStatisticsData_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    StatisticsWrapperInfo info{0, "", 0, "1"};
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_OK});

    ret = rdbMgr.InsertStatisticsData(nonSystemUserId, info);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: QueryStatisticsByBundle_100
 * @tc.desc: Verify QueryStatisticsByBundle returns E_OK
 *
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrStatisticsTest, QueryStatisticsByBundle_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    int32_t uid = 20010044;
    int32_t totalCount = 0;
    int64_t lastTime = 0;
    int64_t beginTime = 1767196800000;
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});

    ret = rdbMgr.QueryStatisticsByBundle(uid, nonSystemUserId, beginTime, totalCount, lastTime);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: UpdateStatisticsTime_100
 * @tc.desc: Verify UpdateStatisticsTime returns E_OK
 *
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrStatisticsTest, UpdateStatisticsTime_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    int32_t uid = 20010044;
    int32_t totalCount = 0;
    int64_t lastTime = 0;
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});

    ret = rdbMgr.UpdateStatisticsTime(nonSystemUserId, 1);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: DropStatisticsTable_100
 * @tc.desc: Verify DropStatisticsTable returns E_OK
 *
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRdbMgrStatisticsTest, DropStatisticsTable_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NotificationRdbMgr rdbMgr(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});

    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR}); // Only one row
    int32_t ret = rdbMgr.Init();
    EXPECT_EQ(ret, NativeRdb::E_OK);

    int32_t nonSystemUserId = 100;
    SetMockExecuteSqlErrCodes({NativeRdb::E_OK});

    ret = rdbMgr.DropStatisticsTable(nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

} // OHOS::Notification::Infra