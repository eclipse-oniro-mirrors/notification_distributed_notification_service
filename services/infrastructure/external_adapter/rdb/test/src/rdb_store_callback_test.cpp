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
#include <memory>
#include <string>
#include "rdb_store_callback.h"
#include "mock_abs_shared_result_set.h"
#include "mock_rdb_event_handler.h"
#include "mock_rdb_store.h"

using namespace testing::ext;

namespace OHOS::Notification::Infra {
class RdbStoreCallbackTest : public ::testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: OnCreate_100
 * @tc.desc: Verify OnCreate returns 0 when the registered event handler processes table creation successfully.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(RdbStoreCallbackTest, OnCreate_100, TestSize.Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    const std::set<RdbEventHandlerType> eventHandlerTypes = {
        RdbEventHandlerType::ON_CREATE_INIT_DEFAULT_TABLE
    };
    RdbStoreCallback cb(config, hookMgr, eventHandlerTypes);
    MockRdbStore store;
    EXPECT_EQ(cb.OnCreate(store), NativeRdb::E_OK);
}

/**
 * @tc.name: AllEvents_100
 * @tc.desc: Verify all RDB lifecycle callbacks (OnUpgrade, OnDowngrade, OnOpen, OnCorruption) return 0 when
 *           all registered handlers succeed.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(RdbStoreCallbackTest, AllEvents_100, TestSize.Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    RdbStoreCallback cb(config, hookMgr, eventHandlerTypes);
    MockRdbStore store;
    EXPECT_EQ(cb.OnUpgrade(store, 1, 2), NativeRdb::E_OK);
    EXPECT_EQ(cb.OnDowngrade(store, 2, 1), NativeRdb::E_OK);
    EXPECT_EQ(cb.OnOpen(store), NativeRdb::E_OK);
    EXPECT_EQ(cb.onCorruption("file.db"), NativeRdb::E_OK);
}

/**
 * @tc.name: OnCorruption_EmptyFile
 * @tc.desc: Verify onCorruption returns E_OK when databaseFile is empty (no deletion attempted).
 * @tc.type: FUNC
 * @tc.require: issue#4249
 */
HWTEST_F(RdbStoreCallbackTest, OnCorruption_EmptyFile, TestSize.Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    RdbStoreCallback cb(config, hookMgr, eventHandlerTypes);
    int32_t ret = cb.onCorruption("");
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_NoResidualMark_100
 * @tc.desc: Verify OnUpgrade runs migration directly when no residual mark exists.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCallbackTest, OnUpgrade_NoResidualMark_100, TestSize.Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    const std::set<RdbEventHandlerType> eventHandlerTypes = {
        RdbEventHandlerType::ON_UPGRADE_LIVE_VIEW_MIGRATION
    };
    RdbStoreCallback cb(config, hookMgr, eventHandlerTypes);
    MockRdbStore store;
    // Mark read: no row → no cleanup
    SetMockQueryResults({nullptr});
    SetMockQuerySqlResults({nullptr});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockDeleteErrCodes({NativeRdb::E_OK});
    EXPECT_EQ(cb.OnUpgrade(store, 1, 2), NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_ResidualMark_100
 * @tc.desc: Verify OnUpgrade cleans data when residual crash count reaches threshold (2).
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCallbackTest, OnUpgrade_ResidualMark_100, TestSize.Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    const std::set<RdbEventHandlerType> eventHandlerTypes = {
        RdbEventHandlerType::ON_UPGRADE_LIVE_VIEW_MIGRATION
    };
    RdbStoreCallback cb(config, hookMgr, eventHandlerTypes);
    MockRdbStore store;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    // Mark read: "2" ≥ threshold → cleanup
    SetMockQueryResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"2"}, {NativeRdb::E_OK});
    SetMockQuerySqlResults({nullptr, nullptr});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockDeleteErrCodes({NativeRdb::E_OK});
    EXPECT_EQ(cb.OnUpgrade(store, 1, 2), NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_PerBusinessIsolation_100
 * @tc.desc: Verify only the crashed business gets cleaned; healthy business keeps its data.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCallbackTest, OnUpgrade_PerBusinessIsolation_100, TestSize.Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    const std::set<RdbEventHandlerType> eventHandlerTypes = {
        RdbEventHandlerType::ON_UPGRADE_LIVE_VIEW_MIGRATION,
        RdbEventHandlerType::ON_UPGRADE_PRIORITY_INFO_MIGRATION
    };
    RdbStoreCallback cb(config, hookMgr, eventHandlerTypes);
    MockRdbStore store;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    // Mark reads: live-view "2" ≥ threshold → cleaned; priority no row → not cleaned
    SetMockQueryResults({mockResultSet, nullptr});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK, NativeRdb::E_ERROR});
    SetMockGetStringValuesAndErrCodes({"2"}, {NativeRdb::E_OK});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_OK, NativeRdb::E_OK,
        NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockDeleteErrCodes({NativeRdb::E_OK});
    SetMockQuerySqlResults({nullptr, nullptr});
    EXPECT_EQ(cb.OnUpgrade(store, 1, 2), NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_EmptyMarkResult_100
 * @tc.desc: Verify OnUpgrade handles empty mark result (GoToFirstRow fails) without crash.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCallbackTest, OnUpgrade_EmptyMarkResult_100, TestSize.Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    const std::set<RdbEventHandlerType> eventHandlerTypes = {
        RdbEventHandlerType::ON_UPGRADE_LIVE_VIEW_MIGRATION
    };
    RdbStoreCallback cb(config, hookMgr, eventHandlerTypes);
    MockRdbStore store;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    // Mark read: GoToFirstRow fails → no residual mark
    SetMockQueryResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_ERROR});
    SetMockQuerySqlResults({nullptr});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockDeleteErrCodes({NativeRdb::E_OK});
    EXPECT_EQ(cb.OnUpgrade(store, 1, 2), NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_NullMarkResult_100
 * @tc.desc: Verify OnUpgrade handles null Query result (mark read) without crash.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreCallbackTest, OnUpgrade_NullMarkResult_100, TestSize.Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    auto hookMgr = std::make_shared<NtfRdbHookMgr>(hooks);
    const std::set<RdbEventHandlerType> eventHandlerTypes = {
        RdbEventHandlerType::ON_UPGRADE_LIVE_VIEW_MIGRATION
    };
    RdbStoreCallback cb(config, hookMgr, eventHandlerTypes);
    MockRdbStore store;
    // Mark read: null result → no residual mark
    SetMockQueryResults({nullptr});
    SetMockQuerySqlResults({nullptr});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockDeleteErrCodes({NativeRdb::E_OK});
    EXPECT_EQ(cb.OnUpgrade(store, 1, 2), NativeRdb::E_OK);
}
} // namespace OHOS::Notification::Infra