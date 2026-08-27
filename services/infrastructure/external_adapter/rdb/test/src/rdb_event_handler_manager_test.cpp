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
#include "rdb_event_handler_manager.h"
#include "mock_abs_shared_result_set.h"
#include "mock_rdb_event_handler.h"
#include "mock_rdb_store.h"

using namespace testing::ext;

namespace OHOS::Notification::Infra {
class RdbEventHandlerManagerTest : public ::testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: RegisterHandler_100
 * @tc.desc: Verify RegisterHandler returns false when attempting to register a null handler, preventing invalid handler
 *           registration.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(RdbEventHandlerManagerTest, RegisterHandler_100, TestSize.Level1)
{
    RdbEventHandlerManager mgr;
    auto handler = nullptr;
    bool ret = mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_CREATE, handler);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: RegisterHandler_200
 * @tc.desc: Verify RegisterHandler returns true when a valid handler is registered successfully and can be retrieved
 *           via IsHandlerRegistered.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(RdbEventHandlerManagerTest, RegisterHandler_200, TestSize.Level1)
{
    RdbEventHandlerManager mgr;
    auto handler = std::make_shared<MockRdbEventHandler>("handler1");
    bool ret = mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_CREATE, handler);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: RegisterHandler_300
 * @tc.desc: Verify RegisterHandler returns false on duplicate registration attempts, ensuring single handler per
 *           event type constraint.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(RdbEventHandlerManagerTest, RegisterHandler_300, TestSize.Level1)
{
    RdbEventHandlerManager mgr;
    auto handler = std::make_shared<MockRdbEventHandler>("handler1");
    EXPECT_TRUE(mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_CREATE, handler));
    // Duplicate registration should fail
    EXPECT_FALSE(mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_CREATE, handler));
}

/**
 * @tc.name: UnregisterHandler_100
 * @tc.desc: Verify UnregisterHandler returns true and the handler is successfully removed, confirmed by
 *           IsHandlerRegistered returning false.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(RdbEventHandlerManagerTest, UnregisterHandler_100, TestSize.Level1)
{
    RdbEventHandlerManager mgr;
    auto handler = std::make_shared<MockRdbEventHandler>("handler1");
    mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_CREATE, handler);
    EXPECT_TRUE(mgr.UnregisterHandler("handler1"));
}

/**
 * @tc.name: UnregisterHandler_200
 * @tc.desc: Verify UnregisterHandler returns false when attempting to unregister a non-existent handler,
 *           gracefully handling missing handlers.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(RdbEventHandlerManagerTest, UnregisterHandler_200, TestSize.Level1)
{
    RdbEventHandlerManager mgr;
    EXPECT_FALSE(mgr.UnregisterHandler("not_exist"));
}

/**
 * @tc.name: ExecuteOnCreate_100
 * @tc.desc: Verify ExecuteOnCreate returns 0 when all registered handlers for the ON_CREATE event succeed in execution.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(RdbEventHandlerManagerTest, ExecuteOnCreate_100, TestSize.Level1)
{
    RdbEventHandlerManager mgr;
    auto handler1 = std::make_shared<MockRdbEventHandler>("h1", 0);
    auto handler2 = std::make_shared<MockRdbEventHandler>("h2", 0);
    mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_CREATE, handler1);
    mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_CREATE, handler2);
    MockRdbStore store;
    EXPECT_EQ(mgr.ExecuteOnCreate(store), 0);
}

/**
 * @tc.name: ExecuteOnCreate_200
 * @tc.desc: Verify ExecuteOnCreate returns failure code (-1) when one of multiple handlers fails, demonstrating
 *           fail-fast behavior.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(RdbEventHandlerManagerTest, ExecuteOnCreate_200, TestSize.Level1)
{
    RdbEventHandlerManager mgr;
    auto handler1 = std::make_shared<MockRdbEventHandler>("h1", 0);
    auto handler2 = std::make_shared<MockRdbEventHandler>("h2", -1);
    mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_CREATE, handler1);
    mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_CREATE, handler2);
    MockRdbStore store;
    EXPECT_EQ(mgr.ExecuteOnCreate(store), -1);
}

/**
 * @tc.name: ExecuteOnCreate_300
 * @tc.desc: Verify ExecuteOnCreate returns success when skipping disabled handlers and executing only enabled ones.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(RdbEventHandlerManagerTest, ExecuteOnCreate_300, TestSize.Level1)
{
    RdbEventHandlerManager mgr;
    auto handler1 = std::make_shared<MockRdbEventHandler>("h1", -1, false);
    auto handler2 = std::make_shared<MockRdbEventHandler>("h2", 0);
    mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_CREATE, handler1);
    mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_CREATE, handler2);
    MockRdbStore store;
    EXPECT_EQ(mgr.ExecuteOnCreate(store), 0);
}

/**
 * @tc.name: ExecuteAllEvents_100
 * @tc.desc: Verify ExecuteOnUpgrade, ExecuteOnDowngrade, ExecuteOnOpen, and ExecuteOnCorruption all
 *           return 0 when handlers with unique names succeed for each RDB lifecycle event.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(RdbEventHandlerManagerTest, ExecuteAllEvents_100, TestSize.Level1)
{
    RdbEventHandlerManager mgr;
    auto handler1 = std::make_shared<MockRdbEventHandler>("h1", 0);
    auto handler2 = std::make_shared<MockRdbEventHandler>("h2", 0);
    auto handler3 = std::make_shared<MockRdbEventHandler>("h3", 0);
    auto handler4 = std::make_shared<MockRdbEventHandler>("h4", 0);
    EXPECT_TRUE(mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_UPGRADE, handler1));
    EXPECT_TRUE(mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_DOWNGRADE, handler2));
    EXPECT_TRUE(mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_OPEN, handler3));
    EXPECT_TRUE(mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_CORRUPTION, handler4));
    MockRdbStore store;
    EXPECT_EQ(mgr.ExecuteOnUpgrade(store, 1, 2), 0);
    EXPECT_EQ(mgr.ExecuteOnDowngrade(store, 2, 1), 0);
    EXPECT_EQ(mgr.ExecuteOnOpen(store), 0);
    EXPECT_EQ(mgr.ExecuteOnCorruption("file.db"), 0);
}

/**
 * @tc.name: RegisterHandler_400
 * @tc.desc: Verify RegisterHandler returns true when registering handlers with different names for different event
 *           types, covering the IsHandlerRegistered not-found branch that continues the search loop across a
 *           non-empty eventHandlers_ map.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(RdbEventHandlerManagerTest, RegisterHandler_400, TestSize.Level1)
{
    RdbEventHandlerManager mgr;
    auto handler1 = std::make_shared<MockRdbEventHandler>("h1", 0);
    auto handler2 = std::make_shared<MockRdbEventHandler>("h2", 0);
    EXPECT_TRUE(mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_CREATE, handler1));
    EXPECT_TRUE(mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_UPGRADE, handler2));
}

/**
 * @tc.name: UnregisterHandler_300
 * @tc.desc: Verify UnregisterHandler returns false when unregistering a non-existent handler from a non-empty
 *           registry, covering the not-found branch that continues the search loop across registered event lists.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(RdbEventHandlerManagerTest, UnregisterHandler_300, TestSize.Level1)
{
    RdbEventHandlerManager mgr;
    auto handler = std::make_shared<MockRdbEventHandler>("h1", 0);
    EXPECT_TRUE(mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_CREATE, handler));
    EXPECT_FALSE(mgr.UnregisterHandler("not_exist"));
}

/**
 * @tc.name: ExecuteOnCreate_400
 * @tc.desc: Verify ExecuteOnCreate returns 0 when no handlers are registered for the ON_CREATE event type,
 *           covering the event-not-found early-return path in ExecuteHandlerList.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(RdbEventHandlerManagerTest, ExecuteOnCreate_400, TestSize.Level1)
{
    RdbEventHandlerManager mgr;
    MockRdbStore store;
    EXPECT_EQ(mgr.ExecuteOnCreate(store), 0);
}

/**
 * @tc.name: ExecuteOnUpgradeWithCrashRecovery_100
 * @tc.desc: Verify first crash-interruption only retries; cleanup happens on second interruption.
 * @tc.type: FUNC
 */
HWTEST_F(RdbEventHandlerManagerTest, ExecuteOnUpgradeWithCrashRecovery_100, TestSize.Level1)
{
    RdbEventHandlerManager mgr;
    auto crashedOnce = std::make_shared<MockRdbEventHandler>("crashed_once_h", 0);
    crashedOnce->SetMigrationMarkKey("upgrade_migration_mark_crashed_once");
    mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_UPGRADE, crashedOnce);
    MockRdbStore store;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    // Mark read: residual count "1" < threshold → no cleanup
    SetMockQueryResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"1"}, {NativeRdb::E_OK});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockDeleteErrCodes({NativeRdb::E_OK});
    int32_t ret = mgr.ExecuteOnUpgradeWithCrashRecovery(store, 1, 2);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ(crashedOnce->GetUpgradeFailureCallCount(), 0);
}

/**
 * @tc.name: ExecuteOnUpgradeWithCrashRecovery_200
 * @tc.desc: Verify cleanup runs when residual crash count reaches threshold (2).
 * @tc.type: FUNC
 */
HWTEST_F(RdbEventHandlerManagerTest, ExecuteOnUpgradeWithCrashRecovery_200, TestSize.Level1)
{
    RdbEventHandlerManager mgr;
    auto crashedTwice = std::make_shared<MockRdbEventHandler>("crashed_twice_h", 0);
    crashedTwice->SetMigrationMarkKey("upgrade_migration_mark_crashed_twice");
    auto healthy = std::make_shared<MockRdbEventHandler>("healthy_h", 0);
    healthy->SetMigrationMarkKey("upgrade_migration_mark_healthy");
    mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_UPGRADE, crashedTwice);
    mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_UPGRADE, healthy);
    MockRdbStore store;
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    // Mark reads: crashed_twice "2" ≥ threshold → cleanup; healthy no row → no cleanup
    SetMockQueryResults({mockResultSet, nullptr});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK, NativeRdb::E_ERROR});
    SetMockGetStringValuesAndErrCodes({"2"}, {NativeRdb::E_OK});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_OK, NativeRdb::E_OK,
        NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockDeleteErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    int32_t ret = mgr.ExecuteOnUpgradeWithCrashRecovery(store, 1, 2);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ(crashedTwice->GetUpgradeFailureCallCount(), 1);
    EXPECT_EQ(healthy->GetUpgradeFailureCallCount(), 0);
}

/**
 * @tc.name: ExecuteOnUpgradeWithCrashRecovery_300
 * @tc.desc: Verify no short-circuit: a failing handler does not block subsequent handlers.
 * @tc.type: FUNC
 */
HWTEST_F(RdbEventHandlerManagerTest, ExecuteOnUpgradeWithCrashRecovery_300, TestSize.Level1)
{
    RdbEventHandlerManager mgr;
    auto failing = std::make_shared<MockRdbEventHandler>("failing_h", -1);
    failing->SetMigrationMarkKey("upgrade_migration_mark_failing");
    auto healthy = std::make_shared<MockRdbEventHandler>("healthy_h", 0);
    healthy->SetMigrationMarkKey("upgrade_migration_mark_healthy");
    mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_UPGRADE, failing);
    mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_UPGRADE, healthy);
    MockRdbStore store;
    SetMockQueryResults({nullptr, nullptr});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_OK, NativeRdb::E_OK,
        NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockDeleteErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    int32_t ret = mgr.ExecuteOnUpgradeWithCrashRecovery(store, 1, 2);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: ExecuteOnUpgradeWithCrashRecovery_400
 * @tc.desc: Verify handler with empty mark key skips crash recovery and runs directly.
 * @tc.type: FUNC
 */
HWTEST_F(RdbEventHandlerManagerTest, ExecuteOnUpgradeWithCrashRecovery_400, TestSize.Level1)
{
    RdbEventHandlerManager mgr;
    auto optOut = std::make_shared<MockRdbEventHandler>("opt_out_h", 0);
    mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_UPGRADE, optOut);
    MockRdbStore store;
    int32_t ret = mgr.ExecuteOnUpgradeWithCrashRecovery(store, 1, 2);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ(optOut->GetUpgradeFailureCallCount(), 0);
}

/**
 * @tc.name: ExecuteOnUpgradeWithCrashRecovery_500
 * @tc.desc: Verify business failure keeps data: no cleanup runs and mark is cleared.
 * @tc.type: FUNC
 */
HWTEST_F(RdbEventHandlerManagerTest, ExecuteOnUpgradeWithCrashRecovery_500, TestSize.Level1)
{
    RdbEventHandlerManager mgr;
    auto failing = std::make_shared<MockRdbEventHandler>("failing_h", -1);
    failing->SetMigrationMarkKey("upgrade_migration_mark_failing");
    mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_UPGRADE, failing);
    MockRdbStore store;
    SetMockQueryResults({nullptr});
    SetMockInsertWithConflictResolutionErrCodes({NativeRdb::E_OK});
    SetMockDeleteErrCodes({NativeRdb::E_OK});
    int32_t ret = mgr.ExecuteOnUpgradeWithCrashRecovery(store, 1, 2);
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(failing->GetUpgradeFailureCallCount(), 0);
}
} // namespace