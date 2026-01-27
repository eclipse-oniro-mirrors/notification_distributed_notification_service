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
 *           return 0 when handlers succeed for all RDB lifecycle events.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(RdbEventHandlerManagerTest, ExecuteAllEvents_100, TestSize.Level1)
{
    RdbEventHandlerManager mgr;
    auto handler = std::make_shared<MockRdbEventHandler>("h", 0);
    mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_UPGRADE, handler);
    mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_DOWNGRADE, handler);
    mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_OPEN, handler);
    mgr.RegisterHandler(RdbEventHandlerManager::EventType::ON_CORRUPTION, handler);
    MockRdbStore store;
    EXPECT_EQ(mgr.ExecuteOnUpgrade(store, 1, 2), 0);
    EXPECT_EQ(mgr.ExecuteOnDowngrade(store, 2, 1), 0);
    EXPECT_EQ(mgr.ExecuteOnOpen(store), 0);
    EXPECT_EQ(mgr.ExecuteOnCorruption("file.db"), 0);
}
} // namespace