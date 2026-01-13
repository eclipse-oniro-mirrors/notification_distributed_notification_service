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
} // namespace OHOS::Notification::Infra