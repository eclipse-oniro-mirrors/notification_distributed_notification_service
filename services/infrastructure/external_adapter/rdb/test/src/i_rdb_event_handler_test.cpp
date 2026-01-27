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
#include "i_rdb_event_handler.h"
#include "mock_rdb_store.h"

using namespace testing::ext;

namespace OHOS::Notification::Infra {
class IRdbEventHandlerTest : public ::testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

class MockIRdbEventHandler : public IRdbEventHandler {
public:
    std::string GetHandlerName() const override
    {
        return "MockHandler";
    }
};
/**
 * @tc.name: OnCreate_100
 * @tc.desc: Verify IRdbEventHandler base class OnCreate returns E_OK as the default implementation.
 * @tc.type: FUNC
 */
HWTEST_F(IRdbEventHandlerTest, OnCreate_100, Function | SmallTest | Level1)
{
    MockIRdbEventHandler handler;
    MockRdbStore rdbStore;
    int32_t ret = handler.OnCreate(rdbStore);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnUpgrade_100
 * @tc.desc: Verify IRdbEventHandler base class OnUpgrade returns E_OK as the default implementation for schema version
 *           upgrades.
 * @tc.type: FUNC
 */
HWTEST_F(IRdbEventHandlerTest, OnUpgrade_100, Function | SmallTest | Level1)
{
    MockIRdbEventHandler handler;
    MockRdbStore rdbStore;
    int32_t ret = handler.OnUpgrade(rdbStore, 1, 2);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnDowngrade_100
 * @tc.desc: Verify IRdbEventHandler base class OnDowngrade returns E_OK as the default implementation for schema
 *           version downgrades.
 * @tc.type: FUNC
 */
HWTEST_F(IRdbEventHandlerTest, OnDowngrade_100, Function | SmallTest | Level1)
{
    MockIRdbEventHandler handler;
    MockRdbStore rdbStore;
    int32_t ret = handler.OnDowngrade(rdbStore, 2, 1);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnOpen_100
 * @tc.desc: Verify IRdbEventHandler base class OnOpen returns E_OK as the default implementation for database opening.
 * @tc.type: FUNC
 */
HWTEST_F(IRdbEventHandlerTest, OnOpen_100, Function | SmallTest | Level1)
{
    MockIRdbEventHandler handler;
    MockRdbStore rdbStore;
    int32_t ret = handler.OnOpen(rdbStore);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnCorruption_100
 * @tc.desc: Verify IRdbEventHandler base class OnCorruption returns E_OK as the default implementation for database
 *           corruption recovery.
 * @tc.type: FUNC
 */
HWTEST_F(IRdbEventHandlerTest, OnCorruption_100, Function | SmallTest | Level1)
{
    MockIRdbEventHandler handler;
    std::string dbFile = "test.db";
    int32_t ret = handler.OnCorruption(dbFile);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: IsEnabled_100
 * @tc.desc: Verify IRdbEventHandler base class IsEnabled returns true by default, indicating handlers are disabled
 *           initially.
 * @tc.type: FUNC
 */
HWTEST_F(IRdbEventHandlerTest, IsEnabled_100, Function | SmallTest | Level1)
{
    MockIRdbEventHandler handler;
    EXPECT_TRUE(handler.IsEnabled());
}

/**
 * @tc.name: SetEnabled_100
 * @tc.desc: Verify SetEnabled correctly toggles handler state between enabled and disabled, confirmed by IsEnabled
 *           returning the set value.
 * @tc.type: FUNC
 */
HWTEST_F(IRdbEventHandlerTest, SetEnabled_100, Function | SmallTest | Level1)
{
    MockIRdbEventHandler handler;
    handler.SetEnabled(true);
    EXPECT_TRUE(handler.IsEnabled());
    handler.SetEnabled(false);
    EXPECT_FALSE(handler.IsEnabled());
}
} // namespace OHOS::Notification::Infra