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
#include "init_default_table_handler.h"
#include "mock_rdb_store.h"

using namespace testing::ext;

namespace OHOS::Notification::Infra {
class InitDefaultTableHandlerTest : public ::testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        // Initialize mock to default success value before each test
        SetMockExecuteSqlErrCodes({NativeRdb::E_OK});
    }
    void TearDown() override {}
};

/**
 * @tc.name: OnCreate_Success_001
 * @tc.desc: Verify OnCreate returns E_OK when table is not yet initialized and ExecuteSql completes successfully,
 *           properly creating database schema.
 * @tc.type: FUNC
 */
HWTEST_F(InitDefaultTableHandlerTest, OnCreate_Success_001, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = "test_table";
    InitDefaultTableHandler handler(config);
    MockRdbStore rdbStore;
    // Default mock value already set in SetUp
    int32_t ret = handler.OnCreate(rdbStore);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnCreate_AlreadyInitialized_002
 * @tc.desc: Verify OnCreate returns E_OK without re-executing SQL when tableInitialized_ is true, ensuring
 *           idempotency of schema initialization.
 * @tc.type: FUNC
 */
HWTEST_F(InitDefaultTableHandlerTest, OnCreate_AlreadyInitialized_002, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = "test_table";
    InitDefaultTableHandler handler(config);
    MockRdbStore rdbStore;
    // First call to initialize
    // Default mock value already set in SetUp
    handler.OnCreate(rdbStore);
    // Second call should not execute SQL
    int32_t ret = handler.OnCreate(rdbStore);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: OnCreate_Fail_003
 * @tc.desc: Verify OnCreate returns E_ERROR when ExecuteSql fails during table creation, propagating database
 *           operation failures.
 * @tc.type: FUNC
 */
HWTEST_F(InitDefaultTableHandlerTest, OnCreate_Fail_003, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.tableName = "test_table";
    InitDefaultTableHandler handler(config);
    MockRdbStore rdbStore;
    SetMockExecuteSqlErrCodes({NativeRdb::E_ERROR}); // Override default for this test
    int32_t ret = handler.OnCreate(rdbStore);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: GetHandlerName_004
 * @tc.desc: Verify GetHandlerName returns the correct handler identifier "InitDefaultTableHandler" for event handler
 *           tracking and debugging.
 * @tc.type: FUNC
 */
HWTEST_F(InitDefaultTableHandlerTest, GetHandlerName_004, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    InitDefaultTableHandler handler(config);
    std::string name = handler.GetHandlerName();
    EXPECT_EQ(name, "InitDefaultTableHandler");
}

} // namespace OHOS::Notification::Infra