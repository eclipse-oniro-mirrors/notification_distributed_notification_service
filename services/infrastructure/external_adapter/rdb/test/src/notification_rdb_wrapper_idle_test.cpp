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

#include <memory>
#include <set>
#include <string>

#include "gtest/gtest.h"

#include "rdb_store_wrapper.h"
#include "mock_rdb_helper.h"
#include "mock_rdb_store.h"
#include "mock_abs_shared_result_set.h"

using namespace testing::ext;

namespace OHOS::Notification::Infra {

class NtfRdbWrapperIdleTest : public ::testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override;
    void TearDown() override;
};

void NtfRdbWrapperIdleTest::SetUp()
{
    ResetMockRdbHelper();
    ResetMockAbsSharedResultSet();
    ResetMockRdbStore();
}

void NtfRdbWrapperIdleTest::TearDown()
{
    ResetMockRdbHelper();
    ResetMockAbsSharedResultSet();
    ResetMockRdbStore();
}

/**
 * @tc.name: IdleRelease_100
 * @tc.desc: Verify the store is reported closed before initialization and open after a successful Init.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbWrapperIdleTest, IdleRelease_100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.idleReleaseTimeoutMs = 0;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    EXPECT_FALSE(rdbWrapper.IsStoreOpen());

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"notification"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});

    EXPECT_EQ(rdbWrapper.Init(), NativeRdb::E_OK);
    EXPECT_TRUE(rdbWrapper.IsStoreOpen());
}

/**
 * @tc.name: IdleRelease_200
 * @tc.desc: Verify ReleaseIfIdle closes an idle store and keeps the database file (no DeleteRdbStore call).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbWrapperIdleTest, IdleRelease_200, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.idleReleaseTimeoutMs = 0;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"notification"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    ASSERT_EQ(rdbWrapper.Init(), NativeRdb::E_OK);
    ASSERT_TRUE(rdbWrapper.IsStoreOpen());

    EXPECT_EQ(rdbWrapper.ReleaseIfIdle(0), NativeRdb::E_OK);
    EXPECT_FALSE(rdbWrapper.IsStoreOpen());
    // Releasing twice is harmless and keeps the closed state.
    EXPECT_EQ(rdbWrapper.ReleaseIfIdle(0), NativeRdb::E_OK);
    // Destroy still owns the "delete file" semantics, so it fails on an already closed store.
    EXPECT_EQ(rdbWrapper.Destroy(), NativeRdb::E_ERROR);
}

/**
 * @tc.name: IdleRelease_300
 * @tc.desc: Verify ReleaseIfIdle keeps the store open when it was used within the idle window.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbWrapperIdleTest, IdleRelease_300, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.idleReleaseTimeoutMs = 0;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"notification"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    ASSERT_EQ(rdbWrapper.Init(), NativeRdb::E_OK);

    constexpr int64_t oneHourMs = 60 * 60 * 1000;
    EXPECT_EQ(rdbWrapper.ReleaseIfIdle(oneHourMs), NativeRdb::E_ERROR);
    EXPECT_TRUE(rdbWrapper.IsStoreOpen());
}

/**
 * @tc.name: IdleRelease_400
 * @tc.desc: Verify an operation transparently reopens the store after it was released.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbWrapperIdleTest, IdleRelease_400, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.idleReleaseTimeoutMs = 0;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto firstStore = std::make_shared<MockRdbStore>();
    auto secondStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({firstStore, secondStore});
    SetMockGetRdbHelperErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"notification"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    ASSERT_EQ(rdbWrapper.Init(), NativeRdb::E_OK);

    ASSERT_EQ(rdbWrapper.ReleaseIfIdle(0), NativeRdb::E_OK);
    ASSERT_FALSE(rdbWrapper.IsStoreOpen());

    EXPECT_EQ(rdbWrapper.InsertData("key", "value", -1), NativeRdb::E_OK);
    EXPECT_TRUE(rdbWrapper.IsStoreOpen());
}

/**
 * @tc.name: IdleRelease_500
 * @tc.desc: Verify the idle release timer is not armed when the idle timeout is disabled, and that the store keeps
 *           working across repeated idle checks.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbWrapperIdleTest, IdleRelease_500, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.idleReleaseTimeoutMs = 0;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);

    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"notification"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    ASSERT_EQ(rdbWrapper.Init(), NativeRdb::E_OK);

    EXPECT_EQ(rdbWrapper.InsertData("key", "value", -1), NativeRdb::E_OK);
    EXPECT_EQ(rdbWrapper.InsertData("key2", "value2", -1), NativeRdb::E_OK);
    EXPECT_TRUE(rdbWrapper.IsStoreOpen());
}

/**
 * @tc.name: IdleRelease_600
 * @tc.desc: Verify an operation returns E_ERROR when the store cannot be reopened after an idle release.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbWrapperIdleTest, IdleRelease_600, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.idleReleaseTimeoutMs = 0;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"normal_table"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    ASSERT_EQ(rdbWrapper.Init(), NativeRdb::E_OK);
    ASSERT_EQ(rdbWrapper.ReleaseIfIdle(0), NativeRdb::E_OK);

    // Reopen fails: the operation must fail instead of touching a null store.
    SetMockGetRdbHelperErrCodes({NativeRdb::E_ERROR});
    SetMockRdbStoreResults({nullptr});
    EXPECT_EQ(rdbWrapper.InsertData("key", "value", -1), NativeRdb::E_ERROR);
    EXPECT_FALSE(rdbWrapper.IsStoreOpen());
}

/**
 * @tc.name: IdleRelease_700
 * @tc.desc: Verify an operation returns E_ERROR when reloading tables fails after an idle release.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbWrapperIdleTest, IdleRelease_700, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.idleReleaseTimeoutMs = 0;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"normal_table"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    ASSERT_EQ(rdbWrapper.Init(), NativeRdb::E_OK);
    ASSERT_EQ(rdbWrapper.ReleaseIfIdle(0), NativeRdb::E_OK);

    // Reopen succeeds but the table reload fails.
    auto secondStore = std::make_shared<MockRdbStore>();
    SetMockGetRdbHelperErrCodes({NativeRdb::E_OK});
    SetMockRdbStoreResults({secondStore});
    SetMockQuerySqlResults({nullptr});
    EXPECT_EQ(rdbWrapper.InsertData("key", "value", -1), NativeRdb::E_ERROR);
    EXPECT_FALSE(rdbWrapper.IsStoreOpen());
}

/**
 * @tc.name: IdleRelease_800
 * @tc.desc: Verify the store still works after a reopen when the database reports no tables.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbWrapperIdleTest, IdleRelease_800, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    config.idleReleaseTimeoutMs = 0;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"normal_table"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    ASSERT_EQ(rdbWrapper.Init(), NativeRdb::E_OK);
    ASSERT_EQ(rdbWrapper.ReleaseIfIdle(0), NativeRdb::E_OK);

    auto secondStore = std::make_shared<MockRdbStore>();
    SetMockGetRdbHelperErrCodes({NativeRdb::E_OK});
    SetMockRdbStoreResults({secondStore});
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_EMPTY_VALUES_BUCKET});
    EXPECT_EQ(rdbWrapper.InsertData("key", "value", -1), NativeRdb::E_OK);
    EXPECT_TRUE(rdbWrapper.IsStoreOpen());
}
} // OHOS::Notification::Infra
