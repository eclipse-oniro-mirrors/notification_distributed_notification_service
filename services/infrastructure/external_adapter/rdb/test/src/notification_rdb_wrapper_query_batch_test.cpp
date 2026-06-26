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

// Bundle key prefix/suffix aligned with rdb_store_wrapper_query.cpp
static const std::string TEST_BUNDLE_PREFIX = "ans_bundle_";
static const std::string TEST_SUFFIX_NAME = "_name";
static const std::string TEST_SUFFIX_UID = "_uid";
static const std::string TEST_SUFFIX_ENABLED_NOTIFICATION = "_enabledNotification";

class NtfRdbStoreWrapperQueryBatchTest : public ::testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override;
    void TearDown() override;

    static void InitWrapperSuccess(NtfRdbStoreWrapper &rdbWrapper);
};

void NtfRdbStoreWrapperQueryBatchTest::SetUp()
{
    ResetMockRdbHelper();
    ResetMockAbsSharedResultSet();
    ResetMockRdbStore();
}

void NtfRdbStoreWrapperQueryBatchTest::TearDown()
{
    ResetMockRdbHelper();
    ResetMockAbsSharedResultSet();
    ResetMockRdbStore();
}

void NtfRdbStoreWrapperQueryBatchTest::InitWrapperSuccess(NtfRdbStoreWrapper &rdbWrapper)
{
    auto mockRdbStore = std::make_shared<MockRdbStore>();
    SetMockRdbStoreResults({mockRdbStore});
    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQuerySqlResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes({"testValue"}, {NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_ERROR});
    int32_t ret = rdbWrapper.Init();
    ASSERT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.name: QueryDataInKeys_Normal_0100
 * @tc.desc: Verify QueryDataInKeys returns E_OK and aggregates the matched key-value pairs when
 *           multiple keys are queried and the result set contains matching rows.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperQueryBatchTest, QueryDataInKeys_Normal_0100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    InitWrapperSuccess(rdbWrapper);

    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQueryResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes(
        {"key1", "value1", "key2", "value2"},
        {NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_OK, NativeRdb::E_ERROR});

    std::vector<std::string> keys = {"key1", "key2", "key3_missing"};
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    int32_t ret = rdbWrapper.QueryDataInKeys(keys, values, nonSystemUserId);

    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ(values.size(), 2u);
    EXPECT_EQ(values["key1"], "value1");
    EXPECT_EQ(values["key2"], "value2");
    EXPECT_EQ(values.count("key3_missing"), 0u);
}

/**
 * @tc.name: QueryDataInKeys_Empty_0100
 * @tc.desc: Verify QueryDataInKeys short-circuits and returns E_OK without touching the database when
 *           the keys vector is empty.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperQueryBatchTest, QueryDataInKeys_Empty_0100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    InitWrapperSuccess(rdbWrapper);

    std::vector<std::string> keys;
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    int32_t ret = rdbWrapper.QueryDataInKeys(keys, values, nonSystemUserId);

    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_TRUE(values.empty());
}

/**
 * @tc.name: QueryDataInKeys_BatchBoundary_0100
 * @tc.desc: Verify QueryDataInKeys correctly splits more than 100 keys into multiple batches and aggregates
 *           the results across batches. 101 keys should produce two batches (100 + 1), each batch returns
 *           its own result set and all matched pairs are merged into the output map.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperQueryBatchTest, QueryDataInKeys_BatchBoundary_0100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    InitWrapperSuccess(rdbWrapper);

    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQueryResults({mockResultSet, mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGetStringValuesAndErrCodes(
        {"k_1", "v_1", "k_2", "v_2", "k_101", "v_101"},
        {NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_OK, NativeRdb::E_ERROR, NativeRdb::E_ERROR});

    std::vector<std::string> keys;
    keys.reserve(101);
    for (int i = 1; i <= 101; ++i) {
        keys.push_back("k_" + std::to_string(i));
    }
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    int32_t ret = rdbWrapper.QueryDataInKeys(keys, values, nonSystemUserId);

    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ(values.size(), 3u);
    EXPECT_EQ(values["k_1"], "v_1");
    EXPECT_EQ(values["k_2"], "v_2");
    EXPECT_EQ(values["k_101"], "v_101");
}

/**
 * @tc.name: QueryDataInKeys_RdbStoreNull_0100
 * @tc.desc: Verify QueryDataInKeys returns E_ERROR when rdbStore_ is null because Init failed.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperQueryBatchTest, QueryDataInKeys_RdbStoreNull_0100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);

    std::vector<std::string> keys = {"key1"};
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.QueryDataInKeys(keys, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    EXPECT_TRUE(values.empty());
}

/**
 * @tc.name: QueryDataInKeys_Corrupt_0100
 * @tc.desc: Verify QueryDataInKeys returns E_ERROR when GoToFirstRow fails with SQLITE_CORRUPT,
 *           triggering the multi-table error recovery path which also fails.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperQueryBatchTest, QueryDataInKeys_Corrupt_0100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    InitWrapperSuccess(rdbWrapper);

    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQueryResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    SetMockReStoreErrCodes({NativeRdb::E_SQLITE_CORRUPT});

    std::vector<std::string> keys = {"key1"};
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    int32_t ret = rdbWrapper.QueryDataInKeys(keys, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}

/**
 * @tc.name: QueryDataInKeys_NoData_0100
 * @tc.desc: Verify QueryDataInKeys returns E_OK with an empty map when none of the provided keys exist.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperQueryBatchTest, QueryDataInKeys_NoData_0100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    InitWrapperSuccess(rdbWrapper);

    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQueryResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_EMPTY_VALUES_BUCKET});

    std::vector<std::string> keys = {"nonexistent_key"};
    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    int32_t ret = rdbWrapper.QueryDataInKeys(keys, values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_TRUE(values.empty());
}

/**
 * @tc.name: QueryEnabledBundles_Normal_0100
 * @tc.desc: Verify QueryEnabledBundles returns E_OK and aggregates _enabledNotification records into
 *           the output map when matching rows exist.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperQueryBatchTest, QueryEnabledBundles_Normal_0100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    InitWrapperSuccess(rdbWrapper);

    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQueryResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    const std::string nameKey = TEST_BUNDLE_PREFIX + "com.example.app1_100" + TEST_SUFFIX_NAME;
    const std::string uidKey = TEST_BUNDLE_PREFIX + "com.example.app1_100" + TEST_SUFFIX_UID;
    const std::string enabledKey =
        TEST_BUNDLE_PREFIX + "com.example.app1_100" + TEST_SUFFIX_ENABLED_NOTIFICATION;
    SetMockGetStringValuesAndErrCodes(
        {nameKey, "com.example.app1", uidKey, "100", enabledKey, "1"},
        {NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_ERROR});

    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    int32_t ret = rdbWrapper.QueryEnabledBundles(values, nonSystemUserId);

    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ(values.size(), 3u);
    EXPECT_EQ(values[nameKey], "com.example.app1");
    EXPECT_EQ(values[uidKey], "100");
    EXPECT_EQ(values[enabledKey], "1");
}

/**
 * @tc.name: QueryEnabledBundles_ValueFilter_0100
 * @tc.desc: Verify QueryEnabledBundles returns _enabledNotification records whose VALUE is '1' or '3'.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperQueryBatchTest, QueryEnabledBundles_ValueFilter_0100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    InitWrapperSuccess(rdbWrapper);

    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQueryResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_OK});
    const std::string enabledKey1 =
        TEST_BUNDLE_PREFIX + "com.example.app1_100" + TEST_SUFFIX_ENABLED_NOTIFICATION;
    const std::string enabledKey2 =
        TEST_BUNDLE_PREFIX + "com.example.app2_200" + TEST_SUFFIX_ENABLED_NOTIFICATION;
    SetMockGetStringValuesAndErrCodes(
        {enabledKey1, "1", enabledKey2, "3"},
        {NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_OK, NativeRdb::E_OK});
    SetMockGoToNextRowErrCodes({NativeRdb::E_OK, NativeRdb::E_ERROR});

    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    int32_t ret = rdbWrapper.QueryEnabledBundles(values, nonSystemUserId);

    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_EQ(values.size(), 2u);
    EXPECT_EQ(values[enabledKey1], "1");
    EXPECT_EQ(values[enabledKey2], "3");
}

/**
 * @tc.name: QueryEnabledBundles_Empty_0100
 * @tc.desc: Verify QueryEnabledBundles returns E_OK with an empty map when no matching rows exist.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperQueryBatchTest, QueryEnabledBundles_Empty_0100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    InitWrapperSuccess(rdbWrapper);

    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQueryResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_EMPTY_VALUES_BUCKET});

    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    int32_t ret = rdbWrapper.QueryEnabledBundles(values, nonSystemUserId);

    EXPECT_EQ(ret, NativeRdb::E_OK);
    EXPECT_TRUE(values.empty());
}

/**
 * @tc.name: QueryEnabledBundles_RdbStoreNull_0100
 * @tc.desc: Verify QueryEnabledBundles returns E_ERROR when rdbStore_ is null because Init failed.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperQueryBatchTest, QueryEnabledBundles_RdbStoreNull_0100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    int32_t ret = rdbWrapper.Init();
    EXPECT_EQ(ret, NativeRdb::E_ERROR);

    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    ret = rdbWrapper.QueryEnabledBundles(values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    EXPECT_TRUE(values.empty());
}

/**
 * @tc.name: QueryEnabledBundles_Corrupt_0100
 * @tc.desc: Verify QueryEnabledBundles returns E_ERROR when GoToFirstRow fails with SQLITE_CORRUPT,
 *           triggering the multi-table error recovery path which also fails.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NtfRdbStoreWrapperQueryBatchTest, QueryEnabledBundles_Corrupt_0100, Function | SmallTest | Level1)
{
    NotificationRdbConfig config;
    const NtfRdbHook hooks;
    const std::set<RdbEventHandlerType> eventHandlerTypes;
    NtfRdbStoreWrapper rdbWrapper(config, hooks, eventHandlerTypes);
    InitWrapperSuccess(rdbWrapper);

    auto mockResultSet = std::make_shared<MockAbsSharedResultSet>();
    SetMockQueryResults({mockResultSet});
    SetMockGoToFirstRowErrCodes({NativeRdb::E_SQLITE_CORRUPT});
    SetMockReStoreErrCodes({NativeRdb::E_SQLITE_CORRUPT});

    std::unordered_map<std::string, std::string> values;
    int32_t nonSystemUserId = 100;
    int32_t ret = rdbWrapper.QueryEnabledBundles(values, nonSystemUserId);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
}
} // namespace OHOS::Notification::Infra
