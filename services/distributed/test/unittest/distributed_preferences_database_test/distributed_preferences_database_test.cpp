/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#define private public
#include "distributed_preferences_database.h"

#include "mock_single_kv_store.h"

extern void MockKvStoreFlowControl(bool mockRet);
extern void MockGet(bool mockRet);
extern void MockKvManagerFlowControl(bool mockRet);
extern void MockCloseKvStore(bool mockRet);

using namespace testing::ext;
using namespace OHOS::DistributedKv;
namespace OHOS {
namespace Notification {
class DistributedPreferencesDatabaseTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
};

void DistributedPreferencesDatabaseTest::SetUp()
{}

void DistributedPreferencesDatabaseTest::TearDown()
{}

/**
 * @tc.name   : DistributedPreferencesDatabase_00100
 * @tc.number : DistributedPreferencesDatabase_00100
 * @tc.desc   : test CheckKvDataManager and kvDataManager_ == nullptr.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_00100, Function | SmallTest | Level1)
{
    DistributedPreferencesDatabase distributedPreferencesDatabase;
    distributedPreferencesDatabase.kvDataManager_ = nullptr;
    EXPECT_EQ(true, distributedPreferencesDatabase.CheckKvDataManager());
}

/**
 * @tc.name   : DistributedPreferencesDatabase_00200
 * @tc.number : DistributedPreferencesDatabase_00200
 * @tc.desc   : test GetKvStore and status != DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_00200, Function | SmallTest | Level1)
{
    std::shared_ptr<DistributedPreferencesDatabase> distributedPreferencesDatabase =
        std::make_shared<DistributedPreferencesDatabase>();
    ASSERT_NE(nullptr, distributedPreferencesDatabase);
    distributedPreferencesDatabase->GetKvStore();
}

/**
 * @tc.name   : DistributedPreferencesDatabase_00300
 * @tc.number : DistributedPreferencesDatabase_00300
 * @tc.desc   : test CheckKvStore and kvStore_ == nullptr.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_00300, Function | SmallTest | Level1)
{
    DistributedPreferencesDatabase distributedPreferencesDatabase;
    distributedPreferencesDatabase.kvStore_ = nullptr;
    EXPECT_EQ(false, distributedPreferencesDatabase.CheckKvStore());
}

/**
 * @tc.name   : DistributedPreferencesDatabase_00400
 * @tc.number : DistributedPreferencesDatabase_00400
 * @tc.desc   : test PutToDistributedDB and CheckKvStore is false.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_00400, Function | SmallTest | Level1)
{
    DistributedPreferencesDatabase distributedPreferencesDatabase;
    distributedPreferencesDatabase.kvStore_ = nullptr;
    std::string key = "aa";
    std::string value = "bb";
    EXPECT_EQ(false, distributedPreferencesDatabase.PutToDistributedDB(key, value));
}

/**
 * @tc.name   : DistributedPreferencesDatabase_00500
 * @tc.number : DistributedPreferencesDatabase_00500
 * @tc.desc   : test PutToDistributedDB and KvStoreFlowControl is false.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_00500, Function | SmallTest | Level1)
{
    DistributedPreferencesDatabase distributedPreferencesDatabase;
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    distributedPreferencesDatabase.kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(false);
    std::string key = "aa";
    std::string value = "bb";
    EXPECT_EQ(false, distributedPreferencesDatabase.PutToDistributedDB(key, value));
}

/**
 * @tc.name   : DistributedPreferencesDatabase_00600
 * @tc.number : DistributedPreferencesDatabase_00600
 * @tc.desc   : test PutToDistributedDB and status != DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_00600, Function | SmallTest | Level1)
{
    DistributedPreferencesDatabase distributedPreferencesDatabase;
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    distributedPreferencesDatabase.kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(true);
    std::string key = "aa";
    std::string value = "bb";
    EXPECT_EQ(false, distributedPreferencesDatabase.PutToDistributedDB(key, value));
}

/**
 * @tc.name   : DistributedPreferencesDatabase_00700
 * @tc.number : DistributedPreferencesDatabase_00700
 * @tc.desc   : test GetFromDistributedDB and CheckKvStore is false.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_00700, Function | SmallTest | Level1)
{
    DistributedPreferencesDatabase distributedPreferencesDatabase;
    distributedPreferencesDatabase.kvStore_ = nullptr;
    std::string key = "aa";
    std::string value = "bb";
    EXPECT_EQ(false, distributedPreferencesDatabase.GetFromDistributedDB(key, value));
}

/**
 * @tc.name   : DistributedPreferencesDatabase_00800
 * @tc.number : DistributedPreferencesDatabase_00800
 * @tc.desc   : test GetFromDistributedDB and CheckKvStore is true and KvStoreFlowControl is false.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_00800, Function | SmallTest | Level1)
{
    DistributedPreferencesDatabase distributedPreferencesDatabase;
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    distributedPreferencesDatabase.kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(false);
    std::string key = "aa";
    std::string value = "bb";
    EXPECT_EQ(false, distributedPreferencesDatabase.GetFromDistributedDB(key, value));
}

/**
 * @tc.name   : DistributedPreferencesDatabase_00900
 * @tc.number : DistributedPreferencesDatabase_00900
 * @tc.desc   : test GetFromDistributedDB KvStoreFlowControl is true and status != DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_00900, Function | SmallTest | Level1)
{
    DistributedPreferencesDatabase distributedPreferencesDatabase;
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    distributedPreferencesDatabase.kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(true);
    MockGet(true);
    std::string key = "aa";
    std::string value = "bb";
    EXPECT_EQ(false, distributedPreferencesDatabase.GetFromDistributedDB(key, value));
}

/**
 * @tc.name   : DistributedPreferencesDatabase_01000
 * @tc.number : DistributedPreferencesDatabase_01000
 * @tc.desc   : test GetFromDistributedDB KvStoreFlowControl is true and status == DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_01000, Function | SmallTest | Level1)
{
    DistributedPreferencesDatabase distributedPreferencesDatabase;
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    distributedPreferencesDatabase.kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(true);
    MockGet(false);
    std::string key = "aa";
    std::string value = "bb";
    EXPECT_EQ(true, distributedPreferencesDatabase.GetFromDistributedDB(key, value));
}

/**
 * @tc.name   : DistributedPreferencesDatabase_01100
 * @tc.number : DistributedPreferencesDatabase_01100
 * @tc.desc   : test GetEntriesFromDistributedDB and CheckKvStore is false.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_01100, Function | SmallTest | Level1)
{
    DistributedPreferencesDatabase distributedPreferencesDatabase;
    distributedPreferencesDatabase.kvStore_ = nullptr;
    std::string prefixKey = "aa";
    std::vector<Entry> entries;
    EXPECT_EQ(false, distributedPreferencesDatabase.GetEntriesFromDistributedDB(prefixKey, entries));
}

/**
 * @tc.name   : DistributedPreferencesDatabase_01200
 * @tc.number : DistributedPreferencesDatabase_01200
 * @tc.desc   : test GetEntriesFromDistributedDB and KvStoreFlowControl is false.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_01200, Function | SmallTest | Level1)
{
    DistributedPreferencesDatabase distributedPreferencesDatabase;
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    distributedPreferencesDatabase.kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(false);
    std::string prefixKey = "aa";
    std::vector<Entry> entries;
    EXPECT_EQ(false, distributedPreferencesDatabase.GetEntriesFromDistributedDB(prefixKey, entries));
}

/**
 * @tc.name   : DistributedPreferencesDatabase_01300
 * @tc.number : DistributedPreferencesDatabase_01300
 * @tc.desc   : test GetEntriesFromDistributedDB and status != DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_01300, Function | SmallTest | Level1)
{
    DistributedPreferencesDatabase distributedPreferencesDatabase;
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    distributedPreferencesDatabase.kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(true);
    std::string prefixKey = "aa";
    std::vector<Entry> entries;
    EXPECT_EQ(false, distributedPreferencesDatabase.GetEntriesFromDistributedDB(prefixKey, entries));
}

/**
 * @tc.name   : DistributedPreferencesDatabase_01400
 * @tc.number : DistributedPreferencesDatabase_01400
 * @tc.desc   : test DeleteToDistributedDB and CheckKvStore is false.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_01400, Function | SmallTest | Level1)
{
    DistributedPreferencesDatabase distributedPreferencesDatabase;
    distributedPreferencesDatabase.kvStore_ = nullptr;
    std::string key = "aa";
    EXPECT_EQ(false, distributedPreferencesDatabase.DeleteToDistributedDB(key));
}

/**
 * @tc.name   : DistributedPreferencesDatabase_01500
 * @tc.number : DistributedPreferencesDatabase_01500
 * @tc.desc   : test DeleteToDistributedDB and KvStoreFlowControl is false.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_01500, Function | SmallTest | Level1)
{
    DistributedPreferencesDatabase distributedPreferencesDatabase;
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    distributedPreferencesDatabase.kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(false);
    std::string key = "aa";
    EXPECT_EQ(false, distributedPreferencesDatabase.DeleteToDistributedDB(key));
}

/**
 * @tc.name   : DistributedPreferencesDatabase_01600
 * @tc.number : DistributedPreferencesDatabase_01600
 * @tc.desc   : test DeleteToDistributedDB and status != DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_01600, Function | SmallTest | Level1)
{
    DistributedPreferencesDatabase distributedPreferencesDatabase;
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    distributedPreferencesDatabase.kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(true);
    std::string key = "aa";
    EXPECT_EQ(false, distributedPreferencesDatabase.DeleteToDistributedDB(key));
}

/**
 * @tc.name   : DistributedPreferencesDatabase_01700
 * @tc.number : DistributedPreferencesDatabase_01700
 * @tc.desc   : test ClearDatabase and KvManagerFlowControl is false.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_01700, Function | SmallTest | Level1)
{
    DistributedPreferencesDatabase distributedPreferencesDatabase;
    MockKvManagerFlowControl(false);
    EXPECT_EQ(false, distributedPreferencesDatabase.ClearDatabase());
}

/**
 * @tc.name   : DistributedPreferencesDatabase_01800
 * @tc.number : DistributedPreferencesDatabase_01800
 * @tc.desc   : test ClearDatabase and status != DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_01800, Function | SmallTest | Level1)
{
    DistributedPreferencesDatabase distributedPreferencesDatabase;
    MockKvManagerFlowControl(true);
    MockCloseKvStore(false);
    EXPECT_EQ(false, distributedPreferencesDatabase.ClearDatabase());
}

/**
 * @tc.name   : DistributedPreferencesDatabase_01900
 * @tc.number : DistributedPreferencesDatabase_01900
 * @tc.desc   : test ClearDatabase and status != DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedPreferencesDatabaseTest, DistributedPreferencesDatabase_01900, Function | SmallTest | Level1)
{
    DistributedPreferencesDatabase distributedPreferencesDatabase;
    MockKvManagerFlowControl(true);
    MockCloseKvStore(true);
    EXPECT_EQ(false, distributedPreferencesDatabase.ClearDatabase());
}
}  // namespace Notification
}  // namespace OHOS