/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "distributed_database.h"

#include "ans_inner_errors.h"
#include "mock_single_kv_store.h"

extern void MockInitDeviceManager(bool mockRet);
extern void MockRegisterDevStateCallback(bool mockRet);
extern void MockGetSingleKvStore(bool mockRet);
extern void MockSubscribeKvStore(bool mockRet);
extern void MockKvStoreFlowControl(bool mockRet);
extern void MockRemoveDeviceData(bool mockRet);
extern void MockKvManagerFlowControl(bool mockRet);
extern void MockGetLocalDevice(bool mockRet);
extern void MockGetTrustedDeviceList(bool mockRet);

using namespace testing::ext;
using namespace OHOS::DistributedKv;
namespace OHOS {
namespace Notification {
class DistributedDatabaseBranchTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;

public:
    virtual void OnInsert(const std::string &deviceId, const std::string &key, const std::string &value);
    virtual void OnUpdate(const std::string &deviceId, const std::string &key, const std::string &value);
    virtual void OnDelete(const std::string &deviceId, const std::string &key, const std::string &value);
    virtual void OnConnected(const std::string &deviceId);
    virtual void OnDisconnected(const std::string &deviceId);

protected:
    std::shared_ptr<DistributedDatabase> database_;
    std::shared_ptr<DistributedDatabaseCallback> databaseCallback_;
    std::shared_ptr<DistributedDeviceCallback> deviceCallback_;
};

void DistributedDatabaseBranchTest::SetUp()
{
    DistributedDatabaseCallback::IDatabaseChange databaseCallback = {
        .OnInsert = std::bind(&DistributedDatabaseBranchTest::OnInsert,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
        .OnUpdate = std::bind(&DistributedDatabaseBranchTest::OnUpdate,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
        .OnDelete = std::bind(&DistributedDatabaseBranchTest::OnDelete,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
    };
    DistributedDeviceCallback::IDeviceChange deviceCallback = {
        .OnConnected = std::bind(&DistributedDatabaseBranchTest::OnConnected, this, std::placeholders::_1),
        .OnDisconnected = std::bind(&DistributedDatabaseBranchTest::OnDisconnected, this, std::placeholders::_1),
    };

    databaseCallback_ = std::make_shared<DistributedDatabaseCallback>(databaseCallback);
    deviceCallback_ = std::make_shared<DistributedDeviceCallback>(deviceCallback);
    database_ = std::make_shared<DistributedDatabase>(databaseCallback_, deviceCallback_);
    database_->OnDeviceConnected();
}

void DistributedDatabaseBranchTest::TearDown()
{
    database_ = nullptr;
    databaseCallback_ = nullptr;
    deviceCallback_ = nullptr;
}

void DistributedDatabaseBranchTest::OnInsert(
    const std::string &deviceId, const std::string &key, const std::string &value) {}

void DistributedDatabaseBranchTest::OnUpdate(
    const std::string &deviceId, const std::string &key, const std::string &value) {}

void DistributedDatabaseBranchTest::OnDelete(
    const std::string &deviceId, const std::string &key, const std::string &value) {}

void DistributedDatabaseBranchTest::OnConnected(const std::string &deviceId)
{}

void DistributedDatabaseBranchTest::OnDisconnected(const std::string &deviceId)
{}

/**
 * @tc.name   : DistributedDatabaseBranchTest_0100
 * @tc.number : DistributedDatabaseBranchTest_0100
 * @tc.desc   : Test CheckKvDataManager function and kvDataManager_ == nullptr.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_0100, Function | SmallTest | Level1)
{
    ASSERT_NE(nullptr, database_);
    database_->kvDataManager_ = nullptr;
    MockInitDeviceManager(false);
    MockRegisterDevStateCallback(false);
    EXPECT_EQ(true, database_->CheckKvDataManager());
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_0200
 * @tc.number : DistributedDatabaseBranchTest_0200
 * @tc.desc   : Test GetKvStore function and CheckKvDataManager is false.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_0200, Function | SmallTest | Level1)
{
    ASSERT_NE(nullptr, database_);
    database_->kvDataManager_ = nullptr;
    MockInitDeviceManager(false);
    MockRegisterDevStateCallback(true);
    database_->GetKvStore();
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_0300
 * @tc.number : DistributedDatabaseBranchTest_0300
 * @tc.desc   : Test GetKvStore function and status != DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_0300, Function | SmallTest | Level1)
{
    ASSERT_NE(nullptr, database_);
    database_->kvDataManager_ = std::make_unique<DistributedKv::DistributedKvDataManager>();
    MockGetSingleKvStore(false);
    database_->GetKvStore();
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_0400
 * @tc.number : DistributedDatabaseBranchTest_0400
 * @tc.desc   : Test GetKvStore function and kvStore_ == nullptr.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_0400, Function | SmallTest | Level1)
{
    ASSERT_NE(nullptr, database_);
    database_->kvDataManager_ = std::make_unique<DistributedKv::DistributedKvDataManager>();
    MockGetSingleKvStore(true);
    database_->kvStore_ = nullptr;
    database_->GetKvStore();
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_0500
 * @tc.number : DistributedDatabaseBranchTest_0500
 * @tc.desc   : Test GetKvStore function and SubscribeKvStore != DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_0500, Function | SmallTest | Level1)
{
    ASSERT_NE(nullptr, database_);
    database_->kvDataManager_ = std::make_unique<DistributedKv::DistributedKvDataManager>();
    // set GetSingleKvStore is Status::SUCCESS
    MockGetSingleKvStore(true);
    // set kvStore_ is not nullptr
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    database_->kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    // set SubscribeKvStore != Status::SUCCESS
    MockSubscribeKvStore(false);
    database_->GetKvStore();
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_0600
 * @tc.number : DistributedDatabaseBranchTest_0600
 * @tc.desc   : Test CheckKvStore function and kvStore_ != nullptr.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_0600, Function | SmallTest | Level1)
{
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    database_->kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    EXPECT_EQ(true, database_->CheckKvStore());
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_0700
 * @tc.number : DistributedDatabaseBranchTest_0700
 * @tc.desc   : Test CheckKvStore function and kvStore_ == nullptr.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_0700, Function | SmallTest | Level1)
{
    database_->kvStore_ = nullptr;
    MockInitDeviceManager(false);
    MockRegisterDevStateCallback(true);
    EXPECT_EQ(false, database_->CheckKvStore());
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_0800
 * @tc.number : DistributedDatabaseBranchTest_0800
 * @tc.desc   : Test PutToDistributedDB function and KvStoreFlowControl is false.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_0800, Function | SmallTest | Level1)
{
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    database_->kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(false);
    std::string key = "<key>";
    std::string value = "<value>";
    EXPECT_EQ(false, database_->PutToDistributedDB(key, value));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_0900
 * @tc.number : DistributedDatabaseBranchTest_0900
 * @tc.desc   : Test PutToDistributedDB function and status != DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_0900, Function | SmallTest | Level1)
{
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    database_->kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(true);
    std::string key = "<key>";
    std::string value = "<value>";
    EXPECT_EQ(false, database_->PutToDistributedDB(key, value));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_1000
 * @tc.number : DistributedDatabaseBranchTest_1000
 * @tc.desc   : Test GetFromDistributedDB function and kvStore_ == nullptr.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_1000, Function | SmallTest | Level1)
{
    database_->kvStore_ = nullptr;
    std::string key = "<key>";
    std::string value = "<value>";
    EXPECT_EQ(false, database_->GetFromDistributedDB(key, value));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_1100
 * @tc.number : DistributedDatabaseBranchTest_1100
 * @tc.desc   : Test GetFromDistributedDB function and KvStoreFlowControl is false.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_1100, Function | SmallTest | Level1)
{
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    database_->kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(false);
    std::string key = "<key>";
    std::string value = "<value>";
    EXPECT_EQ(false, database_->GetFromDistributedDB(key, value));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_1200
 * @tc.number : DistributedDatabaseBranchTest_1200
 * @tc.desc   : Test GetFromDistributedDB function and status != DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_1200, Function | SmallTest | Level1)
{
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    database_->kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(true);
    std::string key = "<key>";
    std::string value = "<value>";
    EXPECT_EQ(false, database_->GetFromDistributedDB(key, value));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_1300
 * @tc.number : DistributedDatabaseBranchTest_1300
 * @tc.desc   : Test GetEntriesFromDistributedDB function and kvStore_ == nullptr.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_1300, Function | SmallTest | Level1)
{
    database_->kvStore_ = nullptr;
    std::string prefixKey = "<prefixKey>";
    Entry entry;
    std::vector<Entry> entries;
    entries.emplace_back(entry);
    EXPECT_EQ(false, database_->GetEntriesFromDistributedDB(prefixKey, entries));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_1400
 * @tc.number : DistributedDatabaseBranchTest_1400
 * @tc.desc   : Test GetEntriesFromDistributedDB function and KvStoreFlowControl is false.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_1400, Function | SmallTest | Level1)
{
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    database_->kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(false);
    std::string prefixKey = "<prefixKey>";
    Entry entry;
    std::vector<Entry> entries;
    entries.emplace_back(entry);
    EXPECT_EQ(false, database_->GetEntriesFromDistributedDB(prefixKey, entries));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_1500
 * @tc.number : DistributedDatabaseBranchTest_1500
 * @tc.desc   : Test GetEntriesFromDistributedDB function and status != DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_1500, Function | SmallTest | Level1)
{
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    database_->kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(true);
    std::string prefixKey = "<prefixKey>";
    Entry entry;
    std::vector<Entry> entries;
    entries.emplace_back(entry);
    EXPECT_EQ(false, database_->GetEntriesFromDistributedDB(prefixKey, entries));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_1600
 * @tc.number : DistributedDatabaseBranchTest_1600
 * @tc.desc   : Test DeleteToDistributedDB function and KvStoreFlowControl is false.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_1600, Function | SmallTest | Level1)
{
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    database_->kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(false);
    std::string key = "<key>";
    EXPECT_EQ(false, database_->DeleteToDistributedDB(key));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_1700
 * @tc.number : DistributedDatabaseBranchTest_1700
 * @tc.desc   : Test DeleteToDistributedDB function and status != DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_1700, Function | SmallTest | Level1)
{
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    database_->kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(true);
    std::string key = "<key>";
    EXPECT_EQ(false, database_->DeleteToDistributedDB(key));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_1800
 * @tc.number : DistributedDatabaseBranchTest_1800
 * @tc.desc   : Test ClearDataByDevice function and kvStore_ == nullptr.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_1800, Function | SmallTest | Level1)
{
    database_->kvStore_ = nullptr;
    std::string deviceId = "<deviceId>";
    EXPECT_EQ(false, database_->ClearDataByDevice(deviceId));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_1900
 * @tc.number : DistributedDatabaseBranchTest_1900
 * @tc.desc   : Test ClearDataByDevice function and KvStoreFlowControl is false.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_1900, Function | SmallTest | Level1)
{
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    database_->kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(false);
    std::string deviceId = "<deviceId>";
    EXPECT_EQ(false, database_->ClearDataByDevice(deviceId));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_2000
 * @tc.number : DistributedDatabaseBranchTest_2000
 * @tc.desc   : Test ClearDataByDevice function and status != DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_2000, Function | SmallTest | Level1)
{
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    database_->kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(true);
    MockRemoveDeviceData(false);
    std::string deviceId = "<deviceId>";
    EXPECT_EQ(false, database_->ClearDataByDevice(deviceId));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_2100
 * @tc.number : DistributedDatabaseBranchTest_2100
 * @tc.desc   : Test ClearDataByDevice function and status == DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_2100, Function | SmallTest | Level1)
{
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    database_->kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    MockKvStoreFlowControl(true);
    MockRemoveDeviceData(true);
    std::string deviceId = "<deviceId>";
    EXPECT_EQ(true, database_->ClearDataByDevice(deviceId));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_2200
 * @tc.number : DistributedDatabaseBranchTest_2200
 * @tc.desc   : Test GetLocalDeviceId function and localDeviceId_ is not empty.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_2200, Function | SmallTest | Level1)
{
    database_->kvDataManager_ = std::make_unique<DistributedKv::DistributedKvDataManager>();
    // set localDeviceId_ is localDeviceId
    database_->localDeviceId_ = "localDeviceId";
    MockKvManagerFlowControl(false);
    std::string deviceId = "<deviceId>";
    EXPECT_EQ(true, database_->GetLocalDeviceId(deviceId));
    // set localDeviceId_ is empty
    database_->localDeviceId_ = "";
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_2300
 * @tc.number : DistributedDatabaseBranchTest_2300
 * @tc.desc   : Test GetLocalDeviceId function and localDeviceId_ is empty.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_2300, Function | SmallTest | Level1)
{
    database_->kvDataManager_ = std::make_unique<DistributedKv::DistributedKvDataManager>();
    MockKvManagerFlowControl(false);
    std::string deviceId = "<deviceId>";
    EXPECT_EQ(false, database_->GetLocalDeviceId(deviceId));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_2400
 * @tc.number : DistributedDatabaseBranchTest_2400
 * @tc.desc   : Test GetLocalDeviceInfo function and CheckKvDataManager is false.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_2400, Function | SmallTest | Level1)
{
    database_->kvDataManager_ = nullptr;
    MockInitDeviceManager(true);
    DistributedHardware::DmDeviceInfo localInfo;
    EXPECT_EQ(false, database_->GetLocalDeviceInfo(localInfo));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_2500
 * @tc.number : DistributedDatabaseBranchTest_2500
 * @tc.desc   : Test GetLocalDeviceInfo function and KvManagerFlowControl is false.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_2500, Function | SmallTest | Level1)
{
    database_->kvDataManager_ = std::make_unique<DistributedKv::DistributedKvDataManager>();
    MockKvManagerFlowControl(false);
    DistributedHardware::DmDeviceInfo localInfo;
    EXPECT_EQ(false, database_->GetLocalDeviceInfo(localInfo));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_2600
 * @tc.number : DistributedDatabaseBranchTest_2600
 * @tc.desc   : Test GetLocalDeviceInfo function and status != DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_2600, Function | SmallTest | Level1)
{
    database_->kvDataManager_ = std::make_unique<DistributedKv::DistributedKvDataManager>();
    MockKvManagerFlowControl(true);
    MockGetLocalDevice(false);
    DistributedHardware::DmDeviceInfo localInfo;
    EXPECT_EQ(true, database_->GetLocalDeviceInfo(localInfo));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_2700
 * @tc.number : DistributedDatabaseBranchTest_2700
 * @tc.desc   : Test GetDeviceInfoList function and ret == ERR_OK.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_2700, Function | SmallTest | Level1)
{
    database_->kvDataManager_ = std::make_unique<DistributedKv::DistributedKvDataManager>();
    MockKvManagerFlowControl(true);
    MockGetTrustedDeviceList(false);
    std::vector<DistributedHardware::DmDeviceInfo> deviceList;
    EXPECT_EQ(true, database_->GetDeviceInfoList(deviceList));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_2800
 * @tc.number : DistributedDatabaseBranchTest_2800
 * @tc.desc   : Test GetDeviceInfoList function and KvManagerFlowControl is false.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_2800, Function | SmallTest | Level1)
{
    database_->kvDataManager_ = std::make_unique<DistributedKv::DistributedKvDataManager>();
    MockKvManagerFlowControl(false);
    std::vector<DistributedHardware::DmDeviceInfo> deviceList;
    EXPECT_EQ(false, database_->GetDeviceInfoList(deviceList));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_2900
 * @tc.number : DistributedDatabaseBranchTest_2900
 * @tc.desc   : Test GetDeviceInfoList function and ret != ERR_OK.
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_2900, Function | SmallTest | Level1)
{
    database_->kvDataManager_ = std::make_unique<DistributedKv::DistributedKvDataManager>();
    MockKvManagerFlowControl(true);
    MockGetTrustedDeviceList(true);
    std::vector<DistributedHardware::DmDeviceInfo> deviceList;
    EXPECT_EQ(false, database_->GetDeviceInfoList(deviceList));
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_3000
 * @tc.number : DistributedDatabaseBranchTest_3000
 * @tc.desc   : 1.Test RecreateDistributedDB function and CheckKvDataManager is true.
 *              2.set KvManagerFlowControl is true
 *              3.status is DistributedKv::Status::SUCCESS
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_3000, Function | SmallTest | Level1)
{
    database_->kvDataManager_ = std::make_unique<DistributedKv::DistributedKvDataManager>();
    MockKvManagerFlowControl(true);
    EXPECT_EQ(true, database_->RecreateDistributedDB());
}

/**
 * @tc.name   : DistributedDatabaseBranchTest_3100
 * @tc.number : DistributedDatabaseBranchTest_3100
 * @tc.desc   : 1.Test RecreateDistributedDB function and CheckKvDataManager is true.
 *              2.set KvManagerFlowControl is false
 */
HWTEST_F(DistributedDatabaseBranchTest, DistributedDatabaseBranchTest_3100, Function | SmallTest | Level1)
{
    database_->kvDataManager_ = std::make_unique<DistributedKv::DistributedKvDataManager>();
    MockKvManagerFlowControl(false);
    EXPECT_EQ(false, database_->RecreateDistributedDB());
}
}  // namespace Notification
}  // namespace OHOS
