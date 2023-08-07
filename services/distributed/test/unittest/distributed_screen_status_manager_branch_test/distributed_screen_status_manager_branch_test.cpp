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
#include "distributed_screen_status_manager.h"

#include "ans_inner_errors.h"
#include "mock_single_kv_store.h"

extern void MockInitDeviceManager(bool mockRet);
extern void MockRegisterDevStateCallback(bool mockRet);
extern void MockGetTrustedDeviceList(bool mockRet);
extern void MockKvManagerFlowControl(bool mockRet);
extern void MockKvStoreFlowControl(bool mockRet);
extern void MockGetEntries(bool mockRet);
extern void MockGetLocalDevice(bool mockRet);

using namespace testing::ext;
using namespace OHOS::DistributedKv;
namespace OHOS {
namespace Notification {
class DistributedScreenStatusManagerBranchTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
};

void DistributedScreenStatusManagerBranchTest::SetUp()
{}

void DistributedScreenStatusManagerBranchTest::TearDown()
{}

/**
 * @tc.name   : DistributedScreen_0100
 * @tc.number : DistributedScreen_0100
 * @tc.desc   : Test CheckKvDataManager function and kvDataManager_ == nullptr.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_0100, Function | SmallTest | Level1)
{
    DistributedScreenStatusManager distributedScreenStatusManager;
    distributedScreenStatusManager.kvDataManager_ = nullptr;
    MockInitDeviceManager(false);
    MockRegisterDevStateCallback(false);
    EXPECT_EQ(true, distributedScreenStatusManager.CheckKvDataManager());
}

/**
 * @tc.name   : DistributedScreen_0200
 * @tc.number : DistributedScreen_0200
 * @tc.desc   : Test OnDeviceDisconnected function and ret == ERR_OK.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_0200, Function | SmallTest | Level1)
{
    std::shared_ptr<DistributedScreenStatusManager> distributedScreenStatusManager =
        std::make_shared<DistributedScreenStatusManager>();
    ASSERT_NE(nullptr, distributedScreenStatusManager);
    MockInitDeviceManager(false);
    MockRegisterDevStateCallback(false);
    MockGetTrustedDeviceList(false);
    std::string deviceId = "aa";
    distributedScreenStatusManager->OnDeviceDisconnected(deviceId);
}

/**
 * @tc.name   : DistributedScreen_0300
 * @tc.number : DistributedScreen_0300
 * @tc.desc   : Test OnDeviceDisconnected function and ret != ERR_OK.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_0300, Function | SmallTest | Level1)
{
    std::shared_ptr<DistributedScreenStatusManager> distributedScreenStatusManager =
        std::make_shared<DistributedScreenStatusManager>();
    ASSERT_NE(nullptr, distributedScreenStatusManager);
    MockInitDeviceManager(false);
    MockRegisterDevStateCallback(false);
    MockGetTrustedDeviceList(true);
    std::string deviceId = "aa";
    distributedScreenStatusManager->OnDeviceDisconnected(deviceId);
}

/**
 * @tc.name   : DistributedScreen_0400
 * @tc.number : DistributedScreen_0400
 * @tc.desc   : Test CheckKvStore function and kvStore_ == nullptr.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_0400, Function | SmallTest | Level1)
{
    DistributedScreenStatusManager distributedScreenStatusManager;
    distributedScreenStatusManager.kvStore_ = nullptr;
    EXPECT_EQ(false, distributedScreenStatusManager.CheckKvStore());
}

/**
 * @tc.name   : DistributedScreen_0500
 * @tc.number : DistributedScreen_0500
 * @tc.desc   : Test CheckKvStore function and kvStore_ != nullptr.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_0500, Function | SmallTest | Level1)
{
    DistributedScreenStatusManager distributedScreenStatusManager;
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    distributedScreenStatusManager.kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    EXPECT_EQ(true, distributedScreenStatusManager.CheckKvStore());
}

/**
 * @tc.name   : DistributedScreen_0600
 * @tc.number : DistributedScreen_0600
 * @tc.desc   : Test OnDeviceDisconnected function and CheckKvStore is false.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_0600, Function | SmallTest | Level1)
{
    std::shared_ptr<DistributedScreenStatusManager> distributedScreenStatusManager =
        std::make_shared<DistributedScreenStatusManager>();
    ASSERT_NE(nullptr, distributedScreenStatusManager);
    MockInitDeviceManager(false);
    MockRegisterDevStateCallback(false);
    MockGetTrustedDeviceList(false);
    distributedScreenStatusManager->kvStore_ = nullptr;
    std::string deviceId = "aa";
    distributedScreenStatusManager->OnDeviceDisconnected(deviceId);
}

/**
 * @tc.name   : DistributedScreen_0700
 * @tc.number : DistributedScreen_0700
 * @tc.desc   : Test GetKvDataManager function and ret != 0.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_0700, Function | SmallTest | Level1)
{
    std::shared_ptr<DistributedScreenStatusManager> distributedScreenStatusManager =
        std::make_shared<DistributedScreenStatusManager>();
    ASSERT_NE(nullptr, distributedScreenStatusManager);
    MockInitDeviceManager(true);
    distributedScreenStatusManager->GetKvDataManager();
}

/**
 * @tc.name   : DistributedScreen_0800
 * @tc.number : DistributedScreen_0800
 * @tc.desc   : Test GetKvStore function and CheckKvDataManager is false.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_0800, Function | SmallTest | Level1)
{
    std::shared_ptr<DistributedScreenStatusManager> distributedScreenStatusManager =
        std::make_shared<DistributedScreenStatusManager>();
    ASSERT_NE(nullptr, distributedScreenStatusManager);
    MockInitDeviceManager(true);
    distributedScreenStatusManager->GetKvStore();
}

/**
 * @tc.name   : DistributedScreen_0900
 * @tc.number : DistributedScreen_0900
 * @tc.desc   : Test GetKvStore function and status != DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_0900, Function | SmallTest | Level1)
{
    std::shared_ptr<DistributedScreenStatusManager> distributedScreenStatusManager =
        std::make_shared<DistributedScreenStatusManager>();
    ASSERT_NE(nullptr, distributedScreenStatusManager);
    MockInitDeviceManager(false);
    MockRegisterDevStateCallback(true);
    distributedScreenStatusManager->GetKvStore();
}

/**
 * @tc.name   : DistributedScreen_1000
 * @tc.number : DistributedScreen_1000
 * @tc.desc   : Test OnDeviceDisconnected function and CheckKvDataManager is false.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_1000, Function | SmallTest | Level1)
{
    std::shared_ptr<DistributedScreenStatusManager> distributedScreenStatusManager =
        std::make_shared<DistributedScreenStatusManager>();
    ASSERT_NE(nullptr, distributedScreenStatusManager);
    distributedScreenStatusManager->kvDataManager_ = nullptr;
    MockInitDeviceManager(false);
    MockRegisterDevStateCallback(true);
    std::string deviceId = "aa";
    distributedScreenStatusManager->OnDeviceDisconnected(deviceId);
}

/**
 * @tc.name   : DistributedScreen_1100
 * @tc.number : DistributedScreen_1100
 * @tc.desc   : Test CheckRemoteDevicesIsUsing function and CheckKvDataManager is false and kvStore_ is nullptr.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_1100, Function | SmallTest | Level1)
{
    DistributedScreenStatusManager distributedScreenStatusManager;
    // set CheckKvDataManager is false
    distributedScreenStatusManager.kvDataManager_ = nullptr;
    MockInitDeviceManager(false);
    MockRegisterDevStateCallback(true);
    // set kvStore_ is nullptr
    distributedScreenStatusManager.kvStore_ = nullptr;
    bool isUsing = true;
    EXPECT_EQ(ERR_ANS_DISTRIBUTED_OPERATION_FAILED, distributedScreenStatusManager.CheckRemoteDevicesIsUsing(isUsing));
}

/**
 * @tc.name   : DistributedScreen_1200
 * @tc.number : DistributedScreen_1200
 * @tc.desc   : Test CheckRemoteDevicesIsUsing function and KvManagerFlowControl is false KvStoreFlowControl false.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_1200, Function | SmallTest | Level1)
{
    DistributedScreenStatusManager distributedScreenStatusManager;
    // set CheckKvDataManager is true
    MockInitDeviceManager(false);
    MockRegisterDevStateCallback(false);
    // set kvStore_ is not nullptr
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    distributedScreenStatusManager.kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    // set KvManagerFlowControl is false
    MockKvManagerFlowControl(false);
    // set KvStoreFlowControl is false
    MockKvStoreFlowControl(false);
    bool isUsing = true;
    EXPECT_EQ(ERR_ANS_DISTRIBUTED_OPERATION_FAILED, distributedScreenStatusManager.CheckRemoteDevicesIsUsing(isUsing));
}

/**
 * @tc.name   : DistributedScreen_1300
 * @tc.number : DistributedScreen_1300
 * @tc.desc   : Test CheckRemoteDevicesIsUsing function and KvManagerFlowControl is true KvStoreFlowControl true.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_1300, Function | SmallTest | Level1)
{
    DistributedScreenStatusManager distributedScreenStatusManager;
    // set CheckKvDataManager is true
    MockInitDeviceManager(false);
    MockRegisterDevStateCallback(false);
    // set kvStore_ is not nullptr
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    distributedScreenStatusManager.kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    // set KvManagerFlowControl is true
    MockKvManagerFlowControl(true);
    // set KvStoreFlowControl is true
    MockKvStoreFlowControl(true);
    // set ret != ERR_OK
    MockGetTrustedDeviceList(true);
    bool isUsing = true;
    EXPECT_EQ(ERR_ANS_DISTRIBUTED_GET_INFO_FAILED, distributedScreenStatusManager.CheckRemoteDevicesIsUsing(isUsing));
}

/**
 * @tc.name   : DistributedScreen_1400
 * @tc.number : DistributedScreen_1400
 * @tc.desc   : Test CheckRemoteDevicesIsUsing function and status != DistributedKv::Status::SUCCESS.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_1400, Function | SmallTest | Level1)
{
    DistributedScreenStatusManager distributedScreenStatusManager;
    // set CheckKvDataManager is true
    MockInitDeviceManager(false);
    MockRegisterDevStateCallback(false);
    // set kvStore_ is not nullptr
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    distributedScreenStatusManager.kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    // set KvManagerFlowControl is true
    MockKvManagerFlowControl(true);
    // set KvStoreFlowControl is true
    MockKvStoreFlowControl(true);
    // set ret == ERR_OK
    MockGetTrustedDeviceList(false);
    // set status != DistributedKv::Status::SUCCESS
    MockGetEntries(false);
    bool isUsing = true;
    EXPECT_EQ(ERR_ANS_DISTRIBUTED_GET_INFO_FAILED, distributedScreenStatusManager.CheckRemoteDevicesIsUsing(isUsing));
}

/**
 * @tc.name   : DistributedScreen_1500
 * @tc.number : DistributedScreen_1500
 * @tc.desc   : Test CheckRemoteDevicesIsUsing function and status == DistributedKv::Status::SUCCESS isUsing = true.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_1500, Function | SmallTest | Level1)
{
    DistributedScreenStatusManager distributedScreenStatusManager;
    // set CheckKvDataManager is true
    MockInitDeviceManager(false);
    MockRegisterDevStateCallback(false);
    // set kvStore_ is not nullptr
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    distributedScreenStatusManager.kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    // set KvManagerFlowControl is true
    MockKvManagerFlowControl(true);
    // set KvStoreFlowControl is true
    MockKvStoreFlowControl(true);
    // set ret == ERR_OK
    MockGetTrustedDeviceList(false);
    // set status == DistributedKv::Status::SUCCESS
    MockGetEntries(true);
    bool isUsing = true;
    EXPECT_EQ(ERR_OK, distributedScreenStatusManager.CheckRemoteDevicesIsUsing(isUsing));
}

/**
 * @tc.name   : DistributedScreen_1600
 * @tc.number : DistributedScreen_1600
 * @tc.desc   : Test CheckRemoteDevicesIsUsing function and status == DistributedKv::Status::SUCCESS isUsing = false.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_1600, Function | SmallTest | Level1)
{
    DistributedScreenStatusManager distributedScreenStatusManager;
    // set CheckKvDataManager is true
    MockInitDeviceManager(false);
    MockRegisterDevStateCallback(false);
    // set kvStore_ is not nullptr
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    distributedScreenStatusManager.kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    // set KvManagerFlowControl is true
    MockKvManagerFlowControl(true);
    // set KvStoreFlowControl is true
    MockKvStoreFlowControl(true);
    // set ret == ERR_OK
    MockGetTrustedDeviceList(false);
    // set status == DistributedKv::Status::SUCCESS
    MockGetEntries(true);
    bool isUsing = false;
    EXPECT_EQ(ERR_OK, distributedScreenStatusManager.CheckRemoteDevicesIsUsing(isUsing));
}

/**
 * @tc.name   : DistributedScreen_1700
 * @tc.number : DistributedScreen_1700
 * @tc.desc   : Test SetLocalScreenStatus function.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_1700, Function | SmallTest | Level1)
{
    DistributedScreenStatusManager distributedScreenStatusManager;
    // set kvStore_ is not nullptr
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    distributedScreenStatusManager.kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    // set KvManagerFlowControl is false
    MockKvManagerFlowControl(false);
    // set KvStoreFlowControl is false
    MockKvStoreFlowControl(false);
    bool screenOn = true;
    EXPECT_EQ(ERR_ANS_DISTRIBUTED_OPERATION_FAILED, distributedScreenStatusManager.SetLocalScreenStatus(screenOn));
}

/**
 * @tc.name   : DistributedScreen_1800
 * @tc.number : DistributedScreen_1800
 * @tc.desc   : Test SetLocalScreenStatus function.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_1800, Function | SmallTest | Level1)
{
    DistributedScreenStatusManager distributedScreenStatusManager;
    // set kvStore_ is not nullptr
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    distributedScreenStatusManager.kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    // set KvManagerFlowControl is true
    MockKvManagerFlowControl(true);
    // set KvStoreFlowControl is true
    MockKvStoreFlowControl(true);
    // set ret != ERR_OK
    MockGetLocalDevice(true);
    bool screenOn = true;
    EXPECT_EQ(ERR_ANS_DISTRIBUTED_GET_INFO_FAILED, distributedScreenStatusManager.SetLocalScreenStatus(screenOn));
}

/**
 * @tc.name   : DistributedScreen_1900
 * @tc.number : DistributedScreen_1900
 * @tc.desc   : Test SetLocalScreenStatus function and kvStore_->Put is Status::INVALID_ARGUMENT.
 */
HWTEST_F(DistributedScreenStatusManagerBranchTest, DistributedScreen_1900, Function | SmallTest | Level1)
{
    DistributedScreenStatusManager distributedScreenStatusManager;
    // set kvStore_ is not nullptr
    std::shared_ptr<MockSingleKvStore> kvStore = std::make_shared<MockSingleKvStore>();
    distributedScreenStatusManager.kvStore_ = std::static_pointer_cast<SingleKvStore>(kvStore);
    // set KvManagerFlowControl is true
    MockKvManagerFlowControl(true);
    // set KvStoreFlowControl is true
    MockKvStoreFlowControl(true);
    // set ret == ERR_OK
    MockGetLocalDevice(false);
    bool screenOn = true;
    EXPECT_EQ(ERR_ANS_DISTRIBUTED_OPERATION_FAILED, distributedScreenStatusManager.SetLocalScreenStatus(screenOn));
}
}  // namespace Notification
}  // namespace OHOS