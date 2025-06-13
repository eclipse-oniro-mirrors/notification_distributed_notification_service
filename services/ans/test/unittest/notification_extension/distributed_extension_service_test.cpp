/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define private public
#include "ans_inner_errors.h"
#include "distributed_data_define.h"
#include "distributed_extension_service.h"
#include "distributed_device_manager.h"
#include "mock_device_manager_impl.h"

namespace OHOS {
namespace Notification {

using namespace testing::ext;
using namespace DistributedHardware;

class DistributedExtensionServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() {};
    void TearDown() {};
};

void DistributedExtensionServiceTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "SetUp Case start";
    GTEST_LOG_(INFO) << "SetUp end";
}

void DistributedExtensionServiceTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "TearDown case";
}

/**
 * @tc.name: Distributed extension service config check
 * @tc.desc: Test device data service
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedExtensionServiceTest, extension_00001, Function | SmallTest | Level1)
{
    // init extension conifg.
    bool result = DistributedExtensionService::GetInstance().initConfig();
    ASSERT_EQ(result, true);
    DistributedDeviceConfig config = DistributedExtensionService::GetInstance().deviceConfig_;
    if (config.localType == "Phone") {
        ASSERT_EQ(config.supportPeerDevice.count("Pc"), 1);
        ASSERT_EQ(config.supportPeerDevice.count("Watch"), 1);
        ASSERT_EQ(config.supportPeerDevice.count("Tablet"), 1);
    }
}

/**
 * @tc.name: Distributed extension service
 * @tc.desc: Check device Type Convert
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedExtensionServiceTest, extension_00003, Function | SmallTest | Level1)
{
    std::string deviceType;
    deviceType = DistributedExtensionService::TransDeviceTypeToName(DmDeviceType::DEVICE_TYPE_WATCH);
    ASSERT_EQ(deviceType, "Watch");
    deviceType = DistributedExtensionService::TransDeviceTypeToName(DmDeviceType::DEVICE_TYPE_PAD);
    ASSERT_EQ(deviceType, "Tablet");
    deviceType = DistributedExtensionService::TransDeviceTypeToName(DmDeviceType::DEVICE_TYPE_PHONE);
    ASSERT_EQ(deviceType, "Phone");
    deviceType = DistributedExtensionService::TransDeviceTypeToName(DmDeviceType::DEVICE_TYPE_2IN1);
    ASSERT_EQ(deviceType, "Pc");
    deviceType = DistributedExtensionService::TransDeviceTypeToName(DmDeviceType::DEVICE_TYPE_PC);
    ASSERT_EQ(deviceType, "Pc");
    deviceType = DistributedExtensionService::DeviceTypeToTypeString(DmDeviceType::DEVICE_TYPE_PAD);
    ASSERT_EQ(deviceType, "pad");
    deviceType = DistributedExtensionService::DeviceTypeToTypeString(DmDeviceType::DEVICE_TYPE_PC);
    ASSERT_EQ(deviceType, "pc");
    deviceType = DistributedExtensionService::DeviceTypeToTypeString(DmDeviceType::DEVICE_TYPE_2IN1);
    ASSERT_EQ(deviceType, "pc");
}

/**
 * @tc.name: Distributed extension service
 * @tc.desc: Check the device status change
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedExtensionServiceTest, extension_00002, Function | SmallTest | Level1)
{
    // register device manager.
    bool result = DistributedDeviceManager::GetInstance().RegisterDms(true);
    ASSERT_EQ(result, true);
    // register device manager.
    DistributedDeviceManager::GetInstance().InitTrustList();
    // trigger device online
    DeviceTrigger::TriggerDeviceOnline();
    DistributedExtensionService::GetInstance().OnAllConnectOnline();
    sleep(1);
    // check online device
    bool isEmpty = DistributedExtensionService::GetInstance().deviceMap_.empty();
    ASSERT_EQ(isEmpty, false);
    // trigger device ready
    DeviceTrigger::TriggerDeviceReady();
    // trigger device change
    DeviceTrigger::TriggerDeviceChanged();
    // trigger device offline
    DeviceTrigger::TriggerDeviceOffline();
    sleep(1);
    // check online device
    isEmpty = DistributedExtensionService::GetInstance().deviceMap_.empty();
    ASSERT_EQ(isEmpty, true);
    sleep(1);
    DistributedExtensionService::GetInstance().distributedQueue_ = nullptr;
}
}
}
