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
        ASSERT_EQ(config.supportPeerDevice.count("Watch"), 1);
    }
}

/**
 * @tc.name: Distributed extension service
 * @tc.desc: Check device Type Convert
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedExtensionServiceTest, extension_00002, Function | SmallTest | Level1)
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
    deviceType = DistributedExtensionService::TransDeviceTypeToName(DmDeviceType::DEVICE_TYPE_WIFI_CAMERA);
    ASSERT_EQ(deviceType, "");
    deviceType = DistributedExtensionService::DeviceTypeToTypeString(DmDeviceType::DEVICE_TYPE_PAD);
    ASSERT_EQ(deviceType, "pad");
    deviceType = DistributedExtensionService::DeviceTypeToTypeString(DmDeviceType::DEVICE_TYPE_PC);
    ASSERT_EQ(deviceType, "pc");
    deviceType = DistributedExtensionService::DeviceTypeToTypeString(DmDeviceType::DEVICE_TYPE_2IN1);
    ASSERT_EQ(deviceType, "pc");
    deviceType = DistributedExtensionService::DeviceTypeToTypeString(DmDeviceType::DEVICE_TYPE_WATCH);
    ASSERT_EQ(deviceType, "");
}

/**
 * @tc.name: Distributed extension service
 * @tc.desc: Check device Type Convert
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedExtensionServiceTest, extension_00003, Function | SmallTest | Level1)
{
    nlohmann::json operationJson;
    operationJson["operationReplyTimeout"] = 10;
    DistributedExtensionService::GetInstance().SetOperationReplyTimeout(operationJson);
    int32_t data = DistributedExtensionService::GetInstance().deviceConfig_.operationReplyTimeout;
    ASSERT_EQ(data, 10);
    nlohmann::json emptyTimeJson;
    DistributedExtensionService::GetInstance().SetOperationReplyTimeout(emptyTimeJson);
    data = DistributedExtensionService::GetInstance().deviceConfig_.operationReplyTimeout;
    ASSERT_EQ(data, 3);
    emptyTimeJson["operationReplyTimeout"] = "10";
    DistributedExtensionService::GetInstance().SetOperationReplyTimeout(emptyTimeJson);
    data = DistributedExtensionService::GetInstance().deviceConfig_.operationReplyTimeout;
    ASSERT_EQ(data, 3);


    nlohmann::json contentJson;
    contentJson["maxContentLength"] = 20;
    DistributedExtensionService::GetInstance().SetMaxContentLength(contentJson);
    data = DistributedExtensionService::GetInstance().deviceConfig_.maxContentLength;
    ASSERT_EQ(data, 20);
    nlohmann::json emptyJson;
    DistributedExtensionService::GetInstance().SetMaxContentLength(emptyJson);
    data = DistributedExtensionService::GetInstance().deviceConfig_.maxContentLength;
    ASSERT_EQ(data, 400);
    emptyJson["maxContentLength"] = "20";
    DistributedExtensionService::GetInstance().SetMaxContentLength(emptyJson);
    data = DistributedExtensionService::GetInstance().deviceConfig_.maxContentLength;
    ASSERT_EQ(data, 400);
}

/**
 * @tc.name: Distributed extension service
 * @tc.desc: Check the device status change
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedExtensionServiceTest, extension_00004, Function | SmallTest | Level1)
{
    // register device manager.
    bool result = DistributedDeviceManager::GetInstance().RegisterDms(true);
    ASSERT_EQ(result, true);
    // register device manager.
    DeviceTrigger::TriggerOnRemoteDied();
    DistributedExtensionService::GetInstance().HADotCallback(0, 0, 0, "{\"deviceType\":\"pc\"}");
    DistributedExtensionService::GetInstance().HADotCallback(0, 0, 0, "{\"result\":\"ok\"}");
    DistributedDeviceManager::GetInstance().InitTrustList();
    // trigger device online
    DeviceTrigger::MockTransDeviceIdToUdid(true);
    DeviceTrigger::TriggerDeviceOnline();
    DeviceTrigger::MockTransDeviceIdToUdid(false);
    bool isEmpty = DistributedExtensionService::GetInstance().deviceMap_.empty();
    ASSERT_EQ(isEmpty, true);

    DeviceTrigger::TriggerDeviceOnline();
    DistributedExtensionService::GetInstance().OnAllConnectOnline();
    sleep(1);
    // check online device
    DistributedExtensionService::GetInstance().HADotCallback(7, 0, BRANCH_3, "{\"result\":\"ok\"}");
    isEmpty = DistributedExtensionService::GetInstance().deviceMap_.empty();
    ASSERT_EQ(isEmpty, false);
    // trigger device ready
    DistributedExtensionService::GetInstance().HADotCallback(7, 0, BRANCH_4, "{\"result\":\"ok\"}");
    DeviceTrigger::TriggerDeviceReady();
    // trigger device change
    DistributedExtensionService::GetInstance().HADotCallback(7, 5, BRANCH_5, "{\"result\":\"ok\"}");
    DeviceTrigger::TriggerDeviceChanged();
    // trigger device offline
    DistributedExtensionService::GetInstance().HADotCallback(5, 0, BRANCH_5, "{\"result\":\"ok\"}");
    DeviceTrigger::TriggerDeviceOffline();
    sleep(1);
    DistributedExtensionService::GetInstance().HADotCallback(6, 0, 0, "{\"result\":\"ok\"}");
    DistributedExtensionService::GetInstance().SendReportCallback(7, 0, "ok");
    // check online device
    isEmpty = DistributedExtensionService::GetInstance().deviceMap_.empty();
    ASSERT_EQ(isEmpty, true);
}

/**
 * @tc.name: Distributed extension service
 * @tc.desc: Check branch when ffrt is null
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedExtensionServiceTest, extension_00005, Function | SmallTest | Level1)
{
    // register device manager.
    DeviceTrigger::MockInitDeviceManager(true);
    bool result = DistributedDeviceManager::GetInstance().RegisterDms(true);
    ASSERT_EQ(result, false);
    DeviceTrigger::MockInitDeviceManager(false);

    DeviceTrigger::MockRegisterDevStateCallback(true);
    DistributedDeviceManager::GetInstance().hasInit.store(false);
    DistributedDeviceManager::GetInstance().InitTrustList();
    result = DistributedDeviceManager::GetInstance().RegisterDms(true);
    ASSERT_EQ(result, false);
    DistributedDeviceManager::GetInstance().hasInit.store(true);
    DeviceTrigger::MockGetTrustedDeviceList(true);
    DistributedDeviceManager::GetInstance().InitTrustList();
    DeviceTrigger::MockGetTrustedDeviceList(false);
    DeviceTrigger::MockRegisterDevStateCallback(false);
    result = DistributedDeviceManager::GetInstance().RegisterDms(true);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: Distributed extension service
 * @tc.desc: Check ccm config
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedExtensionServiceTest, extension_00006, Function | SmallTest | Level1)
{
    DistributedDeviceConfig config;
    DistributedExtensionService::GetInstance().deviceConfig_ = config;
    // register device manager.
    DeviceTrigger::MockConfigScene(0);
    bool result = DistributedExtensionService::GetInstance().initConfig();
    ASSERT_EQ(result, false);

    DeviceTrigger::MockConfigScene(1);
    result = DistributedExtensionService::GetInstance().initConfig();
    ASSERT_EQ(result, false);

    DeviceTrigger::MockConfigScene(2);
    result = DistributedExtensionService::GetInstance().initConfig();
    ASSERT_EQ(result, false);

    DeviceTrigger::MockConfigScene(3);
    result = DistributedExtensionService::GetInstance().initConfig();
    ASSERT_EQ(result, false);

    DeviceTrigger::MockConfigScene(4);
    result = DistributedExtensionService::GetInstance().initConfig();
    ASSERT_EQ(result, true);
    std::string localType = DistributedExtensionService::GetInstance().deviceConfig_.localType;
    ASSERT_EQ(localType.empty(), true);
    auto peers = DistributedExtensionService::GetInstance().deviceConfig_.supportPeerDevice;
    ASSERT_EQ(peers.empty(), false);
    int len = DistributedExtensionService::GetInstance().deviceConfig_.maxTitleLength;
    ASSERT_EQ(len, 200);
    DeviceTrigger::MockConfigScene(-1);
    result = DistributedExtensionService::GetInstance().initConfig();
    ASSERT_EQ(result, true);
}
}
}
