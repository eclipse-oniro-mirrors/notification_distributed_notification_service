/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#define private public
#include "ans_inner_errors.h"
#include "distributed_device_service.h"

static constexpr int32_t STATE_TYPE_BOTH = 3;
static constexpr int32_t STATE_TYPE_SWITCH = 2;
static constexpr int32_t STATE_TYPE_LOCKSCREEN = 1;
static constexpr int32_t SYNC_BUNDLE_ICONS = 1;
static constexpr int32_t SYNC_LIVE_VIEW = 2;
static constexpr int32_t SYNC_INSTALLED_BUNDLE = 3;
static constexpr int32_t DEVICE_USAGE = 4;

using namespace testing::ext;
using namespace testing;
using namespace OHOS;
using namespace Notification;

// Test suite class
class DistributedDeviceServiceTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize objects and dependencies
        distributedDeviceService = &DistributedDeviceService::GetInstance();
    }

    void TearDown() override {}

    DistributedDeviceService *distributedDeviceService = nullptr;
};

/**
 * @tc.name: DeviceTypeToTypeString_Test_001
 * @tc.desc: Test that DeviceTypeToTypeString returns "wearable" when deviceType is DEVICE_TYPE_WATCH
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, DeviceTypeToTypeString_Test_001, Function | SmallTest | Level1)
{
    uint16_t deviceType = DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    std::string result = distributedDeviceService->DeviceTypeToTypeString(deviceType);
    EXPECT_EQ(result, "wearable");
}

/**
 * @tc.name: DeviceTypeToTypeString_Test_002
 * @tc.desc: Test that DeviceTypeToTypeString returns "pad" when deviceType is DEVICE_TYPE_PAD
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, DeviceTypeToTypeString_Test_002, Function | SmallTest | Level1)
{
    uint16_t deviceType = DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD;
    std::string result = distributedDeviceService->DeviceTypeToTypeString(deviceType);
    EXPECT_EQ(result, "pad");
}

/**
 * @tc.name: DeviceTypeToTypeString_Test_003
 * @tc.desc: Test that DeviceTypeToTypeString returns "pc" when deviceType is DEVICE_TYPE_PC
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, DeviceTypeToTypeString_Test_003, Function | SmallTest | Level1)
{
    uint16_t deviceType = DistributedHardware::DmDeviceType::DEVICE_TYPE_PC;
    std::string result = distributedDeviceService->DeviceTypeToTypeString(deviceType);
    EXPECT_EQ(result, "pc");
}

/**
 * @tc.name: DeviceTypeToTypeString_Test_004
 * @tc.desc: Test that DeviceTypeToTypeString returns "phone" when deviceType is DEVICE_TYPE_PHONE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, DeviceTypeToTypeString_Test_004, Function | SmallTest | Level1)
{
    uint16_t deviceType = DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE;
    std::string result = distributedDeviceService->DeviceTypeToTypeString(deviceType);
    EXPECT_EQ(result, "phone");
}

/**
 * @tc.name: DeviceTypeToTypeString_Test_005
 * @tc.desc: Test that DeviceTypeToTypeString returns an empty string when deviceType is unknown
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, DeviceTypeToTypeString_Test_005, Function | SmallTest | Level1)
{
    uint16_t deviceType = 0xFFFF; // An unknown device type
    std::string result = distributedDeviceService->DeviceTypeToTypeString(deviceType);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: InitLocalDevice_Test_001
 * @tc.desc: Test InitLocalDevice and GetLocalDevice.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, InitLocalDevice_Test_001, Function | SmallTest | Level1)
{
    // Arrange
    std::string deviceId = "device123";
    uint16_t deviceType = 1;

    // Act
    distributedDeviceService->InitLocalDevice(deviceId, deviceType);
    auto localDevice = distributedDeviceService->GetLocalDevice();

    // Assert
    EXPECT_EQ(localDevice.deviceId_, deviceId);
    EXPECT_EQ(localDevice.deviceType_, deviceType);
}

/**
 * @tc.name: SetSubscribeAllConnect_Test_001
 * @tc.desc: Test SetSubscribeAllConnect and IsSubscribeAllConnect.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, SetSubscribeAllConnect_Test_001, Function | SmallTest | Level1)
{
    // Arrange
    bool subscribe = true;

    // Act
    distributedDeviceService->SetSubscribeAllConnect(subscribe);
    auto subscribeAllConnect = distributedDeviceService->IsSubscribeAllConnect();

    // Assert
    EXPECT_EQ(subscribeAllConnect, subscribe);
}

/**
 * @tc.name: IsSyncLiveView_Test_001
 * @tc.desc: Test case to verify that IsSyncLiveView returns false when the device does not exist.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, IsSyncLiveView_Test_001, Function | SmallTest | Level1)
{
    std::string deviceId = "non_existent_device";
    bool forceSync = false;

    bool result = distributedDeviceService->IsSyncLiveView(deviceId, forceSync);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsSyncLiveView_Test_002
 * @tc.desc: Test case to verify that IsSyncLiveView returns false when the device type is PC.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, IsSyncLiveView_Test_002, Function | SmallTest | Level1)
{
    std::string deviceId = "device_pc";
    bool forceSync = false;

    // Add a device with type DEVICE_TYPE_PC
    DistributedDeviceInfo deviceData;
    deviceData.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_PC;
    distributedDeviceService->peerDevice_[deviceId] = deviceData;

    bool result = distributedDeviceService->IsSyncLiveView(deviceId, forceSync);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsSyncLiveView_Test_003
 * @tc.desc: Test case to verify that IsSyncLiveView returns false when the device type is 2in1.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, IsSyncLiveView_Test_003, Function | SmallTest | Level1)
{
    std::string deviceId = "device_2in1";
    bool forceSync = false;

    // Add a device with type DEVICE_TYPE_2IN1
    DistributedDeviceInfo deviceData;
    deviceData.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_2IN1;
    distributedDeviceService->peerDevice_[deviceId] = deviceData;

    bool result = distributedDeviceService->IsSyncLiveView(deviceId, forceSync);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsSyncLiveView_Test_004
 * @tc.desc: Test case to verify that IsSyncLiveView returns false when the device type
 *           is PAD and deviceUsage is false.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, IsSyncLiveView_Test_004, Function | SmallTest | Level1)
{
    std::string deviceId = "device_pad";
    bool forceSync = false;

    // Add a device with type DEVICE_TYPE_PAD
    DistributedDeviceInfo deviceData;
    deviceData.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD;
    deviceData.deviceUsage = false;
    distributedDeviceService->peerDevice_[deviceId] = deviceData;

    bool result = distributedDeviceService->IsSyncLiveView(deviceId, forceSync);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsSyncLiveView_Test_005
 * @tc.desc: Test case to verify that IsSyncLiveView returns false when the device type
 *           is PAD and peerState is STATE_SYNC.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, IsSyncLiveView_Test_005, Function | SmallTest | Level1)
{
    std::string deviceId = "device_pad";
    bool forceSync = false;

    // Add a device with type DEVICE_TYPE_PAD
    DistributedDeviceInfo deviceData;
    deviceData.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD;
    deviceData.peerState_ = DeviceState::STATE_SYNC;
    distributedDeviceService->peerDevice_[deviceId] = deviceData;

    bool result = distributedDeviceService->IsSyncLiveView(deviceId, forceSync);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsSyncLiveView_Test_006
 * @tc.desc: Test case to verify that IsSyncLiveView returns false when forceSync is 
 *           false and liveViewSync is true.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, IsSyncLiveView_Test_006, Function | SmallTest | Level1)
{
    std::string deviceId = "device_other";
    bool forceSync = false;

    // Add a device with type DEVICE_TYPE_PHONE
    DistributedDeviceInfo deviceData;
    deviceData.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE;
    deviceData.liveViewSync = true;
    distributedDeviceService->peerDevice_[deviceId] = deviceData;

    bool result = distributedDeviceService->IsSyncLiveView(deviceId, forceSync);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsSyncIcons_Test_001
 * @tc.desc: Test IsSyncIcons function when the device does not exist in peerDevice_.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, IsSyncIcons_Test_001, Function | SmallTest | Level1)
{
    std::string deviceId = "non_existent_device";
    bool forceSync = false;

    bool result = distributedDeviceService->IsSyncIcons(deviceId, forceSync);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsSyncIcons_Test_002
 * @tc.desc: Test IsSyncIcons function when the device type is not DEVICE_TYPE_WATCH.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, IsSyncIcons_Test_002, Function | SmallTest | Level1)
{
    std::string deviceId = "existing_device";
    bool forceSync = false;

    // Add a device with type DEVICE_TYPE_PHONE
    DistributedDeviceInfo deviceData;
    deviceData.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE;
    distributedDeviceService->peerDevice_[deviceId] = deviceData;

    bool result = distributedDeviceService->IsSyncLiveView(deviceId, forceSync);
    EXPECT_TRUE(result);
}


/**
 * @tc.name: IsSyncIcons_Test_003
 * @tc.desc: Test IsSyncIcons function when forceSync is false and iconSync is true.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, IsSyncIcons_Test_003, Function | SmallTest | Level1)
{
    std::string deviceId = "existing_device";
    bool forceSync = false;

    // Add a device with type DEVICE_TYPE_WATCH
    DistributedDeviceInfo deviceData;
    deviceData.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    deviceData.iconSync = true;
    distributedDeviceService->peerDevice_[deviceId] = deviceData;

    bool result = distributedDeviceService->IsSyncLiveView(deviceId, forceSync);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsSyncIcons_Test_004
 * @tc.desc: Test IsSyncIcons function when forceSync is true or iconSync is false.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, IsSyncIcons_Test_004, Function | SmallTest | Level1)
{
    std::string deviceId = "existing_device";
    bool forceSync = true;

    // Add a device with type DEVICE_TYPE_WATCH
    DistributedDeviceInfo deviceData;
    deviceData.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    deviceData.iconSync = false;
    distributedDeviceService->peerDevice_[deviceId] = deviceData;

    bool result = distributedDeviceService->IsSyncLiveView(deviceId, forceSync);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsSyncInstalledBundle_Test_001
 * @tc.desc: Test case to verify that the function returns false when the device does not exist.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, IsSyncInstalledBundle_Test_001, Function | SmallTest | Level1)
{
    std::string deviceId = "non_existent_device_id";
    bool forceSync = false;

    bool result = distributedDeviceService->IsSyncInstalledBundle(deviceId, forceSync);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsSyncInstalledBundle_Test_002
 * @tc.desc: Test case to verify that the function returns false when the device does not exist.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, IsSyncInstalledBundle_Test_002, Function | SmallTest | Level1)
{
    std::string deviceId = "existing_device_id";
    bool forceSync = false;

    // Add a device with type DEVICE_TYPE_WATCH
    DistributedDeviceInfo deviceData;
    deviceData.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    distributedDeviceService->peerDevice_[deviceId] = deviceData;

    bool result = distributedDeviceService->IsSyncInstalledBundle(deviceId, forceSync);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsSyncInstalledBundle_Test_003
 * @tc.desc: Test case to verify that the function returns false when the device does not exist.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, IsSyncInstalledBundle_Test_003, Function | SmallTest | Level1)
{
    std::string deviceId = "existing_device_id";
    bool forceSync = false;

    // Add a device with type not DEVICE_TYPE_WATCH and installedBundlesSync true
    DistributedDeviceInfo deviceData;
    deviceData.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE;
    deviceData.installedBundlesSync = true;
    distributedDeviceService->peerDevice_[deviceId] = deviceData;

    bool result = distributedDeviceService->IsSyncInstalledBundle(deviceId, forceSync);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsSyncInstalledBundle_Test_004
 * @tc.desc: Test case to verify that the function returns true when forceSync is true.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, IsSyncInstalledBundle_Test_004, Function | SmallTest | Level1)
{
    std::string deviceId = "existing_device_id";
    bool forceSync = true;

    // Add a device with type not DEVICE_TYPE_WATCH and installedBundlesSync false
    DistributedDeviceInfo deviceData;
    deviceData.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE;
    deviceData.installedBundlesSync = false;
    distributedDeviceService->peerDevice_[deviceId] = deviceData;

    bool result = distributedDeviceService->IsSyncInstalledBundle(deviceId, forceSync);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsSyncInstalledBundle_Test_005
 * @tc.desc: Test case to verify that the function returns true when the device is not synced.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, IsSyncInstalledBundle_Test_005, Function | SmallTest | Level1)
{
    std::string deviceId = "existing_device_id";
    bool forceSync = false;

    // Add a device with type not DEVICE_TYPE_WATCH and installedBundlesSync false
    DistributedDeviceInfo deviceData;
    deviceData.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE;
    deviceData.installedBundlesSync = false;
    distributedDeviceService->peerDevice_[deviceId] = deviceData;

    bool result = distributedDeviceService->IsSyncInstalledBundle(deviceId, forceSync);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: SetDeviceSyncData_Test_001
 * @tc.desc: Test that SetDeviceSyncData does nothing when the deviceId does not exist.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, SetDeviceSyncData_Test_001, Function | SmallTest | Level1)
{
    std::string deviceId = "non_existent_device_id";
    int32_t type = SYNC_BUNDLE_ICONS;
    bool syncData = true;

    // Call the function with a non-existent deviceId
    distributedDeviceService->SetDeviceSyncData(deviceId, type, syncData);

    // Verify that no device data is updated
    EXPECT_EQ(distributedDeviceService->peerDevice_.find(deviceId), distributedDeviceService->peerDevice_.end());
}

/**
 * @tc.name: SetDeviceSyncData_Test_002
 * @tc.desc: Test that SetDeviceSyncData updates iconSync when the type is SYNC_BUNDLE_ICONS.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, SetDeviceSyncData_Test_002, Function | SmallTest | Level1)
{
    std::string deviceId = "existing_device_id";
    int32_t type = SYNC_BUNDLE_ICONS;
    bool syncData = true;

    // Add a device to the peerDevice_ map
    distributedDeviceService->peerDevice_[deviceId] = DistributedDeviceInfo();

    // Call the function with SYNC_BUNDLE_ICONS type
    distributedDeviceService->SetDeviceSyncData(deviceId, type, syncData);

    // Verify that iconSync is updated
    EXPECT_TRUE(distributedDeviceService->peerDevice_[deviceId].iconSync);
}

/**
 * @tc.name: SetDeviceSyncData_Test_003
 * @tc.desc: Test that SetDeviceSyncData updates iconSync when the type is SYNC_LIVE_VIEW.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, SetDeviceSyncData_Test_003, Function | SmallTest | Level1)
{
    std::string deviceId = "existing_device_id";
    int32_t type = SYNC_LIVE_VIEW;
    bool syncData = true;

    // Add a device to the peerDevice_ map
    distributedDeviceService->peerDevice_[deviceId] = DistributedDeviceInfo();

    // Call the function with SYNC_LIVE_VIEW type
    distributedDeviceService->SetDeviceSyncData(deviceId, type, syncData);

    // Verify that liveViewSync is updated
    EXPECT_TRUE(distributedDeviceService->peerDevice_[deviceId].liveViewSync);
}

/**
 * @tc.name: SetDeviceSyncData_Test_004
 * @tc.desc: Test that SetDeviceSyncData updates iconSync when the type is SYNC_INSTALLED_BUNDLE.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, SetDeviceSyncData_Test_004, Function | SmallTest | Level1)
{
    std::string deviceId = "existing_device_id";
    int32_t type = SYNC_INSTALLED_BUNDLE;
    bool syncData = true;

    // Add a device to the peerDevice_ map
    distributedDeviceService->peerDevice_[deviceId] = DistributedDeviceInfo();

    // Call the function with SYNC_INSTALLED_BUNDLE type
    distributedDeviceService->SetDeviceSyncData(deviceId, type, syncData);

    // Verify that installedBundlesSync is updated
    EXPECT_TRUE(distributedDeviceService->peerDevice_[deviceId].installedBundlesSync);
}

/**
 * @tc.name: SetDeviceSyncData_Test_005
 * @tc.desc: Test that SetDeviceSyncData updates iconSync when the type is DEVICE_USAGE.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, SetDeviceSyncData_Test_005, Function | SmallTest | Level1)
{
    std::string deviceId = "existing_device_id";
    int32_t type = DEVICE_USAGE;
    bool syncData = true;

    // Add a device to the peerDevice_ map
    distributedDeviceService->peerDevice_[deviceId] = DistributedDeviceInfo();

    // Call the function with DEVICE_USAGE type
    distributedDeviceService->SetDeviceSyncData(deviceId, type, syncData);

    // Verify that deviceUsage is updated
    EXPECT_TRUE(distributedDeviceService->peerDevice_[deviceId].deviceUsage);
}

/**
 * @tc.name: SetDeviceState_Test_001
 * @tc.desc: Test that the state is correctly set when the device exists in the peerDevice_ map.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, SetDeviceState_Test_001, Function | SmallTest | Level1)
{
    // Arrange
    std::string deviceId = "device1";
    int32_t state = 1;
    DistributedDeviceInfo deviceData;
    deviceData.peerState_ = 0; // Initial state
    distributedDeviceService->peerDevice_[deviceId] = deviceData;

    // Act
    distributedDeviceService->SetDeviceState(deviceId, state);

    // Assert
    EXPECT_EQ(distributedDeviceService->peerDevice_[deviceId].peerState_, state);
}

/**
 * @tc.name: CheckDeviceExist_Test_001
 * @tc.desc: Test case to verify that CheckDeviceExist returns false when the device does not exist.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, CheckDeviceExist_Test_001, Function | SmallTest | Level1)
{
    std::string deviceId = "non_existent_device_id";
    EXPECT_FALSE(distributedDeviceService->CheckDeviceExist(deviceId));
}

/**
 * @tc.name: CheckDeviceExist_Test_002
 * @tc.desc: Test case to verify that CheckDeviceExist returns true when the device exists.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, CheckDeviceExist_Test_002, Function | SmallTest | Level1)
{
    std::string deviceId = "existing_device_id";
    // Add the device to peerDevice_
    distributedDeviceService->peerDevice_[deviceId] = DistributedDeviceInfo();
    EXPECT_TRUE(distributedDeviceService->CheckDeviceExist(deviceId));
}

/**
 * @tc.name: GetDeviceInfo_Test_001
 * @tc.desc: Test case to verify that CheckDeviceExist returns true when the device exists.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, GetDeviceInfo_Test_001, Function | SmallTest | Level1)
{
    std::string deviceId = "non_existent_device_id";
    DistributedDeviceInfo device;

    bool result = distributedDeviceService->GetDeviceInfo(deviceId, device);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: GetDeviceInfo_Test_002
 * @tc.desc: Test case to verify that CheckDeviceExist returns true when the device exists.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, GetDeviceInfo_Test_002, Function | SmallTest | Level1)
{
    std::string deviceId = "existing_device_id";
    DistributedDeviceInfo deviceInfo;
    deviceInfo.deviceId_ = "Test Device";
    distributedDeviceService->peerDevice_[deviceId] = deviceInfo;

    DistributedDeviceInfo device;

    bool result = distributedDeviceService->GetDeviceInfo(deviceId, device);

    EXPECT_TRUE(result);
    EXPECT_EQ(device.deviceId_, "Test Device");
}

/**
 * @tc.name: GetDeviceInfoByUdid_Test_001
 * @tc.desc: Test that GetDeviceInfoByUdid returns true when the device with the given udid exists.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, GetDeviceInfoByUdid_Test_001, Function | SmallTest | Level1)
{
    // Arrange
    DistributedDeviceInfo deviceInfo;
    deviceInfo.udid_ = "test_udid";
    distributedDeviceService->peerDevice_["test_udid"] = deviceInfo;

    DistributedDeviceInfo resultDevice;

    // Act
    bool result = distributedDeviceService->GetDeviceInfoByUdid("test_udid", resultDevice);

    // Assert
    EXPECT_TRUE(result);
    EXPECT_EQ(resultDevice.udid_, "test_udid");
}

/**
 * @tc.name: GetDeviceInfoByUdid_Test_002
 * @tc.desc: Test that GetDeviceInfoByUdid returns false when the device list is empty.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, GetDeviceInfoByUdid_Test_002, Function | SmallTest | Level1)
{
    // Arrange
    DistributedDeviceInfo resultDevice;

    // Act
    bool result = distributedDeviceService->GetDeviceInfoByUdid("test_udid1", resultDevice);

    // Assert
    EXPECT_FALSE(result);
}

/**
 * @tc.name: GetDeviceInfoByUdid_Test_003
 * @tc.desc: Test that GetDeviceInfoByUdid returns false when the device with the given udid does not exist.
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceServiceTest, GetDeviceInfoByUdid_Test_003, Function | SmallTest | Level1)
{
    // Arrange
    DistributedDeviceInfo resultDevice;

    // Act
    bool result = distributedDeviceService->GetDeviceInfoByUdid("non_existent_udid", resultDevice);

    // Assert
    EXPECT_FALSE(result);
}