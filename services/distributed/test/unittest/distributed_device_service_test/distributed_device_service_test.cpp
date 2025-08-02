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

#include <memory>

#include "gtest/gtest.h"
#include "distributed_device_service.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {

class DistributedDeviceServiceTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
};

void DistributedDeviceServiceTest::SetUp() {}

void DistributedDeviceServiceTest::TearDown() {}

/**
 * @tc.name      : DistributedDeviceServiceTest_00100
 * @tc.number    : DistributedDeviceServiceTest_00100
 * @tc.desc      : Test the device status.
 */
HWTEST_F(DistributedDeviceServiceTest, DistributedDeviceServiceTest_00100, Function | SmallTest | Level1)
{
    DistributedDeviceInfo deviceItem;
    deviceItem.deviceId_ = "id";
    deviceItem.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD;
    DistributedDeviceService::GetInstance().AddDeviceInfo(deviceItem);
    DistributedDeviceInfo device;
    bool exit = DistributedDeviceService::GetInstance().GetDeviceInfo("id", device);
    ASSERT_EQ(exit, true);
    ASSERT_EQ(device.peerState_, DeviceState::STATE_INIT);
    DistributedDeviceService::GetInstance().ResetDeviceInfo("id", DeviceState::STATE_ONLINE);
    exit = DistributedDeviceService::GetInstance().GetDeviceInfo("id", device);
    ASSERT_EQ(exit, true);
    ASSERT_EQ(device.peerState_, DeviceState::STATE_ONLINE);
    DistributedDeviceService::GetInstance().DeleteDeviceInfo("id");
}
} // namespace Notification
} // namespace OHOS
