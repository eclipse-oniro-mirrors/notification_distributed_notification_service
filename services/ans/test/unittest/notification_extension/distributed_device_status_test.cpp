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
#include "distributed_device_status.h"
#include "mock_device_manager_impl.h"

namespace OHOS {
namespace Notification {

using namespace testing::ext;

class DistributedDeviceStatusTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() {};
    void TearDown() {};
};

void DistributedDeviceStatusTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "SetUp Case start";
    GTEST_LOG_(INFO) << "SetUp end";
}

void DistributedDeviceStatusTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "TearDown case";
}

/**
 * @tc.name: Device status check
 * @tc.desc: Check device status config, change device status, and updat device status by networkid.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceStatusTest, DeviceData_00001, Function | SmallTest | Level1)
{
    // set device status online
    int32_t result = DelayedSingleton<DistributedDeviceStatus>::GetInstance()->SetDeviceStatus(
        "pad", 1, 33, "udidNum", 100);
    ASSERT_EQ(result, 0);
    DeviceStatus deviceStatus = DelayedSingleton<DistributedDeviceStatus>::GetInstance()->GetMultiDeviceStatus(
        "pad", 1);
    ASSERT_EQ(deviceStatus.deviceType.empty(), false);
    result = DelayedSingleton<DistributedDeviceStatus>::GetInstance()->SetDeviceStatus(
        "pc", 1, 33, "udidNum", 100);
    ASSERT_EQ(result, 0);
    result = DelayedSingleton<DistributedDeviceStatus>::GetInstance()->SetDeviceStatus(
        "pad", 0, 33, "udidNum1", 100);
    ASSERT_EQ(result, 0);

    // set device status offline
    result = DelayedSingleton<DistributedDeviceStatus>::GetInstance()->SetDeviceStatus(
        "pad", 0, 33, "udidNum", 100);
    ASSERT_EQ(result, 0);
    deviceStatus = DelayedSingleton<DistributedDeviceStatus>::GetInstance()->GetMultiDeviceStatus(
        "pad", 1);
    ASSERT_EQ(deviceStatus.deviceType.empty(), true);

    result = DelayedSingleton<DistributedDeviceStatus>::GetInstance()->SetDeviceStatus(
        "pad", 1, 33, "udidNum", 100);
    ASSERT_EQ(result, 0);

    DeviceTrigger::MockTransDeviceIdToUdid(true);
    result = DelayedSingleton<DistributedDeviceStatus>::GetInstance()->SetDeviceStatus(
        "pad", 0, 65537, "netWorkId", 100);
    ASSERT_EQ(result, (int32_t)ERR_OK);
    DeviceTrigger::MockTransDeviceIdToUdid(false);

    result = DelayedSingleton<DistributedDeviceStatus>::GetInstance()->SetDeviceStatus(
        "pad", 0, 65537, "netWorkId", 100);
    ASSERT_EQ(result, 0);
    deviceStatus = DelayedSingleton<DistributedDeviceStatus>::GetInstance()->GetMultiDeviceStatus(
        "pad", 1);
    ASSERT_EQ(deviceStatus.deviceType.empty(), false);
}
}
}
