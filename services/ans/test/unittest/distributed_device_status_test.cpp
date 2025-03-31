/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "distributed_device_status.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class DistributedDeviceStatusTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name  : SetDeviceStatus_100
 * @tc.desc  : Test SetDeviceStatus function when deviceType is liteWearable and status is 0.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedDeviceStatusTest, SetDeviceStatus_100, Function | SmallTest | Level1)
{
    DistributedDeviceStatus distributedDeviceStatus;
    std::string deviceType = "liteWearable";
    uint32_t status = 0;
    uint32_t controlFlag = 1;

    ErrCode result = distributedDeviceStatus.SetDeviceStatus(deviceType, status, controlFlag);

    uint32_t value = 0;
    ASSERT_TRUE(distributedDeviceStatus.deviceStatus_.Find("wearable", value));
}

/**
 * @tc.name  : SetDeviceStatus_200
 * @tc.desc  : Test SetDeviceStatus function when deviceType is not liteWearable and status is 0.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedDeviceStatusTest, SetDeviceStatus_200, Function | SmallTest | Level1)
{
    DistributedDeviceStatus distributedDeviceStatus;
    std::string deviceType = "not_liteWearable";
    uint32_t status = 0;
    uint32_t controlFlag = 1;

    ErrCode result = distributedDeviceStatus.SetDeviceStatus(deviceType, status, controlFlag);

    uint32_t value = 0;
    ASSERT_FALSE(distributedDeviceStatus.deviceStatus_.Find("wearable", value));
}

/**
 * @tc.name  : SetDeviceStatus_300
 * @tc.desc  : Test SetDeviceStatus function when deviceType is liteWearable and status is not 0.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedDeviceStatusTest, SetDeviceStatus_300, Function | SmallTest | Level1)
{
    DistributedDeviceStatus distributedDeviceStatus;
    std::string deviceType = "liteWearable";
    uint32_t status = 1;
    uint32_t controlFlag = 1;

    ErrCode result = distributedDeviceStatus.SetDeviceStatus(deviceType, status, controlFlag);

    uint32_t value = 0;
    ASSERT_TRUE(distributedDeviceStatus.deviceStatus_.Find("wearable", value));
    ASSERT_TRUE((distributedDeviceStatus.deviceStatus_.ReadVal("wearable") & status) != 0);
}

/**
 * @tc.name  : SetDeviceStatus_400
 * @tc.desc  : Test SetDeviceStatus function when deviceType is not liteWearable and status is not 0.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedDeviceStatusTest, SetDeviceStatus_400, Function | SmallTest | Level1)
{
    DistributedDeviceStatus distributedDeviceStatus;
    std::string deviceType = "not_liteWearable";
    uint32_t status = 1;
    uint32_t controlFlag = 1;

    ErrCode result = distributedDeviceStatus.SetDeviceStatus(deviceType, status, controlFlag);

    uint32_t value = 0;
    ASSERT_FALSE(distributedDeviceStatus.deviceStatus_.Find("wearable", value));
    ASSERT_TRUE((distributedDeviceStatus.deviceStatus_.ReadVal(deviceType) & status) != 0);
}
} // Notification
} // OHOS