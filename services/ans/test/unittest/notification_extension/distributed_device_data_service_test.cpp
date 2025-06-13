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
#include "distributed_device_data_service.h"

namespace OHOS {
namespace Notification {

using namespace testing::ext;

namespace {
const std::string DEVICE_ID = "abcd";
const std::string DEVICE_TYPE = "pc";
}
class DistributedDeviceDataServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() {};
    void TearDown() {};
};

void DistributedDeviceDataServiceTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "SetUp Case start";
    DistributedDeviceDataService::GetInstance().ResetTargetDevice(DEVICE_TYPE, DEVICE_ID);
    GTEST_LOG_(INFO) << "SetUp end";
}

void DistributedDeviceDataServiceTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "TearDown case";
}

/**
 * @tc.name: Device sync switch check
 * @tc.desc: Test device data service
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceDataServiceTest, DeviceData_00001, Function | SmallTest | Level1)
{
    // add device sync switch data failed, because deviceType or deviceId is empty.
    int32_t result = DistributedDeviceDataService::GetInstance().SetDeviceSyncSwitch("", "", true, true);
    ASSERT_EQ(result, (int)ERR_ANS_INVALID_PARAM);

    // add device sync switch data
    result = DistributedDeviceDataService::GetInstance().SetDeviceSyncSwitch(DEVICE_TYPE,
        DEVICE_ID, true, true);
    ASSERT_EQ(result, (int)ERR_OK);

    bool liveView = DistributedDeviceDataService::GetInstance().GetDeviceLiveViewEnable(DEVICE_TYPE, DEVICE_ID);
    ASSERT_EQ(true, liveView);

    bool notification = DistributedDeviceDataService::GetInstance().GetDeviceNotificationEnable(DEVICE_TYPE, DEVICE_ID);
    ASSERT_EQ(true, notification);

    // change device sync switch data
    result = DistributedDeviceDataService::GetInstance().SetDeviceSyncSwitch(DEVICE_TYPE,
        DEVICE_ID, true, false);

    notification = DistributedDeviceDataService::GetInstance().GetDeviceLiveViewEnable(DEVICE_TYPE, DEVICE_ID);
    ASSERT_EQ(false, notification);
}

/**
 * @tc.name: Device sync installed bundle check
 * @tc.desc: Test device data service
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceDataServiceTest, DeviceData_00002, Function | SmallTest | Level1)
{
    StringAnonymous(DEVICE_ID);
    // add device installed bundles failed, because deviceType or deviceId is empty.
    int32_t result = DistributedDeviceDataService::GetInstance().SetTargetDeviceBundleList("",
        DEVICE_ID, BunleListOperationType::ADD_BUNDLES, {});
    ASSERT_EQ(result, (int)ERR_ANS_INVALID_PARAM);

    // add device installed bundles
    std::vector<std::string> bundleList = { "ohos.com.test1", "ohos.com.test2" };
    result = DistributedDeviceDataService::GetInstance().SetTargetDeviceBundleList(DEVICE_TYPE,
        DEVICE_ID, BunleListOperationType::ADD_BUNDLES, bundleList);
    ASSERT_EQ(result, (int)ERR_OK);
    bool exist = DistributedDeviceDataService::GetInstance().CheckDeviceBundleExist(DEVICE_TYPE,
        DEVICE_ID, "ohos.com.test1");
    ASSERT_EQ(exist, true);

    // remove device installed bundles
    result = DistributedDeviceDataService::GetInstance().SetTargetDeviceBundleList(DEVICE_TYPE,
        DEVICE_ID, BunleListOperationType::REMOVE_BUNDLES, { "ohos.com.test1" });
    ASSERT_EQ(result, (int)ERR_OK);
    exist = DistributedDeviceDataService::GetInstance().CheckDeviceBundleExist(DEVICE_TYPE,
        DEVICE_ID, "ohos.com.test1");
    ASSERT_EQ(exist, false);
    exist = DistributedDeviceDataService::GetInstance().CheckDeviceBundleExist(DEVICE_TYPE,
        DEVICE_ID, "ohos.com.test2");
    ASSERT_EQ(exist, true);

    // clear device installed bundles
    result = DistributedDeviceDataService::GetInstance().SetTargetDeviceBundleList(DEVICE_TYPE,
        DEVICE_ID, BunleListOperationType::RELEASE_BUNDLES, {});
    ASSERT_EQ(result, (int)ERR_OK);
    exist = DistributedDeviceDataService::GetInstance().CheckDeviceBundleExist(DEVICE_TYPE,
        DEVICE_ID, "ohos.com.test2");
    ASSERT_EQ(exist, false);
}
}
}
