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
    result = DistributedDeviceDataService::GetInstance().SetDeviceSyncSwitch(DEVICE_TYPE, "", true, true);
    ASSERT_EQ(result, (int)ERR_ANS_INVALID_PARAM);

    // add device sync switch data
    result = DistributedDeviceDataService::GetInstance().SetDeviceSyncSwitch(DEVICE_TYPE,
        DEVICE_ID, true, true);
    ASSERT_EQ(result, (int)ERR_OK);

    bool liveView = DistributedDeviceDataService::GetInstance().GetDeviceLiveViewEnable(DEVICE_TYPE, DEVICE_ID);
    ASSERT_EQ(liveView, true);

    liveView = DistributedDeviceDataService::GetInstance().GetDeviceLiveViewEnable("", DEVICE_ID);
    ASSERT_EQ(liveView, false);
    liveView = DistributedDeviceDataService::GetInstance().GetDeviceLiveViewEnable(DEVICE_TYPE, "");
    ASSERT_EQ(liveView, false);

    bool notification = DistributedDeviceDataService::GetInstance().GetDeviceNotificationEnable(DEVICE_TYPE, DEVICE_ID);
    ASSERT_EQ(true, notification);

    notification = DistributedDeviceDataService::GetInstance().GetDeviceNotificationEnable("", DEVICE_ID);
    ASSERT_EQ(false, notification);
    notification = DistributedDeviceDataService::GetInstance().GetDeviceNotificationEnable(DEVICE_TYPE, "");
    ASSERT_EQ(false, notification);

    // change device sync switch data
    result = DistributedDeviceDataService::GetInstance().SetDeviceSyncSwitch(DEVICE_TYPE,
        DEVICE_ID, true, false);

    notification = DistributedDeviceDataService::GetInstance().GetDeviceLiveViewEnable(DEVICE_TYPE, DEVICE_ID);
    ASSERT_EQ(false, notification);
    result = DistributedDeviceDataService::GetInstance().SetDeviceSyncSwitch("", DEVICE_ID, true, true);
    ASSERT_EQ(result, (int)ERR_ANS_INVALID_PARAM);
    result = DistributedDeviceDataService::GetInstance().SetDeviceSyncSwitch(DEVICE_TYPE, "", true, true);
    ASSERT_EQ(result, (int)ERR_ANS_INVALID_PARAM);
    // clear data
    DistributedDeviceDataService::GetInstance().ResetTargetDevice("", DEVICE_ID);
    DistributedDeviceDataService::GetInstance().ResetTargetDevice(DEVICE_TYPE, "");
    DistributedDeviceDataService::GetInstance().ResetTargetDevice(DEVICE_TYPE, DEVICE_ID);
}

/**
 * @tc.name: Device sync installed bundle check
 * @tc.desc: Test device data service
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedDeviceDataServiceTest, DeviceData_00002, Function | SmallTest | Level1)
{
    // clear data
    DistributedDeviceDataService::GetInstance().ResetTargetDevice(DEVICE_TYPE, DEVICE_ID);
    StringAnonymous(DEVICE_ID);
    // add device installed bundles failed, because deviceType or deviceId is empty.
    int32_t result = DistributedDeviceDataService::GetInstance().SetTargetDeviceBundleList("",
        DEVICE_ID, BundleListOperationType::ADD_BUNDLES, {}, {});
    ASSERT_EQ(result, (int)ERR_ANS_INVALID_PARAM);
    result = DistributedDeviceDataService::GetInstance().SetTargetDeviceBundleList(DEVICE_TYPE,
        "", BundleListOperationType::ADD_BUNDLES, {}, {});
    ASSERT_EQ(result, (int)ERR_ANS_INVALID_PARAM);
    result = DistributedDeviceDataService::GetInstance().SetTargetDeviceBundleList(DEVICE_TYPE,
        DEVICE_ID, BundleListOperationType::REMOVE_BUNDLES, {}, {});
    ASSERT_EQ(result, (int)ERR_ANS_INVALID_PARAM);

    // add device installed bundles
    std::vector<std::string> bundleList = { "ohos.com.test1", "ohos.com.test2" };
    std::vector<std::string> labelList = { "test1", "test2" };
    result = DistributedDeviceDataService::GetInstance().SetTargetDeviceBundleList(DEVICE_TYPE,
        DEVICE_ID, BundleListOperationType::ADD_BUNDLES, bundleList, labelList);
    ASSERT_EQ(result, (int)ERR_OK);
    result = DistributedDeviceDataService::GetInstance().SetTargetDeviceBundleList(DEVICE_TYPE,
        DEVICE_ID, BundleListOperationType::ADD_BUNDLES, { "ohos.com.test0" }, { "test0" });
    ASSERT_EQ(result, (int)ERR_OK);
    result = DistributedDeviceDataService::GetInstance().SetTargetDeviceBundleList("Pad",
        DEVICE_ID, BundleListOperationType::ADD_BUNDLES, { "ohos.com.test0" }, { "test0" });
    ASSERT_EQ(result, (int)ERR_OK);
    result = DistributedDeviceDataService::GetInstance().SetTargetDeviceBundleList(DEVICE_TYPE,
        "abcdef", BundleListOperationType::ADD_BUNDLES, { "ohos.com.test0" }, { "test0" });
    ASSERT_EQ(result, (int)ERR_OK);
    bool exist = DistributedDeviceDataService::GetInstance().CheckDeviceBundleExist(DEVICE_TYPE,
        DEVICE_ID, "ohos.com.test1", "");
    ASSERT_EQ(exist, true);

    exist = DistributedDeviceDataService::GetInstance().CheckDeviceBundleExist("",
        DEVICE_ID, "ohos.com.test1", "");
    ASSERT_EQ(exist, false);

    // remove device installed bundles
    result = DistributedDeviceDataService::GetInstance().SetTargetDeviceBundleList(DEVICE_TYPE,
        DEVICE_ID, BundleListOperationType::REMOVE_BUNDLES, { "ohos.com.test1" }, { "test1" });
    ASSERT_EQ(result, (int)ERR_OK);
    exist = DistributedDeviceDataService::GetInstance().CheckDeviceBundleExist(DEVICE_TYPE,
        DEVICE_ID, "ohos.com.test1", "");
    ASSERT_EQ(exist, false);
    exist = DistributedDeviceDataService::GetInstance().CheckDeviceBundleExist(DEVICE_TYPE,
        DEVICE_ID, "ohos.com.test2", "");
    ASSERT_EQ(exist, true);

    exist = DistributedDeviceDataService::GetInstance().CheckDeviceBundleExist(DEVICE_TYPE,
        DEVICE_ID, "", "test2");
    ASSERT_EQ(exist, true);

    // clear device installed bundles
    result = DistributedDeviceDataService::GetInstance().SetTargetDeviceBundleList(DEVICE_TYPE,
        DEVICE_ID, BundleListOperationType::RELEASE_BUNDLES, {}, {});
    ASSERT_EQ(result, (int)ERR_OK);
    exist = DistributedDeviceDataService::GetInstance().CheckDeviceBundleExist(DEVICE_TYPE,
        DEVICE_ID, "ohos.com.test2", "");
    ASSERT_EQ(exist, false);
}
}
}
