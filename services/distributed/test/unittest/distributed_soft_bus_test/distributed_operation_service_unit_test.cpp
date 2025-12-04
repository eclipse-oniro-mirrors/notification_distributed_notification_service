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

#include <gtest/gtest.h>

#define private public
#define protected public
#include "distributed_device_service.h"
#include "distributed_operation_service.h"
#undef private
#undef protected
#include "ans_inner_errors.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class DistributedOperationServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

#ifdef DISTRIBUTED_FEATURE_MASTER
#else
/**
 * @tc.name: OnOperationResponse_0100
 * @tc.desc: Test OnOperationResponse with invalid param.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedOperationServiceTest, OnOperationResponse_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationOperationInfo> operationInfo = std::make_shared<NotificationOperationInfo>();
    DistributedDeviceInfo device;
    device.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_2IN1;
    auto result = DistributedOperationService::GetInstance().OnOperationResponse(operationInfo, device);
    EXPECT_EQ(result, ERR_ANS_DISTRIBUTED_OPERATION_FAILED);
}

/**
 * @tc.name: OnOperationResponse_0200
 * @tc.desc: Test OnOperationResponse with invalid param.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedOperationServiceTest, OnOperationResponse_0200, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationOperationInfo> operationInfo = std::make_shared<NotificationOperationInfo>();
    DistributedDeviceService::GetInstance().InitLocalDevice(
        "deviceId", DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD);
    DistributedDeviceInfo device;
    device.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE;
    auto result = DistributedOperationService::GetInstance().OnOperationResponse(operationInfo, device);
    EXPECT_EQ(result, ERR_ANS_DISTRIBUTED_OPERATION_FAILED);
}
#endif
}
}