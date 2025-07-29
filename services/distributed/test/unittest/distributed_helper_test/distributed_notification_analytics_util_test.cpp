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
#define private public
#include "batch_remove_box.h"
#include "distributed_service.h"
#include "distributed_publish_service.h"
#include "distributed_device_service.h"
#undef private
#include "analytics_util.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {

class DistributedAnalyticsUtilTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
};

void DistributedAnalyticsUtilTest::SetUp() {}

void DistributedAnalyticsUtilTest::TearDown() {}

static int32_t g_mockReportCallback = 0;

void MockSendReportCallback(int32_t messageType, int32_t errCode, std::string reason)
{
    g_mockReportCallback++;
}

/**
 * @tc.name      : DistributedAnalyticsUtilTest_00100
 * @tc.number    : DistributedAnalyticsUtilTest_00100
 * @tc.desc      : Test the ha callback is nullptr or not phone.
 */
HWTEST_F(DistributedAnalyticsUtilTest, DistributedServiceTest_00100, Function | SmallTest | Level1)
{
    AnalyticsUtil::GetInstance().SendEventReport(0, 0, "test reason.");
    ASSERT_EQ(g_mockReportCallback, 0);
    AnalyticsUtil::GetInstance().InitSendReportCallBack(&MockSendReportCallback);
    DistributedDeviceService::GetInstance().InitLocalDevice("deviceId",
        DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH);
    AnalyticsUtil::GetInstance().SendEventReport(0, 0, "test reason.");
    ASSERT_EQ(g_mockReportCallback, 0);
    DistributedDeviceService::GetInstance().InitLocalDevice("deviceId",
        DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE);
    AnalyticsUtil::GetInstance().SendEventReport(0, 0, "test reason.");
    ASSERT_EQ(g_mockReportCallback, 1);
    g_mockReportCallback = 0;
}
} // namespace Notification
} // namespace OHOS
