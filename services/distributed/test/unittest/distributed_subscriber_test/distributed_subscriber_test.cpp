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
#include "distributed_subscriber.h"
#include "int_wrapper.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {

class DistributedSubscriberTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
};

void DistributedSubscriberTest::SetUp() {}

void DistributedSubscriberTest::TearDown() {}

/**
 * @tc.name      : DistributedSubscriberTest_00100
 * @tc.number    : DistributedSubscriberTest_00100
 * @tc.desc      : Test the device status.
 */
HWTEST_F(DistributedSubscriberTest, DistributedSubscriberTest_00100, Function | SmallTest | Level1)
{
    std::shared_ptr<DistribuedSubscriber> subscriber = std::make_shared<DistribuedSubscriber>();
    DistributedDeviceInfo peerDevice;
    peerDevice.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD;
    subscriber->SetPeerDevice(peerDevice);
    sptr<NotificationRequest> request = new NotificationRequest(100);
    EXPECT_EQ(subscriber->CheckCollaborationNotification(request), true);

    peerDevice.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    subscriber->SetPeerDevice(peerDevice);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    EXPECT_EQ(subscriber->CheckCollaborationNotification(request), true);

    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    EXPECT_EQ(subscriber->CheckCollaborationNotification(request), true);

    std::shared_ptr<AAFwk::WantParams> extendInfo = std::make_shared<AAFwk::WantParams>();
    request->SetExtendInfo(extendInfo);
    EXPECT_EQ(subscriber->CheckCollaborationNotification(request), true);

    extendInfo->SetParam("collaboration_device_list", AAFwk::Integer::Box(2));
    request->SetExtendInfo(extendInfo);
    EXPECT_EQ(subscriber->CheckCollaborationNotification(request), true);

    extendInfo->SetParam("collaboration_device_list", AAFwk::Integer::Box(4));
    request->SetExtendInfo(extendInfo);
    EXPECT_EQ(subscriber->CheckCollaborationNotification(request), false);
}
} // namespace Notification
} // namespace OHOS
