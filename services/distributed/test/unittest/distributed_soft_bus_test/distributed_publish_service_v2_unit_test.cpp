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
#include "distributed_publish_service.h"
#undef private
#undef protected
#include "mock_request_box.h"
#include "mock_invoke_counting.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class DistributedPublishServiceV2Test : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

#ifdef DISTRIBUTED_FEATURE_MASTER
/**
 * @tc.name: SetNotificationButtons_0100
 * @tc.desc: Test SetNotificationButtons success.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedPublishServiceV2Test, SetNotificationButtons_0100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    std::shared_ptr<NotificationActionButton> actionButton1 =
        NotificationActionButton::Create(nullptr, "title", nullptr);
    request->AddActionButton(actionButton1);
    std::shared_ptr<NotificationActionButton> actionButton2 =
        NotificationActionButton::Create(nullptr, "title2", nullptr);
    request->AddActionButton(actionButton2);
    std::shared_ptr<NotificationRequestBox> requestBox = std::make_shared<NotificationRequestBox>();
    DistributedPublishService::GetInstance().SetNotificationButtons(
        request, DistributedHardware::DmDeviceType::DEVICE_TYPE_2IN1,
        NotificationConstant::SlotType::SOCIAL_COMMUNICATION, requestBox);
    std::shared_ptr<MockNotificationRequestBox> mockRequest = std::make_shared<MockNotificationRequestBox>();
    mockRequest->box_ = requestBox->box_;
    std::vector<std::string> buttonsTitle;
    mockRequest->GetActionButtonsTitle(buttonsTitle);
    EXPECT_EQ(buttonsTitle.size(), 2);
}

/**
 * @tc.name: RemoveAllDistributedNotifications_0100
 * @tc.desc: Test RemoveAllDistributedNotifications success.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedPublishServiceV2Test, RemoveAllDistributedNotifications_0100, Function | SmallTest | Level1)
{
    MockInvokeCounting::GetInstance().MockReSetCount();
    DistributedDeviceInfo device;
    device.deviceId_ = "deviceId_";
    DistributedPublishService::GetInstance().RemoveAllDistributedNotifications(device,
        NotificationConstant::DistributedDeleteType::DEVICE_ID, NotificationConstant::DISTRIBUTED_RELEASE_DELETE);
    EXPECT_EQ(1, MockInvokeCounting::GetInstance().MockGetCount());
}

/**
 * @tc.name: SendNotifictionRequest_0100
 * @tc.desc: Test SendNotifictionRequest fail cause wrong params.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedPublishServiceV2Test, SendNotifictionRequest_0100, Function | SmallTest | Level1)
{
    DistributedDeviceInfo device;
    MockInvokeCounting::GetInstance().MockReSetCount();
    device.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_2IN1;
    DistributedPublishService::GetInstance().SendNotifictionRequest(nullptr, device, true);
    EXPECT_EQ(0, MockInvokeCounting::GetInstance().MockGetCount());
}

/**
 * @tc.name: SendNotifictionRequest_0200
 * @tc.desc: Test SendNotifictionRequest fail cause wrong params.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedPublishServiceV2Test, SendNotifictionRequest_0200, Function | SmallTest | Level1)
{
    DistributedDeviceInfo device;
    MockInvokeCounting::GetInstance().MockReSetCount();
    device.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_2IN1;
    sptr<NotificationRequest> request = new(std::nothrow) NotificationRequest(10);
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(request);
    DistributedPublishService::GetInstance().SendNotifictionRequest(sharedNotification, device, true);
    EXPECT_EQ(0, MockInvokeCounting::GetInstance().MockGetCount());
}
#else
/**
 * @tc.name: MakeNotificationButtons_0100
 * @tc.desc: Test MakeNotificationButtons success.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedPublishServiceV2Test, MakeNotificationButtons_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<TlvBox> boxMessage = std::make_shared<TlvBox>();
    boxMessage->PutValue(std::make_shared<TlvItem>(TlvType::ACTION_BUTTONS_LENGTH, 1));
    boxMessage->PutValue(std::make_shared<TlvItem>(ACTION_BUTTONS_TITILE_INDEX, "buttonTitle"));
    NotificationRequestBox requestBox = NotificationRequestBox(boxMessage);
    DistributedDeviceService::GetInstance().InitLocalDevice(
        "deviceId", DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD);
    sptr<NotificationRequest> request = new(std::nothrow) NotificationRequest(10);
    DistributedPublishService::GetInstance().MakeNotificationButtons(
        requestBox, NotificationConstant::SlotType::ILLEGAL_TYPE, request);
    EXPECT_EQ(1, request->GetActionButtons().size());
}
#endif
}
}