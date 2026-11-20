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
#include "distributed_device_service.h"
#include "distributed_publish_service.h"
#include "distributed_send_adapter.h"
#include "distributed_service.h"
#include "tlv_box.h"
#undef private
#include "mock_invoke_counting.h"
#include "remove_box.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {

class DistributedServiceTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
};

void DistributedServiceTest::SetUp() {}

void DistributedServiceTest::TearDown() {}

/**
 * @tc.name      : DistributedServiceTest_00100
 * @tc.number    : DistributedServiceTest_00100
 * @tc.desc      : Test the RemoveNotification function with a null boxMessage.
 */
HWTEST_F(DistributedServiceTest, DistributedServiceTest_00100, Function | SmallTest | Level1)
{
    std::shared_ptr<TlvBox> boxMessage = nullptr;
    DistributedPublishService::GetInstance().RemoveNotification(boxMessage);
    ASSERT_EQ(boxMessage, nullptr);
}

/**
 * @tc.name      : DistributedServiceTest_00200
 * @tc.number    : DistributedServiceTest_00200
 * @tc.desc      : Test the RemoveNotification function with a valid NotificationRemoveBox.
 */
HWTEST_F(DistributedServiceTest, DistributedServiceTest_00200, Function | SmallTest | Level1)
{
    NotificationRemoveBox removeBox;
    std::string notificationKey = "notificationId";
    removeBox.SetNotificationHashCode(notificationKey);
    DistributedPublishService::GetInstance().RemoveNotification(removeBox.box_);
    ASSERT_NE(removeBox.box_, nullptr);
}

/**
 * @tc.name      : DistributedServiceTest_00300
 * @tc.number    : DistributedServiceTest_00300
 * @tc.desc      : Test the RemoveNotification function with empty notificationKey.
 */
HWTEST_F(DistributedServiceTest, DistributedServiceTest_00300, Function | SmallTest | Level1)
{
    std::shared_ptr<TlvBox> boxMessage = nullptr;
    DistributedPublishService::GetInstance().RemoveNotifications(boxMessage);
    ASSERT_EQ(boxMessage, nullptr);
}

/**
 * @tc.name      : DistributedServiceTest_00400
 * @tc.number    : DistributedServiceTest_00400
 * @tc.desc      : Test the OnBatchCanceled function with an valid notifications.
 */
HWTEST_F(DistributedServiceTest, DistributedServiceTest_00400, Function | SmallTest | Level1)
{
    BatchRemoveNotificationBox batchRemoveBox;
    std::string hashCodes = "notificationId1 notificationId2";
    batchRemoveBox.SetNotificationHashCodes(hashCodes);
    DistributedPublishService::GetInstance().RemoveNotifications(batchRemoveBox.box_);
    ASSERT_NE(batchRemoveBox.box_, nullptr);
}

/**
 * @tc.name      : DistributedServiceTest_00500
 * @tc.number    : DistributedServiceTest_00500
 * @tc.desc      : Test the OnBatchCanceled function with a null serviceQueue_.
 */
HWTEST_F(DistributedServiceTest, DistributedServiceTest_00500, Function | SmallTest | Level1)
{
    std::vector<std::shared_ptr<Notification>> notifications;
    DistributedDeviceInfo peerDevice;

    auto serviceQueue = DistributedService::GetInstance().serviceQueue_.queue_;
    DistributedService::GetInstance().serviceQueue_.queue_ = nullptr;
    DistributedService::GetInstance().OnBatchCanceled(notifications, peerDevice);

    ASSERT_EQ(DistributedService::GetInstance().serviceQueue_.queue_, nullptr);
    DistributedService::GetInstance().serviceQueue_.queue_ = serviceQueue;
}

/**
 * @tc.name      : DistributedServiceTest_00600
 * @tc.number    : DistributedServiceTest_00600
 * @tc.desc      : Test the OnBatchCanceled function with valid notifications and peer device.
 */
HWTEST_F(DistributedServiceTest, DistributedServiceTest_00600, Function | SmallTest | Level1)
{
    std::vector<std::shared_ptr<Notification>> notifications;
    DistributedDeviceInfo peerDevice;
    peerDevice.deviceId_ = 1;
    peerDevice.deviceType_ = 1;

    std::shared_ptr<Notification> notificationNull = nullptr;
    sptr<NotificationRequest> request = new NotificationRequest();
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);
    notification->SetKey("notificationKey");
    notifications.push_back(notificationNull);
    notifications.push_back(notification);
    DistributedService::GetInstance().OnBatchCanceled(notifications, peerDevice);
    ASSERT_EQ((notificationNull == nullptr && notification != nullptr), true);
}

/**
 * @tc.name      : DistributedServiceTest_00700
 * @tc.number    : DistributedServiceTest_00700
 * @tc.desc      : Test the OnCanceled function with a valid notification and peer device.
 */
HWTEST_F(DistributedServiceTest, DistributedServiceTest_00700, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);
    notification->SetKey("notificationKey");
    DistributedDeviceInfo peerDevice;
    peerDevice.deviceId_ = 1;
    peerDevice.deviceType_ = 1;

    auto serviceQueue = DistributedService::GetInstance().serviceQueue_.queue_;
    DistributedService::GetInstance().serviceQueue_.queue_ = nullptr;
    DistributedService::GetInstance().OnCanceled(notification, peerDevice);

    ASSERT_EQ(DistributedService::GetInstance().serviceQueue_.queue_, nullptr);
    DistributedService::GetInstance().serviceQueue_.queue_ = serviceQueue;
}

/**
 * @tc.name      : DistributedServiceTest_00800
 * @tc.number    : DistributedServiceTest_00800
 * @tc.desc      : Test the OnCanceled function with a null notification.
 */
HWTEST_F(DistributedServiceTest, DistributedServiceTest_00800, Function | SmallTest | Level1)
{
    std::shared_ptr<Notification> notificationNull = nullptr;
    DistributedDeviceInfo peerDevice;
    DistributedService::GetInstance().OnCanceled(notificationNull, peerDevice);
    ASSERT_EQ(notificationNull, nullptr);
}

/**
 * @tc.name      : DistributedServiceTest_00900
 * @tc.number    : DistributedServiceTest_00900
 * @tc.desc      : Test the OnCanceled function with a valid notification and null peer device.
 */
HWTEST_F(DistributedServiceTest, DistributedServiceTest_00900, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);
    notification->SetKey("notificationKey");
    DistributedDeviceInfo peerDevice;
    peerDevice.deviceId_ = 1;
    peerDevice.deviceType_ = 1;
    DistributedService::GetInstance().OnCanceled(notification, peerDevice);
    ASSERT_NE(notification, nullptr);
}

/**
 * @tc.name      : DistributedServiceTest_01000
 * @tc.number    : DistributedServiceTest_01000
 * @tc.desc      :  Test the OnCanceled function with a null notification.
 */
HWTEST_F(DistributedServiceTest, DistributedServiceTest_01000, Function | SmallTest | Level1)
{
    std::shared_ptr<Notification> notificationNull = nullptr;
    std::string result = DistributedService::GetInstance().GetNotificationKey(notificationNull);
    ASSERT_EQ(result, "");
}

/**
 * @tc.name      : DistributedServiceTest_01100
 * @tc.number    : DistributedServiceTest_01100
 * @tc.desc      : Test the OnCanceled function with a valid notification.
 */
HWTEST_F(DistributedServiceTest, DistributedServiceTest_01100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(request);
    notification->SetKey("_notificationKey");
    std::string result = DistributedService::GetInstance().GetNotificationKey(notification);
    ASSERT_EQ(result, "ans_distributed_notificationKey");
}

/**
 * @tc.name      : CollaborationAbilityTest_01000
 * @tc.number    : CollaborationAbilityTest_01000
 * @tc.desc      : Test the check collaboration ability.
 */
HWTEST_F(DistributedServiceTest, CollaborationAbilityTest_01000, Function | SmallTest | Level1)
{
    std::string extraData;
    DistributedDeviceInfo peerDevice;
    auto result = DistributedService::GetInstance().CheckCollaborationAbility(peerDevice, extraData);
    ASSERT_EQ(result, true);

    extraData = "extra_data";
    result = DistributedService::GetInstance().CheckCollaborationAbility(peerDevice, extraData);
    ASSERT_EQ(result, true);

    extraData = "{\"OS_TYPE\":10,\"OS_VERSION\":\"OpenHarmony\"}";
    peerDevice.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_2IN1;
    DistributedDeviceService::GetInstance().InitLocalDevice("id", DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD);
    result = DistributedService::GetInstance().CheckCollaborationAbility(peerDevice, extraData);
    ASSERT_EQ(result, true);

    peerDevice.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    result = DistributedService::GetInstance().CheckCollaborationAbility(peerDevice, extraData);
    ASSERT_EQ(result, true);

    DistributedDeviceService::GetInstance().InitLocalDevice("id", DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE);
    result = DistributedService::GetInstance().CheckCollaborationAbility(peerDevice, extraData);
    ASSERT_EQ(result, true);

    extraData = "{\"OS_TYPE\":9,\"OS_VERSION\":\"OpenHarmony\"}";
    result = DistributedService::GetInstance().CheckCollaborationAbility(peerDevice, extraData);
    ASSERT_EQ(result, false);

    extraData = "{\"OS_TYPE\":\"type\",\"OS_VERSION\":\"OpenHarmony\"}";
    result = DistributedService::GetInstance().CheckCollaborationAbility(peerDevice, extraData);
    ASSERT_EQ(result, true);

    extraData = "{\"OS_VERSION\":\"OpenHarmony\"}";
    result = DistributedService::GetInstance().CheckCollaborationAbility(peerDevice, extraData);
    ASSERT_EQ(result, true);

    extraData = "[\"OS_VERSION\":\"OpenHarmony\"]";
    result = DistributedService::GetInstance().CheckCollaborationAbility(peerDevice, extraData);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name      : HandleMatchSync_0100
 * @tc.number    : HandleMatchSync_0100
 * @tc.desc      : Test the HandleMatchSync function with a valid notification.
 */
HWTEST_F(DistributedServiceTest, HandleMatchSync_0100, Function | SmallTest | Level1)
{
    MockInvokeCounting::GetInstance().MockReSetCount();
    std::shared_ptr<TlvBox> box = std::make_shared<TlvBox>();
    box->PutValue(std::make_shared<TlvItem>(TlvType::MATCH_TYPE, MatchType::MATCH_SYN));
    box->PutValue(std::make_shared<TlvItem>(TlvType::LOCAL_DEVICE_ID, "deviceId"));
    DistributedDeviceInfo deviceItem;
    deviceItem.deviceId_ = "deviceId";
    DistributedDeviceService::GetInstance().AddDeviceInfo(deviceItem);
    DistributedService::GetInstance().HandleMatchSync(box);
    EXPECT_EQ(0, MockInvokeCounting::GetInstance().MockGetCount());
}

/**
 * @tc.name   : handle device status change.
 * @tc.number : DistributedServiceTest_StatusChange_0100
 * @tc.desc   : test handle device status change.
 */
#ifdef DISTRIBUTED_FEATURE_MASTER
HWTEST_F(DistributedServiceTest, DistributedServiceTest_StatusChange_0100, Function | SmallTest | Level1)
{
    DistributedDeviceInfo deviceItem;
    deviceItem.deviceId_ = "1234";
    deviceItem.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    DistributedDeviceService::GetInstance().AddDeviceInfo(deviceItem);

    DeviceStatueChangeInfo changeInfo;
    changeInfo.enableChange = false;
    changeInfo.deviceType = NotificationConstant::HEADSET_DEVICE_TYPE;
    changeInfo.changeType = DeviceStatueChangeType::NOTIFICATION_ENABLE_CHANGE;
    DistributedService::GetInstance().HandleStatusChange(changeInfo);

    EXPECT_EQ(0, MockInvokeCounting::GetInstance().MockGetCount());

    changeInfo.deviceType = NotificationConstant::CURRENT_DEVICE_TYPE ;
    DistributedService::GetInstance().HandleStatusChange(changeInfo);
    EXPECT_EQ(0, MockInvokeCounting::GetInstance().MockGetCount());

    deviceItem.deviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD;
    DistributedDeviceService::GetInstance().AddDeviceInfo(deviceItem);
    DistributedService::GetInstance().HandleStatusChange(changeInfo);
    EXPECT_EQ(0, MockInvokeCounting::GetInstance().MockGetCount());

    deviceItem.peerState_ = DeviceState::STATE_ONLINE;
    DistributedDeviceService::GetInstance().AddDeviceInfo(deviceItem);
    DistributedService::GetInstance().HandleStatusChange(changeInfo);
    EXPECT_NE(0, MockInvokeCounting::GetInstance().MockGetCount());
}

/**
 * @tc.name      : DistributedServiceTest_OnConsumedSetFlags_0100
 * @tc.desc      : test OnConsumedSetFlags with null notification.
 */
HWTEST_F(DistributedServiceTest, DistributedServiceTest_OnConsumedSetFlags_0100, Function | SmallTest | Level1)
{
    DistributedDeviceInfo device;
    std::shared_ptr<Notification> request = nullptr;
    EXPECT_FALSE(DistributedService::GetInstance().OnConsumedSetFlags(request, device));
}

/**
 * @tc.name      : DistributedServiceTest_OnConsumedSetFlags_0200
 * @tc.desc      : test OnConsumedSetFlags with null notification request point.
 */
HWTEST_F(DistributedServiceTest, DistributedServiceTest_OnConsumedSetFlags_0200, Function | SmallTest | Level1)
{
    DistributedDeviceInfo device;
    auto request = std::make_shared<Notification>("001", nullptr);
    EXPECT_FALSE(DistributedService::GetInstance().OnConsumedSetFlags(request, device));
}
#endif
/**
 * @tc.name      : DistributedServiceTest_01200
 * @tc.number    : DistributedServiceTest_01200
 * @tc.desc      : Test OnConsumedSetFlags with a null notification and a notification
 *                 whose request point is null.
 */
HWTEST_F(DistributedServiceTest, DistributedServiceTest_01200, Function | SmallTest | Level1)
{
    DistributedDeviceInfo peerDevice;
    EXPECT_FALSE(DistributedService::GetInstance().OnConsumedSetFlags(nullptr, peerDevice));

    sptr<NotificationRequest> nullRequest = nullptr;
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(nullRequest);
    EXPECT_FALSE(DistributedService::GetInstance().OnConsumedSetFlags(notification, peerDevice));
}

/**
 * @tc.name      : DistributedServiceTest_01300
 * @tc.number    : DistributedServiceTest_01300
 * @tc.desc      : Test ConnectPeerDevice is skipped after service destroyed (isDestroyed_ set).
 */
HWTEST_F(DistributedServiceTest, DistributedServiceTest_01300, Function | SmallTest | Level1)
{
    DistributedDeviceInfo device;
    device.deviceId_ = "testDeviceIdSkip";
    device.peerState_ = DeviceState::STATE_SYNC;
    DistributedDeviceService::GetInstance().AddDeviceInfo(device);

    DistributedService::GetInstance().isDestroyed_.store(true);
    DistributedService::GetInstance().ConnectPeerDevice(device);
    std::map<std::string, DistributedDeviceInfo> devices;
    DistributedDeviceService::GetInstance().GetDeviceList(devices);
    EXPECT_EQ(devices["testDeviceIdSkip"].connectedTry_, 0);

    DistributedService::GetInstance().isDestroyed_.store(false);
    DistributedService::GetInstance().ConnectPeerDevice(device);
    devices.clear();
    DistributedDeviceService::GetInstance().GetDeviceList(devices);
    EXPECT_EQ(devices["testDeviceIdSkip"].connectedTry_, 1);

    device.peerState_ = DeviceState::STATE_ONLINE;
    DistributedDeviceService::GetInstance().AddDeviceInfo(device);
    DistributedService::GetInstance().isDestroyed_.store(false);
}
} // namespace Notification
} // namespace OHOS
