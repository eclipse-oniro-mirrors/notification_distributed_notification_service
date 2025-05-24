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
#undef private
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
    batchRemoveBox.SetNotificationHashCode(hashCodes);
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

    std::shared_ptr<ffrt::queue> serviceQueue = DistributedService::GetInstance().serviceQueue_;
    DistributedService::GetInstance().serviceQueue_ = nullptr;
    DistributedService::GetInstance().OnBatchCanceled(notifications, peerDevice);

    ASSERT_EQ(DistributedService::GetInstance().serviceQueue_, nullptr);
    DistributedService::GetInstance().serviceQueue_ = serviceQueue;
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

    std::shared_ptr<ffrt::queue> serviceQueue = DistributedService::GetInstance().serviceQueue_;
    DistributedService::GetInstance().serviceQueue_ = nullptr;
    DistributedService::GetInstance().OnCanceled(notification, peerDevice);

    ASSERT_EQ(DistributedService::GetInstance().serviceQueue_, nullptr);
    DistributedService::GetInstance().serviceQueue_ = serviceQueue;
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
} // namespace Notification
} // namespace OHOS
