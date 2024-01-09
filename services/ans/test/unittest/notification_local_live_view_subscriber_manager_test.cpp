/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <iostream>

#define private public
#include "notification_local_live_view_subscriber.h"
#include "notification_local_live_view_subscriber_manager.h"

#include "ans_inner_errors.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace Notification {
class NotificationLocalLiveViewSubscriberManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    class TestAnsSubscriber : public NotificationLocalLiveViewSubscriber {
    public:
        void OnConnected() override
        {}
        void OnDisconnected() override
        {}
        void OnDied() override
        {}
        void OnResponse(int32_t notificationId, sptr<NotificationButtonOption> buttonOption) override
        {}
    };

    static std::shared_ptr<NotificationLocalLiveViewSubscriberManager> notificationLocalLiveViewSubscriberManager_;
    static TestAnsSubscriber testAnsSubscriber_;
    static sptr<AnsSubscriberLocalLiveViewInterface> subscriber_;
};

std::shared_ptr<NotificationLocalLiveViewSubscriberManager>
    NotificationLocalLiveViewSubscriberManagerTest::notificationLocalLiveViewSubscriberManager_ = nullptr;
NotificationLocalLiveViewSubscriberManagerTest::TestAnsSubscriber
    NotificationLocalLiveViewSubscriberManagerTest::testAnsSubscriber_;
sptr<AnsSubscriberLocalLiveViewInterface>
    NotificationLocalLiveViewSubscriberManagerTest::subscriber_ = nullptr;

void NotificationLocalLiveViewSubscriberManagerTest::SetUpTestCase()
{
    notificationLocalLiveViewSubscriberManager_ = NotificationLocalLiveViewSubscriberManager::GetInstance();
    subscriber_ = testAnsSubscriber_.GetImpl();
}

void NotificationLocalLiveViewSubscriberManagerTest::TearDownTestCase()
{
    subscriber_ = nullptr;
    if (notificationLocalLiveViewSubscriberManager_ != nullptr) {
        notificationLocalLiveViewSubscriberManager_->ResetFfrtQueue();
        notificationLocalLiveViewSubscriberManager_ = nullptr;
    }
}

void NotificationLocalLiveViewSubscriberManagerTest::SetUp()
{
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    notificationLocalLiveViewSubscriberManager_->AddLocalLiveViewSubscriber(subscriber_, info);
}

void NotificationLocalLiveViewSubscriberManagerTest::TearDown()
{
    notificationLocalLiveViewSubscriberManager_->RemoveLocalLiveViewSubscriber(subscriber_, nullptr);
}

/**
 * @tc.number    : NotificationLocalLiveViewSubscriberManagerTest_001
 * @tc.name      : ANS_AddSubscriber_001
 * @tc.desc      : Test AddSubscriber function, return is ERR_OK.
 */
HWTEST_F(NotificationLocalLiveViewSubscriberManagerTest,
    NotificationLocalLiveViewSubscriberManagerTest_001, Function | SmallTest | Level1)
{
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    EXPECT_EQ(notificationLocalLiveViewSubscriberManager_->AddLocalLiveViewSubscriber(subscriber_, info), (int)ERR_OK);
}

/**
 * @tc.number    : NotificationLocalLiveViewSubscriberManagerTest_002
 * @tc.name      : ANS_AddSubscriber_002
 * @tc.desc      : Test AddSubscriber function AND RemoveSubscriberInner, return is ERR_OK.
 */
HWTEST_F(NotificationLocalLiveViewSubscriberManagerTest,
    NotificationLocalLiveViewSubscriberManagerTest_002, Function | SmallTest | Level1)
{
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    EXPECT_EQ(notificationLocalLiveViewSubscriberManager_->AddLocalLiveViewSubscriber(subscriber_, info), (int)ERR_OK);
    EXPECT_EQ(notificationLocalLiveViewSubscriberManager_->
        RemoveLocalLiveViewSubscriber(subscriber_, info), (int)ERR_OK);
}

/**
 * @tc.number    : NotificationLocalLiveViewSubscriberManagerTest_003
 * @tc.name      : ANS_AddSubscriber_003
 * @tc.desc      : Test NotifyTriggerResponse, return is not nullptr.
 */
HWTEST_F(NotificationLocalLiveViewSubscriberManagerTest,
    NotificationLocalLiveViewSubscriberManagerTest_003, Function | SmallTest | Level1)
{
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    EXPECT_EQ(notificationLocalLiveViewSubscriberManager_->AddLocalLiveViewSubscriber(subscriber_, info), (int)ERR_OK);
    sptr<NotificationButtonOption> buttonOption = new NotificationButtonOption();
    sptr<NotificationRequest> request = new NotificationRequest();
    sptr<Notification> notification = new Notification(request);
    notificationLocalLiveViewSubscriberManager_->NotifyTriggerResponse(notification, buttonOption);
}
}  // namespace Notification
}  // namespace OHOS
