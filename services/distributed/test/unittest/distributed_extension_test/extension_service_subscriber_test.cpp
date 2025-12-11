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

#include <chrono>
#include <thread>
#include <vector>

#include "gtest/gtest.h"
#define private public
#include "extension_service_connection_service.h"
#include "extension_service_subscriber.h"
#include "notification.h"
#include "notification_bundle_option.h"
#include "notification_request.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
class ExtensionServiceSubscriberTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

static std::shared_ptr<Notification> CreateNotification(int32_t id)
{
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetNotificationId(id);
    return std::make_shared<Notification>(req);
}

/**
 * @tc.name   : ExtensionServiceSubscriber_Constructor_NoQueue_0100
 * @tc.number : ExtensionServiceSubscriber_Constructor_NoQueue_0100
 * @tc.desc   : Construct subscriber and verify messageQueue_ not null (basic ctor path).
 */
HWTEST_F(
    ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_Constructor_NoQueue_0100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleCtor", 2000);
    ExtensionServiceSubscriber subscriber;
    subscriber.Init(bundle);
    EXPECT_NE(subscriber.messageQueue_, nullptr);
    EXPECT_TRUE(subscriber.Init(bundle));
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnDied_0100
 * @tc.number : ExtensionServiceSubscriber_OnDied_0100
 * @tc.desc   : OnDied should execute without throwing and not alter connections.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnDied_0100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleDied", 2001);
    ExtensionServiceSubscriber subscriber;
    subscriber.Init(bundle);
    auto beforeSize = ExtensionServiceConnectionService::GetInstance().connectionMap_.size();
    subscriber.OnDied();
    EXPECT_EQ(beforeSize, ExtensionServiceConnectionService::GetInstance().connectionMap_.size());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnConnected_OnDisconnected_0100
 * @tc.number : ExtensionServiceSubscriber_OnConnected_OnDisconnected_0100
 * @tc.desc   : OnConnected/OnDisconnected should not modify connection map.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnConnected_OnDisconnected_0100,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleConn", 2002);
    ExtensionServiceSubscriber subscriber;
    subscriber.Init(bundle);
    auto beforeSize = ExtensionServiceConnectionService::GetInstance().connectionMap_.size();
    subscriber.OnConnected();
    subscriber.OnDisconnected();
    EXPECT_EQ(beforeSize, ExtensionServiceConnectionService::GetInstance().connectionMap_.size());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnUpdate_0100
 * @tc.number : ExtensionServiceSubscriber_OnUpdate_0100
 * @tc.desc   : OnUpdate no-op path.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnUpdate_0100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleUpd", 2003);
    ExtensionServiceSubscriber subscriber;
    subscriber.Init(bundle);
    auto beforeConnSize = ExtensionServiceConnectionService::GetInstance().connectionMap_.size();
    subscriber.OnUpdate(nullptr);
    EXPECT_EQ(beforeConnSize, ExtensionServiceConnectionService::GetInstance().connectionMap_.size());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnDoNotDisturbDateChange_0100
 * @tc.number : ExtensionServiceSubscriber_OnDoNotDisturbDateChange_0100
 * @tc.desc   : OnDoNotDisturbDateChange no-op path.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnDoNotDisturbDateChange_0100,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleDnd", 2004);
    ExtensionServiceSubscriber subscriber;
    subscriber.Init(bundle);
    auto beforeConnSize = ExtensionServiceConnectionService::GetInstance().connectionMap_.size();
    subscriber.OnDoNotDisturbDateChange(nullptr);
    EXPECT_EQ(beforeConnSize, ExtensionServiceConnectionService::GetInstance().connectionMap_.size());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnEnabledNotificationChanged_0100
 * @tc.number : ExtensionServiceSubscriber_OnEnabledNotificationChanged_0100
 * @tc.desc   : OnEnabledNotificationChanged no-op path.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnEnabledNotificationChanged_0100,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleEn", 2005);
    ExtensionServiceSubscriber subscriber;
    subscriber.Init(bundle);
    auto beforeConnSize = ExtensionServiceConnectionService::GetInstance().connectionMap_.size();
    subscriber.OnEnabledNotificationChanged(nullptr);
    EXPECT_EQ(beforeConnSize, ExtensionServiceConnectionService::GetInstance().connectionMap_.size());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnBadgeChanged_0100
 * @tc.number : ExtensionServiceSubscriber_OnBadgeChanged_0100
 * @tc.desc   : OnBadgeChanged no-op path.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnBadgeChanged_0100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleBadge", 2006);
    ExtensionServiceSubscriber subscriber;
    subscriber.Init(bundle);
    auto beforeConnSize = ExtensionServiceConnectionService::GetInstance().connectionMap_.size();
    subscriber.OnBadgeChanged(nullptr);
    EXPECT_EQ(beforeConnSize, ExtensionServiceConnectionService::GetInstance().connectionMap_.size());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnBadgeEnabledChanged_0100
 * @tc.number : ExtensionServiceSubscriber_OnBadgeEnabledChanged_0100
 * @tc.desc   : OnBadgeEnabledChanged no-op path.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnBadgeEnabledChanged_0100,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleBadgeEn", 2007);
    ExtensionServiceSubscriber subscriber;
    subscriber.Init(bundle);
    auto beforeConnSize = ExtensionServiceConnectionService::GetInstance().connectionMap_.size();
    subscriber.OnBadgeEnabledChanged(nullptr);
    EXPECT_EQ(beforeConnSize, ExtensionServiceConnectionService::GetInstance().connectionMap_.size());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnBatchCanceled_0100
 * @tc.number : ExtensionServiceSubscriber_OnBatchCanceled_0100
 * @tc.desc   : OnBatchCanceled no-op path.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnBatchCanceled_0100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleBatch", 2008);
    ExtensionServiceSubscriber subscriber;
    subscriber.Init(bundle);
    std::vector<std::shared_ptr<Notification>> emptyList;
    auto beforeConnSize = ExtensionServiceConnectionService::GetInstance().connectionMap_.size();
    subscriber.OnBatchCanceled(emptyList, nullptr, 0);
    EXPECT_EQ(beforeConnSize, ExtensionServiceConnectionService::GetInstance().connectionMap_.size());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnApplicationInfoNeedChanged_0100
 * @tc.number : ExtensionServiceSubscriber_OnApplicationInfoNeedChanged_0100
 * @tc.desc   : OnApplicationInfoNeedChanged no-op path.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnApplicationInfoNeedChanged_0100,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleAppNeed", 2009);
    ExtensionServiceSubscriber subscriber;
    subscriber.Init(bundle);
    auto beforeConnSize = ExtensionServiceConnectionService::GetInstance().connectionMap_.size();
    subscriber.OnApplicationInfoNeedChanged("bundleAppNeed");
    EXPECT_EQ(beforeConnSize, ExtensionServiceConnectionService::GetInstance().connectionMap_.size());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnOperationResponse_0100
 * @tc.number : ExtensionServiceSubscriber_OnOperationResponse_0100
 * @tc.desc   : OnOperationResponse should return ERR_OK.
 */
HWTEST_F(
    ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnOperationResponse_0100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleOp", 2010);
    ExtensionServiceSubscriber subscriber;
    subscriber.Init(bundle);
    auto ret = subscriber.OnOperationResponse(nullptr);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnConsumed_Normal_0100
 * @tc.number : ExtensionServiceSubscriber_OnConsumed_Normal_0100
 * @tc.desc   : OnConsumed should create connection for each injected subscriber info.
 */
HWTEST_F(
    ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnConsumed_Normal_0100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleA", 1000);
    ExtensionServiceSubscriber subscriber;
    subscriber.Init(bundle);
    auto info = std::make_shared<ExtensionSubscriberInfo>();
    info->bundleName = "bundleA";
    info->extensionName = "extA";
    info->uid = 1000;
    info->userId = 1;
    subscriber.extensionSubscriberInfo_ = info;

    auto notification = CreateNotification(1);
    EXPECT_NE(notification, nullptr);
    ExtensionServiceConnectionService &svc = ExtensionServiceConnectionService::GetInstance();
    std::string key = info->bundleName + "_" + info->extensionName + "_" +
        std::to_string(info->uid) + "_" + std::to_string(info->userId);
    EXPECT_TRUE(svc.connectionMap_.find(key) == svc.connectionMap_.end());

    subscriber.OnConsumed(notification, nullptr);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(svc.connectionMap_.find(key) != svc.connectionMap_.end());

    svc.RemoveConnection(*info);
    EXPECT_TRUE(svc.connectionMap_.find(key) == svc.connectionMap_.end());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnConsumed_NullRequest_0100
 * @tc.number : ExtensionServiceSubscriber_OnConsumed_NullRequest_0100
 * @tc.desc   : OnConsumed with nullptr request should not create connection.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnConsumed_NullRequest_0100,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleB", 1001);
    ExtensionServiceSubscriber subscriber;
    subscriber.Init(bundle);
    auto info = std::make_shared<ExtensionSubscriberInfo>();
    info->bundleName = "bundleB";
    info->extensionName = "extB";
    info->uid = 1001;
    info->userId = 2;
    subscriber.extensionSubscriberInfo_ = info;
    ExtensionServiceConnectionService &svc = ExtensionServiceConnectionService::GetInstance();
    std::string key = info->bundleName + "_" + info->extensionName + "_" + std::to_string(info->userId);

    subscriber.OnConsumed(nullptr, nullptr);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(svc.connectionMap_.find(key) == svc.connectionMap_.end());
}

HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnConsumed_NullSubscribeInfo_0100,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleB", 1001);
    ExtensionServiceSubscriber subscriber;
    subscriber.Init(bundle);
    auto info = std::make_shared<ExtensionSubscriberInfo>();
    info->bundleName = "bundleC";
    info->extensionName = "extC";
    info->uid = 1002;
    info->userId = 3;

    subscriber.extensionSubscriberInfo_ = nullptr;
    ExtensionServiceConnectionService &svc = ExtensionServiceConnectionService::GetInstance();
    std::string key = info->bundleName + "_" + info->extensionName + "_" + std::to_string(info->userId);
    auto notification = CreateNotification(1);

    subscriber.OnConsumed(notification, nullptr);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(svc.connectionMap_.find(key) == svc.connectionMap_.end());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnCanceled_Normal_0100
 * @tc.number : ExtensionServiceSubscriber_OnCanceled_Normal_0100
 * @tc.desc   : OnCanceled should create connection and push hash code.
 */
HWTEST_F(
    ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnCanceled_Normal_0100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleC", 1002);
    ExtensionServiceSubscriber subscriber;
    subscriber.Init(bundle);
    auto info = std::make_shared<ExtensionSubscriberInfo>();
    info->bundleName = "bundleC";
    info->extensionName = "extC";
    info->uid = 1002;
    info->userId = 3;
    subscriber.extensionSubscriberInfo_ = info;
    auto notification = CreateNotification(2);
    ExtensionServiceConnectionService &svc = ExtensionServiceConnectionService::GetInstance();
    std::string key = info->bundleName + "_" + info->extensionName + "_" +
        std::to_string(info->uid) + "_" + std::to_string(info->userId);
    EXPECT_TRUE(svc.connectionMap_.find(key) == svc.connectionMap_.end());

    subscriber.OnCanceled(notification, nullptr, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(svc.connectionMap_.find(key) != svc.connectionMap_.end());

    svc.RemoveConnection(*info);
    EXPECT_TRUE(svc.connectionMap_.find(key) == svc.connectionMap_.end());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnCanceled_NullRequest_0100
 * @tc.number : ExtensionServiceSubscriber_OnCanceled_NullRequest_0100
 * @tc.desc   : OnCanceled with nullptr request should not create connection.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnCanceled_NullRequest_0100,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleD", 1003);
    ExtensionServiceSubscriber subscriber;
    subscriber.Init(bundle);
    auto info = std::make_shared<ExtensionSubscriberInfo>();
    info->bundleName = "bundleD";
    info->extensionName = "extD";
    info->uid = 1003;
    info->userId = 4;
    subscriber.extensionSubscriberInfo_ = info;
    ExtensionServiceConnectionService &svc = ExtensionServiceConnectionService::GetInstance();
    std::string key = info->bundleName + "_" + info->extensionName + "_" + std::to_string(info->userId);

    subscriber.OnCanceled(nullptr, nullptr, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(svc.connectionMap_.find(key) == svc.connectionMap_.end());
}

HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnCanceled_NullSubscribeInfo_0100,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleD", 1003);
    ExtensionServiceSubscriber subscriber;
    subscriber.Init(bundle);
    auto info = std::make_shared<ExtensionSubscriberInfo>();
    info->bundleName = "bundleC";
    info->extensionName = "extC";
    info->uid = 1002;
    info->userId = 3;
    subscriber.extensionSubscriberInfo_ = nullptr;
    ExtensionServiceConnectionService &svc = ExtensionServiceConnectionService::GetInstance();
    std::string key = info->bundleName + "_" + info->extensionName + "_" + std::to_string(info->userId);
    auto notification = CreateNotification(2);

    subscriber.OnCanceled(notification, nullptr, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(svc.connectionMap_.find(key) == svc.connectionMap_.end());
}
} // namespace Notification
} // namespace OHOS
