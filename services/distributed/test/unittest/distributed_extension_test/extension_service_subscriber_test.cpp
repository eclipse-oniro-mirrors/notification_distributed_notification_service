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
    NotificationBundleOption bundle("bundleCtor", 2000);
    ExtensionServiceSubscriber subscriber(bundle);
    ASSERT_NE(subscriber.messageQueue_, nullptr);
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnDied_0100
 * @tc.number : ExtensionServiceSubscriber_OnDied_0100
 * @tc.desc   : OnDied should execute without throwing and not alter connections.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnDied_0100, Function | SmallTest | Level1)
{
    NotificationBundleOption bundle("bundleDied", 2001);
    ExtensionServiceSubscriber subscriber(bundle);
    auto beforeSize = ExtensionServiceConnectionService::GetInstance().connectionMap_.size();
    subscriber.OnDied();
    ASSERT_EQ(beforeSize, ExtensionServiceConnectionService::GetInstance().connectionMap_.size());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnConnected_OnDisconnected_0100
 * @tc.number : ExtensionServiceSubscriber_OnConnected_OnDisconnected_0100
 * @tc.desc   : OnConnected/OnDisconnected should not modify connection map.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnConnected_OnDisconnected_0100,
    Function | SmallTest | Level1)
{
    NotificationBundleOption bundle("bundleConn", 2002);
    ExtensionServiceSubscriber subscriber(bundle);
    auto beforeSize = ExtensionServiceConnectionService::GetInstance().connectionMap_.size();
    subscriber.OnConnected();
    subscriber.OnDisconnected();
    ASSERT_EQ(beforeSize, ExtensionServiceConnectionService::GetInstance().connectionMap_.size());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnUpdate_0100
 * @tc.number : ExtensionServiceSubscriber_OnUpdate_0100
 * @tc.desc   : OnUpdate no-op path.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnUpdate_0100, Function | SmallTest | Level1)
{
    NotificationBundleOption bundle("bundleUpd", 2003);
    ExtensionServiceSubscriber subscriber(bundle);
    auto beforeInfos = subscriber.extensionSubscriberInfos_.size();
    auto beforeConnSize = ExtensionServiceConnectionService::GetInstance().connectionMap_.size();
    subscriber.OnUpdate(nullptr);
    ASSERT_EQ(beforeInfos, subscriber.extensionSubscriberInfos_.size());
    ASSERT_EQ(beforeConnSize, ExtensionServiceConnectionService::GetInstance().connectionMap_.size());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnDoNotDisturbDateChange_0100
 * @tc.number : ExtensionServiceSubscriber_OnDoNotDisturbDateChange_0100
 * @tc.desc   : OnDoNotDisturbDateChange no-op path.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnDoNotDisturbDateChange_0100,
    Function | SmallTest | Level1)
{
    NotificationBundleOption bundle("bundleDnd", 2004);
    ExtensionServiceSubscriber subscriber(bundle);
    auto beforeInfos = subscriber.extensionSubscriberInfos_.size();
    auto beforeConnSize = ExtensionServiceConnectionService::GetInstance().connectionMap_.size();
    subscriber.OnDoNotDisturbDateChange(nullptr);
    ASSERT_EQ(beforeInfos, subscriber.extensionSubscriberInfos_.size());
    ASSERT_EQ(beforeConnSize, ExtensionServiceConnectionService::GetInstance().connectionMap_.size());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnEnabledNotificationChanged_0100
 * @tc.number : ExtensionServiceSubscriber_OnEnabledNotificationChanged_0100
 * @tc.desc   : OnEnabledNotificationChanged no-op path.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnEnabledNotificationChanged_0100,
    Function | SmallTest | Level1)
{
    NotificationBundleOption bundle("bundleEn", 2005);
    ExtensionServiceSubscriber subscriber(bundle);
    auto beforeInfos = subscriber.extensionSubscriberInfos_.size();
    auto beforeConnSize = ExtensionServiceConnectionService::GetInstance().connectionMap_.size();
    subscriber.OnEnabledNotificationChanged(nullptr);
    ASSERT_EQ(beforeInfos, subscriber.extensionSubscriberInfos_.size());
    ASSERT_EQ(beforeConnSize, ExtensionServiceConnectionService::GetInstance().connectionMap_.size());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnBadgeChanged_0100
 * @tc.number : ExtensionServiceSubscriber_OnBadgeChanged_0100
 * @tc.desc   : OnBadgeChanged no-op path.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnBadgeChanged_0100, Function | SmallTest | Level1)
{
    NotificationBundleOption bundle("bundleBadge", 2006);
    ExtensionServiceSubscriber subscriber(bundle);
    auto beforeInfos = subscriber.extensionSubscriberInfos_.size();
    auto beforeConnSize = ExtensionServiceConnectionService::GetInstance().connectionMap_.size();
    subscriber.OnBadgeChanged(nullptr);
    ASSERT_EQ(beforeInfos, subscriber.extensionSubscriberInfos_.size());
    ASSERT_EQ(beforeConnSize, ExtensionServiceConnectionService::GetInstance().connectionMap_.size());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnBadgeEnabledChanged_0100
 * @tc.number : ExtensionServiceSubscriber_OnBadgeEnabledChanged_0100
 * @tc.desc   : OnBadgeEnabledChanged no-op path.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnBadgeEnabledChanged_0100,
    Function | SmallTest | Level1)
{
    NotificationBundleOption bundle("bundleBadgeEn", 2007);
    ExtensionServiceSubscriber subscriber(bundle);
    auto beforeInfos = subscriber.extensionSubscriberInfos_.size();
    auto beforeConnSize = ExtensionServiceConnectionService::GetInstance().connectionMap_.size();
    subscriber.OnBadgeEnabledChanged(nullptr);
    ASSERT_EQ(beforeInfos, subscriber.extensionSubscriberInfos_.size());
    ASSERT_EQ(beforeConnSize, ExtensionServiceConnectionService::GetInstance().connectionMap_.size());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnBatchCanceled_0100
 * @tc.number : ExtensionServiceSubscriber_OnBatchCanceled_0100
 * @tc.desc   : OnBatchCanceled no-op path.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnBatchCanceled_0100, Function | SmallTest | Level1)
{
    NotificationBundleOption bundle("bundleBatch", 2008);
    ExtensionServiceSubscriber subscriber(bundle);
    std::vector<std::shared_ptr<Notification>> emptyList;
    auto beforeInfos = subscriber.extensionSubscriberInfos_.size();
    auto beforeConnSize = ExtensionServiceConnectionService::GetInstance().connectionMap_.size();
    subscriber.OnBatchCanceled(emptyList, nullptr, 0);
    ASSERT_EQ(beforeInfos, subscriber.extensionSubscriberInfos_.size());
    ASSERT_EQ(beforeConnSize, ExtensionServiceConnectionService::GetInstance().connectionMap_.size());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnApplicationInfoNeedChanged_0100
 * @tc.number : ExtensionServiceSubscriber_OnApplicationInfoNeedChanged_0100
 * @tc.desc   : OnApplicationInfoNeedChanged no-op path.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnApplicationInfoNeedChanged_0100,
    Function | SmallTest | Level1)
{
    NotificationBundleOption bundle("bundleAppNeed", 2009);
    ExtensionServiceSubscriber subscriber(bundle);
    auto beforeInfos = subscriber.extensionSubscriberInfos_.size();
    auto beforeConnSize = ExtensionServiceConnectionService::GetInstance().connectionMap_.size();
    subscriber.OnApplicationInfoNeedChanged("bundleAppNeed");
    ASSERT_EQ(beforeInfos, subscriber.extensionSubscriberInfos_.size());
    ASSERT_EQ(beforeConnSize, ExtensionServiceConnectionService::GetInstance().connectionMap_.size());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnOperationResponse_0100
 * @tc.number : ExtensionServiceSubscriber_OnOperationResponse_0100
 * @tc.desc   : OnOperationResponse should return ERR_OK.
 */
HWTEST_F(
    ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnOperationResponse_0100, Function | SmallTest | Level1)
{
    NotificationBundleOption bundle("bundleOp", 2010);
    ExtensionServiceSubscriber subscriber(bundle);
    auto ret = subscriber.OnOperationResponse(nullptr);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnConsumed_Normal_0100
 * @tc.number : ExtensionServiceSubscriber_OnConsumed_Normal_0100
 * @tc.desc   : OnConsumed should create connection for each injected subscriber info.
 */
HWTEST_F(
    ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnConsumed_Normal_0100, Function | SmallTest | Level1)
{
    NotificationBundleOption bundle("bundleA", 1000);
    ExtensionServiceSubscriber subscriber(bundle);
    auto info = std::make_shared<ExtensionSubscriberInfo>();
    info->bundleName = "bundleA";
    info->extensionName = "extA";
    info->uid = 1000;
    info->userId = 1;
    subscriber.extensionSubscriberInfos_.push_back(info);

    auto notification = CreateNotification(1);
    ASSERT_NE(notification, nullptr);
    ExtensionServiceConnectionService &svc = ExtensionServiceConnectionService::GetInstance();
    std::string key = info->bundleName + "_" + info->extensionName + "_" + std::to_string(info->userId);
    ASSERT_TRUE(svc.connectionMap_.find(key) == svc.connectionMap_.end());

    subscriber.OnConsumed(notification, nullptr);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    ASSERT_TRUE(svc.connectionMap_.find(key) != svc.connectionMap_.end());

    svc.RemoveConnection(*info);
    ASSERT_TRUE(svc.connectionMap_.find(key) == svc.connectionMap_.end());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnConsumed_NullRequest_0100
 * @tc.number : ExtensionServiceSubscriber_OnConsumed_NullRequest_0100
 * @tc.desc   : OnConsumed with nullptr request should not create connection.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnConsumed_NullRequest_0100,
    Function | SmallTest | Level1)
{
    NotificationBundleOption bundle("bundleB", 1001);
    ExtensionServiceSubscriber subscriber(bundle);
    auto info = std::make_shared<ExtensionSubscriberInfo>();
    info->bundleName = "bundleB";
    info->extensionName = "extB";
    info->uid = 1001;
    info->userId = 2;
    subscriber.extensionSubscriberInfos_.push_back(info);
    ExtensionServiceConnectionService &svc = ExtensionServiceConnectionService::GetInstance();
    std::string key = info->bundleName + "_" + info->extensionName + "_" + std::to_string(info->userId);

    subscriber.OnConsumed(nullptr, nullptr);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    ASSERT_TRUE(svc.connectionMap_.find(key) == svc.connectionMap_.end());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnCanceled_Normal_0100
 * @tc.number : ExtensionServiceSubscriber_OnCanceled_Normal_0100
 * @tc.desc   : OnCanceled should create connection and push hash code.
 */
HWTEST_F(
    ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnCanceled_Normal_0100, Function | SmallTest | Level1)
{
    NotificationBundleOption bundle("bundleC", 1002);
    ExtensionServiceSubscriber subscriber(bundle);
    auto info = std::make_shared<ExtensionSubscriberInfo>();
    info->bundleName = "bundleC";
    info->extensionName = "extC";
    info->uid = 1002;
    info->userId = 3;
    subscriber.extensionSubscriberInfos_.push_back(info);
    auto notification = CreateNotification(2);
    ExtensionServiceConnectionService &svc = ExtensionServiceConnectionService::GetInstance();
    std::string key = info->bundleName + "_" + info->extensionName + "_" + std::to_string(info->userId);
    ASSERT_TRUE(svc.connectionMap_.find(key) == svc.connectionMap_.end());

    subscriber.OnCanceled(notification, nullptr, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    ASSERT_TRUE(svc.connectionMap_.find(key) != svc.connectionMap_.end());

    svc.RemoveConnection(*info);
    ASSERT_TRUE(svc.connectionMap_.find(key) == svc.connectionMap_.end());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_OnCanceled_NullRequest_0100
 * @tc.number : ExtensionServiceSubscriber_OnCanceled_NullRequest_0100
 * @tc.desc   : OnCanceled with nullptr request should not create connection.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_OnCanceled_NullRequest_0100,
    Function | SmallTest | Level1)
{
    NotificationBundleOption bundle("bundleD", 1003);
    ExtensionServiceSubscriber subscriber(bundle);
    auto info = std::make_shared<ExtensionSubscriberInfo>();
    info->bundleName = "bundleD";
    info->extensionName = "extD";
    info->uid = 1003;
    info->userId = 4;
    subscriber.extensionSubscriberInfos_.push_back(info);
    ExtensionServiceConnectionService &svc = ExtensionServiceConnectionService::GetInstance();
    std::string key = info->bundleName + "_" + info->extensionName + "_" + std::to_string(info->userId);

    subscriber.OnCanceled(nullptr, nullptr, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    ASSERT_TRUE(svc.connectionMap_.find(key) == svc.connectionMap_.end());
}

/**
 * @tc.name   : ExtensionServiceSubscriber_Destructor_0100
 * @tc.number : ExtensionServiceSubscriber_Destructor_0100
 * @tc.desc   : Destructor should close existing connections.
 */
HWTEST_F(ExtensionServiceSubscriberTest, ExtensionServiceSubscriber_Destructor_0100, Function | SmallTest | Level1)
{
    ExtensionSubscriberInfo injectedInfo;
    std::string key;
    {
        NotificationBundleOption bundle("bundleE", 1004);
        auto subscriber = std::make_unique<ExtensionServiceSubscriber>(bundle);
        auto info = std::make_shared<ExtensionSubscriberInfo>();
        info->bundleName = "bundleE";
        info->extensionName = "extE";
        info->uid = 1004;
        info->userId = 5;
        key = info->bundleName + "_" + info->extensionName + "_" + std::to_string(info->userId);
        subscriber->extensionSubscriberInfos_.push_back(info);
        auto notification = CreateNotification(3);
        subscriber->OnConsumed(notification, nullptr);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        ASSERT_TRUE(ExtensionServiceConnectionService::GetInstance().connectionMap_.find(key) !=
                    ExtensionServiceConnectionService::GetInstance().connectionMap_.end());
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    ASSERT_TRUE(ExtensionServiceConnectionService::GetInstance().connectionMap_.find(key) ==
                ExtensionServiceConnectionService::GetInstance().connectionMap_.end());
}
} // namespace Notification
} // namespace OHOS
