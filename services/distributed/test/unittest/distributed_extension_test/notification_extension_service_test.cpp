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
#include "extension_service_connection_service.h"
#include "extension_service_subscribe_service.h"
#include "extension_service_connection_timer_info.h"
#include "extension_service.h"
#include "notification_request.h"
#include "notification_bundle_option.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
class NotificationExtensionServiceTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name   : GetConnectionTest_0100
 * @tc.number : GetConnectionTest_0100
 * @tc.desc   : Test GetConnection.
 */
HWTEST_F(NotificationExtensionServiceTest, GetConnectionTest_0100, Function | SmallTest | Level1)
{
    auto& extensionServiceConnectionService = ExtensionServiceConnectionService::GetInstance();
    ExtensionSubscriberInfo subscriberInfo;
    subscriberInfo.bundleName = "testBundle";
    subscriberInfo.extensionName = "testExtension";
    subscriberInfo.userId = 1;

    auto connection = extensionServiceConnectionService.GetConnection(
        std::make_shared<ExtensionSubscriberInfo>(subscriberInfo));
    ASSERT_NE(connection, nullptr);
    auto& connectionMap = extensionServiceConnectionService.connectionMap_;
    ASSERT_TRUE(connectionMap.find("testBundle_testExtension_1") != connectionMap.end());

    extensionServiceConnectionService.RemoveConnection(subscriberInfo);
    ASSERT_TRUE(connectionMap.find("testBundle_testExtension_1") == connectionMap.end());
}

/**
 * @tc.name   : GetConnectionTest_0200
 * @tc.number : GetConnectionTest_0200
 * @tc.desc   : Test GetConnection.
 */
HWTEST_F(NotificationExtensionServiceTest, GetConnectionTest_0200, Function | SmallTest | Level1)
{
    auto& extensionServiceConnectionService = ExtensionServiceConnectionService::GetInstance();
    ExtensionSubscriberInfo subscriberInfo;
    subscriberInfo.bundleName = "testBundle";
    subscriberInfo.extensionName = "testExtension";
    subscriberInfo.userId = 1;

    auto connection = extensionServiceConnectionService.GetConnection(
        std::make_shared<ExtensionSubscriberInfo>(subscriberInfo));
    ASSERT_NE(connection, nullptr);

    auto connection2 = extensionServiceConnectionService.GetConnection(
        std::make_shared<ExtensionSubscriberInfo>(subscriberInfo));
    auto& connectionMap = extensionServiceConnectionService.connectionMap_;
    ASSERT_TRUE(connectionMap.size() == 1);

    extensionServiceConnectionService.RemoveConnection(subscriberInfo);
    ASSERT_TRUE(connectionMap.empty());
}

/**
 * @tc.name   : CloseConnectionTest_0100
 * @tc.number : CloseConnectionTest_0100
 * @tc.desc   : Test CloseConnection.
 */
HWTEST_F(NotificationExtensionServiceTest, CloseConnectionTest_0100, Function | SmallTest | Level1)
{
    auto& extensionServiceConnectionService = ExtensionServiceConnectionService::GetInstance();
    ExtensionSubscriberInfo subscriberInfo;
    subscriberInfo.bundleName = "testBundle";
    subscriberInfo.extensionName = "testExtension";
    subscriberInfo.userId = 1;

    auto connection = extensionServiceConnectionService.GetConnection(
        std::make_shared<ExtensionSubscriberInfo>(subscriberInfo));
    ASSERT_NE(connection, nullptr);

    extensionServiceConnectionService.RemoveConnection(subscriberInfo);
    ASSERT_TRUE(extensionServiceConnectionService.connectionMap_.empty());
}

/**
 * @tc.name   : CloseConnectionTest_0200
 * @tc.number : CloseConnectionTest_0200
 * @tc.desc   : Test CloseConnection.
 */
HWTEST_F(NotificationExtensionServiceTest, CloseConnectionTest_0200, Function | SmallTest | Level1)
{
    auto& extensionServiceConnectionService = ExtensionServiceConnectionService::GetInstance();
    ExtensionSubscriberInfo subscriberInfo;
    subscriberInfo.bundleName = "testBundle";
    subscriberInfo.extensionName = "testExtension";
    subscriberInfo.userId = 1;

    ExtensionSubscriberInfo subscriberInfo2;
    subscriberInfo.bundleName = "testBundle2";
    subscriberInfo.extensionName = "testExtension2";
    subscriberInfo.userId = 2;

    auto connection = extensionServiceConnectionService.GetConnection(
        std::make_shared<ExtensionSubscriberInfo>(subscriberInfo));
    ASSERT_NE(connection, nullptr);

    extensionServiceConnectionService.CloseConnection(subscriberInfo2);
    auto& connectionMap = extensionServiceConnectionService.connectionMap_;
    ASSERT_FALSE(connectionMap.empty());

    extensionServiceConnectionService.RemoveConnection(subscriberInfo);
    ASSERT_TRUE(connectionMap.empty());
}

/**
 * @tc.name   : CloseConnectionTest_0300
 * @tc.number : CloseConnectionTest_0300
 * @tc.desc   : Test CloseConnection.
 */
HWTEST_F(NotificationExtensionServiceTest, CloseConnectionTest_0300, Function | SmallTest | Level1)
{
    auto& extensionServiceConnectionService = ExtensionServiceConnectionService::GetInstance();
    ExtensionSubscriberInfo subscriberInfo;
    subscriberInfo.bundleName = "testBundle";
    subscriberInfo.extensionName = "testExtension";
    subscriberInfo.userId = 1;

    std::string connectionKey = extensionServiceConnectionService.GetConnectionKey(subscriberInfo);
    extensionServiceConnectionService.connectionMap_.emplace(connectionKey, nullptr);
    extensionServiceConnectionService.CloseConnection(subscriberInfo);
    ASSERT_TRUE(extensionServiceConnectionService.connectionMap_.empty());
}

/**
 * @tc.name   : NotifyOnReceiveMessageTest_0100
 * @tc.number : NotifyOnReceiveMessageTest_0100
 * @tc.desc   : Test CloseConnection.
 */
HWTEST_F(NotificationExtensionServiceTest, NotifyOnReceiveMessageTest_0100, Function | SmallTest | Level1)
{
    auto& extensionServiceConnectionService = ExtensionServiceConnectionService::GetInstance();
    ExtensionSubscriberInfo subscriberInfo;
    subscriberInfo.bundleName = "testBundle";
    subscriberInfo.extensionName = "testExtension";
    subscriberInfo.userId = 1;
    sptr<NotificationRequest> request = new NotificationRequest(1);

    extensionServiceConnectionService.NotifyOnReceiveMessage(
        std::make_shared<ExtensionSubscriberInfo>(subscriberInfo), request);
    auto& connectionMap = extensionServiceConnectionService.connectionMap_;
    ASSERT_TRUE(connectionMap.find("testBundle_testExtension_1") != connectionMap.end());

    extensionServiceConnectionService.RemoveConnection(subscriberInfo);
    ASSERT_TRUE(connectionMap.empty());
}

/**
 * @tc.name   : NotifyOnCancelMessagesTest_0100
 * @tc.number : NotifyOnCancelMessagesTest_0100
 * @tc.desc   : Test CloseConnection.
 */
HWTEST_F(NotificationExtensionServiceTest, NotifyOnCancelMessagesTest_0100, Function | SmallTest | Level1)
{
    auto& extensionServiceConnectionService = ExtensionServiceConnectionService::GetInstance();
    ExtensionSubscriberInfo subscriberInfo;
    subscriberInfo.bundleName = "testBundle";
    subscriberInfo.extensionName = "testExtension";
    subscriberInfo.userId = 1;
    auto hashCodes = std::make_shared<std::vector<std::string>>(std::vector<std::string>{
        "hash123", "hash456", "hash789"
    });

    extensionServiceConnectionService.NotifyOnCancelMessages(
        std::make_shared<ExtensionSubscriberInfo>(subscriberInfo), hashCodes);
    auto& connectionMap = extensionServiceConnectionService.connectionMap_;
    ASSERT_TRUE(connectionMap.find("testBundle_testExtension_1") != connectionMap.end());

    extensionServiceConnectionService.RemoveConnection(subscriberInfo);
    ASSERT_TRUE(connectionMap.empty());
}

/**
 * @tc.name   : NotificationExtensionServiceTest_0100
 * @tc.number : NotificationExtensionServiceTest_0100
 * @tc.desc   : test NotificationExtensionService function.
 */
HWTEST_F(NotificationExtensionServiceTest, NotificationExtensionServiceTest_0100, Function | SmallTest | Level1)
{
    auto notificationExtensionService = NotificationExtensionService::GetInstance();
    notificationExtensionService.InitService(nullptr, nullptr);
    auto bundle = sptr<NotificationBundleOption>(new NotificationBundleOption("testBundle", 1));
    auto bundle2 = sptr<NotificationBundleOption>(new NotificationBundleOption("testBundle2", 2));
    std::vector<sptr<NotificationBundleOption>> subscribedBundles;
    subscribedBundles.emplace_back(new NotificationBundleOption("subscribedBundle", 1));
    std::vector<sptr<NotificationBundleOption>> subscribedBundles2;
    subscribedBundles2.emplace_back(new NotificationBundleOption("subscribedBundle2", 2));
    auto& extensionServiceSubscribeService = ExtensionServiceSubscribeService::GetInstance();
    std::string key = extensionServiceSubscribeService.MakeBundleKey(*bundle);
    std::string key2 = extensionServiceSubscribeService.MakeBundleKey(*bundle2);

    notificationExtensionService.SubscribeNotification(bundle, subscribedBundles);
    notificationExtensionService.SubscribeNotification(bundle2, subscribedBundles2);
    auto& subscriberMap = ExtensionServiceSubscribeService::GetInstance().subscriberMap_;
    ASSERT_TRUE(subscriberMap.find(key) != subscriberMap.end());
    ASSERT_TRUE(subscriberMap.find(key2) != subscriberMap.end());

    notificationExtensionService.UnsubscribeNotification(bundle);
    ASSERT_TRUE(subscriberMap.find(key) == subscriberMap.end());
    ASSERT_TRUE(subscriberMap.find(key2) != subscriberMap.end());
    notificationExtensionService.DestroyService();
}
} // namespace Notification
} // namespace OHOS