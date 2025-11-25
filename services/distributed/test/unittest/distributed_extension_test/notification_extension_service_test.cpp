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

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

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

class DummyRemote : public IRemoteObject {
public:
    DummyRemote() : IRemoteObject(u"dummy.remote") {}
    int GetObjectRefCount()
    {
        return 1;
    }
    bool AddDeathRecipient(const sptr<IRemoteObject::DeathRecipient> &recipient) override
    {
        recipient_ = recipient;
        return true;
    }
    bool RemoveDeathRecipient(const sptr<IRemoteObject::DeathRecipient> &recipient) override
    {
        if (recipient_ == recipient) {
            recipient_ = nullptr;
        }
        return true;
    }
    int SendRequest(uint32_t, MessageParcel &, MessageParcel &, MessageOption &) override
    {
        return ERR_OK;
    }
    int Dump(int, const std::vector<std::u16string> &)
    {
        return 0;
    }
    sptr<IRemoteObject::DeathRecipient> recipient_ = nullptr;
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
    subscriberInfo.uid = 1;
    subscriberInfo.userId = 1;

    auto connection = extensionServiceConnectionService.GetConnection(
        std::make_shared<ExtensionSubscriberInfo>(subscriberInfo));
    ASSERT_NE(connection, nullptr);
    auto& connectionMap = extensionServiceConnectionService.connectionMap_;
    ASSERT_TRUE(connectionMap.find("testBundle_testExtension_1_1") != connectionMap.end());

    extensionServiceConnectionService.RemoveConnection(subscriberInfo);
    ASSERT_TRUE(connectionMap.find("testBundle_testExtension_1_1") == connectionMap.end());
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

    std::string connectionKey = subscriberInfo.GetKey();
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
    ASSERT_TRUE(connectionMap.find("testBundle_testExtension_-1_1") != connectionMap.end());

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
    ASSERT_TRUE(connectionMap.find("testBundle_testExtension_-1_1") != connectionMap.end());

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
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto& subscriberMap = ExtensionServiceSubscribeService::GetInstance().subscriberMap_;
    ASSERT_TRUE(subscriberMap.find(key) != subscriberMap.end());
    ASSERT_TRUE(subscriberMap.find(key2) != subscriberMap.end());

    notificationExtensionService.UnsubscribeNotification(bundle);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    ASSERT_TRUE(subscriberMap.find(key) == subscriberMap.end());
    ASSERT_TRUE(subscriberMap.find(key2) != subscriberMap.end());
    notificationExtensionService.DestroyService();
}

/**
 * @tc.name   : NotificationExtensionService_SendHaReport_Callback_0100
 * @tc.number : NotificationExtensionService_SendHaReport_Callback_0100
 * @tc.desc   : Verify SendHaReport invokes haReportCallback with correct parameters when set.
 */
HWTEST_F(NotificationExtensionServiceTest, NotificationExtensionService_SendHaReport_Callback_0100,
    Function | SmallTest | Level1)
{
    auto &service = NotificationExtensionService::GetInstance();
    std::atomic<uint32_t> gotScene { 0 };
    std::atomic<uint32_t> gotBranch { 0 };
    std::atomic<int32_t> gotError { 0 };
    std::string gotMsg;
    service.InitService(nullptr, [&](uint32_t scene, uint32_t branch, int32_t error, std::string msg) {
        gotScene = scene;
        gotBranch = branch;
        gotError = error;
        gotMsg = msg;
    });
    uint32_t scene = 11;
    uint32_t branchId = 22;
    int32_t errorCode = -33;
    std::string message = "ha_test_msg";
    service.SendHaReport(scene, branchId, errorCode, message);
    ASSERT_EQ(gotScene.load(), scene);
    ASSERT_EQ(gotBranch.load(), branchId);
    ASSERT_EQ(gotError.load(), errorCode);
    ASSERT_EQ(gotMsg, message);
    service.DestroyService();
}

/**
 * @tc.name   : NotificationExtensionService_SendHaReport_NoCallback_0100
 * @tc.number : NotificationExtensionService_SendHaReport_NoCallback_0100
 * @tc.desc   : Verify SendHaReport does nothing when haReportCallback not set.
 */
HWTEST_F(NotificationExtensionServiceTest, NotificationExtensionService_SendHaReport_NoCallback_0100,
    Function | SmallTest | Level1)
{
    auto &service = NotificationExtensionService::GetInstance();
    std::atomic<int> flag { 0 };
    service.InitService(nullptr, [&](uint32_t, uint32_t, int32_t, std::string) { flag = 1; });
    service.SendHaReport(1, 2, 3, "msg1");
    ASSERT_EQ(flag.load(), 1);
    service.InitService(nullptr, nullptr);
    flag = 0;
    service.SendHaReport(9, 9, 9, "unused");
    ASSERT_EQ(flag.load(), 0);
    service.DestroyService();
}

/**
 * @tc.name   : ExtensionServiceConnectionTimerInfo_SetType_0100
 * @tc.number : ExtensionServiceConnectionTimerInfo_SetType_0100
 * @tc.desc   : Test SetType sets type correctly.
 */
HWTEST_F(
    NotificationExtensionServiceTest, ExtensionServiceConnectionTimerInfo_SetType_0100, Function | SmallTest | Level1)
{
    ExtensionServiceConnectionTimerInfo info([]() {});
    int type = 123;
    info.SetType(type);
    ASSERT_EQ(info.type, type);
}

/**
 * @tc.name   : ExtensionServiceConnectionTimerInfo_SetRepeat_0100
 * @tc.number : ExtensionServiceConnectionTimerInfo_SetRepeat_0100
 * @tc.desc   : Test SetRepeat sets repeat correctly.
 */
HWTEST_F(
    NotificationExtensionServiceTest, ExtensionServiceConnectionTimerInfo_SetRepeat_0100, Function | SmallTest | Level1)
{
    ExtensionServiceConnectionTimerInfo info([]() {});
    info.SetRepeat(true);
    ASSERT_TRUE(info.repeat);
    info.SetRepeat(false);
    ASSERT_FALSE(info.repeat);
}

/**
 * @tc.name   : ExtensionServiceConnectionTimerInfo_SetInterval_0100
 * @tc.number : ExtensionServiceConnectionTimerInfo_SetInterval_0100
 * @tc.desc   : Test SetInterval sets interval correctly.
 */
HWTEST_F(NotificationExtensionServiceTest, ExtensionServiceConnectionTimerInfo_SetInterval_0100,
    Function | SmallTest | Level1)
{
    ExtensionServiceConnectionTimerInfo info([]() {});
    uint64_t interval = 99999;
    info.SetInterval(interval);
    ASSERT_EQ(info.interval, interval);
}

/**
 * @tc.name   : ExtensionServiceConnectionTimerInfo_SetWantAgent_0100
 * @tc.number : ExtensionServiceConnectionTimerInfo_SetWantAgent_0100
 * @tc.desc   : Test SetWantAgent sets wantAgent correctly.
 */
HWTEST_F(NotificationExtensionServiceTest, ExtensionServiceConnectionTimerInfo_SetWantAgent_0100,
    Function | SmallTest | Level1)
{
    ExtensionServiceConnectionTimerInfo info([]() {});
    auto wantAgent = std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    info.SetWantAgent(wantAgent);
    ASSERT_EQ(info.wantAgent, wantAgent);
}

/**
 * @tc.name   : ExtensionServiceConnectionTimerInfo_OnTrigger_0100
 * @tc.number : ExtensionServiceConnectionTimerInfo_OnTrigger_0100
 * @tc.desc   : Test OnTrigger calls callback correctly.
 */
HWTEST_F(
    NotificationExtensionServiceTest, ExtensionServiceConnectionTimerInfo_OnTrigger_0100, Function | SmallTest | Level1)
{
    bool called = false;
    ExtensionServiceConnectionTimerInfo info([&called]() { called = true; });
    info.OnTrigger();
    ASSERT_TRUE(called);
}

/**
 * @tc.name   : ExtensionServiceConnection_OnAbilityConnectDone_0100
 * @tc.number : ExtensionServiceConnection_OnAbilityConnectDone_0100
 * @tc.desc   : Test OnAbilityConnectDone sets state connected and flushes cached messages.
 */
HWTEST_F(NotificationExtensionServiceTest, ExtensionServiceConnection_OnAbilityConnectDone_0100,
    Function | SmallTest | Level1)
{
    bool disconnectedCalled = false;
    ExtensionSubscriberInfo info;
    info.bundleName = "bundleA";
    info.extensionName = "extA";
    info.userId = 1;
    info.uid = 10;
    sptr<ExtensionServiceConnection> connection = new (std::nothrow)
        ExtensionServiceConnection(info, [&](const ExtensionSubscriberInfo &) { disconnectedCalled = true; });
    ASSERT_NE(connection, nullptr);
    sptr<NotificationRequest> request = new NotificationRequest(1);
    connection->state_ = ExtensionServiceConnectionState::CONNECTING;
    connection->NotifyOnReceiveMessage(request);
    sptr<IRemoteObject> remote = new DummyRemote();
    AppExecFwk::ElementName element("device", info.bundleName, info.extensionName);
    connection->OnAbilityConnectDone(element, remote, 0);
    ASSERT_EQ(connection->state_, ExtensionServiceConnectionState::CONNECTED);
    ASSERT_TRUE(connection->messages_.empty());
    ASSERT_EQ(connection->remoteObject_, remote);
    for (int i = 0; i < 50; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    connection->Close();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    connection = nullptr;
}

/**
 * @tc.name   : ExtensionServiceConnection_OnAbilityDisconnectDone_0100
 * @tc.number : ExtensionServiceConnection_OnAbilityDisconnectDone_0100
 * @tc.desc   : Test OnAbilityDisconnectDone sets state disconnected and invokes callback via Close logic.
 */
HWTEST_F(NotificationExtensionServiceTest, ExtensionServiceConnection_OnAbilityDisconnectDone_0100,
    Function | SmallTest | Level1)
{
    bool disconnectedCalled = false;
    ExtensionSubscriberInfo info;
    info.bundleName = "bundleB";
    info.extensionName = "extB";
    info.userId = 2;
    info.uid = 11;
    sptr<ExtensionServiceConnection> connection = new (std::nothrow)
        ExtensionServiceConnection(info, [&](const ExtensionSubscriberInfo &) { disconnectedCalled = true; });
    ASSERT_NE(connection, nullptr);
    sptr<IRemoteObject> remote = new DummyRemote();
    AppExecFwk::ElementName element("device", info.bundleName, info.extensionName);
    connection->OnAbilityConnectDone(element, remote, 0);
    ASSERT_EQ(connection->state_, ExtensionServiceConnectionState::CONNECTED);
    connection->OnAbilityDisconnectDone(element, 0);
    ASSERT_EQ(connection->state_, ExtensionServiceConnectionState::DISCONNECTED);
    ASSERT_TRUE(disconnectedCalled);
    connection->Close();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    connection = nullptr;
}

/**
 * @tc.name   : ExtensionServiceConnection_SetExtensionLifecycleDestroyTime_0100
 * @tc.number : ExtensionServiceConnection_SetExtensionLifecycleDestroyTime_0100
 * @tc.desc   : Test SetExtensionLifecycleDestroyTime rejects small value and accepts valid value.
 */
HWTEST_F(NotificationExtensionServiceTest, ExtensionServiceConnection_SetExtensionLifecycleDestroyTime_0100,
    Function | SmallTest | Level1)
{
    uint32_t original = ExtensionServiceConnection::DISCONNECT_DELAY_TIME;
    ExtensionServiceConnection::SetExtensionLifecycleDestroyTime(1);
    ASSERT_EQ(ExtensionServiceConnection::DISCONNECT_DELAY_TIME, 1800u);
    ExtensionServiceConnection::SetExtensionLifecycleDestroyTime(4000);
    ASSERT_EQ(ExtensionServiceConnection::DISCONNECT_DELAY_TIME, 4000u);
    ExtensionServiceConnection::DISCONNECT_DELAY_TIME = original;
}

/**
 * @tc.name   : ExtensionServiceConnection_AppendMessage_0100
 * @tc.number : ExtensionServiceConnection_AppendMessage_0100
 * @tc.desc   : Test AppendMessage message suffix according to callResult and retResult.
 */
HWTEST_F(NotificationExtensionServiceTest, ExtensionServiceConnection_AppendMessage_0100, Function | SmallTest | Level1)
{
    std::string msg1 = "base";
    ExtensionServiceConnection::AppendMessage(msg1, ERR_OK, ERR_OK);
    ASSERT_TRUE(msg1.find(" OK") != std::string::npos);
    std::string msg2 = "base";
    ExtensionServiceConnection::AppendMessage(msg2, ERR_INVALID_DATA, ERR_OK);
    ASSERT_TRUE(msg2.find("callResult") != std::string::npos);
    std::string msg3 = "base";
    ExtensionServiceConnection::AppendMessage(msg3, ERR_OK, ERR_INVALID_DATA);
    ASSERT_TRUE(msg3.find("retResult") != std::string::npos);
}

/**
 * @tc.name   : ExtensionServiceConnection_HandleDisconnectedState_0100
 * @tc.number : ExtensionServiceConnection_HandleDisconnectedState_0100
 * @tc.desc   : Test HandleDisconnectedState clears remote and invokes onDisconnected.
 */
HWTEST_F(NotificationExtensionServiceTest, ExtensionServiceConnection_HandleDisconnectedState_0100,
    Function | SmallTest | Level1)
{
    bool disconnectedCalled = false;
    ExtensionSubscriberInfo info;
    info.bundleName = "bundleC";
    info.extensionName = "extC";
    info.userId = 3;
    info.uid = 12;
    sptr<ExtensionServiceConnection> connection = new (std::nothrow)
        ExtensionServiceConnection(info, [&](const ExtensionSubscriberInfo &) { disconnectedCalled = true; });
    ASSERT_NE(connection, nullptr);
    connection->remoteObject_ = new DummyRemote();
    connection->HandleDisconnectedState();
    ASSERT_EQ(connection->remoteObject_, nullptr);
    ASSERT_TRUE(disconnectedCalled);
    connection = nullptr;
}

/**
 * @tc.name   : ExtensionServiceConnection_OnRemoteDied_0100
 * @tc.number : ExtensionServiceConnection_OnRemoteDied_0100
 * @tc.desc   : Test OnRemoteDied changes state to DISCONNECTED and triggers Close path.
 */
HWTEST_F(NotificationExtensionServiceTest, ExtensionServiceConnection_OnRemoteDied_0100, Function | SmallTest | Level1)
{
    bool disconnectedCalled = false;
    ExtensionSubscriberInfo info;
    info.bundleName = "bundleD";
    info.extensionName = "extD";
    info.userId = 4;
    info.uid = 13;
    sptr<ExtensionServiceConnection> connection = new (std::nothrow)
        ExtensionServiceConnection(info, [&](const ExtensionSubscriberInfo &) { disconnectedCalled = true; });
    ASSERT_NE(connection, nullptr);
    sptr<IRemoteObject> remote = new DummyRemote();
    AppExecFwk::ElementName element("device", info.bundleName, info.extensionName);
    connection->OnAbilityConnectDone(element, remote, 0);
    ASSERT_EQ(connection->state_, ExtensionServiceConnectionState::CONNECTED);
    wptr<IRemoteObject> wRemote = remote;
    connection->OnRemoteDied(wRemote);
    ASSERT_EQ(connection->state_, ExtensionServiceConnectionState::DISCONNECTED);
    ASSERT_TRUE(disconnectedCalled);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    remote = nullptr;
    connection = nullptr;
}

/**
 * @tc.name   : ExtensionServiceConnection_FreezeUnfreeze_0100
 * @tc.number : ExtensionServiceConnection_FreezeUnfreeze_0100
 * @tc.desc   : Test Freeze and Unfreeze call DoFreezeUnfreeze with correct flag.
 */
HWTEST_F(
    NotificationExtensionServiceTest, ExtensionServiceConnection_FreezeUnfreeze_0100, Function | SmallTest | Level1)
{
    ExtensionSubscriberInfo info;
    info.bundleName = "bundleE";
    info.extensionName = "extE";
    info.userId = 5;
    info.uid = 14;
    ExtensionServiceConnection connection(info, [](const ExtensionSubscriberInfo &) {});
    connection.state_ = ExtensionServiceConnectionState::CONNECTED;
    connection.Freeze();
    connection.Unfreeze();
    ASSERT_EQ(connection.state_, ExtensionServiceConnectionState::CONNECTED);
    ASSERT_EQ(connection.remoteObject_, nullptr);
}

/**
 * @tc.name   : ExtensionServiceConnection_PrepareFreezeDisconnect_0100
 * @tc.number : ExtensionServiceConnection_PrepareFreezeDisconnect_0100
 * @tc.desc   : Test PrepareFreeze and PrepareDisconnect do not crash when timer client missing.
 */
HWTEST_F(NotificationExtensionServiceTest, ExtensionServiceConnection_PrepareFreezeDisconnect_0100,
    Function | SmallTest | Level1)
{
    ExtensionSubscriberInfo info;
    info.bundleName = "bundleF";
    info.extensionName = "extF";
    info.userId = 6;
    info.uid = 15;
    ExtensionServiceConnection connection(info, [](const ExtensionSubscriberInfo &) {});
    connection.state_ = ExtensionServiceConnectionState::CONNECTED;
    connection.PrepareFreeze();
    connection.PrepareDisconnect();
    ASSERT_EQ(connection.state_, ExtensionServiceConnectionState::CONNECTED);
    ASSERT_EQ(connection.remoteObject_, nullptr);
}

/**
 * @tc.name   : ExtensionServiceConnection_Disconnect_0100
 * @tc.number : ExtensionServiceConnection_Disconnect_0100
 * @tc.desc   : Test Disconnect submits async task and removes death recipient.
 */
HWTEST_F(NotificationExtensionServiceTest, ExtensionServiceConnection_Disconnect_0100, Function | SmallTest | Level1)
{
    ExtensionSubscriberInfo info;
    info.bundleName = "bundleG";
    info.extensionName = "extG";
    info.userId = 7;
    info.uid = 16;
    sptr<ExtensionServiceConnection> connection =
        new (std::nothrow) ExtensionServiceConnection(info, [](const ExtensionSubscriberInfo &) {});
    ASSERT_NE(connection, nullptr);
    connection->state_ = ExtensionServiceConnectionState::CONNECTED;
    connection->remoteObject_ = new DummyRemote();
    ASSERT_NE(connection->remoteObject_, nullptr);
    connection->Disconnect();
    for (int i = 0; i < 50 && connection->remoteObject_ != nullptr; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    ASSERT_EQ(connection->remoteObject_, nullptr);
    connection->Close();
    connection = nullptr;
}
} // namespace Notification
} // namespace OHOS