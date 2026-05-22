/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "extension_service_connection.h"
#include "notification_bundle_option.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {

class ExtensionServiceConnectionTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: ExtensionServiceConnection_Close_ConnectedState_00001
 * @tc.desc: Test Close when state is CONNECTED calls DisconnectAbility
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(ExtensionServiceConnectionTest, ExtensionServiceConnection_Close_ConnectedState_00001,
    Function | SmallTest | Level1)
{
    ExtensionSubscriberInfo info;
    info.bundleName = "testBundle";
    info.extensionName = "testExtension";
    info.uid = 100;
    info.userId = 100;
    
    auto connection = std::make_shared<ExtensionServiceConnection>(info, nullptr);
    connection->state_ = ExtensionServiceConnectionState::CONNECTED;
    
    connection->Close();
    
    EXPECT_NE(connection->state_, ExtensionServiceConnectionState::CONNECTED);
}

/**
 * @tc.name: ExtensionServiceConnection_PrepareFreeze_StateNotConnected_00001
 * @tc.desc: Test PrepareFreeze returns early when state is not CONNECTED
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(ExtensionServiceConnectionTest, ExtensionServiceConnection_PrepareFreeze_StateNotConnected_00001,
    Function | SmallTest | Level1)
{
    ExtensionSubscriberInfo info;
    info.bundleName = "testBundle";
    info.extensionName = "testExtension";
    info.uid = 101;
    info.userId = 101;
    
    auto connection = std::make_shared<ExtensionServiceConnection>(info, nullptr);
    connection->state_ = ExtensionServiceConnectionState::CREATED;
    
    connection->PrepareFreeze();
    
    EXPECT_EQ(connection->state_, ExtensionServiceConnectionState::CREATED);
}

/**
 * @tc.name: ExtensionServiceConnection_OnAbilityConnectDone_UnknownMessageType_00001
 * @tc.desc: Test OnAbilityConnectDone handles unknown NotifyType in default case
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(ExtensionServiceConnectionTest, ExtensionServiceConnection_OnAbilityConnectDone_UnknownMessageType_00001,
    Function | SmallTest | Level1)
{
    ExtensionSubscriberInfo info;
    info.bundleName = "testBundle";
    info.extensionName = "testExtension";
    info.uid = 102;
    info.userId = 102;
    
    auto connection = std::make_shared<ExtensionServiceConnection>(info, nullptr);
    
    ExtensionServiceConnection::NotifyParam param;
    connection->messages_.emplace_back(static_cast<ExtensionServiceConnection::NotifyType>(9999), param);
    
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("testBundle");
    elementName.SetAbilityName("testExtension");
    
    sptr<OHOS::IRemoteObject> remoteObject = nullptr;
    
    connection->OnAbilityConnectDone(elementName, remoteObject, 0);
    
    EXPECT_EQ(connection->messages_.size(), 0);
}

} // namespace Notification
} // namespace OHOS