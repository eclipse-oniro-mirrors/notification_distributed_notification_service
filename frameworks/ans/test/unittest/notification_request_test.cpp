/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "notification_request.h"
#undef private 
#undef protected
#include "want_agent_helper.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationRequestTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: NotificationGetWantAgent_0100
 * @tc.desc: GetWantAgent
 * @tc.type: FUNC
 * @tc.require: issueI5RW70
 */
HWTEST_F(NotificationRequestTest, NotificationGetWantAgent_0100, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent = notificationRequest.GetWantAgent();
    EXPECT_EQ(wantAgent, nullptr);
}

/**
 * @tc.name: NotificationSetMaxScreenWantAgent_0100
 * @tc.desc: SetMaxScreenWantAgent
 * @tc.type: FUNC
 * @tc.require: issueI5RW70
 */
HWTEST_F(NotificationRequestTest, NotificationSetMaxScreenWantAgent_0100, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent = notificationRequest.GetWantAgent();
    notificationRequest.SetMaxScreenWantAgent(wantAgent);
    auto result = notificationRequest.GetMaxScreenWantAgent();
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: NotificationGetAdditionalData_0100
 * @tc.desc: GetAdditionalData
 * @tc.type: FUNC
 * @tc.require: issueI5RW70
 */
HWTEST_F(NotificationRequestTest, NotificationGetAdditionalData_0100, Level1)
{
    int32_t myNotificationId = 10;
    std::shared_ptr<AAFwk::WantParams> additionalPtr;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetAdditionalData(additionalPtr);
    auto result = notificationRequest.GetAdditionalData();
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: NotificationSetIsAgentNotification_0100
 * @tc.desc: SetIsAgentNotification
 * @tc.type: FUNC
 * @tc.require: issueI5RW70
 */
HWTEST_F(NotificationRequestTest, NotificationSetIsAgentNotification_0100, Level1)
{
    int32_t myNotificationId = 10;
    bool isAgentTrue = true;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetIsAgentNotification(isAgentTrue);
    auto result = notificationRequest.IsAgentNotification();
    EXPECT_EQ(result, true);
    bool isAgentFalse = false;
    notificationRequest.SetIsAgentNotification(isAgentFalse);
    result = notificationRequest.IsAgentNotification();
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: NotificationOwnerUid_0100
 * @tc.desc: SetOwnerUid and GetOwnerUid
 * @tc.type: FUNC
 * @tc.require: issueI5RW70
 */
HWTEST_F(NotificationRequestTest, NotificationOwnerUid_0100, Level1)
{
    int32_t myNotificationId = 10;
    int32_t uid = 5;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetOwnerUid(uid);
    auto result = notificationRequest.GetOwnerUid();
    EXPECT_EQ(result, uid);
}

/**
 * @tc.name: NotificationOwnerUserId_0100
 * @tc.desc: SetOwnerUserId and GetOwnerUserId
 * @tc.type: FUNC
 * @tc.require: issueI5RW70
 */
HWTEST_F(NotificationRequestTest, NotificationOwnerUserId_0100, Level1)
{
    int32_t myNotificationId = 10;
    int32_t userid = 5;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetOwnerUserId(userid);
    auto result = notificationRequest.GetOwnerUserId();
    EXPECT_EQ(result, userid);
}

/**
 * @tc.name: NotificationMarshalling_0100
 * @tc.desc: Marshalling
 * @tc.type: FUNC
 * @tc.require: issueI5RW70
 */
HWTEST_F(NotificationRequestTest, NotificationMarshalling_0100, Level1)
{
    int32_t myNotificationId = 10;
    Parcel parcel;
    NotificationRequest notificationRequest(myNotificationId);
    auto result = notificationRequest.Marshalling(parcel);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: NotificationReadFromParcel_0100
 * @tc.desc: ReadFromParcel
 * @tc.type: FUNC
 * @tc.require: issueI5RW70
 */
HWTEST_F(NotificationRequestTest, NotificationReadFromParcel_0100, Level1)
{
    int32_t myNotificationId = 10;
    Parcel parcel;
    NotificationRequest notificationRequest(myNotificationId);
    auto result = notificationRequest.ReadFromParcel(parcel);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: NotificationSetReceiverUserId_0100
 * @tc.desc: SetReceiverUserId
 * @tc.type: FUNC
 * @tc.require: issueI5RW70
 */
HWTEST_F(NotificationRequestTest, NotificationSetReceiverUserId_0100, Level1)
{
    int32_t myNotificationId = 10;
    int32_t userid = 5;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetReceiverUserId(userid);
    auto result = notificationRequest.GetReceiverUserId();
    EXPECT_EQ(result, userid);
}
}
}
