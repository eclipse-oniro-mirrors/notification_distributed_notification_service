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

/**
 * @tc.name: AddActionButton_0100
 * @tc.desc: AddActionButton
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, AddActionButton_0100, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    std::shared_ptr<NotificationActionButton> actionButton = nullptr;
    notificationRequest.AddActionButton(actionButton);
    AbilityRuntime::WantAgent::WantAgentInfo paramsInfo;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(paramsInfo);
    std::shared_ptr<NotificationActionButton> actionButton1 =
        NotificationActionButton::Create(nullptr, "title", wantAgent);
    notificationRequest.AddActionButton(actionButton1);
    std::shared_ptr<NotificationActionButton> actionButton2 =
        NotificationActionButton::Create(nullptr, "title2", wantAgent);
    notificationRequest.AddActionButton(actionButton2);
    std::shared_ptr<NotificationActionButton> actionButton3 =
        NotificationActionButton::Create(nullptr, "title3", wantAgent);
    notificationRequest.AddActionButton(actionButton3);
    std::vector<std::shared_ptr<NotificationActionButton>> result =
        notificationRequest.GetActionButtons();
    notificationRequest.ClearActionButtons();
    EXPECT_EQ(result.size(), 3);
}

/**
 * @tc.name: AddMessageUser_0100
 * @tc.desc: AddMessageUser
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, AddMessageUser_0100, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    std::shared_ptr<MessageUser> messageUser = nullptr;
    notificationRequest.AddMessageUser(messageUser);
    std::vector<std::shared_ptr<MessageUser>> result = notificationRequest.GetMessageUsers();
    EXPECT_EQ(result.size(), 0);
}

/**
 * @tc.name: SetColor_0100
 * @tc.desc: SetColor
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, SetColor_0100, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    uint32_t color = 1;
    notificationRequest.SetColor(color);
    uint32_t result = notificationRequest.GetColor();
    uint32_t ret = 4278190081;
    EXPECT_EQ(result, ret);
}

/**
 * @tc.name: IsColorEnabled_0100
 * @tc.desc: IsColorEnabled
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, IsColorEnabled_0100, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    notificationRequest.SetColorEnabled(true);
    notificationRequest.SetContent(nullptr);
    notificationRequest.GetContent();
    uint32_t result1 = notificationRequest.IsColorEnabled();
    EXPECT_EQ(result1, false);
}

/**
 * @tc.name: IsColorEnabled_0200
 * @tc.desc: IsColorEnabled
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, IsColorEnabled_0200, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    notificationRequest.SetColorEnabled(true);
    std::shared_ptr<NotificationMediaContent> mediaContent = std::make_shared<NotificationMediaContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(mediaContent);
    notificationRequest.SetContent(content);
    std::shared_ptr<NotificationContent> result = notificationRequest.GetContent();
    EXPECT_EQ(result, content);
    uint32_t result1 = notificationRequest.IsColorEnabled();
    EXPECT_EQ(result1, false);
}

/**
 * @tc.name: IsColorEnabled_0300
 * @tc.desc: IsColorEnabled
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, IsColorEnabled_0300, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    notificationRequest.SetColorEnabled(true);
    std::shared_ptr<NotificationPictureContent> pictureContent = std::make_shared<NotificationPictureContent>();
    std::shared_ptr<NotificationContent> content1 = std::make_shared<NotificationContent>(pictureContent);
    notificationRequest.SetContent(content1);
    std::shared_ptr<NotificationContent> result = notificationRequest.GetContent();
    EXPECT_EQ(result, content1);
    uint32_t result1 = notificationRequest.IsColorEnabled();
    EXPECT_EQ(result1, false);
}

/**
 * @tc.name: SetSettingsText_0100
 * @tc.desc: SetSettingsText
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, SetSettingsText_0100, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    std::shared_ptr<NotificationPictureContent> pictureContent = std::make_shared<NotificationPictureContent>();
    std::shared_ptr<NotificationContent> content1 = std::make_shared<NotificationContent>(pictureContent);
    notificationRequest.SetContent(content1);
    std::shared_ptr<NotificationContent> result = notificationRequest.GetContent();
    EXPECT_EQ(result, content1);
    std::string text = "text";
    notificationRequest.SetSettingsText(text);
    
    std::shared_ptr<NotificationLongTextContent> longTextContent =
        std::make_shared<NotificationLongTextContent>("longtext");
    std::shared_ptr<NotificationContent> content2 = std::make_shared<NotificationContent>(longTextContent);
    notificationRequest.SetContent(content2);
    std::shared_ptr<NotificationContent> result2 = notificationRequest.GetContent();
    EXPECT_EQ(result2, content2);
    notificationRequest.SetSettingsText(text);
}

/**
 * @tc.name: SetNotificationUserInputHistory_0100
 * @tc.desc: SetNotificationUserInputHistory
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, SetNotificationUserInputHistory_0100, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    std::vector<std::string> text;
    notificationRequest.SetNotificationUserInputHistory(text);
    std::vector<std::string> result = notificationRequest.GetNotificationUserInputHistory();
    EXPECT_EQ(result.size(), 0);
}

/**
 * @tc.name: GetNotificationHashCode_0100
 * @tc.desc: GetNotificationHashCode
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, GetNotificationHashCode_0100, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    std::string ownerName = "";
    notificationRequest.SetOwnerBundleName(ownerName);
    std::string result1 = notificationRequest.GetNotificationHashCode();
    EXPECT_EQ(result1, ownerName);

    std::string creatorName = "";
    notificationRequest.SetCreatorBundleName(creatorName);
    std::string result2 = notificationRequest.GetNotificationHashCode();
    EXPECT_EQ(result2, creatorName);

    int32_t uid = 0;
    notificationRequest.SetCreatorUid(uid);
    std::string result3 = notificationRequest.GetNotificationHashCode();
    EXPECT_EQ(result3, creatorName);

    notificationRequest.SetOwnerBundleName("ownerName");
    notificationRequest.SetCreatorBundleName("creatorName");
    notificationRequest.SetCreatorUid(2);
    std::string result4 = notificationRequest.GetNotificationHashCode();
    std::string ret = "10_creatorName_2_ownerName";
    EXPECT_EQ(result4, ret);
}

/**
 * @tc.name: GetNotificationHashCode_0200
 * @tc.desc: GetNotificationHashCode
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, GetNotificationHashCode_0200, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    notificationRequest.SetCreatorBundleName("creatorName");
    int32_t uid = 0;
    notificationRequest.SetCreatorUid(uid);
    std::string result3 = notificationRequest.GetNotificationHashCode();
    std::string creatorName = "";
    EXPECT_EQ(result3, creatorName);
}

/**
 * @tc.name: GetNotificationHashCode_0300
 * @tc.desc: GetNotificationHashCode
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, GetNotificationHashCode_0300, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    notificationRequest.SetCreatorBundleName("creatorName");
    notificationRequest.SetCreatorUid(2);

    std::string ownerName = "";
    notificationRequest.SetOwnerBundleName(ownerName);
    std::string result1 = notificationRequest.GetNotificationHashCode();
    EXPECT_EQ(result1, ownerName);
}

/**
 * @tc.name: SetDevicesSupportDisplay_0100
 * @tc.desc: SetDevicesSupportDisplay
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, SetDevicesSupportDisplay_0100, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    std::vector<std::string> devices;
    notificationRequest.SetDevicesSupportDisplay(devices);
    notificationRequest.SetDevicesSupportOperate(devices);
    nlohmann::json jsonObject;
    notificationRequest.ConvertJsonToNum(nullptr, jsonObject);

    Notification::NotificationRequest* target = new Notification::NotificationRequest(myNotificationId);
    notificationRequest.ConvertJsonToNum(target, jsonObject);
    notificationRequest.ConvertJsonToString(nullptr, jsonObject);
    notificationRequest.ConvertJsonToEnum(nullptr, jsonObject);
    notificationRequest.ConvertJsonToBool(nullptr, jsonObject);
    notificationRequest.ConvertJsonToPixelMap(nullptr, jsonObject);
    bool result1 = notificationRequest.ConvertJsonToNotificationContent(nullptr, jsonObject);
    bool result2 = notificationRequest.ConvertJsonToNotificationActionButton(nullptr, jsonObject);
    bool result3 = notificationRequest.ConvertJsonToNotificationFlags(nullptr, jsonObject);
    EXPECT_EQ(result1, false);
    EXPECT_EQ(result2, false);
    EXPECT_EQ(result3, false);
}

/**
 * @tc.name: ConvertJsonToString_0100
 * @tc.desc: ConvertJsonToString when target not null
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToString_0100, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    nlohmann::json jsonObject;
    Notification::NotificationRequest* target = new Notification::NotificationRequest(myNotificationId);
    
    notificationRequest.ConvertJsonToString(target, jsonObject);
    notificationRequest.ConvertJsonToEnum(target, jsonObject);
    notificationRequest.ConvertJsonToBool(target, jsonObject);
    notificationRequest.ConvertJsonToPixelMap(target, jsonObject);
    bool result1 = notificationRequest.ConvertJsonToNotificationContent(target, jsonObject);
    bool result2 = notificationRequest.ConvertJsonToNotificationActionButton(target, jsonObject);
    bool result3 = notificationRequest.ConvertJsonToNotificationFlags(target, jsonObject);
    EXPECT_EQ(result1, true);
    EXPECT_EQ(result2, true);
    EXPECT_EQ(result3, true);
}

/**
 * @tc.name: ConvertJsonToNotificationDistributedOptions_0100
 * @tc.desc: ConvertJsonToNotificationDistributedOptions
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNotificationDistributedOptions_0100, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    nlohmann::json jsonObject;
    bool result1 = notificationRequest.ConvertJsonToNotificationDistributedOptions(nullptr, jsonObject);
    EXPECT_EQ(result1, false);
}

/**
 * @tc.name: ConvertJsonToNotificationDistributedOptions_0200
 * @tc.desc: ConvertJsonToNotificationDistributedOptions
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNotificationDistributedOptions_0200, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    nlohmann::json jsonObject;
    Notification::NotificationRequest* target = new Notification::NotificationRequest(myNotificationId);
    bool result1 = notificationRequest.ConvertJsonToNotificationDistributedOptions(target, jsonObject);
    EXPECT_EQ(result1, true);
}
}
}
