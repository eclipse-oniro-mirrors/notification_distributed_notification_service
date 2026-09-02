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
#include <utility>

#define private public
#define protected public
#include "ans_inner_errors.h"
#include "ans_service_errors.h"
#include "notification_conversational_content.h"
#include "notification_live_view_content.h"
#include "notification_long_text_content.h"
#include "notification_multiline_content.h"
#include "notification_normal_content.h"
#include "notification_picture_content.h"
#include "notification_request.h"
#include "notification_trigger.h"
#include "pixel_map.h"
#undef private
#undef protected
#include "want_agent_helper.h"
#include "bool_wrapper.h"
#include "string_wrapper.h"
#include "int_wrapper.h"

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
 * @tc.name: NotificationMarshalling_0101
 * @tc.desc: Marshalling with groupInfo
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, NotificationMarshalling_0101, Level1)
{
    int32_t myNotificationId = 10;
    Parcel parcel;
    NotificationRequest notificationRequest(myNotificationId);
    auto groupInfo = std::make_shared<NotificationGroupInfo>();
    groupInfo->SetIsGroupIcon(true);
    groupInfo->SetGroupTitle("testtitle");
    notificationRequest.SetGroupInfo(groupInfo);
    auto result = notificationRequest.Marshalling(parcel);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: NotificationMarshalling_0102
 * @tc.desc: Marshalling with groupInfo
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, NotificationMarshalling_0102, Level1)
{
    int32_t myNotificationId = 10;
    Parcel parcel;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetGroupInfo(nullptr);
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
 * @tc.name: NotificationSetReceiverUserId_0200
 * @tc.desc: GetReceiverUserId return creator userId
 * @tc.type: FUNC
 * @tc.require: issueI5RW70
 */
HWTEST_F(NotificationRequestTest, NotificationSetReceiverUserId_0200, Level1)
{
    int32_t myNotificationId = 10;
    int32_t ownerUserId = 5;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetOwnerUserId(ownerUserId);
    auto result = notificationRequest.GetReceiverUserId();
    EXPECT_EQ(result, ownerUserId);
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
    std::shared_ptr<NotificationActionButton> actionButton4 =
        NotificationActionButton::Create(nullptr, "title4", wantAgent);
    notificationRequest.AddActionButton(actionButton4);
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

    nlohmann::json jsonObject = nlohmann::json{
        {"appMessageId", 10},
    };
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
 * @tc.name: ConvertJsonToString_0200
 * @tc.desc: ConvertJsonToString when appMessageId is string
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToString_0200, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    nlohmann::json jsonObject = nlohmann::json{
        {"appMessageId", "test"},
    };
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

/**
 * @tc.name: CheckLiveViewRequest_0001
 * @tc.desc: Check default notification request is not live view request
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckLiveViewRequest_0001, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    EXPECT_EQ(notificationRequest.IsCommonLiveView(), false);
}

/**
 * @tc.name: CheckLiveViewRequest_0002
 * @tc.desc: Check live view request pass
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckLiveViewRequest_0002, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);
    EXPECT_EQ(notificationRequest.IsCommonLiveView(), true);
}

/**
 * @tc.name: IsSharedThirdpartyLiveView_0001
 * @tc.desc: Non-live-view request returns false for IsSharedThirdpartyLiveView.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, IsSharedThirdpartyLiveView_0001, Level1)
{
    NotificationRequest notificationRequest(1);
    EXPECT_EQ(notificationRequest.IsSharedThirdpartyLiveView(), false);
}

/**
 * @tc.name: IsSharedThirdpartyLiveView_0002
 * @tc.desc: Common live view with null extendInfo returns false.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, IsSharedThirdpartyLiveView_0002, Level1)
{
    NotificationRequest notificationRequest(1);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);
    EXPECT_EQ(notificationRequest.GetExtendInfo(), nullptr);
    EXPECT_EQ(notificationRequest.IsSharedThirdpartyLiveView(), false);
}

/**
 * @tc.name: IsSharedThirdpartyLiveView_0003
 * @tc.desc: Common live view with extendInfo but no isShared param returns false.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, IsSharedThirdpartyLiveView_0003, Level1)
{
    NotificationRequest notificationRequest(1);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);
    auto extendInfo = std::make_shared<AAFwk::WantParams>();
    notificationRequest.SetExtendInfo(extendInfo);
    EXPECT_FALSE(notificationRequest.GetExtendInfo()->HasParam("isShared"));
    EXPECT_EQ(notificationRequest.IsSharedThirdpartyLiveView(), false);
}

/**
 * @tc.name: IsSharedThirdpartyLiveView_0004
 * @tc.desc: Common live view with isShared param of wrong type returns false.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, IsSharedThirdpartyLiveView_0004, Level1)
{
    NotificationRequest notificationRequest(1);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);
    auto extendInfo = std::make_shared<AAFwk::WantParams>();
    extendInfo->SetParam("isShared", AAFwk::String::Box("true"));
    notificationRequest.SetExtendInfo(extendInfo);
    EXPECT_TRUE(notificationRequest.GetExtendInfo()->HasParam("isShared"));
    EXPECT_EQ(notificationRequest.IsSharedThirdpartyLiveView(), false);
}

/**
 * @tc.name: IsSharedThirdpartyLiveView_0005
 * @tc.desc: Common live view with isShared number 1 returns true.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, IsSharedThirdpartyLiveView_0005, Level1)
{
    NotificationRequest notificationRequest(1);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);
    auto extendInfo = std::make_shared<AAFwk::WantParams>();
    extendInfo->SetParam("isShared", AAFwk::Integer::Box(1));
    notificationRequest.SetExtendInfo(extendInfo);
    EXPECT_EQ(notificationRequest.IsSharedThirdpartyLiveView(), true);
}

/**
 * @tc.name: IsSharedThirdpartyLiveView_0006
 * @tc.desc: Common live view with isShared number 0 returns false.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, IsSharedThirdpartyLiveView_0006, Level1)
{
    NotificationRequest notificationRequest(1);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);
    auto extendInfo = std::make_shared<AAFwk::WantParams>();
    extendInfo->SetParam("isShared", AAFwk::Integer::Box(0));
    notificationRequest.SetExtendInfo(extendInfo);
    EXPECT_EQ(notificationRequest.IsSharedThirdpartyLiveView(), false);
}

/**
 * @tc.name: IsSharedThirdpartyLiveView_0007
 * @tc.desc: Common live view with isShared number other than 1 returns false.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, IsSharedThirdpartyLiveView_0007, Level1)
{
    NotificationRequest notificationRequest(1);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);
    auto extendInfo = std::make_shared<AAFwk::WantParams>();
    extendInfo->SetParam("isShared", AAFwk::Integer::Box(2));
    notificationRequest.SetExtendInfo(extendInfo);
    EXPECT_EQ(notificationRequest.IsSharedThirdpartyLiveView(), false);
}

/**
 * @tc.name: CheckLiveViewRequestParam_0001
 * @tc.desc: Default notification request no need to check live view paramter
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckLiveViewRequestParam_0001, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    EXPECT_EQ(notificationRequest.CheckNotificationRequest(nullptr), ERR_OK);
}

/**
 * @tc.name: CheckLiveViewRequestParam_0002
 * @tc.desc: Check pass when no old notification request
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckLiveViewRequestParam_0002, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);
    EXPECT_EQ(notificationRequest.CheckNotificationRequest(nullptr), ERR_OK);
}

/**
 * @tc.name: CheckLiveViewRequestParam_0003
 * @tc.desc: Check not pass when update without old notification request
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckLiveViewRequestParam_0003, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE);
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);
    ErrCode result = notificationRequest.CheckNotificationRequest(nullptr);
    EXPECT_EQ(result, ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.name: CheckLiveViewRequestParam_0004
 * @tc.desc: Check not pass when old request not live view request
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckLiveViewRequestParam_0004, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE);
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);

    sptr<NotificationRequest> oldNotificationRequest(new (std::nothrow) NotificationRequest());
    oldNotificationRequest->SetNotificationId(myNotificationId);
    oldNotificationRequest->SetSlotType(NotificationConstant::SlotType::OTHER);
    ErrCode result = notificationRequest.CheckNotificationRequest(oldNotificationRequest);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: CheckLiveViewRequestParam_0005
 * @tc.desc: Check not pass when live view request end
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckLiveViewRequestParam_0005, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE);
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);

    sptr<NotificationRequest> oldNotificationRequest(new (std::nothrow) NotificationRequest());
    oldNotificationRequest->SetNotificationId(myNotificationId);
    oldNotificationRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto oldLiveContent = std::make_shared<NotificationLiveViewContent>();
    oldLiveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    auto oldContent = std::make_shared<NotificationContent>(oldLiveContent);
    oldNotificationRequest->SetContent(oldContent);
    ErrCode result = notificationRequest.CheckNotificationRequest(oldNotificationRequest);
    EXPECT_EQ(result, ERR_ANS_INNER_END_NOTIFICATION);
}

/**
 * @tc.name: CheckLiveViewRequestParam_0006
 * @tc.desc: Check not pass when repeate create
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckLiveViewRequestParam_0006, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);

    sptr<NotificationRequest> oldNotificationRequest(new (std::nothrow) NotificationRequest());
    oldNotificationRequest->SetNotificationId(myNotificationId);
    oldNotificationRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto oldLiveContent = std::make_shared<NotificationLiveViewContent>();
    oldLiveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE);
    auto oldContent = std::make_shared<NotificationContent>(oldLiveContent);
    oldNotificationRequest->SetContent(oldContent);
    ErrCode result = notificationRequest.CheckNotificationRequest(oldNotificationRequest);
    EXPECT_EQ(result, ERR_ANS_INNER_REPEAT_CREATE);
}

/**
 * @tc.name: CheckLiveViewRequestParam_0007
 * @tc.desc: Check not pass when live view version invalid
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckLiveViewRequestParam_0007, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE);
    liveContent->SetVersion(NotificationLiveViewContent::MAX_VERSION);
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);

    sptr<NotificationRequest> oldNotificationRequest(new (std::nothrow) NotificationRequest());
    oldNotificationRequest->SetNotificationId(myNotificationId);
    oldNotificationRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto oldLiveContent = std::make_shared<NotificationLiveViewContent>();
    oldLiveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE);
    oldLiveContent->SetVersion(1);
    auto oldContent = std::make_shared<NotificationContent>(oldLiveContent);
    oldNotificationRequest->SetContent(oldContent);
    ErrCode result = notificationRequest.CheckNotificationRequest(oldNotificationRequest);
    EXPECT_EQ(result, ERR_ANS_INNER_EXPIRED_NOTIFICATION);
}

/**
 * @tc.name: CheckLiveViewRequestParam_0008
 * @tc.desc: Check not pass when version is expired
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckLiveViewRequestParam_0008, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE);
    liveContent->SetVersion(1);
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);

    sptr<NotificationRequest> oldNotificationRequest(new (std::nothrow) NotificationRequest());
    oldNotificationRequest->SetNotificationId(myNotificationId);
    oldNotificationRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto oldLiveContent = std::make_shared<NotificationLiveViewContent>();
    oldLiveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE);
    oldLiveContent->SetVersion(1);
    auto oldContent = std::make_shared<NotificationContent>(oldLiveContent);
    oldNotificationRequest->SetContent(oldContent);
    ErrCode result = notificationRequest.CheckNotificationRequest(oldNotificationRequest);
    EXPECT_EQ(result, ERR_ANS_INNER_EXPIRED_NOTIFICATION);
}

/**
 * @tc.name: CheckLiveViewRequestParam_0009
 * @tc.desc: Check pass when the version is new
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckLiveViewRequestParam_0009, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE);
    liveContent->SetVersion(1);
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);

    sptr<NotificationRequest> oldNotificationRequest(new (std::nothrow) NotificationRequest());
    oldNotificationRequest->SetNotificationId(myNotificationId);
    oldNotificationRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto oldLiveContent = std::make_shared<NotificationLiveViewContent>();
    oldLiveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE);
    auto oldContent = std::make_shared<NotificationContent>(oldLiveContent);
    oldNotificationRequest->SetContent(oldContent);
    ErrCode result = notificationRequest.CheckNotificationRequest(oldNotificationRequest);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: CheckLiveViewRequestParam_0010
 * @tc.desc: Check pass when the old version is invalid
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckLiveViewRequestParam_0010, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE);
    liveContent->SetVersion(1);
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);

    sptr<NotificationRequest> oldNotificationRequest(new (std::nothrow) NotificationRequest());
    oldNotificationRequest->SetNotificationId(myNotificationId);
    oldNotificationRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto oldLiveContent = std::make_shared<NotificationLiveViewContent>();
    oldLiveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE);
    oldLiveContent->SetVersion(NotificationLiveViewContent::MAX_VERSION);
    auto oldContent = std::make_shared<NotificationContent>(oldLiveContent);
    oldNotificationRequest->SetContent(oldContent);
    ErrCode result = notificationRequest.CheckNotificationRequest(oldNotificationRequest);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: CheckVersion_NullOldContent_001
 * @tc.desc: Test CheckVersion when oldRequest has LIVE_VIEW type but GetContent() returns nullptr
 *           (type field set, content pointer null - IPC inconsistent state).
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, CheckVersion_NullOldContent_001, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);

    sptr<NotificationRequest> oldRequest(new (std::nothrow) NotificationRequest());
    oldRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto oldLiveContent = std::make_shared<NotificationLiveViewContent>();
    auto oldContent = std::make_shared<NotificationContent>(oldLiveContent);
    oldRequest->SetContent(oldContent);
    oldRequest->notificationContent_ = nullptr;

    ErrCode result = notificationRequest.CheckVersion(oldRequest);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: CheckVersion_NullOldContent_002
 * @tc.desc: Test CheckVersion when oldRequest GetContent() is non-null but
 *           GetNotificationContent() returns nullptr (inner content_ null).
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, CheckVersion_NullOldContent_002, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);

    sptr<NotificationRequest> oldRequest(new (std::nothrow) NotificationRequest());
    oldRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto oldLiveContent = std::make_shared<NotificationLiveViewContent>();
    auto oldContent = std::make_shared<NotificationContent>(oldLiveContent);
    oldRequest->SetContent(oldContent);
    oldRequest->GetContent()->content_ = nullptr;

    ErrCode result = notificationRequest.CheckVersion(oldRequest);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: CheckNotificationRequest_NullOldContent_001
 * @tc.desc: Test CheckNotificationRequest when oldRequest has LIVE_VIEW type but
 *           GetContent() returns nullptr (IPC inconsistent state).
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, CheckNotificationRequest_NullOldContent_001, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE);
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);

    sptr<NotificationRequest> oldRequest(new (std::nothrow) NotificationRequest());
    oldRequest->SetNotificationId(myNotificationId);
    oldRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto oldLiveContent = std::make_shared<NotificationLiveViewContent>();
    auto oldContent = std::make_shared<NotificationContent>(oldLiveContent);
    oldRequest->SetContent(oldContent);
    oldRequest->notificationContent_ = nullptr;

    ErrCode result = notificationRequest.CheckNotificationRequest(oldRequest);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: CheckNotificationRequest_NullOldContent_002
 * @tc.desc: Test CheckNotificationRequest when oldRequest GetContent() is non-null but
 *           GetNotificationContent() returns nullptr (inner content_ null).
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, CheckNotificationRequest_NullOldContent_002, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE);
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);

    sptr<NotificationRequest> oldRequest(new (std::nothrow) NotificationRequest());
    oldRequest->SetNotificationId(myNotificationId);
    oldRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto oldLiveContent = std::make_shared<NotificationLiveViewContent>();
    auto oldContent = std::make_shared<NotificationContent>(oldLiveContent);
    oldRequest->SetContent(oldContent);
    oldRequest->GetContent()->content_ = nullptr;

    ErrCode result = notificationRequest.CheckNotificationRequest(oldRequest);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

HWTEST_F(NotificationRequestTest, FillMissingParameters_0001, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    notificationRequest.FillMissingParameters(nullptr);
    EXPECT_EQ(notificationRequest.GetNotificationId(), myNotificationId);
}

/**
 * @tc.name: FillMissingParameters_0002
 * @tc.desc: Check no need to fill parameter when not exist old request
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, FillMissingParameters_0002, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);
    notificationRequest.FillMissingParameters(nullptr);
    EXPECT_EQ(notificationRequest.GetNotificationId(), myNotificationId);
}

/**
 * @tc.name: FillMissingParameters_0003
 * @tc.desc: Check no need to fill param when full update
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, FillMissingParameters_0003, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE);
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);

    sptr<NotificationRequest> oldNotificationRequest(new (std::nothrow) NotificationRequest());
    oldNotificationRequest->SetNotificationId(myNotificationId);

    notificationRequest.FillMissingParameters(oldNotificationRequest);
    EXPECT_EQ(notificationRequest.GetNotificationId(), myNotificationId);
}

/**
 * @tc.name: FillMissingParameters_0004
 * @tc.desc: Check update request correctly when batch update
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, FillMissingParameters_0004, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE);
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);

    sptr<NotificationRequest> oldNotificationRequest(new (std::nothrow) NotificationRequest());
    oldNotificationRequest->SetNotificationId(myNotificationId);
    oldNotificationRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto oldLiveContent = std::make_shared<NotificationLiveViewContent>();
    auto oldExtraInfo = std::make_shared<AAFwk::WantParams>();
    oldExtraInfo->SetParam(string("test"), nullptr);
    oldLiveContent->SetExtraInfo(oldExtraInfo);
    PictureMap pictureMap;
    pictureMap.insert(std::make_pair(string("test"), std::vector<std::shared_ptr<Media::PixelMap>>()));
    oldLiveContent->SetPicture(pictureMap);
    auto oldContent = std::make_shared<NotificationContent>(oldLiveContent);
    oldNotificationRequest->SetContent(oldContent);

    notificationRequest.FillMissingParameters(oldNotificationRequest);
    EXPECT_FALSE(liveContent->GetPicture().empty());
    EXPECT_TRUE(liveContent->GetExtraInfo()->HasParam(string("test")));
}

/**
 * @tc.name: FillMissingParameters_0005
 * @tc.desc: Check update request correctly when old extrainfo is null
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, FillMissingParameters_0005, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE);
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);

    sptr<NotificationRequest> oldNotificationRequest(new (std::nothrow) NotificationRequest());
    oldNotificationRequest->SetNotificationId(myNotificationId);
    oldNotificationRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto oldLiveContent = std::make_shared<NotificationLiveViewContent>();
    PictureMap pictureMap;
    pictureMap.insert(std::make_pair(string("test"), std::vector<std::shared_ptr<Media::PixelMap>>()));
    oldLiveContent->SetPicture(pictureMap);
    auto oldContent = std::make_shared<NotificationContent>(oldLiveContent);
    oldNotificationRequest->SetContent(oldContent);

    notificationRequest.FillMissingParameters(oldNotificationRequest);
    EXPECT_FALSE(liveContent->GetPicture().empty());
    EXPECT_EQ(oldLiveContent->GetExtraInfo(), nullptr);
    EXPECT_EQ(liveContent->GetExtraInfo(), nullptr);

    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    extraInfo->SetParam(string("test"), nullptr);
    liveContent->SetExtraInfo(extraInfo);
    notificationRequest.FillMissingParameters(oldNotificationRequest);
    EXPECT_FALSE(liveContent->GetPicture().empty());
    EXPECT_EQ(oldLiveContent->GetExtraInfo(), nullptr);
    EXPECT_TRUE(liveContent->GetExtraInfo()->HasParam(string("test")));
}

/**
 * @tc.name: FillMissingParameters_0006
 * @tc.desc: Check update request correctly when old extrainfo is null
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, FillMissingParameters_0006, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE);
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);

    sptr<NotificationRequest> oldNotificationRequest(new (std::nothrow) NotificationRequest());
    oldNotificationRequest->SetNotificationId(myNotificationId);

    oldNotificationRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto oldLiveContent = std::make_shared<NotificationLiveViewContent>();
    auto oldContent = std::make_shared<NotificationContent>(oldLiveContent);
    oldNotificationRequest->SetContent(oldContent);

    notificationRequest.FillMissingParameters(oldNotificationRequest);
    EXPECT_EQ(notificationRequest.GetNotificationId(), myNotificationId);
}

/**
 * @tc.name: FillMissingParameters_0007
 * @tc.desc: Check update request correctly when old extrainfo is null
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, FillMissingParameters_0007, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto newExtraInfo = std::make_shared<AAFwk::WantParams>();
    liveContent->SetExtraInfo(newExtraInfo);

    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE);
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);

    sptr<NotificationRequest> oldNotificationRequest(new (std::nothrow) NotificationRequest());
    oldNotificationRequest->SetNotificationId(myNotificationId);

    oldNotificationRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto oldLiveContent = std::make_shared<NotificationLiveViewContent>();
    auto oldExtraInfo = std::make_shared<AAFwk::WantParams>();
    oldExtraInfo->SetParam("eventControl", AAFwk::String::Box("test_eventControl"));
    oldLiveContent->SetExtraInfo(oldExtraInfo);
    auto oldContent = std::make_shared<NotificationContent>(oldLiveContent);
    oldNotificationRequest->SetContent(oldContent);

    notificationRequest.FillMissingParameters(oldNotificationRequest);
    EXPECT_EQ(notificationRequest.GetNotificationId(), myNotificationId);
}

/**
 * @tc.name: GetNotificationRequestKey_0001
 * @tc.desc: Check get key right
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, GetNotificationRequestKey_0001, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetCreatorUid(0);
    notificationRequest.SetCreatorUserId(1);
    notificationRequest.SetLabel(string("test"));
    notificationRequest.SetCreatorBundleName(string("push.com"));
    auto key = notificationRequest.GetKey();
    string expectKey {"ans_live_view___1_0_push.com_test_10"};
    EXPECT_EQ(key, expectKey);
}

/**
 * @tc.name: GetNotificationRequestKey_0002
 * @tc.desc: Check get key right
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, GetNotificationRequestKey_0002, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetOwnerUid(2);
    notificationRequest.SetOwnerUserId(1);
    notificationRequest.SetLabel(string("test"));
    notificationRequest.SetOwnerBundleName(string("test.com"));
    notificationRequest.SetIsAgentNotification(true);
    auto key = notificationRequest.GetKey();
    string expectKey {"ans_live_view___1_2_test.com_test_10"};
    EXPECT_EQ(key, expectKey);
}

inline std::shared_ptr<Media::PixelMap> TestMakePixelMap(int32_t width, int32_t height)
{
    const int32_t PIXEL_BYTES = 4;
    std::shared_ptr<Media::PixelMap> pixelMap = std::make_shared<Media::PixelMap>();
    if (pixelMap == nullptr) {
        return nullptr;
    }
    Media::ImageInfo info;
    info.size.width = width;
    info.size.height = height;
    info.pixelFormat = Media::PixelFormat::ARGB_8888;
    info.colorSpace = Media::ColorSpace::SRGB;
    pixelMap->SetImageInfo(info);
    int32_t rowDataSize = width * PIXEL_BYTES;
    uint32_t bufferSize = rowDataSize * height;
    void *buffer = malloc(bufferSize);
    if (buffer != nullptr) {
        pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, Media::AllocatorType::HEAP_ALLOC, nullptr);
    }
    return pixelMap;
}

/**
 * @tc.name: CheckImageSizeForContent_0001
 * @tc.desc: Check no need to check image size when request is default
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckImageSizeForContent_0001, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);

    auto result = notificationRequest.CheckImageSizeForContent();
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: CheckImageSizeForContent_0002
 * @tc.desc: Check pass when conversation request image size is small
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckImageSizeForContent_0002, Level1)
{
    const int32_t ICON_SIZE = 36;
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    MessageUser msgUser;
    msgUser.SetPixelMap(TestMakePixelMap(ICON_SIZE, ICON_SIZE));
    auto conversationContent = std::make_shared<NotificationConversationalContent>(msgUser);
    conversationContent->GetMessageUser();
    auto content = std::make_shared<NotificationContent>(conversationContent);
    notificationRequest.SetContent(content);

    auto result = notificationRequest.CheckImageSizeForContent();
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: CheckImageSizeForContent_0003
 * @tc.desc: Check not pass when the pixel of picture request exceed limit
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckImageSizeForContent_0003, Level1)
{
    const int32_t ICON_SIZE = 2 * 1024;
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    auto pictureContent = std::make_shared<NotificationPictureContent>();
    pictureContent->SetBigPicture(TestMakePixelMap(ICON_SIZE, ICON_SIZE));
    auto content = std::make_shared<NotificationContent>(pictureContent);
    notificationRequest.SetContent(content);

    auto result = notificationRequest.CheckImageSizeForContent();
    EXPECT_EQ(result, ERR_ANS_INNER_PICTURE_OVER_SIZE);
}

/**
 * @tc.name: CheckImageSizeForContent_0004
 * @tc.desc: Check not pass when live view request icon is empty
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckImageSizeForContent_0004, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    PictureMap pictureMap;
    pictureMap.insert(std::make_pair(string("test"), PictureMap::mapped_type()));
    liveViewContent->SetPicture(pictureMap);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    notificationRequest.SetContent(content);

    auto result = notificationRequest.CheckImageSizeForContent();
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: CheckImageSizeForContent_0005
 * @tc.desc: Check not pass when the number of live view request exceed limit
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckImageSizeForContent_0005, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    PictureMap pictureMap;
    pictureMap.insert(std::make_pair(string("test"), PictureMap::mapped_type(MAX_LIVE_VIEW_ICON_NUM + 1)));
    liveViewContent->SetPicture(pictureMap);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    notificationRequest.SetContent(content);

    auto result = notificationRequest.CheckImageSizeForContent();
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: CheckImageSizeForContent_0006
 * @tc.desc: Check not pass when the pixel of live view request exceed limit
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckImageSizeForContent_0006, Level1)
{
    const int32_t ICON_SIZE = 8 * 32;
    auto pixelMap = TestMakePixelMap(ICON_SIZE, ICON_SIZE);
    PictureMap pictureMap;
    PictureMap::mapped_type vecPixelMap;
    vecPixelMap.push_back(pixelMap);
    pictureMap.insert(std::make_pair(string("test"), vecPixelMap));
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetPicture(pictureMap);
    auto content = std::make_shared<NotificationContent>(liveViewContent);

    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetContent(content);

    auto result = notificationRequest.CheckImageSizeForContent();
    EXPECT_EQ(result, ERR_ANS_INNER_ICON_OVER_SIZE);
}

/**
 * @tc.name: CheckImageSizeForContent_0007
 * @tc.desc: Check live view picture pass when pixel doesn't exceed limit
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckImageSizeForContent_0007, Level1)
{
    const int32_t ICON_SIZE = 3 * 32;
    auto pixelMap = TestMakePixelMap(ICON_SIZE, ICON_SIZE);
    PictureMap pictureMap;
    PictureMap::mapped_type vecPixelMap;
    vecPixelMap.push_back(pixelMap);
    pictureMap.insert(std::make_pair(string("test"), vecPixelMap));
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetPicture(pictureMap);
    auto content = std::make_shared<NotificationContent>(liveViewContent);

    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetContent(content);

    auto result = notificationRequest.CheckImageSizeForContent();
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: CheckImageSizeForContent_0008
 * @tc.desc: Check pass when notification request is other types
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CheckImageSizeForContent_0008, Level1)
{
    auto multiLineContent = std::make_shared<NotificationMultiLineContent>();
    auto content = std::make_shared<NotificationContent>(multiLineContent);

    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetContent(content);

    auto result = notificationRequest.CheckImageSizeForContent();
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: SetUpdateDeadLine_0001
 * @tc.desc: Check SetUpdateDeadLine operator
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, SetUpdateDeadLine_0001, Level1)
{
    auto multiLineContent = std::make_shared<NotificationMultiLineContent>();
    auto content = std::make_shared<NotificationContent>(multiLineContent);

    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetContent(content);

    //override the constructor operator
    NotificationRequest newNotificationRequest = notificationRequest;
    int updateDeadLine = 1;
    newNotificationRequest.SetUpdateDeadLine(updateDeadLine);
    EXPECT_EQ(newNotificationRequest.GetUpdateDeadLine(), 1);
}

/**
 * @tc.name: SetArchiveDeadLine_0001
 * @tc.desc: Check SetArchiveDeadLine operator
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, SetArchiveDeadLine_0001, Level1)
{
    int archiveDeadLine = 1;
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetArchiveDeadLine(archiveDeadLine);
    EXPECT_EQ(notificationRequest.GetArchiveDeadLine(), 1);
}

/**
 * @tc.name: NotificationCollaboration_0100
 * @tc.desc: GetAdditionalData
 * @tc.type: FUNC
 * @tc.require: issueI5RW70
 */
HWTEST_F(NotificationRequestTest, NotificationCollaboration_0100, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetAutoDeletedTime(100);
    notificationRequest.SetGroupName("groupName");
    notificationRequest.SetLabel("label");
    notificationRequest.SetClassification("sys");
    notificationRequest.SetRemoveAllowed(false);
    notificationRequest.SetTapDismissed(true);
    notificationRequest.SetInProgress(true);
    notificationRequest.SetAlertOneTime(true);
    notificationRequest.SetUnremovable(true);

    auto groupInfo = std::make_shared<NotificationGroupInfo>();
    groupInfo->SetIsGroupIcon(true);
    groupInfo->SetGroupTitle("groupTitle");
    notificationRequest.SetGroupInfo(groupInfo);

    std::shared_ptr<AAFwk::WantParams> extras = std::make_shared<AAFwk::WantParams>();
    extras->SetParam("sys_traceid", AAFwk::String::Box("hi"));
    notificationRequest.SetAdditionalData(extras);

    auto notificationTemplate = std::make_shared<NotificationTemplate>();
    notificationTemplate->SetTemplateName("name");
    std::shared_ptr<AAFwk::WantParams> templateParam = std::make_shared<AAFwk::WantParams>();
    templateParam->SetParam("sys_traceid", AAFwk::String::Box("hi"));
    notificationTemplate->SetTemplateData(templateParam);
    notificationRequest.SetTemplate(notificationTemplate);

    std::string basicInfo;
    auto result = notificationRequest.CollaborationToJson(basicInfo);
    EXPECT_EQ(result, true);

    sptr<NotificationRequest> point = NotificationRequest::CollaborationFromJson(basicInfo);
    EXPECT_EQ(point != nullptr, true);
}

HWTEST_F(NotificationRequestTest, SetAppIndex_0001, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetAppIndex(10);
    EXPECT_EQ(notificationRequest.GetAppIndex(), 10);
}

/**
 * @tc.name: GetGeofenceTriggerDeadLine_0100
 * @tc.desc: Test GetGeofenceTriggerDeadLine
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, GetGeofenceTriggerDeadLine_0100, Level1)
{
    int32_t notificationId = 10;
    NotificationRequest notificationRequest(notificationId);
    int64_t triggerDeadLine = 100;
    notificationRequest.SetGeofenceTriggerDeadLine(triggerDeadLine);
    EXPECT_EQ(notificationRequest.GetGeofenceTriggerDeadLine(), 100);
}

/**
 * @tc.name: GetLiveViewStatus_0100
 * @tc.desc: Test GetLiveViewStatus
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, GetLiveViewStatus_0100, Level1)
{
    int32_t notificationId = 10;
    NotificationRequest notificationRequest(notificationId);
    EXPECT_EQ(notificationRequest.GetLiveViewStatus(), NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_BUTT);
}

/**
 * @tc.name: GetLiveViewStatus_0200
 * @tc.desc: Test GetLiveViewStatus
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, GetLiveViewStatus_0200, Level1)
{
    int32_t notificationId = 10;
    NotificationRequest notificationRequest(notificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContentOne = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> contentOne = std::make_shared<NotificationContent>(liveViewContentOne);
    notificationRequest.SetContent(contentOne);
    EXPECT_EQ(notificationRequest.GetLiveViewStatus(), NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
}

/**
 * @tc.name: SetLiveViewStatus_0100
 * @tc.desc: Test SetLiveViewStatus
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, SetLiveViewStatus_0100, Level1)
{
    int32_t notificationId = 10;
    NotificationRequest notificationRequest(notificationId);
    NotificationLiveViewContent::LiveViewStatus status =
        NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE;
    EXPECT_EQ(notificationRequest.SetLiveViewStatus(status), false);
}

/**
 * @tc.name: SetLiveViewStatus_0200
 * @tc.desc: Test SetLiveViewStatus
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, SetLiveViewStatus_0200, Level1)
{
    int32_t notificationId = 10;
    NotificationRequest notificationRequest(notificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContentOne = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> contentOne = std::make_shared<NotificationContent>(liveViewContentOne);
    notificationRequest.SetContent(contentOne);
    NotificationLiveViewContent::LiveViewStatus status =
        NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE;
    EXPECT_EQ(notificationRequest.SetLiveViewStatus(status), true);
}

/**
 * @tc.name:ConvertObjectsToJson_0001
 * @tc.desc: Check return true when notificationTrigger_ is not null
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, ConvertObjectsToJson_0001, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    std::shared_ptr<NotificationTrigger> notificationTrigger = std::make_shared<NotificationTrigger>();
    notificationTrigger->SetConfigPath(NotificationConstant::ConfigPath::CONFIG_PATH_CLOUD_CONFIG);
    notificationRequest.SetNotificationTrigger(notificationTrigger);
    nlohmann::json jsonObject;
    auto result = notificationRequest.ConvertObjectsToJson(jsonObject);
    EXPECT_EQ(result, true);
    EXPECT_EQ(jsonObject["notificationTrigger"]["triggerConfigPath"],
        NotificationConstant::ConfigPath::CONFIG_PATH_CLOUD_CONFIG);
}

/**
 * @tc.name:ConvertJsonToNotificationGeofence_0001
 * @tc.desc: Test ConvertJsonToNotificationGeofence
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNotificationGeofence_0001, Level1)
{
    std::shared_ptr<NotificationTrigger> notificationTrigger = std::make_shared<NotificationTrigger>();
    ASSERT_NE(notificationTrigger, nullptr);
    nlohmann::json jsonObject;
    EXPECT_FALSE(notificationTrigger->ConvertJsonToNotificationGeofence(nullptr, jsonObject));
}

HWTEST_F(NotificationRequestTest, IsConsumedDevices_0001, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest request(myNotificationId);

    request.AddConsumedDevices(NotificationConstant::THIRD_PARTY_WEARABLE_DEVICE_TYPE);
    request.AddConsumedDevices(NotificationConstant::PAD_DEVICE_TYPE);
    request.AddConsumedDevices("testDevice");

    EXPECT_TRUE(request.IsConsumedDevices(NotificationConstant::THIRD_PARTY_WEARABLE_DEVICE_TYPE));
    EXPECT_TRUE(request.IsConsumedDevices(NotificationConstant::PAD_DEVICE_TYPE));
    EXPECT_FALSE(request.IsConsumedDevices(NotificationConstant::PC_DEVICE_TYPE));
    EXPECT_FALSE(request.IsConsumedDevices(NotificationConstant::WEARABLE_DEVICE_TYPE));
    EXPECT_FALSE(request.IsConsumedDevices(NotificationConstant::LITEWEARABLE_DEVICE_TYPE));
    EXPECT_FALSE(request.IsConsumedDevices(NotificationConstant::CURRENT_DEVICE_TYPE));
    EXPECT_FALSE(request.IsConsumedDevices(NotificationConstant::HEADSET_DEVICE_TYPE));
}

/**
 * @tc.name:GetAtomicServiceInstallStatus_0100
 * @tc.desc: Test GetAtomicServiceInstallStatus
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, GetAtomicServiceInstallStatus_0100, Level1)
{
    NotificationRequest notificationRequest(1);
    int32_t status = 100;
    bool result = notificationRequest.GetAtomicServiceInstallStatus(status);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name:GetAtomicServiceInstallStatus_0200
 * @tc.desc: Test GetAtomicServiceInstallStatus
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, GetAtomicServiceInstallStatus_0200, Level1)
{
    NotificationRequest notificationRequest(1);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);
    notificationRequest.SetIsAgentNotification(true);
    int32_t status = 100;
    bool result = notificationRequest.GetAtomicServiceInstallStatus(status);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name:GetAtomicServiceInstallStatus_0300
 * @tc.desc: Test GetAtomicServiceInstallStatus
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, GetAtomicServiceInstallStatus_0300, Level1)
{
    NotificationRequest notificationRequest(1);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);
    notificationRequest.SetIsAgentNotification(true);
    auto extendInfo = std::make_shared<AAFwk::WantParams>();
    extendInfo->SetParam("autoServiceInstallStatus", AAFwk::Integer::Box(PKG_INSTALL_STATUS_UNINSTALL));
    notificationRequest.SetExtendInfo(extendInfo);
    int32_t status = 100;
    bool result = notificationRequest.GetAtomicServiceInstallStatus(status);
    EXPECT_EQ(result, true);
    EXPECT_EQ(status, PKG_INSTALL_STATUS_UNINSTALL);
}

/**
 * @tc.name:GetAtomicServiceInstallStatus_0400
 * @tc.desc: Test GetAtomicServiceInstallStatus
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, GetAtomicServiceInstallStatus_0400, Level1)
{
    NotificationRequest notificationRequest(1);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);
    notificationRequest.SetIsAgentNotification(true);
    auto extendInfo = std::make_shared<AAFwk::WantParams>();
    extendInfo->SetParam("autoServiceInstallStatus", AAFwk::Integer::Box(PKG_INSTALL_STATUS_INSTALL));
    notificationRequest.SetExtendInfo(extendInfo);
    int32_t status = 100;
    bool result = notificationRequest.GetAtomicServiceInstallStatus(status);
    EXPECT_EQ(result, true);
    EXPECT_EQ(status, PKG_INSTALL_STATUS_INSTALL);
}

/**
 * @tc.name:TestGroupInfo_001
 * @tc.desc: Test NotificationGroupInfo
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, TestGroupInfo_001, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest request(myNotificationId);
    std::shared_ptr<NotificationGroupInfo> groupInfo = std::make_shared<NotificationGroupInfo>();
    ASSERT_NE(groupInfo, nullptr);
    groupInfo->SetIsGroupIcon(true);
    groupInfo->SetGroupTitle("testTitle");
    request.SetGroupInfo(groupInfo);
    EXPECT_EQ(request.GetGroupInfo()->GetIsGroupIcon(), true);
    EXPECT_EQ(request.GetGroupInfo()->GetGroupTitle(), "testTitle");
}

/**
 * @tc.name:ConvertGroupInfoToJson_001
 * @tc.desc: Test ConvertGroupInfoToJson
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, ConvertGroupInfoToJson_001, Level0)
{
    int32_t myNotificationId = 10;
    NotificationRequest request(myNotificationId);
    std::shared_ptr<NotificationGroupInfo> groupInfo = std::make_shared<NotificationGroupInfo>();
    ASSERT_NE(groupInfo, nullptr);
    groupInfo->SetIsGroupIcon(true);
    groupInfo->SetGroupTitle("testTitle");
    request.SetGroupInfo(groupInfo);

    nlohmann::json jsonObject;
    EXPECT_EQ(request.ConvertGroupInfoToJson(jsonObject), true);
}

/**
 * @tc.name:ConvertJsonToGroupInfo_001
 * @tc.desc: Test ConvertJsonToGroupInfo
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToGroupInfo_001, Level0)
{
    int32_t myNotificationId = 10;
    NotificationRequest request(myNotificationId);
    NotificationRequest *target = nullptr;
    nlohmann::json jsonObject;
    EXPECT_EQ(request.ConvertJsonToGroupInfo(target, jsonObject), false);
}

/**
 * @tc.name:ConvertJsonToGroupInfo_002
 * @tc.desc: Test ConvertJsonToGroupInfo
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToGroupInfo_002, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest request(myNotificationId);
    nlohmann::json jsonObject;
    jsonObject["id"] = 0;
    EXPECT_EQ(request.ConvertJsonToGroupInfo(&request, jsonObject), true);
}

/**
 * @tc.name:ConvertJsonToGroupInfo_003
 * @tc.desc: Test ConvertJsonToGroupInfo
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToGroupInfo_003, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest request(myNotificationId);
    nlohmann::json jsonObject;
    jsonObject["groupInfo"] = nullptr;
    EXPECT_EQ(request.ConvertJsonToGroupInfo(&request, jsonObject), true);
}

/**
 * @tc.name:ConvertObjectsToJson_0002
 * @tc.desc: Check return true when groupInfo_ is not null
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, ConvertObjectsToJson_0002, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest request(myNotificationId);
    std::shared_ptr<NotificationGroupInfo> groupInfo = std::make_shared<NotificationGroupInfo>();
    ASSERT_NE(groupInfo, nullptr);
    groupInfo->SetIsGroupIcon(true);
    groupInfo->SetGroupTitle("testTitle");
    request.SetGroupInfo(groupInfo);
    nlohmann::json jsonObject;
    auto result = request.ConvertObjectsToJson(jsonObject);
    EXPECT_EQ(result, true);
    EXPECT_EQ(jsonObject["groupInfo"]["groupTitle"], "testTitle");
}

/**
 * @tc.name:ConvertObjectsToJson_0003
 * @tc.desc: Check return true when groupInfo_ is null
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, ConvertObjectsToJson_0003, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest request(myNotificationId);
    request.SetGroupInfo(nullptr);
    nlohmann::json jsonObject;
    auto result = request.ConvertObjectsToJson(jsonObject);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: ConvertJsonToNotificationContent_0100
 * @tc.desc: ConvertJsonToNotificationContent when OwnerUid not DEFAULT_UID
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNotificationContent_0100, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    nlohmann::json jsonObject = nlohmann::json{
        {"wantAgent", 1},
        {"removalWantAgent", 1},
    };
    Notification::NotificationRequest* target = new Notification::NotificationRequest(myNotificationId);
    target->SetOwnerUid(22);
    Notification::NotificationRequest::ConvertJsonToWantAgent(target, jsonObject);
    bool result1 = notificationRequest.ConvertJsonToNotificationContent(target, jsonObject);
    EXPECT_EQ(result1, true);
}

/**
 * @tc.name: ConvertJsonToNotificationContent_0200
 * @tc.desc: ConvertJsonToNotificationContent when OwnerUid is DEFAULT_UID
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNotificationContent_0200, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    nlohmann::json jsonObject = nlohmann::json{
        {"wantAgent", 1},
        {"removalWantAgent", 1},
    };
    Notification::NotificationRequest* target = new Notification::NotificationRequest(myNotificationId);
    target->SetOwnerUid(0);
    Notification::NotificationRequest::ConvertJsonToWantAgent(target, jsonObject);
    bool result1 = notificationRequest.ConvertJsonToNotificationContent(target, jsonObject);
    EXPECT_EQ(result1, true);
}

/**
 * @tc.name: ConvertJsonToNotificationContent_0300
 * @tc.desc: ConvertJsonToNotificationContent when OwnerUid not DEFAULT_UID
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNotificationContent_0300, Level1)
{
    int32_t myNotificationId = 10;
    Notification::NotificationRequest* request = new Notification::NotificationRequest(myNotificationId);
    auto multiLineContent = std::make_shared<NotificationMultiLineContent>();
    auto wantAgent = std::make_shared<AbilityRuntime::WantAgent::WantAgent>();
    multiLineContent->SetLineWantAgents({wantAgent, wantAgent});
    multiLineContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::MULTILINE));
    multiLineContent->SetLineWantAgentStrs({"test001", "test002"});
    std::shared_ptr<NotificationContent> notificationContent = std::make_shared<NotificationContent>(multiLineContent);
    request->SetContent(notificationContent);
    nlohmann::json jsonObject = nlohmann::json{
        {"wantAgent", 1},
        {"removalWantAgent", 1},
    };
    bool result1 = request->ConvertObjectsToJson(jsonObject);
    EXPECT_EQ(result1, true);
    Notification::NotificationRequest* target = new Notification::NotificationRequest(myNotificationId);
    target->SetOwnerUid(22);
    Notification::NotificationRequest::ConvertJsonToWantAgent(target, jsonObject);
    bool result2 = Notification::NotificationRequest::ConvertJsonToNotificationContent(target, jsonObject);
    EXPECT_EQ(result2, true);
}

/**
 * @tc.name: ConvertJsonToNotificationContent_0400
 * @tc.desc: ConvertJsonToNotificationContent when OwnerUid is DEFAULT_UID
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNotificationContent_0400, Level1)
{
    int32_t myNotificationId = 10;
    Notification::NotificationRequest* request = new Notification::NotificationRequest(myNotificationId);
    auto multiLineContent = std::make_shared<NotificationMultiLineContent>();
    auto wantAgent = std::make_shared<AbilityRuntime::WantAgent::WantAgent>();
    multiLineContent->SetLineWantAgents({wantAgent, wantAgent});
    multiLineContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::MULTILINE));
    multiLineContent->SetLineWantAgentStrs({"test001", "test002"});
    std::shared_ptr<NotificationContent> notificationContent = std::make_shared<NotificationContent>(multiLineContent);
    request->SetContent(notificationContent);
    nlohmann::json jsonObject = nlohmann::json{
        {"wantAgent", "test"},
        {"removalWantAgent", "test"},
    };
    bool result1 = request->ConvertObjectsToJson(jsonObject);
    EXPECT_EQ(result1, true);
    Notification::NotificationRequest* target = new Notification::NotificationRequest(myNotificationId);
    target->SetOwnerUid(0);
    Notification::NotificationRequest::ConvertJsonToWantAgent(target, jsonObject);
    bool result2 = Notification::NotificationRequest::ConvertJsonToNotificationContent(target, jsonObject);
    EXPECT_EQ(result2, true);
}

/**
 * @tc.name: ReadFromParcel_ContentTypeSync_0100
 * @tc.desc: Test ReadFromParcel syncs notificationContentType_ from notificationContent_ with BASIC_TEXT type
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ReadFromParcel_ContentTypeSync_0100, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetText("test text");
    normalContent->SetTitle("test title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    notificationRequest.SetContent(content);

    Parcel parcel;
    auto marshallingResult = notificationRequest.Marshalling(parcel);
    EXPECT_EQ(marshallingResult, true);

    auto *unmarshalledRequest = NotificationRequest::Unmarshalling(parcel);
    ASSERT_NE(unmarshalledRequest, nullptr);
    EXPECT_EQ(unmarshalledRequest->GetNotificationType(), NotificationContent::Type::BASIC_TEXT);
    EXPECT_NE(unmarshalledRequest->GetContent(), nullptr);
    EXPECT_EQ(unmarshalledRequest->GetContent()->GetContentType(), NotificationContent::Type::BASIC_TEXT);
    EXPECT_EQ(unmarshalledRequest->notificationContentType_,
        unmarshalledRequest->notificationContent_->GetContentType());
    delete unmarshalledRequest;
}

/**
 * @tc.name: ReadFromParcel_ContentTypeSync_0200
 * @tc.desc: Test ReadFromParcel syncs notificationContentType_ from notificationContent_ with LONG_TEXT type
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ReadFromParcel_ContentTypeSync_0200, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    auto longTextContent = std::make_shared<NotificationLongTextContent>("long text content");
    longTextContent->SetTitle("long title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(longTextContent);
    notificationRequest.SetContent(content);

    Parcel parcel;
    auto marshallingResult = notificationRequest.Marshalling(parcel);
    EXPECT_EQ(marshallingResult, true);

    auto *unmarshalledRequest = NotificationRequest::Unmarshalling(parcel);
    ASSERT_NE(unmarshalledRequest, nullptr);
    EXPECT_EQ(unmarshalledRequest->GetNotificationType(), NotificationContent::Type::LONG_TEXT);
    EXPECT_NE(unmarshalledRequest->GetContent(), nullptr);
    EXPECT_EQ(unmarshalledRequest->GetContent()->GetContentType(), NotificationContent::Type::LONG_TEXT);
    EXPECT_EQ(unmarshalledRequest->notificationContentType_,
        unmarshalledRequest->notificationContent_->GetContentType());
    delete unmarshalledRequest;
}

/**
 * @tc.name: ReadFromParcel_ContentTypeSync_0300
 * @tc.desc: Test ReadFromParcel syncs notificationContentType_ from notificationContent_ with MULTILINE type
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ReadFromParcel_ContentTypeSync_0300, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    auto multiLineContent = std::make_shared<NotificationMultiLineContent>();
    multiLineContent->SetText("multiline text");
    multiLineContent->SetTitle("multiline title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(multiLineContent);
    notificationRequest.SetContent(content);

    Parcel parcel;
    auto marshallingResult = notificationRequest.Marshalling(parcel);
    EXPECT_EQ(marshallingResult, true);

    auto *unmarshalledRequest = NotificationRequest::Unmarshalling(parcel);
    ASSERT_NE(unmarshalledRequest, nullptr);
    EXPECT_EQ(unmarshalledRequest->GetNotificationType(), NotificationContent::Type::MULTILINE);
    EXPECT_NE(unmarshalledRequest->GetContent(), nullptr);
    EXPECT_EQ(unmarshalledRequest->GetContent()->GetContentType(), NotificationContent::Type::MULTILINE);
    EXPECT_EQ(unmarshalledRequest->notificationContentType_,
        unmarshalledRequest->notificationContent_->GetContentType());
    delete unmarshalledRequest;
}

/**
 * @tc.name: ReadFromParcel_ContentTypeSync_0400
 * @tc.desc: Test ReadFromParcel syncs notificationContentType_ from notificationContent_ with PICTURE type
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ReadFromParcel_ContentTypeSync_0400, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    auto pictureContent = std::make_shared<NotificationPictureContent>();
    pictureContent->SetText("picture text");
    pictureContent->SetTitle("picture title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(pictureContent);
    notificationRequest.SetContent(content);

    Parcel parcel;
    auto marshallingResult = notificationRequest.Marshalling(parcel);
    EXPECT_EQ(marshallingResult, true);

    auto *unmarshalledRequest = NotificationRequest::Unmarshalling(parcel);
    ASSERT_NE(unmarshalledRequest, nullptr);
    EXPECT_EQ(unmarshalledRequest->GetNotificationType(), NotificationContent::Type::PICTURE);
    EXPECT_NE(unmarshalledRequest->GetContent(), nullptr);
    EXPECT_EQ(unmarshalledRequest->GetContent()->GetContentType(), NotificationContent::Type::PICTURE);
    EXPECT_EQ(unmarshalledRequest->notificationContentType_,
        unmarshalledRequest->notificationContent_->GetContentType());
    delete unmarshalledRequest;
}

/**
 * @tc.name: ReadFromParcel_ContentTypeSync_0500
 * @tc.desc: Test SetContent nullptr sets notificationContentType_ to NONE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ReadFromParcel_ContentTypeSync_0500, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetContent(nullptr);
    EXPECT_EQ(notificationRequest.GetNotificationType(), NotificationContent::Type::NONE);
    EXPECT_EQ(notificationRequest.GetContent(), nullptr);
}

/**
 * @tc.name: IncrementalUpdateLiveview_NullContent_0001
 * @tc.desc: Test IncrementalUpdateLiveview with null content
 * @tc.type: FUNC
 * @tc.require: issue4281
 */
HWTEST_F(NotificationRequestTest, IncrementalUpdateLiveview_NullContent_0001, Function | SmallTest | Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    sptr<NotificationRequest> oldRequest = new NotificationRequest(myNotificationId);
    auto oldLiveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto oldContent = std::make_shared<NotificationContent>(oldLiveViewContent);
    oldRequest->SetContent(oldContent);
    notificationRequest.notificationContent_ = nullptr;
    notificationRequest.notificationContentType_ = NotificationContent::Type::LIVE_VIEW;
    notificationRequest.IncrementalUpdateLiveview(oldRequest);
    EXPECT_EQ(notificationRequest.GetContent(), nullptr);
}

/**
 * @tc.name: IncrementalUpdateLiveview_NullInnerContent_0001
 * @tc.desc: Test IncrementalUpdateLiveview with null GetNotificationContent
 * @tc.type: FUNC
 * @tc.require: issue4281
 */
HWTEST_F(NotificationRequestTest, IncrementalUpdateLiveview_NullInnerContent_0001, Function | SmallTest | Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    sptr<NotificationRequest> oldRequest = new NotificationRequest(myNotificationId);
    auto oldLiveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto oldContent = std::make_shared<NotificationContent>(oldLiveViewContent);
    oldRequest->SetContent(oldContent);
    auto emptyContent = std::make_shared<NotificationContent>();
    notificationRequest.notificationContent_ = emptyContent;
    notificationRequest.notificationContentType_ = NotificationContent::Type::LIVE_VIEW;
    notificationRequest.IncrementalUpdateLiveview(oldRequest);
    EXPECT_NE(notificationRequest.GetContent(), nullptr);
}

/**
 * @tc.name: IncrementalUpdateLiveview_NullOldRequest_0001
 * @tc.desc: Test IncrementalUpdateLiveview with null oldRequest
 * @tc.type: FUNC
 * @tc.require: issue4281
 */
HWTEST_F(NotificationRequestTest, IncrementalUpdateLiveview_NullOldRequest_0001, Function | SmallTest | Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    notificationRequest.SetContent(content);
    notificationRequest.IncrementalUpdateLiveview(nullptr);
    EXPECT_NE(notificationRequest.GetContent(), nullptr);
}

/**
 * @tc.name: SetSlotType_Invalid_001
 * @tc.desc: Test SetSlotType with invalid slot type does not set.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, SetSlotType_Invalid_001, Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    auto before = notificationRequest.GetSlotType();
    notificationRequest.SetSlotType(static_cast<NotificationConstant::SlotType>(-1));
    EXPECT_EQ(notificationRequest.GetSlotType(), before);
    notificationRequest.SetSlotType(static_cast<NotificationConstant::SlotType>(100));
    EXPECT_EQ(notificationRequest.GetSlotType(), before);
}

/**
 * @tc.name: SetNotificationUserInputHistory_TooLarge_001
 * @tc.desc: Test SetNotificationUserInputHistory rejects vector exceeding MAX_USER_INPUT_HISTORY.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, SetNotificationUserInputHistory_TooLarge_001, Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    std::vector<std::string> text(NotificationRequest::MAX_USER_INPUT_HISTORY + 1, "input");
    notificationRequest.SetNotificationUserInputHistory(text);
    EXPECT_EQ(notificationRequest.GetNotificationUserInputHistory().size(), 0);
}

/**
 * @tc.name: SetDevicesSupportOperate_TooLarge_001
 * @tc.desc: Test SetDevicesSupportOperate rejects vector exceeding MAX_PARCELABLE_VECTOR_NUM.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, SetDevicesSupportOperate_TooLarge_001, Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    std::vector<std::string> devices(static_cast<size_t>(MAX_PARCELABLE_VECTOR_NUM) + 1, "device");
    notificationRequest.SetDevicesSupportOperate(devices);
    auto opts = notificationRequest.GetNotificationDistributedOptions();
    EXPECT_EQ(opts.GetDevicesSupportOperate().size(), 0);
}

/**
 * @tc.name: GetCreatorUserId_Invalid_001
 * @tc.desc: Test GetCreatorUserId returns the raw creatorUserId_ value when it is negative.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, GetCreatorUserId_Invalid_001, Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    notificationRequest.creatorUserId_ = -100;
    EXPECT_EQ(notificationRequest.GetCreatorUserId(), -100);
}

/**
 * @tc.name: CollaborationFromJson_InvalidExtraInfo_001
 * @tc.desc: Test CollaborationFromJson skips ParseWantParams when extraInfo is invalid JSON.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CollaborationFromJson_InvalidExtraInfo_001, Function | SmallTest | Level1)
{
    std::string jsonStr = R"({"extraInfo": "not_json{"})";
    auto *result = NotificationRequest::CollaborationFromJson(jsonStr);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->additionalParams_, nullptr);
    delete result;
}

/**
 * @tc.name: ConvertJsonToTemplate_TooLarge_001
 * @tc.desc: Test ConvertJsonToTemplate skips templateData when size exceeds MAX_PARCELABLE_VECTOR_NUM.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToTemplate_TooLarge_001, Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    std::string largeData(static_cast<size_t>(MAX_PARCELABLE_VECTOR_NUM) + 1, 'a');
    nlohmann::json jsonObject = nlohmann::json{
        {"template", {{"templateName", "test"}, {"templateData", largeData}}}
    };
    notificationRequest.ConvertJsonToTemplate(&notificationRequest, jsonObject);
    ASSERT_NE(notificationRequest.notificationTemplate_, nullptr);
    EXPECT_EQ(notificationRequest.notificationTemplate_->GetTemplateData(), nullptr);
}

/**
 * @tc.name: ReadFromParcel_UserInputHistoryTooLarge_001
 * @tc.desc: Test ReadFromParcel returns false when userInputHistory size exceeds MAX_USER_INPUT_HISTORY.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ReadFromParcel_UserInputHistoryTooLarge_001, Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    notificationRequest.userInputHistory_.resize(NotificationRequest::MAX_USER_INPUT_HISTORY + 1, "test");
    Parcel parcel;
    ASSERT_TRUE(notificationRequest.Marshalling(parcel));
    parcel.RewindRead(0);
    NotificationRequest result(10);
    EXPECT_EQ(result.ReadFromParcel(parcel), false);
}

/**
 * @tc.name: ConvertJsonToNumExt_OwnerUserIdOutOfRange_001
 * @tc.desc: Test ConvertJsonToNumExt skips ownerUserId when out of int32 range.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNumExt_OwnerUserIdOutOfRange_001, Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    int32_t defaultVal = notificationRequest.GetOwnerUserId();
    nlohmann::json jsonObject = nlohmann::json{{"ownerUserId", 2147483648LL}};
    notificationRequest.ConvertJsonToNumExt(&notificationRequest, jsonObject);
    EXPECT_EQ(notificationRequest.GetOwnerUserId(), defaultVal);
}

/**
 * @tc.name: ConvertJsonToNumExt_OwnerUidOutOfRange_001
 * @tc.desc: Test ConvertJsonToNumExt skips ownerUid when out of int32 range.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNumExt_OwnerUidOutOfRange_001, Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    int32_t defaultVal = notificationRequest.GetOwnerUid();
    nlohmann::json jsonObject = nlohmann::json{{"ownerUid", 2147483648LL}};
    notificationRequest.ConvertJsonToNumExt(&notificationRequest, jsonObject);
    EXPECT_EQ(notificationRequest.GetOwnerUid(), defaultVal);
}

/**
 * @tc.name: ConvertJsonToNumExt_NotificationControlFlagsOutOfRange_001
 * @tc.desc: Test ConvertJsonToNumExt skips notificationControlFlags when out of range.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNumExt_NotificationControlFlagsOutOfRange_001,
    Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    uint32_t defaultVal = notificationRequest.GetNotificationControlFlags();
    nlohmann::json jsonObject = nlohmann::json{{"notificationControlFlags", -1}};
    notificationRequest.ConvertJsonToNumExt(&notificationRequest, jsonObject);
    EXPECT_EQ(notificationRequest.GetNotificationControlFlags(), defaultVal);
}

/**
 * @tc.name: ConvertJsonToEnum_InvalidSlotType_001
 * @tc.desc: Test ConvertJsonToEnum skips slotType when invalid.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToEnum_InvalidSlotType_001, Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    auto before = notificationRequest.GetSlotType();
    nlohmann::json jsonObject = nlohmann::json{{"slotType", -1}};
    notificationRequest.ConvertJsonToEnum(&notificationRequest, jsonObject);
    EXPECT_EQ(notificationRequest.GetSlotType(), before);
    nlohmann::json jsonObject2 = nlohmann::json{{"slotType", 100}};
    notificationRequest.ConvertJsonToEnum(&notificationRequest, jsonObject2);
    EXPECT_EQ(notificationRequest.GetSlotType(), before);
}

/**
 * @tc.name: ConvertJsonToNotificationActionButton_NotArray_001
 * @tc.desc: Test ConvertJsonToNotificationActionButton returns false when actionButtons is not an array.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNotificationActionButton_NotArray_001, Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    nlohmann::json jsonObject = nlohmann::json{{"actionButtons", "not_array"}};
    bool result = notificationRequest.ConvertJsonToNotificationActionButton(&notificationRequest, jsonObject);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: ConvertJsonToNotificationTrigger_InvalidTriggerType_001
 * @tc.desc: Test ConvertJsonToNotificationTrigger returns false when triggerType is out of range.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNotificationTrigger_InvalidTriggerType_001,
    Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    nlohmann::json jsonObject = nlohmann::json{
        {"notificationTrigger", {{"triggerType", 0}}}
    };
    bool result = notificationRequest.ConvertJsonToNotificationTrigger(&notificationRequest, jsonObject);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: ConvertJsonToNotificationTrigger_InvalidConfigPath_001
 * @tc.desc: Test ConvertJsonToNotificationTrigger returns false when triggerConfigPath is out of range.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNotificationTrigger_InvalidConfigPath_001, Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    nlohmann::json jsonObject = nlohmann::json{
        {"notificationTrigger", {{"triggerConfigPath", 0}}}
    };
    bool result = notificationRequest.ConvertJsonToNotificationTrigger(&notificationRequest, jsonObject);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: NotificationTrigger_FromJson_InvalidTriggerType_001
 * @tc.desc: Test NotificationTrigger::FromJson skips type_ when triggerType is out of range.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, NotificationTrigger_FromJson_InvalidTriggerType_001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{{"triggerType", 0}};
    auto *trigger = NotificationTrigger::FromJson(jsonObject);
    ASSERT_NE(trigger, nullptr);
    EXPECT_NE(trigger->GetTriggerType(), NotificationConstant::TriggerType::TRIGGER_TYPE_FENCE);
    delete trigger;
}

/**
 * @tc.name: NotificationTrigger_FromJson_InvalidConfigPath_001
 * @tc.desc: Test NotificationTrigger::FromJson skips configPath_ when triggerConfigPath is out of range.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, NotificationTrigger_FromJson_InvalidConfigPath_001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{{"triggerConfigPath", 0}};
    auto *trigger = NotificationTrigger::FromJson(jsonObject);
    ASSERT_NE(trigger, nullptr);
    EXPECT_EQ(trigger->GetConfigPath(), NotificationConstant::ConfigPath::CONFIG_PATH_DEVICE_CONFIG);
    delete trigger;
}

/**
 * @tc.name: ConvertJsonToNotificationTrigger_NoTriggerKey_001
 * @tc.desc: Test ConvertJsonToNotificationTrigger returns true when notificationTrigger key is absent.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNotificationTrigger_NoTriggerKey_001,
    Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    nlohmann::json jsonObject = nlohmann::json{{"id", 1}};
    bool result = notificationRequest.ConvertJsonToNotificationTrigger(&notificationRequest, jsonObject);
    EXPECT_EQ(result, true);
    EXPECT_EQ(notificationRequest.GetNotificationTrigger(), nullptr);
}

/**
 * @tc.name: ConvertJsonToNotificationTrigger_NullTrigger_001
 * @tc.desc: Test ConvertJsonToNotificationTrigger returns true when notificationTrigger is null.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNotificationTrigger_NullTrigger_001,
    Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    nlohmann::json jsonObject = nlohmann::json{{"notificationTrigger", nullptr}};
    bool result = notificationRequest.ConvertJsonToNotificationTrigger(&notificationRequest, jsonObject);
    EXPECT_EQ(result, true);
    EXPECT_EQ(notificationRequest.GetNotificationTrigger(), nullptr);
}

/**
 * @tc.name: SetNotificationUserInputHistory_Valid_001
 * @tc.desc: Test SetNotificationUserInputHistory assigns all elements when size is within limit.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, SetNotificationUserInputHistory_Valid_001, Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    std::vector<std::string> text {"input1", "input2", "input3"};
    notificationRequest.SetNotificationUserInputHistory(text);
    auto result = notificationRequest.GetNotificationUserInputHistory();
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], "input1");
    EXPECT_EQ(result[1], "input2");
    EXPECT_EQ(result[2], "input3");

    std::vector<std::string> boundary(NotificationRequest::MAX_USER_INPUT_HISTORY, "input");
    notificationRequest.SetNotificationUserInputHistory(boundary);
    EXPECT_EQ(
        notificationRequest.GetNotificationUserInputHistory().size(), NotificationRequest::MAX_USER_INPUT_HISTORY);
}

/**
 * @tc.name: ConvertJsonToEnum_ValidSlotType_001
 * @tc.desc: Test ConvertJsonToEnum sets slotType when value is valid.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToEnum_ValidSlotType_001, Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    nlohmann::json jsonObject = nlohmann::json{{"slotType", 5}};
    notificationRequest.ConvertJsonToEnum(&notificationRequest, jsonObject);
    EXPECT_EQ(notificationRequest.GetSlotType(), NotificationConstant::SlotType::LIVE_VIEW);
}

/**
 * @tc.name: CollaborationFromJson_NoExtraInfo_001
 * @tc.desc: Test CollaborationFromJson works when extraInfo key is absent.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CollaborationFromJson_NoExtraInfo_001, Function | SmallTest | Level1)
{
    std::string jsonStr = R"({"id": 1})";
    auto *result = NotificationRequest::CollaborationFromJson(jsonStr);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->additionalParams_, nullptr);
    delete result;
}

/**
 * @tc.name: CollaborationFromJson_ExtraInfoNotString_001
 * @tc.desc: Test CollaborationFromJson skips extraInfo when it is not a string.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CollaborationFromJson_ExtraInfoNotString_001, Function | SmallTest | Level1)
{
    std::string jsonStr = R"({"extraInfo": 123})";
    auto *result = NotificationRequest::CollaborationFromJson(jsonStr);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->additionalParams_, nullptr);
    delete result;
}

/**
 * @tc.name: CollaborationFromJson_ExtraInfoEmpty_001
 * @tc.desc: Test CollaborationFromJson skips extraInfo when it is an empty string.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, CollaborationFromJson_ExtraInfoEmpty_001, Function | SmallTest | Level1)
{
    std::string jsonStr = R"({"extraInfo": ""})";
    auto *result = NotificationRequest::CollaborationFromJson(jsonStr);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->additionalParams_, nullptr);
    delete result;
}

/**
 * @tc.name: ConvertJsonToNumExt_ValidValues_001
 * @tc.desc: Test ConvertJsonToNumExt assigns all fields when values are in range.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNumExt_ValidValues_001, Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    nlohmann::json jsonObject = nlohmann::json{
        {"updateDeadLine", 111},
        {"finishDeadLine", 222},
        {"triggerDeadLine", 333},
        {"ownerUserId", 10},
        {"ownerUid", 20},
        {"notificationControlFlags", 30},
        {"snoozeDelayTime", 444}
    };
    notificationRequest.ConvertJsonToNumExt(&notificationRequest, jsonObject);
    EXPECT_EQ(notificationRequest.GetUpdateDeadLine(), 111);
    EXPECT_EQ(notificationRequest.GetFinishDeadLine(), 222);
    EXPECT_EQ(notificationRequest.GetGeofenceTriggerDeadLine(), 333);
    EXPECT_EQ(notificationRequest.GetOwnerUserId(), 10);
    EXPECT_EQ(notificationRequest.GetOwnerUid(), 20);
    EXPECT_EQ(notificationRequest.GetNotificationControlFlags(), 30U);
    EXPECT_EQ(notificationRequest.GetSnoozeDelayTime(), 444);
}

/**
 * @tc.name: ConvertJsonToNumExt_NonIntegerValues_001
 * @tc.desc: Test ConvertJsonToNumExt skips fields when values are not integers.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNumExt_NonIntegerValues_001, Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    int64_t defaultUpdateDeadLine = notificationRequest.GetUpdateDeadLine();
    int64_t defaultFinishDeadLine = notificationRequest.GetFinishDeadLine();
    int64_t defaultTriggerDeadLine = notificationRequest.GetGeofenceTriggerDeadLine();
    int32_t defaultOwnerUserId = notificationRequest.GetOwnerUserId();
    int32_t defaultOwnerUid = notificationRequest.GetOwnerUid();
    uint32_t defaultFlags = notificationRequest.GetNotificationControlFlags();
    int64_t defaultSnoozeDelayTime = notificationRequest.GetSnoozeDelayTime();

    nlohmann::json jsonObject = nlohmann::json{
        {"updateDeadLine", "abc"},
        {"finishDeadLine", "abc"},
        {"triggerDeadLine", "abc"},
        {"ownerUserId", "abc"},
        {"ownerUid", "abc"},
        {"notificationControlFlags", "abc"},
        {"snoozeDelayTime", "abc"}
    };
    notificationRequest.ConvertJsonToNumExt(&notificationRequest, jsonObject);
    EXPECT_EQ(notificationRequest.GetUpdateDeadLine(), defaultUpdateDeadLine);
    EXPECT_EQ(notificationRequest.GetFinishDeadLine(), defaultFinishDeadLine);
    EXPECT_EQ(notificationRequest.GetGeofenceTriggerDeadLine(), defaultTriggerDeadLine);
    EXPECT_EQ(notificationRequest.GetOwnerUserId(), defaultOwnerUserId);
    EXPECT_EQ(notificationRequest.GetOwnerUid(), defaultOwnerUid);
    EXPECT_EQ(notificationRequest.GetNotificationControlFlags(), defaultFlags);
    EXPECT_EQ(notificationRequest.GetSnoozeDelayTime(), defaultSnoozeDelayTime);
}

/**
 * @tc.name: ConvertJsonToNumExt_BoundaryValues_001
 * @tc.desc: Test ConvertJsonToNumExt assigns fields at boundary values.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNumExt_BoundaryValues_001, Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    nlohmann::json jsonObject = nlohmann::json{
        {"updateDeadLine", INT64_MIN},
        {"finishDeadLine", INT64_MAX},
        {"triggerDeadLine", -1},
        {"ownerUserId", INT32_MIN},
        {"ownerUid", INT32_MAX},
        {"notificationControlFlags", 4294967295LL},
        {"snoozeDelayTime", 0}
    };
    notificationRequest.ConvertJsonToNumExt(&notificationRequest, jsonObject);
    EXPECT_EQ(notificationRequest.GetUpdateDeadLine(), INT64_MIN);
    EXPECT_EQ(notificationRequest.GetFinishDeadLine(), INT64_MAX);
    EXPECT_EQ(notificationRequest.GetGeofenceTriggerDeadLine(), -1);
    EXPECT_EQ(notificationRequest.GetOwnerUserId(), INT32_MIN);
    EXPECT_EQ(notificationRequest.GetOwnerUid(), INT32_MAX);
    EXPECT_EQ(notificationRequest.GetNotificationControlFlags(), 4294967295U);
    EXPECT_EQ(notificationRequest.GetSnoozeDelayTime(), 0);
}

/**
 * @tc.name: ConvertJsonToNotificationTrigger_ValidTrigger_001
 * @tc.desc: Test ConvertJsonToNotificationTrigger succeeds with valid triggerType and triggerConfigPath.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNotificationTrigger_ValidTrigger_001,
    Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    nlohmann::json jsonObject = nlohmann::json{
        {"notificationTrigger", {{"triggerType", 1}, {"triggerConfigPath", 2}, {"triggerDisplayTime", 100}}}
    };
    bool result = notificationRequest.ConvertJsonToNotificationTrigger(&notificationRequest, jsonObject);
    EXPECT_EQ(result, true);
    auto trigger = notificationRequest.GetNotificationTrigger();
    ASSERT_NE(trigger, nullptr);
    EXPECT_EQ(trigger->GetTriggerType(), NotificationConstant::TriggerType::TRIGGER_TYPE_FENCE);
    EXPECT_EQ(trigger->GetConfigPath(), NotificationConstant::ConfigPath::CONFIG_PATH_CLOUD_CONFIG);
    EXPECT_EQ(trigger->GetDisplayTime(), 100);
}

/**
 * @tc.name: ConvertJsonToNotificationTrigger_TriggerTypeTooLarge_001
 * @tc.desc: Test ConvertJsonToNotificationTrigger returns false when triggerType is greater than range.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNotificationTrigger_TriggerTypeTooLarge_001,
    Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    nlohmann::json jsonObject = nlohmann::json{
        {"notificationTrigger", {{"triggerType", 2}}}
    };
    bool result = notificationRequest.ConvertJsonToNotificationTrigger(&notificationRequest, jsonObject);
    EXPECT_EQ(result, false);
    EXPECT_EQ(notificationRequest.GetNotificationTrigger(), nullptr);
}

/**
 * @tc.name: ConvertJsonToNotificationTrigger_ConfigPathTooLarge_001
 * @tc.desc: Test ConvertJsonToNotificationTrigger returns false when triggerConfigPath is greater than range.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNotificationTrigger_ConfigPathTooLarge_001,
    Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    nlohmann::json jsonObject = nlohmann::json{
        {"notificationTrigger", {{"triggerConfigPath", 3}}}
    };
    bool result = notificationRequest.ConvertJsonToNotificationTrigger(&notificationRequest, jsonObject);
    EXPECT_EQ(result, false);
    EXPECT_EQ(notificationRequest.GetNotificationTrigger(), nullptr);
}

/**
 * @tc.name: ConvertJsonToNotificationTrigger_NonIntegerValues_001
 * @tc.desc: Test ConvertJsonToNotificationTrigger skips validation when values are not integers.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNotificationTrigger_NonIntegerValues_001,
    Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    nlohmann::json jsonObject = nlohmann::json{
        {"notificationTrigger", {{"triggerType", "abc"}, {"triggerConfigPath", "xyz"}}}
    };
    bool result = notificationRequest.ConvertJsonToNotificationTrigger(&notificationRequest, jsonObject);
    EXPECT_EQ(result, true);
    auto trigger = notificationRequest.GetNotificationTrigger();
    ASSERT_NE(trigger, nullptr);
    EXPECT_EQ(trigger->GetConfigPath(), NotificationConstant::ConfigPath::CONFIG_PATH_DEVICE_CONFIG);
}

/**
 * @tc.name: ConvertJsonToNotificationTrigger_NoTypeAndConfigKeys_001
 * @tc.desc: Test ConvertJsonToNotificationTrigger succeeds when triggerType and triggerConfigPath keys are absent.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNotificationTrigger_NoTypeAndConfigKeys_001,
    Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    nlohmann::json jsonObject = nlohmann::json{
        {"notificationTrigger", {{"triggerDisplayTime", 50}}}
    };
    bool result = notificationRequest.ConvertJsonToNotificationTrigger(&notificationRequest, jsonObject);
    EXPECT_EQ(result, true);
    auto trigger = notificationRequest.GetNotificationTrigger();
    ASSERT_NE(trigger, nullptr);
    EXPECT_EQ(trigger->GetDisplayTime(), 50);
}

/**
 * @tc.name: ConvertJsonToNotificationTrigger_NotObject_001
 * @tc.desc: Test ConvertJsonToNotificationTrigger returns false when notificationTrigger is not an object.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToNotificationTrigger_NotObject_001,
    Function | SmallTest | Level1)
{
    NotificationRequest notificationRequest(10);
    nlohmann::json jsonObject = nlohmann::json{{"notificationTrigger", 123}};
    bool result = notificationRequest.ConvertJsonToNotificationTrigger(&notificationRequest, jsonObject);
    EXPECT_EQ(result, false);
    EXPECT_EQ(notificationRequest.GetNotificationTrigger(), nullptr);
}


/**
 * @tc.name: CheckNotificationRequest_NullNewContent_001
 * @tc.desc: Test CheckNotificationRequest when new request is common live view but
 *           notificationContent_ is nullptr (IPC/JSON inconsistent state: type set, content absent).
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, CheckNotificationRequest_NullNewContent_001, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    notificationRequest.notificationContent_ = nullptr;
    notificationRequest.notificationContentType_ = NotificationContent::Type::LIVE_VIEW;
    EXPECT_TRUE(notificationRequest.IsCommonLiveView());
 
    ErrCode result = notificationRequest.CheckNotificationRequest(nullptr);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}
 
/**
 * @tc.name: CheckNotificationRequest_NullNewContent_002
 * @tc.desc: Test CheckNotificationRequest when new request is common live view with null
 *           notificationContent_ and oldRequest is a valid live view request.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, CheckNotificationRequest_NullNewContent_002, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    notificationRequest.notificationContent_ = nullptr;
    notificationRequest.notificationContentType_ = NotificationContent::Type::LIVE_VIEW;
 
    sptr<NotificationRequest> oldRequest(new (std::nothrow) NotificationRequest());
    oldRequest->SetNotificationId(myNotificationId);
    oldRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto oldLiveContent = std::make_shared<NotificationLiveViewContent>();
    oldLiveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    auto oldContent = std::make_shared<NotificationContent>(oldLiveContent);
    oldRequest->SetContent(oldContent);
 
    ErrCode result = notificationRequest.CheckNotificationRequest(oldRequest);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}
 
/**
 * @tc.name: CheckNotificationRequest_NullNewInnerContent_001
 * @tc.desc: Test CheckNotificationRequest when new request is common live view, notificationContent_
 *           is non-null but its inner content is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, CheckNotificationRequest_NullNewInnerContent_001, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    notificationRequest.notificationContent_ = std::make_shared<NotificationContent>();
    notificationRequest.notificationContentType_ = NotificationContent::Type::LIVE_VIEW;
    EXPECT_EQ(notificationRequest.GetContent()->GetNotificationContent(), nullptr);
 
    ErrCode result = notificationRequest.CheckNotificationRequest(nullptr);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}
 
/**
 * @tc.name: CheckNotificationRequest_NullNewInnerContent_002
 * @tc.desc: Test CheckNotificationRequest when new request inner content is nullptr and
 *           oldRequest is a valid live view request.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, CheckNotificationRequest_NullNewInnerContent_002, Level1)
{
    int32_t myNotificationId = 10;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    notificationRequest.notificationContent_ = std::make_shared<NotificationContent>();
    notificationRequest.notificationContentType_ = NotificationContent::Type::LIVE_VIEW;
 
    sptr<NotificationRequest> oldRequest(new (std::nothrow) NotificationRequest());
    oldRequest->SetNotificationId(myNotificationId);
    oldRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto oldLiveContent = std::make_shared<NotificationLiveViewContent>();
    oldLiveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    auto oldContent = std::make_shared<NotificationContent>(oldLiveContent);
    oldRequest->SetContent(oldContent);
 
    ErrCode result = notificationRequest.CheckNotificationRequest(oldRequest);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}
 
/**
 * @tc.name: ConvertJsonToEnum_ValidContentType_001
 * @tc.desc: Test ConvertJsonToEnum accepts valid notificationContentType values.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, ConvertJsonToEnum_ValidContentType_001, Level1)
{
    NotificationRequest notificationRequest(10);
    nlohmann::json jsonObject = nlohmann::json{
        {"notificationContentType", static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW)},
    };
    NotificationRequest::ConvertJsonToEnum(&notificationRequest, jsonObject);
    EXPECT_EQ(notificationRequest.GetNotificationType(), NotificationContent::Type::LIVE_VIEW);
}
 
/**
 * @tc.name: FromJson_ContentTypeSyncWithContent_001
 * @tc.desc: Test FromJson syncs notificationContentType_ from the actual content object,
 *           preventing LIVE_VIEW type confusion when content is another type.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, FromJson_ContentTypeSyncWithContent_001, Level1)
{
    nlohmann::json jsonObject = nlohmann::json{
        {"slotType", static_cast<int32_t>(NotificationConstant::SlotType::LIVE_VIEW)},
        {"notificationContentType", static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW)},
        {"content", {
            {"contentType", static_cast<int32_t>(NotificationContent::Type::BASIC_TEXT)},
            {"content", {{"text", "test text"}, {"title", "test title"}}}
        }},
    };
 
    auto *request = NotificationRequest::FromJson(jsonObject);
    ASSERT_NE(request, nullptr);
    EXPECT_NE(request->GetContent(), nullptr);
    EXPECT_EQ(request->GetContent()->GetContentType(), NotificationContent::Type::BASIC_TEXT);
    EXPECT_EQ(request->GetNotificationType(), NotificationContent::Type::LIVE_VIEW);
    EXPECT_TRUE(request->IsCommonLiveView());
    delete request;
}
 
/**
 * @tc.name: FromJson_LiveViewContentConsistent_001
 * @tc.desc: Test FromJson keeps LIVE_VIEW type when content is a real live view content
 *           and CheckNotificationRequest works on the parsed request.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, FromJson_LiveViewContentConsistent_001, Level1)
{
    nlohmann::json jsonObject = nlohmann::json{
        {"slotType", static_cast<int32_t>(NotificationConstant::SlotType::LIVE_VIEW)},
        {"notificationContentType", static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW)},
        {"content", {
            {"contentType", static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW)},
            {"content", {{"text", "test text"}, {"title", "test title"},
                {"status", static_cast<int32_t>(
                    NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE)}}}
        }},
    };
 
    auto *request = NotificationRequest::FromJson(jsonObject);
    ASSERT_NE(request, nullptr);
    EXPECT_EQ(request->GetNotificationType(), NotificationContent::Type::LIVE_VIEW);
    EXPECT_TRUE(request->IsCommonLiveView());
    EXPECT_EQ(request->CheckNotificationRequest(nullptr), ERR_OK);
    delete request;
}
 
/**
 * @tc.name: FromJson_LiveViewWithoutContent_001
 * @tc.desc: Test CheckNotificationRequest on a request parsed from JSON which declares
 *           LIVE_VIEW type but carries no content object (no crash, invalid param).
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRequestTest, FromJson_LiveViewWithoutContent_001, Level1)
{
    nlohmann::json jsonObject = nlohmann::json{
        {"slotType", static_cast<int32_t>(NotificationConstant::SlotType::LIVE_VIEW)},
        {"notificationContentType", static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW)},
        {"content", nullptr},
    };
 
    auto *request = NotificationRequest::FromJson(jsonObject);
    ASSERT_NE(request, nullptr);
    EXPECT_EQ(request->GetContent(), nullptr);
    EXPECT_TRUE(request->IsCommonLiveView());
    EXPECT_EQ(request->CheckNotificationRequest(nullptr), ERR_ANS_INNER_INVALID_PARAM);
    delete request;
}
} // namespace Notification
} // namespace OHOS
