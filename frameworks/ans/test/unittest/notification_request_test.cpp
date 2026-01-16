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
#include "notification_conversational_content.h"
#include "notification_live_view_content.h"
#include "notification_multiline_content.h"
#include "notification_request.h"
#include "pixel_map.h"
#undef private
#undef protected
#include "want_agent_helper.h"
#include "string_wrapper.h"

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
    EXPECT_EQ(result, ERR_ANS_NOTIFICATION_NOT_EXISTS);
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
    EXPECT_EQ(result, ERR_ANS_INVALID_PARAM);
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
    EXPECT_EQ(result, ERR_ANS_END_NOTIFICATION);
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
    EXPECT_EQ(result, ERR_ANS_REPEAT_CREATE);
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
    EXPECT_EQ(result, ERR_ANS_EXPIRED_NOTIFICATION);
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
    EXPECT_EQ(result, ERR_ANS_EXPIRED_NOTIFICATION);
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
 * @tc.name: FillMissingParameters_0001
 * @tc.desc: Check no need to fill parameter when not live view request
 * @tc.type: FUNC
 * @tc.require: issue
 */
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
    EXPECT_EQ(result, ERR_ANS_PICTURE_OVER_SIZE);
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
    EXPECT_EQ(result, ERR_ANS_INVALID_PARAM);
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
    EXPECT_EQ(result, ERR_ANS_INVALID_PARAM);
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
    EXPECT_EQ(result, ERR_ANS_ICON_OVER_SIZE);
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
} // namespace Notification
} // namespace OHOS
