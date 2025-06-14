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
#include <memory>

#define private public
#define protected public
#include "notification_action_button.h"
#undef private
#undef protected

#include "want_agent_helper.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationActionButtontTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: AddMimeTypeOnlyUserInput_0100
 * @tc.desc: AddMimeTypeOnlyUserInput
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationActionButtontTest, AddActionButton_0100, Level1)
{
    std::shared_ptr<NotificationActionButton> actionButton = nullptr;
    std::shared_ptr<NotificationActionButton> notificationActionButton =
        NotificationActionButton::Create(actionButton);
    AbilityRuntime::WantAgent::WantAgentInfo paramsInfo;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(paramsInfo);
    std::shared_ptr<NotificationActionButton> actionButton1 =
        NotificationActionButton::Create(nullptr, "title", wantAgent);
    std::shared_ptr<NotificationActionButton> notificationActionButton1 =
        NotificationActionButton::Create(actionButton1);
    notificationActionButton1->AddMimeTypeOnlyUserInput(nullptr);
    EXPECT_EQ(notificationActionButton, nullptr);
}

/**
 * @tc.name: Marshalling_0100
 * @tc.desc: Marshalling
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationActionButtontTest, Marshalling_0100, Level1)
{
    AbilityRuntime::WantAgent::WantAgentInfo paramsInfo;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(paramsInfo);
    std::shared_ptr<NotificationActionButton> actionButton1 =
        NotificationActionButton::Create(nullptr, "title", wantAgent);
    std::shared_ptr<NotificationActionButton> notificationActionButton1 =
        NotificationActionButton::Create(actionButton1);

    Parcel parcel;
    bool result = notificationActionButton1->Marshalling(parcel);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: Unmarshalling_0100
 * @tc.desc: Unmarshalling
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationActionButtontTest, Unmarshalling_0100, Level1)
{
    AbilityRuntime::WantAgent::WantAgentInfo paramsInfo;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(paramsInfo);
    std::shared_ptr<NotificationActionButton> actionButton1 =
        NotificationActionButton::Create(nullptr, "title", wantAgent);
    std::shared_ptr<NotificationActionButton> notificationActionButton1 =
        NotificationActionButton::Create(actionButton1);

    Parcel parcel;
    bool result = notificationActionButton1->ReadFromParcel(parcel);
    notificationActionButton1->Unmarshalling(parcel);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: Unmarshalling_0200
 * @tc.desc: Unmarshalling
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(NotificationActionButtontTest, Unmarshalling_0200, Level1)
{
    std::shared_ptr<Media::PixelMap> icon = nullptr;
    std::string title = "thios is title";
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent = nullptr;
    std::shared_ptr<AAFwk::WantParams> extras;
    NotificationConstant::SemanticActionButton semanticActionButton =
        NotificationConstant::SemanticActionButton(2);
    bool autoCreatedReplies = true;
    auto userInput = std::make_shared<NotificationUserInput>();
    std::vector<std::string> options = {"test1", "test2"};
    userInput->SetOptions(options);
    userInput->SetPermitMimeTypes("test", true);
    std::vector<std::shared_ptr<NotificationUserInput>> mimeTypeOnlyInputs = {userInput};
    bool isContextual = false;

    auto button = std::make_shared<NotificationActionButton>(icon, title, wantAgent, extras,
        semanticActionButton, autoCreatedReplies, mimeTypeOnlyInputs, userInput, isContextual);
    Parcel parcel;
    EXPECT_EQ(button->Marshalling(parcel), true);
    EXPECT_NE(button->Unmarshalling(parcel), nullptr);
}

/**
 * @tc.name: Create_00001
 * @tc.desc: Test Create parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationActionButtontTest, Create_00001, Function | SmallTest | Level1)
{
    std::shared_ptr<Media::PixelMap> icon = nullptr;
    std::string title = "thios is title";
    AbilityRuntime::WantAgent::WantAgentInfo paramsInfo;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent = nullptr;
    std::shared_ptr<AAFwk::WantParams> extras;
    NotificationConstant::SemanticActionButton semanticActionButton =
        NotificationConstant::SemanticActionButton(2);
    bool autoCreatedReplies = true;
    std::vector<std::shared_ptr<NotificationUserInput>> mimeTypeOnlyInputs;
    std::shared_ptr<NotificationUserInput> userInput;
    bool isContextual = true;
    std::shared_ptr<NotificationActionButton> notificationActionButton = std::make_shared<NotificationActionButton>();
    ASSERT_NE(nullptr, notificationActionButton);
    std::shared_ptr<NotificationActionButton> result = notificationActionButton->Create
    (icon, title, wantAgent, extras, semanticActionButton,
    autoCreatedReplies, mimeTypeOnlyInputs, userInput, isContextual);
}

/**
 * @tc.name: Create_00002
 * @tc.desc: Test Create parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationActionButtontTest, Create_00002, Function | SmallTest | Level1)
{
    std::shared_ptr<Media::PixelMap> icon = std::make_shared<Media::PixelMap>();
    std::string title = "thios is title";
    AbilityRuntime::WantAgent::WantAgentInfo paramsInfo;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(paramsInfo);
    std::shared_ptr<AAFwk::WantParams> extras;
    NotificationConstant::SemanticActionButton semanticActionButton =
        NotificationConstant::SemanticActionButton(2);
    bool autoCreatedReplies = true;
    std::vector<std::shared_ptr<NotificationUserInput>> mimeTypeOnlyInputs;
    std::shared_ptr<NotificationUserInput> userInput;
    bool isContextual = true;
    auto rrc = std::make_shared<NotificationActionButton>();
    ASSERT_NE(nullptr, rrc);
    rrc->Create(icon, title, wantAgent, extras, semanticActionButton,
    autoCreatedReplies, mimeTypeOnlyInputs, userInput, isContextual);
}

/**
 * @tc.name: Create_00003
 * @tc.desc: Test Create parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationActionButtontTest, Create_00003, Function | SmallTest | Level1)
{
    std::shared_ptr<Media::PixelMap> icon = std::make_shared<Media::PixelMap>();
    std::string title = "thios is title";
    AbilityRuntime::WantAgent::WantAgentInfo paramsInfo;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        std::make_shared<AbilityRuntime::WantAgent::WantAgent>();
    std::shared_ptr<AAFwk::WantParams> extras;
    NotificationConstant::SemanticActionButton semanticActionButton =
        NotificationConstant::SemanticActionButton(2);
    bool autoCreatedReplies = true;
    std::vector<std::shared_ptr<NotificationUserInput>> mimeTypeOnlyInputs;
    ASSERT_EQ(mimeTypeOnlyInputs.size(), 0);
    std::shared_ptr<NotificationUserInput> userInput = std::make_shared<NotificationUserInput>();
    userInput->SetPermitFreeFormInput(false);
    userInput->SetPermitMimeTypes("test", true);
    bool isContextual = true;

    std::shared_ptr<NotificationActionButton> notificationActionButton = std::make_shared<NotificationActionButton>();
    
    std::shared_ptr<NotificationActionButton> result = notificationActionButton->Create
    (icon, title, wantAgent, extras, semanticActionButton,
    autoCreatedReplies, mimeTypeOnlyInputs, userInput, isContextual);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->GetMimeTypeOnlyUserInputs().size(), 1);
}

/**
 * @tc.name: Dump_00002
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationActionButtontTest, Dump_00002, Function | SmallTest | Level1)
{
    std::shared_ptr<Media::PixelMap> icon = std::make_shared<Media::PixelMap>();
    std::string title = "thios is title";
    AbilityRuntime::WantAgent::WantAgentInfo paramsInfo;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        std::make_shared<AbilityRuntime::WantAgent::WantAgent>();
    std::shared_ptr<AAFwk::WantParams> extras;
    NotificationConstant::SemanticActionButton semanticActionButton =
        NotificationConstant::SemanticActionButton(2);
    bool autoCreatedReplies = true;
    std::vector<std::shared_ptr<NotificationUserInput>> mimeTypeOnlyInputs;
    ASSERT_EQ(mimeTypeOnlyInputs.size(), 0);
    std::shared_ptr<NotificationUserInput> userInput = std::make_shared<NotificationUserInput>();
    userInput->SetPermitFreeFormInput(false);
    userInput->SetPermitMimeTypes("test", true);
    bool isContextual = true;

    std::shared_ptr<NotificationActionButton> notificationActionButton = std::make_shared<NotificationActionButton>();
    
    std::shared_ptr<NotificationActionButton> result = notificationActionButton->Create
    (icon, title, wantAgent, extras, semanticActionButton,
    autoCreatedReplies, mimeTypeOnlyInputs, userInput, isContextual);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->GetMimeTypeOnlyUserInputs().size(), 1);
    std::string temp = result->Dump();

    auto it = temp.find("mimeTypeOnlyUserInputs");
    ASSERT_NE(it, std::string::npos);
}


/**
 * @tc.name: FromJson_00002
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationActionButtontTest, FromJson_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationActionButton>();
    nlohmann::json jsonObject = nlohmann::json{"processName", "soundEnabled", "name", "arrivedTime1"};
    rrc->FromJson(jsonObject);
    EXPECT_EQ(jsonObject.is_object(), false);
    EXPECT_EQ(rrc->FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: FromJson_00003
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationActionButtontTest, FromJson_00003, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationActionButton>();
    nlohmann::json jsonObject = nlohmann::json{
        {"processName", "process6"}, {"APL", 1},
        {"version", 2}, {"tokenId", 685266937},
        {"tokenAttr", 0},
        {"dcaps", {"AT_CAP", "ST_CAP"}}};
    rrc->FromJson(jsonObject);
    EXPECT_EQ(jsonObject.is_object(), true);
}

/**
 * @tc.name: FromJson_00004
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationActionButtontTest, FromJson_00004, Function | SmallTest | Level1)
{
    std::shared_ptr<Media::PixelMap> icon = std::make_shared<Media::PixelMap>();
    std::string title = "test";
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        std::make_shared<AbilityRuntime::WantAgent::WantAgent>();
    std::shared_ptr<AAFwk::WantParams> extras = std::make_shared<AAFwk::WantParams>();
    NotificationConstant::SemanticActionButton semanticActionButton =
        NotificationConstant::SemanticActionButton(2);
    bool autoCreatedReplies = true;
    std::vector<std::shared_ptr<NotificationUserInput>> mimeTypeOnlyInputs;
    ASSERT_EQ(mimeTypeOnlyInputs.size(), 0);
    std::shared_ptr<NotificationUserInput> userInput = std::make_shared<NotificationUserInput>();
    userInput->SetPermitFreeFormInput(false);
    userInput->SetPermitMimeTypes("test", true);
    bool isContextual = true;
    
    std::shared_ptr<NotificationActionButton> notificationActionButton = std::make_shared<NotificationActionButton>();
    std::shared_ptr<NotificationActionButton> rrc = notificationActionButton->Create
    (icon, title, wantAgent, extras, semanticActionButton,
    autoCreatedReplies, mimeTypeOnlyInputs, userInput, isContextual);
    
    nlohmann::json jsonObject;
    auto res = rrc->ToJson(jsonObject);
    ASSERT_EQ(res, true);

    std::string jsonString = jsonObject.dump();
    auto it = jsonString.find("icon");
    ASSERT_NE(it, std::string::npos);
    it = jsonString.find("extras");
    ASSERT_NE(it, std::string::npos);
    it = jsonString.find("wantAgent");
    ASSERT_NE(it, std::string::npos);

    auto temp = rrc->FromJson(jsonObject);
    ASSERT_NE(temp, nullptr);
    ASSERT_EQ(temp->GetTitle(), "test");
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationActionButtontTest, Dump_00001, Function | SmallTest | Level1)
{
    auto button = std::make_shared<NotificationActionButton>();
    auto userInput = std::make_shared<NotificationUserInput>();
    userInput->SetPermitFreeFormInput(false);
    userInput->SetPermitMimeTypes("test", true);
    button->AddMimeTypeOnlyUserInput(userInput);
    button->AddNotificationUserInput(userInput);

    EXPECT_EQ(button->GetMimeTypeOnlyUserInputs().size(), 1);
    EXPECT_NE(button->GetUserInput(), nullptr);

    std::string dumpStr = "";
    EXPECT_NE(button->Dump(), dumpStr);
}

}
}
