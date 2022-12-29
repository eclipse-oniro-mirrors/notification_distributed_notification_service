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
}
}
