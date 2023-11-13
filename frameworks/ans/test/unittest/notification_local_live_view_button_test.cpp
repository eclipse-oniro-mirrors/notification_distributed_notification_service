/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <string>
#include <unistd.h>
#include "notification_local_live_view_button.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationLocalLiveViewButtonTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: AddSingleButtonName__00001
 * @tc.desc: Test buttonNames_ parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, AddSingleButtonName__00001, Function | SmallTest | Level1)
{
    std::string buttonName = "testOneButton";
    auto rrc = std::make_shared<NotificationLocalLiveViewButton>();
    rrc->addSingleButtonName(buttonName);
    EXPECT_EQ(rrc->GetAllButtonNames()[0], buttonName);
}

/**
 * @tc.name: AddSingleButtonName__00002
 * @tc.desc: Test buttonNames_ parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, AddSingleButtonName__00002, Function | SmallTest | Level1)
{
    std::string buttonName = "testOneButton";
    auto rrc = std::make_shared<NotificationLocalLiveViewButton>();
    rrc->addSingleButtonName(buttonName);
    EXPECT_EQ(rrc->GetAllButtonNames().size(), 1);
}

/**
 * @tc.name: AddSingleButtonName__00003
 * @tc.desc: Test buttonNames_ parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, AddSingleButtonName__00003, Function | SmallTest | Level1)
{
    std::string buttonNameOne = "testOneButton";
    std::string buttonNameTwo = "testTwoButton";
    std::string buttonNameThree = "testThreeButton";
    std::string buttonNameFour = "testFourButton";
    auto rrc = std::make_shared<NotificationLocalLiveViewButton>();
    rrc->addSingleButtonName(buttonNameOne);
    rrc->addSingleButtonName(buttonNameTwo);
    rrc->addSingleButtonName(buttonNameThree);
    rrc->addSingleButtonName(buttonNameFour);
    EXPECT_EQ(rrc->GetAllButtonNames().size(), 3);
}

/**
 * @tc.name: ToJson_00001
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, ToJson_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    auto rrc = std::make_shared<NotificationLocalLiveViewButton>();
    rrc->FromJson(jsonObject);
    EXPECT_EQ(rrc->ToJson(jsonObject), true);
}

/**
 * @tc.name: FromJson_00001
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, FromJson_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLocalLiveViewButton>();
    nlohmann::json jsonObject = nlohmann::json{"test"};
    EXPECT_EQ(jsonObject.is_object(), false);
    EXPECT_EQ(rrc->FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationLocalLiveViewButton>();
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    std::shared_ptr<NotificationLocalLiveViewButton> result =
    std::make_shared<NotificationLocalLiveViewButton>();

    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, true);
}
}
}
