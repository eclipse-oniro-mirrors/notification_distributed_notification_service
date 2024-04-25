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
#include "ans_image_util.h"

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
 * @tc.name: AddSingleButtonName_00001
 * @tc.desc: Test buttonNames_ parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, AddSingleButtonName_00001, Function | SmallTest | Level1)
{
    std::string buttonName = "testOneButton";
    auto rrc = std::make_shared<NotificationLocalLiveViewButton>();
    rrc->addSingleButtonName(buttonName);
    EXPECT_EQ(rrc->GetAllButtonNames()[0], buttonName);
}

/**
 * @tc.name: AddSingleButtonName_00002
 * @tc.desc: Test buttonNames_ parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, AddSingleButtonName_00002, Function | SmallTest | Level1)
{
    std::string buttonName = "testOneButton";
    auto rrc = std::make_shared<NotificationLocalLiveViewButton>();
    rrc->addSingleButtonName(buttonName);
    EXPECT_EQ(rrc->GetAllButtonNames().size(), 1);
}

/**
 * @tc.name: AddSingleButtonName_00003
 * @tc.desc: Test buttonNames_ parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, AddSingleButtonName_00003, Function | SmallTest | Level1)
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
 * @tc.name: addSingleButtonIcon_00001
 * @tc.desc: Test buttonNames_ parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, addSingleButtonIcon_00001, Function | SmallTest | Level1)
{
    auto pixelMapOne = std::make_shared<Media::PixelMap>();
    auto pixelMapTwo = std::make_shared<Media::PixelMap>();
    auto pixelMapThree = std::make_shared<Media::PixelMap>();
    auto pixelMapFour = std::make_shared<Media::PixelMap>();
    auto rrc = std::make_shared<NotificationLocalLiveViewButton>();
    rrc->addSingleButtonIcon(pixelMapOne);
    rrc->addSingleButtonIcon(pixelMapTwo);
    rrc->addSingleButtonIcon(pixelMapThree);
    rrc->addSingleButtonIcon(pixelMapFour);

    EXPECT_EQ(rrc->GetAllButtonIcons().size(), 3);
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
 * @tc.name: ToJson_00002
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, ToJson_00002, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    auto button = std::make_shared<NotificationLocalLiveViewButton>();
    auto pixelMap = std::make_shared<Media::PixelMap>();
    button->addSingleButtonIcon(pixelMap);

    EXPECT_EQ(button->ToJson(jsonObject), true);
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
 * @tc.name: FromJson_00002
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, FromJson_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLocalLiveViewButton>();
    nlohmann::json jsonObject = nlohmann::json{{"names", {"test"}}, {"icons", {}}};
    EXPECT_EQ(jsonObject.is_object(), true);
    EXPECT_NE(rrc->FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: FromJson_00003
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, FromJson_00003, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLocalLiveViewButton>();
    nlohmann::json jsonObject = nlohmann::json{{"names", {"test"}}, {"icons", {1, "testIcons"}}};
    EXPECT_EQ(jsonObject.is_object(), true);
    EXPECT_EQ(rrc->FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: Marshalling_00002
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, Marshalling_00002, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto button = std::make_shared<NotificationLocalLiveViewButton>();
    button->addSingleButtonName("test");
    auto pixelMap = std::make_shared<Media::PixelMap>();
    button->addSingleButtonIcon(pixelMap);

    EXPECT_EQ(button->Marshalling(parcel), false);
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
HWTEST_F(NotificationLocalLiveViewButtonTest, Unmarshalling_00001, Function | SmallTest | Level1)
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

/**
 * @tc.name: Unmarshalling_00002
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, Unmarshalling_00002, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto button = std::make_shared<NotificationLocalLiveViewButton>();
    button->addSingleButtonName("test");
    button->Marshalling(parcel);

    auto newButton = button->Unmarshalling(parcel);
    EXPECT_NE(newButton, nullptr);
}

/**
 * @tc.name: Unmarshalling_00003
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, Unmarshalling_00003, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto button = std::make_shared<NotificationLocalLiveViewButton>();
    std::shared_ptr<Media::PixelMap> icon = std::make_shared<Media::PixelMap>();
    button->addSingleButtonName("test");
    button->addSingleButtonIcon(icon);
    button->Marshalling(parcel);
    
    auto newButton = button->Unmarshalling(parcel);
    EXPECT_EQ(newButton, nullptr);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, Dump_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLocalLiveViewButton>();

    EXPECT_EQ(rrc->Dump(), "");
}
}
}
