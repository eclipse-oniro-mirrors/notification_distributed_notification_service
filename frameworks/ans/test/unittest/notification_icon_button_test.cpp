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
#include "notification_icon_button.h"
#include "ans_image_util.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationIconButtonTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(NotificationIconButtonTest, ToJson_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    auto rrc = std::make_shared<NotificationIconButton>();
    rrc->SetText("text");
    rrc->SetName("name");
    rrc->SetHidePanel(true);
    auto resource = std::make_shared<ResourceManager::Resource>();
    resource->id = 1;
    resource->bundleName = "bundleName";
    resource->moduleName = "moduleName";
    rrc->SetIconResource(resource);
    std::shared_ptr<Media::PixelMap> iconImage = std::make_shared<Media::PixelMap>();
    rrc->SetIconImage(iconImage);
    EXPECT_EQ(rrc->ToJson(jsonObject), true);
}

HWTEST_F(NotificationIconButtonTest, ToJson_00002_With_PixelMap, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    auto rrc = std::make_shared<NotificationIconButton>();
    rrc->SetText("text");
    rrc->SetName("name");
    rrc->SetHidePanel(true);
    std::shared_ptr<Media::PixelMap> iconImage = std::make_shared<Media::PixelMap>();
    rrc->SetIconImage(iconImage);
    EXPECT_EQ(rrc->ToJson(jsonObject), true);
}

HWTEST_F(NotificationIconButtonTest, ToJson_With_Res, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    auto rrc = std::make_shared<NotificationIconButton>();
    rrc->SetText("text");
    rrc->SetName("name");
    rrc->SetHidePanel(true);
    auto resource = std::make_shared<ResourceManager::Resource>();
    resource->id = 1;
    resource->bundleName = "bundleName";
    resource->moduleName = "moduleName";
    rrc->SetIconResource(resource);
    EXPECT_EQ(rrc->ToJson(jsonObject), true);
}

HWTEST_F(NotificationIconButtonTest, ToJson_Without_All, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    auto rrc = std::make_shared<NotificationIconButton>();
    EXPECT_EQ(rrc->ToJson(jsonObject), true);
}

/**
 * @tc.name: FromJson_00001
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationIconButtonTest, FromJson_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationIconButton>();
    nlohmann::json jsonObject = nlohmann::json{"testjson"};
    EXPECT_EQ(jsonObject.is_object(), false);
    EXPECT_EQ(rrc->FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: FromJson_00002
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationIconButtonTest, FromJson_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationIconButton>();
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
HWTEST_F(NotificationIconButtonTest, FromJson_00003, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationIconButton>();
    nlohmann::json jsonObject = nlohmann::json{{"names", {"test"}}, {"icons", {1, "testIcons"}}};
    EXPECT_EQ(jsonObject.is_object(), true);
    EXPECT_NE(rrc->FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: Marshalling_00002
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationIconButtonTest, Marshalling_00002, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto button = std::make_shared<NotificationIconButton>();
    button->SetText("test");
    EXPECT_EQ(button->Marshalling(parcel), true);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationIconButtonTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationIconButton>();
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationIconButtonTest, Unmarshalling_00001, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    std::shared_ptr<NotificationIconButton> result =
        std::make_shared<NotificationIconButton>();

    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, false);
}

/**
 * @tc.name: Unmarshalling_00002
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationIconButtonTest, Unmarshalling_00002, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto button = std::make_shared<NotificationIconButton>();
    button->SetText("testText");
    button->SetName("testName");
    button->Marshalling(parcel);

    auto newButton = button->Unmarshalling(parcel);
    EXPECT_NE(newButton, nullptr);
}


/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationIconButtonTest, Dump_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationIconButton>();
    rrc->SetName("test");
    EXPECT_EQ(rrc->Dump(), "NotificationIconButton {name = test, text = , hidePanel = 0 }");
}
}
}
