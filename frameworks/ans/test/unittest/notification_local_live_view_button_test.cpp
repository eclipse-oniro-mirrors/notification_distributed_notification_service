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

HWTEST_F(NotificationLocalLiveViewButtonTest, GetAllButtonIconResource_00001, Function | SmallTest | Level1)
{
    auto button = std::make_shared<NotificationLocalLiveViewButton>();
    auto resource = std::make_shared<ResourceManager::Resource>();
    resource->id = 1;
    resource->bundleName = "bundleName";
    resource->moduleName = "moduleName";
    button->addSingleButtonIconResource(resource);
    EXPECT_EQ(button->GetAllButtonIconResource().size(), 1);
    EXPECT_NE(button->GetAllButtonIconResource()[0], nullptr);
    EXPECT_EQ(button->GetAllButtonIconResource()[0]->bundleName, "bundleName");
}

HWTEST_F(NotificationLocalLiveViewButtonTest, addSingleButtonIconResource_00001, Function | SmallTest | Level1)
{
    auto button = std::make_shared<NotificationLocalLiveViewButton>();
    auto resource1 = std::make_shared<ResourceManager::Resource>();
    auto resource2 = std::make_shared<ResourceManager::Resource>();
    auto resource3 = std::make_shared<ResourceManager::Resource>();
    auto resource4 = std::make_shared<ResourceManager::Resource>();
    button->addSingleButtonIconResource(resource1);
    button->addSingleButtonIconResource(resource2);
    button->addSingleButtonIconResource(resource3);
    button->addSingleButtonIconResource(resource4);
    EXPECT_EQ(button->GetAllButtonIconResource().size(), 4);
}

HWTEST_F(NotificationLocalLiveViewButtonTest, ClearButtonIcons_00001, Function | SmallTest | Level1)
{
    auto button = std::make_shared<NotificationLocalLiveViewButton>();
    auto pixelMap = std::make_shared<Media::PixelMap>();
    button->addSingleButtonIcon(pixelMap);
    EXPECT_EQ(button->GetAllButtonIcons().size(), 1);
    button->ClearButtonIcons();
    EXPECT_EQ(button->GetAllButtonIcons().size(), 0);
}

HWTEST_F(NotificationLocalLiveViewButtonTest, ClearButtonIconsResource_00001, Function | SmallTest | Level1)
{
    auto button = std::make_shared<NotificationLocalLiveViewButton>();
    auto resource = std::make_shared<ResourceManager::Resource>();
    button->addSingleButtonIconResource(resource);
    EXPECT_EQ(button->GetAllButtonIconResource().size(), 1);
    button->ClearButtonIconsResource();
    EXPECT_EQ(button->GetAllButtonIconResource().size(), 0);
}

HWTEST_F(NotificationLocalLiveViewButtonTest, ToJson_00003, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    auto button = std::make_shared<NotificationLocalLiveViewButton>();
    button->addSingleButtonName("button1");
    auto resource = std::make_shared<ResourceManager::Resource>();
    resource->id = 1;
    resource->bundleName = "bundleName";
    resource->moduleName = "moduleName";
    button->addSingleButtonIconResource(resource);
    EXPECT_EQ(button->ToJson(jsonObject), true);
    EXPECT_TRUE(jsonObject.contains("iconResources"));
    EXPECT_EQ(jsonObject["iconResources"].size(), 1);
}

HWTEST_F(NotificationLocalLiveViewButtonTest, FromJson_00004, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{{"names", {"button1", "button2"}},
        {"iconResources", {nlohmann::json{{"bundleName", "bundleName"}, {"moduleName", "moduleName"}, {"id", 123}}}}};
    auto button = NotificationLocalLiveViewButton::FromJson(jsonObject);
    EXPECT_NE(button, nullptr);
    EXPECT_EQ(button->GetAllButtonNames().size(), 2);
    EXPECT_EQ(button->GetAllButtonIconResource().size(), 1);
    EXPECT_EQ(button->GetAllButtonIconResource()[0]->bundleName, "bundleName");
    EXPECT_EQ(button->GetAllButtonIconResource()[0]->moduleName, "moduleName");
    EXPECT_EQ(button->GetAllButtonIconResource()[0]->id, 123);
}

HWTEST_F(NotificationLocalLiveViewButtonTest, FromJson_00005, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{{"names", {"button1"}},
        {"iconResources", {nlohmann::json{{"bundleName", "bundleName"}}}}};
    auto button = NotificationLocalLiveViewButton::FromJson(jsonObject);
    EXPECT_NE(button, nullptr);
    EXPECT_EQ(button->GetAllButtonIconResource().size(), 0);
}

HWTEST_F(NotificationLocalLiveViewButtonTest, Marshalling_00003, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto button = std::make_shared<NotificationLocalLiveViewButton>();
    button->addSingleButtonName("button1");
    auto resource = std::make_shared<ResourceManager::Resource>();
    resource->id = 1;
    resource->bundleName = "bundleName";
    resource->moduleName = "moduleName";
    button->addSingleButtonIconResource(resource);
    EXPECT_EQ(button->Marshalling(parcel), true);
}

HWTEST_F(NotificationLocalLiveViewButtonTest, Marshalling_00004, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto button = std::make_shared<NotificationLocalLiveViewButton>();
    auto resource1 = std::make_shared<ResourceManager::Resource>();
    auto resource2 = std::make_shared<ResourceManager::Resource>();
    auto resource3 = std::make_shared<ResourceManager::Resource>();
    button->addSingleButtonIconResource(resource1);
    button->addSingleButtonIconResource(resource2);
    button->addSingleButtonIconResource(resource3);
    EXPECT_EQ(button->Marshalling(parcel), true);
}

HWTEST_F(NotificationLocalLiveViewButtonTest, Unmarshalling_00004, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteStringVector({"button1", "button2"});
    parcel.WriteUint64(0);
    parcel.WriteUint64(1);
    parcel.WriteStringVector({"bundleName", "moduleName", "123"});
    
    auto button = NotificationLocalLiveViewButton::Unmarshalling(parcel);
    EXPECT_NE(button, nullptr);
    EXPECT_EQ(button->GetAllButtonNames().size(), 2);
    EXPECT_EQ(button->GetAllButtonIconResource().size(), 1);
    EXPECT_EQ(button->GetAllButtonIconResource()[0]->bundleName, "bundleName");
    EXPECT_EQ(button->GetAllButtonIconResource()[0]->moduleName, "moduleName");
}

HWTEST_F(NotificationLocalLiveViewButtonTest, Unmarshalling_00005, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteStringVector({"button1"});
    parcel.WriteUint64(0);
    parcel.WriteUint64(2);
    parcel.WriteStringVector({"bundleName", "moduleName", "123"});
    parcel.WriteStringVector({"bundleName2", "moduleName2", "456"});
    
    auto button = NotificationLocalLiveViewButton::Unmarshalling(parcel);
    EXPECT_NE(button, nullptr);
    EXPECT_EQ(button->GetAllButtonIconResource().size(), 2);
}

HWTEST_F(NotificationLocalLiveViewButtonTest, Unmarshalling_00006, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteStringVector({"button1"});
    parcel.WriteUint64(0);
    parcel.WriteUint64(1);
    parcel.WriteStringVector({"bundleName", "moduleName"});
    
    auto button = NotificationLocalLiveViewButton::Unmarshalling(parcel);
    EXPECT_EQ(button, nullptr);
}

HWTEST_F(NotificationLocalLiveViewButtonTest, Unmarshalling_00007, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteStringVector({"button1"});
    parcel.WriteUint64(0);
    parcel.WriteUint64(1);
    parcel.WriteStringVector({"bundleName", "moduleName", "invalid"});
    
    auto button = NotificationLocalLiveViewButton::Unmarshalling(parcel);
    EXPECT_EQ(button, nullptr);
}

HWTEST_F(NotificationLocalLiveViewButtonTest, Unmarshalling_00008, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteStringVector({"button1"});
    parcel.WriteUint64(5);
    auto pixelMap = std::make_shared<Media::PixelMap>();
    parcel.WriteParcelable(pixelMap.get());
    parcel.WriteUint64(0);
    
    auto button = NotificationLocalLiveViewButton::Unmarshalling(parcel);
    EXPECT_EQ(button, nullptr);
}

/**
 * @tc.name: FromJson_00006
 * @tc.desc: Test FromJson with names containing non-string elements (should skip them).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, FromJson_00006, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{
        {"names", {1, "valid", true, "end"}}};
    auto *res = NotificationLocalLiveViewButton::FromJson(jsonObject);
    EXPECT_NE(res, nullptr);
    delete res;
}

/**
 * @tc.name: FromJson_00007
 * @tc.desc: Test FromJson with null json.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, FromJson_00007, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    auto *res = NotificationLocalLiveViewButton::FromJson(jsonObject);
    EXPECT_EQ(res, nullptr);
}

/**
 * @tc.name: FromJson_00008
 * @tc.desc: Test FromJson with names as non-array (should be ignored).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewButtonTest, FromJson_00008, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{
        {"names", "not_array"}};
    auto *res = NotificationLocalLiveViewButton::FromJson(jsonObject);
    EXPECT_NE(res, nullptr);
    delete res;
}
}
}
