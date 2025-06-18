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
#include "notification_local_live_view_content.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationLocalLiveViewContentTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetTypeCode_00001
 * @tc.desc: Test SetTypeCode parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewContentTest, SetTypeCode_00001, Function | SmallTest | Level1)
{
    int32_t typeCode = 1;
    auto rrc = std::make_shared<NotificationLocalLiveViewContent>();
    rrc->SetType(typeCode);
    EXPECT_EQ(rrc->GetType(), typeCode);
}


/**
 * @tc.name: ToJson_00001
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationLocalLiveViewContentTest, ToJson_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    auto rrc = std::make_shared<NotificationLocalLiveViewContent>();
    rrc->FromJson(jsonObject);
    EXPECT_EQ(rrc->ToJson(jsonObject), true);
}

/**
 * @tc.name: ToJson_00002
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewContentTest, ToJson_00002, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    auto liveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    NotificationCapsule capsule;
    capsule.SetTitle("testTitle");
    liveViewContent->SetCapsule(capsule);

    NotificationLocalLiveViewButton button;
    button.addSingleButtonName("test");
    liveViewContent->SetButton(button);

    NotificationProgress progress;
    progress.SetMaxValue(1);
    liveViewContent->SetProgress(progress);

    NotificationTime time;
    time.SetInitialTime(1);
    liveViewContent->SetTime(time);

    liveViewContent->addFlag(0);
    liveViewContent->ToJson(jsonObject);
    EXPECT_NE(jsonObject.dump(), "");
}

/**
 * @tc.name: FromJson_00001
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewContentTest, FromJson_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLocalLiveViewContent>();
    nlohmann::json jsonObject = nlohmann::json{"typeCode", "capsule", "button", "progress", "time"};
    rrc->FromJson(jsonObject);
    EXPECT_EQ(jsonObject.is_object(), false);
    EXPECT_EQ(rrc->FromJson(jsonObject), NULL);
}

/**
 * @tc.name: FromJson_00003
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewContentTest, FromJson_00003, Function | SmallTest | Level1)
{
    auto liveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    nlohmann::json jsonObject = nlohmann::json{
        {"additionalText", ""}, {"button", ""}, {"capsule", ""}, {"flags", ""},
        {"progress", ""}, {"text", ""}, {"time", ""}, {"title", ""}, {"typeCode", 1}};
    EXPECT_EQ(jsonObject.is_object(), true);
    auto *liveView = liveViewContent->FromJson(jsonObject);
    EXPECT_EQ(liveView->GetType(), 1);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationLocalLiveViewContentTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationLocalLiveViewContent>();
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationLocalLiveViewContentTest, Unmarshalling_00001, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    auto result = std::make_shared<NotificationLocalLiveViewContent>();

    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, false);
}

/**
 * @tc.name: FromJson_00002
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewContentTest, FromJson_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLocalLiveViewContent>();
    nlohmann::json jsonObject = nlohmann::json{
        {"longText", "test"},
        {"expandedTitle", "test"},
        {"briefText", "test"}};
    EXPECT_NE(rrc->FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: Unmarshalling_00002
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationLocalLiveViewContentTest, Unmarshalling_00002, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto liveViewContent = std::make_shared<NotificationLocalLiveViewContent>();

    NotificationCapsule capsule;
    capsule.SetTitle("testTitle");
    liveViewContent->SetCapsule(capsule);

    NotificationLocalLiveViewButton button;
    button.addSingleButtonName("test");
    liveViewContent->SetButton(button);

    NotificationProgress progress;
    progress.SetMaxValue(1);
    liveViewContent->SetProgress(progress);

    NotificationTime time;
    time.SetInitialTime(1);
    liveViewContent->SetTime(time);
    liveViewContent->addFlag(0);

    liveViewContent->Marshalling(parcel);
    EXPECT_NE(liveViewContent->Unmarshalling(parcel), nullptr);
}

/**
 * @tc.name: SetLocalLiveViewContent_00001
 * @tc.desc: Test Set liveViewContent attribute.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewContentTest, SetLocalLiveViewContent_00001, Function | SmallTest | Level1)
{
    NotificationCapsule capsule;
    capsule.SetTitle("testTitle");
    auto liveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    liveViewContent->SetCapsule(capsule);
    EXPECT_EQ(liveViewContent->GetCapsule().GetTitle(), "testTitle");

    NotificationLocalLiveViewButton button;
    button.addSingleButtonName("test");
    liveViewContent->SetButton(button);
    EXPECT_EQ(liveViewContent->GetButton().GetAllButtonNames()[0], "test");

    NotificationProgress progress;
    progress.SetMaxValue(1);
    liveViewContent->SetProgress(progress);
    EXPECT_EQ(liveViewContent->GetProgress().GetMaxValue(), 1);

    NotificationTime time;
    time.SetInitialTime(1);
    liveViewContent->SetTime(time);
    EXPECT_EQ(liveViewContent->GetTime().GetInitialTime(), 1);

    liveViewContent->addFlag(0);
    EXPECT_EQ(liveViewContent->isFlagExist(1), false);
    EXPECT_EQ(liveViewContent->isFlagExist(0), true);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewContentTest, Dump_00001, Function | SmallTest | Level1)
{
    NotificationCapsule capsule;
    capsule.SetTitle("testTitle");
    auto liveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    liveViewContent->SetCapsule(capsule);

    NotificationLocalLiveViewButton button;
    button.addSingleButtonName("test");
    liveViewContent->SetButton(button);

    NotificationProgress progress;
    progress.SetMaxValue(1);
    liveViewContent->SetProgress(progress);

    NotificationTime time;
    time.SetInitialTime(1);
    liveViewContent->SetTime(time);
    liveViewContent->addFlag(0);

    std::string dumpStr = "NotificationLocalLiveViewContent{ title = , text = , additionalText = , "
        "lockScreenPicture = null, type = 0, "
        "capsule = Capsule{ title = testTitle, backgroundColor = , content = , icon = null, time = 0 }, button = , "
        "progress = Progress{ maxValue = 1, currentValue = 0, isPercentage = 1 }, "
        "time = Time{ initialTime = 1, isCountDown = 0, isPaused = 0, isInTitle = 0 }, liveviewType = 0 }";
    EXPECT_EQ(liveViewContent->Dump(), dumpStr);
}

/**
 * @tc.name: SetCardButton_00001
 * @tc.desc: Test SetCardButton.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewContentTest, SetCardButton_00001, Function | SmallTest | Level1)
{
    auto liveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto buttons = liveViewContent->GetCardButton();
    EXPECT_EQ(buttons.size(), 0);

    NotificationIconButton button;
    buttons.push_back(button);

    liveViewContent->SetCardButton(buttons);
    buttons = liveViewContent->GetCardButton();
    EXPECT_EQ(buttons.size(), 1);
}

/**
 * @tc.name: SetLiveViewType_00001
 * @tc.desc: Test SetLiveViewType.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewContentTest, SetLiveViewType_00001, Function | SmallTest | Level1)
{
    auto liveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    liveViewContent->SetLiveViewType(NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_ACTIVITY);
    
    auto type = liveViewContent->GetLiveViewType();
    EXPECT_EQ(type, NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_ACTIVITY);
}

/**
 * @tc.name: FromJson_00004
 * @tc.desc: Test FromJson_00004.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewContentTest, FromJson_00004, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLocalLiveViewContent>();

    NotificationCapsule capsule;
    capsule.SetTitle("testTitle");
    rrc->SetCapsule(capsule);

    nlohmann::json json;
    rrc->ToJson(json);

    sptr<NotificationLocalLiveViewContent> temp = rrc->FromJson(json);
    EXPECT_NE(temp, nullptr);
    EXPECT_EQ(temp->GetCapsule().GetTitle(), "testTitle");
}

/**
 * @tc.name: FromJson_00005
 * @tc.desc: Test FromJson_00005.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewContentTest, FromJson_00005, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLocalLiveViewContent>();

    NotificationLocalLiveViewButton button;
    button.addSingleButtonName("test");
    rrc->SetButton(button);

    nlohmann::json json;
    rrc->ToJson(json);

    sptr<NotificationLocalLiveViewContent> temp = rrc->FromJson(json);
    EXPECT_NE(temp, nullptr);
    EXPECT_EQ(temp->GetButton().GetAllButtonNames().size(), 1);
}

/**
 * @tc.name: FromJson_00007
 * @tc.desc: Test FromJson_00007.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewContentTest, FromJson_00007, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLocalLiveViewContent>();

    NotificationProgress progress;
    progress.SetMaxValue(1);
    rrc->SetProgress(progress);
    EXPECT_EQ(rrc->GetProgress().GetMaxValue(), 1);

    nlohmann::json json;
    rrc->ToJson(json);

    sptr<NotificationLocalLiveViewContent> temp = rrc->FromJson(json);
    EXPECT_NE(temp, nullptr);
    EXPECT_EQ(temp->GetProgress().GetMaxValue(), 1);
}

/**
 * @tc.name: FromJson_00008
 * @tc.desc: Test FromJson_00008.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewContentTest, FromJson_00008, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLocalLiveViewContent>();

    NotificationTime time;
    time.SetInitialTime(1);
    rrc->SetTime(time);
    EXPECT_EQ(rrc->GetTime().GetInitialTime(), 1);

    nlohmann::json json;
    rrc->ToJson(json);

    sptr<NotificationLocalLiveViewContent> temp = rrc->FromJson(json);
    EXPECT_NE(temp, nullptr);
    EXPECT_EQ(temp->GetTime().GetInitialTime(), 1);
}

/**
 * @tc.name: FromJson_00009
 * @tc.desc: Test FromJson_00009.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewContentTest, FromJson_00009, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLocalLiveViewContent>();
    rrc->addFlag(1);
    EXPECT_TRUE(rrc->isFlagExist(1));

    nlohmann::json json;
    rrc->ToJson(json);

    sptr<NotificationLocalLiveViewContent> temp = rrc->FromJson(json);
    EXPECT_NE(temp, nullptr);
    EXPECT_TRUE(temp->isFlagExist(1));
}

/**
 * @tc.name: FromJson_00010
 * @tc.desc: Test FromJson_00010.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewContentTest, FromJson_00010, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLocalLiveViewContent>();
    rrc->SetLiveViewType(NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_ACTIVITY);
    
    auto type = rrc->GetLiveViewType();
    EXPECT_EQ(type, NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_ACTIVITY);

    nlohmann::json json;
    rrc->ToJson(json);

    sptr<NotificationLocalLiveViewContent> temp = rrc->FromJson(json);
    EXPECT_NE(temp, nullptr);
    EXPECT_EQ(temp->GetLiveViewType(),
        NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_ACTIVITY);
}

/**
 * @tc.name: ReadFromParcel_00001
 * @tc.desc: Test ReadFromParcel_00001.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewContentTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    auto liveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto buttons = liveViewContent->GetCardButton();
    EXPECT_EQ(buttons.size(), 0);

    NotificationIconButton button;
    buttons.push_back(button);

    liveViewContent->SetCardButton(buttons);

    Parcel parcel;
    liveViewContent->Marshalling(parcel);
    sptr<NotificationLocalLiveViewContent> temp = liveViewContent->Unmarshalling(parcel);
    
    EXPECT_NE(temp, nullptr);
    EXPECT_EQ(temp->GetCardButton().size(), 1);
}
}
}
