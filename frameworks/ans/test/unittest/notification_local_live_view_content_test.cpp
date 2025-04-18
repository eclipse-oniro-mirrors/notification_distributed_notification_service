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
}
}
