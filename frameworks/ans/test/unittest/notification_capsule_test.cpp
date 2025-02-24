/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <string>
#include <unistd.h>
#include "notification_capsule.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationCapsuleTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetTitle_00001
 * @tc.desc: Test title_ parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCapsuleTest, SetTitle_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationCapsule>();
    std::string title = "testTitle";
    rrc->SetTitle(title);
    EXPECT_EQ(rrc->GetTitle(), title);
}

/**
 * @tc.name: SetBackgroundColor_00001
 * @tc.desc: Test buttonNames_ parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCapsuleTest, SetBackgroundColor_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationCapsule>();
    std::string backgroundColor = "testBackgroundColor";
    rrc->SetBackgroundColor(backgroundColor);
    EXPECT_EQ(rrc->GetBackgroundColor(), backgroundColor);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test buttonNames_ dump.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCapsuleTest, Dump_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationCapsule>();
    std::string title = "testTitle";
    rrc->SetTitle(title);
    std::string backgroundColor = "testBackgroundColor";
    rrc->SetBackgroundColor(backgroundColor);
    EXPECT_EQ(rrc->Dump(), "Capsule{ title = " + title + ", backgroundColor = " + backgroundColor +
        ", content = , icon = null, time = 0 }");
}

/**
 * @tc.name: FromJson_00001
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCapsuleTest, FromJson_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationCapsule>();
    nlohmann::json jsonObject = nlohmann::json{"title", "backgroundColor", "icon"};
    EXPECT_EQ(jsonObject.is_object(), false);
    EXPECT_EQ(rrc->FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: FromJson_00002
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCapsuleTest, FromJson_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationCapsule>();
    nlohmann::json jsonObject = nlohmann::json{{"title", "testTitle"}, {"backgroundColor", "testBkColor"},
        {"icon", ""}};
    EXPECT_EQ(jsonObject.is_object(), true);
    EXPECT_NE(rrc->FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationCapsuleTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationCapsule>();
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationCapsuleTest, Unmarshalling_00001, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    std::shared_ptr<NotificationCapsule> result =
        std::make_shared<NotificationCapsule>();

    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, true);
}

/**
 * @tc.name: SetIcon_00001
 * @tc.desc: Test SetIcon.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationCapsuleTest, SetIcon_00001, Function | SmallTest | Level1)
{
    auto pixmap = std::make_shared<Media::PixelMap>();
    auto capsule = std::make_shared<NotificationCapsule>();
    capsule->SetIcon(pixmap);
    EXPECT_NE(capsule->GetIcon(), nullptr);
}
}
}
