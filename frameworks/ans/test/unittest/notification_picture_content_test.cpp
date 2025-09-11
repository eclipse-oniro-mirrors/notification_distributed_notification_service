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

#define private public
#define protected public
#include "notification_picture_content.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationPictureContentTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetExpandedTitle_00001
 * @tc.desc: Test SetExpandedTitle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationPictureContentTest, SetExpandedTitle_00001, Function | SmallTest | Level1)
{
    std::string exTitle = "ExTitle";
    auto rrc = std::make_shared<NotificationPictureContent>();
    rrc->SetExpandedTitle(exTitle);
    EXPECT_EQ(rrc->GetExpandedTitle(), exTitle);
}

/**
 * @tc.name: SetBriefText_00001
 * @tc.desc: Test SetBriefText parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationPictureContentTest, SetBriefText_00001, Function | SmallTest | Level1)
{
    std::string briefText = "BriefText";
    auto rrc = std::make_shared<NotificationPictureContent>();
    rrc->SetBriefText(briefText);
    EXPECT_EQ(rrc->GetBriefText(), briefText);
}

/**
 * @tc.name: SetBigPicture_00001
 * @tc.desc: Test SetBigPicture parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationPictureContentTest, SetBigPicture_00001, Function | SmallTest | Level1)
{
    std::shared_ptr<Media::PixelMap> bigPicture = std::make_shared<Media::PixelMap>();
    auto rrc = std::make_shared<NotificationPictureContent>();
    rrc->SetBigPicture(bigPicture);
    EXPECT_EQ(rrc->GetBigPicture(), bigPicture);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationPictureContentTest, Dump_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationPictureContent>();
    std::string ret = "NotificationPictureContent{ title = , text = , "
    "additionalText = , lockScreenPicture = null, structuredText = null, "
    "briefText = , expandedTitle = , bigPicture = null }";

    EXPECT_EQ(rrc->Dump(), ret);
}

/**
 * @tc.name: ToJson_00001
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBHI
 */
HWTEST_F(NotificationPictureContentTest, ToJson_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    auto rrc = std::make_shared<NotificationPictureContent>();
    rrc->FromJson(jsonObject);
    EXPECT_EQ(rrc->ToJson(jsonObject), true);
}

/**
 * @tc.name: FromJson_00001
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBHI
 */
HWTEST_F(NotificationPictureContentTest, FromJson_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationPictureContent>();

    nlohmann::json jsonObject = nlohmann::json{"processName", "process6", "expandedTitle", "arrivedTime1"};
    rrc->FromJson(jsonObject);
    EXPECT_EQ(jsonObject.is_object(), false);
    EXPECT_EQ(rrc->FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: FromJson_00002
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBHI
 */
HWTEST_F(NotificationPictureContentTest, FromJson_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationPictureContent>();

    nlohmann::json jsonObject = nlohmann::json{
        {"processName", "process6"}, {"APL", 1},
        {"version", 2}, {"tokenId", 685266937},
        {"tokenAttr", 0},
        {"dcaps", {"AT_CAP", "ST_CAP"}}};
    rrc->FromJson(jsonObject);
    EXPECT_EQ(jsonObject.is_object(), true);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBHI
 */
HWTEST_F(NotificationPictureContentTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationPictureContent>();
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationPictureContentTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    std::shared_ptr<NotificationPictureContent> result =
    std::make_shared<NotificationPictureContent>();

    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, false);
}

/**
 * @tc.name: ReadFromParcel_00001
 * @tc.desc: Test ReadFromParcel parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBHI
 */
HWTEST_F(NotificationPictureContentTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationPictureContent>();
    EXPECT_EQ(rrc->ReadFromParcel(parcel), false);
}

/**
 * @tc.name: FromJson_00003
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBHI
 */
HWTEST_F(NotificationPictureContentTest, FromJson_00003, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationPictureContent>();

    nlohmann::json jsonObject = nlohmann::json{
        {"expandedTitle", "title"},
        {"briefText", "test"},
        {"bigPicture", "/data/image/1.jpeg"}};
    auto res = rrc->FromJson(jsonObject);
    EXPECT_NE(res, nullptr);
}

/**
 * @tc.name: Marshalling_00002
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBHI
 */
HWTEST_F(NotificationPictureContentTest, Marshalling_00002, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationPictureContent>();
    auto data = std::make_shared<Media::PixelMap>();
    rrc->SetBigPicture(data);
    rrc->SetExpandedTitle("title");
    rrc->SetBriefText("test");
    EXPECT_EQ(rrc->Marshalling(parcel), false);
    EXPECT_EQ(rrc->ReadFromParcel(parcel), false);
}
}
}