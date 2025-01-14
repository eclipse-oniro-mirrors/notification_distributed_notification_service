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

#define private public
#define protected public
#include "notification_live_view_content.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationLiveViewContentTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetLiveViewStatus_00001
 * @tc.desc: Test SetLiveViewStatus parameter.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLiveViewContentTest, SetLiveViewStatus_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLiveViewContent>();
    rrc->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    EXPECT_EQ(rrc->GetLiveViewStatus(), NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    rrc->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_BUTT);
    EXPECT_EQ(rrc->GetLiveViewStatus(), NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_BUTT);
}

/**
 * @tc.name: SetVersion_00001
 * @tc.desc: Test SetVersion parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLiveViewContentTest, SetVersion_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLiveViewContent>();
    rrc->SetVersion(NotificationLiveViewContent::MAX_VERSION);
    EXPECT_EQ(rrc->GetVersion(), NotificationLiveViewContent::MAX_VERSION);
}

/**
 * @tc.name: SetExtraInfo_00001
 * @tc.desc: Test SetExtraInfo parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLiveViewContentTest, SetExtraInfo_00001, Function | SmallTest | Level1)
{
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    auto rrc = std::make_shared<NotificationLiveViewContent>();
    rrc->SetExtraInfo(extraInfo);
    EXPECT_EQ(rrc->GetExtraInfo(), extraInfo);
}

/**
 * @tc.name: SetPicture_00001
 * @tc.desc: Test SetPicture parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLiveViewContentTest, SetPicture_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLiveViewContent>();
    PictureMap pictureMap{};
    rrc->SetPicture(pictureMap);
    EXPECT_EQ(rrc->GetPicture(), pictureMap);
}

/**
 * @tc.name: SetIsOnlyLocalUpdate_00001
 * @tc.desc: Test SetIsOnlyLocalUpdate parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLiveViewContentTest, SetIsOnlyLocalUpdate_00001, Function | SmallTest | Level1)
{
    bool isOnlyLocalUpdate = true;
    auto rrc = std::make_shared<NotificationLiveViewContent>();
    rrc->SetIsOnlyLocalUpdate(isOnlyLocalUpdate);
    EXPECT_EQ(rrc->GetIsOnlyLocalUpdate(), isOnlyLocalUpdate);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLiveViewContentTest, Dump_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLiveViewContent>();
    std::string ret = "NotificationLiveViewContent{ title = , text = , "
    "additionalText = , lockScreenPicture = null, status = 0, version = -1, extraInfo = null, "
    "isOnlyLocalUpdate_ = false, pictureMap = {}}";

    EXPECT_EQ(rrc->Dump(), ret);
}

/**
 * @tc.name: Dump_00002
 * @tc.desc: Test Dump parameters when pictureMap isn't empty.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLiveViewContentTest, Dump_00002, Function | SmallTest | Level1)
{
    PictureMap pictureMap;
    std::vector<std::shared_ptr<Media::PixelMap>> pixelVec;
    pixelVec.push_back(std::make_shared<Media::PixelMap>());
    auto picture = std::make_pair(std::string{"test"}, pixelVec);
    pictureMap.insert(picture);

    auto rrc = std::make_shared<NotificationLiveViewContent>();
    rrc->SetPicture(pictureMap);
    rrc->SetTitle("title");
    rrc->SetText("text");
    rrc->SetAdditionalText("addText");

    std::string ret = "NotificationLiveViewContent{ title = title, text = text, "
        "additionalText = addText, lockScreenPicture = null, status = 0, version = -1, extraInfo = null, "
        "isOnlyLocalUpdate_ = false, pictureMap = { { key = test, value = not empty } }}";

    EXPECT_EQ(rrc->Dump(), ret);
}

/**
 * @tc.name: JsonConvert_00001
 * @tc.desc: Test JsonConvert parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLiveViewContentTest, JsonConvert_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLiveViewContent>();

    PictureMap pictureMap;
    std::vector<std::shared_ptr<Media::PixelMap>> pixelVec;
    pixelVec.push_back(std::make_shared<Media::PixelMap>());
    auto picture = std::make_pair(std::string{"test"}, pixelVec);
    pictureMap.insert(picture);
    rrc->SetPicture(pictureMap);

    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    rrc->SetExtraInfo(extraInfo);

    rrc->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE);
    rrc->SetVersion(NotificationLiveViewContent::MAX_VERSION);
    rrc->SetTitle("title");
    rrc->SetText("text");
    rrc->SetAdditionalText("addText");

    nlohmann::json jsonObject;
    EXPECT_EQ(rrc->ToJson(jsonObject), true);
    const auto &jsonEnd = jsonObject.cend();
    EXPECT_NE(jsonObject.find("pictureMap"), jsonEnd);
    EXPECT_NE(jsonObject.find("extraInfo"), jsonEnd);

    auto ptr = NotificationLiveViewContent::FromJson(jsonObject);
    EXPECT_EQ(jsonObject.is_object(), true);
    EXPECT_NE(ptr, nullptr);
    EXPECT_EQ(ptr->GetTitle(), std::string("title"));
    EXPECT_EQ(ptr->GetText(), std::string("text"));
    EXPECT_EQ(ptr->GetAdditionalText(), std::string("addText"));
    EXPECT_EQ(ptr->GetLiveViewStatus(), NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE);
    EXPECT_EQ(ptr->GetVersion(), NotificationLiveViewContent::MAX_VERSION);
    EXPECT_NE(ptr->GetExtraInfo(), nullptr);
    EXPECT_EQ(ptr->GetPicture().size(), 1);
    delete ptr;
}

/**
 * @tc.name: FromJson_00001
 * @tc.desc: Test FromJson parameters when jsonObject is invalid.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLiveViewContentTest, FromJson_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLiveViewContent>();
    nlohmann::json jsonObject = nlohmann::json{"processName", "process6", "expandedTitle", "arrivedTime1"};
    auto ptr = rrc->FromJson(jsonObject);
    EXPECT_EQ(jsonObject.is_object(), false);
    EXPECT_EQ(ptr, nullptr);
}

/**
 * @tc.name: MarshallConvert_00001
 * @tc.desc: Test MarshallConvert parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLiveViewContentTest, MarshallConvert_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationLiveViewContent>();

    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    rrc->SetExtraInfo(extraInfo);

    rrc->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    uint32_t version = NotificationLiveViewContent::MAX_VERSION - 1;
    rrc->SetVersion(version);

    bool isOnlyLocalUpdate = true;
    rrc->SetIsOnlyLocalUpdate(isOnlyLocalUpdate);

    rrc->SetTitle("title");
    rrc->SetText("text");
    rrc->SetAdditionalText("addText");

    Parcel parcel;
    EXPECT_EQ(rrc->Marshalling(parcel), true);

    auto ptr = NotificationLiveViewContent::Unmarshalling(parcel);
    EXPECT_NE(ptr, nullptr);
    EXPECT_EQ(ptr->GetTitle(), std::string("title"));
    EXPECT_EQ(ptr->GetText(), std::string("text"));
    EXPECT_EQ(ptr->GetAdditionalText(), std::string("addText"));
    EXPECT_EQ(ptr->GetLiveViewStatus(), NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    EXPECT_EQ(ptr->GetVersion(), version);
    EXPECT_NE(ptr->GetExtraInfo(), nullptr);
    EXPECT_EQ(ptr->GetPicture().size(), 0);
    EXPECT_EQ(ptr->GetIsOnlyLocalUpdate(), true);
    delete ptr;
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLiveViewContentTest, Unmarshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto ptr = NotificationLiveViewContent::Unmarshalling(parcel);
    EXPECT_EQ(ptr, nullptr);
}

/**
 * @tc.name: MarshallingPictureMap_00001
 * @tc.desc: Test MarshallingPictureMap.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLiveViewContentTest, MarshallingPictureMap_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    bool isSuccess = liveViewContent->MarshallingPictureMap(parcel);
    EXPECT_EQ(isSuccess, true);
}

/**
 * @tc.name: MarshallingPictureMap_00002
 * @tc.desc: Test MarshallingPictureMap.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLiveViewContentTest, MarshallingPictureMap_00002, Function | SmallTest | Level1)
{
    PictureMap pictureMap;

    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetPicture(pictureMap);
    bool isEmptyMarshallingMap = liveViewContent->GetPictureMarshallingMap().empty();
    EXPECT_EQ(isEmptyMarshallingMap, true);

    Parcel parcel;
    bool isSuccess = liveViewContent->MarshallingPictureMap(parcel);
    EXPECT_EQ(isSuccess, true);
}

/**
 * @tc.name: MarshallingPictureMap_00003
 * @tc.desc: Test MarshallingPictureMap.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLiveViewContentTest, MarshallingPictureMap_00003, Function | SmallTest | Level1)
{
    PictureMap pictureMap;

    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetPicture(pictureMap);
    liveViewContent->FillPictureMarshallingMap();
    bool isEmptyMarshallingMap = liveViewContent->GetPictureMarshallingMap().empty();
    EXPECT_EQ(isEmptyMarshallingMap, true);

    Parcel parcel;
    bool isSuccess = liveViewContent->MarshallingPictureMap(parcel);
    EXPECT_EQ(isSuccess, true);
}
}
}
