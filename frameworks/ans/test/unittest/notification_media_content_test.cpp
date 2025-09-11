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
#include "notification_media_content.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationMediaContentTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetAVToken_00001
 * @tc.desc: Test SetAVToken parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationMediaContentTest, SetAVToken_00001, Function | SmallTest | Level1)
{
    std::shared_ptr<AVToken> avToken = nullptr;
    auto rrc = std::make_shared<NotificationMediaContent>();
    rrc->SetAVToken(avToken);
    EXPECT_EQ(rrc->GetAVToken(), avToken);
}

/**
 * @tc.name: SetShownActions_00001
 * @tc.desc: Test SetShownActions parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationMediaContentTest, SetShownActions_00001, Function | SmallTest | Level1)
{
    std::vector<uint32_t> actions;
    auto rrc = std::make_shared<NotificationMediaContent>();
    rrc->SetShownActions(actions);
    EXPECT_EQ(rrc->GetShownActions(), actions);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationMediaContentTest, Dump_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationMediaContent>();
    std::string ret = "NotificationMediaContent{ title = , text = , "
    "additionalText = , lockScreenPicture = null, structuredText = null, avToken = null, sequenceNumbers =  }";

    EXPECT_EQ(rrc->Dump(), ret);
}

/**
 * @tc.name: ToJson_00001
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationMediaContentTest, ToJson_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    auto rrc = std::make_shared<NotificationMediaContent>();
    rrc->FromJson(jsonObject);
    EXPECT_EQ(rrc->ToJson(jsonObject), true);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationMediaContentTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationMediaContent>();
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationMediaContentTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    std::shared_ptr<NotificationMediaContent> result =
    std::make_shared<NotificationMediaContent>();

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
HWTEST_F(NotificationMediaContentTest, Unmarshalling_00002, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto mediaContent = std::make_shared<NotificationMediaContent>();
    std::vector<uint32_t> actions = {1, 2};
    mediaContent->SetShownActions(actions);
    mediaContent->Marshalling(parcel);
    EXPECT_NE(mediaContent->Unmarshalling(parcel), nullptr);
}

/**
 * @tc.name: ReadFromParcel_00001
 * @tc.desc: Test ReadFromParcel parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationMediaContentTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationMediaContent>();
    EXPECT_EQ(rrc->ReadFromParcel(parcel), false);
}

/**
 * @tc.name: ToJson_00002
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationMediaContentTest, ToJson_00002, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{
        {"teset", "test"}};
    auto rrc = std::make_shared<NotificationMediaContent>();
    auto res = rrc->FromJson(jsonObject);
    EXPECT_NE(res, nullptr);
}

/**
 * @tc.name: FromJson_00001
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationMediaContentTest, FromJson_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{
        {"sequenceNumbers", {1, 2}}};
    auto mediaContent = std::make_shared<NotificationMediaContent>();
    auto res = mediaContent->FromJson(jsonObject);
    EXPECT_NE(res, nullptr);
    EXPECT_EQ(res->GetShownActions().size(), 2);
}
}
}
