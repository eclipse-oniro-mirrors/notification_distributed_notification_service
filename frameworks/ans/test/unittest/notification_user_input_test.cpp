/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "notification_user_input.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationUserInputTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: NotificationUserInput_00001
 * @tc.desc: Test NotificationUserInput parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, Dump_00001, Function | SmallTest | Level1)
{
    std::string inputKey = "InputKey";
    std::string tag = "Tag";
    std::vector<std::string> options;
    bool permitFreeFormInput = true;
    std::set<std::string> permitMimeTypes;
    std::shared_ptr<AAFwk::WantParams> additional = nullptr;
    Notification::NotificationConstant::InputEditType editType =
            Notification::NotificationConstant::InputEditType(1);
    auto rrc = std::make_shared<NotificationUserInput>(inputKey, tag, options, permitFreeFormInput, permitMimeTypes,
    additional, editType);
    std::string ret = rrc->GetInputKey();
    EXPECT_EQ(ret, inputKey);
}

/**
 * @tc.name: ToJson_00001
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, ToJson_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    auto rrc = std::make_shared<NotificationUserInput>();
    rrc->FromJson(jsonObject);
    EXPECT_EQ(rrc->ToJson(jsonObject), true);
}

/**
 * @tc.name: ToJson_00002
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, ToJson_00002, Function | SmallTest | Level1)
{
    std::string inputKey = "InputKey";
    std::string tag = "Tag";
    std::vector<std::string> options;
    bool permitFreeFormInput = true;
    std::set<std::string> permitMimeTypes;
    std::shared_ptr<AAFwk::WantParams> additional = std::make_shared<AAFwk::WantParams>();;
    Notification::NotificationConstant::InputEditType editType =
        Notification::NotificationConstant::InputEditType(1);
    auto rrc = std::make_shared<NotificationUserInput>(inputKey, tag, options, permitFreeFormInput, permitMimeTypes,
    additional, editType);
    std::shared_ptr<AAFwk::WantParams> ret = rrc->GetAdditionalData();

    nlohmann::json jsonObject;
    rrc->FromJson(jsonObject);
    EXPECT_EQ(rrc->ToJson(jsonObject), true);
}

/**
 * @tc.name: FromJson_00001
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, FromJson_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    auto rrc = std::make_shared<NotificationUserInput>();
    std::shared_ptr<NotificationUserInput> userInput = nullptr;
    rrc->FromJson(jsonObject);
    EXPECT_EQ(rrc->FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: FromJson_00002
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, FromJson_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationUserInput>();
    nlohmann::json jsonObject = nlohmann::json{"processName", "soundEnabled", "name", "arrivedTime1"};
    rrc->FromJson(jsonObject);
    EXPECT_EQ(jsonObject.is_object(), false);
    EXPECT_EQ(rrc->FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: FromJson_00003
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, FromJson_00003, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationUserInput>();
    nlohmann::json jsonObject = nlohmann::json{
        {"processName", "process6"}, {"APL", 1},
        {"version", 2}, {"tokenId", 685266937},
        {"tokenAttr", 0},
        {"dcaps", {"AT_CAP", "ST_CAP"}}};
    rrc->FromJson(jsonObject);
    EXPECT_EQ(jsonObject.is_object(), true);
}

/**
 * @tc.name: FromJson_00004
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, FromJson_00004, Function | SmallTest | Level1)
{
    auto userInput = std::make_shared<NotificationUserInput>();
    nlohmann::json jsonObject = nlohmann::json{
        {"inputKey", "testKey"}, {"tag", "testTag"},
        {"options", {"testOption"}}, {"permitFreeFormInput", 1},
        {"permitMimeTypes", {"testType"}}, {"additionalData", "testData"},
        {"editType", 1}};
    EXPECT_EQ(jsonObject.is_object(), true);
    auto res = userInput->FromJson(jsonObject);
    EXPECT_EQ(res->GetPermitMimeTypes().size(), 1);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationUserInput>();
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    std::shared_ptr<NotificationUserInput> result =
    std::make_shared<NotificationUserInput>();

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
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, Unmarshalling_002, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto userInput = std::make_shared<NotificationUserInput>("testKey");
    std::vector<std::string> options = {"test1", "test2"};
    userInput->SetOptions(options);
    userInput->SetPermitMimeTypes("test", true);
    EXPECT_EQ(userInput->Marshalling(parcel), true);
    EXPECT_NE(userInput->Unmarshalling(parcel), nullptr);
}

/**
 * @tc.name: ReadFromParcel_00001
 * @tc.desc: Test ReadFromParcel parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationUserInput>();
    EXPECT_EQ(rrc->ReadFromParcel(parcel), false);
}

/**
 * @tc.name: Create_00001
 * @tc.desc: Test Create parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, Create_00001, Function | SmallTest | Level1)
{
    std::string inputKey = "";
    auto rrc = std::make_shared<NotificationUserInput>();
    std::shared_ptr<NotificationUserInput> result = rrc->Create(inputKey);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: Create_00002
 * @tc.desc: Test NotificationUserInput parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, Create_00002, Function | SmallTest | Level1)
{
    std::string inputKey = "";
    std::string tag = "Tag";
    std::vector<std::string> options;
    bool permitFreeFormInput = true;
    std::set<std::string> permitMimeTypes;
    std::shared_ptr<AAFwk::WantParams> additional = nullptr;
    Notification::NotificationConstant::InputEditType editType =
        Notification::NotificationConstant::InputEditType(1);
    auto rrc = std::make_shared<NotificationUserInput>();
    std::shared_ptr<NotificationUserInput> result = rrc->Create(inputKey, tag, options,
        permitFreeFormInput, permitMimeTypes, additional, editType);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: Create_00003
 * @tc.desc: Test NotificationUserInput parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, Create_00003, Function | SmallTest | Level1)
{
    std::string inputKey = "this is inputKey";
    std::string tag = "Tag";
    std::vector<std::string> options;
    bool permitFreeFormInput = false;
    std::set<std::string> permitMimeTypes;
    std::shared_ptr<AAFwk::WantParams> additional = nullptr;
    Notification::NotificationConstant::InputEditType editType =
        Notification::NotificationConstant::InputEditType::EDIT_ENABLED;
    auto rrc = std::make_shared<NotificationUserInput>();
    std::shared_ptr<NotificationUserInput> result = rrc->Create(inputKey, tag, options,
        permitFreeFormInput, permitMimeTypes, additional, editType);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: Create_00004
 * @tc.desc: Test NotificationUserInput parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, Create_00004, Function | SmallTest | Level1)
{
    std::string inputKey = "this is inputKey";
    std::string tag = "Tag";
    std::vector<std::string> options;
    bool permitFreeFormInput = true;
    std::set<std::string> permitMimeTypes;
    std::shared_ptr<AAFwk::WantParams> additional = nullptr;
    Notification::NotificationConstant::InputEditType editType =
        Notification::NotificationConstant::InputEditType::EDIT_ENABLED;
    std::shared_ptr<NotificationUserInput> notificationUserInput = std::make_shared<NotificationUserInput>();
    ASSERT_NE(nullptr, notificationUserInput);
    notificationUserInput->Create(inputKey, tag, options, permitFreeFormInput, permitMimeTypes,
        additional, editType);
}

/**
 * @tc.name: Create_00005
 * @tc.desc: Test NotificationUserInput parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, Create_00005, Function | SmallTest | Level1)
{
    std::string inputKey = "this is inputKey";
    std::string tag = "Tag";
    std::vector<std::string> options;
    std::string option = "this is option";
    options.emplace_back(option);
    bool permitFreeFormInput = false;
    std::set<std::string> permitMimeTypes;
    std::string permitMimeType = "this is permitMimeType";
    permitMimeTypes.insert(permitMimeType);
    std::shared_ptr<AAFwk::WantParams> additional = nullptr;
    Notification::NotificationConstant::InputEditType editType =
        Notification::NotificationConstant::InputEditType::EDIT_DISABLED;
    std::shared_ptr<NotificationUserInput> notificationUserInput = std::make_shared<NotificationUserInput>();
    ASSERT_NE(nullptr, notificationUserInput);
    notificationUserInput->Create(inputKey, tag, options, permitFreeFormInput, permitMimeTypes,
        additional, editType);
}

/**
 * @tc.name: Create_00006
 * @tc.desc: Test NotificationUserInput parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, Create_00006, Function | SmallTest | Level1)
{
    std::string inputKey = "inputKey";
    std::string tag = "Tag";
    std::vector<std::string> vecs;
    std::string option = "option";
    vecs.emplace_back(option);
    bool permitFreeFormInput = false;
    std::set<std::string> permitMimeTypes;
    std::string permitMimeType = "permitMimeType";
    permitMimeTypes.insert(permitMimeType);
    std::shared_ptr<AAFwk::WantParams> additional = std::make_shared<AAFwk::WantParams>();
    Notification::NotificationConstant::InputEditType editType =
        Notification::NotificationConstant::InputEditType::EDIT_DISABLED;
    std::shared_ptr<NotificationUserInput> notificationUserInput = std::make_shared<NotificationUserInput>();
    ASSERT_NE(nullptr, notificationUserInput);
    notificationUserInput->Create(inputKey, tag, vecs, permitFreeFormInput, permitMimeTypes,
        additional, editType);
}

/**
 * @tc.name: SetPermitMimeTypes_00001
 * @tc.desc: Test SetPermitMimeTypes parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, SetPermitMimeTypes_00001, Function | SmallTest | Level1)
{
    std::string mimeType = "";
    bool doPermit = true;
    auto rrc = std::make_shared<NotificationUserInput>();
    rrc->SetPermitMimeTypes(mimeType, doPermit);
    auto result = rrc->GetPermitMimeTypes();
    EXPECT_EQ(result.size(), 0);
}

/**
 * @tc.name: AddAdditionalData_00001
 * @tc.desc: Test AddAdditionalData parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, AddAdditionalData_00001, Function | SmallTest | Level1)
{
    std::string inputKey = "InputKey";
    std::string tag = "Tag";
    std::vector<std::string> vecs;
    bool permitFreeFormInput = true;
    std::set<std::string> permitMimeTypes;
    std::shared_ptr<AAFwk::WantParams> additional = nullptr;
    Notification::NotificationConstant::InputEditType inputEditType =
        Notification::NotificationConstant::InputEditType(1);
    auto rrc = std::make_shared<NotificationUserInput>(inputKey, tag, vecs, permitFreeFormInput, permitMimeTypes,
    additional, inputEditType);
    std::shared_ptr<AAFwk::WantParams> ret = rrc->GetAdditionalData();
    EXPECT_EQ(ret, nullptr);
    AAFwk::WantParams aitional;
    rrc->AddAdditionalData(aitional);
}

/**
 * @tc.name: Dump_00002
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationUserInputTest, Dump_00002, Function | SmallTest | Level1)
{
    std::string inputKey = "InputKey";
    std::string tag = "Tag";
    std::vector<std::string> options;
    std::string option1 = "this is option1";
    std::string option2 = "this is option2";
    options.emplace_back(option1);
    options.emplace_back(option2);
    bool permitFreeFormInput = true;
    std::set<std::string> permitMimeTypes;
    std::string permitMimeType1 = "this is permitMimeType1";
    std::string permitMimeType2 = "this is permitMimeType2";
    permitMimeTypes.insert(permitMimeType1);
    permitMimeTypes.insert(permitMimeType2);
    std::shared_ptr<AAFwk::WantParams> additional = nullptr;
    Notification::NotificationConstant::InputEditType editType =
        Notification::NotificationConstant::InputEditType(1);
    auto rrc = std::make_shared<NotificationUserInput>(inputKey, tag, options, permitFreeFormInput, permitMimeTypes,
    additional, editType);
    std::string ret = rrc->Dump();
    std::string dump = "NotificationUserInput{ inputKey = InputKey, tag = Tag, "
    "options = [this is option1, this is option2], permitFreeFormInput = true, "
    "permitMimeTypes = [this is permitMimeType1, this is permitMimeType2], editType = 1 }";
    EXPECT_EQ(ret, dump);
}
}
}
