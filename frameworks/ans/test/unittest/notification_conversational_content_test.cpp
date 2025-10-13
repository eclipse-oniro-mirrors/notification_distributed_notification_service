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
#include "notification_conversational_content.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationConversationalContentTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: ToJson_00001
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConversationalContentTest, ToJson_00001, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    nlohmann::json jsonObject;
    auto rrc = std::make_shared<NotificationConversationalContent>(messageUser);
    rrc->FromJson(jsonObject);
    EXPECT_EQ(rrc->ToJson(jsonObject), true);
}

/**
 * @tc.name: FromJson_00001
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConversationalContentTest, FromJson_00001, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    auto rrc = std::make_shared<NotificationConversationalContent>(messageUser);

    nlohmann::json jsonObject = nlohmann::json{"processName", "process6", "messageUser", "arrivedTime1"};
    rrc->FromJson(jsonObject);
    EXPECT_EQ(jsonObject.is_object(), false);
    EXPECT_EQ(rrc->FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: FromJson_00002
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConversationalContentTest, FromJson_00002, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    auto rrc = std::make_shared<NotificationConversationalContent>(messageUser);

    nlohmann::json jsonObject = nlohmann::json{
        {"processName", "process6"}, {"APL", 1},
        {"version", 2}, {"tokenId", 685266937},
        {"tokenAttr", 0},
        {"dcaps", {"AT_CAP", "ST_CAP"}}};
    messageUser.FromJson(jsonObject);
    EXPECT_EQ(jsonObject.is_object(), true);
}

/**
 * @tc.name: FromJson_00003
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConversationalContentTest, FromJson_00003, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    auto content = std::make_shared<NotificationConversationalContent>(messageUser);
    nlohmann::json jsonObject = nlohmann::json{
        {"messageUser", {{"key", "testKey"}, {"name", "test"}}},
        {"message", {{"arrivedTime", 1}}}};
    auto newContent = content->FromJson(jsonObject);

    EXPECT_NE(newContent, nullptr);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConversationalContentTest, Marshalling_00001, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    Parcel parcel;
    auto rrc = std::make_shared<NotificationConversationalContent>(messageUser);
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConversationalContentTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    bool unmarshalling = true;
    Parcel parcel;
    std::shared_ptr<NotificationConversationalContent> result =
    std::make_shared<NotificationConversationalContent>(messageUser);

    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, false);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConversationalContentTest, Unmarshalling_002, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    Parcel parcel;
    auto content = std::make_shared<NotificationConversationalContent>(messageUser);
    content->SetConversationTitle("testTitle");
    content->AddConversationalMessage("text", 1, messageUser);
    content->Marshalling(parcel);

    EXPECT_NE(content->Unmarshalling(parcel), nullptr);
}

/**
 * @tc.name: ReadFromParcel_00001
 * @tc.desc: Test ReadFromParcel parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConversationalContentTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    Parcel parcel;
    auto rrc = std::make_shared<NotificationConversationalContent>(messageUser);
    EXPECT_EQ(rrc->ReadFromParcel(parcel), false);
}

/**
 * @tc.name: AddConversationalMessage_00001
 * @tc.desc: Test AddConversationalMessage parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConversationalContentTest, AddConversationalMessage_00001, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    auto rrc = std::make_shared<NotificationConversationalContent>(messageUser);

    MessageUser  sender;
    std::shared_ptr<NotificationConversationalMessage> messagePtr =
        std::make_shared<NotificationConversationalMessage>("messageptr", 0, sender);
    EXPECT_NE(messagePtr, nullptr);
    rrc->AddConversationalMessage(messagePtr);
    EXPECT_EQ(rrc->GetAllConversationalMessages().size(), 1);
}

/**
 * @tc.name: AddConversationalMessage_00002
 * @tc.desc: Test AddConversationalMessage parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConversationalContentTest, AddConversationalMessage_00002, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    auto rrc = std::make_shared<NotificationConversationalContent>(messageUser);

    MessageUser  sender;
    std::shared_ptr<NotificationConversationalMessage> messagePtr = nullptr;
    rrc->AddConversationalMessage(messagePtr);
    EXPECT_EQ(rrc->GetAllConversationalMessages().size(), 0);
    std::string result = rrc->Dump();
    std::string ret = "NotificationConversationalContent{ title = , text = , additionalText = , "
        "lockScreenPicture = null, structuredText = null, conversationTitle = , "
        "isGroup = false, messageUser = MessageUser{ key = , name = , "
        "pixelMap = null, uri = , isMachine = false, isUserImportant = false }, messages =  }";
    EXPECT_EQ(result, ret);
}

/**
 * @tc.name: ToJson_00002
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConversationalContentTest, ToJson_00002, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    nlohmann::json jsonObject = nlohmann::json{
        {"processName", "process6"}, {"APL", 1},
        {"version", 2}, {"tokenId", 685266937},
        {"tokenAttr", 0},
        {"dcaps", {"AT_CAP", "ST_CAP"}}};
    auto rrc = std::make_shared<NotificationConversationalContent>(messageUser);
    rrc->FromJson(jsonObject);
    EXPECT_EQ(rrc->ToJson(jsonObject), true);
}

/**
 * @tc.name: ToJson_00003
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConversationalContentTest, ToJson_00003, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    nlohmann::json jsonObject = nlohmann::json{
        {"processName", "process6"}, {"APL", 1},
        {"version", 2}, {"tokenId", 685266937},
        {"tokenAttr", 0},
        {"dcaps", {"AT_CAP", "ST_CAP"}}};
    auto rrc = std::make_shared<NotificationConversationalContent>(messageUser);
    MessageUser sender;
    std::shared_ptr<NotificationConversationalMessage> messagePtr =
        std::make_shared<NotificationConversationalMessage>("testMessage", 0, sender);
    EXPECT_NE(messagePtr, nullptr);
    rrc->AddConversationalMessage(messagePtr);
    rrc->FromJson(jsonObject);
    EXPECT_EQ(rrc->ToJson(jsonObject), true);
}

/**
 * @tc.name: FromJson_00004
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConversationalContentTest, FromJson_00004, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    nlohmann::json jsonObject = nlohmann::json{
        {"processName", "process6"}, {"APL", 1},
        {"version", 2}, {"tokenId", 685266937},
        {"tokenAttr", 0},
        {"dcaps", {"AT_CAP", "ST_CAP"}}};
    auto rrc = std::make_shared<NotificationConversationalContent>(messageUser);
    std::shared_ptr<NotificationConversationalMessage> messagePtr = nullptr;
    rrc->AddConversationalMessage(messagePtr);
    EXPECT_NE(rrc->FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConversationalContentTest, Dump_00001, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    auto rrc = std::make_shared<NotificationConversationalContent>(messageUser);
    MessageUser sender;
    int64_t timestamp = 0;
    auto messagePtr = std::make_shared<NotificationConversationalMessage>("test", timestamp, sender);
    rrc->AddConversationalMessage(messagePtr);
    messagePtr = nullptr;
    EXPECT_EQ(rrc->GetAllConversationalMessages().size(), 1);
    std::string result = rrc->Dump();
}

}
}
