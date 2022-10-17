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
#include "notification_conversational_message.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationConversationalMessageTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: GetText_00001
 * @tc.desc: Test GetText parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationConversationalMessageTest, GetText_00001, Function | SmallTest | Level1)
{
    std::string text = "Text";
    int64_t timestamp = 10;
    MessageUser sender;
    auto rrc = std::make_shared<NotificationConversationalMessage>(text, timestamp, sender);
    rrc->GetSender();
    EXPECT_EQ(rrc->GetText(), text);
    EXPECT_EQ(rrc->GetArrivedTime(), timestamp);
}

/**
 * @tc.name: SetData_00001
 * @tc.desc: Test SetData parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationConversationalMessageTest, SetData_00001, Function | SmallTest | Level1)
{
    std::string text = "Text";
    int64_t timestamp = 10;
    MessageUser sender;
    std::string mimeType = "MimeType";
    std::string uri;
    std::shared_ptr<Uri> uriPtr = std::make_shared<Uri>(uri);
    auto rrc = std::make_shared<NotificationConversationalMessage>(text, timestamp, sender);
    rrc->SetData(mimeType, uriPtr);
    EXPECT_EQ(rrc->GetMimeType(), mimeType);
    EXPECT_EQ(rrc->GetUri(), uriPtr);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationConversationalMessageTest, Dump_00001, Function | SmallTest | Level1)
{
    std::string text = "Text";
    int64_t timestamp = 10;
    MessageUser sender;
    auto rrc = std::make_shared<NotificationConversationalMessage>(text, timestamp, sender);
    std::string ret =
    "NotificationConversationalMessage{ text = Text, arrivedTime = 10, mimeType = , uri = null, "
    "sender = MessageUser{ key = , name = , pixelMap = null, uri = , isMachine = false, isUserImportant = false } }";

    EXPECT_EQ(rrc->Dump(), ret);
}

/**
 * @tc.name: ToJson_00001
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationConversationalMessageTest, ToJson_00001, Function | SmallTest | Level1)
{
    std::string text = "Text";
    int64_t timestamp = 10;
    MessageUser sender;
    nlohmann::json jsonObject;
    auto rrc = std::make_shared<NotificationConversationalMessage>(text, timestamp, sender);
    rrc->FromJson(jsonObject);
    EXPECT_EQ(rrc->ToJson(jsonObject), true);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationConversationalMessageTest, Marshalling_00001, Function | SmallTest | Level1)
{
    std::string text = "Text";
    int64_t timestamp = 10;
    MessageUser sender;
    Parcel parcel;
    auto rrc = std::make_shared<NotificationConversationalMessage>(text, timestamp, sender);
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationConversationalMessageTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    std::string text = "Text";
    int64_t timestamp = 10;
    MessageUser sender;
    bool unmarshalling = true;
    Parcel parcel;
    std::shared_ptr<NotificationConversationalMessage> result =
    std::make_shared<NotificationConversationalMessage>(text, timestamp, sender);

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
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationConversationalMessageTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    std::string text = "Text";
    int64_t timestamp = 10;
    MessageUser sender;
    Parcel parcel;
    auto rrc = std::make_shared<NotificationConversationalMessage>(text, timestamp, sender);
    EXPECT_EQ(rrc->ReadFromParcel(parcel), false);
}
}
}