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
#include "message_user.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class MessageUserTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: FromJson_00001
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(MessageUserTest, FromJson_00001, Function | SmallTest | Level1)
{
    sptr<MessageUser> messageUser = nullptr;
    nlohmann::json jsonObject;
    EXPECT_EQ(messageUser ->FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: FromJson_00002
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(MessageUserTest, FromJson_00002, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    nlohmann::json jsonObject = nlohmann::json{"processName", "process6", "name", "arrivedTime1"};
    messageUser.FromJson(jsonObject);
    EXPECT_EQ(jsonObject.is_object(), false);
    EXPECT_EQ(messageUser.FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: FromJson_00003
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(MessageUserTest, FromJson_00003, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    nlohmann::json jsonObject = nlohmann::json{
        {"processName", "process6"}, {"APL", 1},
        {"version", 2}, {"tokenId", 685266937},
        {"tokenAttr", 0},
        {"dcaps", {"AT_CAP", "ST_CAP"}}};
    auto result = messageUser.FromJson(jsonObject);
    EXPECT_EQ(jsonObject.is_object(), true);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(MessageUserTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    std::shared_ptr<MessageUser> result = std::make_shared<MessageUser>();

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
 * @tc.require: issue
 */
HWTEST_F(MessageUserTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    Parcel parcel;

    EXPECT_EQ(messageUser.ReadFromParcel(parcel), false);
}

/**
 * @tc.name: ReadFromParcel_00002
 * @tc.desc: Test ReadFromParcel parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(MessageUserTest, ReadFromParcel_00002, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    Parcel parcel;
    int32_t empty = 10;

    parcel.WriteInt32(empty);
    EXPECT_EQ(messageUser.ReadFromParcel(parcel), false);
}

/**
 * @tc.name: FromJson_00004
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(MessageUserTest, FromJson_00004, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    nlohmann::json jsonObject = nlohmann::json{
        {"key", "key"},
        {"name", "test"},
        {"uri", "/data/log/"},
        {"isMachine", true},
        {"isUserImportant", true}};
    auto res = messageUser.FromJson(jsonObject);
    EXPECT_NE(res, nullptr);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(MessageUserTest, Marshalling_00001, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    Parcel parcel;
    auto res = messageUser.Marshalling(parcel);
    EXPECT_NE(res, false);
}

/**
 * @tc.name: ReadFromParcel_00003
 * @tc.desc: Test ReadFromParcel when only key is written (name read fails).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(MessageUserTest, ReadFromParcel_00003, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    Parcel parcel;

    parcel.WriteString("key");
    EXPECT_EQ(messageUser.ReadFromParcel(parcel), false);
}

/**
 * @tc.name: ReadFromParcel_00004
 * @tc.desc: Test ReadFromParcel when key and name are written (isMachine read fails).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(MessageUserTest, ReadFromParcel_00004, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    Parcel parcel;

    parcel.WriteString("key");
    parcel.WriteString("name");
    EXPECT_EQ(messageUser.ReadFromParcel(parcel), false);
}

/**
 * @tc.name: ReadFromParcel_00005
 * @tc.desc: Test ReadFromParcel when key, name and isMachine are written (isUserImportant read fails).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(MessageUserTest, ReadFromParcel_00005, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    Parcel parcel;

    parcel.WriteString("key");
    parcel.WriteString("name");
    parcel.WriteBool(true);
    EXPECT_EQ(messageUser.ReadFromParcel(parcel), false);
}

/**
 * @tc.name: ReadOptionalFromParcel_00001
 * @tc.desc: Test ReadOptionalFromParcel when ReadInt32 fails.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(MessageUserTest, ReadOptionalFromParcel_00001, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    Parcel parcel;

    EXPECT_EQ(messageUser.ReadOptionalFromParcel(parcel), false);
}

/**
 * @tc.name: ReadOptionalFromParcel_00002
 * @tc.desc: Test ReadOptionalFromParcel when uri string read fails.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(MessageUserTest, ReadOptionalFromParcel_00002, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    Parcel parcel;

    parcel.WriteInt32(MessageUser::VALUE_OBJECT);
    EXPECT_EQ(messageUser.ReadOptionalFromParcel(parcel), false);
}

/**
 * @tc.name: ReadOptionalFromParcel_00003
 * @tc.desc: Test ReadOptionalFromParcel when pixelMap valid bool read fails.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(MessageUserTest, ReadOptionalFromParcel_00003, Function | SmallTest | Level1)
{
    MessageUser messageUser;
    Parcel parcel;

    parcel.WriteInt32(MessageUser::VALUE_NULL);
    EXPECT_EQ(messageUser.ReadOptionalFromParcel(parcel), false);
}
}
}