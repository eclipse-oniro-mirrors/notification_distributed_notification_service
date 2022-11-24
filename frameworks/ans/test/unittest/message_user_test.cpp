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
}
}