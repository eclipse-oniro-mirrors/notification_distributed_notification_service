/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "notification_check_request.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationCheckRequestTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetContentType_00001
 * @tc.desc: Test SetContentType.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCheckRequestTest, SetContentType_00001, Function | SmallTest | Level1)
{
    NotificationCheckRequest checkRequest;
    checkRequest.SetContentType(NotificationContent::Type::BASIC_TEXT);
    EXPECT_EQ(NotificationContent::Type::BASIC_TEXT, checkRequest.GetContentType());
}

/**
 * @tc.name: SetSlotType_00001
 * @tc.desc: Test SetSlotType.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCheckRequestTest, SetSlotType_00001, Function | SmallTest | Level1)
{
    NotificationCheckRequest checkRequest;
    checkRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    EXPECT_EQ(NotificationConstant::SlotType::LIVE_VIEW, checkRequest.GetSlotType());
}

/**
 * @tc.name: SetExtraKeys_00001
 * @tc.desc: Test SetExtraKeys.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCheckRequestTest, SetExtraKeys_00001, Function | SmallTest | Level1)
{
    NotificationCheckRequest checkRequest;
    std::vector<std::string> vector;
    vector.emplace_back("test1");
    checkRequest.SetExtraKeys(vector);
    auto getVector = checkRequest.GetExtraKeys();
    EXPECT_EQ(1, getVector.size());
}

/**
 * @tc.name: SetUid_00001
 * @tc.desc: Test SetUid.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCheckRequestTest, SetUid_00001, Function | SmallTest | Level1)
{
    NotificationCheckRequest checkRequest;
    checkRequest.SetUid(1);
    EXPECT_EQ(1, checkRequest.GetUid());
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCheckRequestTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    NotificationCheckRequest checkRequest;
    std::vector<std::string> vector;
    vector.emplace_back("test1");
    checkRequest.SetExtraKeys(vector);
    EXPECT_EQ(true, checkRequest.Marshalling(parcel));
    EXPECT_NE(checkRequest.Unmarshalling(parcel), nullptr);
}
}
}
