/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "ans_common_utils.h"
#include "ans_const_define.h"
#include "notification_icon_button.h"
#include "parcel.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;

namespace {
const int32_t OVER_LIMIT_SIZE = MAX_PARCELABLE_VECTOR_NUM + 1;
}

class AnsCommonUtilsTest : public ::testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: WriteParcelableVector_00001
 * @tc.desc: Test WriteParcelableVector returns false when vector size exceeds limit.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsCommonUtilsTest, WriteParcelableVector_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    std::vector<std::shared_ptr<NotificationIconButton>> buttons(OVER_LIMIT_SIZE, nullptr);
    EXPECT_EQ(AnsCommonUtils::WriteParcelableVector(buttons, parcel), false);
}

/**
 * @tc.name: WriteParcelableVector_00002
 * @tc.desc: Test WriteParcelableVector with empty vector.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsCommonUtilsTest, WriteParcelableVector_00002, Function | SmallTest | Level1)
{
    Parcel parcel;
    std::vector<std::shared_ptr<NotificationIconButton>> buttons;
    EXPECT_EQ(AnsCommonUtils::WriteParcelableVector(buttons, parcel), true);
}

/**
 * @tc.name: WriteParcelableVector_00003
 * @tc.desc: Test WriteParcelableVector with valid vector.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsCommonUtilsTest, WriteParcelableVector_00003, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto button = std::make_shared<NotificationIconButton>();
    button->SetText("text");
    button->SetName("name");
    std::vector<std::shared_ptr<NotificationIconButton>> buttons = {button};
    EXPECT_EQ(AnsCommonUtils::WriteParcelableVector(buttons, parcel), true);
}

/**
 * @tc.name: ReadParcelableVector_00001
 * @tc.desc: Test ReadParcelableVector returns false when size is negative.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsCommonUtilsTest, ReadParcelableVector_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteInt32(-1);
    parcel.RewindRead(0);
    std::vector<std::shared_ptr<NotificationIconButton>> buttons;
    EXPECT_EQ(AnsCommonUtils::ReadParcelableVector(buttons, parcel), false);
}

/**
 * @tc.name: ReadParcelableVector_00002
 * @tc.desc: Test ReadParcelableVector returns false when size exceeds limit.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsCommonUtilsTest, ReadParcelableVector_00002, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteInt32(OVER_LIMIT_SIZE);
    parcel.RewindRead(0);
    std::vector<std::shared_ptr<NotificationIconButton>> buttons;
    EXPECT_EQ(AnsCommonUtils::ReadParcelableVector(buttons, parcel), false);
}

/**
 * @tc.name: ReadParcelableVector_00003
 * @tc.desc: Test ReadParcelableVector with zero size.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsCommonUtilsTest, ReadParcelableVector_00003, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteInt32(0);
    parcel.RewindRead(0);
    std::vector<std::shared_ptr<NotificationIconButton>> buttons;
    EXPECT_EQ(AnsCommonUtils::ReadParcelableVector(buttons, parcel), true);
    EXPECT_EQ(buttons.size(), 0);
}

/**
 * @tc.name: ReadParcelableVector_00004
 * @tc.desc: Test ReadParcelableVector after WriteParcelableVector round trip.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsCommonUtilsTest, ReadParcelableVector_00004, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto button = std::make_shared<NotificationIconButton>();
    button->SetText("text");
    button->SetName("name");
    std::vector<std::shared_ptr<NotificationIconButton>> buttons = {button};
    ASSERT_EQ(AnsCommonUtils::WriteParcelableVector(buttons, parcel), true);

    std::vector<std::shared_ptr<NotificationIconButton>> result;
    EXPECT_EQ(AnsCommonUtils::ReadParcelableVector(result, parcel), true);
    ASSERT_EQ(result.size(), 1);
    ASSERT_NE(result[0], nullptr);
    EXPECT_EQ(result[0]->GetText(), "text");
    EXPECT_EQ(result[0]->GetName(), "name");
}
