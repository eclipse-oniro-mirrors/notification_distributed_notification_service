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
#include "notification_do_not_disturb_date.h"
#undef private
#undef protected

#include "notification_constant.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationDoNotDisturbDateTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetDoNotDisturbType_00001
 * @tc.desc: Test SetDoNotDisturbType parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationDoNotDisturbDateTest, SetDoNotDisturbType_00001, Function | SmallTest | Level1)
{
    NotificationConstant::DoNotDisturbType doNotDisturbType = NotificationConstant::DoNotDisturbType::ONCE;
    int64_t beginDate = 10;
    int64_t endDate = 10;
    auto rrc = std::make_shared<NotificationDoNotDisturbDate>(doNotDisturbType, beginDate, endDate);
    rrc->SetDoNotDisturbType(doNotDisturbType);
    EXPECT_EQ(rrc->GetDoNotDisturbType(), doNotDisturbType);
}

/**
 * @tc.name: SetBeginDate_00001
 * @tc.desc: Test SetBeginDate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationDoNotDisturbDateTest, SetBeginDate_00001, Function | SmallTest | Level1)
{
    NotificationConstant::DoNotDisturbType doNotDisturbType = NotificationConstant::DoNotDisturbType::ONCE;
    int64_t beginDate = 10;
    int64_t beginDate1 = 20;
    int64_t endDate = 10;
    auto rrc = std::make_shared<NotificationDoNotDisturbDate>(doNotDisturbType, beginDate, endDate);
    rrc->SetBeginDate(beginDate1);
    EXPECT_EQ(rrc->GetBeginDate(), beginDate1);
}

/**
 * @tc.name: SetEndDate_00001
 * @tc.desc: Test SetEndDate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationDoNotDisturbDateTest, SetEndDate_00001, Function | SmallTest | Level1)
{
    NotificationConstant::DoNotDisturbType doNotDisturbType = NotificationConstant::DoNotDisturbType::ONCE;
    int64_t beginDate = 10;
    int64_t endDate1 = 20;
    int64_t endDate = 10;
    auto rrc = std::make_shared<NotificationDoNotDisturbDate>(doNotDisturbType, beginDate, endDate);
    rrc->SetEndDate(endDate1);
    EXPECT_EQ(rrc->GetEndDate(), endDate1);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationDoNotDisturbDateTest, Dump_00001, Function | SmallTest | Level1)
{
    NotificationConstant::DoNotDisturbType doNotDisturbType = NotificationConstant::DoNotDisturbType::ONCE;
    int64_t beginDate = 10;
    int64_t endDate = 10;
    auto rrc = std::make_shared<NotificationDoNotDisturbDate>(doNotDisturbType, beginDate, endDate);
    std::string ret = "NotificationDoNotDisturbDate{ doNotDisturbType = 1, beginDate = 10, endDate = 10 }";
    EXPECT_EQ(rrc->Dump(), ret);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationDoNotDisturbDateTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    NotificationConstant::DoNotDisturbType doNotDisturbType = NotificationConstant::DoNotDisturbType::ONCE;
    int64_t beginDate = 10;
    int64_t endDate = 10;
    auto rrc = std::make_shared<NotificationDoNotDisturbDate>(doNotDisturbType, beginDate, endDate);
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationDoNotDisturbDateTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    NotificationConstant::DoNotDisturbType doNotDisturbType = NotificationConstant::DoNotDisturbType::ONCE;
    int64_t beginDate = 10;
    int64_t endDate = 10;
    std::shared_ptr<NotificationDoNotDisturbDate> result =
    std::make_shared<NotificationDoNotDisturbDate>(doNotDisturbType, beginDate, endDate);
    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, true);
}

/**
 * @tc.name: ReadFromParcel_00001
 * @tc.desc: Test ReadFromParcel parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationDoNotDisturbDateTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    NotificationConstant::DoNotDisturbType doNotDisturbType = NotificationConstant::DoNotDisturbType::ONCE;
    int64_t beginDate = 10;
    int64_t endDate = 10;
    auto rrc = std::make_shared<NotificationDoNotDisturbDate>(doNotDisturbType, beginDate, endDate);
    EXPECT_EQ(rrc->ReadFromParcel(parcel), true);
}
}
}