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

#include <gtest/gtest.h>

#define private public
#define protected public
#include "notification_switch_changed_callback_data.h"
#include "ans_const_define.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationSwitchChangedCallbackDataTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetUserId_00001
 * @tc.desc: Test SetUserId and GetUserId.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationSwitchChangedCallbackDataTest, SetUserId_00001, Function | SmallTest | Level1)
{
    std::string switchName = "DEAL";
    int32_t userId = 100;
    NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON;
    auto data = std::make_shared<NotificationSwitchChangedCallbackData>(switchName, userId, enableStatus);
    EXPECT_EQ(data->GetUserId(), userId);
    int32_t newUserId = 200;
    data->SetUserId(newUserId);
    EXPECT_EQ(data->GetUserId(), newUserId);
}

/**
 * @tc.name: SetSwitchName_00001
 * @tc.desc: Test SetSwitchName and GetSwitchName.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationSwitchChangedCallbackDataTest, SetSwitchName_00001, Function | SmallTest | Level1)
{
    std::string switchName = "DEAL";
    int32_t userId = 100;
    NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON;
    auto data = std::make_shared<NotificationSwitchChangedCallbackData>(switchName, userId, enableStatus);
    EXPECT_EQ(data->GetSwitchName(), switchName);
    std::string newSwitchName = "LOGISTICS";
    data->SetSwitchName(newSwitchName);
    EXPECT_EQ(data->GetSwitchName(), newSwitchName);
}

/**
 * @tc.name: SetEnableStatus_00001
 * @tc.desc: Test SetEnableStatus and GetEnableStatus with USER_MODIFIED_ON.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationSwitchChangedCallbackDataTest, SetEnableStatus_00001, Function | SmallTest | Level1)
{
    std::string switchName = "DEAL";
    int32_t userId = 100;
    NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON;
    auto data = std::make_shared<NotificationSwitchChangedCallbackData>(switchName, userId, enableStatus);
    EXPECT_EQ(data->GetEnableStatus(), NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    data->SetEnableStatus(NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
    EXPECT_EQ(data->GetEnableStatus(), NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
}

/**
 * @tc.name: SetEnableStatus_00002
 * @tc.desc: Test SetEnableStatus and GetEnableStatus with SYSTEM_DEFAULT_ON.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationSwitchChangedCallbackDataTest, SetEnableStatus_00002, Function | SmallTest | Level1)
{
    std::string switchName = "LOGISTICS";
    int32_t userId = 100;
    NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
    auto data = std::make_shared<NotificationSwitchChangedCallbackData>(switchName, userId, enableStatus);
    EXPECT_EQ(data->GetEnableStatus(), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
    data->SetEnableStatus(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    EXPECT_EQ(data->GetEnableStatus(), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
}

/**
 * @tc.name: SetEnableStatus_00003
 * @tc.desc: Test default enableStatus is SYSTEM_DEFAULT_OFF for default constructor.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationSwitchChangedCallbackDataTest, SetEnableStatus_00003, Function | SmallTest | Level1)
{
    auto data = std::make_shared<NotificationSwitchChangedCallbackData>();
    EXPECT_EQ(data->GetEnableStatus(), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    EXPECT_EQ(data->GetUserId(), SUBSCRIBE_USER_INIT);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump output format.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationSwitchChangedCallbackDataTest, Dump_00001, Function | SmallTest | Level1)
{
    std::string switchName = "DEAL";
    int32_t userId = 100;
    NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON;
    auto data = std::make_shared<NotificationSwitchChangedCallbackData>(switchName, userId, enableStatus);
    std::string result = "NotificationSwitchChangedCallbackData{ "
        "userId = 100, switchName = DEAL, enableStatus = 1 }";
    EXPECT_EQ(data->Dump(), result);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling returns true when parcel is valid.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationSwitchChangedCallbackDataTest, Marshalling_00001, Function | SmallTest | Level1)
{
    std::string switchName = "DEAL";
    int32_t userId = 100;
    NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON;
    Parcel parcel;
    auto data = std::make_shared<NotificationSwitchChangedCallbackData>(switchName, userId, enableStatus);
    EXPECT_EQ(data->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Marshalling and Unmarshalling roundtrip preserves all fields.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationSwitchChangedCallbackDataTest, Unmarshalling_00001, Function | SmallTest | Level1)
{
    std::string switchName = "LOGISTICS";
    int32_t userId = 200;
    NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
    Parcel parcel;
    auto data = std::make_shared<NotificationSwitchChangedCallbackData>(switchName, userId, enableStatus);
    EXPECT_EQ(data->Marshalling(parcel), true);
    auto unmarshalled = NotificationSwitchChangedCallbackData::Unmarshalling(parcel);
    EXPECT_NE(unmarshalled, nullptr);
    EXPECT_EQ(unmarshalled->GetUserId(), userId);
    EXPECT_EQ(unmarshalled->GetSwitchName(), switchName);
    EXPECT_EQ(unmarshalled->GetEnableStatus(), enableStatus);
}

/**
 * @tc.name: ReadFromParcel_00001
 * @tc.desc: Test ReadFromParcel returns true when parcel data is valid.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationSwitchChangedCallbackDataTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    std::string switchName = "DEAL";
    int32_t userId = 100;
    NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    Parcel parcel;
    auto data = std::make_shared<NotificationSwitchChangedCallbackData>(switchName, userId, enableStatus);
    EXPECT_EQ(data->Marshalling(parcel), true);
    auto newData = std::make_shared<NotificationSwitchChangedCallbackData>();
    EXPECT_EQ(newData->ReadFromParcel(parcel), true);
    EXPECT_EQ(newData->GetUserId(), userId);
    EXPECT_EQ(newData->GetSwitchName(), switchName);
    EXPECT_EQ(newData->GetEnableStatus(), enableStatus);
}
}  // namespace Notification
}  // namespace OHOS