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
#include "enabled_silent_reminder_callback_data.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class EnabledSilentReminderCallbackDataTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetBundle_00001
 * @tc.desc: Test SetBundle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(EnabledSilentReminderCallbackDataTest, SetBundle_00001, Function | SmallTest | Level1)
{
    auto callback = std::make_shared<EnabledSilentReminderCallbackData>();
    callback->SetBundle("bundleName");
    EXPECT_EQ(callback->GetBundle(), "bundleName");
}

/**
 * @tc.name: SetUid_00001
 * @tc.desc: Test SetUid parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(EnabledSilentReminderCallbackDataTest, SetUid_00001, Function | SmallTest | Level1)
{
    auto callback = std::make_shared<EnabledSilentReminderCallbackData>();
    callback->SetUid(200202);
    EXPECT_EQ(callback->GetUid(), 200202);
}

/**
 * @tc.name: SetEnableStatus_00001
 * @tc.desc: Test SetEnableStatus parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(EnabledSilentReminderCallbackDataTest, SetEnableStatus_00001, Function | SmallTest | Level1)
{
    auto callback = std::make_shared<EnabledSilentReminderCallbackData>();
    callback->SetEnableStatus(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    EXPECT_EQ(callback->GetEnableStatus(), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
}

/**
 * @tc.name: Constructor_00001
 * @tc.desc: Test constructor with parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(EnabledSilentReminderCallbackDataTest, Constructor_00001, Function | SmallTest | Level1)
{
    auto callback = std::make_shared<EnabledSilentReminderCallbackData>(
        "bundleName", 200202, NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    EXPECT_EQ(callback->GetBundle(), "bundleName");
    EXPECT_EQ(callback->GetUid(), 200202);
    EXPECT_EQ(callback->GetEnableStatus(), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(EnabledSilentReminderCallbackDataTest, Dump_00001, Function | SmallTest | Level1)
{
    auto callback = std::make_shared<EnabledSilentReminderCallbackData>(
        "bundleName", 200202, NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    EXPECT_NE(callback->Dump(), "");
    EXPECT_TRUE(callback->Dump().find("bundleName") != std::string::npos);
    EXPECT_TRUE(callback->Dump().find("200202") != std::string::npos);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(EnabledSilentReminderCallbackDataTest, Marshalling_00001, Function | SmallTest | Level1)
{
    auto callback = std::make_shared<EnabledSilentReminderCallbackData>(
        "bundleName", 200202, NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    Parcel parcel;
    EXPECT_TRUE(callback->Marshalling(parcel));
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(EnabledSilentReminderCallbackDataTest, Unmarshalling_00001, Function | SmallTest | Level1)
{
    auto callback = std::make_shared<EnabledSilentReminderCallbackData>(
        "bundleName", 200202, NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    Parcel parcel;
    EXPECT_TRUE(callback->Marshalling(parcel));
    EnabledSilentReminderCallbackData *result = callback->Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result->GetBundle(), "bundleName");
    EXPECT_EQ(result->GetUid(), 200202);
    EXPECT_EQ(result->GetEnableStatus(), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    delete result;
}

/**
 * @tc.name: MarshallingAndUnmarshalling_00001
 * @tc.desc: Test Marshalling and Unmarshalling with DISABLED status.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(EnabledSilentReminderCallbackDataTest, MarshallingAndUnmarshalling_00001, Function | SmallTest | Level1)
{
    auto callback = std::make_shared<EnabledSilentReminderCallbackData>(
        "com.example.app", 100001, NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    Parcel parcel;
    EXPECT_TRUE(callback->Marshalling(parcel));
    EnabledSilentReminderCallbackData *result = callback->Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result->GetBundle(), "com.example.app");
    EXPECT_EQ(result->GetUid(), 100001);
    EXPECT_EQ(result->GetEnableStatus(), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    delete result;
}
}
}