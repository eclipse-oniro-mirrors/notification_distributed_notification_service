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
#include "enabled_notification_callback_data.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationCallbackDataTest : public testing::Test {
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
HWTEST_F(NotificationCallbackDataTest, SetBundle_00001, Function | SmallTest | Level1)
{
    std::string bundle = "Bundle";
    uid_t uid = 10;
    bool enable = true;
    auto rrc = std::make_shared<EnabledNotificationCallbackData>(bundle, uid, enable);
    rrc->SetBundle(bundle);
    EXPECT_EQ(rrc->GetBundle(), bundle);
}

/**
 * @tc.name: SetUid_00001
 * @tc.desc: Test SetUid parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationCallbackDataTest, SetUid_00001, Function | SmallTest | Level1)
{
    std::string bundle = "Bundle";
    uid_t uid = 10;
    bool enable = true;
    auto rrc = std::make_shared<EnabledNotificationCallbackData>(bundle, uid, enable);
    rrc->SetUid(uid);
    EXPECT_EQ(rrc->GetUid(), uid);
}

/**
 * @tc.name: SetEnable_00001
 * @tc.desc: Test SetEnable parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationCallbackDataTest, SetEnable_00001, Function | SmallTest | Level1)
{
    std::string bundle = "Bundle";
    uid_t uid = 10;
    bool enable = true;
    auto rrc = std::make_shared<EnabledNotificationCallbackData>(bundle, uid, enable);
    rrc->SetEnable(enable);
    EXPECT_EQ(rrc->GetEnable(), enable);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationCallbackDataTest, Dump_00001, Function | SmallTest | Level1)
{
    std::string bundle = "Bundle";
    uid_t uid = 10;
    bool enable = true;
    std::string result = "EnabledNotificationCallbackData{ bundle = Bundle, uid = 10, enable = 1 }";
    auto rrc = std::make_shared<EnabledNotificationCallbackData>(bundle, uid, enable);
    EXPECT_EQ(rrc->Dump(), result);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationCallbackDataTest, Marshalling_00001, Function | SmallTest | Level1)
{
    std::string bundle = "Bundle";
    uid_t uid = 10;
    bool enable = true;
    Parcel parcel;
    auto rrc = std::make_shared<EnabledNotificationCallbackData>(bundle, uid, enable);
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationCallbackDataTest, Unmarshalling_00001, Function | SmallTest | Level1)
{
    std::string bundle = "Bundle";
    uid_t uid = 10;
    bool enable = true;
    bool unmarshalling = true;
    Parcel parcel;
    auto rrc = std::make_shared<EnabledNotificationCallbackData>(bundle, uid, enable);
    if (nullptr != rrc) {
        if (nullptr == rrc->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, true);
}

/**
 * @tc.name: ReadFromParcel_00001
 * @tc.desc: Test ReadFromParcel parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(NotificationCallbackDataTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    std::string bundle = "Bundle";
    uid_t uid = 10;
    bool enable = true;
    Parcel parcel;
    auto rrc = std::make_shared<EnabledNotificationCallbackData>(bundle, uid, enable);
    EXPECT_EQ(rrc->ReadFromParcel(parcel), true);
}
}
}