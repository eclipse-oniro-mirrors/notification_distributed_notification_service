/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <string>
#include <unistd.h>
#include "notification_time.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationTimeTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetInitialTime_00001
 * @tc.desc: Test initialTime_ parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTimeTest, SetInitialTime_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationTime>();
    int32_t initialTime = 1;
    rrc->SetInitialTime(initialTime);
    EXPECT_EQ(rrc->GetInitialTime(), initialTime);
}

/**
 * @tc.name: SetIsCountDown_00001
 * @tc.desc: Test isCountDown_ parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTimeTest, SetIsCountDown_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationTime>();
    bool isCountDown = true;
    rrc->SetIsCountDown(isCountDown);
    EXPECT_EQ(rrc->GetIsCountDown(), isCountDown);
}

/**
 * @tc.name: SetIsPaused_0001
 * @tc.desc: Test isPaused_ parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTimeTest, SetIsPaused_0001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationTime>();
    bool isPaused = true;
    rrc->SetIsPaused(isPaused);
    EXPECT_EQ(rrc->GetIsPaused(), isPaused);
}

/**
 * @tc.name: SetIsInTitle_0001
 * @tc.desc: Test isInTitle_ parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTimeTest, SetIsInTitle_0001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationTime>();
    bool isInTitle = true;
    rrc->SetIsInTitle(isInTitle);
    EXPECT_EQ(rrc->GetIsInTitle(), isInTitle);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test buttonNames_ dump.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTimeTest, Dump_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationTime>();
    int32_t initialTime = 1;
    rrc->SetInitialTime(initialTime);
    bool isCountDown = true;
    rrc->SetIsCountDown(isCountDown);
    bool isPaused = true;
    rrc->SetIsPaused(isPaused);
    bool isInTitle = true;
    rrc->SetIsInTitle(isInTitle);
    EXPECT_EQ(rrc->Dump(), "Time{ "
            "initialTime = " + std::to_string(initialTime) +
            ", isCountDown = " + std::to_string(isCountDown) +
            ", isPaused = " + std::to_string(isPaused) +
            ", isInTitle = " + std::to_string(isInTitle) +
            " }");
}

/**
 * @tc.name: FromJson_00001
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTimeTest, FromJson_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationTime>();
    nlohmann::json jsonObject = nlohmann::json{"initialTime", "isCountDown", "isPaused", "isInTitle"};
    EXPECT_EQ(jsonObject.is_object(), false);
    EXPECT_EQ(rrc->FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: FromJson_00002
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTimeTest, FromJson_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationTime>();
    nlohmann::json jsonObject = nlohmann::json{{"initialTime", 60}, {"isCountDown", false},
        {"isPaused", false}, {"isInTitle", false}};
    EXPECT_EQ(jsonObject.is_object(), true);
    EXPECT_NE(rrc->FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationTimeTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationTime>();
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationTimeTest, Unmarshalling_00001, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    std::shared_ptr<NotificationTime> result =
        std::make_shared<NotificationTime>();

    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, true);
}
}
}
