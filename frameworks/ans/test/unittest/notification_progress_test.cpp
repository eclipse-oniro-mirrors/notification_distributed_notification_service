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

#include "notification_progress.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationProgressTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetMaxValue_00001
 * @tc.desc: Test SetMaxValue.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationProgressTest, SetMaxValue_00001, Function | SmallTest | Level1)
{
    NotificationProgress notificationProgress;
    notificationProgress.SetMaxValue(0xffffffff);
    EXPECT_EQ(0xffffffff, notificationProgress.GetMaxValue());
}

/**
 * @tc.name: SetCurrentValue_00001
 * @tc.desc: Test SetCurrentValue.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationProgressTest, SetCurrentValue_00001, Function | SmallTest | Level1)
{
    NotificationProgress notificationProgress;
    notificationProgress.SetCurrentValue(0xffffffff);
    EXPECT_EQ(0xffffffff, notificationProgress.GetCurrentValue());
}

/**
 * @tc.name: SetIsPercentage_00001
 * @tc.desc: Test SetIsPercentage.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationProgressTest, SetIsPercentage_00001, Function | SmallTest | Level1)
{
    NotificationProgress notificationProgress;
    notificationProgress.SetIsPercentage(true);
    EXPECT_EQ(true, notificationProgress.GetIsPercentage());
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationProgressTest, Dump_00001, Function | SmallTest | Level1)
{
    NotificationProgress notificationProgress;
    notificationProgress.SetIsPercentage(true);
    notificationProgress.SetMaxValue(1);
    notificationProgress.SetCurrentValue(1);
    std::string dumpStr = "Progress{ maxValue = 1, currentValue = 1, isPercentage = 1 }";
    EXPECT_EQ(dumpStr, notificationProgress.Dump());
}

/**
 * @tc.name: FromJson_00001
 * @tc.desc: Test FromJson and json is null.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationProgressTest, FromJson_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{};
    NotificationProgress notificationProgress;

    EXPECT_EQ(nullptr, notificationProgress.FromJson(jsonObject));
}

/**
 * @tc.name: FromJson_00002
 * @tc.desc: Test FromJson.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationProgressTest, FromJson_00002, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{
        {"maxValue", 1}, {"currentValue", 1},
        {"isPercentage", 1}};
    NotificationProgress notificationProgress;
    NotificationProgress *progress = notificationProgress.FromJson(jsonObject);
    EXPECT_NE(nullptr, progress);
    if (progress != nullptr) {
        delete progress;
    }
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationProgressTest, Marshalling_00001, Function | SmallTest | Level1)
{
    NotificationProgress notificationProgress;
    notificationProgress.SetIsPercentage(true);
    notificationProgress.SetMaxValue(1);
    notificationProgress.SetCurrentValue(1);

    Parcel parcel;
    notificationProgress.Marshalling(parcel);
    EXPECT_NE(nullptr, notificationProgress.Unmarshalling(parcel));
}
}
}
