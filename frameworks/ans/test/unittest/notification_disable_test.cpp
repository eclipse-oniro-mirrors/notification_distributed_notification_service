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

#include "notification_disable.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationDisableTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: GetDisabled_0100
 * @tc.desc: Test GetDisabled.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, GetDisabled_0100, Function | SmallTest | Level1)
{
    NotificationDisable notificationDisable;
    notificationDisable.SetDisabled(true);
    EXPECT_TRUE(notificationDisable.GetDisabled());
}

/**
 * @tc.name: GetDisabled_0200
 * @tc.desc: Test GetDisabled.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, GetDisabled_0200, Function | SmallTest | Level1)
{
    NotificationDisable notificationDisable;
    notificationDisable.SetDisabled(false);
    EXPECT_FALSE(notificationDisable.GetDisabled());
}

/**
 * @tc.name: GetBundleList_0100
 * @tc.desc: Test GetBundleList.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, GetBundleList_0100, Function | SmallTest | Level1)
{
    NotificationDisable notificationDisable;
    std::vector<std::string> bundleList = { "com.example.app" };
    notificationDisable.SetBundleList(bundleList);
    ASSERT_EQ(notificationDisable.GetBundleList(), bundleList);
}

/**
 * @tc.name: Marshalling_0100
 * @tc.desc: Test Marshalling.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, Marshalling_0100, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationDisable>();
    EXPECT_TRUE(rrc->Marshalling(parcel));
}

/**
 * @tc.name: ReadFromParcel_0100
 * @tc.desc: Test ReadFromParcel.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, ReadFromParcel_0100, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationDisable>();
    EXPECT_TRUE(rrc->ReadFromParcel(parcel));
}

/**
 * @tc.name: Unmarshalling_0100
 * @tc.desc: Test Unmarshalling.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, Unmarshalling_0100, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    auto rrc = std::make_shared<NotificationDisable>();
    if (nullptr != rrc) {
        if (nullptr == rrc->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_TRUE(unmarshalling);
}
}
}
