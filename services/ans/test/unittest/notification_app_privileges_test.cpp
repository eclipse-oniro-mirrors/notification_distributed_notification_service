/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "notification_app_privileges.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationAppPrivilegesTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name      : NotificationAppPrivileges_00100
 * @tc.number    :
 * @tc.desc      : Test constructure.
 */
HWTEST_F(NotificationAppPrivilegesTest, NotificationAppPrivileges_00100, Function | SmallTest | Level1)
{
    NotificationAppPrivileges appPrivileges("1");
    EXPECT_EQ(appPrivileges.IsLiveViewEnabled(), true);
    EXPECT_EQ(appPrivileges.IsBannerEnabled(), false);
    EXPECT_EQ(appPrivileges.IsReminderEnabled(), false);
}


/**
 * @tc.name      : NotificationAppPrivileges_00100
 * @tc.number    :
 * @tc.desc      : Test constructure.
 */
HWTEST_F(NotificationAppPrivilegesTest, NotificationAppPrivileges_00200, Function | SmallTest | Level1)
{
    NotificationAppPrivileges appPrivileges("11");
    EXPECT_EQ(appPrivileges.IsLiveViewEnabled(), true);
    EXPECT_EQ(appPrivileges.IsBannerEnabled(), true);
    EXPECT_EQ(appPrivileges.IsReminderEnabled(), false);
}

/**
 * @tc.name      : NotificationAppPrivileges_00100
 * @tc.number    :
 * @tc.desc      : Test constructure.
 */
HWTEST_F(NotificationAppPrivilegesTest, NotificationAppPrivileges_00300, Function | SmallTest | Level1)
{
    NotificationAppPrivileges appPrivileges("111");
    EXPECT_EQ(appPrivileges.IsLiveViewEnabled(), true);
    EXPECT_EQ(appPrivileges.IsBannerEnabled(), true);
    EXPECT_EQ(appPrivileges.IsReminderEnabled(), true);
}

/**
 * @tc.name      : NotificationAppPrivileges_00100
 * @tc.number    :
 * @tc.desc      : Test constructure.
 */
HWTEST_F(NotificationAppPrivilegesTest, NotificationAppPrivileges_00400, Function | SmallTest | Level1)
{
    NotificationAppPrivileges appPrivileges("001");
    EXPECT_EQ(appPrivileges.IsLiveViewEnabled(), false);
    EXPECT_EQ(appPrivileges.IsBannerEnabled(), false);
    EXPECT_EQ(appPrivileges.IsReminderEnabled(), true);
}
} // namespace Notification
} // namespace OHOS
