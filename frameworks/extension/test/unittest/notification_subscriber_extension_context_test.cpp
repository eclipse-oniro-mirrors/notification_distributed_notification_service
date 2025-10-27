/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#define protected public
#include "mock_accesstoken_kit.h"
#include "notification_subscriber_extension_context.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationSubscriberExtensionContextTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: CheckCallerIsSystemApp_0100
 * @tc.desc: CheckCallerIsSystemApp.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberExtensionContextTest, CheckCallerIsSystemApp_0100, Function | SmallTest | Level1)
{
    NotificationSubscriberExtensionContext extensionContext;
    MockIsSystemAppByFullTokenID(false);
    bool result = extensionContext.CheckCallerIsSystemApp();
    ASSERT_FALSE(result);
}

/**
 * @tc.name: CheckCallerIsSystemApp_0200
 * @tc.desc: CheckCallerIsSystemApp.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberExtensionContextTest, CheckCallerIsSystemApp_0200, Function | SmallTest | Level1)
{
    NotificationSubscriberExtensionContext extensionContext;
    MockIsSystemAppByFullTokenID(true);
    bool result = extensionContext.CheckCallerIsSystemApp();
    ASSERT_TRUE(result);
}

/**
 * @tc.name: VerifyCallingPermission_0100
 * @tc.desc: VerifyCallingPermission.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberExtensionContextTest, VerifyCallingPermission_0100, Function | SmallTest | Level1)
{
    NotificationSubscriberExtensionContext extensionContext;
    MockIsVerifyPermission(false);
    bool result = extensionContext.VerifyCallingPermission("test");
    ASSERT_FALSE(result);
}

/**
 * @tc.name: VerifyCallingPermission_0200
 * @tc.desc: VerifyCallingPermission.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberExtensionContextTest, VerifyCallingPermission_0200, Function | SmallTest | Level1)
{
    NotificationSubscriberExtensionContext extensionContext;
    MockIsVerifyPermission(true);
    bool result = extensionContext.VerifyCallingPermission("test");
    ASSERT_TRUE(result);
}
}
}
