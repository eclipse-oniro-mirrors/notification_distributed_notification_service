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

#define private public
#include <gtest/gtest.h>

#define private public
#define protected public
#include "notification_dialog.h"
#undef private
#undef protected
#include "ans_inner_errors.h"

extern void MockQueryActiveOsAccountIds(bool mockRet, uint8_t mockCase);


using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationDialogTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name      : NotificationDialog_00100
 * @tc.number    :
 * @tc.desc      : test GetActiveUserId function and QueryActiveOsAccountIds is ERR_OK
 */
HWTEST_F(NotificationDialogTest, NotificationDialog_00100, Function | SmallTest | Level1)
{
    NotificationDialog notificationDialog;
    MockQueryActiveOsAccountIds(true, 0);
    int32_t result = notificationDialog.GetActiveUserId();
    int32_t activeUserId = 100;
    EXPECT_EQ(result, activeUserId);
}

/**
 * @tc.name      : NotificationDialog_00200
 * @tc.number    :
 * @tc.desc      : test GetActiveUserId function and QueryActiveOsAccountIds is ERR_INVALID_OPERATION
 */
HWTEST_F(NotificationDialogTest, NotificationDialog_00200, Function | SmallTest | Level1)
{
    NotificationDialog notificationDialog;
    MockQueryActiveOsAccountIds(false, 1);
    int32_t result = notificationDialog.GetActiveUserId();
    int32_t activeUserId = -4;
    EXPECT_EQ(result, activeUserId);

    std::string bundleName = "BundleName";
    int32_t result2 =  notificationDialog.GetUidByBundleName(bundleName);
    int32_t code = -1;
    EXPECT_EQ(result2, code);
}

/**
 * @tc.name      : NotificationDialog_00300
 * @tc.number    :
 * @tc.desc      : test StartEnableNotificationDialogAbility function and topUid is uid
 */
HWTEST_F(NotificationDialogTest, NotificationDialog_00300, Function | SmallTest | Level1)
{
    NotificationDialog notificationDialog;
    MockQueryActiveOsAccountIds(false, 1);
    int32_t result = notificationDialog.GetActiveUserId();
    int32_t activeUserId = -4;
    EXPECT_EQ(result, activeUserId);

    std::string bundleName = "BundleName";
    int32_t result2 =  notificationDialog.GetUidByBundleName(bundleName);
    int32_t code = -1;
    EXPECT_EQ(result2, code);

    int32_t uid = 2;
    sptr<IRemoteObject> callerToken = nullptr;
    ErrCode result3 =  notificationDialog.StartEnableNotificationDialogAbility(uid, callerToken);
    EXPECT_EQ(result3, ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name      : NotificationDialog_00400
 * @tc.number    :
 * @tc.desc      : test StartEnableNotificationDialogAbility function and topUid is not uid
 */
HWTEST_F(NotificationDialogTest, NotificationDialog_00400, Function | SmallTest | Level1)
{
    NotificationDialog notificationDialog;
    MockQueryActiveOsAccountIds(false, 1);
    int32_t result = notificationDialog.GetActiveUserId();
    int32_t activeUserId = -4;
    EXPECT_EQ(result, activeUserId);

    std::string bundleName = "BundleName";
    int32_t result2 =  notificationDialog.GetUidByBundleName(bundleName);
    int32_t code = -1;
    EXPECT_EQ(result2, code);
    
    int32_t uid = -1;
    sptr<IRemoteObject> callerToken = nullptr;
    ErrCode result3 =  notificationDialog.StartEnableNotificationDialogAbility(uid, callerToken);
    EXPECT_EQ(result3, ERR_ANS_INVALID_BUNDLE);
}
}  // namespace Notification
}  // namespace OHOS
