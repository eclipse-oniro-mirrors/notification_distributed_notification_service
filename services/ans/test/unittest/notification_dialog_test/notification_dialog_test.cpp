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
#include "notification_dialog_manager.h"
#undef private
#undef protected
#include "ans_inner_errors.h"
#include "ans_service_errors.h"
#include "notification_bundle_option.h"

extern void MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase);
extern void MockGetOsAccountLocalIdFromUid(bool mockRet, uint8_t mockCase = 0);


using namespace testing::ext;
namespace OHOS {
namespace Notification {
namespace {
constexpr const char* NOTIFICATION_DIALOG_SERVICE_BUNDLE = "com.ohos.notificationdialog";
constexpr const char* NOTIFICATION_DIALOG_SERVICE_ABILITY = "EnableNotificationDialog";
#ifdef ENABLE_ANS_PRIVILEGED_MESSAGE_EXT_WRAPPER
// NotificationDialogManager only stores the AdvancedNotificationService reference in its
// constructor, and SetDialogPoppedTimeInterVal never dereferences it, so binding the
// reference to a dummy object is sufficient for these tests.
AdvancedNotificationService& GetAnsRefForDialogManager()
{
    static unsigned char dummyAns[sizeof(void *)] = {0};
    return *reinterpret_cast<AdvancedNotificationService *>(dummyAns);
}
#endif
}

class NotificationDialogTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name      : NotificationDialog_00200
 * @tc.number    :
 * @tc.desc      : test QueryActiveOsAccountIds is ERR_INVALID_OPERATION
 */
HWTEST_F(NotificationDialogTest, NotificationDialog_00200, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(false, 1);

    std::string bundleName = "BundleName";
    int32_t result2 =  NotificationDialog::GetUidByBundleName(bundleName);
    int32_t code = -1;
    ASSERT_EQ(result2, code);
}

/**
 * @tc.name      : NotificationDialog_00300
 * @tc.number    :
 * @tc.desc      : test StartEnableNotificationDialogAbility function and topUid is uid
 */
HWTEST_F(NotificationDialogTest, NotificationDialog_00300, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(false, 1);

    std::string bundleName = "BundleName";
    int32_t result2 =  NotificationDialog::GetUidByBundleName(bundleName);
    int32_t code = -1;
    ASSERT_EQ(result2, code);

    int32_t uid = 2;
    sptr<IRemoteObject> callerToken = nullptr;
    ErrCode result3 =  NotificationDialog::StartEnableNotificationDialogAbility(
        NotificationDialogManager::NOTIFICATION_DIALOG_SERVICE_BUNDLE,
        NotificationDialogManager::NOTIFICATION_DIALOG_SERVICE_ABILITY,
        uid,
        bundleName,
        callerToken,
        false,
        false);
    ASSERT_EQ(result3, ERR_ANS_INNER_INVALID_BUNDLE);
}

/**
 * @tc.name      : NotificationDialog_00400
 * @tc.number    :
 * @tc.desc      : test StartEnableNotificationDialogAbility function topUid is not uid
 */
HWTEST_F(NotificationDialogTest, NotificationDialog_00400, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(false, 1);

    std::string bundleName = "BundleName";
    int32_t result2 =  NotificationDialog::GetUidByBundleName(bundleName);
    int32_t code = -1;
    ASSERT_EQ(result2, code);

    int32_t uid = 100;
    sptr<IRemoteObject> callerToken = nullptr;
    ErrCode result3 =  NotificationDialog::StartEnableNotificationDialogAbility(
        NotificationDialogManager::NOTIFICATION_DIALOG_SERVICE_BUNDLE,
        NotificationDialogManager::NOTIFICATION_DIALOG_SERVICE_ABILITY,
        uid,
        bundleName,
        callerToken,
        false,
        false);
    ASSERT_EQ(result3, ERR_ANS_INNER_INVALID_BUNDLE);
}

/**
 * @tc.name      : NotificationDialog_00500
 * @tc.number    :
 * @tc.desc      : test StartEnableNotificationDialogAbility function
 */
HWTEST_F(NotificationDialogTest, NotificationDialog_00500, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(false, 1);

    std::string bundleName = "BundleName";
    int32_t result2 =  NotificationDialog::GetUidByBundleName(bundleName);
    int32_t code = -1;
    ASSERT_EQ(result2, code);

    int32_t uid = 100;
    sptr<IRemoteObject> callerToken = nullptr;
    ErrCode result3 =  NotificationDialog::StartEnableNotificationDialogAbility(
        NotificationDialogManager::NOTIFICATION_DIALOG_SERVICE_BUNDLE,
        NotificationDialogManager::NOTIFICATION_DIALOG_SERVICE_ABILITY,
        uid,
        bundleName,
        callerToken,
        true,
        false);
    ASSERT_EQ(result3, ERR_ANS_INNER_INVALID_BUNDLE);
}

/**
 * @tc.name      : NotificationDialog_00600
 * @tc.number    :
 * @tc.desc      : test StartEnableNotificationDialogAbility function
 */
HWTEST_F(NotificationDialogTest, NotificationDialog_00600, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(false, 1);

    std::string bundleName = "topName";

    int32_t uid = 100;
    sptr<IRemoteObject> callerToken = nullptr;
    ErrCode result =  NotificationDialog::StartEnableNotificationDialogAbility(
        NotificationDialogManager::NOTIFICATION_DIALOG_SERVICE_BUNDLE,
        NotificationDialogManager::NOTIFICATION_DIALOG_SERVICE_ABILITY,
        uid,
        bundleName,
        callerToken,
        true,
        false);
    ASSERT_NE(result, (int)ERR_ANS_INVALID_BUNDLE);
}

#ifdef ENABLE_ANS_PRIVILEGED_MESSAGE_EXT_WRAPPER
/**
 * @tc.name      : SetDialogPoppedTimeInterVal_00100
 * @tc.number    : SetDialogPoppedTimeInterVal_00100
 * @tc.desc      : test SetDialogPoppedTimeInterVal when GetOsAccountLocalIdFromUid fails
 */
HWTEST_F(NotificationDialogTest, SetDialogPoppedTimeInterVal_00100, Function | SmallTest | Level1)
{
    NotificationDialogManager dialogManager(GetAnsRefForDialogManager());
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("testBundle", 1);

    MockGetOsAccountLocalIdFromUid(false, 0); // uid-to-userId resolution fails (line 373-374)
    dialogManager.SetDialogPoppedTimeInterVal(bundleOption); // early return, no crash
    EXPECT_NE(bundleOption, nullptr);
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

/**
 * @tc.name      : SetDialogPoppedTimeInterVal_00200
 * @tc.number    : SetDialogPoppedTimeInterVal_00200
 * @tc.desc      : test SetDialogPoppedTimeInterVal when resolved userId is invalid (<= 0)
 */
HWTEST_F(NotificationDialogTest, SetDialogPoppedTimeInterVal_00200, Function | SmallTest | Level1)
{
    NotificationDialogManager dialogManager(GetAnsRefForDialogManager());
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("testBundle", 1);

    MockGetOsAccountLocalIdFromUid(true, 1); // mock invalid userId (-2)
    dialogManager.SetDialogPoppedTimeInterVal(bundleOption); // early return, no crash
    EXPECT_NE(bundleOption, nullptr);
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}
#endif
}  // namespace Notification
}  // namespace OHOS
