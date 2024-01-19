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
#include <memory>

#define private public
#define protected public
#include "advanced_notification_service.h"
#include "notification_dialog_manager.h"
#undef private
#undef protected
#include "common_event_manager.h"
#include "matching_skills.h"
#include "ans_const_define.h"
#include "ans_log_wrapper.h"
#include "notification_bundle_option.h"
#include "notification_dialog.h"
#include "ans_dialog_host_client.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
class NotificationDialogManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: Init_00001
 * @tc.desc: Test Init
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationDialogManagerTest, Init_00001, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    auto dialogManager = std::make_unique<NotificationDialogManager>(ans);
    EXPECT_EQ(dialogManager->Init(), true);
}

/**
 * @tc.name: AddDialogInfoIfNotExist_00001
 * @tc.desc: Test AddDialogInfoIfNotExist
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationDialogManagerTest, AddDialogInfoIfNotExist_00001, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    auto dialogManager = std::make_unique<NotificationDialogManager>(ans);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    sptr<AnsDialogHostClient> callback = nullptr;
    AnsDialogHostClient::CreateIfNullptr(callback);
    callback = AnsDialogHostClient::GetInstance();
    EXPECT_EQ(dialogManager->AddDialogInfoIfNotExist(bundle, callback), true);
}

/**
 * @tc.name: RequestEnableNotificationDailog_00001
 * @tc.desc: Test RequestEnableNotificationDailog
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationDialogManagerTest, RequestEnableNotificationDailog_00001, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    auto dialogManager = std::make_unique<NotificationDialogManager>(ans);
    EXPECT_EQ(dialogManager->RequestEnableNotificationDailog(nullptr, nullptr, nullptr), (int)ERROR_INTERNAL_ERROR);
}

/**
 * @tc.name: RequestEnableNotificationDailog_00002
 * @tc.desc: Test RequestEnableNotificationDailog
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationDialogManagerTest, RequestEnableNotificationDailog_00002, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    auto dialogManager = std::make_unique<NotificationDialogManager>(ans);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    sptr<AnsDialogHostClient> callback = nullptr;
    AnsDialogHostClient::CreateIfNullptr(callback);
    callback = AnsDialogHostClient::GetInstance();
    EXPECT_EQ(dialogManager->AddDialogInfoIfNotExist(bundle, callback), true);
    EXPECT_EQ(dialogManager->RequestEnableNotificationDailog(bundle, callback, nullptr),
        (int)ERR_ANS_DIALOG_IS_POPPING);
}

/**
 * @tc.name: RequestEnableNotificationDailog_00003
 * @tc.desc: Test RequestEnableNotificationDailog
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationDialogManagerTest, RequestEnableNotificationDailog_00003, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    auto dialogManager = std::make_unique<NotificationDialogManager>(ans);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    sptr<AnsDialogHostClient> callback = nullptr;
    AnsDialogHostClient::CreateIfNullptr(callback);
    callback = AnsDialogHostClient::GetInstance();
    EXPECT_NE(dialogManager->RequestEnableNotificationDailog(bundle, callback, nullptr), (int)ERR_OK);
}

/**
 * @tc.name: OnBundleEnabledStatusChanged_00001
 * @tc.desc: Test OnBundleEnabledStatusChanged
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationDialogManagerTest, OnBundleEnabledStatusChanged_00001, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    auto dialogManager = std::make_unique<NotificationDialogManager>(ans);
    EXPECT_NE(dialogManager->OnBundleEnabledStatusChanged(DialogStatus::ALLOW_CLICKED, "test"), ERR_OK);
}

/**
 * @tc.name: OnBundleEnabledStatusChanged_00002
 * @tc.desc: Test OnBundleEnabledStatusChanged
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationDialogManagerTest, OnBundleEnabledStatusChanged_00002, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    auto dialogManager = std::make_unique<NotificationDialogManager>(ans);
    EXPECT_NE(dialogManager->OnBundleEnabledStatusChanged(DialogStatus::DENY_CLICKED, "test1"), ERR_OK);
}

/**
 * @tc.name: OnBundleEnabledStatusChanged_00003
 * @tc.desc: Test OnBundleEnabledStatusChanged
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationDialogManagerTest, OnBundleEnabledStatusChanged_00003, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    auto dialogManager = std::make_unique<NotificationDialogManager>(ans);
    EXPECT_NE(dialogManager->OnBundleEnabledStatusChanged(DialogStatus::DIALOG_CRASHED, "test2"), ERR_OK);
}

/**
 * @tc.name: GetBundleOptionByBundleName_00001
 * @tc.desc: Test GetBundleOptionByBundleName
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationDialogManagerTest, GetBundleOptionByBundleName_00001, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    auto dialogManager = std::make_unique<NotificationDialogManager>(ans);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    sptr<AnsDialogHostClient> callback = nullptr;
    AnsDialogHostClient::CreateIfNullptr(callback);
    callback = AnsDialogHostClient::GetInstance();
    EXPECT_EQ(dialogManager->AddDialogInfoIfNotExist(bundle, callback), true);
    EXPECT_NE(dialogManager->GetBundleOptionByBundleName("test"), nullptr);
}

/**
 * @tc.name: GetBundleOptionByBundleName_00002
 * @tc.desc: Test GetBundleOptionByBundleName
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationDialogManagerTest, GetBundleOptionByBundleName_00002, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    auto dialogManager = std::make_unique<NotificationDialogManager>(ans);
    EXPECT_EQ(dialogManager->GetBundleOptionByBundleName("test"), nullptr);
}

/**
 * @tc.name: RemoveDialogInfoByBundleOption_00001
 * @tc.desc: Test RemoveDialogInfoByBundleOption
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationDialogManagerTest, RemoveDialogInfoByBundleOption_00001, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    auto dialogManager = std::make_unique<NotificationDialogManager>(ans);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    sptr<AnsDialogHostClient> callback = nullptr;
    AnsDialogHostClient::CreateIfNullptr(callback);
    callback = AnsDialogHostClient::GetInstance();
    EXPECT_EQ(dialogManager->AddDialogInfoIfNotExist(bundle, callback), true);
    EXPECT_NE(dialogManager->GetBundleOptionByBundleName("test"), nullptr);

    std::unique_ptr<NotificationDialogManager::DialogInfo> dialogInfoRemoved = nullptr;
    dialogManager->RemoveDialogInfoByBundleOption(bundle, dialogInfoRemoved);
    EXPECT_NE(dialogInfoRemoved, nullptr);

    dialogManager->RemoveDialogInfoByBundleOption(bundle, dialogInfoRemoved);
    EXPECT_EQ(dialogInfoRemoved, nullptr);
}

/**
 * @tc.name: RemoveAllDialogInfos_00001
 * @tc.desc: Test RemoveAllDialogInfos
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationDialogManagerTest, RemoveAllDialogInfos_00001, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    auto dialogManager = std::make_unique<NotificationDialogManager>(ans);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    sptr<AnsDialogHostClient> callback = nullptr;
    AnsDialogHostClient::CreateIfNullptr(callback);
    callback = AnsDialogHostClient::GetInstance();
    EXPECT_EQ(dialogManager->AddDialogInfoIfNotExist(bundle, callback), true);

    std::list<std::unique_ptr<NotificationDialogManager::DialogInfo>> dialogInfosRemoved;
    dialogManager->RemoveAllDialogInfos(dialogInfosRemoved);
    EXPECT_EQ(dialogInfosRemoved.empty(), false);
}

/**
 * @tc.name: SetHasPoppedDialog_00001
 * @tc.desc: Test SetHasPoppedDialog
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationDialogManagerTest, SetHasPoppedDialog_00001, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    auto dialogManager = std::make_unique<NotificationDialogManager>(ans);
    EXPECT_EQ(dialogManager->SetHasPoppedDialog(nullptr, true), false);
}

/**
 * @tc.name: SetHasPoppedDialog_00002
 * @tc.desc: Test SetHasPoppedDialog
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationDialogManagerTest, SetHasPoppedDialog_00002, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    auto dialogManager = std::make_unique<NotificationDialogManager>(ans);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    EXPECT_EQ(dialogManager->SetHasPoppedDialog(nullptr, true), false);
}
}  // namespace Notification
}  // namespace OHOS
