/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <functional>

#include "ans_inner_errors.h"
#include "ans_manager_proxy.h"
#include "advanced_notification_service.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "notification_helper.h"
#include "remote_native_token.h"
#include "system_ability_definition.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
static sptr<ISystemAbilityManager> systemAbilityManager =
    SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
const int32_t CALLING_UID = 9998;
const int32_t USERID = 100;

class AnsInnerKitsModuleSettingTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AnsInnerKitsModuleSettingTest::SetUpTestCase()
{
    RemoteNativeToken::SetNativeToken();
    sptr<AdvancedNotificationService> service = OHOS::Notification::AdvancedNotificationService::GetInstance();
    OHOS::ISystemAbilityManager::SAExtraProp saExtraProp;
    systemAbilityManager->AddSystemAbility(OHOS::ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID, service, saExtraProp);
}

void AnsInnerKitsModuleSettingTest::TearDownTestCase()
{}

void AnsInnerKitsModuleSettingTest::SetUp()
{}

void AnsInnerKitsModuleSettingTest::TearDown()
{}

/**
 * @tc.number    : ANS_Interface_MT_NotificationSetting_00100
 * @tc.name      : NotificationSetting_00100
 * @tc.desc      : Set a specified application to show badge, get the specified application can show badge.
 * @tc.expected  : Set a specified application to show badge success, get the specified application can show badge.
 */
HWTEST_F(AnsInnerKitsModuleSettingTest, ANS_Interface_MT_NotificationSetting_00100, Function | MediumTest | Level1)
{
    NotificationBundleOption bundleOption;
    bundleOption.SetBundleName("bundlename");
    bundleOption.SetUid(CALLING_UID);
    GTEST_LOG_(INFO) << "BundleOption is:"<<bundleOption.Dump();
    EXPECT_EQ(0, NotificationHelper::SetShowBadgeEnabledForBundle(bundleOption, true));
    bool enabled = false;
    EXPECT_EQ(0, NotificationHelper::GetShowBadgeEnabledForBundle(bundleOption, enabled));
    EXPECT_EQ(true, enabled);
    EXPECT_EQ("bundlename", bundleOption.GetBundleName());
    EXPECT_EQ(CALLING_UID, bundleOption.GetUid());
}

/**
 * @tc.number    : ANS_Interface_MT_NotificationSetting_00200
 * @tc.name      : NotificationSetting_00100
 * @tc.desc      : Set a specified application do not show badge, get the specified application can not show badge.
 * @tc.expected  : Set a specified application do not show badge success, get the specified application can not show
 *                 badge.
 */
HWTEST_F(AnsInnerKitsModuleSettingTest, ANS_Interface_MT_NotificationSetting_00200, Function | MediumTest | Level1)
{
    NotificationBundleOption bundleOption("bundlename", CALLING_UID);
    EXPECT_EQ(0, NotificationHelper::SetShowBadgeEnabledForBundle(bundleOption, false));
    bool enabled = false;
    EXPECT_EQ(0, NotificationHelper::GetShowBadgeEnabledForBundle(bundleOption, enabled));
    EXPECT_EQ(false, enabled);
    EXPECT_EQ("bundlename", bundleOption.GetBundleName());
    EXPECT_EQ(CALLING_UID, bundleOption.GetUid());
}

/**
 * @tc.number    : ANS_Interface_MT_NotificationSetting_00300
 * @tc.name      : NotificationSetting_00300
 * @tc.desc      : Set a specified application can publish notification, get the specified application can publish
 *                 notification.
 * @tc.expected  : Set a specified application can publish notification success, get the specified application can
 *                 publish notification.
 */
HWTEST_F(AnsInnerKitsModuleSettingTest, ANS_Interface_MT_NotificationSetting_00300, Function | MediumTest | Level1)
{
    NotificationBundleOption bundleOption("bundlename", CALLING_UID);
    std::string deviceId;
    EXPECT_EQ(0, NotificationHelper::SetNotificationsEnabledForSpecifiedBundle(bundleOption, deviceId, true));
    bool enabled = false;
    EXPECT_EQ(0, NotificationHelper::IsAllowedNotify(bundleOption, enabled));
    EXPECT_EQ(true, enabled);
    EXPECT_EQ("bundlename", bundleOption.GetBundleName());
    EXPECT_EQ(CALLING_UID, bundleOption.GetUid());
}

/**
 * @tc.number    : ANS_Interface_MT_NotificationSetting_00400
 * @tc.name      : NotificationSetting_00400
 * @tc.desc      : Set a specified application do not publish notification, get the specified application can not
 *                 publish notification.
 * @tc.expected  : Set a specified application do not publish notification success, get the specified application can
 *                 not publish notification.
 */
HWTEST_F(AnsInnerKitsModuleSettingTest, ANS_Interface_MT_NotificationSetting_00400, Function | MediumTest | Level1)
{
    NotificationBundleOption bundleOption("bundlename", CALLING_UID);
    std::string deviceId;
    EXPECT_EQ(0, NotificationHelper::SetNotificationsEnabledForSpecifiedBundle(bundleOption, deviceId, false));
    bool enabled = false;
    EXPECT_EQ(0, NotificationHelper::IsAllowedNotify(bundleOption, enabled));
    EXPECT_EQ(false, enabled);
    EXPECT_EQ("bundlename", bundleOption.GetBundleName());
    EXPECT_EQ(CALLING_UID, bundleOption.GetUid());
}

/**
 * @tc.number    : ANS_Interface_MT_NotificationSetting_00500
 * @tc.name      : NotificationSetting_00500
 * @tc.desc      : If the template configuration file does not exist, query whether the template exists.
 * @tc.expected  : Query return failed.
 */
HWTEST_F(AnsInnerKitsModuleSettingTest, ANS_Interface_MT_NotificationSetting_00500, Function | MediumTest | Level1)
{
    std::string templateName("downloadTemplate");
    bool support = false;
    EXPECT_EQ(0, NotificationHelper::IsSupportTemplate(templateName, support));
    EXPECT_EQ(true, support);
}

/**
 * @tc.number    : ANS_Interface_MT_NotificationSetting_00700
 * @tc.name      : NotificationSetting_00700
 * @tc.desc      : The template does not exist in the system, query whether the template exists.
 * @tc.expected  : Query return failed.
 */
HWTEST_F(AnsInnerKitsModuleSettingTest, ANS_Interface_MT_NotificationSetting_00700, Function | MediumTest | Level1)
{
    std::string templateName("downloadTemplate_1");
    bool support = false;
    EXPECT_EQ(0, NotificationHelper::IsSupportTemplate(templateName, support));
    EXPECT_EQ(false, support);
}

/**
 * @tc.number    : ANS_Interface_MT_NotificationSetting_00800
 * @tc.name      : NotificationSetting_00800
 * @tc.desc      : Set whether to sync notifications to devices that do not have the app installed.
 * @tc.expected  : Set true, get true.
 */
HWTEST_F(AnsInnerKitsModuleSettingTest, ANS_Interface_MT_NotificationSetting_00800, Function | MediumTest | Level1)
{
    NotificationBundleOption bundleOption("bundlename", CALLING_UID);
    EXPECT_EQ(0, NotificationHelper::SetSyncNotificationEnabledWithoutApp(USERID, true));
    bool enabled = false;
    EXPECT_EQ(0, NotificationHelper::GetSyncNotificationEnabledWithoutApp(USERID, enabled));
    EXPECT_EQ(true, enabled);
}

/**
 * @tc.number    : ANS_Interface_MT_NotificationSetting_00900
 * @tc.name      : NotificationSetting_00900
 * @tc.desc      : Set a specified application do not show badge, get the specified application can not show badge.
 * @tc.expected  : Set false, get false.
 */
HWTEST_F(AnsInnerKitsModuleSettingTest, ANS_Interface_MT_NotificationSetting_00900, Function | MediumTest | Level1)
{
    NotificationBundleOption bundleOption("bundlename", CALLING_UID);
    EXPECT_EQ(0, NotificationHelper::SetSyncNotificationEnabledWithoutApp(USERID, false));
    bool enabled = true;
    EXPECT_EQ(0, NotificationHelper::GetSyncNotificationEnabledWithoutApp(USERID, enabled));
    EXPECT_EQ(false, enabled);
}
}  // namespace Notification
}  // namespace OHOS