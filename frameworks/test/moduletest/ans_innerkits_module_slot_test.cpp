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

#define private public
#include "advanced_notification_service.h"
#undef private
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_manager_proxy.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "notification_helper.h"
#include "remote_native_token.h"
#include "system_ability_definition.h"
#include "accesstoken_kit.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);

const int32_t SLEEP_TIME = 1;
static sptr<ISystemAbilityManager> systemAbilityManager =
    SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();

class AnsInnerKitsModuleSlotTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static sptr<AdvancedNotificationService> service_;
};

sptr<AdvancedNotificationService> AnsInnerKitsModuleSlotTest::service_;
void AnsInnerKitsModuleSlotTest::SetUpTestCase()
{
    RemoteNativeToken::SetNativeToken("ans_innerkits_module_slot_test");
    service_ = OHOS::Notification::AdvancedNotificationService::GetInstance();
    OHOS::ISystemAbilityManager::SAExtraProp saExtraProp;
    systemAbilityManager->AddSystemAbility(OHOS::ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID, service_, saExtraProp);
}

void AnsInnerKitsModuleSlotTest::TearDownTestCase()
{
    if (service_ != nullptr) {
        service_->SelfClean();
    }
}

void AnsInnerKitsModuleSlotTest::SetUp()
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    NotificationHelper::RemoveAllSlots();
}

void AnsInnerKitsModuleSlotTest::TearDown()
{}

/**
 * @tc.number    : ANS_Interface_MT_NotificationSlot_00100
 * @tc.name      : NotificationSlot_00100
 * @tc.desc      : Add notification slot(type is SOCIAL_COMMUNICATION), get notification slot and remove notification
 * slot.
 * @tc.expected  : Add notification slot success, get notification slot correctly and remove notification slot success.
 */
HWTEST_F(AnsInnerKitsModuleSlotTest, ANS_Interface_MT_NotificationSlot_00100, Function | MediumTest | Level1)
{
    NotificationSlot slot(NotificationConstant::SOCIAL_COMMUNICATION);
    slot.SetEnableLight(true);
    slot.SetDescription("description");
    slot.SetLedLightColor(0);
    slot.SetLevel(NotificationSlot::NotificationLevel::LEVEL_LOW);
    slot.SetSound(Uri("."));
    std::vector<int64_t> style;
    style.push_back(0);
    slot.SetVibrationStyle(style);
    slot.EnableBypassDnd(true);
    slot.EnableBadge(true);
    EXPECT_EQ(0, NotificationHelper::AddNotificationSlot(slot));
    sleep(SLEEP_TIME);

    sptr<NotificationSlot> spSlot(new NotificationSlot());
    EXPECT_EQ(0, NotificationHelper::GetNotificationSlot(NotificationConstant::SOCIAL_COMMUNICATION, spSlot));
    EXPECT_NE(nullptr, spSlot);
    GTEST_LOG_(INFO) << "after get slot dump slot information:" << spSlot->Dump();
    EXPECT_EQ(true, spSlot->CanEnableLight());
    EXPECT_EQ(true, spSlot->CanVibrate());
    EXPECT_EQ("description", spSlot->GetDescription());
    EXPECT_EQ("SOCIAL_COMMUNICATION", spSlot->GetId());
    EXPECT_EQ(0, spSlot->GetLedLightColor());
    EXPECT_EQ(NotificationSlot::NotificationLevel::LEVEL_LOW, spSlot->GetLevel());
    EXPECT_EQ(NotificationConstant::SOCIAL_COMMUNICATION, spSlot->GetType());
    EXPECT_EQ(NotificationConstant::VisiblenessType::PUBLIC, spSlot->GetLockScreenVisibleness());
    EXPECT_EQ("SOCIAL_COMMUNICATION", spSlot->GetName());
    EXPECT_EQ(Uri("."), spSlot->GetSound());
    for (auto it : spSlot->GetVibrationStyle()) {
        EXPECT_EQ(0, it);
    }
    EXPECT_EQ(Uri("."), spSlot->GetSound());
    EXPECT_EQ(true, spSlot->IsEnableBypassDnd());
    EXPECT_EQ(true, spSlot->IsShowBadge());
    EXPECT_EQ(0, NotificationHelper::RemoveNotificationSlot(NotificationConstant::SOCIAL_COMMUNICATION));
    EXPECT_EQ(0, NotificationHelper::GetNotificationSlot(NotificationConstant::SOCIAL_COMMUNICATION, spSlot));
}

/**
 * @tc.number    : ANS_Interface_MT_NotificationSlot_00200
 * @tc.name      : NotificationSlot_00200
 * @tc.desc      : Add notification slot(type is SERVICE_REMINDER), get notification slot and remove notification slot.
 * @tc.expected  : Add notification slot success, get notification slot correctly and remove notification slot success.
 */
HWTEST_F(AnsInnerKitsModuleSlotTest, ANS_Interface_MT_NotificationSlot_00200, Function | MediumTest | Level1)
{
    NotificationSlot slot(NotificationConstant::SERVICE_REMINDER);
    slot.SetEnableLight(true);
    slot.SetDescription("description");
    slot.SetLedLightColor(0);
    slot.SetLevel(NotificationSlot::NotificationLevel::LEVEL_LOW);
    slot.SetSound(Uri("."));
    std::vector<int64_t> style;
    style.push_back(0);
    slot.SetVibrationStyle(style);
    slot.EnableBypassDnd(true);
    slot.EnableBadge(true);
    EXPECT_EQ(0, NotificationHelper::AddNotificationSlot(slot));
    sleep(SLEEP_TIME);
    sptr<NotificationSlot> spSlot(new NotificationSlot());
    EXPECT_EQ(0, NotificationHelper::GetNotificationSlot(NotificationConstant::SERVICE_REMINDER, spSlot));

    EXPECT_NE(nullptr, spSlot);
    EXPECT_EQ(true, spSlot->CanEnableLight());
    EXPECT_EQ(true, spSlot->CanVibrate());
    EXPECT_EQ("description", spSlot->GetDescription());
    EXPECT_EQ("SERVICE_REMINDER", spSlot->GetId());
    EXPECT_EQ(0, spSlot->GetLedLightColor());
    EXPECT_EQ(NotificationSlot::NotificationLevel::LEVEL_LOW, spSlot->GetLevel());
    EXPECT_EQ(NotificationConstant::SERVICE_REMINDER, spSlot->GetType());
    EXPECT_EQ(NotificationConstant::VisiblenessType::PUBLIC, spSlot->GetLockScreenVisibleness());
    EXPECT_EQ("SERVICE_REMINDER", spSlot->GetName());
    EXPECT_EQ(Uri("."), spSlot->GetSound());
    for (auto it : spSlot->GetVibrationStyle()) {
        EXPECT_EQ(0, it);
    }
    EXPECT_EQ(Uri("."), spSlot->GetSound());
    EXPECT_EQ(true, spSlot->IsEnableBypassDnd());
    EXPECT_EQ(true, spSlot->IsShowBadge());
    EXPECT_EQ(0, NotificationHelper::RemoveNotificationSlot(NotificationConstant::SERVICE_REMINDER));
    EXPECT_EQ(0, NotificationHelper::GetNotificationSlot(NotificationConstant::SERVICE_REMINDER, spSlot));
}

/**
 * @tc.number    : ANS_Interface_MT_NotificationSlot_00300
 * @tc.name      : NotificationSlot_00300
 * @tc.desc      : Add notification slot(type is CONTENT_INFORMATION), get notification slot and remove notification
 * slot.
 * @tc.expected  : Add notification slot success, get notification slot correctly and remove notification slot success.
 */
HWTEST_F(AnsInnerKitsModuleSlotTest, ANS_Interface_MT_NotificationSlot_00300, Function | MediumTest | Level1)
{
    NotificationSlot slot(NotificationConstant::CONTENT_INFORMATION);
    slot.SetEnableLight(true);
    slot.SetDescription("description");
    slot.SetLedLightColor(0);
    slot.SetLevel(NotificationSlot::NotificationLevel::LEVEL_LOW);
    slot.SetSound(Uri("."));
    std::vector<int64_t> style;
    style.push_back(0);
    slot.SetVibrationStyle(style);
    slot.EnableBypassDnd(true);
    slot.EnableBadge(true);
    EXPECT_EQ(0, NotificationHelper::AddNotificationSlot(slot));
    sleep(SLEEP_TIME);
    sptr<NotificationSlot> spSlot(new NotificationSlot());
    EXPECT_EQ(0, NotificationHelper::GetNotificationSlot(NotificationConstant::CONTENT_INFORMATION, spSlot));

    EXPECT_NE(nullptr, spSlot);
    EXPECT_EQ(true, spSlot->CanEnableLight());
    EXPECT_EQ(true, spSlot->CanVibrate());
    EXPECT_EQ("description", spSlot->GetDescription());
    EXPECT_EQ("CONTENT_INFORMATION", spSlot->GetId());
    EXPECT_EQ(0, spSlot->GetLedLightColor());
    EXPECT_EQ(NotificationSlot::NotificationLevel::LEVEL_LOW, spSlot->GetLevel());
    EXPECT_EQ(NotificationConstant::CONTENT_INFORMATION, spSlot->GetType());
    EXPECT_EQ(NotificationConstant::VisiblenessType::SECRET, spSlot->GetLockScreenVisibleness());
    EXPECT_EQ("CONTENT_INFORMATION", spSlot->GetName());
    EXPECT_EQ(Uri("."), spSlot->GetSound());
    for (auto it : spSlot->GetVibrationStyle()) {
        EXPECT_EQ(0, it);
    }
    EXPECT_EQ(Uri("."), spSlot->GetSound());
    EXPECT_EQ(true, spSlot->IsEnableBypassDnd());
    EXPECT_EQ(true, spSlot->IsShowBadge());
    EXPECT_EQ(0, NotificationHelper::RemoveNotificationSlot(NotificationConstant::CONTENT_INFORMATION));
    EXPECT_EQ(0, NotificationHelper::GetNotificationSlot(NotificationConstant::CONTENT_INFORMATION, spSlot));
}

/**
 * @tc.number    : ANS_Interface_MT_NotificationSlot_00400
 * @tc.name      : NotificationSlot_00400
 * @tc.desc      : Add notification slot(type is OTHER), get notification slot and remove notification slot.
 * @tc.expected  : Add notification slot success, get notification slot correctly and remove notification slot success.
 */
HWTEST_F(AnsInnerKitsModuleSlotTest, ANS_Interface_MT_NotificationSlot_00400, Function | MediumTest | Level1)
{
    NotificationSlot slot(NotificationConstant::OTHER);
    slot.SetEnableLight(true);
    slot.SetDescription("description");
    slot.SetLedLightColor(0);
    slot.SetLevel(NotificationSlot::NotificationLevel::LEVEL_LOW);
    slot.SetSound(Uri("."));
    std::vector<int64_t> style;
    style.push_back(0);
    slot.SetVibrationStyle(style);
    slot.EnableBypassDnd(true);
    slot.EnableBadge(true);
    EXPECT_EQ(0, NotificationHelper::AddNotificationSlot(slot));
    sleep(SLEEP_TIME);
    sptr<NotificationSlot> spSlot(new NotificationSlot());
    EXPECT_EQ(0, NotificationHelper::GetNotificationSlot(NotificationConstant::OTHER, spSlot));

    EXPECT_NE(nullptr, spSlot);
    EXPECT_EQ(true, spSlot->CanEnableLight());
    EXPECT_EQ(true, spSlot->CanVibrate());
    EXPECT_EQ("description", spSlot->GetDescription());
    EXPECT_EQ("OTHER", spSlot->GetId());
    EXPECT_EQ(0, spSlot->GetLedLightColor());
    EXPECT_EQ(NotificationSlot::NotificationLevel::LEVEL_LOW, spSlot->GetLevel());
    EXPECT_EQ(NotificationConstant::OTHER, spSlot->GetType());
    EXPECT_EQ(NotificationConstant::VisiblenessType::SECRET, spSlot->GetLockScreenVisibleness());
    EXPECT_EQ("OTHER", spSlot->GetName());
    EXPECT_EQ(Uri("."), spSlot->GetSound());
    for (auto it : spSlot->GetVibrationStyle()) {
        EXPECT_EQ(0, it);
    }
    EXPECT_EQ(Uri("."), spSlot->GetSound());
    EXPECT_EQ(true, spSlot->IsEnableBypassDnd());
    EXPECT_EQ(true, spSlot->IsShowBadge());
    EXPECT_EQ(0, NotificationHelper::RemoveNotificationSlot(NotificationConstant::OTHER));
    EXPECT_EQ(0, NotificationHelper::GetNotificationSlot(NotificationConstant::OTHER, spSlot));
}

/**
 * @tc.number    : ANS_Interface_MT_NotificationSlot_00500
 * @tc.name      : NotificationSlot_00500
 * @tc.desc      : Add notification slot(type is OTHER), slot set description character length exceed 1000
 *                 characters, get notification slot and remove notification slot.
 * @tc.expected  : Add notification slot success, get notification slot correctly and remove notification slot success.
 */
HWTEST_F(AnsInnerKitsModuleSlotTest, ANS_Interface_MT_NotificationSlot_00500, Function | MediumTest | Level1)
{
    NotificationSlot slot(NotificationConstant::OTHER);
    slot.SetEnableLight(true);
    std::string description(2000, 'c');
    slot.SetDescription(description);
    slot.SetLedLightColor(0);
    slot.SetLevel(NotificationSlot::NotificationLevel::LEVEL_LOW);
    slot.SetSound(Uri("."));
    std::vector<int64_t> style;
    style.push_back(0);
    slot.SetVibrationStyle(style);
    slot.EnableBypassDnd(true);
    slot.EnableBadge(true);
    EXPECT_EQ(0, NotificationHelper::AddNotificationSlot(slot));
    sleep(SLEEP_TIME);
    sptr<NotificationSlot> spSlot(new NotificationSlot());
    EXPECT_EQ(0, NotificationHelper::GetNotificationSlot(NotificationConstant::OTHER, spSlot));

    EXPECT_NE(nullptr, spSlot);
    GTEST_LOG_(INFO) << "get slot is:" << spSlot->Dump();
    EXPECT_EQ(true, spSlot->CanEnableLight());
    EXPECT_EQ(true, spSlot->CanVibrate());
    std::string expecteDescription(1000, 'c');
    EXPECT_EQ(expecteDescription, spSlot->GetDescription());
    EXPECT_EQ("OTHER", spSlot->GetId());
    EXPECT_EQ(0, spSlot->GetLedLightColor());
    EXPECT_EQ(NotificationSlot::NotificationLevel::LEVEL_LOW, spSlot->GetLevel());
    EXPECT_EQ(NotificationConstant::OTHER, spSlot->GetType());
    EXPECT_EQ(NotificationConstant::VisiblenessType::SECRET, spSlot->GetLockScreenVisibleness());
    EXPECT_EQ("OTHER", spSlot->GetName());
    EXPECT_EQ(Uri("."), spSlot->GetSound());
    for (auto it : spSlot->GetVibrationStyle()) {
        EXPECT_EQ(0, it);
    }
    EXPECT_EQ(Uri("."), spSlot->GetSound());
    EXPECT_EQ(true, spSlot->IsEnableBypassDnd());
    EXPECT_EQ(true, spSlot->IsShowBadge());
    EXPECT_EQ(0, NotificationHelper::RemoveNotificationSlot(NotificationConstant::OTHER));
    EXPECT_EQ(0, NotificationHelper::GetNotificationSlot(NotificationConstant::OTHER, spSlot));
}

/**
 * @tc.number    : ANS_Interface_MT_NotificationSlot_00600
 * @tc.name      : NotificationSlot_00600
 * @tc.desc      : Create notification slot(type is SOCIAL_COMMUNICATION), get sound and vibration.
 * @tc.expected  : Create notification slot success, get sound and vibration success.
 */
HWTEST_F(AnsInnerKitsModuleSlotTest, ANS_Interface_MT_NotificationSlot_00600, Function | MediumTest | Level1)
{
    NotificationSlot slot(NotificationConstant::SOCIAL_COMMUNICATION);
    EXPECT_EQ("SOCIAL_COMMUNICATION", slot.GetName());
    EXPECT_EQ(NotificationConstant::VisiblenessType::PUBLIC, slot.GetLockScreenVisibleness());
    EXPECT_EQ(DEFAULT_NOTIFICATION_SOUND.ToString(), slot.GetSound().ToString());
    EXPECT_TRUE(slot.CanVibrate());
    EXPECT_EQ(DEFAULT_NOTIFICATION_VIBRATION, slot.GetVibrationStyle());
    EXPECT_EQ(NotificationSlot::NotificationLevel::LEVEL_HIGH, slot.GetLevel());
}

/**
 * @tc.number    : ANS_Interface_MT_NotificationSlot_00700
 * @tc.name      : NotificationSlot_00700
 * @tc.desc      : Create notification slot(type is SERVICE_REMINDER),  get sound and vibration.
 * @tc.expected  : Create notification slot success, get sound and vibration success.
 */
HWTEST_F(AnsInnerKitsModuleSlotTest, ANS_Interface_MT_NotificationSlot_00700, Function | MediumTest | Level1)
{
    NotificationSlot slot(NotificationConstant::SERVICE_REMINDER);
    EXPECT_EQ("SERVICE_REMINDER", slot.GetName());
    EXPECT_EQ(NotificationConstant::VisiblenessType::PUBLIC, slot.GetLockScreenVisibleness());
    EXPECT_EQ(DEFAULT_NOTIFICATION_SOUND.ToString(), slot.GetSound().ToString());
    EXPECT_TRUE(slot.CanVibrate());
    EXPECT_EQ(DEFAULT_NOTIFICATION_VIBRATION, slot.GetVibrationStyle());
    EXPECT_EQ(NotificationSlot::NotificationLevel::LEVEL_DEFAULT, slot.GetLevel());
}

/**
 * @tc.number    : ANS_Interface_MT_NotificationSlot_00800
 * @tc.name      : NotificationSlot_00800
 * @tc.desc      : Create notification slot(type is CONTENT_INFORMATION), get sound and vibration.
 * @tc.expected  : Create notification slot success, get sound and vibration success.
 */
HWTEST_F(AnsInnerKitsModuleSlotTest, ANS_Interface_MT_NotificationSlot_00800, Function | MediumTest | Level1)
{
    NotificationSlot slot(NotificationConstant::CONTENT_INFORMATION);
    EXPECT_EQ("CONTENT_INFORMATION", slot.GetName());
    EXPECT_EQ(NotificationConstant::VisiblenessType::SECRET, slot.GetLockScreenVisibleness());
    EXPECT_EQ("", slot.GetSound().ToString());
    EXPECT_FALSE(slot.CanVibrate());
    EXPECT_EQ(0U, slot.GetVibrationStyle().size());
    EXPECT_EQ(NotificationSlot::NotificationLevel::LEVEL_MIN, slot.GetLevel());
}

/**
 * @tc.number    : ANS_Interface_MT_NotificationSlot_00900
 * @tc.name      : NotificationSlot_00900
 * @tc.desc      : Create notification slot(type is OTHER), get sound and vibration.
 * @tc.expected  : Create notification slot success, get sound and vibration success.
 */
HWTEST_F(AnsInnerKitsModuleSlotTest, ANS_Interface_MT_NotificationSlot_00900, Function | MediumTest | Level1)
{
    NotificationSlot slot(NotificationConstant::OTHER);
    EXPECT_EQ("OTHER", slot.GetName());
    EXPECT_EQ(NotificationConstant::VisiblenessType::SECRET, slot.GetLockScreenVisibleness());
    EXPECT_EQ("", slot.GetSound().ToString());
    EXPECT_FALSE(slot.CanVibrate());
    EXPECT_EQ(0U, slot.GetVibrationStyle().size());
    EXPECT_EQ(NotificationSlot::NotificationLevel::LEVEL_MIN, slot.GetLevel());
}

/**
 * @tc.number    : ANS_Interface_MT_SetEnabledForBundleSlot_00100
 * @tc.name      : SetEnabledForBundleSlot_00100
 * @tc.desc      : Add notification slot(type is SOCIAL_COMMUNICATION), get slot default enable,
 * set and get slot enable.
 * @tc.expected  : Add notification slot success, slot default enalbe is true, get is the same as setting.
 */
HWTEST_F(AnsInnerKitsModuleSlotTest, ANS_Interface_MT_SetEnabledForBundleSlot_00100, Function | MediumTest | Level1)
{
    NotificationSlot slot(NotificationConstant::SOCIAL_COMMUNICATION);
    slot.SetEnableLight(true);
    slot.SetDescription("description");
    slot.SetLedLightColor(0);
    slot.SetLevel(NotificationSlot::NotificationLevel::LEVEL_LOW);
    slot.SetSound(Uri("."));
    std::vector<int64_t> style;
    style.push_back(0);
    slot.SetVibrationStyle(style);
    slot.EnableBypassDnd(true);
    slot.EnableBadge(true);
    EXPECT_EQ(0, NotificationHelper::AddNotificationSlot(slot));
    sleep(SLEEP_TIME);
    sptr<NotificationSlot> spSlot(new NotificationSlot());
    EXPECT_EQ(0, NotificationHelper::GetNotificationSlot(NotificationConstant::SOCIAL_COMMUNICATION, spSlot));
    EXPECT_NE(spSlot, nullptr);
    EXPECT_EQ(spSlot->GetEnable(), true);

    bool enable = false;
    NotificationBundleOption bo("bundlename", 1);
    EXPECT_EQ(0, NotificationHelper::SetEnabledForBundleSlot(
        bo, NotificationConstant::SOCIAL_COMMUNICATION, enable, false));
    sleep(SLEEP_TIME);
    EXPECT_EQ(0, NotificationHelper::GetEnabledForBundleSlot(bo, NotificationConstant::SOCIAL_COMMUNICATION, enable));
    EXPECT_EQ(enable, false);
}

/**
 * @tc.number    : ANS_Interface_MT_SetEnabledForBundleSlot_00200
 * @tc.name      : SetEnabledForBundleSlot_00200
 * @tc.desc      : Add slot when there is no type slot, add it. (SOCIAL_COMMUNICATION)
 * @tc.expected  : Set success, and get success.
 */
HWTEST_F(AnsInnerKitsModuleSlotTest, ANS_Interface_MT_SetEnabledForBundleSlot_00200, Function | MediumTest | Level1)
{
    bool enable = true;
    NotificationBundleOption bo("bundleName", 1);
    EXPECT_EQ(0, NotificationHelper::SetEnabledForBundleSlot(
        bo, NotificationConstant::SOCIAL_COMMUNICATION, enable, false));
    sleep(SLEEP_TIME);
    enable = false;
    EXPECT_EQ(0, NotificationHelper::GetEnabledForBundleSlot(bo, NotificationConstant::SOCIAL_COMMUNICATION, enable));
    EXPECT_EQ(enable, true);

    sptr<NotificationSlot> spSlot(new NotificationSlot());
    EXPECT_EQ(0, NotificationHelper::GetNotificationSlot(NotificationConstant::SOCIAL_COMMUNICATION, spSlot));
    EXPECT_NE(spSlot, nullptr);
    EXPECT_EQ(spSlot->GetEnable(), true);
}

/**
 * @tc.number    : ANS_Interface_MT_SetEnabledForBundleSlot_00300
 * @tc.name      : SetEnabledForBundleSlot_00300
 * @tc.desc      : Add slot when there is no type slot, add it. (SERVICE_REMINDER)
 * @tc.expected  : Set false, and get false.
 */
HWTEST_F(AnsInnerKitsModuleSlotTest, ANS_Interface_MT_SetEnabledForBundleSlot_00300, Function | MediumTest | Level1)
{
    bool enable = false;
    NotificationBundleOption bo("bundleName", 1);
    EXPECT_EQ(0, NotificationHelper::SetEnabledForBundleSlot(
        bo, NotificationConstant::SERVICE_REMINDER, enable, false));
    sleep(SLEEP_TIME);
    enable = true;
    EXPECT_EQ(0, NotificationHelper::GetEnabledForBundleSlot(bo, NotificationConstant::SERVICE_REMINDER, enable));
    EXPECT_EQ(enable, false);

    sptr<NotificationSlot> spSlot(new NotificationSlot());
    EXPECT_EQ(0, NotificationHelper::GetNotificationSlot(NotificationConstant::SERVICE_REMINDER, spSlot));
    EXPECT_NE(spSlot, nullptr);
    EXPECT_EQ(spSlot->GetEnable(), false);
}
}  // namespace Notification
}  // namespace OHOS
