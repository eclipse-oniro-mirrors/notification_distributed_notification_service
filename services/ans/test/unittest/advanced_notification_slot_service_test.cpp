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

#include "notification_bundle_option.h"
#include <chrono>
#include <functional>
#include <memory>
#include <new>
#include <thread>

#include "gtest/gtest.h"

#define private public
#include "advanced_notification_service.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "accesstoken_kit.h"
#include "notification_preferences.h"
#include "notification_constant.h"
#include "notification_config_parse.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {
extern void MockIsVerfyPermisson(bool isVerify);
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);

class AnsSlotServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    void TestAddSlot(NotificationConstant::SlotType type);

private:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AnsSlotServiceTest::advancedNotificationService_ = nullptr;

void AnsSlotServiceTest::SetUpTestCase() {}

void AnsSlotServiceTest::TearDownTestCase() {}

void AnsSlotServiceTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
    advancedNotificationService_->CancelAll("");
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    GTEST_LOG_(INFO) << "SetUp end";
}

void AnsSlotServiceTest::TearDown()
{
    delete advancedNotificationService_;
    advancedNotificationService_ = nullptr;
    GTEST_LOG_(INFO) << "TearDown";
}

void AnsSlotServiceTest::TestAddSlot(NotificationConstant::SlotType type)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(type);
    slot->SetEnable(true);
    slots.push_back(slot);
    ASSERT_EQ(advancedNotificationService_->AddSlots(slots), (int)ERR_OK);
}

/**
 * @tc.name: AddSlots_00001
 * @tc.desc: Test AddSlots
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, AddSlots_00001, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::CUSTOMER_SERVICE;
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(slotType);
    slots.push_back(slot);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    ASSERT_EQ(advancedNotificationService_->AddSlots(slots), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetSlots_00001
 * @tc.desc: Test GetSlots
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetSlots_00001, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    ASSERT_EQ(advancedNotificationService_->GetSlots(slots), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetSlotsByBundle_00001
 * @tc.desc: Test GetSlotsByBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetSlotsByBundle_00001, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationBundleOption> bundle = nullptr;
    ASSERT_EQ(advancedNotificationService_->GetSlotsByBundle(bundle, slots), (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: GetSlotsByBundle_00002
 * @tc.desc: Test GetSlotsByBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetSlotsByBundle_00002, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    ASSERT_EQ(advancedNotificationService_->GetSlotsByBundle(bundle, slots), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: UpdateSlots_00001
 * @tc.desc: Test UpdateSlots
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, UpdateSlots_00001, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationBundleOption> bundle = nullptr;
    ASSERT_EQ(advancedNotificationService_->UpdateSlots(bundle, slots), (int)ERR_ANS_INVALID_BUNDLE);

    bundle = new NotificationBundleOption("test", 1);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    ASSERT_EQ(advancedNotificationService_->UpdateSlots(bundle, slots), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: UpdateSlots_00002
 * @tc.desc: Test UpdateSlots
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, UpdateSlots_00002, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::LIVE_VIEW);
    slot->SetEnable(true);
    slots.push_back(slot);

    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto ret = advancedNotificationService_->UpdateSlots(bundle, slots);
    ASSERT_EQ(ret, (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST);
}

/**
 * @tc.name: RemoveAllSlots_00001
 * @tc.desc: Test RemoveAllSlots
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, RemoveAllSlots_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto ret = advancedNotificationService_->RemoveAllSlots();
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: RemoveAllSlots_00002
 * @tc.desc: Test RemoveAllSlots
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, RemoveAllSlots_00002, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::LIVE_VIEW);
    auto ret = advancedNotificationService_->RemoveAllSlots();
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: GetEnabledForBundleSlotSelf_00001
 * @tc.desc: Test GetEnabledForBundleSlotSelf
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetEnabledForBundleSlotSelf_00001, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::CONTENT_INFORMATION;
    TestAddSlot(slotType);

    bool enable = false;
    advancedNotificationService_->GetEnabledForBundleSlotSelf(slotType, enable);
    ASSERT_EQ(enable, true);
}

/**
 * @tc.name: GetSlotFlagsAsBundle_00001
 * @tc.desc: Test GetSlotFlagsAsBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetSlotFlagsAsBundle_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    auto ret = advancedNotificationService_->SetSlotFlagsAsBundle(bundle, 1);
    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);

    uint32_t flag = 0;
    ret = advancedNotificationService_->GetSlotFlagsAsBundle(bundle, flag);
    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: GetSlotFlagsAsBundle_00002
 * @tc.desc: Test GetSlotFlagsAsBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetSlotFlagsAsBundle_00002, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    auto ret = advancedNotificationService_->SetSlotFlagsAsBundle(bundle, 1);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);

    uint32_t flag = 0;
    ret = advancedNotificationService_->GetSlotFlagsAsBundle(bundle, flag);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: GetSlotFlagsAsBundle_00003
 * @tc.desc: Test GetSlotFlagsAsBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetSlotFlagsAsBundle_00003, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = nullptr;
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    auto ret = advancedNotificationService_->SetSlotFlagsAsBundle(bundle, 1);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);

    uint32_t flag = 0;
    ret = advancedNotificationService_->GetSlotFlagsAsBundle(bundle, flag);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: GetSlotFlagsAsBundle_00004
 * @tc.desc: Test GetSlotFlagsAsBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetSlotFlagsAsBundle_00004, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto ret = advancedNotificationService_->SetSlotFlagsAsBundle(bundle, 1);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    uint32_t flag = 0;
    ret = advancedNotificationService_->GetSlotFlagsAsBundle(bundle, flag);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetSlotFlagsAsBundle_00005
 * @tc.desc: Test GetSlotFlagsAsBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetSlotFlagsAsBundle_00005, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    auto ret = advancedNotificationService_->SetSlotFlagsAsBundle(bundle, 1);
    ASSERT_EQ(ret, (int)ERR_OK);

    uint32_t flag = 0;
    ret = advancedNotificationService_->GetSlotFlagsAsBundle(bundle, flag);
    ASSERT_EQ(ret, (int)ERR_OK);
    ASSERT_EQ(flag, 1);
}

/**
 * @tc.name: SetRequestBySlotType_00001
 * @tc.desc: Test SetRequestBySlotType
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, SetRequestBySlotType_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::CUSTOMER_SERVICE);
    sptr<NotificationBundleOption> bundle = new (std::nothrow) NotificationBundleOption();
    advancedNotificationService_->SetRequestBySlotType(request, bundle);
    EXPECT_NE(request->GetFlags(), nullptr);
}

/**
 * @tc.name: GetSlotByType_00001
 * @tc.desc: Test GetSlotByType
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetSlotByType_00001, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot;
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::CUSTOMER_SERVICE;
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto ret = advancedNotificationService_->AddSlotByType(slotType);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->GetSlotByType(slotType, slot);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: RemoveSlotByType_00001
 * @tc.desc: Test RemoveSlotByType
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, RemoveSlotByType_00001, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::CUSTOMER_SERVICE;
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto ret = advancedNotificationService_->RemoveSlotByType(slotType);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: RemoveSlotByType_00002
 * @tc.desc: Test RemoveSlotByType
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, RemoveSlotByType_00002, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::LIVE_VIEW;
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(slotType);
    slot->SetForceControl(true);
    slots.push_back(slot);
    ASSERT_EQ(advancedNotificationService_->AddSlots(slots), (int)ERR_OK);

    MockIsSystemApp(false);
    auto ret = advancedNotificationService_->RemoveSlotByType(slotType);
    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: GetSlotNumAsBundle_00001
 * @tc.desc: Test GetSlotNumAsBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetSlotNumAsBundle_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    uint64_t num = 0;
    auto ret = advancedNotificationService_->GetSlotNumAsBundle(bundle, num);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetSlotByBundle_00001
 * @tc.desc: Test GetSlotByBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetSlotByBundle_00001, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::CUSTOMER_SERVICE;
    sptr<NotificationBundleOption> bundle = nullptr;
    sptr<NotificationSlot> slot = nullptr;
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    auto ret = advancedNotificationService_->GetSlotByBundle(bundle, slotType, slot);
    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: GetSlotByBundle_00002
 * @tc.desc: Test GetSlotByBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetSlotByBundle_00002, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::CUSTOMER_SERVICE;
    sptr<NotificationBundleOption> bundle = nullptr;
    sptr<NotificationSlot> slot = nullptr;
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    auto ret = advancedNotificationService_->GetSlotByBundle(bundle, slotType, slot);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);

    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->GetSlotByBundle(bundle, slotType, slot);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);

    bundle = new NotificationBundleOption("test", 1);
    ret = advancedNotificationService_->GetSlotByBundle(bundle, slotType, slot);
    ASSERT_EQ(ret, (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST);
}

/**
 * @tc.name: UpdateSlotReminderModeBySlotFlags_00001
 * @tc.desc: Test UpdateSlotReminderModeBySlotFlags
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, UpdateSlotReminderModeBySlotFlags_00001, Function | SmallTest | Level1)
{
    uint32_t slotFlags = 0b111011;
    sptr<NotificationBundleOption> bundle = nullptr;
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    auto ret = advancedNotificationService_->UpdateSlotReminderModeBySlotFlags(bundle, slotFlags);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: UpdateSlotReminderModeBySlotFlags_00002
 * @tc.desc: Test UpdateSlotReminderModeBySlotFlags
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, UpdateSlotReminderModeBySlotFlags_00002, Function | SmallTest | Level1)
{
    uint32_t slotFlags = 0b000011;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot(NotificationConstant::SlotType::CUSTOMER_SERVICE);
    advancedNotificationService_->GenerateSlotReminderMode(slot, bundle);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    NotificationPreferences::GetInstance()->AddNotificationSlots(bundle, slots);

    auto ret = advancedNotificationService_->UpdateSlotReminderModeBySlotFlags(bundle, slotFlags);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: GenerateSlotReminderMode_00001
 * @tc.desc: Test GenerateSlotReminderMode
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GenerateSlotReminderMode_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new (std::nothrow) NotificationBundleOption();
    sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot(NotificationConstant::SlotType::SERVICE_REMINDER);
    advancedNotificationService_->GenerateSlotReminderMode(slot, bundle);
    ASSERT_EQ(slot->GetReminderMode(), (int)0b111011);
}

/**
 * @tc.name: GenerateSlotReminderMode_00002
 * @tc.desc: Test GenerateSlotReminderMode
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GenerateSlotReminderMode_00002, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new (std::nothrow) NotificationBundleOption();
    sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot(NotificationConstant::SlotType::SERVICE_REMINDER);
    advancedNotificationService_->GenerateSlotReminderMode(slot, bundle, true);
    ASSERT_EQ(slot->GetReminderMode(), (int)0b111011);
}

/**
 * @tc.name: GetConfigSlotReminderModeByType_00001
 * @tc.desc: Test GenerateSlotReminderMode
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetConfigSlotReminderModeByType_00001, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SERVICE_REMINDER;
    auto reminderMode =
        DelayedSingleton<NotificationConfigParse>::GetInstance()->GetConfigSlotReminderModeByType(slotType);
    ASSERT_EQ(reminderMode, (int)0b111111);
}
}  // namespace Notification
}  // namespace OHOS
