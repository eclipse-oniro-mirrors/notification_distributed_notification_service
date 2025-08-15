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

#include <chrono>
#include <functional>
#include <memory>
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
#include "ipc_skeleton.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {
extern void MockIsVerfyPermisson(bool isVerify);
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);
extern void MockIsNonBundleName(bool isNonBundleName);

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
 * @tc.name: GetSlotsByBundle_00003
 * @tc.desc: Test GetSlotsByBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetSlotsByBundle_00003, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundle", 100);
    advancedNotificationService_->SetSilentReminderEnabled(bundleOption, true);
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::CUSTOMER_SERVICE;
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(slotType);
    slots.push_back(slot);
    std::vector<sptr<NotificationSlot>> slotRes;
    ASSERT_EQ(advancedNotificationService_->GetSlotsByBundle(bundleOption, slotRes), (int)ERR_OK);
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
    auto res = advancedNotificationService_->GetEnabledForBundleSlotSelf(slotType, enable);
    ASSERT_EQ(res, (int)ERR_OK);
    ASSERT_TRUE(enable);

    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    enable = false;
    res = advancedNotificationService_->GetEnabledForBundleSlotSelf(slotType, enable);
    ASSERT_EQ(res, (int)ERR_ANS_INVALID_PARAM);
    ASSERT_FALSE(enable);
}

/**
 * @tc.name: SetAdditionConfig_00001
 * @tc.desc: Test SetAdditionConfig_00001
 * @tc.type: FUNC
 */
HWTEST_F(AnsSlotServiceTest, SetAdditionConfig_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    MockIsVerfyPermisson(false);
    std::string key = RING_TRUST_PKG_KEY;
    std::string value = "";
    auto ret = advancedNotificationService_->SetAdditionConfig(key, value);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);

    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->SetAdditionConfig(key, value);
    ASSERT_EQ(ret, (int)ERR_OK);

    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    ret = advancedNotificationService_->SetAdditionConfig(key, value);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetAdditionConfig_00002
 * @tc.desc: Test SetAdditionConfig_00002
 * @tc.type: FUNC
 */
HWTEST_F(AnsSlotServiceTest, SetAdditionConfig_00002, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    std::string key = "NOTIFICATION_CTL_LIST_PKG";
    std::string value = "";

    auto ret = advancedNotificationService_->SetAdditionConfig(key, value);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: GetAllLiveViewEnabledBundles_00001
 * @tc.desc: Test GetAllLiveViewEnabledBundles_00001
 * @tc.type: FUNC
 */
HWTEST_F(AnsSlotServiceTest, GetAllLiveViewEnabledBundles_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    MockIsVerfyPermisson(false);
    std::vector<NotificationBundleOption> bundleOptions;
    NotificationBundleOption bundleOption("GetAllLiveViewEnabledBundles_00001", 999);
    bundleOptions.push_back(bundleOption);
    auto ret = advancedNotificationService_->GetAllLiveViewEnabledBundles(bundleOptions);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);

    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->GetAllLiveViewEnabledBundles(bundleOptions);
    ASSERT_EQ(ret, (int)ERR_OK);

    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    ret = advancedNotificationService_->GetAllLiveViewEnabledBundles(bundleOptions);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetEnabledForBundleSlot_00001
 * @tc.desc: Test UpdateSlots
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetEnabledForBundleSlot_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundleOption(
        new NotificationBundleOption("GetEnabledForBundleSlot_00001", 777));
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    bool enanle = true;
    advancedNotificationService_->notificationSvrQueue_= nullptr;
    auto ret = advancedNotificationService_->GetEnabledForBundleSlot(
        bundleOption, slotType, enanle);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
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
 * @tc.name: AddSlotByType_00001
 * @tc.desc: Test AddSlotByType
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, AddSlotByType_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    MockIsVerfyPermisson(false);
    
    auto ret = advancedNotificationService_->AddSlotByType(
        NotificationConstant::SlotType::EMERGENCY_INFORMATION);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->AddSlotByType(
        NotificationConstant::SlotType::LIVE_VIEW);
    ASSERT_EQ(ret, (int)ERR_OK);
    
    ret = advancedNotificationService_->AddSlotByType(
        NotificationConstant::SlotType::LIVE_VIEW);
    ASSERT_EQ(ret, (int)ERR_OK);
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
 * @tc.name: GetSlotFlagsAsBundle_00004
 * @tc.desc: Test GetSlotFlagsAsBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetSlotFlagsAsBundle_00006, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test888", 888);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    uint32_t flag = 0;
    auto ret = advancedNotificationService_->GetSlotFlagsAsBundle(bundle, flag);
    ASSERT_EQ(ret, (int)ERR_OK);
    ASSERT_EQ(flag, DEFAULT_SLOT_FLAGS);
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
    sptr<NotificationBundleOption> bundle = nullptr;
    advancedNotificationService_->SetRequestBySlotType(request, bundle);
    EXPECT_NE(request->GetFlags(), nullptr);
}

/**
 * @tc.name: SetRequestBySlotType_00002
 * @tc.desc: Test SetRequestBySlotType
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, SetRequestBySlotType_00002, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle(new NotificationBundleOption("test009", 9));
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SERVICE_REMINDER;
    sptr<NotificationSlot> slot(new (std::nothrow) NotificationSlot(slotType));
    slot->SetReminderMode(63);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    auto ret = NotificationPreferences::GetInstance()->AddNotificationSlots(bundle, slots);
    ASSERT_EQ(ret, (int)ERR_OK);

    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SERVICE_REMINDER);
    advancedNotificationService_->SetRequestBySlotType(request, bundle);

    auto flagSptr = request->GetFlags();
    ASSERT_NE(flagSptr, nullptr);
    ASSERT_EQ(flagSptr->GetReminderFlags(), 63);
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
 * @tc.name: GetSlotByBundle_00003
 * @tc.desc: Test GetSlotByBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetSlotByBundle_00003, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    sptr<NotificationBundleOption> bundle(new NotificationBundleOption("test99", 999));
    sptr<NotificationSlot> slot(
        new (std::nothrow) NotificationSlot(NotificationConstant::SlotType::CUSTOMER_SERVICE));
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    auto ret = NotificationPreferences::GetInstance()->AddNotificationSlots(bundle, slots);
    ASSERT_EQ(ret, (int)ERR_OK);

    sptr<NotificationSlot> slotOut;
    NotificationConstant::SlotType slotTypeTemp = NotificationConstant::SlotType::ILLEGAL_TYPE;
    ret = advancedNotificationService_->GetSlotByBundle(bundle, slotTypeTemp, slotOut);
    ASSERT_EQ(ret, (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST);
    ASSERT_EQ(slotOut, nullptr);
    
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    ret = advancedNotificationService_->GetSlotByBundle(bundle, slotTypeTemp, slot);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
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
 * @tc.name: UpdateSlotReminderModeBySlotFlags_00003
 * @tc.desc: Test UpdateSlotReminderModeBySlotFlags
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, UpdateSlotReminderModeBySlotFlags_00003, Function | SmallTest | Level1)
{
    uint32_t slotFlags = 0b000011;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test555", 555);

    auto ret = advancedNotificationService_->UpdateSlotReminderModeBySlotFlags(bundle, slotFlags);
    ASSERT_EQ(ret, (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
}

/**
 * @tc.name: GetDefaultSlotFlags_00001
 * @tc.desc: Test GetDefaultSlotFlags_00001
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetDefaultSlotFlags_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest(1));
    uint32_t notificationControlFlags = NotificationConstant::ReminderFlag::SA_SELF_BANNER_FLAG;
    request->SetNotificationControlFlags(notificationControlFlags);
    request->SetCreatorUid(IPCSkeleton::GetCallingUid());
    auto ret = advancedNotificationService_->GetDefaultSlotFlags(request);
    ASSERT_EQ(ret, 63);
}

/**
 * @tc.name: GenerateSlotReminderMode_00001
 * @tc.desc: Test GenerateSlotReminderMode
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GenerateSlotReminderMode_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = nullptr;
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
    sptr<NotificationBundleOption> bundle = nullptr;
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

/**
 * @tc.name: GetNotificationSettings_00001
 * @tc.desc: Verify that bits except for the 0th and 4th are 0
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSlotServiceTest, GetNotificationSettings_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    uint32_t flag = 0xff;
    auto ret = advancedNotificationService_->GetNotificationSettings(flag);
    ASSERT_EQ(ret, ERR_OK);
    // invalid outside of the 0th and 4th position
    uint32_t result = flag & 0xee;
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: GetNotificationSettings_00002
 * @tc.desc: Test GetNotificationSettings
 * @tc.type: FUNC
 */
HWTEST_F(AnsSlotServiceTest, GetNotificationSettings_00002, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundleOption = advancedNotificationService_->GenerateBundleOption();
    ASSERT_NE(bundleOption, nullptr);

    uint32_t flag = 0xff;
    auto ret = advancedNotificationService_->SetSlotFlagsAsBundle(bundleOption, flag);
    ASSERT_EQ(ret, ERR_OK);

    ret = advancedNotificationService_->GetNotificationSettings(flag);
    ASSERT_EQ(ret, ERR_OK);
    EXPECT_EQ(flag, 0x11);
}

/**
 * @tc.name: GetNotificationSettings_00003
 * @tc.desc: Test GetNotificationSettings when notificationSvrQueue is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AnsSlotServiceTest, GetNotificationSettings_00003, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    MockIsVerfyPermisson(false);
    auto advancedNotificationService = std::make_shared<AdvancedNotificationService>();
    ASSERT_NE(advancedNotificationService, nullptr);
    advancedNotificationService->notificationSvrQueue_ = nullptr;
    uint32_t flag;
    auto ret = advancedNotificationService->GetNotificationSettings(flag);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetNotificationSettings_00004
 * @tc.desc: Test GetNotificationSettings when bundleName is empty
 * @tc.type: FUNC
 */
HWTEST_F(AnsSlotServiceTest, GetNotificationSettings_00004, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_INVALID);
    MockIsNonBundleName(true);
    uint32_t flag;
    auto ret = advancedNotificationService_->GetNotificationSettings(flag);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsNonBundleName(false);
    EXPECT_EQ(ret, ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: AssignValidNotificationSlot_00001
 * @tc.desc: Test AssignValidNotificationSlot_00001
 * @tc.type: FUNC
 */
HWTEST_F(AnsSlotServiceTest, AssignValidNotificationSlot_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption("test666", 666));
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    record->request = request;

    uint32_t flag;
    auto ret = advancedNotificationService_->AssignValidNotificationSlot(record, bundleOption);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: SetEnabledForBundleSlotInner_00001
 * @tc.desc: Test SetEnabledForBundleSlotInner_00001
 * @tc.type: FUNC
 */
HWTEST_F(AnsSlotServiceTest, SetEnabledForBundleSlotInner_00001, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot(new NotificationSlot());
    slot->SetEnable(true);
    slot->SetForceControl(true);
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption("test6666", 6666));
    sptr<NotificationBundleOption> bundle(new NotificationBundleOption("test7777", 7777));
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SERVICE_REMINDER;

    auto ret = advancedNotificationService_->SetEnabledForBundleSlotInner(
        bundleOption, bundle, slotType, true, true);
    ASSERT_EQ(ret, ERR_OK);

    ret = advancedNotificationService_->SetEnabledForBundleSlotInner(
        bundleOption, bundle, slotType, true, true);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: PublishSlotChangeCommonEvent_00001
 * @tc.desc: Test PublishSlotChangeCommonEvent_00001
 * @tc.type: FUNC
 */
HWTEST_F(AnsSlotServiceTest, PublishSlotChangeCommonEvent_00001, Function | SmallTest | Level1)
{
    auto ret = advancedNotificationService_->PublishSlotChangeCommonEvent(nullptr);
    ASSERT_FALSE(ret);
}
}  // namespace Notification
}  // namespace OHOS
