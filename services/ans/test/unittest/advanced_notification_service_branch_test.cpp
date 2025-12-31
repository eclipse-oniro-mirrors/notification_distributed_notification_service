/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include <thread>

#include "gtest/gtest.h"

#define private public

#include "advanced_notification_service.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_subscriber_listener.h"
#include "ans_result_data_synchronizer.h"
#include "ans_ut_constant.h"
#include "iremote_object.h"
#include "want_agent_info.h"
#include "want_agent_helper.h"
#include "want_params.h"
#include "mock_ipc_skeleton.h"
#include "notification_preferences.h"
#include "notification_constant.h"
#include "notification_record.h"
#include "notification_subscriber.h"
#include "os_account_manager.h"
#include "refbase.h"

extern void MockVerifyNativeToken(bool mockRet);
extern void MockVerifyShellToken(bool mockRet);
extern void MockGetDistributedEnableInApplicationInfo(bool mockRet, uint8_t mockCase = 0);
extern void MockGetOsAccountLocalIdFromUid(bool mockRet, uint8_t mockCase = 0);
extern void MockIsOsAccountExists(bool mockRet);

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {
extern void MockIsVerfyPermisson(bool isVerify);
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);
extern void MockDistributedNotificationEnabled(bool isEnable);
extern void MockIsNonBundleName(bool isNonBundleName);

class AnsBranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static void InitNotificationRecord(std::shared_ptr<NotificationRecord> &record,
        const NotificationLiveViewContent::LiveViewStatus &status);
private:
    void TestAddSlot(NotificationConstant::SlotType type);

private:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AnsBranchTest::advancedNotificationService_ = nullptr;

void AnsBranchTest::SetUpTestCase() {}

void AnsBranchTest::TearDownTestCase() {}

void AnsBranchTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService_->CancelAll("",
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
    }
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    GTEST_LOG_(INFO) << "SetUp end";
}

void AnsBranchTest::TearDown()
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);
    advancedNotificationService_ = nullptr;
    GTEST_LOG_(INFO) << "TearDown";
}

inline void SleepForFC()
{
    // For ANS Flow Control
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

class TestAnsSubscriber : public NotificationSubscriber {
public:
    void OnDied() override
    {}
    void OnConnected() override
    {}
    void OnDisconnected() override
    {}
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
    void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override
    {}
    void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override
    {}
    void OnEnabledNotificationChanged(
        const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override
    {}
    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>>
        &requestList, const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override
    {}
};

void AnsBranchTest::TestAddSlot(NotificationConstant::SlotType type)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(type);
    slots.push_back(slot);
    ASSERT_EQ(advancedNotificationService_->AddSlots(slots), (int)ERR_OK);
}

/**
 * @tc.number    : AnsBranchTest_222000
 * @tc.name      : PrepareNotificationRequest_1000
 * @tc.desc      : Test PrepareNotificationRequest function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_222000, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);

    req->SetIsAgentNotification(true);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    MockIsVerfyPermisson(false);

    ASSERT_EQ(advancedNotificationService_->PrepareNotificationRequest(req).GetErrCode(), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_223000
 * @tc.name      : PrepareNotificationRequest_2000
 * @tc.desc      : Test PrepareNotificationRequest function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_223000, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);

    req->SetIsAgentNotification(true);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);
    ASSERT_EQ(advancedNotificationService_->PrepareNotificationRequest(req).GetErrCode(), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_224000
 * @tc.name      : Publish_1000
 * @tc.desc      : Test Publish function req is false.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_224000, Function | SmallTest | Level1)
{
    std::string label = "publish's label";
    ASSERT_EQ(advancedNotificationService_->Publish(label, nullptr), ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AnsBranchTest_225000
 * @tc.name      : CancelAsBundle_1000
 * @tc.desc      : Test CancelAsBundle function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_225000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    int32_t notificationId = 1;
    std::string representativeBundle = "RepresentativeBundle";
    int32_t userId = 1;
    int32_t result = ERR_ANS_NON_SYSTEM_APP;
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService_->CancelAsBundle(notificationId, representativeBundle, userId,
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
        ASSERT_EQ(synchronizer->GetResultCode(), result);
    } else {
        ASSERT_EQ(ret, result);
    }
}

/**
 * @tc.number    : AnsBranchTest_22500
 * @tc.name      : CancelAsBundle_1000
 * @tc.desc      : Test CancelAsBundle function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_22500, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    int32_t notificationId = 1;
    std::string representativeBundle = "RepresentativeBundle";
    int32_t userId = 1;
    ASSERT_EQ(advancedNotificationService_->CancelAsBundle(
        notificationId, representativeBundle, userId), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_226000
 * @tc.name      : CancelAsBundle_2000
 * @tc.desc      : Test CancelAsBundle function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_226000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    int32_t notificationId = 1;
    std::string representativeBundle = "RepresentativeBundle";
    int32_t userId = 1;
    int32_t result = ERR_ANS_PERMISSION_DENIED;
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService_->CancelAsBundle(notificationId, representativeBundle, userId,
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
        ASSERT_EQ(synchronizer->GetResultCode(), result);
    } else {
        ASSERT_EQ(ret, result);
    }
}

/**
 * @tc.number    : AnsBranchTest_22600
 * @tc.name      : CancelAsBundle_2000
 * @tc.desc      : Test CancelAsBundle function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_22600, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    int32_t notificationId = 1;
    std::string representativeBundle = "RepresentativeBundle";
    int32_t userId = 1;
    ASSERT_EQ(advancedNotificationService_->CancelAsBundle(
        notificationId, representativeBundle, userId), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_227000
 * @tc.name      : AddSlots_2000
 * @tc.desc      : Test AddSlots function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_227000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::OTHER);
    sptr<NotificationSlot> slot1 = new NotificationSlot(NotificationConstant::OTHER);
    slots.push_back(slot0);
    slots.push_back(slot1);
    ASSERT_EQ(advancedNotificationService_->AddSlots(slots), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_228000
 * @tc.name      : Delete_1000
 * @tc.desc      : Test Delete function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_228000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    const std::string key = "key";
    ASSERT_EQ(advancedNotificationService_->Delete(
        key, NotificationConstant::CANCEL_REASON_DELETE), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_229000
 * @tc.name      : DeleteByBundle_1000
 * @tc.desc      : Test DeleteByBundle function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_229000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    ASSERT_EQ(advancedNotificationService_->DeleteByBundle(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID)), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_230000
 * @tc.name      : DeleteByBundle_2000
 * @tc.desc      : Test DeleteByBundle function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_230000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    ASSERT_EQ(advancedNotificationService_->DeleteByBundle(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID)), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_231000
 * @tc.name      : DeleteAll_1000
 * @tc.desc      : Test DeleteAll function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_231000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    ASSERT_EQ(advancedNotificationService_->DeleteAll(), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_232000
 * @tc.name      : GetSlotsByBundle_1000
 * @tc.desc      : Test GetSlotsByBundle function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_232000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    std::vector<sptr<NotificationSlot>> slots;
    ASSERT_EQ(advancedNotificationService_->GetSlotsByBundle(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), slots), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_233000
 * @tc.name      : GetSlotsByBundle_2000
 * @tc.desc      : Test GetSlotsByBundle function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_233000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    std::vector<sptr<NotificationSlot>> slots;
    ASSERT_EQ(advancedNotificationService_->GetSlotsByBundle(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), slots), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_234000
 * @tc.name      : UpdateSlots_1000
 * @tc.desc      : Test UpdateSlots function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_234000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::OTHER);
    slots.push_back(slot0);
    ASSERT_EQ(advancedNotificationService_->UpdateSlots(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), slots), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_235000
 * @tc.name      : UpdateSlots_1000
 * @tc.desc      : Test UpdateSlots function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_235000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::OTHER);
    slots.push_back(slot0);
    ASSERT_EQ(advancedNotificationService_->UpdateSlots(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), slots), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_236000
 * @tc.name      : SetShowBadgeEnabledForBundle_1000
 * @tc.desc      : Test SetShowBadgeEnabledForBundle function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_236000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    ASSERT_EQ(advancedNotificationService_->SetShowBadgeEnabledForBundle(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), true), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_237000
 * @tc.name      : GetShowBadgeEnabledForBundle_1000
 * @tc.desc      : Test GetShowBadgeEnabledForBundle function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_237000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    int32_t result = ERR_ANS_NON_SYSTEM_APP;
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService_->GetShowBadgeEnabledForBundle(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID),
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
        ASSERT_EQ(synchronizer->GetResultCode(), result);
    } else {
        ASSERT_EQ(ret, result);
    }
}

/**
 * @tc.number    : AnsBranchTest_2370001
 * @tc.name      : GetShowBadgeEnabledForBundle_1000
 * @tc.desc      : Test GetShowBadgeEnabledForBundle function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_2370001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    bool allow = false;
    ASSERT_EQ(advancedNotificationService_->GetShowBadgeEnabledForBundle(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), allow), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_238000
 * @tc.name      : GetShowBadgeEnabledForBundle_2000
 * @tc.desc      : Test GetShowBadgeEnabledForBundle function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_238000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    int32_t result = ERR_ANS_PERMISSION_DENIED;
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService_->GetShowBadgeEnabledForBundle(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID),
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
        ASSERT_EQ(synchronizer->GetResultCode(), result);
    } else {
        ASSERT_EQ(ret, result);
    }
}

/**
 * @tc.number    : AnsBranchTest_2380001
 * @tc.name      : GetShowBadgeEnabledForBundle_2000
 * @tc.desc      : Test GetShowBadgeEnabledForBundle function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_2380001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    bool allow = false;
    ASSERT_EQ(advancedNotificationService_->GetShowBadgeEnabledForBundle(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), allow), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_239000
 * @tc.name      : Subscribe_1000
 * @tc.desc      : Test Subscribe function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_239000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    auto subscriber = new TestAnsSubscriber();
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    ASSERT_EQ(advancedNotificationService_->Subscribe(subscriber->GetImpl(), info, subscriber->subscribedFlags_),
        ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_240000
 * @tc.name      : Subscribe_1000
 * @tc.desc      : Test Subscribe function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_240000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    auto subscriber = new TestAnsSubscriber();
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    ASSERT_EQ(advancedNotificationService_->Subscribe(subscriber->GetImpl(), info, subscriber->subscribedFlags_),
        ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_241000
 * @tc.name      : Unsubscribe_1000
 * @tc.desc      : Test Unsubscribe function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_241000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    auto subscriber = new TestAnsSubscriber();
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    ASSERT_EQ(advancedNotificationService_->Unsubscribe(subscriber->GetImpl(), info), ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SubscribeSelf_279001
 * @tc.require   : issue
 */
HWTEST_F(AnsBranchTest, SubscribeSelf_279001, Function | SmallTest | Level1)
{
    auto res = advancedNotificationService_->SubscribeSelf(nullptr, 1);
    ASSERT_EQ(res, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SubscribeSelf_279002
 * @tc.require   : issue
 */
HWTEST_F(AnsBranchTest, SubscribeSelf_279002, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    auto subscriber = new TestAnsSubscriber();
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    ASSERT_EQ(advancedNotificationService_->SubscribeSelf(subscriber->GetImpl(), subscriber->subscribedFlags_),
        ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : SubscribeSelf_279003
 * @tc.require   : issue
 */
HWTEST_F(AnsBranchTest, SubscribeSelf_279003, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);

    auto subscriber = new TestAnsSubscriber();
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    ASSERT_EQ(advancedNotificationService_->SubscribeSelf(subscriber->GetImpl(), subscriber->subscribedFlags_),
        ERR_OK);
}

/**
 * @tc.number    : AnsBranchTest_242000
 * @tc.name      : GetAllActiveNotifications_1000
 * @tc.desc      : Test GetAllActiveNotifications function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_242000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    int32_t result = ERR_ANS_PERMISSION_DENIED;
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService_->GetAllActiveNotifications(
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
        ASSERT_EQ(synchronizer->GetResultCode(), result);
    } else {
        ASSERT_EQ(ret, result);
    }
}

/**
 * @tc.number    : AnsBranchTest_2420001
 * @tc.name      : GetAllActiveNotifications_1000
 * @tc.desc      : Test GetAllActiveNotifications function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_2420001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    std::vector<sptr<Notification>> allNotifications;
    ASSERT_EQ(advancedNotificationService_->GetAllActiveNotifications(allNotifications), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_243000
 * @tc.name      : GetSpecialActiveNotifications_1000
 * @tc.desc      : Test GetSpecialActiveNotifications function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_243000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    std::vector<std::string> keys;
    std::vector<sptr<Notification>> specialActiveNotifications;
    ASSERT_EQ(advancedNotificationService_->GetSpecialActiveNotifications(
        keys, specialActiveNotifications), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_244000
 * @tc.name      : GetSpecialActiveNotifications_2000
 * @tc.desc      : Test GetSpecialActiveNotifications function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_244000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    std::vector<std::string> keys;
    std::vector<sptr<Notification>> specialActiveNotifications;
    ASSERT_EQ(advancedNotificationService_->GetSpecialActiveNotifications(
        keys, specialActiveNotifications), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_245000
 * @tc.name      : SetNotificationsEnabledForAllBundles_2000
 * @tc.desc      : Test SetNotificationsEnabledForAllBundles function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_245000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForAllBundles(
        std::string(), true), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_246000
 * @tc.name      : SetNotificationsEnabledForAllBundles_1000
 * @tc.desc      : Test SetNotificationsEnabledForAllBundles function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_246000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForAllBundles(
        std::string(), true), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_247000
 * @tc.name      : SetNotificationsEnabledForSpecialBundle_1000
 * @tc.desc      : Test SetNotificationsEnabledForSpecialBundle function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_247000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(
        std::string(), new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), false),
            ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_248000
 * @tc.name      : IsAllowedNotify_1000
 * @tc.desc      : Test IsAllowedNotify function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_248000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    bool allowed = false;
    ASSERT_EQ(advancedNotificationService_->IsAllowedNotify(allowed), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_249000
 * @tc.name      : IsAllowedNotify_2000
 * @tc.desc      : Test IsAllowedNotify function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_249000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    bool allowed = false;
    ASSERT_EQ(advancedNotificationService_->IsAllowedNotify(allowed), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_250000
 * @tc.name      : GetAppTargetBundle_1000
 * @tc.desc      : Test GetAppTargetBundle function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_250000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationBundleOption> targetBundle(nullptr);
    bundleOption->SetBundleName("test");
    ASSERT_EQ(advancedNotificationService_->GetAppTargetBundle(bundleOption, targetBundle), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_251000
 * @tc.name      : IsSpecialBundleAllowedNotify_1000
 * @tc.desc      : Test IsSpecialBundleAllowedNotify function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_251000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    bool allowed = true;
    ASSERT_EQ(advancedNotificationService_->IsSpecialBundleAllowedNotify(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), allowed), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_252000
 * @tc.name      : IsSpecialBundleAllowedNotify_2000
 * @tc.desc      : Test IsSpecialBundleAllowedNotify function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_252000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    bool allowed = true;
    ASSERT_EQ(advancedNotificationService_->IsSpecialBundleAllowedNotify(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), allowed), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_254000
 * @tc.name      : IsSpecialBundleAllowedNotify_4000
 * @tc.desc      : Test IsSpecialBundleAllowedNotify function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_254000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(true);

    MockIsNonBundleName(true);
    bool allowed = true;
    ASSERT_EQ(advancedNotificationService_->IsSpecialBundleAllowedNotify(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), allowed), ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.number    : AnsBranchTest_255000
 * @tc.name      : RemoveNotification_1000
 * @tc.desc      : Test RemoveNotification function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_255000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    int32_t notificationId = 1;
    std::string label = "testRemove";
    auto result = advancedNotificationService_->RemoveNotification(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID),
        notificationId, label, NotificationConstant::CANCEL_REASON_DELETE);
    ASSERT_EQ(result, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_256000
 * @tc.name      : RemoveAllNotifications_1000
 * @tc.desc      : Test RemoveAllNotifications function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_256000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    ASSERT_EQ(advancedNotificationService_->RemoveAllNotifications(bundleOption), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_257000
 * @tc.name      : GetSlotNumAsBundle_1000
 * @tc.desc      : Test GetSlotNumAsBundle function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_257000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    uint64_t num = 1;
    ASSERT_EQ(advancedNotificationService_->GetSlotNumAsBundle(bundleOption, num), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_258000
 * @tc.name      : GetSlotNumAsBundle_2000
 * @tc.desc      : Test GetSlotNumAsBundle function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_258000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    uint64_t num = 1;
    ASSERT_EQ(advancedNotificationService_->GetSlotNumAsBundle(bundleOption, num), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_259000
 * @tc.name      : RemoveGroupByBundle_2000
 * @tc.desc      : Test RemoveGroupByBundle function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_259000, Function | SmallTest | Level1)
{
    MockVerifyNativeToken(false);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    std::string groupName = "group";
    ASSERT_EQ(advancedNotificationService_->RemoveGroupByBundle(bundleOption, groupName), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_260000
 * @tc.name      : SetDoNotDisturbDate_1000
 * @tc.desc      : Test SetDoNotDisturbDate function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_260000, Function | SmallTest | Level1)
{
    MockVerifyNativeToken(false);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
    ASSERT_EQ(advancedNotificationService_->SetDoNotDisturbDate(date), ERR_ANS_NON_SYSTEM_APP);
    ASSERT_EQ(advancedNotificationService_->GetDoNotDisturbDate(date), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_261000
 * @tc.name      : SetDoNotDisturbDate_2000
 * @tc.desc      : Test SetDoNotDisturbDate function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_261000, Function | SmallTest | Level1)
{
    MockVerifyNativeToken(false);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
    ASSERT_EQ(advancedNotificationService_->SetDoNotDisturbDate(date), ERR_ANS_PERMISSION_DENIED);
    ASSERT_EQ(advancedNotificationService_->GetDoNotDisturbDate(date), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_262000
 * @tc.name      : DoesSupportDoNotDisturbMode_1000
 * @tc.desc      : Test DoesSupportDoNotDisturbMode function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_262000, Function | SmallTest | Level1)
{
    MockIsSystemApp(false);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);

    bool doesSupport = true;
    ASSERT_EQ(advancedNotificationService_->DoesSupportDoNotDisturbMode(doesSupport), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_263000
 * @tc.name      : DoesSupportDoNotDisturbMode_2000
 * @tc.desc      : Test DoesSupportDoNotDisturbMode function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_263000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    bool doesSupport = true;
    ASSERT_EQ(advancedNotificationService_->DoesSupportDoNotDisturbMode(doesSupport), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_264000
 * @tc.name      : EnableDistributed_1000
 * @tc.desc      : Test EnableDistributed function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_264000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    bool enabled = true;
    sptr<NotificationBundleOption> bundleOption =
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    ASSERT_EQ(advancedNotificationService_->EnableDistributed(enabled), ERR_ANS_NON_SYSTEM_APP);
    ASSERT_EQ(advancedNotificationService_->EnableDistributedByBundle(bundleOption, enabled), ERR_ANS_NON_SYSTEM_APP);
    ASSERT_EQ(advancedNotificationService_->IsDistributedEnableByBundle(bundleOption, enabled), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_284000
 * @tc.name      : EnableDistributed_2000
 * @tc.desc      : Test EnableDistributed function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_284000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    bool enabled = true;
    sptr<NotificationBundleOption> bundleOption =
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    ASSERT_EQ(advancedNotificationService_->EnableDistributed(enabled), ERR_ANS_PERMISSION_DENIED);
    ASSERT_EQ(advancedNotificationService_->EnableDistributedByBundle(
        bundleOption, enabled), ERR_ANS_PERMISSION_DENIED);
    ASSERT_EQ(advancedNotificationService_->IsDistributedEnableByBundle(
        bundleOption, enabled), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_265000
 * @tc.name      : GetDeviceRemindType_1000
 * @tc.desc      : Test GetDeviceRemindType function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_265000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    int32_t remindType = -1;
    ASSERT_EQ(advancedNotificationService_->GetDeviceRemindType(remindType), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_266000
 * @tc.name      : GetDeviceRemindType_2000
 * @tc.desc      : Test GetDeviceRemindType function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_266000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    int32_t remindType = -1;
    ASSERT_EQ(advancedNotificationService_->GetDeviceRemindType(remindType), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_267000
 * @tc.name      : IsSpecialUserAllowedNotify_1000
 * @tc.desc      : Test IsSpecialUserAllowedNotify function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_267000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    int32_t userId = 3;
    bool allowed = true;
    bool enable = true;
    ASSERT_EQ(advancedNotificationService_->IsSpecialUserAllowedNotify(
        userId, allowed), (int)ERR_ANS_PERMISSION_DENIED);
    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledByUser(
        userId, enable), (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_267100
 * @tc.name      : IsSpecialUserAllowedNotify_1000
 * @tc.desc      : Test IsSpecialUserAllowedNotify function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_267100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    int32_t userId = 3;
    bool allowed = true;
    bool enable = true;
    ASSERT_EQ(advancedNotificationService_->IsSpecialUserAllowedNotify(
        userId, allowed), (int)ERR_ANS_NON_SYSTEM_APP);
    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledByUser(
        userId, enable), (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_268000
 * @tc.name      : SetDoNotDisturbDate_1000
 * @tc.desc      : Test SetDoNotDisturbDate function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_268000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    int32_t userId = 3;
    sptr<NotificationDoNotDisturbDate> date = nullptr;
    ASSERT_EQ(advancedNotificationService_->SetDoNotDisturbDate(userId, date), ERR_ANS_NON_SYSTEM_APP);
    ASSERT_EQ(advancedNotificationService_->GetDoNotDisturbDate(userId, date), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_269000
 * @tc.name      : SetDoNotDisturbDate_2000
 * @tc.desc      : Test SetDoNotDisturbDate function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_269000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    int32_t userId = 3;
    sptr<NotificationDoNotDisturbDate> date = nullptr;
    ASSERT_EQ(advancedNotificationService_->SetDoNotDisturbDate(userId, date), ERR_ANS_PERMISSION_DENIED);
    ASSERT_EQ(advancedNotificationService_->GetDoNotDisturbDate(userId, date), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_270000
 * @tc.name      : SetEnabledForBundleSlot_1000
 * @tc.desc      : Test SetEnabledForBundleSlot function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_270000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    bool enabled = false;
    bool isForceControl = false;
    auto result = advancedNotificationService_->SetEnabledForBundleSlot(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID),
            NotificationConstant::SlotType::SOCIAL_COMMUNICATION, enabled, false);

    ASSERT_EQ(result, ERR_ANS_PERMISSION_DENIED);
    auto result1 = advancedNotificationService_->GetEnabledForBundleSlot(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID),
            NotificationConstant::SlotType::SOCIAL_COMMUNICATION, enabled);
    ASSERT_EQ(result1, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_272000
 * @tc.name      : SetSyncNotificationEnabledWithoutApp_1000
 * @tc.desc      : Test SetSyncNotificationEnabledWithoutApp function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_272000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    int32_t userId = 3;
    bool enabled = true;
    ASSERT_EQ(advancedNotificationService_->SetSyncNotificationEnabledWithoutApp(
        userId, enabled), ERR_ANS_NON_SYSTEM_APP);
    ASSERT_EQ(advancedNotificationService_->GetSyncNotificationEnabledWithoutApp(
        userId, enabled), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_273000
 * @tc.name      : SetSyncNotificationEnabledWithoutApp_2000
 * @tc.desc      : Test SetSyncNotificationEnabledWithoutApp function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_273000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    int32_t userId = 3;
    bool enabled = true;
    ASSERT_EQ(advancedNotificationService_->SetSyncNotificationEnabledWithoutApp(
        userId, enabled), ERR_ANS_PERMISSION_DENIED);
    ASSERT_EQ(advancedNotificationService_->GetSyncNotificationEnabledWithoutApp(
        userId, enabled), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_274000
 * @tc.name      : EnableDistributedByBundle_3000
 * @tc.desc      : Test EnableDistributedByBundle function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_274000, Function | SmallTest | Level1)
{
    MockGetDistributedEnableInApplicationInfo(false, 2);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    bool enabled = true;
    sptr<NotificationBundleOption> bundleOption =
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    ASSERT_EQ(advancedNotificationService_->EnableDistributedByBundle(
        bundleOption, enabled), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AnsBranchTest_275000
 * @tc.name      : EnableDistributedSelf_2000
 * @tc.desc      : Test EnableDistributedSelf function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_275000, Function | SmallTest | Level1)
{
    MockDistributedNotificationEnabled(false);
    MockIsNonBundleName(false);
    bool enabled = true;
    ASSERT_EQ(advancedNotificationService_->EnableDistributedSelf(enabled), (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_276000
 * @tc.name      : IsDistributedEnableByBundle_3000
 * @tc.desc      : Test IsDistributedEnableByBundle function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_276000, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockVerifyNativeToken(true);
    MockGetDistributedEnableInApplicationInfo(true, 2);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(
        TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    bool enabled = false;
    ASSERT_EQ(advancedNotificationService_->IsDistributedEnableByBundle(bundleOption, enabled), ERR_OK);
}

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
/**
 * @tc.number    : AnsBranchTest_277000
 * @tc.name      : DoDistributedPublish_3000
 * @tc.desc      : Test DoDistributedPublish function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_277000, Function | SmallTest | Level1)
{
    MockGetDistributedEnableInApplicationInfo(false, 2);
    MockGetOsAccountLocalIdFromUid(false, 1);
    MockDistributedNotificationEnabled(false);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(
        TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    std::shared_ptr<NotificationRecord> record = nullptr;
    ASSERT_EQ(advancedNotificationService_->DoDistributedPublish(bundleOption, record), ERR_OK);
}

/**
 * @tc.number    : DoDistributedPublish_4000
 * @tc.name      : DoDistributedPublish
 * @tc.desc      : Test DoDistributedPublish function return ERR_ANS_MISSIONPER_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, DoDistributedPublish_4000, Function | SmallTest | Level1)
{
    MockGetDistributedEnableInApplicationInfo(true, 1);
    MockGetOsAccountLocalIdFromUid(false, 2);
    MockDistributedNotificationEnabled(true);
    advancedNotificationService_->EnableDistributed(true);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(
        TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
        int notificationId = 1;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(notificationId);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundleOption);
    ASSERT_EQ(advancedNotificationService_->DoDistributedPublish(bundleOption, record),
        (int)ERR_ANS_DISTRIBUTED_GET_INFO_FAILED);
    auto ret = advancedNotificationService_->DoDistributedDelete(
        "1", "DoDistributedPublish_4000", record->notification);
    ASSERT_EQ(ret, (int)ERR_ANS_DISTRIBUTED_OPERATION_FAILED);
}

/**
 * @tc.number    : AnsBranchTest_278000
 * @tc.name      : GetDistributedEnableInApplicationInfo_3000
 * @tc.desc      : Test GetDistributedEnableInApplicationInfo function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_278000, Function | SmallTest | Level1)
{
    MockGetDistributedEnableInApplicationInfo(false, 2);
    MockGetOsAccountLocalIdFromUid(false, 3);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(
        TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    bool enabled = false;;
    ASSERT_EQ(advancedNotificationService_->GetDistributedEnableInApplicationInfo(
        bundleOption, enabled), ERR_ANS_INVALID_PARAM);
}
#endif

void AnsBranchTest::InitNotificationRecord(std::shared_ptr<NotificationRecord> &record,
    const NotificationLiveViewContent::LiveViewStatus &status)
{
    NotificationRequest notificationRequest;
    notificationRequest.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(status);
    auto content = std::make_shared<NotificationContent>(liveContent);
    notificationRequest.SetContent(content);

    record->request = sptr<NotificationRequest>::MakeSptr(notificationRequest);
    record->notification = new (std::nothrow) Notification(record->request);
}

/**
 * @tc.number    : AnsBranchTest_279000
 * @tc.name      : UpdateNotificationTimerInfo_0001
 * @tc.desc      : Check set update and finish timer when create notification request
 * @tc.require   : issue
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_279000, Function | SmallTest | Level1)
{
    using Status = NotificationLiveViewContent::LiveViewStatus;
    auto record = std::make_shared<NotificationRecord>();
    InitNotificationRecord(record, Status::LIVE_VIEW_CREATE);
    ASSERT_EQ(record->notification->GetFinishTimer(), NotificationConstant::INVALID_TIMER_ID);
    ASSERT_EQ(record->notification->GetUpdateTimer(), NotificationConstant::INVALID_TIMER_ID);
    auto result = advancedNotificationService_->UpdateNotificationTimerInfo(record);
    ASSERT_EQ(result, ERR_OK);
    EXPECT_NE(record->notification->GetFinishTimer(), NotificationConstant::INVALID_TIMER_ID);
    EXPECT_NE(record->notification->GetUpdateTimer(), NotificationConstant::INVALID_TIMER_ID);
}

/**
 * @tc.number    : AnsBranchTest_279001
 * @tc.name      : UpdateNotificationTimerInfo_0002
 * @tc.desc      : Check set update and finish timer when update notification request
 * @tc.require   : issue
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_279001, Function | SmallTest | Level1)
{
    using Status = NotificationLiveViewContent::LiveViewStatus;
    auto record = std::make_shared<NotificationRecord>();
    InitNotificationRecord(record, Status::LIVE_VIEW_INCREMENTAL_UPDATE);
    record->notification->SetUpdateTimer(2);
    record->notification->SetFinishTimer(3);
    auto result = advancedNotificationService_->UpdateNotificationTimerInfo(record);
    ASSERT_EQ(result, ERR_OK);
    /* finish timer not change, but update timer changed */
    EXPECT_NE(record->notification->GetUpdateTimer(), 2);
    ASSERT_EQ(record->notification->GetFinishTimer(), 3);
}

/**
 * @tc.number    : AnsBranchTest_279002
 * @tc.name      : UpdateNotificationTimerInfo_0003
 * @tc.desc      : Check cancel update and finish timer when end notification request
 * @tc.require   : issue
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_279002, Function | SmallTest | Level1)
{
    using Status = NotificationLiveViewContent::LiveViewStatus;
    auto record = std::make_shared<NotificationRecord>();
    InitNotificationRecord(record, Status::LIVE_VIEW_END);
    record->notification->SetUpdateTimer(2);
    record->notification->SetFinishTimer(3);

    auto result = advancedNotificationService_->UpdateNotificationTimerInfo(record);
    ASSERT_EQ(result, ERR_OK);
    /* finish timer not change, but update timer changed */
    ASSERT_EQ(record->notification->GetUpdateTimer(), NotificationConstant::INVALID_TIMER_ID);
    ASSERT_EQ(record->notification->GetFinishTimer(), NotificationConstant::INVALID_TIMER_ID);
}

HWTEST_F(AnsBranchTest, AnsBranchTest_279003, Function | SmallTest | Level1)
{
    auto record = std::make_shared<NotificationRecord>();
    NotificationRequest notificationRequest;
    notificationRequest.SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    auto basicContent = std::make_shared<NotificationNormalContent>();
    auto content = std::make_shared<NotificationContent>(basicContent);
    notificationRequest.SetContent(content);

    record->request = sptr<NotificationRequest>::MakeSptr(notificationRequest);
    record->notification = new (std::nothrow) Notification(record->request);

    auto result = advancedNotificationService_->UpdateNotificationTimerInfo(record);

    ASSERT_EQ(result, ERR_OK);
    /* finish timer not change, but update timer changed */
    ASSERT_EQ(record->notification->GetAutoDeletedTimer(), NotificationConstant::INVALID_TIMER_ID);
}

/**
 * @tc.number    : GetDeviceRemindType_3000
 * @tc.name      : GetDeviceRemindType_3000
 * @tc.desc      : Test GetDeviceRemindType function return ERR_ANS_INVALID_PARAM.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, GetDeviceRemindType_3000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(true);
    MockIsVerfyPermisson(true);
    AdvancedNotificationService ans;
    ans.notificationSvrQueue_ = nullptr;
    int32_t remindType = -1;
    ASSERT_EQ(ans.GetDeviceRemindType(remindType), ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AnsBranchTest_285000
 * @tc.name      : IsNeedSilentInDoNotDisturbMode_1000
 * @tc.desc      : Test IsNeedSilentInDoNotDisturbMode function return ERR_ANS_NON_SYSTEM_APP.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_285000, Function | SmallTest | Level1)
{
    MockIsSystemApp(false);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);

    std::string phoneNumber = "11111111111";
    int32_t callerType = 0;
    ASSERT_EQ(advancedNotificationService_->IsNeedSilentInDoNotDisturbMode(
        phoneNumber, callerType), -1);
}

/**
 * @tc.number    : AnsBranchTest_286000
 * @tc.name      : IsNeedSilentInDoNotDisturbMode_2000
 * @tc.desc      : Test IsNeedSilentInDoNotDisturbMode function return ERR_ANS_PERMISSION_DENIED.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_286000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    std::string phoneNumber = "11111111111";
    int32_t callerType = 0;
    ASSERT_EQ(advancedNotificationService_->IsNeedSilentInDoNotDisturbMode(
        phoneNumber, callerType), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number  : IsNeedSilentInDoNotDisturbMode_3000
 * @tc.name : IsNeedSilentInDoNotDisturbMode
 * @tc.desc : Test IsNeedSilentInDoNotDisturbMode.
 */
HWTEST_F(AnsBranchTest, IsNeedSilentInDoNotDisturbMode_3000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    std::string phoneNumber = "11111111111";
    int32_t callerType = 0;
    int32_t userId = 100;
    ASSERT_EQ(advancedNotificationService_->IsNeedSilentInDoNotDisturbMode(
        phoneNumber, callerType, userId), -1);
}

/**
 * @tc.number  : IsNeedSilentInDoNotDisturbMode_4000
 * @tc.name : IsNeedSilentInDoNotDisturbMode
 * @tc.desc : Test IsNeedSilentInDoNotDisturbMode.
 */
HWTEST_F(AnsBranchTest, IsNeedSilentInDoNotDisturbMode_4000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    std::string phoneNumber = "11111111111";
    int32_t callerType = 0;
    int32_t userId = 100;
    ASSERT_EQ(advancedNotificationService_->IsNeedSilentInDoNotDisturbMode(
        phoneNumber, callerType, userId), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number  : IsNeedSilentInDoNotDisturbMode_5000
 * @tc.name : IsNeedSilentInDoNotDisturbMode
 * @tc.desc : Test IsNeedSilentInDoNotDisturbMode.
 */
HWTEST_F(AnsBranchTest, IsNeedSilentInDoNotDisturbMode_5000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    bool isOsAccountExists = false;
    OHOS::AccountSA::OsAccountManager::IsOsAccountExists(0, isOsAccountExists);
    MockIsOsAccountExists(false);

    std::string phoneNumber = "11111111111";
    int32_t callerType = 0;
    int32_t userId = -99;
    ASSERT_EQ(advancedNotificationService_->IsNeedSilentInDoNotDisturbMode(
        phoneNumber, callerType, userId), ERR_ANS_GET_ACTIVE_USER_FAILED);
    MockIsOsAccountExists(isOsAccountExists);
}

/**
 * @tc.number    : AnsBranchTest_286001
 * @tc.name      : SetCheckConfig
 * @tc.desc      : Test SetCheckConfig function return ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_286001, Function | SmallTest | Level1)
{
    int32_t response = 0;
    std::string requestId = "id";
    std::string key = "key";
    std::string value = "value";
    MockIsVerfyPermisson(false);
    int32_t result = advancedNotificationService_->SetCheckConfig(response, requestId, key, value);
    ASSERT_EQ(result, ERR_ANS_INVALID_PARAM);

    key = "APP_LIVEVIEW_CONFIG";
    result = advancedNotificationService_->SetCheckConfig(response, requestId, key, value);
    ASSERT_EQ(result, ERR_ANS_PERMISSION_DENIED);

    MockIsVerfyPermisson(true);
    result = advancedNotificationService_->SetCheckConfig(0, requestId, key, value);
    ASSERT_EQ(result, ERR_OK);
    result = advancedNotificationService_->SetCheckConfig(6, requestId, key, value);
    ASSERT_EQ(result, ERR_OK);
    result = advancedNotificationService_->SetCheckConfig(10, requestId, key, value);
    ASSERT_EQ(result, ERR_OK);
    result = advancedNotificationService_->SetCheckConfig(11, requestId, key, value);
    ASSERT_EQ(result, ERR_OK);
    result = advancedNotificationService_->SetCheckConfig(7, requestId, key, value);
    ASSERT_EQ(result, ERR_OK);

    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    result = advancedNotificationService_->SetCheckConfig(8, requestId, key, value);
    ASSERT_EQ(result, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AnsBranchTest_286002
 * @tc.name      : SetCheckConfig
 * @tc.desc      : Test SetCheckConfig function return ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_286002, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption();
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL);
    int32_t result = advancedNotificationService_->SetDefaultSlotForBundle(bundle, 5, true, true);
    ASSERT_EQ(result, ERR_ANS_NON_SYSTEM_APP);

    MockIsVerfyPermisson(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    result = advancedNotificationService_->SetDefaultSlotForBundle(bundle, 5, true, true);
    ASSERT_EQ(result, ERR_ANS_PERMISSION_DENIED);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    result = advancedNotificationService_->SetDefaultSlotForBundle(bundle, 5, true, true);
    ASSERT_EQ(result, ERR_ANS_PERMISSION_DENIED);

    MockIsVerfyPermisson(true);
    result = advancedNotificationService_->SetDefaultSlotForBundle(bundle, 5, true, true);
    ASSERT_EQ(result, ERR_ANS_INVALID_BUNDLE);

    bundle->SetBundleName(TEST_DEFUALT_BUNDLE);
    result = advancedNotificationService_->SetDefaultSlotForBundle(bundle, 5, true, true);
    ASSERT_EQ(result, ERR_ANS_INVALID_BUNDLE);

    bundle->SetUid(NON_SYSTEM_APP_UID);
    result = advancedNotificationService_->SetDefaultSlotForBundle(bundle, 5, true, true);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.number : AnsBranchTest_286003
 * @tc.name : GetLiveViewConfig
 * @tc.desc : Test GetLiveViewConfig function return ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_286003, Function | SmallTest | Level1)
{
    std::vector<std::string> bundle_list;

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    auto ret = advancedNotificationService_->GetLiveViewConfig(bundle_list);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    for (int i = 0; i < 80; i++) {
        bundle_list.emplace_back("com.sankuai.hmeituan");
    }

    ret = advancedNotificationService_->GetLiveViewConfig(bundle_list);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number : AnsBranchTest_286004
 * @tc.name : GetLiveViewConfig
 * @tc.desc : Test GetLiveViewConfig function return ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_286004, Function | SmallTest | Level1)
{
    std::vector<std::string> bundle_list;
    for (int i = 0; i < 10; i++) {
        bundle_list.emplace_back("com.sankuai.hmeituan");
    }

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    auto ret = advancedNotificationService_->GetLiveViewConfig(bundle_list);
    ASSERT_EQ(ret, (int)ERR_ANS_PUSH_CHECK_UNREGISTERED);

    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    ret = advancedNotificationService_->GetLiveViewConfig(bundle_list);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    MockIsVerfyPermisson(false);
    ret = advancedNotificationService_->GetLiveViewConfig(bundle_list);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number : AnsBranchTest_286005
 * @tc.name : TriggerLiveViewSwitchCheck
 * @tc.desc : Test TriggerLiveViewSwitchCheck.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_286005, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    advancedNotificationService_->TriggerLiveViewSwitchCheck(0);
}

/**
 * @tc.number : AnsBranchTest_286006
 * @tc.name : InvokeCheckConfig
 * @tc.desc : Test InvokeCheckConfig.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_286006, Function | SmallTest | Level1)
{
    advancedNotificationService_->InvokeCheckConfig(0);
}

/**
 * @tc.number : AnsBranchTest_286007
 * @tc.name : InvockLiveViewSwitchCheck
 * @tc.desc : Test InvockLiveViewSwitchCheck.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_286007, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("com.sankuai.hmeituan", 100);
    std::vector<sptr<NotificationBundleOption>> bundles;
    bundles.emplace_back(bundle);
    advancedNotificationService_->InvockLiveViewSwitchCheck(bundles, 100, 100);
}

/**
 * @tc.number    : AnsBranchTest_287001
 * @tc.name      : SetCheckConfig
 * @tc.desc      : Test SetGeofenceEnabled function return ERR_ANS_SERVICE_NOT_READY.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287001, Function | SmallTest | Level1)
{
    MockVerifyNativeToken(true);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    NotificationPreferences::GetInstance()->preferncesDB_ = nullptr;
    auto result = advancedNotificationService_->SetGeofenceEnabled(false);
    ASSERT_EQ(result, ERR_ANS_SERVICE_NOT_READY);
    bool enabled = false;
    result = advancedNotificationService_->IsGeofenceEnabled(enabled);
    ASSERT_EQ(result, ERR_ANS_SERVICE_NOT_READY);
}

/**
 * @tc.number    : AnsBranchTest_287002
 * @tc.name      : SetCheckConfig
 * @tc.desc      : Test SetGeofenceEnabled function return ERR_ANS_PERMISSION_DENIED.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287002, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);
    auto result = advancedNotificationService_->SetGeofenceEnabled(false);
    ASSERT_EQ(result, ERR_ANS_PERMISSION_DENIED);
    bool enabled = false;
    result = advancedNotificationService_->IsGeofenceEnabled(enabled);
    ASSERT_EQ(result, ERR_ANS_SERVICE_NOT_READY);
}

/**
 * @tc.number    : AnsBranchTest_287004
 * @tc.name      : ClearDelayNotification
 * @tc.desc      : Test ClearDelayNotification function return ERR_ANS_PERMISSION_DENIED.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287004, Function | SmallTest | Level1)
{
    std::vector<std::string> triggerKeys;
    std::vector<int32_t> userIds;
    auto result = advancedNotificationService_->ClearDelayNotification(triggerKeys, userIds);
    ASSERT_EQ(result, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_287005
 * @tc.name      : ClearDelayNotification
 * @tc.desc      : Test ClearDelayNotification function return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287005, Function | SmallTest | Level1)
{
    MockVerifyNativeToken(true);
    MockIsVerfyPermisson(true);
    std::vector<std::string> triggerKeys;
    std::vector<int32_t> userIds;
    auto result = advancedNotificationService_->ClearDelayNotification(triggerKeys, userIds);
    ASSERT_EQ(result, ERR_ANS_INVALID_PARAM);

    triggerKeys.push_back("triggerKey1");
    triggerKeys.push_back("triggerKey2");
    result = advancedNotificationService_->ClearDelayNotification(triggerKeys, userIds);
    ASSERT_EQ(result, ERR_ANS_INVALID_PARAM);

    userIds.push_back(100);
    result = advancedNotificationService_->ClearDelayNotification(triggerKeys, userIds);
    ASSERT_EQ(result, ERR_ANS_INVALID_PARAM);

    userIds.push_back(101);
    result = advancedNotificationService_->ClearDelayNotification(triggerKeys, userIds);
    ASSERT_EQ(result, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.number    : AnsBranchTest_287006
 * @tc.name      : PublishDelayedNotification
 * @tc.desc      : Test PublishDelayedNotification function return ERR_ANS_PERMISSION_DENIED.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287006, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(false);
    std::string triggerKey;
    int32_t userId = 100;
    auto result = advancedNotificationService_->PublishDelayedNotification(triggerKey, userId);
    ASSERT_EQ(result, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number    : AnsBranchTest_287007
 * @tc.name      : PublishDelayedNotification
 * @tc.desc      : Test PublishDelayedNotification function return ERR_ANS_NOTIFICATION_NOT_EXISTS.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287007, Function | SmallTest | Level1)
{
    MockVerifyNativeToken(true);
    MockIsVerfyPermisson(true);
    std::string triggerKey;
    int32_t userId = 100;
    auto result = advancedNotificationService_->PublishDelayedNotification(triggerKey, userId);
    ASSERT_EQ(result, ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.number    : AnsBranchTest_287008
 * @tc.name      : ParseGeofenceNotificationFromDb
 * @tc.desc      : Test ParseGeofenceNotificationFromDb function return ERR_ANS_NOTIFICATION_NOT_EXISTS and ERR_OK.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287008, Function | SmallTest | Level1)
{
    std::string value;
    AdvancedNotificationService::PublishNotificationParameter requestDb;
    auto result = advancedNotificationService_->ParseGeofenceNotificationFromDb(value, requestDb);
    ASSERT_EQ(result, ERR_ANS_NOTIFICATION_NOT_EXISTS);

    value = R"({"name": "test"})";
    result = advancedNotificationService_->ParseGeofenceNotificationFromDb(value, requestDb);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.number    : AnsBranchTest_287009
 * @tc.name      : SetTriggerNotificationRequestToDb
 * @tc.desc      : Test SetTriggerNotificationRequestToDb function return ERR_OK.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287009, Function | SmallTest | Level1)
{
    AdvancedNotificationService::PublishNotificationParameter requestDb;
    requestDb.request = sptr<NotificationRequest>(new (std::nothrow) NotificationRequest());
    auto result = advancedNotificationService_->SetTriggerNotificationRequestToDb(requestDb);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.number    : AnsBranchTest_287010
 * @tc.name      : GetBatchNotificationRequestsFromDb
 * @tc.desc      : Test GetBatchNotificationRequestsFromDb function return ERR_ANS_SERVICE_NOT_READY.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287010, Function | SmallTest | Level1)
{
    std::vector<AdvancedNotificationService::PublishNotificationParameter> requestsDb;
    int32_t userId = -1;
    auto result = advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsDb, userId);
    ASSERT_EQ(result, ERR_ANS_SERVICE_NOT_READY);

    userId = 100;
    result = advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsDb, userId);
    ASSERT_EQ(result, ERR_ANS_SERVICE_NOT_READY);
}

/**
 * @tc.number    : AnsBranchTest_287011
 * @tc.name      : ClearAllGeofenceNotificationRequests
 * @tc.desc      : Test ClearAllGeofenceNotificationRequests function return ERR_OK.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287011, Function | SmallTest | Level1)
{
    int32_t userId = 1000;
    auto result = advancedNotificationService_->ClearAllGeofenceNotificationRequests(userId);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.number    : AnsBranchTest_287012
 * @tc.name      : OnNotifyDelayedNotification
 * @tc.desc      : Test OnNotifyDelayedNotification function return ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287012, Function | SmallTest | Level1)
{
    auto req = new (std::nothrow) NotificationRequest();
    std::shared_ptr<NotificationTrigger> notificationTrigger = std::make_shared<NotificationTrigger>();
    req->SetNotificationTrigger(notificationTrigger);
    AdvancedNotificationService::PublishNotificationParameter parameter;
    parameter.request = req;
    auto result = advancedNotificationService_->OnNotifyDelayedNotification(parameter);
    ASSERT_EQ(result, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AnsBranchTest_287014
 * @tc.name      : OnNotifyDelayedNotificationInner
 * @tc.desc      : Test OnNotifyDelayedNotificationInner function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287014, Function | SmallTest | Level1)
{
    advancedNotificationService_->triggerNotificationList_.clear();
    sptr<NotificationRequest> req(new (std::nothrow) NotificationRequest());
    ASSERT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    req->SetContent(content);
    AdvancedNotificationService::PublishNotificationParameter parameter;
    parameter.request = req;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    auto result = advancedNotificationService_->OnNotifyDelayedNotificationInner(parameter, record);
    ASSERT_NE(result, ERR_OK);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 0);
}

/**
 * @tc.number    : AnsBranchTest_287015
 * @tc.name      : GetDelayedNotificationParameterByTriggerKey
 * @tc.desc      : Test GetDelayedNotificationParameterByTriggerKey function return ERR_ANS_NOTIFICATION_NOT_EXISTS.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287015, Function | SmallTest | Level1)
{
    std::string triggerKey;
    AdvancedNotificationService::PublishNotificationParameter parameter;
    std::shared_ptr<NotificationRecord> record;
    auto result =
        advancedNotificationService_->GetDelayedNotificationParameterByTriggerKey(triggerKey, parameter, record);
    ASSERT_EQ(result, ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.number    : AnsBranchTest_287016
 * @tc.name      : GetDelayedNotificationParameterByTriggerKey
 * @tc.desc      : Test GetDelayedNotificationParameterByTriggerKey function return ERR_OK.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287016, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;
    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetDistributedCollaborate(true);
    reqTwo->SetDistributedHashCode("hashCodeTest");
    record->request = reqTwo;
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    std::string triggerKey = "secure_trigger_live_view_ans_distributedhashCodeTest_";
    AdvancedNotificationService::PublishNotificationParameter parameter;
    std::shared_ptr<NotificationRecord> recordTwo = std::make_shared<NotificationRecord>();
    auto result =
        advancedNotificationService_->GetDelayedNotificationParameterByTriggerKey(triggerKey, parameter, recordTwo);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.number    : AnsBranchTest_287017
 * @tc.name      : GetDelayedNotificationParameterByTriggerKey
 * @tc.desc      : Test GetDelayedNotificationParameterByTriggerKey function return ERR_ANS_NOTIFICATION_NOT_EXISTS.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287017, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_END);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetDistributedCollaborate(true);
    request->SetDistributedHashCode("hashCodeTest");
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = request;
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    record->notification = notificationOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    std::string triggerKey = "secure_trigger_live_view_ans_distributedhashCodeTest";
    AdvancedNotificationService::PublishNotificationParameter parameter;
    std::shared_ptr<NotificationRecord> recordTwo = std::make_shared<NotificationRecord>();
    auto result =
        advancedNotificationService_->GetDelayedNotificationParameterByTriggerKey(triggerKey, parameter, recordTwo);
    ASSERT_EQ(result, ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.number    : AnsBranchTest_287018
 * @tc.name      : UpdateTriggerRequest
 * @tc.desc      : Test UpdateTriggerRequest function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287018, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    advancedNotificationService_->UpdateTriggerRequest(request);
    auto contentTwo = request->GetContent();
    ASSERT_NE(contentTwo, nullptr);
    auto liveViewContentTwo = std::static_pointer_cast<NotificationLiveViewContent>(content->GetNotificationContent());
    ASSERT_NE(liveViewContentTwo, nullptr);
    ASSERT_EQ(
        liveViewContentTwo->GetLiveViewStatus(), NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE);
}

/**
 * @tc.number    : AnsBranchTest_287019
 * @tc.name      : UpdateTriggerRequest
 * @tc.desc      : Test UpdateTriggerRequest function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287019, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<AAFwk::WantParams> extras = std::make_shared<AAFwk::WantParams>();
    liveViewContent->SetExtraInfo(extras);
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_CREATE);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    std::shared_ptr<NotificationTrigger> notificationTrigger = std::make_shared<NotificationTrigger>();
    request->SetNotificationTrigger(notificationTrigger);
    advancedNotificationService_->UpdateTriggerRequest(request);
    auto contentTwo = request->GetContent();
    ASSERT_NE(contentTwo, nullptr);
    auto liveViewContentTwo = std::static_pointer_cast<NotificationLiveViewContent>(content->GetNotificationContent());
    ASSERT_NE(liveViewContentTwo, nullptr);
    ASSERT_EQ(
        liveViewContentTwo->GetLiveViewStatus(), NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
}

/**
 * @tc.number    : AnsBranchTest_287020
 * @tc.name      : UpdateTriggerRequest
 * @tc.desc      : Test UpdateTriggerRequest function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287020, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<AAFwk::WantParams> extras = std::make_shared<AAFwk::WantParams>();
    liveViewContent->SetExtraInfo(extras);
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_END);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    std::shared_ptr<NotificationTrigger> notificationTrigger = std::make_shared<NotificationTrigger>();
    request->SetNotificationTrigger(notificationTrigger);
    advancedNotificationService_->UpdateTriggerRequest(request);
    auto contentTwo = request->GetContent();
    ASSERT_NE(contentTwo, nullptr);
    auto liveViewContentTwo = std::static_pointer_cast<NotificationLiveViewContent>(content->GetNotificationContent());
    ASSERT_NE(liveViewContentTwo, nullptr);
    ASSERT_EQ(
        liveViewContentTwo->GetLiveViewStatus(), NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
}

/**
 * @tc.number    : AnsBranchTest_287021
 * @tc.name      : SetTriggerNotificationRequestToDb
 * @tc.desc      : Test SetTriggerNotificationRequestToDb function return ERR_ANS_SERVICE_NOT_READY.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287021, Function | SmallTest | Level1)
{
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    sptr<NotificationRequest> req(new (std::nothrow) NotificationRequest());
    req->SetContent(content);
    req->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    AdvancedNotificationService::PublishNotificationParameter requestDb;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    requestDb.request = req;
    requestDb.bundleOption = bundleOption;
    auto ret = advancedNotificationService_->SetTriggerNotificationRequestToDb(requestDb);
    ASSERT_EQ(ret, ERR_ANS_SERVICE_NOT_READY);
}

/**
 * @tc.number    : AnsBranchTest_287022
 * @tc.name      : SetTriggerNotificationRequestToDb
 * @tc.desc      : Test SetTriggerNotificationRequestToDb function return ERR_OK.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287022, Function | SmallTest | Level1)
{
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    sptr<NotificationRequest> req(new (std::nothrow) NotificationRequest());
    req->SetContent(content);
    req->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    req->SetAutoDeletedTime(NotificationConstant::NO_DELAY_DELETE_TIME);
    AdvancedNotificationService::PublishNotificationParameter requestDb;
    requestDb.request = req;
    auto ret = advancedNotificationService_->SetTriggerNotificationRequestToDb(requestDb);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.number    : AnsBranchTest_287023
 * @tc.name      : AddToTriggerNotificationList
 * @tc.desc      : Test AddToTriggerNotificationList function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287023, Function | SmallTest | Level1)
{
    advancedNotificationService_->triggerNotificationList_.clear();
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    advancedNotificationService_->AddToTriggerNotificationList(record);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 1);
}

/**
 * @tc.number    : AnsBranchTest_287024
 * @tc.name      : FindGeofenceNotificationRecordByTriggerKey
 * @tc.desc      : Test FindGeofenceNotificationRecordByTriggerKey function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287024, Function | SmallTest | Level1)
{
    std::string triggerKey = "secure_trigger_live_view_ans_distributedhashCodeTest_";
    std::shared_ptr<NotificationRecord> outRecord = nullptr;
    advancedNotificationService_->FindGeofenceNotificationRecordByTriggerKey(triggerKey, outRecord);
    ASSERT_EQ(outRecord, nullptr);

    std::shared_ptr<NotificationRecord> record = nullptr;
    advancedNotificationService_->AddToTriggerNotificationList(record);
    advancedNotificationService_->FindGeofenceNotificationRecordByTriggerKey(triggerKey, outRecord);
    ASSERT_EQ(outRecord, nullptr);
    advancedNotificationService_->triggerNotificationList_.clear();

    record = std::make_shared<NotificationRecord>();
    advancedNotificationService_->AddToTriggerNotificationList(record);
    advancedNotificationService_->FindGeofenceNotificationRecordByTriggerKey(triggerKey, outRecord);
    ASSERT_EQ(outRecord, nullptr);
    advancedNotificationService_->triggerNotificationList_.clear();

    sptr<NotificationRequest> req(new (std::nothrow) NotificationRequest());
    sptr<Notification> notification(new (std::nothrow) Notification(req));
    record->notification = notification;
    advancedNotificationService_->AddToTriggerNotificationList(record);
    advancedNotificationService_->FindGeofenceNotificationRecordByTriggerKey(triggerKey, outRecord);
    ASSERT_EQ(outRecord, nullptr);
    advancedNotificationService_->triggerNotificationList_.clear();

    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetDistributedCollaborate(true);
    reqTwo->SetDistributedHashCode("hashCodeTest");
    record->request = reqTwo;
    advancedNotificationService_->AddToTriggerNotificationList(record);
    advancedNotificationService_->FindGeofenceNotificationRecordByTriggerKey(triggerKey, outRecord);
    ASSERT_NE(outRecord, nullptr);
}

/**
 * @tc.number    : AnsBranchTest_287025
 * @tc.name      : RecoverGeofenceLiveViewFromDb
 * @tc.desc      : Test RecoverGeofenceLiveViewFromDb function return ERR_ANS_SERVICE_NOT_READY.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287025, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationRecord> outRecord = nullptr;
    int32_t userId = 1000;
    auto ret = advancedNotificationService_->RecoverGeofenceLiveViewFromDb(userId);
    ASSERT_EQ(ret, ERR_ANS_SERVICE_NOT_READY);
}

/**
 * @tc.number    : AnsBranchTest_287026
 * @tc.name      : ProcForDeleteGeofenceLiveView
 * @tc.desc      : Test ProcForDeleteGeofenceLiveView function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287026, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    advancedNotificationService_->ProcForDeleteGeofenceLiveView(record);
    ASSERT_EQ(record->request, nullptr);

    sptr<NotificationRequest> req(new (std::nothrow) NotificationRequest());
    record->request = req;
    advancedNotificationService_->ProcForDeleteGeofenceLiveView(record);
    ASSERT_NE(record->request, nullptr);

    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetContent(content);
    reqTwo->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    std::shared_ptr<NotificationRecord> recordTwo = std::make_shared<NotificationRecord>();
    recordTwo->request = reqTwo;
    advancedNotificationService_->ProcForDeleteGeofenceLiveView(record);
    ASSERT_NE(record->request, nullptr);
}

/**
 * @tc.number    : AnsBranchTest_287027
 * @tc.name      : SetGeofenceTriggerTimer
 * @tc.desc      : Test SetGeofenceTriggerTimer function return ERR_ANS_TASK_ERR.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287027, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    sptr<NotificationRequest> req(new (std::nothrow) NotificationRequest());
    record->request = req;
    auto ret = advancedNotificationService_->SetGeofenceTriggerTimer(record);
    ASSERT_EQ(ret, ERR_ANS_TASK_ERR);
}

/**
 * @tc.number    : AnsBranchTest_287028
 * @tc.name      : CancelGeofenceTriggerTimer
 * @tc.desc      : Test CancelGeofenceTriggerTimer function return ERR_ANS_TASK_ERR.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287028, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    sptr<NotificationRequest> req(new (std::nothrow) NotificationRequest());
    record->request = req;
    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    sptr<Notification> notification(new (std::nothrow) Notification(reqTwo));
    record->notification = notification;
    advancedNotificationService_->CancelGeofenceTriggerTimer(record);
    ASSERT_NE(record->request, nullptr);
    ASSERT_EQ(record->request->GetGeofenceTriggerDeadLine(), 0);
}

/**
 * @tc.number    : AnsBranchTest_287029
 * @tc.name      : UpdateTriggerNotification
 * @tc.desc      : Test UpdateTriggerNotification function return ERR_ANS_END_NOTIFICATION.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287029, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> req(new (std::nothrow) NotificationRequest());
    AdvancedNotificationService::PublishNotificationParameter parameter;
    parameter.request = req;
    auto ret = advancedNotificationService_->UpdateTriggerNotification(parameter);
    ASSERT_EQ(ret, ERR_ANS_END_NOTIFICATION);
}

/**
 * @tc.number    : AnsBranchTest_287030
 * @tc.name      : UpdateTriggerNotification
 * @tc.desc      : Test UpdateTriggerNotification function return ERR_ANS_END_NOTIFICATION.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287030, Function | SmallTest | Level1)
{
    bool distributedCollaborate = true;
    std::string hashCode = "hashCodeTest";
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetDistributedCollaborate(distributedCollaborate);
    request->SetDistributedHashCode(hashCode);
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = request;
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    record->notification = notificationOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);

    AdvancedNotificationService::PublishNotificationParameter parameter;
    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetDistributedCollaborate(distributedCollaborate);
    reqTwo->SetDistributedHashCode(hashCode);
    parameter.request = reqTwo;
    auto ret = advancedNotificationService_->UpdateTriggerNotification(parameter);
    ASSERT_EQ(ret, ERR_ANS_END_NOTIFICATION);
}

/**
 * @tc.number    : AnsBranchTest_287031
 * @tc.name      : UpdateTriggerNotification
 * @tc.desc      : Test UpdateTriggerNotification function return ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287031, Function | SmallTest | Level1)
{
    bool distributedCollaborate = true;
    std::string hashCode = "hashCodeTest";
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_CREATE);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetDistributedCollaborate(distributedCollaborate);
    request->SetDistributedHashCode(hashCode);
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = request;
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    record->notification = notificationOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    std::string triggerKey = "secure_trigger_live_view_ans_distributedhashCodeTest";

    AdvancedNotificationService::PublishNotificationParameter parameter;
    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetDistributedCollaborate(distributedCollaborate);
    reqTwo->SetDistributedHashCode(hashCode);
    parameter.request = reqTwo;
    auto ret = advancedNotificationService_->UpdateTriggerNotification(parameter);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AnsBranchTest_287032
 * @tc.name      : UpdateTriggerRecord
 * @tc.desc      : Test UpdateTriggerRecord function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287032, Function | SmallTest | Level1)
{
    advancedNotificationService_->triggerNotificationList_.clear();
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    reqOne->SetDistributedCollaborate(true);
    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    std::shared_ptr<NotificationRecord> oldRecord = std::make_shared<NotificationRecord>();
    std::shared_ptr<NotificationRecord> newRecord = std::make_shared<NotificationRecord>();
    oldRecord->request = reqOne;
    newRecord->request = reqTwo;
    advancedNotificationService_->triggerNotificationList_.push_back(oldRecord);
    advancedNotificationService_->UpdateTriggerRecord(oldRecord, newRecord);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 1);

    reqOne->SetDistributedCollaborate(false);
    advancedNotificationService_->triggerNotificationList_.push_back(oldRecord);
    advancedNotificationService_->UpdateTriggerRecord(oldRecord, newRecord);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.front(), newRecord);
}

/**
 * @tc.number    : AnsBranchTest_287033
 * @tc.name      : CheckGeofenceNotificationRequest
 * @tc.desc      : Test CheckGeofenceNotificationRequest function return ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287033, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> reqOne = nullptr;
    sptr<NotificationBundleOption> bundleOptionOne = new NotificationBundleOption();
    auto ret = advancedNotificationService_->CheckGeofenceNotificationRequest(reqOne, bundleOptionOne);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);

    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    sptr<NotificationBundleOption> bundleOptionTwo = new NotificationBundleOption();
    ret = advancedNotificationService_->CheckGeofenceNotificationRequest(reqTwo, bundleOptionTwo);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);

    sptr<NotificationRequest> reqThree(new (std::nothrow) NotificationRequest());
    std::shared_ptr<NotificationTrigger> notificationTrigger = std::make_shared<NotificationTrigger>();
    reqThree->SetNotificationTrigger(notificationTrigger);
    sptr<NotificationBundleOption> bundleOptionThree = nullptr;
    ret = advancedNotificationService_->CheckGeofenceNotificationRequest(reqThree, bundleOptionThree);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AnsBranchTest_287034
 * @tc.name      : RemoveTriggerNotificationListByTriggerKey
 * @tc.desc      : Test RemoveTriggerNotificationListByTriggerKey function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287034, Function | SmallTest | Level1)
{
    advancedNotificationService_->triggerNotificationList_.clear();
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    reqOne->SetDistributedCollaborate(true);
    reqOne->SetDistributedHashCode("hashCodeTest");
    record->request = reqOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    std::string triggerKeyOne = "testKey";
    advancedNotificationService_->RemoveTriggerNotificationListByTriggerKey(triggerKeyOne);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 1);
    std::string triggerKeyTwo = "secure_trigger_live_view_ans_distributedhashCodeTest_";
    advancedNotificationService_->RemoveTriggerNotificationListByTriggerKey(triggerKeyTwo);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 0);
}

/**
 * @tc.number    : AnsBranchTest_287035
 * @tc.name      : CheckTriggerNotificationRequest
 * @tc.desc      : Test CheckTriggerNotificationRequest function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287035, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    auto ret = advancedNotificationService_->CheckTriggerNotificationRequest(reqOne);
    ASSERT_EQ(ret, ERR_OK);

    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContentOne = std::make_shared<NotificationLiveViewContent>();
    liveViewContentOne->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_CREATE);
    std::shared_ptr<NotificationContent> contentOne = std::make_shared<NotificationContent>(liveViewContentOne);
    reqTwo->SetContent(contentOne);
    ret = advancedNotificationService_->CheckTriggerNotificationRequest(reqTwo);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);

    sptr<NotificationRequest> reqThree(new (std::nothrow) NotificationRequest());
    reqThree->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContentTwo = std::make_shared<NotificationLiveViewContent>();
    liveViewContentTwo->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_END);
    std::shared_ptr<NotificationContent> contentTwo = std::make_shared<NotificationContent>(liveViewContentTwo);
    reqThree->SetContent(contentTwo);
    ret = advancedNotificationService_->CheckTriggerNotificationRequest(reqThree);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);

    sptr<NotificationRequest> reqFour(new (std::nothrow) NotificationRequest());
    std::shared_ptr<NotificationTrigger> notificationTriggerOne = std::make_shared<NotificationTrigger>();
    reqFour->SetNotificationTrigger(notificationTriggerOne);
    ret = advancedNotificationService_->CheckTriggerNotificationRequest(reqFour);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);

    sptr<NotificationRequest> reqFive(new (std::nothrow) NotificationRequest());
    reqFive->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContentThree = std::make_shared<NotificationLiveViewContent>();
    liveViewContentThree->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_END);
    std::shared_ptr<NotificationContent> contentThree = std::make_shared<NotificationContent>(liveViewContentThree);
    reqFive->SetContent(contentThree);
    std::shared_ptr<NotificationTrigger> notificationTriggerTwo = std::make_shared<NotificationTrigger>();
    reqFive->SetNotificationTrigger(notificationTriggerTwo);
    ret = advancedNotificationService_->CheckTriggerNotificationRequest(reqFive);
    ASSERT_EQ(ret, ERR_OK);

    sptr<NotificationRequest> reqSix(new (std::nothrow) NotificationRequest());
    reqSix->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContentFour = std::make_shared<NotificationLiveViewContent>();
    liveViewContentFour->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_CREATE);
    std::shared_ptr<NotificationContent> contentFour = std::make_shared<NotificationContent>(liveViewContentFour);
    reqSix->SetContent(contentFour);
    std::shared_ptr<NotificationTrigger> notificationTriggerThree = std::make_shared<NotificationTrigger>();
    reqSix->SetNotificationTrigger(notificationTriggerThree);
    ret = advancedNotificationService_->CheckTriggerNotificationRequest(reqSix);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.number    : AnsBranchTest_287036
 * @tc.name      : TriggerNotificationRecordFilter
 * @tc.desc      : Test TriggerNotificationRecordFilter function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287036, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationRecord> record = nullptr;
    auto ret = advancedNotificationService_->TriggerNotificationRecordFilter(record);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);

    record = std::make_shared<NotificationRecord>();
    ret = advancedNotificationService_->TriggerNotificationRecordFilter(record);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);

    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    record->request = reqOne;
    ret = advancedNotificationService_->TriggerNotificationRecordFilter(record);
    ASSERT_EQ(ret, ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.number    : AnsBranchTest_287037
 * @tc.name      : TriggerNotificationRecordFilter
 * @tc.desc      : Test TriggerNotificationRecordFilter function return ERR_OK.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287037, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> req(new (std::nothrow) NotificationRequest());
    sptr<Notification> notification(new (std::nothrow) Notification(req));
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notification;

    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    record->request = reqTwo;
    advancedNotificationService_->AddToTriggerNotificationList(record);

    sptr<NotificationRequest> reqThree(new (std::nothrow) NotificationRequest());
    std::shared_ptr<NotificationRecord> recordOne = std::make_shared<NotificationRecord>();
    recordOne->request = reqThree;
    auto ret = advancedNotificationService_->TriggerNotificationRecordFilter(recordOne);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.number    : AnsBranchTest_287038
 * @tc.name      : ExecuteCancelGroupCancelFromTriggerNotificationList
 * @tc.desc      : Test ExecuteCancelGroupCancelFromTriggerNotificationList function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287038, Function | SmallTest | Level1)
{
    advancedNotificationService_->triggerNotificationList_.clear();
    sptr<NotificationBundleOption> bundleOptionOne = new NotificationBundleOption();
    bundleOptionOne->SetBundleName("testName");
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notification(new (std::nothrow) Notification(reqOne));
    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetGroupName("groupName");
    record->bundleOption = bundleOptionOne;
    record->notification = notification;
    record->request = reqTwo;
    advancedNotificationService_->AddToTriggerNotificationList(record);

    sptr<NotificationBundleOption> bundleOptionTwo = new NotificationBundleOption();
    std::string groupName = "groupName";
    advancedNotificationService_->ExecuteCancelGroupCancelFromTriggerNotificationList(bundleOptionTwo, groupName);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 1);

    bundleOptionTwo->SetBundleName("testName");
    advancedNotificationService_->ExecuteCancelGroupCancelFromTriggerNotificationList(bundleOptionTwo, groupName);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 0);
}

/**
 * @tc.number    : AnsBranchTest_287039
 * @tc.name      : RemoveFromTriggerNotificationList
 * @tc.desc      : Test RemoveFromTriggerNotificationList function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287039, Function | SmallTest | Level1)
{
    advancedNotificationService_->triggerNotificationList_.clear();
    sptr<NotificationBundleOption> bundleOptionOne = new NotificationBundleOption();
    bundleOptionOne->SetBundleName("testName");
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notification(new (std::nothrow) Notification(reqOne));
    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetGroupName("groupName");
    record->bundleOption = bundleOptionOne;
    record->notification = notification;
    record->request = reqTwo;
    advancedNotificationService_->AddToTriggerNotificationList(record);

    sptr<NotificationBundleOption> bundleOptionTwo = new NotificationBundleOption();
    NotificationKey notificationKey;
    notificationKey.id = -1;
    notificationKey.label = "";
    advancedNotificationService_->RemoveFromTriggerNotificationList(bundleOptionTwo, notificationKey);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 1);

    notificationKey.id = 0;
    notificationKey.label = "";
    bundleOptionTwo->SetBundleName("testName");
    advancedNotificationService_->RemoveFromTriggerNotificationList(bundleOptionTwo, notificationKey);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 0);
}

/**
 * @tc.number    : AnsBranchTest_287040
 * @tc.name      : CheckSwitchStatus
 * @tc.desc      : Test CheckSwitchStatus function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287040, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = nullptr;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    auto ret = advancedNotificationService_->CheckSwitchStatus(request, bundleOption);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);

    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<NotificationBundleOption> bundleOptionOne = nullptr;
    ret = advancedNotificationService_->CheckSwitchStatus(reqOne, bundleOptionOne);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);

    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    sptr<NotificationBundleOption> bundleOptionTwo = new NotificationBundleOption();
    ret = advancedNotificationService_->CheckSwitchStatus(reqTwo, bundleOptionTwo);
    ASSERT_EQ(ret, ERR_ANS_SERVICE_NOT_READY);
}

/**
 * @tc.number    : AnsBranchTest_287041
 * @tc.name      : CheckGeofenceNotificationRequestLiveViewStatus
 * @tc.desc      : Test CheckGeofenceNotificationRequestLiveViewStatus function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287041, Function | SmallTest | Level1)
{
    advancedNotificationService_->triggerNotificationList_.clear();
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    auto ret = advancedNotificationService_->CheckGeofenceNotificationRequestLiveViewStatus(reqOne);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);

    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContentOne = std::make_shared<NotificationLiveViewContent>();
    liveViewContentOne->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_CREATE);
    std::shared_ptr<NotificationContent> contentOne = std::make_shared<NotificationContent>(liveViewContentOne);
    reqTwo->SetContent(contentOne);
    ret = advancedNotificationService_->CheckGeofenceNotificationRequestLiveViewStatus(reqTwo);
    ASSERT_EQ(ret, ERR_OK);

    sptr<NotificationRequest> reqThree(new (std::nothrow) NotificationRequest());
    reqThree->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContentTwo = std::make_shared<NotificationLiveViewContent>();
    liveViewContentTwo->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_END);
    std::shared_ptr<NotificationContent> contentTwo = std::make_shared<NotificationContent>(liveViewContentTwo);
    reqThree->SetContent(contentTwo);
    ret = advancedNotificationService_->CheckGeofenceNotificationRequestLiveViewStatus(reqThree);
    ASSERT_EQ(ret, ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.number    : AnsBranchTest_287042
 * @tc.name      : CheckLiveViewPendingCreateLiveViewStatus
 * @tc.desc      : Test CheckLiveViewPendingCreateLiveViewStatus function return ERR_OK.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287042, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    ASSERT_NE(reqOne, nullptr);
    auto ret = advancedNotificationService_->CheckLiveViewPendingCreateLiveViewStatus(reqOne);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.number    : AnsBranchTest_287043
 * @tc.name      : CheckLiveViewPendingCreateLiveViewStatus
 * @tc.desc      : Test CheckLiveViewPendingCreateLiveViewStatus function return ERR_ANS_REPEAT_CREATE.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287043, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;
    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetDistributedCollaborate(true);
    reqTwo->SetDistributedHashCode("hashCodeTest");
    record->request = reqTwo;
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    sptr<NotificationRequest> reqThree(new (std::nothrow) NotificationRequest());
    reqThree->SetDistributedCollaborate(true);
    reqThree->SetDistributedHashCode("hashCodeTest");
    auto ret = advancedNotificationService_->CheckLiveViewPendingCreateLiveViewStatus(reqThree);
    ASSERT_EQ(ret, ERR_ANS_REPEAT_CREATE);
}

/**
 * @tc.number    : AnsBranchTest_287044
 * @tc.name      : CheckLiveViewPendingCreateLiveViewStatus
 * @tc.desc      : Test CheckLiveViewPendingCreateLiveViewStatus function return ERR_ANS_REPEAT_CREATE.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287044, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;
    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetDistributedCollaborate(true);
    reqTwo->SetDistributedHashCode("hashCodeTest");
    record->request = reqTwo;
    advancedNotificationService_->notificationList_.push_back(record);
    sptr<NotificationRequest> reqThree(new (std::nothrow) NotificationRequest());
    reqThree->SetDistributedCollaborate(true);
    reqThree->SetDistributedHashCode("hashCodeTest");
    auto ret = advancedNotificationService_->CheckLiveViewPendingCreateLiveViewStatus(reqThree);
    ASSERT_EQ(ret, ERR_ANS_REPEAT_CREATE);
}

/**
 * @tc.number    : AnsBranchTest_287045
 * @tc.name      : CheckLiveViewPendingEndLiveViewStatus
 * @tc.desc      : Test CheckLiveViewPendingEndLiveViewStatus function return ERR_ANS_NOTIFICATION_NOT_EXISTS.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287045, Function | SmallTest | Level1)
{
    advancedNotificationService_->triggerNotificationList_.clear();
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    auto ret = advancedNotificationService_->CheckLiveViewPendingEndLiveViewStatus(reqOne);
    ASSERT_EQ(ret, ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.number    : AnsBranchTest_287046
 * @tc.name      : CheckLiveViewPendingEndLiveViewStatus
 * @tc.desc      : Test CheckLiveViewPendingEndLiveViewStatus function return ERR_OK.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287046, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;
    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetDistributedCollaborate(true);
    reqTwo->SetDistributedHashCode("hashCodeTest");
    record->request = reqTwo;
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    sptr<NotificationRequest> reqThree(new (std::nothrow) NotificationRequest());
    reqThree->SetDistributedCollaborate(true);
    reqThree->SetDistributedHashCode("hashCodeTest");
    auto ret = advancedNotificationService_->CheckLiveViewPendingEndLiveViewStatus(reqThree);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.number    : AnsBranchTest_287047
 * @tc.name      : CheckLiveViewPendingEndLiveViewStatus
 * @tc.desc      : Test CheckLiveViewPendingEndLiveViewStatus function return ERR_ANS_END_NOTIFICATION.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287047, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;

    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_END);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    reqTwo->SetContent(content);
    reqTwo->SetDistributedCollaborate(true);
    reqTwo->SetDistributedHashCode("hashCodeTest");
    record->request = reqTwo;

    advancedNotificationService_->triggerNotificationList_.push_back(record);
    sptr<NotificationRequest> reqThree(new (std::nothrow) NotificationRequest());
    reqThree->SetDistributedCollaborate(true);
    reqThree->SetDistributedHashCode("hashCodeTest");
    auto ret = advancedNotificationService_->CheckLiveViewPendingEndLiveViewStatus(reqThree);
    ASSERT_EQ(ret, ERR_ANS_END_NOTIFICATION);
}

/**
 * @tc.number    : AnsBranchTest_287048
 * @tc.name      : CheckLiveViewPendingEndLiveViewStatus
 * @tc.desc      : Test CheckLiveViewPendingEndLiveViewStatus function return ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287048, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;

    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    reqTwo->SetContent(content);
    reqTwo->SetDistributedCollaborate(true);
    reqTwo->SetDistributedHashCode("hashCodeTest");
    record->request = reqTwo;

    advancedNotificationService_->triggerNotificationList_.push_back(record);
    sptr<NotificationRequest> reqThree(new (std::nothrow) NotificationRequest());
    reqThree->SetDistributedCollaborate(true);
    reqThree->SetDistributedHashCode("hashCodeTest");
    auto ret = advancedNotificationService_->CheckLiveViewPendingEndLiveViewStatus(reqThree);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AnsBranchTest_287049
 * @tc.name      : CheckLiveViewPendingEndLiveViewStatus
 * @tc.desc      : Test CheckLiveViewPendingEndLiveViewStatus function return ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287049, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;

    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    reqTwo->SetContent(content);
    reqTwo->SetDistributedCollaborate(true);
    reqTwo->SetDistributedHashCode("hashCodeTest");
    record->request = reqTwo;

    advancedNotificationService_->notificationList_.push_back(record);
    sptr<NotificationRequest> reqThree(new (std::nothrow) NotificationRequest());
    reqThree->SetDistributedCollaborate(true);
    reqThree->SetDistributedHashCode("hashCodeTest");
    auto ret = advancedNotificationService_->CheckLiveViewPendingEndLiveViewStatus(reqThree);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AnsBranchTest_287050
 * @tc.name      : CheckLiveViewPendingEndLiveViewStatus
 * @tc.desc      : Test CheckLiveViewPendingEndLiveViewStatus function return ERR_ANS_END_NOTIFICATION.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287050, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;

    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    reqTwo->SetContent(content);
    reqTwo->SetDistributedCollaborate(true);
    reqTwo->SetDistributedHashCode("hashCodeTest");
    record->request = reqTwo;

    advancedNotificationService_->notificationList_.push_back(record);
    sptr<NotificationRequest> reqThree(new (std::nothrow) NotificationRequest());
    reqThree->SetDistributedCollaborate(true);
    reqThree->SetDistributedHashCode("hashCodeTest");
    auto ret = advancedNotificationService_->CheckLiveViewPendingEndLiveViewStatus(reqThree);
    ASSERT_EQ(ret, ERR_ANS_END_NOTIFICATION);
}

/**
 * @tc.number    : AnsBranchTest_287051
 * @tc.name      : CheckLiveViewPendingEndLiveViewStatus
 * @tc.desc      : Test CheckLiveViewPendingEndLiveViewStatus function return ERR_OK.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287051, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;

    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetDistributedCollaborate(true);
    reqTwo->SetDistributedHashCode("hashCodeTest");
    record->request = reqTwo;

    advancedNotificationService_->notificationList_.push_back(record);
    sptr<NotificationRequest> reqThree(new (std::nothrow) NotificationRequest());
    reqThree->SetDistributedCollaborate(true);
    reqThree->SetDistributedHashCode("hashCodeTest");
    auto ret = advancedNotificationService_->CheckLiveViewPendingEndLiveViewStatus(reqThree);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.number    : AnsBranchTest_287052
 * @tc.name      : DeleteAllByUserStoppedFromTriggerNotificationList
 * @tc.desc      : Test DeleteAllByUserStoppedFromTriggerNotificationList function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287052, Function | SmallTest | Level1)
{
    advancedNotificationService_->triggerNotificationList_.clear();
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    notificationOne->SetKey("key");
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    std::string key = "";
    int32_t userId = 100;
    advancedNotificationService_->DeleteAllByUserStoppedFromTriggerNotificationList(key, userId);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 1);
    key = "key";
    advancedNotificationService_->DeleteAllByUserStoppedFromTriggerNotificationList(key, userId);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 1);
}

/**
 * @tc.number    : AnsBranchTest_287053
 * @tc.name      : DeleteAllByUserStoppedFromTriggerNotificationList
 * @tc.desc      : Test DeleteAllByUserStoppedFromTriggerNotificationList function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287053, Function | SmallTest | Level1)
{
    advancedNotificationService_->triggerNotificationList_.clear();
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    int32_t userId = 100;
    reqOne->SetCreatorUserId(userId);
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    std::string key = "key";
    notificationOne->SetKey(key);
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    advancedNotificationService_->DeleteAllByUserStoppedFromTriggerNotificationList(key, userId);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 0);
}

/**
 * @tc.number    : AnsBranchTest_287054
 * @tc.name      : DeleteAllByUserStoppedFromTriggerNotificationList
 * @tc.desc      : Test DeleteAllByUserStoppedFromTriggerNotificationList function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287054, Function | SmallTest | Level1)
{
    advancedNotificationService_->triggerNotificationList_.clear();
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    int32_t creatorUserId = 0;
    reqOne->SetCreatorUserId(creatorUserId);
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    std::string key = "key";
    notificationOne->SetKey(key);
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    int32_t userId = 100;
    advancedNotificationService_->DeleteAllByUserStoppedFromTriggerNotificationList(key, userId);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 0);
}

/**
 * @tc.number    : AnsBranchTest_287055
 * @tc.name      : ExecuteRemoveNotificationFromTriggerNotificationList
 * @tc.desc      : Test ExecuteRemoveNotificationFromTriggerNotificationList function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287055, Function | SmallTest | Level1)
{
    advancedNotificationService_->triggerNotificationList_.clear();
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    int32_t notificationId = 1;
    std::string label = "label";
    reqOne->SetNotificationId(notificationId);
    reqOne->SetLabel(label);
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    sptr<NotificationBundleOption> bundleOptionOne = new NotificationBundleOption();
    std::string bundleName = "bundleName";
    int32_t uid = 100;
    bundleOptionOne->SetBundleName(bundleName);
    bundleOptionOne->SetUid(uid);
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;
    record->bundleOption = bundleOptionOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);

    sptr<NotificationBundleOption> bundle = new NotificationBundleOption();
    int32_t id = 0;
    std::string labelTest = "labelTest";
    advancedNotificationService_->ExecuteRemoveNotificationFromTriggerNotificationList(bundle, id, labelTest);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 1);

    bundle->SetBundleName(bundleName);
    advancedNotificationService_->ExecuteRemoveNotificationFromTriggerNotificationList(bundle, id, labelTest);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 1);

    bundle->SetUid(uid);
    advancedNotificationService_->ExecuteRemoveNotificationFromTriggerNotificationList(bundle, id, labelTest);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 1);

    id = 1;
    advancedNotificationService_->ExecuteRemoveNotificationFromTriggerNotificationList(bundle, id, labelTest);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 1);

    labelTest = label;
    advancedNotificationService_->ExecuteRemoveNotificationFromTriggerNotificationList(bundle, id, labelTest);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 0);
}

/**
 * @tc.number    : AnsBranchTest_287056
 * @tc.name      : RemoveGroupByBundleFromTriggerNotificationList
 * @tc.desc      : Test RemoveGroupByBundleFromTriggerNotificationList function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287056, Function | SmallTest | Level1)
{
    advancedNotificationService_->triggerNotificationList_.clear();
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    std::string groupName = "groupName";
    reqOne->SetGroupName(groupName);
    sptr<NotificationBundleOption> bundleOptionOne = new NotificationBundleOption();
    std::string bundleName = "bundleName";
    int32_t uid = 100;
    bundleOptionOne->SetBundleName(bundleName);
    bundleOptionOne->SetUid(uid);
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = reqOne;
    record->bundleOption = bundleOptionOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);

    sptr<NotificationBundleOption> bundle = new NotificationBundleOption();
    std::string groupNameTest = "name";
    advancedNotificationService_->RemoveGroupByBundleFromTriggerNotificationList(bundle, groupNameTest);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 1);

    bundle->SetBundleName(bundleName);
    advancedNotificationService_->RemoveGroupByBundleFromTriggerNotificationList(bundle, groupNameTest);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 1);

    bundle->SetUid(uid);
    advancedNotificationService_->RemoveGroupByBundleFromTriggerNotificationList(bundle, groupNameTest);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 1);

    groupNameTest = groupName;
    advancedNotificationService_->RemoveGroupByBundleFromTriggerNotificationList(bundle, groupNameTest);
    ASSERT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 0);
}

/**
 * @tc.number    : AnsBranchTest_287057
 * @tc.name      : GeneratePublishNotificationParameter
 * @tc.desc      : Test GeneratePublishNotificationParameter function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287057, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> req(new (std::nothrow) NotificationRequest());
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool isUpdateByOwner = false;
    AdvancedNotificationService::PublishNotificationParameter parameter;
    advancedNotificationService_->GeneratePublishNotificationParameter(req, bundleOption, isUpdateByOwner, parameter);
    ASSERT_EQ(parameter.request, req);
    ASSERT_EQ(parameter.bundleOption, bundleOption);
    ASSERT_EQ(parameter.isUpdateByOwner, isUpdateByOwner);
}

/**
 * @tc.number    : AnsBranchTest_287058
 * @tc.name      : IsGeofenceNotificationRequest
 * @tc.desc      : Test IsGeofenceNotificationRequest function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287058, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> reqOne = nullptr;
    auto ret = advancedNotificationService_->IsGeofenceNotificationRequest(reqOne);
    ASSERT_EQ(ret, false);

    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    ret = advancedNotificationService_->IsGeofenceNotificationRequest(reqTwo);
    ASSERT_EQ(ret, false);

    sptr<NotificationRequest> reqThree(new (std::nothrow) NotificationRequest());
    reqThree->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_CREATE);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    reqThree->SetContent(content);
    ret = advancedNotificationService_->IsGeofenceNotificationRequest(reqThree);
    ASSERT_EQ(ret, true);
}

/**
 * @tc.number    : AnsBranchTest_287059
 * @tc.name      : IsExistsGeofence
 * @tc.desc      : Test IsExistsGeofence function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287059, Function | SmallTest | Level1)
{
    advancedNotificationService_->triggerNotificationList_.clear();
    sptr<NotificationRequest> reqOne = nullptr;
    auto ret = advancedNotificationService_->IsExistsGeofence(reqOne);
    ASSERT_EQ(ret, false);

    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    ret = advancedNotificationService_->IsExistsGeofence(reqTwo);
    ASSERT_EQ(ret, false);

    std::shared_ptr<NotificationRecord> record = nullptr;
    advancedNotificationService_->AddToTriggerNotificationList(record);
    ret = advancedNotificationService_->IsExistsGeofence(reqTwo);
    ASSERT_EQ(ret, false);
    advancedNotificationService_->triggerNotificationList_.clear();

    record = std::make_shared<NotificationRecord>();
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    ret = advancedNotificationService_->IsExistsGeofence(reqTwo);
    ASSERT_EQ(ret, false);
    advancedNotificationService_->triggerNotificationList_.clear();

    sptr<NotificationRequest> reqThree(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqThree));
    record->notification = notificationOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    ret = advancedNotificationService_->IsExistsGeofence(reqTwo);
    ASSERT_EQ(ret, false);
    advancedNotificationService_->triggerNotificationList_.clear();

    sptr<NotificationRequest> reqFour(new (std::nothrow) NotificationRequest());
    record->request = reqFour;
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    ret = advancedNotificationService_->IsExistsGeofence(reqTwo);
    ASSERT_EQ(ret, true);
}

/**
 * @tc.number    : AnsBranchTest_287060
 * @tc.name      : FindGeofenceNotificationRecordByKey
 * @tc.desc      : Test FindGeofenceNotificationRecordByKey function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287060, Function | SmallTest | Level1)
{
    std::string triggerKey = "secure_live_view_ans_distributedhashCodeTest";
    std::vector<std::shared_ptr<NotificationRecord>> outRecordVector;
    advancedNotificationService_->FindGeofenceNotificationRecordByKey(triggerKey, outRecordVector);
    ASSERT_EQ(outRecordVector.size(), 0);

    std::shared_ptr<NotificationRecord> record = nullptr;
    advancedNotificationService_->AddToTriggerNotificationList(record);
    advancedNotificationService_->FindGeofenceNotificationRecordByKey(triggerKey, outRecordVector);
    ASSERT_EQ(outRecordVector.size(), 0);
    advancedNotificationService_->triggerNotificationList_.clear();

    record = std::make_shared<NotificationRecord>();
    advancedNotificationService_->AddToTriggerNotificationList(record);
    advancedNotificationService_->FindGeofenceNotificationRecordByKey(triggerKey, outRecordVector);
    ASSERT_EQ(outRecordVector.size(), 0);
    advancedNotificationService_->triggerNotificationList_.clear();

    sptr<NotificationRequest> req(new (std::nothrow) NotificationRequest());
    sptr<Notification> notification(new (std::nothrow) Notification(req));
    record->notification = notification;
    advancedNotificationService_->AddToTriggerNotificationList(record);
    advancedNotificationService_->FindGeofenceNotificationRecordByKey(triggerKey, outRecordVector);
    ASSERT_EQ(outRecordVector.size(), 0);
    advancedNotificationService_->triggerNotificationList_.clear();

    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetDistributedCollaborate(true);
    reqTwo->SetDistributedHashCode("hashCodeTest");
    record->request = reqTwo;
    advancedNotificationService_->AddToTriggerNotificationList(record);
    advancedNotificationService_->FindGeofenceNotificationRecordByKey(triggerKey, outRecordVector);
    ASSERT_EQ(outRecordVector.size(), 1);
}

/**
 * @tc.number    : AnsBranchTest_287061
 * @tc.name      : FindNotificationRecordByKey
 * @tc.desc      : Test FindNotificationRecordByKey function.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287061, Function | SmallTest | Level1)
{
    std::string triggerKey = "secure_live_view_ans_distributedhashCodeTest";
    std::shared_ptr<NotificationRecord> outRecord = nullptr;
    advancedNotificationService_->FindNotificationRecordByKey(triggerKey, outRecord);
    ASSERT_EQ(outRecord, nullptr);

    std::shared_ptr<NotificationRecord> record = nullptr;
    advancedNotificationService_->AddToNotificationList(record);
    advancedNotificationService_->FindNotificationRecordByKey(triggerKey, outRecord);
    ASSERT_EQ(outRecord, nullptr);
    advancedNotificationService_->notificationList_.clear();

    record = std::make_shared<NotificationRecord>();
    advancedNotificationService_->AddToNotificationList(record);
    advancedNotificationService_->FindNotificationRecordByKey(triggerKey, outRecord);
    ASSERT_EQ(outRecord, nullptr);
    advancedNotificationService_->notificationList_.clear();

    sptr<NotificationRequest> req(new (std::nothrow) NotificationRequest());
    sptr<Notification> notification(new (std::nothrow) Notification(req));
    record->notification = notification;
    advancedNotificationService_->AddToNotificationList(record);
    advancedNotificationService_->FindNotificationRecordByKey(triggerKey, outRecord);
    ASSERT_EQ(outRecord, nullptr);
    advancedNotificationService_->notificationList_.clear();

    sptr<NotificationRequest> reqTwo(new (std::nothrow) NotificationRequest());
    reqTwo->SetDistributedCollaborate(true);
    reqTwo->SetDistributedHashCode("hashCodeTest");
    record->request = reqTwo;
    advancedNotificationService_->AddToNotificationList(record);
    advancedNotificationService_->FindNotificationRecordByKey(triggerKey, outRecord);
    ASSERT_NE(outRecord, nullptr);
}

/**
 * @tc.number    : AnsBranchTest_287062
 * @tc.name      : IsGeofenceEnabled
 * @tc.desc      : Test IsGeofenceEnabled function return ERR_ANS_NO_MEMORY.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287062, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    bool enabled = false;
    auto result = advancedNotificationService_->IsGeofenceEnabled(enabled);
    ASSERT_EQ(result, ERR_ANS_NO_MEMORY);
}

/**
 * @tc.number    : AnsBranchTest_287063
 * @tc.name      : SetGeofenceEnabled
 * @tc.desc      : Test SetGeofenceEnabled function return ERR_ANS_NO_MEMORY.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287063, Function | SmallTest | Level1)
{
    MockVerifyNativeToken(true);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    bool enabled = false;
    auto result = advancedNotificationService_->SetGeofenceEnabled(enabled);
    ASSERT_EQ(result, ERR_ANS_NO_MEMORY);
}

/**
 * @tc.number    : AnsBranchTest_287064
 * @tc.name      : OnNotifyDelayedNotification
 * @tc.desc      : Test OnNotifyDelayedNotification function return ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287064, Function | SmallTest | Level1)
{
    AdvancedNotificationService::PublishNotificationParameter parameter;
    auto result = advancedNotificationService_->OnNotifyDelayedNotification(parameter);
    ASSERT_EQ(result, ERR_ANS_INVALID_PARAM);

    auto req = new (std::nothrow) NotificationRequest();
    parameter.request = req;
    result = advancedNotificationService_->OnNotifyDelayedNotification(parameter);
    ASSERT_EQ(result, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AnsBranchTest_287065
 * @tc.name      : ClearDelayNotification
 * @tc.desc      : Test ClearDelayNotification function return ERR_ANS_NO_MEMORY.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287065, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(true);
    std::vector<std::string> triggerKeys;
    triggerKeys.push_back("testKey");
    std::vector<int32_t> userIds;
    userIds.push_back(100);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto result = advancedNotificationService_->ClearDelayNotification(triggerKeys, userIds);
    ASSERT_EQ(result, ERR_ANS_NO_MEMORY);
}

/**
 * @tc.number    : AnsBranchTest_287066
 * @tc.name      : GetDelayedNotificationParameterByTriggerKey
 * @tc.desc      : Test GetDelayedNotificationParameterByTriggerKey function return ERR_ANS_NOTIFICATION_NOT_EXISTS.
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_287066, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_END);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetDistributedCollaborate(true);
    request->SetDistributedHashCode("hashCodeTest");
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = request;
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    record->notification = notificationOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    std::string triggerKey = "secure_trigger_live_view_ans_distributedhashCodeTest_";
    AdvancedNotificationService::PublishNotificationParameter parameter;
    std::shared_ptr<NotificationRecord> recordTwo = std::make_shared<NotificationRecord>();
    auto result =
        advancedNotificationService_->GetDelayedNotificationParameterByTriggerKey(triggerKey, parameter, recordTwo);
    ASSERT_EQ(result, ERR_ANS_NOTIFICATION_NOT_EXISTS);
}
}  // namespace Notification
}  // namespace OHOS
