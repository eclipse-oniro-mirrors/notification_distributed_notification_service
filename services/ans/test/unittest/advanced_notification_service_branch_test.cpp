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
#include "refbase.h"

extern void MockVerifyNativeToken(bool mockRet);
extern void MockVerifyShellToken(bool mockRet);
extern void MockGetDistributedEnableInApplicationInfo(bool mockRet, uint8_t mockCase = 0);
extern void MockGetOsAccountLocalIdFromUid(bool mockRet, uint8_t mockCase = 0);

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

    ASSERT_EQ(advancedNotificationService_->PrepareNotificationRequest(req), ERR_ANS_NON_SYSTEM_APP);
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
    ASSERT_EQ(advancedNotificationService_->PrepareNotificationRequest(req), ERR_ANS_PERMISSION_DENIED);
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
 * @tc.number    : AnsBranchTest_271000
 * @tc.name      : SetEnabledForBundleSlot_1000
 * @tc.desc      : Test SetEnabledForBundleSlot function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(AnsBranchTest, AnsBranchTest_271000, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockVerifyShellToken(false);

    std::string cmd = "CMD";
    std::string bundle = "Bundle";
    int32_t userId = 4;
    std::vector<std::string> dumpInfo;
    ASSERT_EQ(advancedNotificationService_->ShellDump(
        cmd, bundle, userId, 0, dumpInfo), (int)ERR_ANS_PERMISSION_DENIED);
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
    result = advancedNotificationService_->SetCheckConfig(6, requestId, key, value);
    ASSERT_EQ(result, ERR_OK);
    result = advancedNotificationService_->SetCheckConfig(10, requestId, key, value);
    ASSERT_EQ(result, ERR_OK);
    result = advancedNotificationService_->SetCheckConfig(11, requestId, key, value);
    ASSERT_EQ(result, ERR_OK);
    result = advancedNotificationService_->SetCheckConfig(7, requestId, key, value);
    ASSERT_EQ(result, ERR_OK);
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
}  // namespace Notification
}  // namespace OHOS
