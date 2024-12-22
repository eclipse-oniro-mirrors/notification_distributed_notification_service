/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "errors.h"
#include "notification_content.h"
#include "notification_record.h"
#include "notification_request.h"
#include <chrono>
#include <functional>
#include <memory>
#include <thread>

#include "gtest/gtest.h"
#include <vector>

#define private public

#include "advanced_notification_service.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_notification.h"
#include "ans_ut_constant.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "iremote_object.h"
#include "mock_ipc_skeleton.h"
#include "notification_preferences.h"
#include "notification_subscriber.h"
#include "notification_subscriber_manager.h"
#include "mock_push_callback_stub.h"
#include "system_event_observer.h"
#include "notification_constant.h"
#include "want_agent_info.h"
#include "want_agent_helper.h"
#include "want_params.h"
#include "bundle_manager_helper.h"

extern void MockIsOsAccountExists(bool mockRet);

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Notification {
extern void MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);
extern void MockIsNonBundleName(bool isNonBundleName);
extern void MockIsVerfyPermisson(bool isVerify);

class AdvancedNotificationServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    void TestAddSlot(NotificationConstant::SlotType type);
    void TestAddLiveViewSlot(bool isForceControl);
    void MockSystemApp();

private:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AdvancedNotificationServiceTest::advancedNotificationService_ = nullptr;

void AdvancedNotificationServiceTest::SetUpTestCase()
{
    MockIsOsAccountExists(true);
}

void AdvancedNotificationServiceTest::TearDownTestCase() {}

void AdvancedNotificationServiceTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);
    advancedNotificationService_->CancelAll("");
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    GTEST_LOG_(INFO) << "SetUp end";
}

void AdvancedNotificationServiceTest::TearDown()
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
    void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override
    {}
    void OnConnected() override
    {}
    void OnDisconnected() override
    {}
    void OnDied() override
    {}
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override
    {}
    void OnBadgeEnabledChanged(
        const sptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnEnabledNotificationChanged(
        const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override
    {}
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>>
        &requestList, const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override
    {}
};

void AdvancedNotificationServiceTest::TestAddSlot(NotificationConstant::SlotType type)
{
    MockSystemApp();
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(type);
    slots.push_back(slot);
    ASSERT_EQ(advancedNotificationService_->AddSlots(slots), (int)ERR_OK);
}

void AdvancedNotificationServiceTest::MockSystemApp()
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
}

void AdvancedNotificationServiceTest::TestAddLiveViewSlot(bool isForceControl)
{
    MockSystemApp();
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::LIVE_VIEW);
    slot->SetForceControl(isForceControl);
    slots.push_back(slot);
    ASSERT_EQ(advancedNotificationService_->AddSlots(slots), (int)ERR_OK);
}


/**
 * @tc.number    : AdvancedNotificationServiceTest_01600
 * @tc.name      : ANS_GetSlot_0200
 * @tc.desc      : Test GetSlots function when add two identical data
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_01600, Function | SmallTest | Level1)
{
    MockSystemApp();
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::OTHER);
    sptr<NotificationSlot> slot1 = new NotificationSlot(NotificationConstant::OTHER);
    slots.push_back(slot0);
    slots.push_back(slot1);
    std::vector<sptr<NotificationSlot>> slotsResult;
    advancedNotificationService_->AddSlots(slots);
    advancedNotificationService_->GetSlots(slotsResult);
    ASSERT_EQ((int)slots.size(), 2);
    ASSERT_EQ((int)slotsResult.size(), 1);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_01800
 * @tc.name      : ANS_SetNotificationBadgeNum_0100
 * @tc.desc      : Test SetNotificationBadgeNum function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_01800, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    ASSERT_EQ((int)advancedNotificationService_->SetNotificationBadgeNum(2), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_01900
 * @tc.name      : ANS_GetBundleImportance_0100
 * @tc.desc      : Test GetBundleImportance function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_01900, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    int importance;
    ASSERT_EQ((int)advancedNotificationService_->GetBundleImportance(importance), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_02200
 * @tc.name      : ANS_UpdateSlots_0100
 * @tc.desc      : Test UpdateSlots function when no slot
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_02200, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::OTHER);
    slots.push_back(slot0);
    ASSERT_EQ((int)advancedNotificationService_->UpdateSlots(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), slots),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_02300
 * @tc.name      : ANS_UpdateSlots_0200
 * @tc.desc      : Test UpdateSlots function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_02300, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::OTHER);
    slots.push_back(slot0);
    ASSERT_EQ((int)advancedNotificationService_->UpdateSlots(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), slots),
        (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_02700
 * @tc.name      : ANS_SetShowBadgeEnabledForBundle_0100
 * @tc.desc      : Test the SetShowBadgeEnabledForBundle function when the parameter is wrong
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_02700, Function | SmallTest | Level1)
{
    ASSERT_EQ(advancedNotificationService_->SetShowBadgeEnabledForBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), true),
        (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_02800
 * @tc.name      : ANS_GetShowBadgeEnabledForBundle_0100
 * @tc.desc      : Test GetShowBadgeEnabledForBundle function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_02800, Function | SmallTest | Level1)
{
    ASSERT_EQ(advancedNotificationService_->SetShowBadgeEnabledForBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), true),
        (int)ERR_OK);
    bool allow = false;
    ASSERT_EQ((int)advancedNotificationService_->GetShowBadgeEnabledForBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), allow),
        (int)ERR_OK);
    EXPECT_TRUE(allow);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_02900
 * @tc.name      : ANS_GetActiveNotifications_0100
 * @tc.desc      : Test GetActiveNotifications function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_02900, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationRequest>> notifications;
    ASSERT_EQ((int)advancedNotificationService_->GetActiveNotifications(notifications, ""), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_03000
 * @tc.name      : ANS_SetTargetDeviceStatus_0100
 * @tc.desc      : Test SetTargetDeviceStatus function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_03000, Function | SmallTest | Level1)
{
    const std::string device = "current";
    const uint32_t status = 1;
    ASSERT_EQ((int)advancedNotificationService_->SetTargetDeviceStatus(device, status),
              (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_03100
 * @tc.name      : ANS_ClearAllNotificationGroupInfo_0100
 * @tc.desc      : Test ClearAllNotificationGroupInfo function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_03100, Function | SmallTest | Level1)
{
    const std::string localSwitch = "current";
    advancedNotificationService_->ClearAllNotificationGroupInfo(localSwitch);
    EXPECT_TRUE(advancedNotificationService_ != nullptr);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_03200
 * @tc.name      : ANS_UpdateUnifiedGroupInfo_0100
 * @tc.desc      : Test UpdateUnifiedGroupInfo function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_03200, Function | SmallTest | Level1)
{
    const std::string key = "key";
    std::shared_ptr<NotificationUnifiedGroupInfo> groupInfo;
    advancedNotificationService_->UpdateUnifiedGroupInfo(key, groupInfo);
    EXPECT_TRUE(advancedNotificationService_ != nullptr);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_03300
 * @tc.name      : ANS_RemoveSystemLiveViewNotificationsOfSa_0100
 * @tc.desc      : Test RemoveSystemLiveViewNotificationsOfSa function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_03300, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    int32_t uid = 0;
    ASSERT_EQ((int)advancedNotificationService_->RemoveSystemLiveViewNotificationsOfSa(uid),
              (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_03400
 * @tc.name      : ANS_IsAllowedNotifyForBundle_0100
 * @tc.desc      : Test IsAllowedNotifyForBundle function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_03400, Function | SmallTest | Level1)
{
    bool allowed = false;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    auto ret = advancedNotificationService_->IsAllowedNotifyForBundle(bundleOption, allowed);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_03500
 * @tc.name      : ANS_CancelAsBundleWithAgent_0100
 * @tc.desc      : Test CancelAsBundleWithAgent function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_03500, Function | SmallTest | Level1)
{
    int32_t id = 0;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    auto ret = advancedNotificationService_->CancelAsBundleWithAgent(bundleOption, id);
    ASSERT_EQ(ret, (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_03600
 * @tc.name      : ANS_AddDoNotDisturbProfiles_0100
 * @tc.desc      : Test AddDoNotDisturbProfiles function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_03600, Function | SmallTest | Level1)
{
    sptr<NotificationDoNotDisturbProfile> date = nullptr;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles = { date };
    auto ret = advancedNotificationService_->AddDoNotDisturbProfiles(profiles);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_03700
 * @tc.name      : ANS_Delete_0100
 * @tc.desc      : Test Delete function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_03700, Function | SmallTest | Level1)
{
    const std::string key = "key";
    ASSERT_EQ((int)advancedNotificationService_->Delete(key, NotificationConstant::CANCEL_REASON_DELETE),
              (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_03800
 * @tc.name      : ANS_DeleteByBundle_0100
 * @tc.desc      : Test DeleteByBundle function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_03800, Function | SmallTest | Level1)
{
    ASSERT_EQ(advancedNotificationService_->DeleteByBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID)),
        ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_03900
 * @tc.name      : ANS_DeleteAll_0100
 * @tc.desc      : Test DeleteAll function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_03900, Function | SmallTest | Level1)
{
    ASSERT_EQ(advancedNotificationService_->DeleteAll(), ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_04000
 * @tc.name      : ANS_GetSlotsByBundle_0100
 * @tc.desc      : Test GetSlotsByBundle function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_04000, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    ASSERT_EQ(advancedNotificationService_->GetSlotsByBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), slots),
        ERR_OK);
    ASSERT_EQ(slots.size(), (size_t)1);
}


/**
 * @tc.number    : AdvancedNotificationServiceTest_04200
 * @tc.name      : ANS_AddDoNotDisturbProfiles_0100
 * @tc.desc      : Test AddDoNotDisturbProfiles function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_04200, Function | SmallTest | Level1)
{
    sptr<NotificationDoNotDisturbProfile> date = nullptr;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles = { date };
    auto ret = advancedNotificationService_->RemoveDoNotDisturbProfiles(profiles);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_04300
 * @tc.name      : ANS_AddDoNotDisturbProfiles_0100
 * @tc.desc      : Test AddDoNotDisturbProfiles function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_04300, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest());
    std::string bundleName = "bundleName";
    advancedNotificationService_->SetAgentNotification(request, bundleName);
    EXPECT_TRUE(advancedNotificationService_ != nullptr);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_04400
 * @tc.name      : ANS_AddDoNotDisturbProfiles_0100
 * @tc.desc      : Test AddDoNotDisturbProfiles function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_04400, Function | SmallTest | Level1)
{
    std::string enable = "enable";
    auto ret = advancedNotificationService_->GetUnifiedGroupInfoFromDb(enable);
    ASSERT_EQ(ret, -1);
}


/**
 * @tc.number    : AdvancedNotificationServiceTest_05100
 * @tc.name      : ANS_AddSlots_0100
 * @tc.desc      : Test AddSlots function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_05100, Function | SmallTest | Level1)
{
    MockSystemApp();
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::OTHER);
    sptr<NotificationSlot> slot1 = new NotificationSlot(NotificationConstant::OTHER);
    slots.push_back(slot0);
    slots.push_back(slot1);
    ASSERT_EQ(advancedNotificationService_->AddSlots(slots), ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_05200
 * @tc.name      : ANS_RemoveSlotByType_0100
 * @tc.desc      : Test RemoveSlotByType function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_05200, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    ASSERT_EQ(advancedNotificationService_->RemoveSlotByType(NotificationConstant::OTHER), ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_05300
 * @tc.name      : ANS_RemoveSlotByType_0200
 * @tc.desc      : Test RemoveSlotByType function when no type
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_05300, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    ASSERT_EQ((int)advancedNotificationService_->RemoveSlotByType(NotificationConstant::CUSTOM), 0);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_05600
 * @tc.name      : ANS_GetSlot_0100
 * @tc.desc      : Test GetSlot function for data
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_05600, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::OTHER);
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::OTHER);
    slots.push_back(slot0);
    advancedNotificationService_->AddSlots(slots);
    ASSERT_EQ((int)advancedNotificationService_->GetSlotByType(NotificationConstant::OTHER, slot), ERR_OK);
    ASSERT_EQ(slot->GetName(), slot0->GetName());
    ASSERT_EQ(slot->GetId(), slot0->GetId());
    ASSERT_EQ(slot->GetLevel(), slot0->GetLevel());
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_05900
 * @tc.name      : ANS_SetNotificationBadgeNum_0100
 * @tc.desc      : Test SetNotificationBadgeNum function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_05900, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    ASSERT_EQ((int)advancedNotificationService_->SetNotificationBadgeNum(2), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_06000
 * @tc.name      : ANS_GetBundleImportance_0100
 * @tc.desc      : Test GetBundleImportance function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_06000, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    int importance = 0;
    ASSERT_EQ((int)advancedNotificationService_->GetBundleImportance(importance), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_06300
 * @tc.name      : ANS_UpdateSlots_0100
 * @tc.desc      : Test UpdateSlots function when no slot
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_06300, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::OTHER);
    slots.push_back(slot0);
    ASSERT_EQ((int)advancedNotificationService_->UpdateSlots(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), slots),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_06400
 * @tc.name      : ANS_UpdateSlots_0200
 * @tc.desc      : Test UpdateSlots function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_06400, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::OTHER);
    slots.push_back(slot0);
    ASSERT_EQ((int)advancedNotificationService_->UpdateSlots(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), slots),
        (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_06800
 * @tc.name      : ANS_SetShowBadgeEnabledForBundle_0100
 * @tc.desc      : Test the SetShowBadgeEnabledForBundle function when the parameter is wrong
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_06800, Function | SmallTest | Level1)
{
    ASSERT_EQ(advancedNotificationService_->SetShowBadgeEnabledForBundle(
                  new NotificationBundleOption("", SYSTEM_APP_UID), true),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_06900
 * @tc.name      : ANS_GetShowBadgeEnabledForBundle_0100
 * @tc.desc      : Test GetShowBadgeEnabledForBundle function when no bundle
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_06900, Function | SmallTest | Level1)
{
    bool allow = false;
    ASSERT_EQ((int)advancedNotificationService_->GetShowBadgeEnabledForBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), allow),
        (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_07000
 * @tc.name      : ANS_GetActiveNotifications_0100
 * @tc.desc      : Test GetActiveNotifications function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_07000, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationRequest>> notifications;
    ASSERT_EQ((int)advancedNotificationService_->GetActiveNotifications(notifications, ""), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_07800
 * @tc.name      : ANS_Delete_0100
 * @tc.desc      : Test Delete function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_07800, Function | SmallTest | Level1)
{
    const std::string key = "key";
    ASSERT_EQ((int)advancedNotificationService_->Delete(key, NotificationConstant::CANCEL_REASON_DELETE),
              (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_07900
 * @tc.name      : ANS_DeleteByBundle_0100
 * @tc.desc      : Test DeleteByBundle function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_07900, Function | SmallTest | Level1)
{
    ASSERT_EQ(advancedNotificationService_->DeleteByBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID)),
        ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_08000
 * @tc.name      : ANS_DeleteAll_0100
 * @tc.desc      : Test DeleteAll function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_08000, Function | SmallTest | Level1)
{
    ASSERT_EQ(advancedNotificationService_->DeleteAll(), ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_08300
 * @tc.name      : ANS_Subscribe_0100
 * @tc.desc      : Test Subscribe function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_08300, Function | SmallTest | Level1)
{
    auto subscriber = new TestAnsSubscriber();
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    EXPECT_NE((int)advancedNotificationService_->Subscribe(subscriber->GetImpl(), info), (int)ERR_OK);
    ASSERT_EQ((int)advancedNotificationService_->Subscribe(nullptr, info), (int)ERR_ANS_INVALID_PARAM);
    EXPECT_NE((int)advancedNotificationService_->Unsubscribe(subscriber->GetImpl(), nullptr), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_08600
 * @tc.name      : ANS_GetShowBadgeEnabledForBundle_0200
 * @tc.desc      : Test GetShowBadgeEnabledForBundle function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_08600, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    ASSERT_EQ((int)advancedNotificationService_->SetShowBadgeEnabledForBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), true),
        (int)ERR_OK);
    bool allow = false;
    ASSERT_EQ((int)advancedNotificationService_->GetShowBadgeEnabledForBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), allow),
        (int)ERR_OK);
    EXPECT_TRUE(allow);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_08700
 * @tc.name      : ANS_GetSlotByType_0100
 * @tc.desc      : Test GetSlotByType function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_08700, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    ASSERT_EQ((int)advancedNotificationService_->GetSlotByType(NotificationConstant::OTHER, slot), (int)ERR_OK);
    ASSERT_EQ(slot->GetType(), NotificationConstant::SlotType::OTHER);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_09000
 * @tc.name      : ANS_GetAllActiveNotifications_0100
 * @tc.desc      : Test GetAllActiveNotifications function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_09000, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;
    ASSERT_EQ(advancedNotificationService_->GetAllActiveNotifications(notifications), ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_09200
 * @tc.name      : ANS_SetNotificationsEnabledForAllBundles_0200
 * @tc.desc      : Test SetNotificationsEnabledForAllBundles function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_09200, Function | SmallTest | Level1)
{
    ASSERT_EQ(
        (int)advancedNotificationService_->SetNotificationsEnabledForAllBundles(std::string(), true), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_09300
 * @tc.name      : ANS_SetNotificationsEnabledForSpecialBundle_0100
 * @tc.desc      : Test SetNotificationsEnabledForSpecialBundle function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_09300, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<Notification>> notifications;
    ASSERT_EQ((int)advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(
                  std::string(), new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), true),
        (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_09500
 * @tc.name      : ANS_IsAllowedNotify_0100
 * @tc.desc      : Test IsAllowedNotify function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_09500, Function | SmallTest | Level1)
{
    ASSERT_EQ(
        (int)advancedNotificationService_->SetNotificationsEnabledForAllBundles(std::string(), true), (int)ERR_OK);
    bool allowed = false;
    ASSERT_EQ((int)advancedNotificationService_->IsAllowedNotify(allowed), (int)ERR_OK);
    EXPECT_TRUE(allowed);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_09600
 * @tc.name      : ANS_IsAllowedNotifySelf_0100
 * @tc.desc      : Test IsAllowedNotifySelf function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_09600, Function | SmallTest | Level1)
{
    MockSystemApp();
    ASSERT_EQ(
        (int)advancedNotificationService_->SetNotificationsEnabledForAllBundles(std::string(), true), (int)ERR_OK);
    bool allowed = false;
    ASSERT_EQ((int)advancedNotificationService_->IsAllowedNotifySelf(allowed), (int)ERR_OK);
    EXPECT_FALSE(allowed);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_09700
 * @tc.name      : ANS_IsSpecialBundleAllowedNotify_0100
 * @tc.desc      : Test IsSpecialBundleAllowedNotify function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_09700, Function | SmallTest | Level1)
{
    ASSERT_EQ(
        (int)advancedNotificationService_->SetNotificationsEnabledForAllBundles(std::string(), true), (int)ERR_OK);
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    bool allowed = true;
    ASSERT_EQ((int)advancedNotificationService_->IsSpecialBundleAllowedNotify(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), allowed),
        (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_09800
 * @tc.name      : ANS_IsSpecialBundleAllowedNotify_0200
 * @tc.desc      : Test IsSpecialBundleAllowedNotify function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_09800, Function | SmallTest | Level1)
{
    ASSERT_EQ(
        (int)advancedNotificationService_->SetNotificationsEnabledForAllBundles(std::string(), true), (int)ERR_OK);
    std::vector<sptr<Notification>> notifications;
    bool allowed = true;
    ASSERT_EQ((int)advancedNotificationService_->IsSpecialBundleAllowedNotify(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), allowed),
        (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_09900
 * @tc.name      : ANS_GetSlotsByBundle_0200
 * @tc.desc      : Test GetSlotsByBundle function when no bundle
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_09900, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    ASSERT_EQ((int)advancedNotificationService_->GetSlotsByBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), slots),
        (int)ERR_OK);
}


/**
 * @tc.number    : AdvancedNotificationServiceTest_10500
 * @tc.name      : ANS_SetDisturbMode_10500
 * @tc.desc      : Test SetDisturbMode function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_10500, Function | SmallTest | Level1)
{
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
    ASSERT_EQ((int)advancedNotificationService_->SetDoNotDisturbDate(date), (int)ERR_OK);

    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();
    date = new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::ONCE, beginDate, endDate);
    ASSERT_EQ((int)advancedNotificationService_->SetDoNotDisturbDate(date), (int)ERR_OK);

    timePoint = std::chrono::system_clock::now();
    beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    endDate = endDuration.count();
    date = new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::DAILY, beginDate, endDate);
    ASSERT_EQ((int)advancedNotificationService_->SetDoNotDisturbDate(date), (int)ERR_OK);

    timePoint = std::chrono::system_clock::now();
    beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    endDate = endDuration.count();
    date = new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::CLEARLY, beginDate, endDate);
    ASSERT_EQ((int)advancedNotificationService_->SetDoNotDisturbDate(date), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_10600
 * @tc.name      : ANS_GetDisturbMode_10600
 * @tc.desc      : Test GetDisturbMode function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_10600, Function | SmallTest | Level1)
{
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);

    ASSERT_EQ((int)advancedNotificationService_->SetDoNotDisturbDate(date), (int)ERR_OK);

    sptr<NotificationDoNotDisturbDate> result = nullptr;
    ASSERT_EQ((int)advancedNotificationService_->GetDoNotDisturbDate(result), (int)ERR_OK);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->GetDoNotDisturbType(), NotificationConstant::DoNotDisturbType::NONE);
    ASSERT_EQ(result->GetBeginDate(), 0);
    ASSERT_EQ(result->GetEndDate(), 0);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_10700
 * @tc.name      : ANS_GetDisturbMode_10700
 * @tc.desc      : Test GetDisturbMode function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_10700, Function | SmallTest | Level1)
{
    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    timePoint = std::chrono::time_point_cast<std::chrono::minutes>(timePoint);
    timePoint += std::chrono::hours(1);
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();

    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::ONCE, beginDate, endDate);
    ASSERT_EQ((int)advancedNotificationService_->SetDoNotDisturbDate(date), (int)ERR_OK);

    sptr<NotificationDoNotDisturbDate> result = nullptr;
    ASSERT_EQ((int)advancedNotificationService_->GetDoNotDisturbDate(result), (int)ERR_OK);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->GetDoNotDisturbType(), NotificationConstant::DoNotDisturbType::ONCE);
    ASSERT_EQ(result->GetBeginDate(), beginDate);
    ASSERT_EQ(result->GetEndDate(), endDate);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_10800
 * @tc.name      : ANS_GetDisturbMode_10800
 * @tc.desc      : Test GetDisturbMode function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_10800, Function | SmallTest | Level1)
{
    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    timePoint = std::chrono::time_point_cast<std::chrono::minutes>(timePoint);
    timePoint += std::chrono::hours(1);
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();

    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::DAILY, beginDate, endDate);

    ASSERT_EQ((int)advancedNotificationService_->SetDoNotDisturbDate(date), (int)ERR_OK);
    sptr<NotificationDoNotDisturbDate> result = nullptr;
    ASSERT_EQ((int)advancedNotificationService_->GetDoNotDisturbDate(result), (int)ERR_OK);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->GetDoNotDisturbType(), NotificationConstant::DoNotDisturbType::DAILY);
    ASSERT_EQ(result->GetBeginDate(), beginDate);
    ASSERT_EQ(result->GetEndDate(), endDate);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_10900
 * @tc.name      : ANS_GetDisturbMode_10900
 * @tc.desc      : Test GetDisturbMode function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_10900, Function | SmallTest | Level1)
{
    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    timePoint = std::chrono::time_point_cast<std::chrono::minutes>(timePoint);
    timePoint += std::chrono::hours(1);
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();

    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::CLEARLY, beginDate, endDate);
    ASSERT_EQ((int)advancedNotificationService_->SetDoNotDisturbDate(date), (int)ERR_OK);

    sptr<NotificationDoNotDisturbDate> result = nullptr;
    ASSERT_EQ((int)advancedNotificationService_->GetDoNotDisturbDate(result), (int)ERR_OK);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->GetDoNotDisturbType(), NotificationConstant::DoNotDisturbType::CLEARLY);
    ASSERT_EQ(result->GetBeginDate(), beginDate);
    ASSERT_EQ(result->GetEndDate(), endDate);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_12900
 * @tc.name      : ANS_HasNotificationPolicyAccessPermission_0100
 * @tc.desc      : Test HasNotificationPolicyAccessPermission function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_12900, Function | SmallTest | Level1)
{
    bool granted = true;
    ASSERT_EQ(advancedNotificationService_->HasNotificationPolicyAccessPermission(granted), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_13000
 * @tc.name      : ANS_GetShowBadgeEnabled_0100
 * @tc.desc      : Test GetShowBadgeEnabled function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_13000, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    bool enabled = false;
    ASSERT_EQ(advancedNotificationService_->GetShowBadgeEnabled(enabled), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_13100
 * @tc.name      : ANS_RequestEnableNotification_0100
 * @tc.desc      : Test whether to pop dialog
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_13100, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    std::string deviceId = "DeviceId";
    sptr<AnsDialogCallback> callback = nullptr;
    sptr<IRemoteObject> callerToken = nullptr;
    ASSERT_EQ(advancedNotificationService_->RequestEnableNotification(deviceId, callback, callerToken),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_13600
 * @tc.name      : ANS_ActiveNotificationDump_0100
 * @tc.desc      : Test ActiveNotificationDump function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_13600, Function | SmallTest | Level1)
{
    std::string bundle = "Bundle";
    int32_t userId = 2;
    std::vector<std::string> dumpInfo;
    ASSERT_EQ(advancedNotificationService_->ActiveNotificationDump(bundle, userId, 0, dumpInfo), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_13700
 * @tc.name      : ANS_RecentNotificationDump_0100
 * @tc.desc      : Test RecentNotificationDump function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_13700, Function | SmallTest | Level1)
{
    std::string bundle = "Bundle";
    int32_t userId = 3;
    std::vector<std::string> dumpInfo;
    ASSERT_EQ(advancedNotificationService_->RecentNotificationDump(bundle, userId, 0, dumpInfo), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_13800
 * @tc.name      : ANS_SetRecentNotificationCount_0100
 * @tc.desc      : Test SetRecentNotificationCount function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_13800, Function | SmallTest | Level1)
{
    std::string arg = "Arg";
    ASSERT_EQ(advancedNotificationService_->SetRecentNotificationCount(arg), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_13900
 * @tc.name      : ANS_RemoveAllSlots_0100
 * @tc.desc      : Test RemoveAllSlots function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_13900, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    ASSERT_EQ(advancedNotificationService_->RemoveAllSlots(), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_14200
 * @tc.name      : ANS_DoesSupportDoNotDisturbMode_0100
 * @tc.desc      : Test DoesSupportDoNotDisturbMode function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_14200, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    bool doesSupport = true;
    ASSERT_EQ(advancedNotificationService_->DoesSupportDoNotDisturbMode(doesSupport), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_14300
 * @tc.name      : ANS_IsDistributedEnabled_0100
 * @tc.desc      : Test IsDistributedEnabled function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_14300, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    bool enabled = true;
    ASSERT_EQ(advancedNotificationService_->IsDistributedEnabled(enabled), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_14400
 * @tc.name      : ANS_EnableDistributed_0100
 * @tc.desc      : Test EnableDistributed function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_14400, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    bool enabled = true;
    ASSERT_EQ(advancedNotificationService_->EnableDistributed(enabled), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_14600
 * @tc.name      : ANS_EnableDistributedSelf_0100
 * @tc.desc      : Test EnableDistributedSelf function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_14600, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    bool enabled = true;
    ASSERT_EQ(advancedNotificationService_->EnableDistributedSelf(enabled), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_14800
 * @tc.name      : ANS_IsSpecialUserAllowedNotify_0100
 * @tc.desc      : Test IsSpecialUserAllowedNotify function when the result is ERR_ANS_INVALID_PARAM
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_14800, Function | SmallTest | Level1)
{
    int32_t userId = 3;
    bool allowed = true;
    ASSERT_EQ(advancedNotificationService_->IsSpecialUserAllowedNotify(userId, allowed), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_14900
 * @tc.name      : ANS_SetNotificationsEnabledByUser_0100
 * @tc.desc      : Test SetNotificationsEnabledByUser function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_14900, Function | SmallTest | Level1)
{
    int32_t userId = 3;
    bool enabled = true;
    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledByUser(userId, enabled), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_15000
 * @tc.name      : ANS_GetDoNotDisturbDate_0100
 * @tc.desc      : Test GetDoNotDisturbDate function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_15000, Function | SmallTest | Level1)
{
    int32_t userId = 3;
    sptr<NotificationDoNotDisturbDate> date = nullptr;
    ASSERT_EQ(advancedNotificationService_->GetDoNotDisturbDate(userId, date), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_15200
 * @tc.name      : ANS_GetHasPoppedDialog_0100
 * @tc.desc      : Test GetHasPoppedDialog function when the result is ERR_ANS_INVALID_PARAM
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_15200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool hasPopped = true;
    ASSERT_EQ(advancedNotificationService_->GetHasPoppedDialog(bundleOption, hasPopped), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_15300
 * @tc.name      : ANS_ShellDump_0100
 * @tc.desc      : Test ShellDump function when the result is ERR_ANS_INVALID_PARAM
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_15300, Function | SmallTest | Level1)
{
    std::string cmd = "CMD";
    std::string bundle = "Bundle";
    int32_t userId = 4;
    std::vector<std::string> dumpInfo;
    ASSERT_EQ(advancedNotificationService_->ShellDump(cmd, bundle, userId, 0, dumpInfo), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_15400
 * @tc.name      : ANS_Dump_0100
 * @tc.desc      : Test Dump function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_15400, Function | SmallTest | Level1)
{
    int fd = 1;
    std::vector<std::u16string> args;
    ASSERT_EQ(advancedNotificationService_->Dump(fd, args), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_15700
 * @tc.name      : PrepareNotificationRequest_0100
 * @tc.desc      : Test PrepareNotificationRequest function when notification is agent.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_15700, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "PrepareNotificationRequest_0100 test start";
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);

    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("req's label");
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);

    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);

    req->SetContent(content);
    req->SetIsAgentNotification(true);
    ASSERT_EQ(advancedNotificationService_->PrepareNotificationRequest(req), ERR_OK);
    GTEST_LOG_(INFO) << "PrepareNotificationRequest_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_15800
 * @tc.name      : GenerateBundleOption_0100
 * @tc.desc      : Test GenerateBundleOption function when bundle name is null.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_15800, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GenerateBundleOption_0100 test start";
    MockSystemApp();
    MockIsNonBundleName(true);
    ASSERT_EQ(advancedNotificationService_->GenerateBundleOption(), nullptr);
    MockIsNonBundleName(false);
    GTEST_LOG_(INFO) << "GenerateBundleOption_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_16000
 * @tc.name      : CancelPreparedNotification_1000
 * @tc.desc      : Test CancelPreparedNotification function.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16000, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "CancelPreparedNotification_1000 test start";

    int32_t notificationId = 0;
    std::string label = "testLabel";
    sptr<NotificationBundleOption> bundleOption = nullptr;
    ASSERT_EQ(advancedNotificationService_->CancelPreparedNotification(notificationId, label, bundleOption, 8),
        ERR_ANS_INVALID_BUNDLE);

    GTEST_LOG_(INFO) << "CancelPreparedNotification_1000 test end";
}


/**
 * @tc.number    : AdvancedNotificationServiceTest_16200
 * @tc.name      : ANS_CancelAsBundle_0200
 * @tc.desc      : Test CancelAsBundle function
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16200, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_CancelAsBundle_0200 test start";

    TestAddSlot(NotificationConstant::SlotType::OTHER);
    int32_t notificationId = 1;
    std::string representativeBundle = "RepresentativeBundle";
    int32_t userId = 1;
    int result = ERR_ANS_NOTIFICATION_NOT_EXISTS;
    ASSERT_EQ(advancedNotificationService_->CancelAsBundle(notificationId, representativeBundle, userId), result);

    GTEST_LOG_(INFO) << "ANS_CancelAsBundle_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_16300
 * @tc.name      : ANS_CancelAsBundle_0300
 * @tc.desc      : Test CancelAsBundle function when uid is less than 0.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16300, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_CancelAsBundle_0300 test start";

    TestAddSlot(NotificationConstant::SlotType::OTHER);
    int32_t notificationId = 1;
    std::string representativeBundle = "RepresentativeBundle";
    int32_t userId = 0;
    int result = ERR_ANS_INVALID_UID;
    ASSERT_EQ(advancedNotificationService_->CancelAsBundle(notificationId, representativeBundle, userId), result);

    GTEST_LOG_(INFO) << "ANS_CancelAsBundle_0300 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_16500
 * @tc.name      : ANS_CancelAsBundle_0400
 * @tc.desc      : Test CancelAsBundle function
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16500, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_CancelAsBundle_0400 test start";

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    int32_t notificationId = 1;

    int result = ERR_ANS_NOTIFICATION_NOT_EXISTS;
    ASSERT_EQ(advancedNotificationService_->CancelAsBundle(bundleOption, notificationId), result);

    GTEST_LOG_(INFO) << "ANS_CancelAsBundle_0400 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_16400
 * @tc.name      : ANS_AddSlots_0100
 * @tc.desc      : Test AddSlots function whith not system app
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16400, Function | SmallTest | Level1)
{
    MockSystemApp();
    GTEST_LOG_(INFO) << "ANS_AddSlots_0100 test start";
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    slots.push_back(slot);
    ASSERT_EQ(advancedNotificationService_->AddSlots(slots), ERR_OK);

    GTEST_LOG_(INFO) << "ANS_AddSlots_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_16600
 * @tc.name      : ANS_AddSlots_0300
 * @tc.desc      : Test AddSlots function with bundle option is null
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16600, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_AddSlots_0300 test start";
    MockIsNonBundleName(true);
    MockSystemApp();
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    slots.push_back(slot);
    ASSERT_EQ(advancedNotificationService_->AddSlots(slots), ERR_ANS_INVALID_BUNDLE);
    MockIsNonBundleName(false);
    GTEST_LOG_(INFO) << "ANS_AddSlots_0300 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_16700
 * @tc.name      : ANS_AddSlots_0400
 * @tc.desc      : Test AddSlots function with invalid bundle option
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16700, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_AddSlots_0400 test start";

    std::vector<sptr<NotificationSlot>> slots;
    ASSERT_EQ(advancedNotificationService_->AddSlots(slots), ERR_ANS_INVALID_PARAM);

    GTEST_LOG_(INFO) << "ANS_AddSlots_0400 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_16800
 * @tc.name      : ANS_GetSlots_0100
 * @tc.desc      : Test GetSlots function with bundle option is null
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16800, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_GetSlots_0100 test start";
    MockIsNonBundleName(true);
    MockSystemApp();
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    slots.push_back(slot);
    ASSERT_EQ(advancedNotificationService_->GetSlots(slots), ERR_ANS_INVALID_BUNDLE);
    MockIsNonBundleName(false);
    GTEST_LOG_(INFO) << "ANS_GetSlots_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_16900
 * @tc.name      : ANS_GetActiveNotifications_0100
 * @tc.desc      : Test function with bundle option is null
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16900, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_GetActiveNotifications_0100 test start";

    MockIsNonBundleName(true);
    MockSystemApp();
    std::vector<sptr<NotificationRequest>> notifications;
    ASSERT_EQ(advancedNotificationService_->GetActiveNotifications(notifications, ""), ERR_ANS_INVALID_BUNDLE);
    uint64_t num = 1;
    ASSERT_EQ(advancedNotificationService_->GetActiveNotificationNums(num), ERR_ANS_INVALID_BUNDLE);
    ASSERT_EQ(advancedNotificationService_->SetNotificationBadgeNum(num), ERR_ANS_INVALID_BUNDLE);
    int32_t importance = 2;
    ASSERT_EQ(advancedNotificationService_->GetBundleImportance(importance), ERR_ANS_INVALID_BUNDLE);
    bool allow = true;
    ASSERT_EQ(advancedNotificationService_->GetShowBadgeEnabled(allow), ERR_ANS_INVALID_BUNDLE);

    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::OTHER);
    ASSERT_EQ(advancedNotificationService_->GetSlotByType(NotificationConstant::OTHER, slot), ERR_ANS_INVALID_BUNDLE);
    ASSERT_EQ(advancedNotificationService_->RemoveSlotByType(NotificationConstant::OTHER), ERR_ANS_INVALID_BUNDLE);

    std::string deviceId = "DeviceId";
    bool needPop = false;
    ASSERT_EQ(advancedNotificationService_->IsAllowedNotifySelf(needPop), ERR_ANS_INVALID_BUNDLE);
    sptr<NotificationBundleOption> bundleOption;
    ASSERT_EQ(advancedNotificationService_->IsAllowedNotifySelf(bundleOption, needPop), ERR_ANS_INVALID_BUNDLE);

    ASSERT_EQ(advancedNotificationService_->GetAppTargetBundle(bundleOption, bundleOption), ERR_ANS_INVALID_BUNDLE);

    ASSERT_EQ(advancedNotificationService_->RemoveAllSlots(), ERR_ANS_INVALID_BUNDLE);

    ASSERT_EQ(advancedNotificationService_->AddSlotByType(NotificationConstant::SlotType::OTHER),
        ERR_ANS_INVALID_BUNDLE);

    std::string groupName = "name";
    ASSERT_EQ(advancedNotificationService_->CancelGroup(groupName, ""), ERR_ANS_INVALID_BUNDLE);

    bool enabled = true;
    ASSERT_EQ(advancedNotificationService_->EnableDistributedSelf(enabled), ERR_ANS_INVALID_BUNDLE);
    MockIsNonBundleName(false);
    GTEST_LOG_(INFO) << "ANS_GetActiveNotifications_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_17100
 * @tc.name      : ANS_GetSetActiveNotifications_0100
 * @tc.desc      : Test function with NON_SYSTEM_APP_UID
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_17100, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_GetActiveNotifications_0100 test start";

    std::string key = "key";
    int32_t removeReason = 0;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    ASSERT_EQ(advancedNotificationService_->Delete(key, removeReason), ERR_ANS_NOTIFICATION_NOT_EXISTS);

    ASSERT_EQ(advancedNotificationService_->DeleteByBundle(bundleOption), ERR_OK);

    ASSERT_EQ(advancedNotificationService_->DeleteAll(), ERR_OK);

    bool enable = true;
    bool isForceControl = false;
    ASSERT_EQ(advancedNotificationService_->SetShowBadgeEnabledForBundle(bundleOption, enable), ERR_OK);

    ASSERT_EQ(advancedNotificationService_->GetShowBadgeEnabledForBundle(bundleOption, enable), ERR_OK);

    std::vector<sptr<Notification>> notifications;
    ASSERT_EQ(advancedNotificationService_->GetAllActiveNotifications(notifications), ERR_OK);

    std::vector<std::string> keys;
    ASSERT_EQ(advancedNotificationService_->GetSpecialActiveNotifications(keys, notifications),
        ERR_OK);

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForAllBundles(key, enable),
        ERR_OK);

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(
        std::string(), bundleOption, enable), ERR_OK);

    ASSERT_EQ(advancedNotificationService_->IsAllowedNotify(enable), ERR_ANS_INVALID_PARAM);

    int32_t notificationId = 1;
    ASSERT_EQ(advancedNotificationService_->RemoveNotification(bundleOption, notificationId,
        key, removeReason), ERR_ANS_NOTIFICATION_NOT_EXISTS);

    ASSERT_EQ(advancedNotificationService_->RemoveAllNotifications(bundleOption), ERR_OK);

    uint64_t num = 1;
    ASSERT_EQ(advancedNotificationService_->GetSlotNumAsBundle(bundleOption, num), ERR_OK);

    std::string groupName = "group";
    ASSERT_EQ(advancedNotificationService_->RemoveGroupByBundle(bundleOption, groupName), ERR_OK);

    sptr<NotificationDoNotDisturbDate> date = nullptr;
    ASSERT_EQ(advancedNotificationService_->SetDoNotDisturbDate(date), ERR_ANS_INVALID_PARAM);
    ASSERT_EQ(advancedNotificationService_->GetDoNotDisturbDate(date), ERR_OK);

    ASSERT_EQ(advancedNotificationService_->DoesSupportDoNotDisturbMode(enable), ERR_OK);

    ASSERT_EQ(advancedNotificationService_->EnableDistributed(enable), ERR_OK);

    ASSERT_EQ(advancedNotificationService_->EnableDistributedByBundle(bundleOption, enable), ERR_OK);

    ASSERT_EQ(advancedNotificationService_->IsDistributedEnableByBundle(bundleOption, enable), ERR_OK);

    NotificationConstant::RemindType remindType = NotificationConstant::RemindType::DEVICE_ACTIVE_REMIND;
    ASSERT_EQ(advancedNotificationService_->GetDeviceRemindType(remindType), ERR_OK);

    int32_t userId = 1;
    ASSERT_EQ(advancedNotificationService_->IsSpecialUserAllowedNotify(userId, enable), ERR_ANS_INVALID_PARAM);

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledByUser(userId, enable), ERR_OK);

    ASSERT_EQ(advancedNotificationService_->DeleteAllByUser(userId), ERR_OK);

    ASSERT_EQ(advancedNotificationService_->SetDoNotDisturbDate(userId, date), ERR_ANS_INVALID_PARAM);
    ASSERT_EQ(advancedNotificationService_->GetDoNotDisturbDate(userId, date), ERR_OK);

    ASSERT_EQ(advancedNotificationService_->SetEnabledForBundleSlot(bundleOption,
        NotificationConstant::SlotType::OTHER, enable, false), ERR_OK);

    ASSERT_EQ(advancedNotificationService_->GetEnabledForBundleSlot(bundleOption,
        NotificationConstant::SlotType::OTHER, enable), ERR_OK);

    ASSERT_EQ(advancedNotificationService_->SetSyncNotificationEnabledWithoutApp(userId, enable), ERR_OK);

    ASSERT_EQ(advancedNotificationService_->GetSyncNotificationEnabledWithoutApp(userId, enable), ERR_OK);

    std::string phoneNumber = "11111111111";
    int32_t callerType = 0;
    ASSERT_EQ(advancedNotificationService_->IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType), -1);

    GTEST_LOG_(INFO) << "ANS_GetActiveNotifications_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_17300
 * @tc.name      : ANS_GetSlotsByBundle_0100
 * @tc.desc      : Test GetSlotsByBundle function
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_17300, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_GetSlotsByBundle_0100 test start";
    std::vector<sptr<NotificationSlot>> slots;
    ASSERT_EQ(advancedNotificationService_->GetSlotsByBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), slots),
        ERR_OK);

    ASSERT_EQ(advancedNotificationService_->UpdateSlots(
                new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), slots),
        ERR_ANS_INVALID_PARAM);

    GTEST_LOG_(INFO) << "ANS_GetSlotsByBundle_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_17400
 * @tc.name      : Subscribe_1000
 * @tc.desc      : Test Subscribe function.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_17400, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "Subscribe_1000 test start";

    auto subscriber = new TestAnsSubscriber();
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    EXPECT_NE(advancedNotificationService_->Subscribe(subscriber->GetImpl(), info), ERR_OK);
    EXPECT_NE(advancedNotificationService_->Unsubscribe(subscriber->GetImpl(), info), ERR_OK);

    GTEST_LOG_(INFO) << "Subscribe_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_17500
 * @tc.name      : Unsubscribe_1000
 * @tc.desc      : Test Subscribe function.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_17500, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "Unsubscribe_1000 test start";

    auto subscriber = new TestAnsSubscriber();
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    EXPECT_NE(advancedNotificationService_->Subscribe(subscriber->GetImpl(), info), ERR_OK);
    ASSERT_EQ(advancedNotificationService_->Unsubscribe(nullptr, info), ERR_ANS_INVALID_PARAM);

    GTEST_LOG_(INFO) << "Unsubscribe_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_17600
 * @tc.name      : GetAppTargetBundle_1000
 * @tc.desc      : Test GetAppTargetBundle function.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_17600, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetAppTargetBundle_1000 test start";

    sptr<NotificationBundleOption> bundleOption = nullptr;

    ASSERT_EQ(advancedNotificationService_->GetAppTargetBundle(bundleOption, bundleOption), ERR_OK);

    GTEST_LOG_(INFO) << "GetAppTargetBundle_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_17700
 * @tc.name      : GetAppTargetBundle_2000
 * @tc.desc      : Test GetAppTargetBundle function.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_17700, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetAppTargetBundle_2000 test start";
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationBundleOption> targetBundle = nullptr;
    bundleOption->SetBundleName("test");
    ASSERT_EQ(advancedNotificationService_->GetAppTargetBundle(bundleOption, targetBundle), ERR_OK);

    GTEST_LOG_(INFO) << "GetAppTargetBundle_2000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_17800
 * @tc.name      : GetAppTargetBundle_3000
 * @tc.desc      : Test GetAppTargetBundle function.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_17800, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetAppTargetBundle_3000 test start";

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    sptr<NotificationBundleOption> targetBundle = nullptr;
    bundleOption->SetBundleName("test");
    ASSERT_EQ(advancedNotificationService_->GetAppTargetBundle(bundleOption, targetBundle), ERR_OK);

    GTEST_LOG_(INFO) << "GetAppTargetBundle_3000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_18100
 * @tc.name      : ActiveNotificationDump_1000
 * @tc.desc      : Test ActiveNotificationDump function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18100, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ActiveNotificationDump_1000 test start";

    std::string bundle = "Bundle";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;

    ASSERT_EQ(advancedNotificationService_->ActiveNotificationDump(bundle, userId, userId, dumpInfo), ERR_OK);

    GTEST_LOG_(INFO) << "ActiveNotificationDump_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_18200
 * @tc.name      : RecentNotificationDump_1000
 * @tc.desc      : Test RecentNotificationDump function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18200, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "RecentNotificationDump_1000 test start";

    std::string bundle = "Bundle";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;

    ASSERT_EQ(advancedNotificationService_->RecentNotificationDump(bundle, userId, userId, dumpInfo), ERR_OK);

    GTEST_LOG_(INFO) << "RecentNotificationDump_1000 test end";
}

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
/**
 * @tc.number    : AdvancedNotificationServiceTest_18300
 * @tc.name      : DistributedNotificationDump_1000
 * @tc.desc      : Test DistributedNotificationDump function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18300, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "DistributedNotificationDump_1000 test start";

    std::string bundle = "Bundle";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;

    ASSERT_EQ(advancedNotificationService_->DistributedNotificationDump(bundle, userId, userId, dumpInfo), ERR_OK);

    GTEST_LOG_(INFO) << "DistributedNotificationDump_1000 test end";
}
#endif

/**
 * @tc.number    : AdvancedNotificationServiceTest_18400
 * @tc.name      : SetRecentNotificationCount_1000
 * @tc.desc      : Test SetRecentNotificationCount function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18400, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "SetRecentNotificationCount_1000 test start";

    std::string arg = "1100";
    ASSERT_EQ(advancedNotificationService_->SetRecentNotificationCount(arg), ERR_ANS_INVALID_PARAM);

    GTEST_LOG_(INFO) << "SetRecentNotificationCount_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_18500
 * @tc.name      : OnBundleRemoved_1000
 * @tc.desc      : Test OnBundleRemoved function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18500, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "OnBundleRemoved_1000 test start";

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->OnBundleRemoved(bundleOption);

    GTEST_LOG_(INFO) << "OnBundleRemoved_1000 test end";
}

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
/**
 * @tc.number    : AdvancedNotificationServiceTest_18600
 * @tc.name      : OnScreenOn_1000
 * @tc.desc      : Test OnScreenOn function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18600, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "OnScreenOn_1000 test start";

    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->OnScreenOn();
    advancedNotificationService_->OnScreenOff();

    GTEST_LOG_(INFO) << "OnScreenOn_1000 test end";
}
#endif

/**
 * @tc.number    : AdvancedNotificationServiceTest_18700
 * @tc.name      : AddSlotByType_1000
 * @tc.desc      : Test AddSlotByType function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18700, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AddSlotByType_1000 test start";
    MockSystemApp();
    ASSERT_EQ(advancedNotificationService_->AddSlotByType(NotificationConstant::SlotType::SERVICE_REMINDER),
        ERR_OK);

    GTEST_LOG_(INFO) << "AddSlotByType_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_18800
 * @tc.name      : GetSlotNumAsBundle_1000
 * @tc.desc      : Test GetSlotNumAsBundle function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18800, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetSlotNumAsBundle_1000 test start";

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    uint64_t num = 1;
    ASSERT_EQ(advancedNotificationService_->GetSlotNumAsBundle(bundleOption, num), ERR_OK);

    GTEST_LOG_(INFO) << "GetSlotNumAsBundle_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_18900
 * @tc.name      : CancelGroup_1000
 * @tc.desc      : Test CancelGroup function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18900, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "CancelGroup_1000 test start";

    std::string groupName = "";
    ASSERT_EQ(advancedNotificationService_->CancelGroup(groupName, ""), ERR_ANS_INVALID_PARAM);

    GTEST_LOG_(INFO) << "CancelGroup_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19000
 * @tc.name      : RemoveGroupByBundle_1000
 * @tc.desc      : Test RemoveGroupByBundle function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19000, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "RemoveGroupByBundle_1000 test start";

    std::string groupName = "group";
    sptr<NotificationBundleOption> bundleOption = nullptr;
    ASSERT_EQ(advancedNotificationService_->RemoveGroupByBundle(bundleOption, groupName), ERR_ANS_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RemoveGroupByBundle_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19100
 * @tc.name      : ANS_IsDistributedEnabled_0100
 * @tc.desc      : Test IsDistributedEnabled function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19100, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_IsDistributedEnabled_0100 test start";

    bool enabled = false;
    ASSERT_EQ(advancedNotificationService_->IsDistributedEnabled(enabled), ERR_OK);

    GTEST_LOG_(INFO) << "ANS_IsDistributedEnabled_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19200
 * @tc.name      : EnableDistributedByBundle_0100
 * @tc.desc      : Test EnableDistributedByBundle function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19200, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "EnableDistributedByBundle_0100 test start";

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    bool enabled = false;
    ASSERT_EQ(advancedNotificationService_->EnableDistributedByBundle(bundleOption, enabled), ERR_OK);

    GTEST_LOG_(INFO) << "EnableDistributedByBundle_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19300
 * @tc.name      : IsDistributedEnableByBundle_0100
 * @tc.desc      : Test IsDistributedEnableByBundle function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19300, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsDistributedEnableByBundle_0100 test start";

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    bool enabled = true;
    ASSERT_EQ(advancedNotificationService_->IsDistributedEnableByBundle(bundleOption, enabled), ERR_OK);

    GTEST_LOG_(INFO) << "IsDistributedEnableByBundle_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19400
 * @tc.name      : IsDistributedEnableByBundle_0200
 * @tc.desc      : Test IsDistributedEnableByBundle function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19400, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsDistributedEnableByBundle_0200 test start";

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    bool enabled = false;
    ASSERT_EQ(advancedNotificationService_->IsDistributedEnableByBundle(bundleOption, enabled), ERR_OK);

    GTEST_LOG_(INFO) << "IsDistributedEnableByBundle_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19500
 * @tc.name      : GetDeviceRemindType_0100
 * @tc.desc      : Test GetDeviceRemindType function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19500, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetDeviceRemindType_0100 test start";

    NotificationConstant::RemindType remindType = NotificationConstant::RemindType::DEVICE_ACTIVE_REMIND;
    ASSERT_EQ(advancedNotificationService_->GetDeviceRemindType(remindType), ERR_OK);

    GTEST_LOG_(INFO) << "GetDeviceRemindType_0100 test end";
}

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
/**
 * @tc.number    : AdvancedNotificationServiceTest_19600
 * @tc.name      : GetLocalNotificationKeys_0100
 * @tc.desc      : Test GetLocalNotificationKeys function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19600, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetLocalNotificationKeys_0100 test start";

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->GetLocalNotificationKeys(bundleOption);

    GTEST_LOG_(INFO) << "GetLocalNotificationKeys_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19700
 * @tc.name      : CheckDistributedNotificationType_0100
 * @tc.desc      : Test CheckDistributedNotificationType function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19700, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "CheckDistributedNotificationType_0100 test start";

    sptr<NotificationRequest> req = new NotificationRequest();
    ASSERT_EQ(advancedNotificationService_->CheckDistributedNotificationType(req), true);

    GTEST_LOG_(INFO) << "CheckDistributedNotificationType_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19800
 * @tc.name      : CheckDistributedNotificationType_0200
 * @tc.desc      : Test CheckDistributedNotificationType function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19800, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "CheckDistributedNotificationType_0200 test start";

    sptr<NotificationRequest> req = new NotificationRequest();
    std::vector<std::string> devices;
    devices.push_back("a");
    devices.push_back("b");
    devices.push_back("c");
    req->GetNotificationDistributedOptions().SetDevicesSupportDisplay(devices);
    ASSERT_EQ(advancedNotificationService_->CheckDistributedNotificationType(req), true);

    GTEST_LOG_(INFO) << "CheckDistributedNotificationType_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19900
 * @tc.name      : OnDistributedPublish_0100
 * @tc.desc      : Test OnDistributedPublish function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19900, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "CheckDistributedNotificationType_0100 test start";

    std::string deviceId = "DeviceId";
    std::string bundleName = "BundleName";
    sptr<NotificationRequest> request = new NotificationRequest();

    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->OnDistributedPublish(deviceId, bundleName, request);

    GTEST_LOG_(INFO) << "CheckDistributedNotificationType_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_20000
 * @tc.name      : OnDistributedUpdate_0100
 * @tc.desc      : Test OnDistributedUpdate function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_20000, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "OnDistributedUpdate_0100 test start";

    std::string deviceId = "DeviceId";
    std::string bundleName = "BundleName";
    sptr<NotificationRequest> request = new NotificationRequest();

    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->OnDistributedUpdate(deviceId, bundleName, request);

    GTEST_LOG_(INFO) << "OnDistributedUpdate_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_20100
 * @tc.name      : OnDistributedDelete_0100
 * @tc.desc      : Test OnDistributedDelete function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_20100, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "OnDistributedDelete_0100 test start";

    std::string deviceId = "DeviceId";
    std::string bundleName = "BundleName";
    std::string label = "testLabel";
    int32_t id = 1;

    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->OnDistributedDelete(deviceId, bundleName, label, id);

    GTEST_LOG_(INFO) << "OnDistributedDelete_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_20200
 * @tc.name      : CheckPublishWithoutApp_0100
 * @tc.desc      : Test CheckPublishWithoutApp function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_20200, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "CheckPublishWithoutApp_0100 test start";

    int32_t userId = 1;
    sptr<NotificationRequest> request = new NotificationRequest();
    ASSERT_EQ(advancedNotificationService_->CheckPublishWithoutApp(userId, request), false);

    GTEST_LOG_(INFO) << "CheckPublishWithoutApp_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_20300
 * @tc.name      : CheckPublishWithoutApp_0200
 * @tc.desc      : Test CheckPublishWithoutApp function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_20300, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "CheckPublishWithoutApp_0200 test start";

    int32_t userId = SYSTEM_APP_UID;
    sptr<NotificationRequest> request = new NotificationRequest();
    ASSERT_EQ(advancedNotificationService_->CheckPublishWithoutApp(userId, request), false);

    GTEST_LOG_(INFO) << "CheckPublishWithoutApp_0200 test end";
}
#endif

/**
 * @tc.number    : AdvancedNotificationServiceTest_20400
 * @tc.name      : TriggerRemoveWantAgent_0100
 * @tc.desc      : Test TriggerRemoveWantAgent function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_20400, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "TriggerRemoveWantAgent_0100 test start";

    sptr<NotificationRequest> request = new NotificationRequest();
    AbilityRuntime::WantAgent::WantAgentInfo paramsInfo;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(paramsInfo);

    request->SetRemovalWantAgent(wantAgent);
    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->TriggerRemoveWantAgent(request);

    GTEST_LOG_(INFO) << "TriggerRemoveWantAgent_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_20500
 * @tc.name      : DeleteAllByUser_0100
 * @tc.desc      : Test DeleteAllByUser function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_20500, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "DeleteAllByUser_0100 test start";

    int32_t userId = -2;
    ASSERT_EQ(advancedNotificationService_->DeleteAllByUser(userId), ERR_ANS_INVALID_PARAM);

    sptr<NotificationDoNotDisturbDate> date = nullptr;
    ASSERT_EQ(advancedNotificationService_->SetDoNotDisturbDate(userId, date), ERR_ANS_INVALID_PARAM);
    ASSERT_EQ(advancedNotificationService_->GetDoNotDisturbDate(userId, date), ERR_ANS_INVALID_PARAM);
    ASSERT_EQ(advancedNotificationService_->SetDoNotDisturbDateByUser(userId, date), ERR_ANS_INVALID_PARAM);
    GTEST_LOG_(INFO) << "DeleteAllByUser_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_20600
 * @tc.name      : OnResourceRemove_0100
 * @tc.desc      : Test OnResourceRemove function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_20600, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "OnResourceRemove_0100 test start";

    int32_t userId = -2;
    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->OnResourceRemove(userId);

    GTEST_LOG_(INFO) << "OnResourceRemove_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_20700
 * @tc.name      : OnBundleDataCleared_0100
 * @tc.desc      : Test OnBundleDataCleared function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_20700, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "OnBundleDataCleared_0100 test start";

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->OnBundleDataCleared(bundleOption);

    GTEST_LOG_(INFO) << "OnBundleDataCleared_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_20900
 * @tc.name      : GetDumpInfo_0100
 * @tc.desc      : Test GetDumpInfo function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_20900, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetDumpInfo_0100 test start";

    std::vector<std::u16string> args;
    args.push_back(Str8ToStr16("args"));
    std::string result = "result";
    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->GetDumpInfo(args, result);

    GTEST_LOG_(INFO) << "GetDumpInfo_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_21000
 * @tc.name      : GetDumpInfo_0200
 * @tc.desc      : Test GetDumpInfo function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21000, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetDumpInfo_0200 test start";

    std::vector<std::u16string> args;
    args.push_back(Str8ToStr16("-h"));
    std::string result = "result";
    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->GetDumpInfo(args, result);

    GTEST_LOG_(INFO) << "GetDumpInfo_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_21100
 * @tc.name      : SendFlowControlOccurHiSysEvent_0100
 * @tc.desc      : Test SendFlowControlOccurHiSysEvent function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21100, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "SendFlowControlOccurHiSysEvent_0100 test start";

    std::shared_ptr<NotificationRecord> record = nullptr;
    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->SendFlowControlOccurHiSysEvent(record);

    GTEST_LOG_(INFO) << "SendFlowControlOccurHiSysEvent_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_21200
 * @tc.name      : SendFlowControlOccurHiSysEvent_0200
 * @tc.desc      : Test SendFlowControlOccurHiSysEvent function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21200, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "SendFlowControlOccurHiSysEvent_0200 test start";

    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = new NotificationRequest();
    record->bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->SendFlowControlOccurHiSysEvent(record);

    GTEST_LOG_(INFO) << "SendFlowControlOccurHiSysEvent_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_21300
 * @tc.name      : PrepareNotificationRequest_0200
 * @tc.desc      : Test PrepareNotificationRequest function when uid < 0.
 * @tc.require   : issueI62D8C
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21300, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "PrepareNotificationRequest_0200 test start";
    sptr<NotificationRequest> req = new NotificationRequest();
    int32_t myNotificationId = 10;
    bool isAgentTrue = true;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetIsAgentNotification(isAgentTrue);

    std::shared_ptr<BundleManagerHelper> bundleManager = nullptr;

    ASSERT_EQ(advancedNotificationService_->PrepareNotificationRequest(req), ERR_OK);
    GTEST_LOG_(INFO) << "PrepareNotificationRequest_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_21400
 * @tc.name      : PrepareNotificationInfo_2000
 * @tc.desc      : Test PrepareNotificationInfo function.
 * @tc.require   : issueI62D8C
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21400, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "PrepareNotificationInfo_2000 test start";

    sptr<NotificationRequest> req = new (std::nothrow) NotificationRequest(1);
    EXPECT_NE(req, nullptr);
    sptr<NotificationBundleOption> bundleOption = nullptr;

    ASSERT_EQ(advancedNotificationService_->PrepareNotificationInfo(req, bundleOption), ERR_OK);

    GTEST_LOG_(INFO) << "PrepareNotificationInfo_2000 test end";
}



/**
 * @tc.number    : AdvancedNotificationServiceTest_21600
 * @tc.name      : RegisterPushCallback_0100
 * @tc.desc      : Test RegisterPushCallback function.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21600, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "RegisterPushCallback_0100 test start";

    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    sptr<IRemoteObject> pushCallback = pushCallbackProxy->AsObject();
    sptr<NotificationCheckRequest> checkRequest = new (std::nothrow) NotificationCheckRequest();
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    ASSERT_EQ(advancedNotificationService_->RegisterPushCallback(pushCallback, checkRequest), ERR_OK);

    advancedNotificationService_->UnregisterPushCallback();

    GTEST_LOG_(INFO) << "RegisterPushCallback_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_21700
 * @tc.name      : RegisterPushCallback_0200
 * @tc.desc      : Test RegisterPushCallback function.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21700, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "RegisterPushCallback_0200 test start";

    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    sptr<IRemoteObject> pushCallback = pushCallbackProxy->AsObject();
    sptr<NotificationCheckRequest> checkRequest = new (std::nothrow) NotificationCheckRequest();
    ASSERT_EQ(advancedNotificationService_->RegisterPushCallback(pushCallback, checkRequest),
        (int)ERR_OK);
    advancedNotificationService_->UnregisterPushCallback();


    GTEST_LOG_(INFO) << "RegisterPushCallback_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_21800
 * @tc.name      : RegisterPushCallback_0200
 * @tc.desc      : Test RegisterPushCallback function.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21800, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "RegisterPushCallback_0300 test start";

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    sptr<IRemoteObject> pushCallback = pushCallbackProxy->AsObject();
    sptr<IPushCallBack> pushCallBack = iface_cast<IPushCallBack>(pushCallback);
    sptr<NotificationCheckRequest> checkRequest = new (std::nothrow) NotificationCheckRequest();

    advancedNotificationService_->pushCallBacks_.insert_or_assign(checkRequest->GetSlotType(), pushCallBack);

    ASSERT_EQ(advancedNotificationService_->RegisterPushCallback(pushCallback, checkRequest), (int)ERR_OK);

    advancedNotificationService_->UnregisterPushCallback();

    GTEST_LOG_(INFO) << "RegisterPushCallback_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_21900
 * @tc.name      : UnregisterPushCallback_0100
 * @tc.desc      : Test UnregisterPushCallback function.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21900, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "UnregisterPushCallback_0100 test start";

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    sptr<IRemoteObject> pushCallback = pushCallbackProxy->AsObject();
    sptr<IPushCallBack> pushCallBack = iface_cast<IPushCallBack>(pushCallback);
    sptr<NotificationCheckRequest> checkRequest = new (std::nothrow) NotificationCheckRequest();

    advancedNotificationService_->pushCallBacks_.insert_or_assign(checkRequest->GetSlotType(), pushCallBack);

    ASSERT_EQ(advancedNotificationService_->UnregisterPushCallback(), ERR_OK);

    GTEST_LOG_(INFO) << "UnregisterPushCallback_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_22000
 * @tc.name      : UnregisterPushCallback_0200
 * @tc.desc      : Test UnregisterPushCallback function.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_22000, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "UnregisterPushCallback_0200 test start";
    ASSERT_EQ(advancedNotificationService_->UnregisterPushCallback(), (int)ERR_ANS_NON_SYSTEM_APP);

    GTEST_LOG_(INFO) << "UnregisterPushCallback_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_22100
 * @tc.name      : UnregisterPushCallback_0300
 * @tc.desc      : Test UnregisterPushCallback function.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_22100, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "UnregisterPushCallback_0300 test start";

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    ASSERT_EQ(advancedNotificationService_->UnregisterPushCallback(), (int)ERR_INVALID_OPERATION);

    GTEST_LOG_(INFO) << "UnregisterPushCallback_0300 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_22500
 * @tc.name      : PushCheck_0100
 * @tc.desc      : Test PushCheck function.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_22500, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "PushCheck_0100 test start";

    sptr<NotificationRequest> req = new (std::nothrow) NotificationRequest();
    ASSERT_EQ(advancedNotificationService_->PushCheck(req), ERR_ANS_PUSH_CHECK_UNREGISTERED);

    GTEST_LOG_(INFO) << "PushCheck_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_220000
 * @tc.name      : TimeToString_1000
 * @tc.desc      : Test TimeToString function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_220000, Function | SmallTest | Level1)
{
    int64_t time = 60;
    int64_t ret = 20;
    std::string result = advancedNotificationService_->TimeToString(time);
    ASSERT_EQ(result.size(), ret);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_22600
 * @tc.name      : ANS_IsNeedSilentInDoNotDisturbMode_0100
 * @tc.desc      : Test IsNeedSilentInDoNotDisturbMode function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_22600, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    std::string phoneNumber = "11111111111";
    int32_t callerType = 0;
    auto ret = advancedNotificationService_->IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType);
    ASSERT_EQ(ret, -1);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00001
 * @tc.name      : PrepareNotificationRequest
 * @tc.desc      : Test PrepareNotificationRequest function.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00001 test start";
    ASSERT_EQ(advancedNotificationService_->PrepareNotificationRequest(nullptr), ERR_ANS_INVALID_PARAM);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00001 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00002
 * @tc.name      : IsNotificationExists
 * @tc.desc      : Test IsNotificationExists function.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00002, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00002 test start";
    std::string key = "aa";
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    EXPECT_NE(request, nullptr);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    EXPECT_NE(notification, nullptr);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService_->IsNotificationExists(key), false);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00002 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00003
 * @tc.name      : UpdateInNotificationList
 * @tc.desc      : Test UpdateInNotificationList function and notificationList_ is not empty.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00003, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00003 test start";
    std::string key = "aa";
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    EXPECT_NE(request, nullptr);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    EXPECT_NE(notification, nullptr);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    advancedNotificationService_->UpdateInNotificationList(record);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00003 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00004
 * @tc.name      : SetBadgeNumber
 * @tc.desc      : Test SetBadgeNumber function and handler_ is nullptr.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00004, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00004 test start";
    int32_t badgeNumber = 1;
    ASSERT_EQ(advancedNotificationService_->SetBadgeNumber(badgeNumber, ""), ERR_OK);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00004 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00005
 * @tc.name      : SetBadgeNumber
 * @tc.desc      : Test SetBadgeNumber function and handler_ is not nullptr.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00005, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00005 test start";
    int32_t badgeNumber = 1;
    advancedNotificationService_->runner_ = OHOS::AppExecFwk::EventRunner::Create("NotificationSvrMain");
    advancedNotificationService_->handler_ =
        std::make_shared<OHOS::AppExecFwk::EventHandler>(advancedNotificationService_->runner_);
    ASSERT_EQ(advancedNotificationService_->SetBadgeNumber(badgeNumber, ""), ERR_OK);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00005 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00006
 * @tc.name      : ResetPushCallbackProxy
 * @tc.desc      : Test ResetPushCallbackProxy function and pushCallBack_ is nullptr.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00006, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00006 test start";
    EXPECT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->ResetPushCallbackProxy();
    ASSERT_EQ(advancedNotificationService_->pushCallBacks_.empty(), true);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00006 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00007
 * @tc.name      : ResetPushCallbackProxy
 * @tc.desc      : Test ResetPushCallbackProxy function and pushCallBack_ is not nullptr.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00007, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00007 test start";
    EXPECT_NE(advancedNotificationService_, nullptr);
    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    sptr<IRemoteObject> pushCallback = pushCallbackProxy->AsObject();
    sptr<IPushCallBack> pushCallBack = iface_cast<IPushCallBack>(pushCallback);
    sptr<NotificationCheckRequest> checkRequest = new (std::nothrow) NotificationCheckRequest();

    advancedNotificationService_->pushCallBacks_.insert_or_assign(checkRequest->GetSlotType(), pushCallBack);
    advancedNotificationService_->ResetPushCallbackProxy();
    ASSERT_TRUE(advancedNotificationService_->pushCallBacks_.empty());
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00007 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00008
 * @tc.name      : SendEnableNotificationSlotHiSysEvent
 * @tc.desc      : Test SendEnableNotificationSlotHiSysEvent function and bundleOption is nullptr.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00008, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00008 test start";
    sptr<NotificationBundleOption> bundleOption = nullptr;
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::CONTENT_INFORMATION;
    bool enabled = false;
    ErrCode errCode = ERR_OK;
    EXPECT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->SendEnableNotificationSlotHiSysEvent(bundleOption, slotType, enabled, errCode);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00008 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00009
 * @tc.name      : SendEnableNotificationSlotHiSysEvent
 * @tc.desc      : Test SendEnableNotificationSlotHiSysEvent function and errCode != ERR_OK.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00009, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00009 test start";
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::CONTENT_INFORMATION;
    bool enabled = false;
    ErrCode errCode = ERR_ANS_TASK_ERR;
    EXPECT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->SendEnableNotificationSlotHiSysEvent(bundleOption, slotType, enabled, errCode);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00009 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00010
 * @tc.name      : SendRemoveHiSysEvent
 * @tc.desc      : Test SendRemoveHiSysEvent function and errCode is ERR_OK bundleOption is not nullptr.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00010, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00010 test start";
    int32_t notificationId = 1;
    std::string label = "aa";
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    ErrCode errCode = ERR_OK;
    EXPECT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->SendRemoveHiSysEvent(notificationId, label, bundleOption, errCode);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00010 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00011
 * @tc.name      : SendEnableNotificationHiSysEvent
 * @tc.desc      : Test SendEnableNotificationHiSysEvent function andbundleOption is nullptr.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00011, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00011 test start";
    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool enabled = false;
    ErrCode errCode = ERR_ANS_TASK_ERR;
    EXPECT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->SendEnableNotificationHiSysEvent(bundleOption, enabled, errCode);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00011 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00012
 * @tc.name      : SendCancelHiSysEvent
 * @tc.desc      : Test SendCancelHiSysEvent function and errCode is ERR_OK bundleOption is not nullptr.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00012, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00012 test start";
    int32_t notificationId = 1;
    std::string label = "aa";
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    ErrCode errCode = ERR_OK;
    EXPECT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->SendCancelHiSysEvent(notificationId, label, bundleOption, errCode);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00012 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00013
 * @tc.name      : SendPublishHiSysEvent
 * @tc.desc      : Test SendPublishHiSysEvent function and request is nullptr.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00013, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00013 test start";
    sptr<NotificationRequest> request = nullptr;
    ErrCode errCode = ERR_OK;
    EXPECT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->SendPublishHiSysEvent(request, errCode);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00013 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00014
 * @tc.name      : GetTargetRecordList
 * @tc.desc      : Test GetTargetRecordList function and get empty.
 * @tc.require   : #I8B8PI
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00014, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00014 test start";
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = new NotificationRequest();
    record->bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    const int32_t uid = 0;
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    auto contentType = NotificationContent::Type::LOCAL_LIVE_VIEW;
    advancedNotificationService_->notificationList_.clear();
    std::vector<std::shared_ptr<NotificationRecord>> recordList;
    ASSERT_EQ(advancedNotificationService_->GetTargetRecordList(uid, slotType, contentType, recordList),
        ERR_ANS_NOTIFICATION_NOT_EXISTS);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00014 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00015
 * @tc.name      : GetTargetRecordList
 * @tc.desc      : Test GetTargetRecordList function and get success.
 * @tc.require   : #I8B8PI
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00015, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00015 test start";
    std::string bundleName = "testBundle";
    const int32_t uid = 0;
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    auto contentType = NotificationContent::Type::LOCAL_LIVE_VIEW;

    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    EXPECT_NE(request, nullptr);
    request->SetSlotType(slotType);
    auto liveContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    request->SetCreatorUid(uid);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    EXPECT_NE(notification, nullptr);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    std::vector<std::shared_ptr<NotificationRecord>> recordList;
    ASSERT_EQ(advancedNotificationService_->GetTargetRecordList(uid, slotType, contentType, recordList),
        ERR_OK);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00015 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00016
 * @tc.name      : RemoveNotificationFromRecordList
 * @tc.desc      : Test RemoveNotificationFromRecordList function and remove success.
 * @tc.require   : #I8B8PI
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00016, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00016 test start";
    std::string bundleName = "testBundle";
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    auto contentType = NotificationContent::Type::LOCAL_LIVE_VIEW;

    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    EXPECT_NE(request, nullptr);
    request->SetSlotType(slotType);
    auto liveContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    request->SetOwnerBundleName(bundleName);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    EXPECT_NE(notification, nullptr);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    std::vector<std::shared_ptr<NotificationRecord>> recordList;
    recordList.push_back(record);
    ASSERT_EQ(advancedNotificationService_->RemoveNotificationFromRecordList(recordList), ERR_OK);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00016 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00017
 * @tc.name      : RemoveSystemLiveViewNotifications
 * @tc.desc      : Test RemoveNotificationFromRecordList function and remove success.
 * @tc.require   : #I8B8PI
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00017, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00016 test start";
    std::string bundleName = "testBundle";
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    EXPECT_NE(request, nullptr);
    request->SetSlotType(slotType);
    auto liveContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    request->SetOwnerBundleName(bundleName);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    EXPECT_NE(notification, nullptr);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    int32_t uid = 0;
    ASSERT_EQ(advancedNotificationService_->RemoveSystemLiveViewNotifications(bundleName, uid), ERR_OK);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00017 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00018
 * @tc.name      : RemoveSystemLiveViewNotifications
 * @tc.desc      : Test RemoveNotificationFromRecordList function and remove success.
 * @tc.require   : #I8B8PI
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00018, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00018 test start";
    std::string bundleName = "testBundle";
    int32_t uid = 0;
    ASSERT_EQ(advancedNotificationService_->RemoveSystemLiveViewNotifications(bundleName, uid),
        ERR_ANS_NOTIFICATION_NOT_EXISTS);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00018 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00019
 * @tc.name      : RemoveSystemLiveViewNotifications
 * @tc.desc      : Test RemoveNotificationFromRecordList function and remove success.
 * @tc.require   : #I8B8PI
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00019, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00019 test start";
    std::string bundleName = "testBundle";
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    EXPECT_NE(request, nullptr);
    request->SetSlotType(slotType);
    auto liveContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    request->SetOwnerBundleName(bundleName);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    EXPECT_NE(notification, nullptr);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    int32_t uid = 0;
    ASSERT_EQ(advancedNotificationService_->RemoveSystemLiveViewNotifications(bundleName, uid), ERR_ANS_INVALID_PARAM);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00019 test end";
}
/**
 * @tc.number    : IsLiveViewCanRecoverTest_0001
 * @tc.name      : IsLiveViewCanRecover
 * @tc.desc      : Test IsLiveViewCanRecover and liveview is nullptr.
 */
HWTEST_F(AdvancedNotificationServiceTest, IsLiveViewCanRecoverTest_0001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsLiveViewCanRecoverTest_0001 test start";
    ASSERT_EQ(advancedNotificationService_->IsLiveViewCanRecover(nullptr), false);
    GTEST_LOG_(INFO) << "IsLiveViewCanRecoverTest_0001 test end";
}

/**
 * @tc.number    : IsLiveViewCanRecoverTest_0002
 * @tc.name      : IsLiveViewCanRecover
 * @tc.desc      : Test IsLiveViewCanRecover and liveview status is invalid.
 */
HWTEST_F(AdvancedNotificationServiceTest, IsLiveViewCanRecoverTest_0002, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsLiveViewCanRecoverTest_0002 test start";
    sptr<NotificationRequest> request = new NotificationRequest();
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    request->SetContent(content);

    ASSERT_EQ(advancedNotificationService_->IsLiveViewCanRecover(request), false);
    GTEST_LOG_(INFO) << "IsLiveViewCanRecoverTest_0002 test end";
}

/**
 * @tc.number    : IsLiveViewCanRecoverTest_0003
 * @tc.name      : IsLiveViewCanRecover
 * @tc.desc      : Test IsLiveViewCanRecover and liveview is expired.
 */
HWTEST_F(AdvancedNotificationServiceTest, IsLiveViewCanRecoverTest_0003, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsLiveViewCanRecoverTest_0003 test start";
    sptr<NotificationRequest> request = new NotificationRequest();
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    request->SetContent(content);
    request->SetFinishDeadLine(0);

    ASSERT_EQ(advancedNotificationService_->IsLiveViewCanRecover(request), false);
    GTEST_LOG_(INFO) << "IsLiveViewCanRecoverTest_0003 test end";
}

/**
 * @tc.number    : IsLiveViewCanRecoverTest_0004
 * @tc.name      : IsLiveViewCanRecover
 * @tc.desc      : Test IsLiveViewCanRecover and liveview status is create and not expired.
 */
HWTEST_F(AdvancedNotificationServiceTest, IsLiveViewCanRecoverTest_0004, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsLiveViewCanRecoverTest_0004 test start";
    sptr<NotificationRequest> request = new NotificationRequest();
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    request->SetContent(content);

    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    request->SetFinishDeadLine(duration.count() + NotificationConstant::MAX_FINISH_TIME);
    request->SetUpdateDeadLine(duration.count() + NotificationConstant::MAX_UPDATE_TIME);

    ASSERT_EQ(advancedNotificationService_->IsLiveViewCanRecover(request), true);
    GTEST_LOG_(INFO) << "IsLiveViewCanRecoverTest_0004 test end";
}

/**
 * @tc.number    : FillNotificationRecordTest_0001
 * @tc.name      : FillNotificationRecord
 * @tc.desc      : Test FillNotificationRecord and request is nullptr.
 */
HWTEST_F(AdvancedNotificationServiceTest, FillNotificationRecordTest_0001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FillNotificationRecordTest_0001 test start";
    AdvancedNotificationService::NotificationRequestDb requestDbObj = { .request = nullptr, .bundleOption = nullptr};
    auto record = std::make_shared<NotificationRecord>();

    EXPECT_NE(advancedNotificationService_->FillNotificationRecord(requestDbObj, record), ERR_OK);
    GTEST_LOG_(INFO) << "FillNotificationRecordTest_0001 test end";
}

/**
 * @tc.number    : FillNotificationRecordTest_0002
 * @tc.name      : FillNotificationRecord
 * @tc.desc      : Test FillNotificationRecord and request/bundleOption is valid.
 */
HWTEST_F(AdvancedNotificationServiceTest, FillNotificationRecordTest_0002, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FillNotificationRecordTest_0002 test start";
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    std::string bundleName = "BundleName";
    int32_t uid = 10;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(bundleName, uid);
    AdvancedNotificationService::NotificationRequestDb requestDbObj =
        { .request = request, .bundleOption = bundleOption };
    auto record = std::make_shared<NotificationRecord>();

    ASSERT_EQ(advancedNotificationService_->FillNotificationRecord(requestDbObj, record), ERR_OK);
    GTEST_LOG_(INFO) << "FillNotificationRecordTest_0002 test end";
}

/**
 * @tc.number    : RecoverLiveViewFromDb_0002
 * @tc.name      : RecoverLiveViewFromDb
 * @tc.desc      : Test RecoverLiveViewFromDb and liveView can't recover from db.
 */
HWTEST_F(AdvancedNotificationServiceTest, RecoverLiveViewFromDb_0002, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "RecoverLiveViewFromDb_0002 test start";
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest(1);
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    request->SetContent(content);
    request->SetCreatorUid(1);
    request->SetCreatorUserId(2);
    request->SetLabel("test_2");

    std::string bundleName = "BundleName_02";
    int32_t uid = 11;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(bundleName, uid);
    AdvancedNotificationService::NotificationRequestDb requestDbObj =
        { .request = request, .bundleOption = bundleOption };
    auto result = advancedNotificationService_->SetNotificationRequestToDb(requestDbObj);
    ASSERT_EQ(result, ERR_OK);

    advancedNotificationService_->RecoverLiveViewFromDb();
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);

    result = advancedNotificationService_->DeleteNotificationRequestFromDb(request->GetKey(), 0);
    ASSERT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RecoverLiveViewFromDb_0002 test end";
}

/**
 * @tc.number    : IsNeedPushCheckTest_0001
 * @tc.name      : IsNeedPushCheckTest
 * @tc.desc      : Test live view notification need pushCheck.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedPushCheckTest_0001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0001 test start";
    sptr<NotificationRequest> request = new NotificationRequest();
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto status = NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE;
    liveViewContent->SetLiveViewStatus(status);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    ASSERT_EQ(advancedNotificationService_->IsNeedPushCheck(request), true);

    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0001 test end";
}

/**
 * @tc.number    : IsNeedPushCheckTest_0002
 * @tc.name      : IsNeedPushCheckTest
 * @tc.desc      : Test notification except live view registered need push check.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedPushCheckTest_0002, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0002 test start";

    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    sptr<IRemoteObject> pushCallback = pushCallbackProxy->AsObject();
    sptr<IPushCallBack> pushCallBack = iface_cast<IPushCallBack>(pushCallback);

    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);

    advancedNotificationService_->pushCallBacks_.clear();
    advancedNotificationService_->checkRequests_.clear();
    sptr<NotificationCheckRequest> notificationCheckRequest = new (std::nothrow)NotificationCheckRequest();
    notificationCheckRequest->SetSlotType(NotificationConstant::SlotType::CUSTOM);
    notificationCheckRequest->SetContentType(NotificationContent::Type::BASIC_TEXT);
    advancedNotificationService_->pushCallBacks_.insert_or_assign(
        notificationCheckRequest->GetSlotType(), pushCallBack);
    advancedNotificationService_->checkRequests_.insert_or_assign(
        notificationCheckRequest->GetSlotType(), notificationCheckRequest);

    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::CUSTOM);
    ASSERT_EQ(advancedNotificationService_->IsNeedPushCheck(request), true);
    advancedNotificationService_->pushCallBacks_.clear();
    advancedNotificationService_->checkRequests_.clear();

    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0002 test end";
}

/**
 * @tc.number    : IsNeedPushCheckTest_0003
 * @tc.name      : IsNeedPushCheckTest
 * @tc.desc      : Test notification except live view unregistered don't need push check.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedPushCheckTest_0003, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0003 test start";
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::CUSTOM);
    ASSERT_EQ(advancedNotificationService_->IsNeedPushCheck(request), false);

    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0003 test end";
}

/**
 * @tc.number    : IsNeedPushCheckTest_0004
 * @tc.name      : IsNeedPushCheckTest
 * @tc.desc      : Test notification published by system app don't need push check.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedPushCheckTest_0004, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0004 test start";

    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::CUSTOM);
    ASSERT_EQ(advancedNotificationService_->IsNeedPushCheck(request), false);

    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0004 test end";
}

/**
 * @tc.number    : IsNeedPushCheckTest_0005
 * @tc.name      : IsNeedPushCheckTest
 * @tc.desc      : Test live view notification except create status don't need pushCheck.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedPushCheckTest_0005, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0005 test start";
    sptr<NotificationRequest> request = new NotificationRequest();
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto status = NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE;
    liveViewContent->SetLiveViewStatus(status);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    ASSERT_EQ(advancedNotificationService_->IsNeedPushCheck(request), false);

    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0005 test end";
}

/**
 * @tc.number    : IsNeedPushCheckTest_0006
 * @tc.name      : IsNeedPushCheckTest
 * @tc.desc      : Test notification except live view registered but has inconsistent contentType dont't need push check.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedPushCheckTest_0006, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0006 test start";

    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    sptr<IRemoteObject> pushCallback = pushCallbackProxy->AsObject();
    sptr<IPushCallBack> pushCallBack = iface_cast<IPushCallBack>(pushCallback);

    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);

    sptr<NotificationCheckRequest> notificationCheckRequest = new (std::nothrow)NotificationCheckRequest();
    notificationCheckRequest->SetSlotType(NotificationConstant::SlotType::CUSTOM);
    notificationCheckRequest->SetContentType(NotificationContent::Type::PICTURE);
    advancedNotificationService_->pushCallBacks_.insert_or_assign(
        notificationCheckRequest->GetSlotType(), pushCallBack);
    advancedNotificationService_->checkRequests_.insert_or_assign(
        notificationCheckRequest->GetSlotType(), notificationCheckRequest);

    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::CUSTOM);
    ASSERT_EQ(advancedNotificationService_->IsNeedPushCheck(request), false);
    advancedNotificationService_->pushCallBacks_.clear();
    advancedNotificationService_->checkRequests_.clear();

    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0006 test end";
}
/**
 * @tc.number    : PushCheckTest_0001
 * @tc.name      : PushCheckTest
 * @tc.desc      : Test registerer of push check is allowed.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, PushCheckTest_0001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "PushCheckTest_0001 test start";

    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    sptr<IRemoteObject> pushCallback = pushCallbackProxy->AsObject();
    sptr<NotificationCheckRequest> notificationCheckRequest = new (std::nothrow)NotificationCheckRequest();
    notificationCheckRequest->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<IPushCallBack> pushCallBack = iface_cast<IPushCallBack>(pushCallback);
    advancedNotificationService_->pushCallBacks_.insert_or_assign(
        notificationCheckRequest->GetSlotType(), pushCallBack);
    advancedNotificationService_->checkRequests_.insert_or_assign(
        notificationCheckRequest->GetSlotType(), notificationCheckRequest);

    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);

    ASSERT_EQ(advancedNotificationService_->PushCheck(request), ERR_OK);

    advancedNotificationService_->pushCallBacks_.clear();
    advancedNotificationService_->checkRequests_.clear();

    GTEST_LOG_(INFO) << "PushCheckTest_0001 test end";
}

/**
 * @tc.number    : GetActiveNotificationByFilter_0001
 * @tc.name      : GetActiveNotificationByFilter
 * @tc.desc      : Test get non-existent live view notification request by filter.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, GetActiveNotificationByFilter_0001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetActiveNotificationByFilter_0001 test start";

    TestAddSlot(NotificationConstant::SlotType::LIVE_VIEW);
    sptr<NotificationRequest> req;

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    int32_t notificationId = 1;
    std::string label = "GetActiveNotificationByFilter's label";
    std::vector<std::string> extraInfoKeys;

    ASSERT_EQ(advancedNotificationService_->GetActiveNotificationByFilter(bundleOption, notificationId, label,
        extraInfoKeys, req), (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);

    GTEST_LOG_(INFO) << "GetActiveNotificationByFilter_0001 test end";
}

/**
 * @tc.number    : IsAllowedRemoveSlot_0001
 * @tc.name      : IsAllowedRemoveSlot
 * @tc.desc      : Test IsAllowedRemoveSlot and slotType is not liveView.
 */
HWTEST_F(AdvancedNotificationServiceTest, IsAllowedRemoveSlot_0001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0001 test start";
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    ASSERT_EQ(advancedNotificationService_->IsAllowedRemoveSlot(bundleOption, NotificationConstant::SlotType::OTHER),
        (int)ERR_OK);
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0001 test end";
}

/**
 * @tc.number    : IsAllowedRemoveSlot_0002
 * @tc.name      : IsAllowedRemoveSlot
 * @tc.desc      : Test IsAllowedRemoveSlot and slot is not exist.
 */
HWTEST_F(AdvancedNotificationServiceTest, IsAllowedRemoveSlot_0002, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0002 test start";
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    ASSERT_EQ(advancedNotificationService_->IsAllowedRemoveSlot(bundleOption,
        NotificationConstant::SlotType::LIVE_VIEW), (int)ERR_OK);
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0002 test end";
}

/**
 * @tc.number    : IsAllowedRemoveSlot_0003
 * @tc.name      : IsAllowedRemoveSlot
 * @tc.desc      : Test IsAllowedRemoveSlot and slot is forcecontrol is false
 */
HWTEST_F(AdvancedNotificationServiceTest, IsAllowedRemoveSlot_0003, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0003 test start";
    TestAddLiveViewSlot(false);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    ASSERT_EQ(advancedNotificationService_->IsAllowedRemoveSlot(bundleOption,
        NotificationConstant::SlotType::LIVE_VIEW), (int)ERR_OK);
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0003 test end";
}

/**
 * @tc.number    : IsAllowedRemoveSlot_0004
 * @tc.name      : IsAllowedRemoveSlot
 * @tc.desc      : Test IsAllowedRemoveSlot and caller not sa or systemapp
 */
HWTEST_F(AdvancedNotificationServiceTest, IsAllowedRemoveSlot_0004, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0004 test start";
    TestAddLiveViewSlot(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    ASSERT_EQ(advancedNotificationService_->IsAllowedRemoveSlot(bundleOption,
        NotificationConstant::SlotType::LIVE_VIEW), (int)ERR_ANS_NON_SYSTEM_APP);
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0004 test end";
}

/**
 * @tc.number    : IsAllowedRemoveSlot_0005
 * @tc.name      : IsAllowedRemoveSlot
 * @tc.desc      : Test IsAllowedRemoveSlot and caller is systemapp
 */
HWTEST_F(AdvancedNotificationServiceTest, IsAllowedRemoveSlot_0005, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0005 test start";
    TestAddLiveViewSlot(true);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    ASSERT_EQ(advancedNotificationService_->IsAllowedRemoveSlot(bundleOption,
        NotificationConstant::SlotType::LIVE_VIEW), (int)ERR_OK);
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0005 test end";
}

/**
 * @tc.name: NotificationSvrQueue_00001
 * @tc.desc: Test notificationSvrQueue is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, NotificationSvrQueue_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto request = new (std::nothrow) NotificationRequest();

    auto ret = advancedNotificationService_->CancelPreparedNotification(1, "label", bundle, 8);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    std::vector<sptr<NotificationRequest>> requests;
    ret = advancedNotificationService_->GetActiveNotifications(requests, "");
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    uint64_t num = 0;
    ret = advancedNotificationService_->GetActiveNotificationNums(num);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    int importance = 0;
    ret = advancedNotificationService_->GetBundleImportance(importance);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    std::vector<sptr<Notification>> notifications;
    ret = advancedNotificationService_->GetAllActiveNotifications(notifications);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    std::vector<std::string> keys;
    ret = advancedNotificationService_->GetSpecialActiveNotifications(keys, notifications);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    bool enabled = false;
    ret = advancedNotificationService_->IsDistributedEnabled(enabled);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->EnableDistributed(enabled);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: NotificationSvrQueue_00002
 * @tc.desc: Test notificationSvrQueue is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, NotificationSvrQueue_00002, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    sptr<NotificationBundleOption> bundle1 = nullptr;
    auto request = new (std::nothrow) NotificationRequest();

    auto ret = advancedNotificationService_->EnableDistributedSelf(true);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    bool enable = false;
    ret = advancedNotificationService_->IsDistributedEnableByBundle(bundle, enable);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->GetHasPoppedDialog(bundle1, enable);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->SetSyncNotificationEnabledWithoutApp(1, enable);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->GetSyncNotificationEnabledWithoutApp(1, enable);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    request->SetIsCoverActionButtons(true);
    advancedNotificationService_->FillActionButtons(request);
}

/**
 * @tc.name: AssignToNotificationList_00001
 * @tc.desc: Test AssignToNotificationList
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, AssignToNotificationList_00001, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    auto ret = advancedNotificationService_->AssignToNotificationList(record);

    ret = advancedNotificationService_->AssignToNotificationList(record);
    ASSERT_EQ(ret, (int)ERR_OK);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);
}

/**
 * @tc.name: AssignToNotificationList_00002
 * @tc.desc: Test AssignToNotificationList when NotificationRequest's updateOnly is true but notification ID not exists
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, AssignToNotificationList_00002, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetUpdateOnly(true);
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    auto ret = advancedNotificationService_->AssignToNotificationList(record);

    ASSERT_EQ(ret, (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);
    advancedNotificationService_->notificationList_.clear();
}

/**
 * @tc.name: AssignToNotificationList_00003
 * @tc.desc: Test AssignToNotificationList when NotificationRequest's updateOnly is true and notification ID exists
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, AssignToNotificationList_00003, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetUpdateOnly(true);
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->notificationList_.push_back(record);
    auto ret = advancedNotificationService_->AssignToNotificationList(record);

    ASSERT_EQ(ret, (int)ERR_OK);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);
    advancedNotificationService_->notificationList_.clear();
}

/**
 * @tc.name: StartArchiveTimer_00001
 * @tc.desc: Test StartArchiveTimer
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, StartArchiveTimer_00001, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetAutoDeletedTime(NotificationConstant::NO_DELAY_DELETE_TIME);
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->StartArchiveTimer(record);
    ASSERT_EQ(request->GetAutoDeletedTime(), 0);
}

/**
 * @tc.name: Filter_00001
 * @tc.desc: Test Filter
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, Filter_00001, Function | SmallTest | Level1)
{
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto request = new (std::nothrow) NotificationRequest();
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    advancedNotificationService_->notificationSlotFilter_ = nullptr;
    auto ret = advancedNotificationService_->Filter(record, true);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: ChangeNotificationByControlFlags_00001
 * @tc.desc: Test ChangeNotificationByControlFlags
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, ChangeNotificationByControlFlags_00001, Function | SmallTest | Level1)
{
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto request = new (std::nothrow) NotificationRequest();
    uint32_t notificationControlFlags = 0;
    notificationControlFlags |= NotificationConstant::ReminderFlag::SOUND_FLAG;
    notificationControlFlags |= NotificationConstant::ReminderFlag::LOCKSCREEN_FLAG;
    notificationControlFlags |= NotificationConstant::ReminderFlag::BANNER_FLAG;
    notificationControlFlags |= NotificationConstant::ReminderFlag::LIGHTSCREEN_FLAG;
    notificationControlFlags |= NotificationConstant::ReminderFlag::VIBRATION_FLAG;
    notificationControlFlags |= NotificationConstant::ReminderFlag::STATUSBAR_ICON_FLAG;
    request->SetNotificationControlFlags(notificationControlFlags);

    std::shared_ptr<NotificationFlags> flags = std::make_shared<NotificationFlags>();
    flags->SetSoundEnabled(NotificationConstant::FlagStatus::OPEN);
    flags->SetVibrationEnabled(NotificationConstant::FlagStatus::OPEN);
    flags->SetLockScreenVisblenessEnabled(true);
    flags->SetBannerEnabled(true);
    flags->SetLightScreenEnabled(true);
    flags->SetStatusIconEnabled(true);
    request->SetFlags(flags);

    bool isAgentController = true;
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->ChangeNotificationByControlFlags(record, isAgentController);

    u_int32_t reminderFlags = flags->GetReminderFlags();
    ASSERT_EQ(reminderFlags, 0);
}

/**
 * @tc.name: CheckPublishPreparedNotification_00001
 * @tc.desc: Test CheckPublishPreparedNotification
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, CheckPublishPreparedNotification_00001, Function | SmallTest | Level1)
{
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto request = new (std::nothrow) NotificationRequest();
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    auto ret = advancedNotificationService_->CheckPublishPreparedNotification(record, true);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: GetRecordFromNotificationList_00001
 * @tc.desc: Test GetRecordFromNotificationList
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, GetRecordFromNotificationList_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    request->SetLabel("label");
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    auto ret = advancedNotificationService_->AssignToNotificationList(record);

    auto res = advancedNotificationService_->GetRecordFromNotificationList(
        1, SYSTEM_APP_UID, "label", TEST_DEFUALT_BUNDLE);
    EXPECT_NE(res, nullptr);
}

/**
 * @tc.name: RegisterPushCallback_00001
 * @tc.desc: Test RegisterPushCallback
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, RegisterPushCallback_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    sptr<IRemoteObject> pushCallback = nullptr;
    sptr<NotificationCheckRequest> request = nullptr;

    auto ret = advancedNotificationService_->RegisterPushCallback(pushCallback, request);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);

    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->RegisterPushCallback(pushCallback, request);
    ASSERT_EQ(ret, (int)ERR_INVALID_VALUE);

    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    pushCallback = pushCallbackProxy->AsObject();
    ret = advancedNotificationService_->RegisterPushCallback(pushCallback, request);
    ASSERT_EQ(ret, (int)ERR_INVALID_VALUE);
}

/**
 * @tc.name: UnregisterPushCallback_00001
 * @tc.desc: Test UnregisterPushCallback
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, UnregisterPushCallback_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    auto ret = advancedNotificationService_->UnregisterPushCallback();
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: CreateDialogManager_00001
 * @tc.desc: Test CreateDialogManager
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, CreateDialogManager_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->dialogManager_ = nullptr;
    bool ret = advancedNotificationService_->CreateDialogManager();
    ASSERT_EQ(ret, true);

    ret = advancedNotificationService_->CreateDialogManager();
    ASSERT_EQ(ret, true);
}

/**
 * @tc.number    : IsNeedNotifyConsumed_00001
 * @tc.name      : IsNeedNotifyConsumed
 * @tc.desc      : Test IsNeedNotifyConsumed function.
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedNotifyConsumed_00001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsNeedNotifyConsumed_00001 test start";
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    ASSERT_EQ(advancedNotificationService_->IsNeedNotifyConsumed(request), true);
    GTEST_LOG_(INFO) << "IsNeedNotifyConsumed_00001 test end";
}

/**
 * @tc.number    : IsNeedNotifyConsumed_00002
 * @tc.name      : IsNeedNotifyConsumed
 * @tc.desc      : Test IsNeedNotifyConsumed function.
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedNotifyConsumed_00002, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsNeedNotifyConsumed_00002 test start";
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    ASSERT_EQ(advancedNotificationService_->IsNeedNotifyConsumed(request), true);
    GTEST_LOG_(INFO) << "IsNeedNotifyConsumed_00002 test end";
}

/**
 * @tc.number    : GetAllNotificationEnabledBundles_0001
 * @tc.name      : GetAllNotificationEnabledBundles
 * @tc.desc      : Test GetAllNotificationEnabledBundles function if not systemapp.
 * @tc.require   : #I92VGR
 */
HWTEST_F(AdvancedNotificationServiceTest, GetAllNotificationEnabledBundles_0001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetAllNotificationEnabledBundles_0001 test start";

    std::vector<NotificationBundleOption> vec;
    ASSERT_EQ(advancedNotificationService_->GetAllNotificationEnabledBundles(vec), ERR_ANS_NON_SYSTEM_APP);

    GTEST_LOG_(INFO) << "GetAllNotificationEnabledBundles_0001 test end";
}

/**
 * @tc.number    : IsNeedNotifyConsumed_00003
 * @tc.name      : IsNeedNotifyConsumed
 * @tc.desc      : Test IsNeedNotifyConsumed function.
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedNotifyConsumed_00003, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsNeedNotifyConsumed_00003 test start";
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetAutoDeletedTime(0);
    ASSERT_EQ(advancedNotificationService_->IsNeedNotifyConsumed(request), false);
    GTEST_LOG_(INFO) << "IsNeedNotifyConsumed_00003 test end";
}

/**
 * @tc.number    : SetBadgeNumberByBundle_00001
 * @tc.name      : SetBadgeNumberByBundle
 * @tc.desc      : Test SetBadgeNumberByBundle with valid parameters, expect error code ERR_OK.
 */
HWTEST_F(AdvancedNotificationServiceTest, SetBadgeNumberByBundle_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    ASSERT_NE(bundleOption, nullptr);
    std::string bundleName = "invalidBundleName";
    bundleOption->SetBundleName(bundleName);
    int32_t badgeNumber = 1;
    ASSERT_EQ(advancedNotificationService_->SetBadgeNumberByBundle(bundleOption, badgeNumber), ERR_OK);
}

/**
 * @tc.number    : SetBadgeNumberByBundle_00002
 * @tc.name      : SetBadgeNumberByBundle
 * @tc.desc      : Test SetBadgeNumberByBundle with nullptr bundle option, expect error code ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(AdvancedNotificationServiceTest, SetBadgeNumberByBundle_00002, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    MockIsSystemApp(true);
    sptr<NotificationBundleOption> bundleOption = nullptr;
    int32_t badgeNumber = 1;
    ASSERT_EQ(advancedNotificationService_->SetBadgeNumberByBundle(bundleOption, badgeNumber), ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: QueryDoNotDisturbProfile_0100
 * @tc.desc: test QueryDoNotDisturbProfile successfully called
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, QueryDoNotDisturbProfile_0100, TestSize.Level1)
{
    std::string enable;
    std::string profileId;
    int32_t userId = 100;
    EXPECT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->QueryDoNotDisturbProfile(userId, enable, profileId);
}

/**
 * @tc.name: CheckDoNotDisturbProfile_0100
 * @tc.desc: test CheckDoNotDisturbProfile successfully called
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, CheckDoNotDisturbProfile_0100, TestSize.Level1)
{
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto request = new (std::nothrow) NotificationRequest();
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    EXPECT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->CheckDoNotDisturbProfile(record);
}

/**
 * @tc.name: DoNotDisturbUpdataReminderFlags_0100
 * @tc.desc: test DoNotDisturbUpdataReminderFlags can turn off all reminders.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, DoNotDisturbUpdataReminderFlags_0100, TestSize.Level1)
{
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto request = new (std::nothrow) NotificationRequest();
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    std::shared_ptr<NotificationFlags> flagsSet = std::make_shared<NotificationFlags>();
    record->request->SetFlags(flagsSet);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->DoNotDisturbUpdataReminderFlags(record);
    auto flags = record->request->GetFlags();
    EXPECT_NE(flags, nullptr);
    auto res = flags->IsStatusIconEnabled();
    ASSERT_EQ(res, false);
}

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
/**
 * @tc.name: RegisterSwingCallback_00001
 * @tc.desc: Test RegisterSwingCallback
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, RegisterSwingCallback_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    sptr<IRemoteObject> swingCallback = nullptr;
    auto ret = advancedNotificationService_->RegisterSwingCallback(swingCallback);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: RegisterSwingCallback_00002
 * @tc.desc: Test RegisterSwingCallback
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, RegisterSwingCallback_00002, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    MockIsVerfyPermisson(true);
    sptr<IRemoteObject> swingCallback = nullptr;
    auto ret = advancedNotificationService_->RegisterSwingCallback(swingCallback);
    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}
#endif

/**
 * @tc.number    : PublishFlowControl_00001
 * @tc.name      : Test PublishFlowControl
 * @tc.desc      : Test PublishFlowControl function when the record->slot is nullptr
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, PublishInNotificationList_00001, Function | SmallTest | Level1)
{
    for (int i = 0; i < 100; i++) {
        sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
        sptr<Notification> notification = new (std::nothrow) Notification(request);
        auto record = std::make_shared<NotificationRecord>();
        record->request = request;
        record->notification = notification;
        advancedNotificationService_->notificationList_.push_back(record);
    }
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 100);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->PublishInNotificationList(record);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 100);
}

/**
 * @tc.number    : PublishGlobalFlowCtrl_00001
 * @tc.name      : Test PublishGlobalFlowCtrl
 * @tc.desc      : Test PublishGlobalFlowCtrl
 */
HWTEST_F(AdvancedNotificationServiceTest, PublishGlobalFlowCtrl_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->flowControlPublishTimestampList_.clear();
    advancedNotificationService_->systemFlowControlPublishTimestampList_.clear();
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    record->isThirdparty = false;
    record->isNeedFlowCtrl = true;
    ErrCode result = ERR_OK;
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    for (int i = 0; i < advancedNotificationService_->maxCreateNumPerSecond; i++) {
        result = advancedNotificationService_->PublishGlobalFlowCtrl(record, now);
        advancedNotificationService_->systemFlowControlPublishTimestampList_.push_back(now);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = advancedNotificationService_->PublishGlobalFlowCtrl(record, now);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);

    record->isThirdparty = true;
    for (int i = 0; i < advancedNotificationService_->maxCreateNumPerSecond; i++) {
        result = advancedNotificationService_->PublishGlobalFlowCtrl(record, now);
        advancedNotificationService_->flowControlPublishTimestampList_.push_back(now);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = advancedNotificationService_->PublishGlobalFlowCtrl(record, now);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);

    advancedNotificationService_->flowControlPublishTimestampList_.clear();
    advancedNotificationService_->systemFlowControlPublishTimestampList_.clear();
}

/**
 * @tc.number    : PublishSingleAppFlowCtrl_00001
 * @tc.name      : Test PublishSingleAppFlowCtrl
 * @tc.desc      : Test PublishSingleAppFlowCtrl
 */
HWTEST_F(AdvancedNotificationServiceTest, PublishSingleAppFlowCtrl_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->singleAppFlowControlPublishTimestampMap_.clear();
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    record->isNeedFlowCtrl = true;
    ErrCode result = ERR_OK;
    const int32_t callingUid = DEFAULT_UID;
    advancedNotificationService_->singleAppFlowControlPublishTimestampMap_[callingUid] =
        std::make_shared<std::list<std::chrono::system_clock::time_point>>();
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    for (int i = 0; i < advancedNotificationService_->maxCreateNumPerSecondPerApp; i++) {
        result = advancedNotificationService_->PublishSingleAppFlowCtrl(record, now, callingUid);
        advancedNotificationService_->singleAppFlowControlPublishTimestampMap_[callingUid]->push_back(now);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = advancedNotificationService_->PublishSingleAppFlowCtrl(record, now, callingUid);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);

    advancedNotificationService_->singleAppFlowControlPublishTimestampMap_.clear();
}

/**
 * @tc.number    : PublishSingleAppFlowCtrlRemoveExpire_00001
 * @tc.name      : Test PublishSingleAppFlowCtrlRemoveExpire
 * @tc.desc      : Test PublishSingleAppFlowCtrlRemoveExpire
 */
HWTEST_F(AdvancedNotificationServiceTest, PublishSingleAppFlowCtrlRemoveExpire_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->singleAppFlowControlPublishTimestampMap_.clear();

    int32_t callingUid = DEFAULT_UID;
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    advancedNotificationService_->singleAppFlowControlPublishTimestampMap_[callingUid] =
        std::make_shared<std::list<std::chrono::system_clock::time_point>>();
    advancedNotificationService_->singleAppFlowControlPublishTimestampMap_[callingUid]->push_back(now);
    callingUid = NON_SYSTEM_APP_UID;
    advancedNotificationService_->singleAppFlowControlPublishTimestampMap_[callingUid] =
        std::make_shared<std::list<std::chrono::system_clock::time_point>>();
    now = now + SINGLE_APP_FLOW_CONTRL_EXPIRE_TIME;
    advancedNotificationService_->singleAppFlowControlPublishTimestampMap_[callingUid]->push_back(now);
    now = now + SINGLE_APP_FLOW_CONTRL_EXPIRE_TIME;
    ASSERT_EQ(advancedNotificationService_->singleAppFlowControlPublishTimestampMap_.size(), 2);
    advancedNotificationService_->PublishSingleAppFlowCtrlRemoveExpire(now);
    ASSERT_EQ(advancedNotificationService_->singleAppFlowControlPublishTimestampMap_.size(), 1);
    now = now + SINGLE_APP_FLOW_CONTRL_EXPIRE_TIME;
    advancedNotificationService_->PublishSingleAppFlowCtrlRemoveExpire(now);
    ASSERT_EQ(advancedNotificationService_->singleAppFlowControlPublishTimestampMap_.size(), 0);

    advancedNotificationService_->singleAppFlowControlPublishTimestampMap_.clear();
}

/**
 * @tc.number    : PublishFlowCtrl_00001
 * @tc.name      : Test PublishFlowCtrl
 * @tc.desc      : Test PublishFlowCtrl
 */
HWTEST_F(AdvancedNotificationServiceTest, PublishFlowCtrl_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->flowControlPublishTimestampList_.clear();
    advancedNotificationService_->systemFlowControlPublishTimestampList_.clear();
    advancedNotificationService_->singleAppFlowControlPublishTimestampMap_.clear();
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    record->isThirdparty = false;
    record->isNeedFlowCtrl = true;
    ErrCode result = ERR_OK;
    int32_t callingUid = DEFAULT_UID;

    // single app flow control test
    for (int i = 0; i < advancedNotificationService_->maxCreateNumPerSecondPerApp; i++) {
        result = advancedNotificationService_->PublishFlowCtrl(record, callingUid);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = advancedNotificationService_->PublishFlowCtrl(record, callingUid);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);
    ASSERT_EQ(advancedNotificationService_->singleAppFlowControlPublishTimestampMap_.size(), 1);

    // global flow control test
    int gap = advancedNotificationService_->maxCreateNumPerSecond -
        advancedNotificationService_->maxCreateNumPerSecondPerApp;
    callingUid = NON_SYSTEM_APP_UID;
    for (int i = 0; i < gap; i++) {
        result = advancedNotificationService_->PublishFlowCtrl(record, callingUid);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = advancedNotificationService_->PublishFlowCtrl(record, callingUid);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);
    ASSERT_EQ(advancedNotificationService_->singleAppFlowControlPublishTimestampMap_.size(), 2);

    advancedNotificationService_->flowControlPublishTimestampList_.clear();
    advancedNotificationService_->systemFlowControlPublishTimestampList_.clear();
    advancedNotificationService_->singleAppFlowControlPublishTimestampMap_.clear();
}

/**
 * @tc.number    : UpdateGlobalFlowCtrl_00001
 * @tc.name      : Test UpdateGlobalFlowCtrl
 * @tc.desc      : Test UpdateGlobalFlowCtrl
 */
HWTEST_F(AdvancedNotificationServiceTest, UpdateGlobalFlowCtrl_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->flowControlUpdateTimestampList_.clear();
    advancedNotificationService_->systemFlowControlUpdateTimestampList_.clear();
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    record->isThirdparty = false;
    record->isNeedFlowCtrl = true;
    ErrCode result = ERR_OK;
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    for (int i = 0; i < advancedNotificationService_->maxUpdateNumPerSecond; i++) {
        result = advancedNotificationService_->UpdateGlobalFlowCtrl(record, now);
        advancedNotificationService_->systemFlowControlUpdateTimestampList_.push_back(now);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = advancedNotificationService_->UpdateGlobalFlowCtrl(record, now);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_UPDATE_PERSECOND);

    record->isThirdparty = true;
    for (int i = 0; i < advancedNotificationService_->maxUpdateNumPerSecond; i++) {
        result = advancedNotificationService_->UpdateGlobalFlowCtrl(record, now);
        advancedNotificationService_->flowControlUpdateTimestampList_.push_back(now);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = advancedNotificationService_->UpdateGlobalFlowCtrl(record, now);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_UPDATE_PERSECOND);

    advancedNotificationService_->flowControlUpdateTimestampList_.clear();
    advancedNotificationService_->systemFlowControlUpdateTimestampList_.clear();
}

/**
 * @tc.number    : UpdateSingleAppFlowCtrl_00001
 * @tc.name      : Test UpdateSingleAppFlowCtrl
 * @tc.desc      : Test UpdateSingleAppFlowCtrl
 */
HWTEST_F(AdvancedNotificationServiceTest, UpdateSingleAppFlowCtrl_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_.clear();
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    record->isNeedFlowCtrl = true;
    ErrCode result = ERR_OK;
    const int32_t callingUid = DEFAULT_UID;
    advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_[callingUid] =
        std::make_shared<std::list<std::chrono::system_clock::time_point>>();
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    for (int i = 0; i < advancedNotificationService_->maxUpdateNumPerSecondPerApp; i++) {
        result = advancedNotificationService_->UpdateSingleAppFlowCtrl(record, now, callingUid);
        advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_[callingUid]->push_back(now);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = advancedNotificationService_->UpdateSingleAppFlowCtrl(record, now, callingUid);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_UPDATE_PERSECOND);

    advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_.clear();
}

/**
 * @tc.number    : UpdateSingleAppFlowCtrlRemoveExpire_00001
 * @tc.name      : Test UpdateSingleAppFlowCtrlRemoveExpire
 * @tc.desc      : Test UpdateSingleAppFlowCtrlRemoveExpire
 */
HWTEST_F(AdvancedNotificationServiceTest, UpdateSingleAppFlowCtrlRemoveExpire_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_.clear();

    int32_t callingUid = DEFAULT_UID;
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_[callingUid] =
        std::make_shared<std::list<std::chrono::system_clock::time_point>>();
    advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_[callingUid]->push_back(now);
    callingUid = NON_SYSTEM_APP_UID;
    advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_[callingUid] =
        std::make_shared<std::list<std::chrono::system_clock::time_point>>();
    now = now + SINGLE_APP_FLOW_CONTRL_EXPIRE_TIME;
    advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_[callingUid]->push_back(now);
    now = now + SINGLE_APP_FLOW_CONTRL_EXPIRE_TIME;
    ASSERT_EQ(advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_.size(), 2);
    advancedNotificationService_->UpdateSingleAppFlowCtrlRemoveExpire(now);
    ASSERT_EQ(advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_.size(), 1);
    now = now + SINGLE_APP_FLOW_CONTRL_EXPIRE_TIME;
    advancedNotificationService_->UpdateSingleAppFlowCtrlRemoveExpire(now);
    ASSERT_EQ(advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_.size(), 0);

    advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_.clear();
}

/**
 * @tc.number    : UpdateFlowCtrl_00001
 * @tc.name      : Test UpdateFlowCtrl
 * @tc.desc      : Test UpdateFlowCtrl
 */
HWTEST_F(AdvancedNotificationServiceTest, UpdateFlowCtrl_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->flowControlUpdateTimestampList_.clear();
    advancedNotificationService_->systemFlowControlUpdateTimestampList_.clear();
    advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_.clear();
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    record->isThirdparty = false;
    record->isNeedFlowCtrl = true;
    ErrCode result = ERR_OK;
    int32_t callingUid = DEFAULT_UID;

    // single app flow control test
    for (int i = 0; i < advancedNotificationService_->maxUpdateNumPerSecondPerApp; i++) {
        result = advancedNotificationService_->UpdateFlowCtrl(record, callingUid);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = advancedNotificationService_->UpdateFlowCtrl(record, callingUid);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_UPDATE_PERSECOND);
    ASSERT_EQ(advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_.size(), 1);

    // global flow control test
    int gap = advancedNotificationService_->maxUpdateNumPerSecond -
        advancedNotificationService_->maxUpdateNumPerSecondPerApp;
    callingUid = NON_SYSTEM_APP_UID;
    for (int i = 0; i < gap; i++) {
        result = advancedNotificationService_->UpdateFlowCtrl(record, callingUid);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = advancedNotificationService_->UpdateFlowCtrl(record, callingUid);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_UPDATE_PERSECOND);
    ASSERT_EQ(advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_.size(), 2);

    advancedNotificationService_->flowControlUpdateTimestampList_.clear();
    advancedNotificationService_->systemFlowControlUpdateTimestampList_.clear();
    advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_.clear();
}

/**
 * @tc.number    : FlowControl_00001
 * @tc.name      : Test FlowControl
 * @tc.desc      : Test FlowControl
 */
HWTEST_F(AdvancedNotificationServiceTest, FlowControl_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->flowControlPublishTimestampList_.clear();
    advancedNotificationService_->systemFlowControlPublishTimestampList_.clear();
    advancedNotificationService_->singleAppFlowControlPublishTimestampMap_.clear();
    advancedNotificationService_->flowControlUpdateTimestampList_.clear();
    advancedNotificationService_->systemFlowControlUpdateTimestampList_.clear();
    advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_.clear();
    advancedNotificationService_->notificationList_.clear();

    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    record->isThirdparty = false;
    record->isNeedFlowCtrl = true;
    ErrCode result = ERR_OK;
    int32_t callingUid = DEFAULT_UID;

    // create flow control
    // single app flow control test
    for (int i = 0; i < advancedNotificationService_->maxCreateNumPerSecondPerApp; i++) {
        result = advancedNotificationService_->FlowControl(record, callingUid);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = advancedNotificationService_->FlowControl(record, callingUid);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);
    ASSERT_EQ(advancedNotificationService_->singleAppFlowControlPublishTimestampMap_.size(), 1);

    // global flow control test
    int gap = advancedNotificationService_->maxCreateNumPerSecond -
        advancedNotificationService_->maxCreateNumPerSecondPerApp;
    callingUid = NON_SYSTEM_APP_UID;
    for (int i = 0; i < gap; i++) {
        result = advancedNotificationService_->FlowControl(record, callingUid);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = advancedNotificationService_->FlowControl(record, callingUid);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);
    ASSERT_EQ(advancedNotificationService_->singleAppFlowControlPublishTimestampMap_.size(), 2);

    advancedNotificationService_->notificationList_.push_back(record);
    // update flow control
    // single app flow control test
    callingUid = DEFAULT_UID;
    for (int i = 0; i < advancedNotificationService_->maxUpdateNumPerSecondPerApp; i++) {
        result = advancedNotificationService_->FlowControl(record, callingUid);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = advancedNotificationService_->FlowControl(record, callingUid);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_UPDATE_PERSECOND);
    ASSERT_EQ(advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_.size(), 1);

    // global flow control test
    gap = advancedNotificationService_->maxUpdateNumPerSecond -
        advancedNotificationService_->maxUpdateNumPerSecondPerApp;
    callingUid = NON_SYSTEM_APP_UID;
    for (int i = 0; i < gap; i++) {
        result = advancedNotificationService_->FlowControl(record, callingUid);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = advancedNotificationService_->FlowControl(record, callingUid);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_UPDATE_PERSECOND);
    ASSERT_EQ(advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_.size(), 2);

    advancedNotificationService_->flowControlPublishTimestampList_.clear();
    advancedNotificationService_->systemFlowControlPublishTimestampList_.clear();
    advancedNotificationService_->singleAppFlowControlPublishTimestampMap_.clear();
    advancedNotificationService_->flowControlUpdateTimestampList_.clear();
    advancedNotificationService_->systemFlowControlUpdateTimestampList_.clear();
    advancedNotificationService_->singleAppFlowControlUpdateTimestampMap_.clear();
    advancedNotificationService_->notificationList_.clear();
}
}  // namespace Notification
}  // namespace OHOS
