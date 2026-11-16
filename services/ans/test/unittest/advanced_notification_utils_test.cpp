/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_service_errors.h"
#include "ans_log_wrapper.h"
#include "ans_ut_constant.h"
#include "iremote_object.h"
#include "ipc_skeleton.h"
#include "want_agent_info.h"
#include "want_agent_helper.h"
#include "want_params.h"
#include "int_wrapper.h"
#include "bool_wrapper.h"
#include "mock_time_service_client.h"
#include "accesstoken_kit.h"
#include "notification_preferences.h"
#include "notification_record.h"
#include "notification_subscriber.h"
#include "refbase.h"
#include "mock_bundle_manager_helper.h"
#include "mock_accesstoken_kit.h"
#include "mock_bundle_mgr.h"
#include "notification_extension_wrapper.h"
#include "notification_classification_mgr.h"
#include "os_account_manager.h"
#include "os_account_manager_helper.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::Security::AccessToken;

extern void MockIsOsAccountExists(bool mockRet);
extern void MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase);
extern void MockGetOsAccountLocalIdFromUid(bool mockRet, uint8_t mockCase = 0);

namespace OHOS {
namespace Notification {
class AnsUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    void TestAddNotification(int notificationId, const sptr<NotificationBundleOption> &bundle);

private:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AnsUtilsTest::advancedNotificationService_ = nullptr;

void AnsUtilsTest::SetUpTestCase() {}

void AnsUtilsTest::TearDownTestCase() {}

void AnsUtilsTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
    advancedNotificationService_->CancelAll("");
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    GTEST_LOG_(INFO) << "SetUp end";
}

void AnsUtilsTest::TearDown()
{
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

void AnsUtilsTest::TestAddNotification(int notificationId, const sptr<NotificationBundleOption> &bundle)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetOwnerUserId(1);
    request->SetCreatorUserId(2);
    request->SetOwnerBundleName("test");
    request->SetOwnerUid(0);
    request->SetNotificationId(notificationId);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    auto ret = advancedNotificationService_->AssignToNotificationList(record);
}

/**
 * @tc.name: FillRequestByKeys_00001
 * @tc.desc: Test FillRequestByKeys
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, FillRequestByKeys_00001, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> oldRequest = new (std::nothrow) NotificationRequest();
    oldRequest->SetSlotType(slotType);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    sptr<AAFwk::IInterface> value = AAFwk::Integer::Box(1);
    extraInfo->SetParam("key1", value);
    auto content = std::make_shared<NotificationContent>(liveContent);
    liveContent->SetExtraInfo(extraInfo);
    oldRequest->SetContent(content);

    std::vector<std::string> keys = {"key1"};
    sptr<NotificationRequest> newRequest;
    ErrCode ret = advancedNotificationService_->FillRequestByKeys(oldRequest, keys, newRequest);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: IsAllowedGetNotificationByFilter_00001
 * @tc.desc: Test IsAllowedGetNotificationByFilter
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, IsAllowedGetNotificationByFilter_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto record = std::make_shared<NotificationRecord>();
    record->bundleOption = new NotificationBundleOption("test", 1);
    int ret = advancedNotificationService_->IsAllowedGetNotificationByFilter(record, bundle);
    EXPECT_EQ(ret, (int)ERR_OK);

    record->bundleOption->SetBundleName("bundleName");
    ret = advancedNotificationService_->IsAllowedGetNotificationByFilter(record, bundle);
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_PERMISSION_DENIED);

    record->bundleOption->SetBundleName("test");
    record->bundleOption->SetUid(2);
    ret = advancedNotificationService_->IsAllowedGetNotificationByFilter(record, bundle);
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.name: GetActiveNotificationByFilter_00001
 * @tc.desc: Test GetActiveNotificationByFilter
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetActiveNotificationByFilter_00001, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    ans.notificationSvrQueue_.Reset();
    std::string label = "testLabel";
    std::vector<std::string> keys = {"key1"};
    sptr<NotificationRequest> newRequest;
    auto bundleOption = new NotificationBundleOption("test", 1);
    int notificationId = 1;
    int32_t userId = -1;
    EXPECT_EQ(ans.GetActiveNotificationByFilter(bundleOption, notificationId, label, userId, keys, newRequest),
        (int)ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: GetActiveNotificationByFilter_00002
 * @tc.desc: Test GetActiveNotificationByFilter
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetActiveNotificationByFilter_00002, Function | SmallTest | Level1)
{
    std::string label = "testLabel";
    std::vector<std::string> keys = {"key1"};
    sptr<NotificationRequest> newRequest;
    sptr<NotificationBundleOption> bundle;
    int notificationId = 1;
    int32_t userId = -1;
    EXPECT_EQ(advancedNotificationService_->GetActiveNotificationByFilter(
        bundle, notificationId, label, userId, keys, newRequest),
        (int)ERR_ANS_INNER_INVALID_BUNDLE);
}

/**
 * @tc.name: GetActiveNotificationByFilter_00003
 * @tc.desc: Test GetActiveNotificationByFilter
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetActiveNotificationByFilter_00003, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    std::string label = "testLabel";
    int notificationId = 1;
    int32_t userId = -1;

    sptr<NotificationRequest> oldRequest = new (std::nothrow) NotificationRequest();
    oldRequest->SetSlotType(slotType);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    sptr<AAFwk::IInterface> value = AAFwk::Integer::Box(1);
    extraInfo->SetParam("key1", value);
    liveContent->SetExtraInfo(extraInfo);
    auto content = std::make_shared<NotificationContent>(liveContent);
    oldRequest->SetContent(content);
    oldRequest->SetNotificationId(notificationId);

    oldRequest->SetLabel(label);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 101);
    auto record = advancedNotificationService_->MakeNotificationRecord(oldRequest, bundle);
    advancedNotificationService_->AssignToNotificationList(record);


    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    std::vector<std::string> keys;
    sptr<NotificationRequest> newRequest;
    EXPECT_EQ(advancedNotificationService_->GetActiveNotificationByFilter(bundle,
        notificationId, label, userId, keys, newRequest), (int)ERR_ANS_INNER_PERMISSION_DENIED);

    MockIsVerfyPermisson(true);
    EXPECT_EQ(advancedNotificationService_->GetActiveNotificationByFilter(bundle,
        notificationId, label, userId, keys, newRequest), (int)ERR_OK);

    keys.emplace_back("test1");
    EXPECT_EQ(advancedNotificationService_->GetActiveNotificationByFilter(bundle,
        notificationId, label, userId, keys, newRequest), (int)ERR_OK);

    sptr<NotificationBundleOption> bundle1 = new NotificationBundleOption("test1", 1);
    EXPECT_EQ(advancedNotificationService_->GetActiveNotificationByFilter(bundle1,
        notificationId, label, userId, keys, newRequest), (int)ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);
}
#ifdef ANM_SUPPORT_DUMP
/**
 * @tc.name: RecentNotificationDump_00001
 * @tc.desc: Test RecentNotificationDump
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, RecentNotificationDump_00001, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetOwnerUserId(1);
    request->SetCreatorUserId(1);
    request->SetOwnerBundleName("test");
    request->SetOwnerUid(0);
    request->SetNotificationId(1);
    auto notification = new (std::nothrow) Notification(request);

    auto recentNotification = std::make_shared<AdvancedNotificationService::RecentNotification>();
    recentNotification->isActive = true;
    recentNotification->notification = notification;
    advancedNotificationService_->recentInfo_->list.emplace_front(recentNotification);

    std::vector<std::string> dumpInfo;
    int ret = advancedNotificationService_->RecentNotificationDump("test", 1, 1, dumpInfo);
    EXPECT_EQ(ret, (int)ERR_OK);
    EXPECT_EQ(dumpInfo.size(), 1);
}

/**
 * @tc.name: RecentNotificationDump_00002
 * @tc.desc: Test RecentNotificationDump
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, RecentNotificationDump_00002, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetOwnerUserId(1);
    request->SetCreatorUserId(1);
    request->SetOwnerBundleName("test");
    request->SetOwnerUid(1);
    request->SetNotificationId(1);
    auto notification = new (std::nothrow) Notification(request);

    auto recentNotification = std::make_shared<AdvancedNotificationService::RecentNotification>();
    recentNotification->isActive = false;
    recentNotification->notification = notification;
    advancedNotificationService_->recentInfo_->list.emplace_front(recentNotification);

    sptr<NotificationRequest> request1 = new (std::nothrow) NotificationRequest();
    request1->SetOwnerUserId(2);
    auto notification1 = new (std::nothrow) Notification(request1);
    auto recentNotification1 = std::make_shared<AdvancedNotificationService::RecentNotification>();
    recentNotification1->notification = notification1;
    advancedNotificationService_->recentInfo_->list.emplace_front(recentNotification1);

    sptr<NotificationRequest> request2 = new (std::nothrow) NotificationRequest();
    request2->SetOwnerUserId(1);
    request2->SetOwnerBundleName("test1");
    auto notification2 = new (std::nothrow) Notification(request2);
    auto recentNotification2 = std::make_shared<AdvancedNotificationService::RecentNotification>();
    recentNotification2->notification = notification2;
    advancedNotificationService_->recentInfo_->list.emplace_front(recentNotification2);

    sptr<NotificationRequest> request3 = new (std::nothrow) NotificationRequest();
    request3->SetReceiverUserId(2);
    request3->SetOwnerUserId(1);
    auto notification3 = new (std::nothrow) Notification(request3);
    auto recentNotification3 = std::make_shared<AdvancedNotificationService::RecentNotification>();
    recentNotification3->notification = notification3;
    advancedNotificationService_->recentInfo_->list.emplace_front(recentNotification3);

    std::vector<std::string> dumpInfo;
    int ret = advancedNotificationService_->RecentNotificationDump("test", 1, 1, dumpInfo);
    EXPECT_EQ(ret, (int)ERR_OK);
    EXPECT_EQ(dumpInfo.size(), 1);
}

/**
 * @tc.name: RecentNotificationDump_00003
 * @tc.desc: Test RecentNotificationDump
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, RecentNotificationDump_00003, Function | SmallTest | Level1)
{
    sptr<Notification> notification = nullptr;
    auto recentNotification = std::make_shared<AdvancedNotificationService::RecentNotification>();
    recentNotification->isActive = true;
    recentNotification->notification = notification;
    advancedNotificationService_->recentInfo_->list.emplace_front(recentNotification);

    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetOwnerUserId(1);
    request->SetCreatorUserId(1);
    request->SetOwnerBundleName("test");
    request->SetOwnerUid(0);
    request->SetNotificationId(1);
    auto notification1 = new (std::nothrow) Notification(request);

    auto recentNotification1 = std::make_shared<AdvancedNotificationService::RecentNotification>();
    recentNotification1->isActive = false;
    recentNotification1->notification = notification1;
    advancedNotificationService_->recentInfo_->list.emplace_front(recentNotification1);

    std::vector<std::string> dumpInfo;
    int ret = advancedNotificationService_->RecentNotificationDump("test", 1, 1, dumpInfo);
    EXPECT_EQ(ret, (int)ERR_OK);
    EXPECT_EQ(dumpInfo.size(), 1);
}
#endif

/**
 * @tc.name: GetLocalNotificationKeys_00001
 * @tc.desc: Test GetLocalNotificationKeys
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetLocalNotificationKeys_00001, Function | SmallTest | Level1)
{
    int notificationId = 1;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    TestAddNotification(notificationId, bundle);

    notificationId = 2;
    sptr<NotificationBundleOption> bundle2 = new NotificationBundleOption("test1", 2);
    TestAddNotification(notificationId, bundle2);
    EXPECT_EQ(advancedNotificationService_->notificationList_.size(), 2);
#ifdef ANS_FEATURE_ORIGINAL_DISTRIBUTED
    auto keys = advancedNotificationService_->GetLocalNotificationKeys(bundle2);
    EXPECT_EQ(keys.size(), 1);
#endif
}

/**
 * @tc.name: OnBundleDataCleared_00001
 * @tc.desc: Test OnBundleDataCleared
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, OnBundleDataCleared_00001, Function | SmallTest | Level1)
{
    int notificationId = 1;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(notificationId);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
#ifdef ANS_FEATURE_ORIGINAL_DISTRIBUTED
    record->deviceId = "deviceId";
#endif  // ANS_FEATURE_ORIGINAL_DISTRIBUTED
    advancedNotificationService_->AssignToNotificationList(record);
    advancedNotificationService_->OnBundleDataCleared(bundle);
    SleepForFC();
    EXPECT_EQ(advancedNotificationService_->notificationList_.size(), 0);
}

/**
 * @tc.name: OnBundleDataCleared_00002
 * @tc.desc: Test OnBundleDataCleared
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, OnBundleDataCleared_00002, Function | SmallTest | Level1)
{
    int notificationId = 1;
    AdvancedNotificationService advancedNotificationService;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(notificationId);
    auto record = advancedNotificationService.MakeNotificationRecord(request, bundle);
    advancedNotificationService.AssignToNotificationList(record);
    advancedNotificationService.notificationSvrQueue_.Reset();
    advancedNotificationService.OnBundleDataCleared(bundle);
    EXPECT_EQ(advancedNotificationService.notificationList_.size(), 1);
}

/**
 * @tc.name: InitNotificationEnableList_00001
 * @tc.desc: Test InitNotificationEnableList
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, InitNotificationEnableList_00001, Function | SmallTest | Level1)
{
    MockSetBundleInfoEnabled(true);
    advancedNotificationService_->InitNotificationEnableList();
    SleepForFC();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    EXPECT_EQ(static_cast<int32_t>(state), 0);
}

/**
 * @tc.name: InitNotificationEnableList_00002
 * @tc.desc: Test InitNotificationEnableList
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, InitNotificationEnableList_00002, Function | SmallTest | Level1)
{
    MockSetBundleInfoEnabled(true);
    advancedNotificationService_->InitNotificationEnableList();
    SleepForFC();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test1", 2);
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    EXPECT_EQ(static_cast<int32_t>(state), 2);
}

/**
 * @tc.name: InitNotificationStatistics_00001
 * @tc.desc: Test InitNotificationStatistics
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, InitNotificationStatistics_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle01 = new NotificationBundleOption("testBundle", 100);
    EXPECT_EQ((int)NotificationPreferences::GetInstance()->PutNotificationStatistics(
        100, bundle01), ERR_OK);
    advancedNotificationService_->InitNotificationStatistics();
    SleepForFC();
    int32_t recentCount = 0;
    int64_t lastTime = 0;
    EXPECT_EQ((int)NotificationPreferences::GetInstance()->QueryStatisticsByBundle(bundle01,
        recentCount, lastTime), ERR_OK);
}

/**
 * @tc.name: GenerateValidBundleOptionV3_00001
 * @tc.desc: Test GenerateValidBundleOptionV3
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GenerateValidBundleOptionV3_00001, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(false, 0);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test_bundle", 0);
    sptr<NotificationBundleOption> result = advancedNotificationService_->GenerateValidBundleOptionV3(bundleOption);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: GenerateValidBundleOptionV3_00002
 * @tc.desc: Test GenerateValidBundleOptionV3
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GenerateValidBundleOptionV3_00002, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(true, 0);
    MockSetBundleInfoFailed(true);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test_bundle", 100);
    bundleOption->SetInstanceKey(10);
    sptr<NotificationBundleOption> result = advancedNotificationService_->GenerateValidBundleOptionV3(bundleOption);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: GenerateValidBundleOptionV3_00003
 * @tc.desc: Test GenerateValidBundleOptionV3
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GenerateValidBundleOptionV3_00003, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(true, 0);
    MockSetBundleInfoFailed(false);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test_bundle", 100);
    bundleOption->SetInstanceKey(10);
    sptr<NotificationBundleOption> result = advancedNotificationService_->GenerateValidBundleOptionV3(bundleOption);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: GenerateValidBundleOptionV3_00004
 * @tc.desc: Test GenerateValidBundleOptionV3
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GenerateValidBundleOptionV3_00004, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(true, 0);
    MockSetBundleInfoFailed(false);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test_bundle", -1);
    bundleOption->SetInstanceKey(10);
    sptr<NotificationBundleOption> result = advancedNotificationService_->GenerateValidBundleOptionV3(bundleOption);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: GenerateValidBundleOptionV3_00005
 * @tc.desc: Test GenerateValidBundleOptionV3
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GenerateValidBundleOptionV3_00005, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(true, 0);
    MockSetBundleInfoFailed(false);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test_bundle", 20020010);
    bundleOption->SetInstanceKey(10);
    sptr<NotificationBundleOption> result = advancedNotificationService_->GenerateValidBundleOptionV3(bundleOption);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: GenerateValidBundleOptionV3_00006
 * @tc.desc: Test GenerateValidBundleOptionV3
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GenerateValidBundleOptionV3_00006, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(true, 0);
    MockSetBundleInfoFailed(false);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test_bundle", 20020010);
    bundleOption->SetInstanceKey(10);
    sptr<NotificationBundleOption> result = advancedNotificationService_->GenerateValidBundleOptionV3(nullptr);
    EXPECT_EQ(result, nullptr);
}


/**
 * @tc.name: GenerateValidBundleOptionV3_00007
 * @tc.desc: Test GenerateValidBundleOptionV3
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GenerateValidBundleOptionV3_00007, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(true, 0);
    MockSetBundleInfoFailed(false);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("", 20020010);
    bundleOption->SetInstanceKey(10);
    sptr<NotificationBundleOption> result = advancedNotificationService_->GenerateValidBundleOptionV3(bundleOption);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: GetBundleInfoByNotificationBundleOption_00001
 * @tc.desc: Test GetBundleInfoByNotificationBundleOption
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetBundleInfoByNotificationBundleOption_00001, Function | SmallTest | Level1)
{
    MockSetBundleInfoFailed(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    AppExecFwk::BundleInfo bundleInfo;
    bool res = advancedNotificationService_->GetBundleInfoByNotificationBundleOption(bundle, bundleInfo);
    EXPECT_EQ(res, true);
    MockSetBundleInfoFailed(false);
}

/**
 * @tc.name: GetBundleInfoByNotificationBundleOption_00002
 * @tc.desc: Test GetBundleInfoByNotificationBundleOption when GetOsAccountLocalIdFromUid fails
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetBundleInfoByNotificationBundleOption_00002, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    AppExecFwk::BundleInfo bundleInfo;

    MockGetOsAccountLocalIdFromUid(false, 0);
    bool res = advancedNotificationService_->GetBundleInfoByNotificationBundleOption(bundle, bundleInfo);
    EXPECT_EQ(res, false);
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

/**
 * @tc.name: GetBundleInfoByNotificationBundleOption_00003
 * @tc.desc: Test GetBundleInfoByNotificationBundleOption when resolved userId is invalid (< 0)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetBundleInfoByNotificationBundleOption_00003, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    AppExecFwk::BundleInfo bundleInfo;

    MockGetOsAccountLocalIdFromUid(true, 1); // mock invalid userId (-2)
    bool res = advancedNotificationService_->GetBundleInfoByNotificationBundleOption(bundle, bundleInfo);
    EXPECT_EQ(res, false);
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

/**
 * @tc.name: OnBundleRemoved_00001
 * @tc.desc: Test OnBundleRemoved
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, OnBundleRemoved_00001, Function | SmallTest | Level1)
{
    int notificationId = 1;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    TestAddNotification(notificationId, bundle);
    EXPECT_EQ(advancedNotificationService_->notificationList_.size(), 1);

    advancedNotificationService_->OnBundleRemoved(bundle);
    SleepForFC();
    EXPECT_EQ(advancedNotificationService_->notificationList_.size(), 0);
}

/**
 * @tc.name: OnBundleRemoved_00002
 * @tc.desc: Test OnBundleRemoved
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, OnBundleRemoved_00002, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    auto ret = advancedNotificationService_->AssignToNotificationList(record);
    advancedNotificationService_->notificationSvrQueue_.Reset();
    advancedNotificationService_->OnBundleRemoved(bundle);
    EXPECT_EQ(advancedNotificationService_->notificationList_.size(), 1);
}

/**
 * @tc.name: onBundleRemovedByUserId_00001
 * @tc.desc: Test onBundleRemovedByUserId
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, onBundleRemovedByUserId_00001, Function | SmallTest | Level1)
{
    int notificationId = 1;
    int32_t userId = 100;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    TestAddNotification(notificationId, bundle);
    EXPECT_EQ(advancedNotificationService_->notificationList_.size(), 1);

    advancedNotificationService_->onBundleRemovedByUserId(bundle, userId);
    SleepForFC();
    EXPECT_EQ(advancedNotificationService_->notificationList_.size(), 0);
}

/**
 * @tc.name: onBundleRemovedByUserId_00002
 * @tc.desc: Test onBundleRemovedByUserId
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, onBundleRemovedByUserId_00002, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    int32_t userId = 100;
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    auto ret = advancedNotificationService_->AssignToNotificationList(record);
    advancedNotificationService_->notificationSvrQueue_.Reset();
    advancedNotificationService_->onBundleRemovedByUserId(bundle, userId);
    EXPECT_EQ(advancedNotificationService_->notificationList_.size(), 1);
}

/**
 * @tc.name: OnBundleDataAdd_00001
 * @tc.desc: Test OnBundleDataAdd
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, OnBundleDataAdd_00001, Function | SmallTest | Level1)
{
    int notificationId = 1;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("OnBundleDataAdd_00001", 1);
    TestAddNotification(notificationId, bundle);
    MockSetBundleInfoEnabled(false);
    advancedNotificationService_->OnBundleDataAdd(bundle);
    SleepForFC();
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    EXPECT_EQ(static_cast<int32_t>(state), 2);
}

/**
 * @tc.name: OnBundleDataAdd_00002
 * @tc.desc: Test OnBundleDataAdd
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, OnBundleDataAdd_00002, Function | SmallTest | Level1)
{
    int notificationId = 1;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    TestAddNotification(notificationId, bundle);
    MockSetBundleInfoEnabled(true);
    advancedNotificationService_->OnBundleDataAdd(bundle);
    SleepForFC();
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    EXPECT_EQ(static_cast<int32_t>(state), 2);
}

/**
 * @tc.name: OnBundleDataAdd_00003
 * @tc.desc: Test OnBundleDataAdd
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, OnBundleDataAdd_00003, Function | SmallTest | Level1)
{
    int notificationId = 1;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    TestAddNotification(notificationId, bundle);
    MockSetBundleInfoFailed(true);
    advancedNotificationService_->OnBundleDataAdd(bundle);
    SleepForFC();
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    MockSetBundleInfoFailed(false);
    EXPECT_EQ(static_cast<int32_t>(state), 2);
}

/**
 * @tc.name: OnBundleDataUpdate_00001
 * @tc.desc: Test OnBundleDataUpdate
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, OnBundleDataUpdate_00001, Function | SmallTest | Level1)
{
    int notificationId = 1;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    TestAddNotification(notificationId, bundle);

    NotificationPreferences::GetInstance()->SetHasPoppedDialog(bundle, true);
    advancedNotificationService_->OnBundleDataUpdate(bundle);
    EXPECT_NE(advancedNotificationService_, nullptr);
}

/**
 * @tc.name: OnBundleDataUpdate_00002
 * @tc.desc: Test OnBundleDataUpdate
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, OnBundleDataUpdate_00002, Function | SmallTest | Level1)
{
    int notificationId = 1;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    TestAddNotification(notificationId, bundle);
    MockSetBundleInfoEnabled(true);
    advancedNotificationService_->OnBundleDataUpdate(bundle);
    SleepForFC();
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    EXPECT_EQ(static_cast<int32_t>(state), 2);
}

/**
 * @tc.name: OnBundleDataUpdate_00003
 * @tc.desc: Test OnBundleDataUpdate
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, OnBundleDataUpdate_00003, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    int notificationId = 1;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    TestAddNotification(notificationId, bundle);
    MockSetBundleInfoFailed(true);
    advancedNotificationService_->OnBundleDataUpdate(bundle);
    SleepForFC();
    MockSetBundleInfoFailed(false);
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    EXPECT_EQ(static_cast<int32_t>(state), 2);
}

/**
 * @tc.name: GetBundlesOfActiveUser_00001
 * @tc.desc: Test GetBundlesOfActiveUser
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetBundlesOfActiveUser_00001, Function | SmallTest | Level1)
{
    MockSetBundleInfoEnabled(true);
    auto list = advancedNotificationService_->GetBundlesOfActiveUser();
    EXPECT_EQ(list.size(), 0);
}

/**
 * @tc.name: ResetDistributedEnabled_00001
 * @tc.desc: Test ResetDistributedEnabled
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, ResetDistributedEnabled_00001, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    std::string oldKey = "enabledNotificationDistributed-test-88-aaa";
    NotificationPreferences::GetInstance()->SetKvToDb(oldKey, "1", 0);
    ans.notificationSvrQueue_.Reset();
    ans.ResetDistributedEnabled();
    SleepForFC();
    std::string value;
    NotificationPreferences::GetInstance()->GetKvFromDb("tableVersion", value, 0);
    EXPECT_NE(value, "1");
}

/**
 * @tc.name: ResetDistributedEnabled_00002
 * @tc.desc: Test ResetDistributedEnabled
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, ResetDistributedEnabled_00002, Function | SmallTest | Level1)
{
    std::string oldKey = "enabledNotificationDistributed-test-88-aaa";
    std::string oldKey1 = "enabledNotificationDistributed-test-88";
    NotificationPreferences::GetInstance()->SetKvToDb(oldKey, "1", 0);
    NotificationPreferences::GetInstance()->SetKvToDb(oldKey1, "1", 0);
    advancedNotificationService_->ResetDistributedEnabled();
    SleepForFC();
    std::string value;
    NotificationPreferences::GetInstance()->GetKvFromDb("tableVersion", value, 0);
    EXPECT_EQ(value, "1");
}

/**
 * @tc.name: UpdateCloneBundleInfo_00001
 * @tc.desc: Test UpdateCloneBundleInfo
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, UpdateCloneBundleInfo_00001, Function | SmallTest | Level1)
{
    NotificationCloneBundleInfo cloneBundleInfo;
    cloneBundleInfo.SetBundleName("test");
    cloneBundleInfo.SetUid(1);
    cloneBundleInfo.SetIsShowBadge(true);
    cloneBundleInfo.SetEnableNotification(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    cloneBundleInfo.SetSlotFlags(63);
    NotificationCloneBundleInfo::SlotInfo info;
    info.slotType_ = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    info.enable_ = true;
    cloneBundleInfo.AddSlotInfo(info);
    advancedNotificationService_->UpdateCloneBundleInfo(cloneBundleInfo, 0);
    SleepForFC();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    EXPECT_EQ(static_cast<int32_t>(state), 1);
}

/**
 * @tc.name: UpdateCloneBundleInfo_00002
 * @tc.desc: Test UpdateCloneBundleInfo
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, UpdateCloneBundleInfo_00002, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    NotificationCloneBundleInfo cloneBundleInfo;
    cloneBundleInfo.SetBundleName("UpdateCloneBundleInfo_00002");
    cloneBundleInfo.SetUid(1);
    cloneBundleInfo.SetIsShowBadge(true);
    cloneBundleInfo.SetEnableNotification(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    cloneBundleInfo.SetSlotFlags(63);
    NotificationCloneBundleInfo::SlotInfo info;
    info.slotType_ = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    info.enable_ = true;
    cloneBundleInfo.AddSlotInfo(info);
    ans.notificationSvrQueue_.Reset();
    ans.UpdateCloneBundleInfo(cloneBundleInfo, 0);
    SleepForFC();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("UpdateCloneBundleInfo_00002", 1);
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    EXPECT_EQ(static_cast<int32_t>(state), 0);
}
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
HWTEST_F(AnsUtilsTest, UpdateCloneBundleInfo_00003, Function | SmallTest | Level1)
{
    MockIsNeedHapModuleInfos(true);
    MockIsVerfyPermisson(true);
    NotificationCloneBundleInfo cloneBundleInfo;
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    auto type = NotificationConstant::SubscribeType::BLUETOOTH;
    infos.emplace_back(new (std::nothrow) NotificationExtensionSubscriptionInfo("addr", type));
    std::vector<sptr<NotificationBundleOption>> extensionBundles = {
        new NotificationBundleOption("extension.bundle3", 0)
    };
    cloneBundleInfo.SetExtensionSubscriptionBundles(extensionBundles);
    cloneBundleInfo.SetEnabledExtensionSubscription(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    cloneBundleInfo.SetBundleName("UpdateCloneBundleInfo_00003");
    cloneBundleInfo.SetUid(1);
    cloneBundleInfo.SetIsShowBadge(true);
    cloneBundleInfo.SetEnableNotification(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    cloneBundleInfo.SetSlotFlags(63);
    cloneBundleInfo.SetExtensionSubscriptionInfos(infos);
    NotificationCloneBundleInfo::SlotInfo info;
    info.slotType_ = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    info.enable_ = true;
    cloneBundleInfo.AddSlotInfo(info);
    advancedNotificationService_->UpdateCloneBundleInfo(cloneBundleInfo, 0);
    SleepForFC();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("UpdateCloneBundleInfo_00003", 1);
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    EXPECT_EQ(static_cast<int32_t>(state), 1);
    std::vector<sptr<NotificationBundleOption>> resultBundles;
    NotificationPreferences::GetInstance()->GetExtensionSubscriptionBundles(bundle, resultBundles);
    EXPECT_FALSE(resultBundles.empty());
}

HWTEST_F(AnsUtilsTest, UpdateCloneBundleInfo_00004, Function | SmallTest | Level1)
{
    MockIsNeedHapModuleInfos(true);
    MockIsVerfyPermisson(true);
    NotificationCloneBundleInfo cloneBundleInfo;
    cloneBundleInfo.SetBundleName("test");
    cloneBundleInfo.SetUid(1);
    cloneBundleInfo.SetIsShowBadge(true);
    cloneBundleInfo.SetEnabledExtensionSubscription(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    advancedNotificationService_->UpdateCloneBundleInfo(cloneBundleInfo, 0);
    SleepForFC();
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test", 1);
    NotificationConstant::SWITCH_STATE state {};
    bool isExist = false;
    ErrCode result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionEnabled(bundleOption, state);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(state, NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
}

/**
 * @tc.name: UpdateCloneBundleInfo_00005
 * @tc.desc: Test UpdateCloneBundleInfoForExtensionSubscription restores priority subscription
 *           when extensionSubscriptionInfos contains SYSTEM type
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, UpdateCloneBundleInfo_00005, Function | SmallTest | Level1)
{
    MockIsNeedHapModuleInfos(true);
    MockIsVerfyPermisson(true);
    NotificationCloneBundleInfo cloneBundleInfo;
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    auto systemType = NotificationConstant::SubscribeType::SYSTEM;
    infos.emplace_back(new (std::nothrow) NotificationExtensionSubscriptionInfo("addr", systemType));
    cloneBundleInfo.SetExtensionSubscriptionInfos(infos);
    cloneBundleInfo.SetEnabledExtensionSubscription(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    cloneBundleInfo.SetBundleName("UpdateCloneBundleInfo_00005");
    cloneBundleInfo.SetUid(1);
    cloneBundleInfo.SetIsShowBadge(true);
    cloneBundleInfo.SetEnableNotification(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    cloneBundleInfo.SetSlotFlags(63);
    NotificationCloneBundleInfo::SlotInfo slotInfo;
    slotInfo.slotType_ = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    slotInfo.enable_ = true;
    cloneBundleInfo.AddSlotInfo(slotInfo);
    advancedNotificationService_->UpdateCloneBundleInfo(cloneBundleInfo, 0);
    SleepForFC();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("UpdateCloneBundleInfo_00005", 1);
    EXPECT_TRUE(advancedNotificationService_->IsSystemTypeSubscriber(bundle));
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> resultInfos;
    auto ret = NotificationPreferences::GetInstance()->GetExtensionSubscriptionInfos(bundle, resultInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(resultInfos.empty());
    bool hasSystemType = false;
    for (const auto &info : resultInfos) {
        if (info != nullptr && info->GetType() == NotificationConstant::SubscribeType::SYSTEM) {
            hasSystemType = true;
        }
    }
    EXPECT_TRUE(hasSystemType);
}

/**
 * @tc.name: UpdateCloneBundleInfo_00006
 * @tc.desc: Test clone restore persists priority strategy carried by SYSTEM type info
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, UpdateCloneBundleInfo_00006, Function | SmallTest | Level1)
{
    MockIsNeedHapModuleInfos(true);
    MockIsVerfyPermisson(true);
    NotificationCloneBundleInfo cloneBundleInfo;
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    sptr<NotificationExtensionSubscriptionInfo> systemInfo =
        new (std::nothrow) NotificationExtensionSubscriptionInfo(
            "addr", NotificationConstant::SubscribeType::SYSTEM);
    systemInfo->SetPriorityStrategy(
        static_cast<int32_t>(NotificationConstant::PriorityStrategyStatus::STATUS_ALL_PRIORITY));
    infos.emplace_back(systemInfo);
    cloneBundleInfo.SetExtensionSubscriptionInfos(infos);
    cloneBundleInfo.SetEnabledExtensionSubscription(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    cloneBundleInfo.SetBundleName("UpdateCloneBundleInfo_00006");
    cloneBundleInfo.SetUid(1);
    cloneBundleInfo.SetIsShowBadge(true);
    cloneBundleInfo.SetEnableNotification(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    cloneBundleInfo.SetSlotFlags(63);
    advancedNotificationService_->UpdateCloneBundleInfo(cloneBundleInfo, 0);
    SleepForFC();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("UpdateCloneBundleInfo_00006", 1);
    int32_t resultStrategy = 0;
    auto strategyRet = advancedNotificationService_->GetSystemSubscriptionStrategy(bundle, resultStrategy);
    EXPECT_EQ(strategyRet, ERR_OK);
    EXPECT_EQ(resultStrategy,
        static_cast<int32_t>(NotificationConstant::PriorityStrategyStatus::STATUS_ALL_PRIORITY));
}

/**
 * @tc.name: UpdateCloneBundleInfo_00007
 * @tc.desc: Test GetSystemSubscriptionStrategy skips nullptr info in infos
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, UpdateCloneBundleInfo_00007, Function | SmallTest | Level1)
{
    MockIsNeedHapModuleInfos(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("RestoreClone_007", 1);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    infos.emplace_back(nullptr);
    sptr<NotificationExtensionSubscriptionInfo> systemInfo =
        new (std::nothrow) NotificationExtensionSubscriptionInfo(
            "addr", NotificationConstant::SubscribeType::SYSTEM);
    systemInfo->SetPriorityStrategy(
        static_cast<int32_t>(NotificationConstant::PriorityStrategyStatus::STATUS_ALL_PRIORITY));
    infos.emplace_back(systemInfo);
    NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundle, infos);
    int32_t resultStrategy = 0;
    auto strategyRet = advancedNotificationService_->GetSystemSubscriptionStrategy(bundle, resultStrategy);
    EXPECT_EQ(strategyRet, ERR_OK);
    EXPECT_EQ(resultStrategy,
        static_cast<int32_t>(NotificationConstant::PriorityStrategyStatus::STATUS_ALL_PRIORITY));
}

/**
 * @tc.name: UpdateCloneBundleInfo_00008
 * @tc.desc: Test UpdateCloneBundleInfoForExtensionSubscription returns early when
 *           CheckBundleImplExtensionAbility returns false
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, UpdateCloneBundleInfo_00008, Function | SmallTest | Level1)
{
    MockIsNeedHapModuleInfos(false);
    MockIsVerfyPermisson(true);
    NotificationCloneBundleInfo cloneBundleInfo;
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    auto systemType = NotificationConstant::SubscribeType::SYSTEM;
    infos.emplace_back(new (std::nothrow) NotificationExtensionSubscriptionInfo("addr", systemType));
    cloneBundleInfo.SetExtensionSubscriptionInfos(infos);
    cloneBundleInfo.SetEnabledExtensionSubscription(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    cloneBundleInfo.SetBundleName("UpdateCloneBundleInfo_00008");
    cloneBundleInfo.SetUid(1);
    cloneBundleInfo.SetIsShowBadge(true);
    cloneBundleInfo.SetEnableNotification(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    cloneBundleInfo.SetSlotFlags(63);
    advancedNotificationService_->UpdateCloneBundleInfo(cloneBundleInfo, 0);
    SleepForFC();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("UpdateCloneBundleInfo_00008", 1);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> resultInfos;
    NotificationPreferences::GetInstance()->GetExtensionSubscriptionInfos(bundle, resultInfos);
    EXPECT_TRUE(resultInfos.empty());
}

/**
 * @tc.name: UpdateCloneBundleInfo_00009
 * @tc.desc: Test UpdateCloneBundleInfoForExtensionSubscription with invalid grant bundles
 *           (GenerateCloneValidBundleOption returns nullptr due to empty bundleName)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, UpdateCloneBundleInfo_00009, Function | SmallTest | Level1)
{
    MockIsNeedHapModuleInfos(true);
    MockIsVerfyPermisson(true);
    NotificationCloneBundleInfo cloneBundleInfo;
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    auto systemType = NotificationConstant::SubscribeType::SYSTEM;
    infos.emplace_back(new (std::nothrow) NotificationExtensionSubscriptionInfo("addr", systemType));
    std::vector<sptr<NotificationBundleOption>> extensionBundles = {
        new NotificationBundleOption("", 0)
    };
    cloneBundleInfo.SetExtensionSubscriptionBundles(extensionBundles);
    cloneBundleInfo.SetExtensionSubscriptionInfos(infos);
    cloneBundleInfo.SetEnabledExtensionSubscription(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    cloneBundleInfo.SetBundleName("UpdateCloneBundleInfo_00009");
    cloneBundleInfo.SetUid(1);
    cloneBundleInfo.SetIsShowBadge(true);
    cloneBundleInfo.SetEnableNotification(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    cloneBundleInfo.SetSlotFlags(63);
    advancedNotificationService_->UpdateCloneBundleInfo(cloneBundleInfo, 0);
    SleepForFC();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("UpdateCloneBundleInfo_00009", 1);
    std::vector<sptr<NotificationBundleOption>> resultBundles;
    NotificationPreferences::GetInstance()->GetExtensionSubscriptionBundles(bundle, resultBundles);
    EXPECT_TRUE(resultBundles.empty());
}

/**
 * @tc.name: GetSystemSubscriptionStrategy_00001
 * @tc.desc: Test GetSystemSubscriptionStrategy with non-SYSTEM type info, priorityStrategy stays 0
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetSystemSubscriptionStrategy_00001, Function | SmallTest | Level1)
{
    MockIsNeedHapModuleInfos(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("RestoreClone_001", 1);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    infos.emplace_back(new NotificationExtensionSubscriptionInfo(
        "addr", NotificationConstant::SubscribeType::BLUETOOTH));
    NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundle, infos);
    int32_t resultStrategy = -1;
    auto ret = advancedNotificationService_->GetSystemSubscriptionStrategy(bundle, resultStrategy);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(resultStrategy, 0);
}

/**
 * @tc.name: GetSystemSubscriptionStrategy_00002
 * @tc.desc: Test GetSystemSubscriptionStrategy with empty bundleName returns error
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetSystemSubscriptionStrategy_00002, Function | SmallTest | Level1)
{
    MockIsNeedHapModuleInfos(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("", 1);
    int32_t resultStrategy = -1;
    auto ret = advancedNotificationService_->GetSystemSubscriptionStrategy(bundle, resultStrategy);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: GetSystemSubscriptionStrategy_00003
 * @tc.desc: Test GetSystemSubscriptionStrategy returns strategy from SYSTEM type info
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetSystemSubscriptionStrategy_00003, Function | SmallTest | Level1)
{
    MockIsNeedHapModuleInfos(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("GetSystemStrategy_00003", 1);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    sptr<NotificationExtensionSubscriptionInfo> systemInfo =
        new NotificationExtensionSubscriptionInfo("addr", NotificationConstant::SubscribeType::SYSTEM);
    systemInfo->SetPriorityStrategy(
        static_cast<int32_t>(NotificationConstant::PriorityStrategyStatus::STATUS_ALL_PRIORITY));
    infos.emplace_back(systemInfo);
    NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundle, infos);
    int32_t resultStrategy = 0;
    auto ret = advancedNotificationService_->GetSystemSubscriptionStrategy(bundle, resultStrategy);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(resultStrategy,
        static_cast<int32_t>(NotificationConstant::PriorityStrategyStatus::STATUS_ALL_PRIORITY));
}

/**
 * @tc.name: GetSystemSubscriptionStrategy_00004
 * @tc.desc: Test GetSystemSubscriptionStrategy skips nullptr info and hits SYSTEM type info
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetSystemSubscriptionStrategy_00004, Function | SmallTest | Level1)
{
    MockIsNeedHapModuleInfos(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("GetSystemStrategy_00004", 1);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    infos.emplace_back(nullptr);
    sptr<NotificationExtensionSubscriptionInfo> systemInfo =
        new NotificationExtensionSubscriptionInfo("addr", NotificationConstant::SubscribeType::SYSTEM);
    systemInfo->SetPriorityStrategy(
        static_cast<int32_t>(NotificationConstant::PriorityStrategyStatus::STATUS_INTELLIGENT));
    infos.emplace_back(systemInfo);
    NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundle, infos);
    int32_t resultStrategy = 0;
    auto ret = advancedNotificationService_->GetSystemSubscriptionStrategy(bundle, resultStrategy);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(resultStrategy,
        static_cast<int32_t>(NotificationConstant::PriorityStrategyStatus::STATUS_INTELLIGENT));
}
#endif
/**
 * @tc.name: ExecBatchCancel_00001
 * @tc.desc: Test ExecBatchCancel
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, ExecBatchCancel_00001, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    for (int i = 0; i < 201; i++) {
        auto slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
        sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
        request->SetSlotType(slotType);
        request->SetOwnerUserId(100);
        request->SetCreatorUserId(0);
        request->SetOwnerBundleName("test");
        request->SetOwnerUid(0);
        request->SetNotificationId(1000+i);
        auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
        auto ret = advancedNotificationService_->AssignToNotificationList(record);
        sptr<Notification> notification = new Notification(request);
        notifications.push_back(notification);
    }
    int reason = 28;
    advancedNotificationService_->ExecBatchCancel(notifications, reason);
    EXPECT_EQ(notifications.size() == 0, true);
}

/**
 * @tc.name: OnBootSystemCompleted_00001
 * @tc.desc: Test OnBootSystemCompleted
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, OnBootSystemCompleted_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->OnBootSystemCompleted();
}

/**
 * @tc.name: OnDistributedKvStoreDeathRecipient_00001
 * @tc.desc: Test OnDistributedKvStoreDeathRecipient
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, OnDistributedKvStoreDeathRecipient_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->OnDistributedKvStoreDeathRecipient();
    AdvancedNotificationService ans;
    ans.notificationSvrQueue_.Reset();
    ans.OnDistributedKvStoreDeathRecipient();
}

/**
 * @tc.name: SetRequestBundleInfo_00001
 * @tc.desc: Test SetRequestBundleInfo
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, SetRequestBundleInfo_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorBundleName("test");
    request->SetOwnerBundleName("test");
    std::string bundle;
    EXPECT_EQ(advancedNotificationService_->SetRequestBundleInfo(request, 1111, bundle), (int)ERR_OK);
}

/**
 * @tc.name: SendNotificationsOnCanceled_00001
 * @tc.desc: Test SendNotificationsOnCanceled
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, SendNotificationsOnCanceled_00001, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;
    sptr<NotificationRequest> request = new NotificationRequest();
    sptr<Notification> no = new Notification(request);
    notifications.push_back(no);
    advancedNotificationService_->SendNotificationsOnCanceled(notifications, nullptr, 1);
}

/**
 * @tc.name: OnRecoverLiveView_00001
 * @tc.desc: Test OnRecoverLiveView
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, OnRecoverLiveView_00001, Function | SmallTest | Level1)
{
    std::vector<std::string> keys;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    for (int i = 0; i < 10; i++) {
        auto slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
        sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
        request->SetSlotType(slotType);
        request->SetOwnerUserId(100);
        request->SetCreatorUserId(0);
        request->SetOwnerBundleName("test");
        request->SetOwnerUid(0);
        request->SetNotificationId(10000+i);
        auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
        auto ret = advancedNotificationService_->AssignToNotificationList(record);
        sptr<Notification> notification = new Notification(request);
        keys.push_back(notification->GetKey());
    }
    advancedNotificationService_->OnRecoverLiveView(keys);
}

/**
 * @tc.name: OnRecoverLiveView_00002
 * @tc.desc: Test OnRecoverLiveView
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, OnRecoverLiveView_00002, Function | SmallTest | Level1)
{
    std::vector<std::string> keys;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetOwnerUserId(100);
    request->SetCreatorUserId(0);
    request->SetOwnerBundleName("test");
    request->SetOwnerUid(0);
    request->SetNotificationId(222);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    auto ret = advancedNotificationService_->AssignToNotificationList(record);
    sptr<Notification> notification = new Notification(request);
    keys.push_back(notification->GetKey());
    keys.push_back("no");
    advancedNotificationService_->OnRecoverLiveView(keys);
}

/**
 * @tc.name: AllowUseReminder_00001
 * @tc.desc: Test AllowUseReminder
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, AllowUseReminder_00001, Function | SmallTest | Level1)
{
    std::string str = "test1";
    bool b = false;
    advancedNotificationService_->AllowUseReminder(str, b);
    EXPECT_EQ(advancedNotificationService_->AllowUseReminder(str, b), (int)ERR_OK);
}


#ifdef ENABLE_ANS_ADDITIONAL_CONTROL
HWTEST_F(AnsUtilsTest, AllowUseReminder_00002, Function | SmallTest | Level1)
{
    EXTENTION_WRAPPER->reminderControl_ = [](const std::string &bundleName) { return ERR_OK; };
    std::string str = "test1";

    EXPECT_TRUE(advancedNotificationService_->AllowUseReminder(str););
}

HWTEST_F(AnsUtilsTest, AllowUseReminder_00003, Function | SmallTest | Level1)
{
    EXTENTION_WRAPPER->reminderControl_ = [](const std::string &bundleName) { return ERR_ANS_INNER_INVALID_BUNDLE; };
    std::string str = "test1";

    EXPECT_FALSE(advancedNotificationService_->AllowUseReminder(str););
}

HWTEST_F(AnsUtilsTest, AllowUseReminder_00004, Function | SmallTest | Level1)
{
    EXTENTION_WRAPPER->reminderControl_ = [](const std::string &bundleName) { return ERR_OK; };
    std::string str = "test1";
    int32_t userId = 100;

    EXPECT_TRUE(advancedNotificationService_->AllowUseReminder(str, userId););
}

HWTEST_F(AnsUtilsTest, AllowUseReminder_00005, Function | SmallTest | Level1)
{
    EXTENTION_WRAPPER->reminderControl_ = [](const std::string &bundleName) { return ERR_ANS_INNER_INVALID_BUNDLE; };
    std::string str = "test1";
    int32_t userId = 100;

    EXPECT_FALSE(advancedNotificationService_->AllowUseReminder(str, userId););
}
#endif // ENABLE_ANS_ADDITIONAL_CONTROL

/**
 * @tc.name: AllowUseReminder_00006
 * @tc.desc: Test AllowUseReminder
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, AllowUseReminder_00006, Function | SmallTest | Level1)
{
    std::string str = "test1";
    bool b = false;
    int32_t userId = 100;
    ASSERT_EQ(advancedNotificationService_->AllowUseReminder(str, userId, b), (int)ERR_OK);
}

/**
 * @tc.name: AllowUseReminder_00008
 * @tc.desc: Test AllowUseReminder
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, AllowUseReminder_00008, Function | SmallTest | Level1)
{
    bool isOsAccountExists = false;
    OHOS::AccountSA::OsAccountManager::IsOsAccountExists(0, isOsAccountExists);
    MockIsOsAccountExists(false);
    std::string str = "test1";
    int32_t userId = -99;
    auto ret = advancedNotificationService_->AllowUseReminder(str, userId);
    EXPECT_FALSE(ret);
    MockIsOsAccountExists(isOsAccountExists);
}

/**
 * @tc.name: AllowUseReminder_00009
 * @tc.desc: Test AllowUseReminder return false when caller token is not native
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, AllowUseReminder_00009, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    std::string str = "test1";
    EXPECT_FALSE(advancedNotificationService_->AllowUseReminder(str));
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
}

/**
 * @tc.name: AllowUseReminder_00010
 * @tc.desc: Test AllowUseReminder with userId return false when caller token is not native
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, AllowUseReminder_00010, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    std::string str = "test1";
    int32_t userId = 100;
    EXPECT_FALSE(advancedNotificationService_->AllowUseReminder(str, userId));
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
}

/**
 * @tc.name: AllowUseReminder_00011
 * @tc.desc: Test AllowUseReminder out param is false when caller token is not native
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, AllowUseReminder_00011, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    std::string str = "test1";
    bool isAllowUseReminder = true;
    EXPECT_EQ(advancedNotificationService_->AllowUseReminder(str, isAllowUseReminder), (int)ERR_OK);
    EXPECT_FALSE(isAllowUseReminder);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
}

/**
 * @tc.name: AllowUseReminder_00012
 * @tc.desc: Test AllowUseReminder with userId out param is false when caller token is not native
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, AllowUseReminder_00012, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    std::string str = "test1";
    int32_t userId = 100;
    bool isAllowUseReminder = true;
    EXPECT_EQ(advancedNotificationService_->AllowUseReminder(str, userId, isAllowUseReminder), (int)ERR_OK);
    EXPECT_FALSE(isAllowUseReminder);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
}

/**
 * @tc.name: CloseAlert_00001
 * @tc.desc: Test CloseAlert
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, CloseAlert_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(222);
    auto flags = std::make_shared<NotificationFlags>();
    flags->SetBannerEnabled(NotificationConstant::FlagStatus::OPEN);
    request->SetFlags(flags);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->CloseAlert(record);
    advancedNotificationService_->AssignToNotificationList(record);
    EXPECT_EQ(advancedNotificationService_->notificationList_.size(), 1);
    EXPECT_EQ(advancedNotificationService_->notificationList_.front()->request->GetFlags()->GetReminderFlags(), 0);
}

/**
 * @tc.name: OnBundleDataUpdate_00002
 * @tc.desc: Test OnBundleDataUpdate
 * @tc.name: IsSupportTemplate_00001
 * @tc.desc: Test IsSupportTemplate
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, IsSupportTemplate_00001, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    std::string templateName = "";
    bool support = false;
    EXPECT_EQ(ans.IsSupportTemplate(templateName, support), (int)ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: CheckCommonParams_00002
 * @tc.desc: Test CheckCommonParams
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, CheckCommonParams_00002, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    EXPECT_EQ(advancedNotificationService_->CheckCommonParams(), (int)ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.name: DeleteAllByUser_0001
 * @tc.desc: Test DeleteAllByUser_0001
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, DeleteAllByUser_0001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    EXPECT_EQ(advancedNotificationService_->DeleteAllByUser(0), (int)ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.name: DeleteAllByUser_0001
 * @tc.desc: Test DeleteAllByUser_0001
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, DeleteAllByUser_0002, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    EXPECT_EQ(advancedNotificationService_->DeleteAllByUser(0), (int)ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.name: DeleteAllByUserInner_0001
 * @tc.desc: Test OnUserRemoved_0001
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, DeleteAllByUserInner_0001, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    ans.notificationSvrQueue_.Reset();
    EXPECT_EQ(ans.DeleteAllByUserInner(0, 0, true), (int)ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: CheckBundleOptionValid_0001
 * @tc.desc: Test CheckBundleOptionValid_0001
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, CheckBundleOptionValid_0001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = nullptr;
    EXPECT_EQ(advancedNotificationService_->CheckBundleOptionValid(bundle), (int)ERR_ANS_INNER_INVALID_PARAM);

    bundle = new (std::nothrow) NotificationBundleOption("", 1);
    EXPECT_EQ(advancedNotificationService_->CheckBundleOptionValid(bundle), (int)ERR_ANS_INNER_INVALID_PARAM);

    MockQueryForgroundOsAccountId(false, 0);
    bundle = new (std::nothrow) NotificationBundleOption("test", 1);
    EXPECT_EQ(advancedNotificationService_->CheckBundleOptionValid(bundle), (int)ERR_ANS_INNER_INVALID_BUNDLE);

    MockQueryForgroundOsAccountId(true, 0);
    EXPECT_EQ(advancedNotificationService_->CheckBundleOptionValid(bundle), (int)ERR_OK);

    sptr<NotificationBundleOption> bundle1 = new (std::nothrow) NotificationBundleOption("test", 1);
    MockQueryForgroundOsAccountId(true, 2);
    EXPECT_EQ(advancedNotificationService_->CheckBundleOptionValid(bundle1), (int)ERR_OK);

    sptr<NotificationBundleOption> bundle2 = new (std::nothrow) NotificationBundleOption("test", 0);
    EXPECT_EQ(advancedNotificationService_->CheckBundleOptionValid(bundle2), (int)ERR_ANS_INNER_INVALID_BUNDLE);

    sptr<NotificationBundleOption> bundle3 = new (std::nothrow) NotificationBundleOption("test", 0);
    MockQueryForgroundOsAccountId(true, 0);
    EXPECT_EQ(advancedNotificationService_->CheckBundleOptionValid(bundle3), (int)ERR_OK);
}

/**
 * @tc.name: GetCommonTargetRecordList_0001
 * @tc.desc: Test GetCommonTargetRecordList_0001
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetCommonTargetRecordList_0001, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("test", 1);
    request->SetSlotType(slotType);
    request->SetOwnerUserId(1);
    request->SetCreatorUserId(2);
    request->SetOwnerBundleName("test");
    request->SetOwnerUid(0);
    request->SetCreatorUid(1);
    request->SetNotificationId(1);

    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetIsOnlyLocalUpdate(true);
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);

    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundleOption);
    auto ret = advancedNotificationService_->AssignToNotificationList(record);
    std::vector<std::shared_ptr<NotificationRecord>> recordList;
    advancedNotificationService_->GetCommonTargetRecordList(1, NotificationConstant::SlotType::LIVE_VIEW,
        NotificationContent::Type::LIVE_VIEW, recordList);
    EXPECT_EQ(recordList.size(), 1);
}

/**
 * @tc.name: GetCommonTargetRecordList_0002
 * @tc.desc: Test GetCommonTargetRecordList skips null records and records with null request.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetCommonTargetRecordList_0002, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    advancedNotificationService_->notificationList_.push_back(nullptr);
    auto nullRequestRecord = std::make_shared<NotificationRecord>();
    advancedNotificationService_->notificationList_.push_back(nullRequestRecord);

    std::vector<std::shared_ptr<NotificationRecord>> recordList;
    auto ret = advancedNotificationService_->GetCommonTargetRecordList(1,
        NotificationConstant::SlotType::LIVE_VIEW, NotificationContent::Type::LIVE_VIEW, recordList);
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);
    EXPECT_TRUE(recordList.empty());
}

/**
 * @tc.name: GetCommonTargetRecordList_0003
 * @tc.desc: Test GetCommonTargetRecordList skips common live view request whose content is
 *           not live view content (dynamic cast fails), no null pointer dereference.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetCommonTargetRecordList_0003, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::BASIC_TEXT));
    content->content_ = normalContent;
    request->SetContent(content);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);

    std::vector<std::shared_ptr<NotificationRecord>> recordList;
    auto ret = advancedNotificationService_->GetCommonTargetRecordList(1,
        NotificationConstant::SlotType::LIVE_VIEW, NotificationContent::Type::LIVE_VIEW, recordList);
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);
    EXPECT_TRUE(recordList.empty());
}

/**
 * @tc.name: GetCommonTargetRecordList_0004
 * @tc.desc: Test GetCommonTargetRecordList skips common live view request whose content is null,
 *           no null pointer dereference.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetCommonTargetRecordList_0004, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request->notificationContentType_ = NotificationContent::Type::LIVE_VIEW;
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    advancedNotificationService_->notificationList_.push_back(record);

    std::vector<std::shared_ptr<NotificationRecord>> recordList;
    auto ret = advancedNotificationService_->GetCommonTargetRecordList(1,
        NotificationConstant::SlotType::LIVE_VIEW, NotificationContent::Type::LIVE_VIEW, recordList);
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);
    EXPECT_TRUE(recordList.empty());
}

/**
 * @tc.name: GetCommonTargetRecordList_0005
 * @tc.desc: Test GetCommonTargetRecordList skips common live view request whose content object
 *           holds a null inner content, no null pointer dereference.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetCommonTargetRecordList_0005, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    content->content_ = nullptr;
    request->SetContent(content);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    advancedNotificationService_->notificationList_.push_back(record);

    std::vector<std::shared_ptr<NotificationRecord>> recordList;
    auto ret = advancedNotificationService_->GetCommonTargetRecordList(1,
        NotificationConstant::SlotType::LIVE_VIEW, NotificationContent::Type::LIVE_VIEW, recordList);
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);
    EXPECT_TRUE(recordList.empty());
}

/**
 * @tc.name: GenerateBundleOption_00001
 * @tc.desc: Test GenerateBundleOption with a native token returns a bundle option with
 *           the calling uid and an empty bundle name.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GenerateBundleOption_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);

    auto bundleOption = advancedNotificationService_->GenerateBundleOption();

    ASSERT_NE(bundleOption, nullptr);
    EXPECT_EQ(bundleOption->GetBundleName(), "");
    EXPECT_EQ(bundleOption->GetUid(), IPCSkeleton::GetCallingUid());
    EXPECT_EQ(bundleOption->GetAppIndex(), 0);
}

/**
 * @tc.name: GenerateBundleOption_00002
 * @tc.desc: Test GenerateBundleOption with a non-native token and an empty client
 *           bundle name returns nullptr.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GenerateBundleOption_00002, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsNonBundleName(true);

    auto bundleOption = advancedNotificationService_->GenerateBundleOption();

    EXPECT_EQ(bundleOption, nullptr);
    MockIsNonBundleName(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
}

/**
 * @tc.name: GenerateBundleOption_00003
 * @tc.desc: Test GenerateBundleOption with a non-native token and a valid client
 *           bundle name returns a bundle option with the mocked bundle name.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GenerateBundleOption_00003, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsNonBundleName(false);

    auto bundleOption = advancedNotificationService_->GenerateBundleOption();

    ASSERT_NE(bundleOption, nullptr);
    EXPECT_EQ(bundleOption->GetBundleName(), "bundleName");
    EXPECT_EQ(bundleOption->GetUid(), 1);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
}

/**
 * @tc.name: GetAppTargetBundle_00001
 * @tc.desc: Test GetAppTargetBundle with a null bundle option assigns the client
 *           bundle to targetBundle.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetAppTargetBundle_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);

    sptr<NotificationBundleOption> targetBundle = nullptr;
    auto ret = advancedNotificationService_->GetAppTargetBundle(nullptr, targetBundle);

    EXPECT_EQ(ret, (int)ERR_OK);
    ASSERT_NE(targetBundle, nullptr);
    EXPECT_EQ(targetBundle->GetUid(), 1);
}

/**
 * @tc.name: GetAppTargetBundle_00002
 * @tc.desc: Test GetAppTargetBundle with a bundle option matching the client bundle
 *           keeps the passed option as target.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetAppTargetBundle_00002, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("", 1);

    sptr<NotificationBundleOption> targetBundle = nullptr;
    auto ret = advancedNotificationService_->GetAppTargetBundle(bundleOption, targetBundle);

    EXPECT_EQ(ret, (int)ERR_OK);
    EXPECT_EQ(targetBundle.GetRefPtr(), bundleOption.GetRefPtr());
}

/**
 * @tc.name: GetAppTargetBundle_00003
 * @tc.desc: Test GetAppTargetBundle with a mismatched bundle option and a non-system
 *           caller returns ERR_ANS_INNER_NON_SYSTEM_APP.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetAppTargetBundle_00003, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsNonBundleName(false);
    MockIsSystemApp(false);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("other", 999);

    sptr<NotificationBundleOption> targetBundle = nullptr;
    auto ret = advancedNotificationService_->GetAppTargetBundle(bundleOption, targetBundle);

    EXPECT_EQ(ret, (int)ERR_ANS_INNER_NON_SYSTEM_APP);

    MockIsSystemApp(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
}

/**
 * @tc.name: GetAppTargetBundle_00004
 * @tc.desc: Test GetAppTargetBundle with a mismatched bundle option and a system app
 *           resolves the option as target.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetAppTargetBundle_00004, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsNonBundleName(false);
    MockIsSystemApp(true);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("other", 999);

    sptr<NotificationBundleOption> targetBundle = nullptr;
    auto ret = advancedNotificationService_->GetAppTargetBundle(bundleOption, targetBundle);

    EXPECT_EQ(ret, (int)ERR_OK);
    EXPECT_EQ(targetBundle.GetRefPtr(), bundleOption.GetRefPtr());

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
}

/**
 * @tc.name: ResolveBundleOptionUids_00001
 * @tc.desc: Test ResolveBundleOptionUids skips null and unresolvable options and
 *           keeps the already valid one.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, ResolveBundleOptionUids_00001, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(true, 0);
    std::vector<sptr<NotificationBundleOption>> bundleOptions;
    bundleOptions.emplace_back(nullptr);
    bundleOptions.emplace_back(new (std::nothrow) NotificationBundleOption("bundleName", 20031005));
    bundleOptions.emplace_back(new (std::nothrow) NotificationBundleOption("testBundleName", 0));

    auto resolvedBundles = advancedNotificationService_->ResolveBundleOptionUids(bundleOptions);

    ASSERT_EQ(resolvedBundles.size(), 1);
    EXPECT_EQ(resolvedBundles[0]->GetBundleName(), "bundleName");
    EXPECT_EQ(resolvedBundles[0]->GetUid(), 20031005);
}

/**
 * @tc.name: GenerateSortingMap_00001
 * @tc.desc: Test GenerateSortingMap returns a map containing the key of the record
 *           in the notification list.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GenerateSortingMap_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    notification->SetKey("sorting_key_1");
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    record->slot = new (std::nothrow) NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    advancedNotificationService_->notificationList_.push_back(record);

    auto sortingMap = advancedNotificationService_->GenerateSortingMap();

    ASSERT_NE(sortingMap, nullptr);
    auto keys = sortingMap->GetKey();
    ASSERT_EQ(keys.size(), 1);
    EXPECT_EQ(keys[0], "sorting_key_1");
}

/**
 * @tc.name: AdjustDateForDndTypeOnce_00001
 * @tc.desc: Test AdjustDateForDndTypeOnce keeps the window duration for a window
 *           around the current time.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, AdjustDateForDndTypeOnce_00001, Function | SmallTest | Level1)
{
    constexpr int64_t oneHourMs = 3600 * 1000;
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    int64_t beginDate = now - oneHourMs;
    int64_t endDate = now + oneHourMs;

    advancedNotificationService_->AdjustDateForDndTypeOnce(beginDate, endDate);

    EXPECT_LT(beginDate, endDate);
    EXPECT_EQ(endDate - beginDate, 2 * oneHourMs);
}

/**
 * @tc.name: AdjustDateForDndTypeOnce_00002
 * @tc.desc: Test AdjustDateForDndTypeOnce shifts a fully past window to the next day.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, AdjustDateForDndTypeOnce_00002, Function | SmallTest | Level1)
{
    constexpr int64_t oneHourMs = 3600 * 1000;
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    int64_t beginDate = now - 2 * oneHourMs;
    int64_t endDate = now - oneHourMs;

    advancedNotificationService_->AdjustDateForDndTypeOnce(beginDate, endDate);

    EXPECT_LT(beginDate, endDate);
    EXPECT_EQ(endDate - beginDate, oneHourMs);
    EXPECT_GT(endDate, now);
}

/**
 * @tc.name: IsFromAccountNotification_00001
 * @tc.desc: Test IsFromAccountNotification with a null request returns false.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, IsFromAccountNotification_00001, Function | SmallTest | Level1)
{
    EXPECT_FALSE(advancedNotificationService_->IsFromAccountNotification(nullptr));
}

/**
 * @tc.name: IsFromAccountNotification_00002
 * @tc.desc: Test IsFromAccountNotification with a request without extendInfo returns false.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, IsFromAccountNotification_00002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();

    EXPECT_FALSE(advancedNotificationService_->IsFromAccountNotification(request));
}

/**
 * @tc.name: IsFromAccountNotification_00003
 * @tc.desc: Test IsFromAccountNotification with extendInfo carrying
 *           EXTENDINFO_IS_FROM_ACCOUNT true returns true.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, IsFromAccountNotification_00003, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto extendInfo = std::make_shared<AAFwk::WantParams>();
    extendInfo->SetParam(EXTENDINFO_IS_FROM_ACCOUNT, AAFwk::Boolean::Box(true));
    request->SetExtendInfo(extendInfo);

    EXPECT_TRUE(advancedNotificationService_->IsFromAccountNotification(request));
}

#ifdef ANS_FEATURE_ORIGINAL_DISTRIBUTED
/**
 * @tc.name: CheckDistributedNotificationType_00001
 * @tc.desc: Test CheckDistributedNotificationType with an empty device support list
 *           returns true without touching the distributed manager.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, CheckDistributedNotificationType_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();

    EXPECT_TRUE(advancedNotificationService_->CheckDistributedNotificationType(request));
}
#endif

/**
 * @tc.name: CheckApiCompatibility_00002
 * @tc.desc: Test CheckApiCompatibility returns false when the bundle manager mock
 *           reports api incompatibility.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, CheckApiCompatibility_00002, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundleName", 1);
    MockBundleManager::MockCheckApiCompatibility(false);

    EXPECT_FALSE(advancedNotificationService_->CheckApiCompatibility(bundleOption));
}

/**
 * @tc.name: SetAgentNotification_00001
 * @tc.desc: Test SetAgentNotification leaves the request unchanged when resolving
 *           the active user id fails.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, SetAgentNotification_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    std::string bundleName = "agentOwnerBundle";
    MockQueryForgroundOsAccountId(false, 0);

    advancedNotificationService_->SetAgentNotification(request, bundleName);

    EXPECT_FALSE(request->IsAgentNotification());

    MockQueryForgroundOsAccountId(true, 0);
}

/**
 * @tc.name: SetAgentNotification_00002
 * @tc.desc: Test SetAgentNotification marks the request as agent notification with
 *           the active user id and owner bundle name.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, SetAgentNotification_00002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    std::string bundleName = "agentOwnerBundle";
    MockQueryForgroundOsAccountId(true, 1);

    advancedNotificationService_->SetAgentNotification(request, bundleName);

    EXPECT_TRUE(request->IsAgentNotification());
    EXPECT_EQ(request->GetOwnerUserId(), 101);
    EXPECT_EQ(request->GetOwnerBundleName(), "agentOwnerBundle");

    MockQueryForgroundOsAccountId(true, 0);
}

/**
 * @tc.name: PrepareContinuousTaskNotificationRequest_00001
 * @tc.desc: Test PrepareContinuousTaskNotificationRequest fills creator uid/pid and
 *           the delivery time when it is unset.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, PrepareContinuousTaskNotificationRequest_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    constexpr int32_t testUid = 20031009;

    auto status = advancedNotificationService_->PrepareContinuousTaskNotificationRequest(request, testUid);

    EXPECT_TRUE(status.Ok());
    EXPECT_EQ(request->GetCreatorUid(), testUid);
    EXPECT_EQ(request->GetCreatorPid(), IPCSkeleton::GetCallingPid());
    EXPECT_GT(request->GetDeliveryTime(), 0);
}

/**
 * @tc.name: StartAutoDelete_00001
 * @tc.desc: Test StartAutoDelete returns the timer id created by the time service.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, StartAutoDelete_00001, Function | SmallTest | Level1)
{
    MockCreateTimerFailed(false);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto record = std::make_shared<NotificationRecord>();
    record->notification = new (std::nothrow) Notification(request);

    auto timerId = advancedNotificationService_->StartAutoDelete(record, 2000000000, 1);

    EXPECT_EQ(timerId, static_cast<uint64_t>(1));
    ResetTimeServiceMock();
}

/**
 * @tc.name: StartAutoDelete_00002
 * @tc.desc: Test StartAutoDelete returns zero when timer creation fails.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, StartAutoDelete_00002, Function | SmallTest | Level1)
{
    MockCreateTimerFailed(true);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto record = std::make_shared<NotificationRecord>();
    record->notification = new (std::nothrow) Notification(request);

    auto timerId = advancedNotificationService_->StartAutoDelete(record, 2000000000, 1);

    EXPECT_EQ(timerId, static_cast<uint64_t>(0));
    ResetTimeServiceMock();
}

/**
 * @tc.name: CancelTimer_00001
 * @tc.desc: Test CancelTimer with an invalid timer id does not destroy any timer.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, CancelTimer_00001, Function | SmallTest | Level1)
{
    ResetTimeServiceMock();

    advancedNotificationService_->CancelTimer(NotificationConstant::INVALID_TIMER_ID);

    EXPECT_FALSE(IsDestroyTimerCalled());
    ResetTimeServiceMock();
}

/**
 * @tc.name: CancelTimer_00002
 * @tc.desc: Test CancelTimer with a valid timer id destroys the timer.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, CancelTimer_00002, Function | SmallTest | Level1)
{
    ResetTimeServiceMock();

    advancedNotificationService_->CancelTimer(7);

    EXPECT_TRUE(IsDestroyTimerCalled());
    ResetTimeServiceMock();
}

/**
 * @tc.name: BatchCancelTimer_00001
 * @tc.desc: Test BatchCancelTimer skips invalid ids and cancels the valid ones.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, BatchCancelTimer_00001, Function | SmallTest | Level1)
{
    ResetTimeServiceMock();
    std::vector<uint64_t> emptyIds;
    advancedNotificationService_->BatchCancelTimer(emptyIds);
    EXPECT_FALSE(IsDestroyTimerCalled());

    std::vector<uint64_t> timerIds = {NotificationConstant::INVALID_TIMER_ID, 5};
    advancedNotificationService_->BatchCancelTimer(timerIds);

    EXPECT_TRUE(IsDestroyTimerCalled());
    ResetTimeServiceMock();
}

/**
 * @tc.name: GetCommonLiveViewRecordList_00001
 * @tc.desc: Test GetCommonLiveViewRecordList collects only the common live view record
 *           whose create pid matches and removal state is LIVE_VIEW_REMOVE.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, GetCommonLiveViewRecordList_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    constexpr int32_t testPid = 20031007;
    auto matchedRecord = std::make_shared<NotificationRecord>();
    {
        sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
        request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
        auto liveContent = std::make_shared<NotificationLiveViewContent>();
        liveContent->SetCreatePid(testPid);
        liveContent->SetRemoveOnProcessExitState(NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
        request->SetContent(std::make_shared<NotificationContent>(liveContent));
        matchedRecord->request = request;
        matchedRecord->notification = new (std::nothrow) Notification(request);
    }
    auto keptRecord = std::make_shared<NotificationRecord>();
    {
        sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
        request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
        auto liveContent = std::make_shared<NotificationLiveViewContent>();
        liveContent->SetCreatePid(testPid);
        request->SetContent(std::make_shared<NotificationContent>(liveContent));
        keptRecord->request = request;
        keptRecord->notification = new (std::nothrow) Notification(request);
    }
    auto normalRecord = std::make_shared<NotificationRecord>();
    {
        sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
        normalRecord->request = request;
        normalRecord->notification = new (std::nothrow) Notification(request);
    }
    advancedNotificationService_->notificationList_.push_back(matchedRecord);
    advancedNotificationService_->notificationList_.push_back(keptRecord);
    advancedNotificationService_->notificationList_.push_back(normalRecord);

    std::vector<std::shared_ptr<NotificationRecord>> recordList;
    advancedNotificationService_->GetCommonLiveViewRecordList(testPid, recordList);

    ASSERT_EQ(recordList.size(), 1);
    EXPECT_EQ(recordList.front(), matchedRecord);
}

/**
 * @tc.name: IsExistsPidInObservers_00001
 * @tc.desc: Test IsExistsPidInObservers reflects the observer map and RemoveAppObserver
 *           erases a stored null observer without unregistering.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, IsExistsPidInObservers_00001, Function | SmallTest | Level1)
{
    constexpr int32_t testPid = 20031008;
    advancedNotificationService_->appObserverMap_.clear();
    EXPECT_FALSE(advancedNotificationService_->IsExistsPidInObservers(testPid));

    advancedNotificationService_->appObserverMap_[testPid] = nullptr;
    EXPECT_TRUE(advancedNotificationService_->IsExistsPidInObservers(testPid));

    advancedNotificationService_->RemoveAppObserver(testPid);

    EXPECT_FALSE(advancedNotificationService_->IsExistsPidInObservers(testPid));
}
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
HWTEST_F(AnsUtilsTest, TestGenerateCloneValidBundleOption_NullBundleOption, Level1) {
    sptr<NotificationBundleOption> bundleOption = nullptr;
    sptr<NotificationBundleOption> result = advancedNotificationService_->GenerateCloneValidBundleOption(bundleOption);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(AnsUtilsTest, TestGenerateCloneValidBundleOption_EmptyBundleName, Level1) {
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("", 0);
    sptr<NotificationBundleOption> result = advancedNotificationService_->GenerateCloneValidBundleOption(bundleOption);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(AnsUtilsTest, TestGenerateCloneValidBundleOption_GetCurrentActiveUserIdFailed, Level1) {
    MockQueryForgroundOsAccountId(false, 0);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test_bundle", 0);
    sptr<NotificationBundleOption> result = advancedNotificationService_->GenerateCloneValidBundleOption(bundleOption);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(AnsUtilsTest, TestGenerateCloneValidBundleOption_GetCloneBundleInfoFailed, Level1) {
    MockQueryForgroundOsAccountId(true, 0);
    MockGetCloneBundleInfo(false);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test_false", 0);
    bundleOption->SetAppIndex(1);
    sptr<NotificationBundleOption> result = advancedNotificationService_->GenerateCloneValidBundleOption(bundleOption);
    EXPECT_NE(result, nullptr);
}

HWTEST_F(AnsUtilsTest, TestGenerateCloneValidBundleOption_GetCloneBundleInfoNormalCase, Level1) {
    MockQueryForgroundOsAccountId(true, 0);
    MockGetCloneBundleInfo(true);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test_bundle", 0);
    bundleOption->SetAppIndex(1);
    bundleOption->SetInstanceKey(10);
    sptr<NotificationBundleOption> result = advancedNotificationService_->GenerateCloneValidBundleOption(bundleOption);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result->GetBundleName(), "test_bundle");
    EXPECT_EQ(result->GetAppIndex(), 1);
    EXPECT_EQ(result->GetInstanceKey(), 10);
}

HWTEST_F(AnsUtilsTest, TestGenerateCloneValidBundleOption_GetBundleInfoV9NormalCase, Level1) {
    MockQueryForgroundOsAccountId(true, 0);
    MockSetBundleInfoFailed(false);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test_bundle", 0);
    bundleOption->SetAppIndex(0);
    bundleOption->SetInstanceKey(10);
    sptr<NotificationBundleOption> result = advancedNotificationService_->GenerateCloneValidBundleOption(bundleOption);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result->GetBundleName(), "test_bundle");
    EXPECT_EQ(result->GetAppIndex(), 0);
    EXPECT_EQ(result->GetInstanceKey(), 10);
}

HWTEST_F(AnsUtilsTest, TestGenerateCloneValidBundleOption_GetBundleInfoV9Failed, Level1) {
    MockQueryForgroundOsAccountId(true, 0);
    MockSetBundleInfoFailed(true);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test_bundle", 0);
    bundleOption->SetInstanceKey(10);
    sptr<NotificationBundleOption> result = advancedNotificationService_->GenerateCloneValidBundleOption(bundleOption);
    EXPECT_NE(result, nullptr);
}
#endif

/**
 * @tc.name: RemoveDoNotDisturbProfileTrustList_00001
 * @tc.desc: Test RemoveDoNotDisturbProfileTrustList
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, RemoveDoNotDisturbProfileTrustList_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    int32_t userId = 100;
    NotificationPreferences::GetInstance()->RemoveDoNotDisturbProfileTrustList(userId, bundle);
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;

    sptr<NotificationDoNotDisturbProfile> profile;
    preferencesInfo->doNotDisturbProfiles_["2_100_3"] = profile;

    preferencesInfo->GetAllDoNotDisturbProfiles(userId, profiles);
    EXPECT_EQ(profiles.size(), 1);
}

/**
 * @tc.name: RemoveDoNotDisturbProfileTrustList_00002
 * @tc.desc: Test RemoveDoNotDisturbProfileTrustList
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, RemoveDoNotDisturbProfileTrustList_00002, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    int32_t userId = 100;
    NotificationPreferences::GetInstance()->RemoveDoNotDisturbProfileTrustList(userId, bundle);
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;

    sptr<NotificationDoNotDisturbProfile> profile;
    preferencesInfo->doNotDisturbProfiles_["2_99_3"] = profile;

    preferencesInfo->GetAllDoNotDisturbProfiles(userId, profiles);
    EXPECT_EQ(profiles.size(), 0);
}

/**
 * @tc.name: ClassificationMgr_Remove_CancelDistributedNotification_00001
 * @tc.desc: Test ClassificationMgr Remove in CancelDistributedNotification.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, ClassificationMgr_Remove_CancelDistributedNotification_00001, Function | SmallTest | Level1)
{
    NotificationClassificationMgr::GetInstance().Clear();
    std::string key = "utils_cancel_distributed_test_key";
    sptr<NotificationClassification> classification = new NotificationClassification();
    NotificationClassificationMgr::GetInstance().AddOrUpdate(key, classification);
    EXPECT_TRUE(NotificationClassificationMgr::GetInstance().Exists(key));
    EXPECT_TRUE(NotificationClassificationMgr::GetInstance().Remove(key));
    EXPECT_FALSE(NotificationClassificationMgr::GetInstance().Exists(key));
}

/**
 * @tc.name: ClassificationMgr_Remove_DeleteAllByUserStopped_00001
 * @tc.desc: Test ClassificationMgr Remove in DeleteAllByUserStopped.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, ClassificationMgr_Remove_DeleteAllByUserStopped_00001, Function | SmallTest | Level1)
{
    NotificationClassificationMgr::GetInstance().Clear();
    std::string key = "utils_delete_all_user_stopped_test_key";
    sptr<NotificationClassification> classification = new NotificationClassification();
    NotificationClassificationMgr::GetInstance().AddOrUpdate(key, classification);
    EXPECT_TRUE(NotificationClassificationMgr::GetInstance().Exists(key));
    EXPECT_TRUE(NotificationClassificationMgr::GetInstance().Remove(key));
    EXPECT_FALSE(NotificationClassificationMgr::GetInstance().Exists(key));
}

/**
 * @tc.name: GetBundleVersionCode_NullBundleOption_00001
 * @tc.desc: Test GetBundleVersionCode with nullptr bundleOption.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(AnsUtilsTest, GetBundleVersionCode_NullBundleOption_00001, Function | SmallTest | Level1)
{
    uint32_t versionCode = 0;
    ErrCode ret = advancedNotificationService_->GetBundleVersionCode(nullptr, versionCode);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_BUNDLE);
    EXPECT_EQ(versionCode, 0u);
}

/**
 * @tc.name: GetBundleVersionCode_EmptyBundleName_00001
 * @tc.desc: Test GetBundleVersionCode with empty bundle name.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(AnsUtilsTest, GetBundleVersionCode_EmptyBundleName_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("", 1000);
    uint32_t versionCode = 0;
    ErrCode ret = advancedNotificationService_->GetBundleVersionCode(bundleOption, versionCode);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_BUNDLE);
    EXPECT_EQ(versionCode, 0u);
}

/**
 * @tc.name: GetBundleVersionCode_GetActiveUserIdFailed_00001
 * @tc.desc: Test GetBundleVersionCode when GetCurrentActiveUserId fails.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(AnsUtilsTest, GetBundleVersionCode_GetActiveUserIdFailed_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("com.test.bundle", 1000);
    uint32_t versionCode = 0;
    MockQueryForgroundOsAccountId(false, 0);
    ErrCode ret = advancedNotificationService_->GetBundleVersionCode(bundleOption, versionCode);
    EXPECT_EQ(ret, ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
    EXPECT_EQ(versionCode, 0u);
    MockQueryForgroundOsAccountId(true, 0);
}

/**
 * @tc.name: GetBundleVersionCode_GetBundleInfoFailed_00001
 * @tc.desc: Test GetBundleVersionCode when GetBundleInfoV9 fails.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(AnsUtilsTest, GetBundleVersionCode_GetBundleInfoFailed_00001, Function | SmallTest | Level1)
{
    MockBundleManager::MockBundleRseult(false);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("invalid.bundle", 1000);
    uint32_t versionCode = 0;
    ErrCode ret = advancedNotificationService_->GetBundleVersionCode(bundleOption, versionCode);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_BUNDLE);
    EXPECT_EQ(versionCode, 0u);
    MockBundleManager::MockBundleRseult(true);
}

/**
 * @tc.name: GetBundleVersionCode_ValidBundle_00001
 * @tc.desc: Test GetBundleVersionCode with valid bundle option.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(AnsUtilsTest, GetBundleVersionCode_ValidBundle_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("com.test.bundle", 1000);
    uint32_t versionCode = 0;
    MockSetBundleInfoFailed(false);
    ErrCode ret = advancedNotificationService_->GetBundleVersionCode(bundleOption, versionCode);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: PrePublishNotificationBySa_PresetCreatorUserId_00001
 * @tc.desc: Test PrePublishNotificationBySa keeps the preset CreatorUserId without re-resolution
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, PrePublishNotificationBySa_PresetCreatorUserId_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUserId(2); // already resolved, no re-resolution
    std::string bundle = "";

    auto result = advancedNotificationService_->PrePublishNotificationBySa(request, 100, bundle);
    EXPECT_TRUE(result.Ok());
    EXPECT_EQ(request->GetCreatorUserId(), 2);
}

/**
 * @tc.name: PrePublishNotificationBySa_ResolveCreatorFailed_00001
 * @tc.desc: Test PrePublishNotificationBySa fails when CreatorUid to userId resolution fails
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, PrePublishNotificationBySa_ResolveCreatorFailed_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(100);
    std::string bundle = "";

    MockGetOsAccountLocalIdFromUid(false, 0); // resolution fails
    auto result = advancedNotificationService_->PrePublishNotificationBySa(request, 100, bundle);
    EXPECT_FALSE(result.Ok()); // resolution failure is rejected
    EXPECT_EQ(result.GetErrCode(), ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
    EXPECT_EQ(request->GetCreatorUserId(), SUBSCRIBE_USER_INIT); // creatorUserId is not set
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

/**
 * @tc.name: PrePublishNotificationBySa_InvalidResolvedUserId_00001
 * @tc.desc: Test PrePublishNotificationBySa fails when resolved userId is invalid (<= 0)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, PrePublishNotificationBySa_InvalidResolvedUserId_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(100);
    std::string bundle = "";

    MockGetOsAccountLocalIdFromUid(true, 1); // mock invalid userId (-2)
    auto result = advancedNotificationService_->PrePublishNotificationBySa(request, 100, bundle);
    EXPECT_FALSE(result.Ok()); // invalid resolved userId is rejected
    EXPECT_EQ(result.GetErrCode(), ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
    EXPECT_EQ(request->GetCreatorUserId(), SUBSCRIBE_USER_INIT); // creatorUserId is not set
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

/**
 * @tc.name: PrePublishNotificationBySa_ZeroCreatorUidResolveFailed_00001
 * @tc.desc: Test PrePublishNotificationBySa with zero CreatorUid (callingUid path) rejects resolution failure
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, PrePublishNotificationBySa_ZeroCreatorUidResolveFailed_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(0); // falls into the callingUid branch
    std::string bundle = "";

    MockGetOsAccountLocalIdFromUid(false, 0); // calling-uid resolution fails
    auto result = advancedNotificationService_->PrePublishNotificationBySa(request, 100, bundle);
    EXPECT_FALSE(result.Ok()); // resolution failure is rejected
    EXPECT_EQ(result.GetErrCode(), ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
    EXPECT_EQ(request->GetCreatorUserId(), SUBSCRIBE_USER_INIT); // creatorUserId is not set
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

/**
 * @tc.name: PrePublishNotificationBySa_ValidCreatorUid_00001
 * @tc.desc: Test PrePublishNotificationBySa resolves userId from CreatorUid and stores it in the request
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, PrePublishNotificationBySa_ValidCreatorUid_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(100);
    std::string bundle = "";

    auto result = advancedNotificationService_->PrePublishNotificationBySa(request, 100, bundle);
    EXPECT_TRUE(result.Ok());
    EXPECT_EQ(request->GetCreatorUserId(), 100); // annex mock default id is 100
}

/**
 * @tc.name: ResolveCreatorUserId_PresetUserId_00001
 * @tc.desc: Test ResolveCreatorUserId keeps the preset CreatorUserId and returns Ok without re-resolution
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, ResolveCreatorUserId_PresetUserId_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUserId(2); // already resolved, early return expected
    request->SetCreatorUid(100);

    MockGetOsAccountLocalIdFromUid(false, 0); // resolution would fail if re-resolved
    auto result = advancedNotificationService_->ResolveCreatorUserId(request);
    EXPECT_TRUE(result.Ok());
    EXPECT_EQ(request->GetCreatorUserId(), 2); // preset value is kept
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

/**
 * @tc.name: ResolveCreatorUserId_CreatorUidResolveFailed_00001
 * @tc.desc: Test ResolveCreatorUserId fails when CreatorUid resolution returns error
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, ResolveCreatorUserId_CreatorUidResolveFailed_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(100);

    MockGetOsAccountLocalIdFromUid(false, 0); // resolution fails
    auto result = advancedNotificationService_->ResolveCreatorUserId(request);
    EXPECT_FALSE(result.Ok());
    EXPECT_EQ(result.GetErrCode(), ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
    EXPECT_EQ(request->GetCreatorUserId(), SUBSCRIBE_USER_INIT); // creatorUserId is not set
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

/**
 * @tc.name: ResolveCreatorUserId_CreatorUidInvalidUserId_00001
 * @tc.desc: Test ResolveCreatorUserId fails when CreatorUid resolves to an invalid userId
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, ResolveCreatorUserId_CreatorUidInvalidUserId_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(100);

    MockGetOsAccountLocalIdFromUid(true, 1); // mock invalid userId (-2)
    auto result = advancedNotificationService_->ResolveCreatorUserId(request);
    EXPECT_FALSE(result.Ok());
    EXPECT_EQ(result.GetErrCode(), ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
    EXPECT_EQ(request->GetCreatorUserId(), SUBSCRIBE_USER_INIT); // creatorUserId is not set
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

/**
 * @tc.name: ResolveCreatorUserId_CallingUidResolveFailed_00001
 * @tc.desc: Test ResolveCreatorUserId fails when callingUid resolution returns error (CreatorUid is 0)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, ResolveCreatorUserId_CallingUidResolveFailed_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(0); // falls into the callingUid branch

    MockGetOsAccountLocalIdFromUid(false, 0); // resolution fails
    auto result = advancedNotificationService_->ResolveCreatorUserId(request);
    EXPECT_FALSE(result.Ok());
    EXPECT_EQ(result.GetErrCode(), ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
    EXPECT_EQ(request->GetCreatorUserId(), SUBSCRIBE_USER_INIT); // creatorUserId is not set
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

/**
 * @tc.name: ResolveCreatorUserId_CallingUidInvalidUserId_00001
 * @tc.desc: Test ResolveCreatorUserId fails when callingUid resolves to an invalid userId (CreatorUid is 0)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, ResolveCreatorUserId_CallingUidInvalidUserId_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(0); // falls into the callingUid branch

    MockGetOsAccountLocalIdFromUid(true, 1); // mock invalid userId (-2)
    auto result = advancedNotificationService_->ResolveCreatorUserId(request);
    EXPECT_FALSE(result.Ok());
    EXPECT_EQ(result.GetErrCode(), ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
    EXPECT_EQ(request->GetCreatorUserId(), SUBSCRIBE_USER_INIT); // creatorUserId is not set
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

/**
 * @tc.name: ResolveCreatorUserId_CallingUidValidUserId_00001
 * @tc.desc: Test ResolveCreatorUserId stores the resolved userId when callingUid resolution succeeds
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, ResolveCreatorUserId_CallingUidValidUserId_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(0); // falls into the callingUid branch

    auto result = advancedNotificationService_->ResolveCreatorUserId(request);
    EXPECT_TRUE(result.Ok());
    EXPECT_EQ(request->GetCreatorUserId(), 100); // annex mock default id is 100
}

/**
 * @tc.name: ResolveCreatorUserId_ValidCreatorUid_00001
 * @tc.desc: Test ResolveCreatorUserId stores the resolved userId when CreatorUid resolution succeeds
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, ResolveCreatorUserId_ValidCreatorUid_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(100);

    auto result = advancedNotificationService_->ResolveCreatorUserId(request);
    EXPECT_TRUE(result.Ok());
    EXPECT_EQ(request->GetCreatorUserId(), 100); // annex mock default id is 100
}

/**
 * @tc.name: PrePublishNotificationBySa_OwnerUidInvalidUserId_00001
 * @tc.desc: Test PrePublishNotificationBySa fails when OwnerUid resolves to invalid userId
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, PrePublishNotificationBySa_OwnerUidInvalidUserId_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUserId(100); // preset, ResolveCreatorUserId early-returns without mock call
    request->SetCreatorUid(100);
    request->SetOwnerUid(200); // non-default owner uid, OwnerUserId stays SUBSCRIBE_USER_INIT
    std::string bundle = "";

    // CreatorUserId is preset so only the OwnerUid resolution sees the invalid mock id (-2)
    MockGetOsAccountLocalIdFromUid(true, 1); // mock invalid userId (-2)
    auto result = advancedNotificationService_->PrePublishNotificationBySa(request, 100, bundle);
    EXPECT_FALSE(result.Ok());
    EXPECT_EQ(result.GetErrCode(), ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
    EXPECT_EQ(request->GetCreatorUserId(), 100); // preset creator userId is kept
    EXPECT_EQ(request->GetOwnerUserId(), SUBSCRIBE_USER_INIT); // owner userId is not set
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
/**
 * @tc.name: DelNormalCloneBundleForExtensionSubscription_InvalidUserId_00001
 * @tc.desc: Test DelNormalCloneBundleForExtensionSubscription returns early when
 *           GetOsAccountLocalIdFromUid fails or resolved userId < 0
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, DelNormalCloneBundleForExtensionSubscription_InvalidUserId_00001,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 1);

    MockGetOsAccountLocalIdFromUid(false, 0); // resolution fails
    advancedNotificationService_->DelNormalCloneBundleForExtensionSubscription(bundle);
    EXPECT_NE(bundle, nullptr);

    MockGetOsAccountLocalIdFromUid(true, 1); // invalid userId (-2)
    advancedNotificationService_->DelNormalCloneBundleForExtensionSubscription(bundle);
    EXPECT_NE(bundle, nullptr);
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

/**
 * @tc.name: DelNormalCloneBundleForExtensionSubscription_EmptyUpdatedBundles_00001
 * @tc.desc: Test DelNormalCloneBundleForExtensionSubscription with valid userId and empty
 *           updated bundles returns early without crash
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, DelNormalCloneBundleForExtensionSubscription_EmptyUpdatedBundles_00001,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 1);

    // mock default userId 100 is a system account, updated bundles are empty -> early return
    advancedNotificationService_->DelNormalCloneBundleForExtensionSubscription(bundle);
    EXPECT_NE(bundle, nullptr);
}
#endif
}  // namespace Notification
}  // namespace OHOS
