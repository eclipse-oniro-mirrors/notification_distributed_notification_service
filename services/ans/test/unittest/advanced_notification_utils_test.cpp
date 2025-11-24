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
#include "ans_log_wrapper.h"
#include "ans_result_data_synchronizer.h"
#include "ans_ut_constant.h"
#include "iremote_object.h"
#include "ipc_skeleton.h"
#include "want_agent_info.h"
#include "want_agent_helper.h"
#include "want_params.h"
#include "int_wrapper.h"
#include "accesstoken_kit.h"
#include "notification_preferences.h"
#include "notification_constant.h"
#include "notification_record.h"
#include "notification_subscriber.h"
#include "refbase.h"
#include "bundle_manager_helper.h"
#include "mock_bundle_mgr.h"
#include "notification_extension_wrapper.h"
#include "os_account_manager_helper.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::Security::AccessToken;

extern void MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase);

namespace OHOS {
namespace Notification {
extern void MockIsVerfyPermisson(bool isVerify);
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);

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

    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
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
    ASSERT_EQ(ret, (int)ERR_OK);
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
    ASSERT_EQ(ret, (int)ERR_OK);

    record->bundleOption->SetBundleName("bundleName");
    ret = advancedNotificationService_->IsAllowedGetNotificationByFilter(record, bundle);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);

    record->bundleOption->SetBundleName("test");
    record->bundleOption->SetUid(2);
    ret = advancedNotificationService_->IsAllowedGetNotificationByFilter(record, bundle);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
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
    ans.notificationSvrQueue_ = nullptr;
    std::string label = "testLabel";
    std::vector<std::string> keys = {"key1"};
    sptr<NotificationRequest> newRequest;
    auto bundleOption = new NotificationBundleOption("test", 1);
    int notificationId = 1;
    int32_t userId = -1;
    ASSERT_EQ(ans.GetActiveNotificationByFilter(bundleOption, notificationId, label, userId, keys, newRequest),
        (int)ERR_ANS_INVALID_PARAM);
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
    ASSERT_EQ(advancedNotificationService_->GetActiveNotificationByFilter(
        bundle, notificationId, label, userId, keys, newRequest),
        (int)ERR_ANS_INVALID_BUNDLE);
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
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto record = advancedNotificationService_->MakeNotificationRecord(oldRequest, bundle);
    advancedNotificationService_->AssignToNotificationList(record);


    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    std::vector<std::string> keys;
    sptr<NotificationRequest> newRequest;
    ASSERT_EQ(advancedNotificationService_->GetActiveNotificationByFilter(bundle,
        notificationId, label, userId, keys, newRequest), (int)ERR_ANS_PERMISSION_DENIED);

    MockIsVerfyPermisson(true);
    ASSERT_EQ(advancedNotificationService_->GetActiveNotificationByFilter(bundle,
        notificationId, label, userId, keys, newRequest), (int)ERR_OK);

    keys.emplace_back("test1");
    ASSERT_EQ(advancedNotificationService_->GetActiveNotificationByFilter(bundle,
        notificationId, label, userId, keys, newRequest), (int)ERR_OK);
    
    sptr<NotificationBundleOption> bundle1 = new NotificationBundleOption("test1", 1);
    ASSERT_EQ(advancedNotificationService_->GetActiveNotificationByFilter(bundle1,
        notificationId, label, userId, keys, newRequest), (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

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
    ASSERT_EQ(ret, (int)ERR_OK);
    ASSERT_EQ(dumpInfo.size(), 1);
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
    ASSERT_EQ(ret, (int)ERR_OK);
    ASSERT_EQ(dumpInfo.size(), 1);
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
    ASSERT_EQ(ret, (int)ERR_OK);
    ASSERT_EQ(dumpInfo.size(), 1);
}

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
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 2);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    auto keys = advancedNotificationService_->GetLocalNotificationKeys(bundle2);
    ASSERT_EQ(keys.size(), 1);
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
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    record->deviceId = "deviceId";
#endif  // DISTRIBUTED_NOTIFICATION_SUPPORTED
    advancedNotificationService_->AssignToNotificationList(record);
    advancedNotificationService_->OnBundleDataCleared(bundle);
    SleepForFC();
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);
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
    advancedNotificationService.notificationSvrQueue_ = nullptr;
    advancedNotificationService.OnBundleDataCleared(bundle);
    ASSERT_EQ(advancedNotificationService.notificationList_.size(), 1);
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
    ASSERT_EQ(static_cast<int32_t>(state), 3);
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
    ASSERT_EQ(static_cast<int32_t>(state), 2);
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
    ASSERT_EQ(res, false);
    MockSetBundleInfoFailed(false);
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
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);

    advancedNotificationService_->OnBundleRemoved(bundle);
    SleepForFC();
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);
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
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    advancedNotificationService_->OnBundleRemoved(bundle);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);
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
    ASSERT_EQ(static_cast<int32_t>(state), 2);
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
    ASSERT_EQ(static_cast<int32_t>(state), 3);
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
    ASSERT_EQ(static_cast<int32_t>(state), 0);
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
    ASSERT_EQ(static_cast<int32_t>(state), 3);
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
    ASSERT_EQ(static_cast<int32_t>(state), 0);
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
    ASSERT_EQ(list.size(), 2);
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
    ans.notificationSvrQueue_ = nullptr;
    ans.ResetDistributedEnabled();
    SleepForFC();
    std::string value;
    NotificationPreferences::GetInstance()->GetKvFromDb("tableVersion", value, 0);
    ASSERT_NE(value, "1");
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
    ASSERT_EQ(value, "1");
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
    std::vector<sptr<NotificationBundleOption>> extensionBundles = {
        new NotificationBundleOption("extension.bundle1", 0),
        new NotificationBundleOption("extension.bundle2", 0)
    };
    cloneBundleInfo.SetExtensionSubscriptionBundles(extensionBundles);
    NotificationCloneBundleInfo::SlotInfo info;
    info.slotType_ = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    info.enable_ = true;
    cloneBundleInfo.AddSlotInfo(info);
    advancedNotificationService_->UpdateCloneBundleInfo(cloneBundleInfo, 0);
    SleepForFC();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    ASSERT_EQ(static_cast<int32_t>(state), 1);
    std::vector<sptr<NotificationBundleOption>> resultBundles;
    NotificationPreferences::GetInstance()->GetExtensionSubscriptionBundles(bundle, resultBundles);
    ASSERT_TRUE(resultBundles.empty());
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
    std::vector<sptr<NotificationBundleOption>> extensionBundles = {
        new NotificationBundleOption("extension.bundle3", 0)
    };
    cloneBundleInfo.SetExtensionSubscriptionBundles(extensionBundles);
    NotificationCloneBundleInfo::SlotInfo info;
    info.slotType_ = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    info.enable_ = true;
    cloneBundleInfo.AddSlotInfo(info);
    ans.notificationSvrQueue_ = nullptr;
    ans.UpdateCloneBundleInfo(cloneBundleInfo, 0);
    SleepForFC();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("UpdateCloneBundleInfo_00002", 1);
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    ASSERT_EQ(static_cast<int32_t>(state), 0);
    std::vector<sptr<NotificationBundleOption>> resultBundles;
    NotificationPreferences::GetInstance()->GetExtensionSubscriptionBundles(bundle, resultBundles);
    ASSERT_TRUE(resultBundles.empty());
}

/**
 * @tc.name: UpdateCloneBundleInfo_00003
 * @tc.desc: Test UpdateCloneBundleInfo
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, UpdateCloneBundleInfo_00003, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    NotificationCloneBundleInfo cloneBundleInfo;
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    auto type = NotificationConstant::SubscribeType::BLUETOOTH;
    infos.emplace_back(new (std::nothrow) NotificationExtensionSubscriptionInfo("addr", type));
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
    ans.notificationSvrQueue_ = nullptr;
    ans.UpdateCloneBundleInfo(cloneBundleInfo, 0);
    SleepForFC();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("UpdateCloneBundleInfo_00003", 1);
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    ASSERT_EQ(static_cast<int32_t>(state), 0);
}

/**
 * @tc.name: UpdateCloneBundleInfo_00004
 * @tc.desc: Test UpdateCloneBundleInfo
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, UpdateCloneBundleInfo_00004, Function | SmallTest | Level1)
{
    NotificationCloneBundleInfo cloneBundleInfo;
    cloneBundleInfo.SetBundleName("test");
    cloneBundleInfo.SetUid(1);
    cloneBundleInfo.SetIsShowBadge(true);
    cloneBundleInfo.SetEnabledExtensionSubscription(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    advancedNotificationService_->UpdateCloneBundleInfo(cloneBundleInfo, 0);
    SleepForFC();
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test", 1);
    NotificationConstant::SWITCH_STATE state {};
    bool isExist = false;
    ErrCode result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionEnabled(bundleOption, state);
    ASSERT_EQ(result, ERR_OK);
    ASSERT_EQ(state, NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
}

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
    ASSERT_EQ(notifications.size() == 0, true);
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
    ans.notificationSvrQueue_ = nullptr;
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
    ASSERT_EQ(advancedNotificationService_->SetRequestBundleInfo(request, 1111, bundle), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->AllowUseReminder(str, b), (int)ERR_OK);
}


#ifdef ENABLE_ANS_ADDITIONAL_CONTROL
HWTEST_F(AnsUtilsTest, AllowUseReminder_00002, Function | SmallTest | Level1)
{
    EXTENTION_WRAPPER->reminderControl_ = [](const std::string &bundleName) { return ERR_OK; };
    std::string str = "test1";
    
    ASSERT_TRUE(advancedNotificationService_->AllowUseReminder(str););
}

HWTEST_F(AnsUtilsTest, AllowUseReminder_00003, Function | SmallTest | Level1)
{
    EXTENTION_WRAPPER->reminderControl_ = [](const std::string &bundleName) { return ERR_ANS_INVALID_BUNDLE; };
    std::string str = "test1";
    
    ASSERT_FALSE(advancedNotificationService_->AllowUseReminder(str););
}
#endif // ENABLE_ANS_ADDITIONAL_CONTROL

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
    flags->SetBannerEnabled(true);
    request->SetFlags(flags);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->CloseAlert(record);
    advancedNotificationService_->AssignToNotificationList(record);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);
    ASSERT_EQ(advancedNotificationService_->notificationList_.front()->request->GetFlags()->GetReminderFlags(), 0);
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
    ASSERT_EQ(ans.IsSupportTemplate(templateName, support), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: CheckCommonParams_00001
 * @tc.desc: Test CheckCommonParams
 * @tc.name: CheckCommonParams_00001
 * @tc.desc: Test CheckCommonParams
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, CheckCommonParams_00001, Function | SmallTest | Level1)
{
    AdvancedNotificationService ans;
    ans.notificationSvrQueue_ = nullptr;
    ASSERT_EQ(ans.CheckCommonParams(), (int)ERR_ANS_INVALID_PARAM);
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
    ASSERT_EQ(advancedNotificationService_->CheckCommonParams(), (int)ERR_ANS_NON_SYSTEM_APP);
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
    ASSERT_EQ(advancedNotificationService_->DeleteAllByUser(0), (int)ERR_ANS_NON_SYSTEM_APP);
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
    ASSERT_EQ(advancedNotificationService_->DeleteAllByUser(0), (int)ERR_ANS_PERMISSION_DENIED);
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
    ans.notificationSvrQueue_ = nullptr;
    ASSERT_EQ(ans.DeleteAllByUserInner(0, 0, true), (int)ERR_ANS_INVALID_PARAM);
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
    ASSERT_EQ(advancedNotificationService_->CheckBundleOptionValid(bundle), (int)ERR_ANS_INVALID_PARAM);

    bundle = new (std::nothrow) NotificationBundleOption("", 1);
    ASSERT_EQ(advancedNotificationService_->CheckBundleOptionValid(bundle), (int)ERR_ANS_INVALID_PARAM);

    MockQueryForgroundOsAccountId(false, 0);
    bundle = new (std::nothrow) NotificationBundleOption("test", 1);
    ASSERT_EQ(advancedNotificationService_->CheckBundleOptionValid(bundle), (int)ERR_ANS_INVALID_BUNDLE);

    MockQueryForgroundOsAccountId(true, 0);
    ASSERT_EQ(advancedNotificationService_->CheckBundleOptionValid(bundle), (int)ERR_OK);

    sptr<NotificationBundleOption> bundle1 = new (std::nothrow) NotificationBundleOption("test", 1);
    MockQueryForgroundOsAccountId(true, 2);
    ASSERT_EQ(advancedNotificationService_->CheckBundleOptionValid(bundle1), (int)ERR_OK);

    sptr<NotificationBundleOption> bundle2 = new (std::nothrow) NotificationBundleOption("test", 0);
    ASSERT_EQ(advancedNotificationService_->CheckBundleOptionValid(bundle2), (int)ERR_ANS_INVALID_BUNDLE);

    sptr<NotificationBundleOption> bundle3 = new (std::nothrow) NotificationBundleOption("test", 0);
    MockQueryForgroundOsAccountId(true, 0);
    ASSERT_EQ(advancedNotificationService_->CheckBundleOptionValid(bundle3), (int)ERR_OK);
}

/**
 * @tc.name: SubmitAsyncTask_0001
 * @tc.desc: Test SubmitAsyncTask_0001
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, SubmitAsyncTask_0001, Function | SmallTest | Level1)
{
    ErrCode result = ERR_OK;
    advancedNotificationService_->SubmitAsyncTask(std::bind([&]() {
        result = ERR_ANS_INVALID_PARAM;
    }));
    SleepForFC();
    ASSERT_EQ(result, (int)ERR_ANS_INVALID_PARAM);
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
    ASSERT_EQ(recordList.size(), 1);
}

/**
 * @tc.name: UpdateCloneBundleInfoForRingtone_0001
 * @tc.desc: old device without rington info, new device has.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, UpdateCloneBundleInfoForRingtone_0001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("com.ohos.demo", 20020300);
    sptr<NotificationRingtoneInfo> info = new NotificationRingtoneInfo(
        NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE, "title", "name", "uri");
    NotificationPreferences::GetInstance()->SetRingtoneInfoByBundle(bundleOption, info);

    NotificationRingtoneInfo ringtoneInfo;
    NotificationCloneBundleInfo cloneBundleInfo;
    advancedNotificationService_->UpdateCloneBundleInfoForRingtone(ringtoneInfo, 100, bundleOption, cloneBundleInfo);

    sptr<NotificationRingtoneInfo> newInfo = new NotificationRingtoneInfo();
    auto reuslt = NotificationPreferences::GetInstance()->GetRingtoneInfoByBundle(bundleOption, newInfo);
    ASSERT_EQ(reuslt, (int32_t)ERR_ANS_NO_CUSTOM_RINGTONE_INFO);
}

/**
 * @tc.name: UpdateCloneBundleInfoForRingtone_0002
 * @tc.desc: old device without rington info, new device has.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, UpdateCloneBundleInfoForRingtone_0002, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("com.ohos.demo", 20020300);

    NotificationCloneBundleInfo cloneBundleInfo;
    cloneBundleInfo.SetAppIndex(0);
    cloneBundleInfo.SetBundleName("com.ohos.demo");
    NotificationRingtoneInfo ringtoneInfo(NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE,
        "title", "name", "uri");
    advancedNotificationService_->UpdateCloneBundleInfoForRingtone(ringtoneInfo, 100, bundleOption, cloneBundleInfo);

    NotificationPreferences::GetInstance()->SetNotificationsEnabledForBundle(bundleOption,
        NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
    sptr<NotificationRingtoneInfo> newInfo = new NotificationRingtoneInfo();
    auto reuslt = NotificationPreferences::GetInstance()->GetRingtoneInfoByBundle(bundleOption, newInfo);
    ASSERT_EQ(reuslt, (int32_t)ERR_ANS_NO_CUSTOM_RINGTONE_INFO);

    // not in clone range time
    int32_t userId = SUBSCRIBE_USER_INIT;
    OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    int64_t curTime = NotificationAnalyticsUtil::GetCurrentTime() - NotificationConstant::MAX_CLONE_TIME - 10000;
    NotificationPreferences::GetInstance()->SetCloneTimeStamp(userId, curTime);

    advancedNotificationService_->UpdateCloneBundleInfoForRingtone(ringtoneInfo, 100, bundleOption, cloneBundleInfo);
    reuslt = NotificationPreferences::GetInstance()->GetRingtoneInfoByBundle(bundleOption, newInfo);
    ASSERT_EQ(reuslt, (int32_t)ERR_ANS_NO_CUSTOM_RINGTONE_INFO);

    // not in clone range time
    curTime = NotificationAnalyticsUtil::GetCurrentTime() + NotificationConstant::MAX_CLONE_TIME;
    NotificationPreferences::GetInstance()->SetCloneTimeStamp(userId, curTime);

    advancedNotificationService_->UpdateCloneBundleInfoForRingtone(ringtoneInfo, 100, bundleOption, cloneBundleInfo);
    reuslt = NotificationPreferences::GetInstance()->GetRingtoneInfoByBundle(bundleOption, newInfo);
    ASSERT_EQ(reuslt, (int32_t)ERR_ANS_NO_CUSTOM_RINGTONE_INFO);

    // not in clone range time
    curTime = NotificationAnalyticsUtil::GetCurrentTime() - 100000;
    NotificationPreferences::GetInstance()->SetCloneTimeStamp(userId, curTime);

    advancedNotificationService_->UpdateCloneBundleInfoForRingtone(ringtoneInfo, 100, bundleOption, cloneBundleInfo);
    reuslt = NotificationPreferences::GetInstance()->GetRingtoneInfoByBundle(bundleOption, newInfo);
    ASSERT_EQ(reuslt, (int32_t)ERR_OK);
    ASSERT_EQ(newInfo->GetRingtoneUri(), "uri");

    NotificationPreferences::GetInstance()->RemoveRingtoneInfoByBundle(bundleOption);
}

/**
 * @tc.name: UpdateCloneBundleInfoForRingtone_0003
 * @tc.desc: continuous cloning.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsUtilsTest, UpdateCloneBundleInfoForRingtone_0003, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("com.ohos.demo", 20020300);

    NotificationCloneBundleInfo cloneBundleInfo;
    cloneBundleInfo.SetAppIndex(0);
    cloneBundleInfo.SetBundleName("com.ohos.demo");
    NotificationRingtoneInfo ringtoneInfo(NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE,
        "title", "name", "uri");

    NotificationCloneBundleInfo bundleInfo;
    sptr<NotificationRingtoneInfo> cloneRingtoneInfo = new NotificationRingtoneInfo(
        NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE, "title", "name", "uri");
    cloneBundleInfo.AddRingtoneInfo(cloneRingtoneInfo);
    NotificationPreferences::GetInstance()->UpdateCloneRingtoneInfo(100, cloneBundleInfo);
    advancedNotificationService_->UpdateCloneBundleInfoForRingtone(ringtoneInfo, 100, bundleOption, cloneBundleInfo);

    // case
    cloneRingtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    NotificationPreferences::GetInstance()->UpdateCloneRingtoneInfo(100, cloneBundleInfo);
    advancedNotificationService_->UpdateCloneBundleInfoForRingtone(ringtoneInfo, 100, bundleOption, cloneBundleInfo);
    // case
    cloneRingtoneInfo->SetRingtoneTitle("title1");
    NotificationPreferences::GetInstance()->UpdateCloneRingtoneInfo(100, cloneBundleInfo);
    advancedNotificationService_->UpdateCloneBundleInfoForRingtone(ringtoneInfo, 100, bundleOption, cloneBundleInfo);
    // case
    cloneRingtoneInfo->SetRingtoneFileName("name1");
    NotificationPreferences::GetInstance()->UpdateCloneRingtoneInfo(100, cloneBundleInfo);
    advancedNotificationService_->UpdateCloneBundleInfoForRingtone(ringtoneInfo, 100, bundleOption, cloneBundleInfo);
    // case
    cloneRingtoneInfo->SetRingtoneUri("uri1");
    NotificationPreferences::GetInstance()->UpdateCloneRingtoneInfo(100, cloneBundleInfo);
    advancedNotificationService_->UpdateCloneBundleInfoForRingtone(ringtoneInfo, 100, bundleOption, cloneBundleInfo);
    // case
    cloneRingtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE);
    NotificationPreferences::GetInstance()->UpdateCloneRingtoneInfo(100, cloneBundleInfo);
    advancedNotificationService_->UpdateCloneBundleInfoForRingtone(ringtoneInfo, 100, bundleOption, cloneBundleInfo);
    // case
    cloneRingtoneInfo->SetRingtoneTitle("title");
    NotificationPreferences::GetInstance()->UpdateCloneRingtoneInfo(100, cloneBundleInfo);
    advancedNotificationService_->UpdateCloneBundleInfoForRingtone(ringtoneInfo, 100, bundleOption, cloneBundleInfo);
    // case
    cloneRingtoneInfo->SetRingtoneFileName("name");
    NotificationPreferences::GetInstance()->UpdateCloneRingtoneInfo(100, cloneBundleInfo);
    advancedNotificationService_->UpdateCloneBundleInfoForRingtone(ringtoneInfo, 100, bundleOption, cloneBundleInfo);

    NotificationPreferences::GetInstance()->SetNotificationsEnabledForBundle(bundleOption,
        NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
    sptr<NotificationRingtoneInfo> newInfo = new NotificationRingtoneInfo();
    auto reuslt = NotificationPreferences::GetInstance()->GetRingtoneInfoByBundle(bundleOption, newInfo);
    ASSERT_EQ(reuslt, (int32_t)ERR_OK);

    NotificationPreferences::GetInstance()->RemoveRingtoneInfoByBundle(bundleOption);
}

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
    sptr<NotificationBundleOption> result = advancedNotificationService_->GenerateCloneValidBundleOption(bundleOption);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(AnsUtilsTest, TestGenerateCloneValidBundleOption_NormalCase, Level1) {
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
}  // namespace Notification
}  // namespace OHOS
