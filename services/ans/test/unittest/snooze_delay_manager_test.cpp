/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "ans_result_data_synchronizer.h"
#include "accesstoken_kit.h"
#include "notification_preferences.h"
#include "notification_constant.h"
#include "notification_config_parse.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

extern void MockIsOsAccountExists(bool mockRet);

namespace OHOS {
namespace Notification {
extern void MockIsVerfyPermisson(bool isVerify);
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);
extern void MockIsNonBundleName(bool isNonBundleName);

class AnsSnoozeDelayTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AnsSnoozeDelayTest::advancedNotificationService_ = nullptr;

void AnsSnoozeDelayTest::SetUpTestCase() {}

void AnsSnoozeDelayTest::TearDownTestCase() {}

void AnsSnoozeDelayTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
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

void AnsSnoozeDelayTest::TearDown()
{
    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
    advancedNotificationService_->timerImpl_.StopTimer();
    advancedNotificationService_->timerImpl_.DestroyTimer();
    delete advancedNotificationService_;
    advancedNotificationService_ = nullptr;
    GTEST_LOG_(INFO) << "TearDown";
}

/**
 * @tc.name: SnoozeNotification_00001
 * @tc.desc: Test SnoozeNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, SnoozeNotification_00001, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    std::string hashCode = "test123";
    int64_t delayTime = 10;
    ASSERT_EQ(advancedNotificationService_->SnoozeNotification(hashCode, delayTime),
        (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.name: SnoozeNotification_00002
 * @tc.desc: Test SnoozeNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, SnoozeNotification_00002, Function | SmallTest | Level1)
{
    MockIsSystemApp(false);
    MockIsVerfyPermisson(true);
    std::string hashCode = "test123";
    int64_t delayTime = 10;
    ASSERT_EQ(advancedNotificationService_->SnoozeNotification(hashCode, delayTime),
        (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);

    MockIsSystemApp(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    ASSERT_EQ(advancedNotificationService_->SnoozeNotification(hashCode, delayTime),
        (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    ASSERT_EQ(advancedNotificationService_->SnoozeNotification(hashCode, delayTime), (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: SnoozeNotification_00003
 * @tc.desc: Test SnoozeNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, SnoozeNotification_00003, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    std::string hashCode = "test123";
    int64_t delayTime = 10;
    ASSERT_EQ(advancedNotificationService_->SnoozeNotification(hashCode, delayTime), (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: ExcuteSnoozeNotification_00001
 * @tc.desc: Test ExcuteSnoozeNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, ExcuteSnoozeNotification_00001, Function | SmallTest | Level1)
{
    std::string hashCode = "test123";
    int64_t delayTime = NotificationAnalyticsUtil::GetCurrentTime() + 60000;
    auto record = std::make_shared<NotificationRecord>();
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    record->request = request;
    record->notification = nullptr;
    advancedNotificationService_->notificationList_.push_back(record);

    notification->SetKey("test111");
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request;
    record1->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record1);
    advancedNotificationService_->notificationList_.push_back(nullptr);
    ASSERT_EQ(advancedNotificationService_->ExcuteSnoozeNotification(hashCode, delayTime),
        (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.name: ExcuteSnoozeNotification_00002
 * @tc.desc: Test ExcuteSnoozeNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, ExcuteSnoozeNotification_00002, Function | SmallTest | Level1)
{
    std::string hashCode = "test123";
    int64_t delayTime = NotificationAnalyticsUtil::GetCurrentTime() + 60000;
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW));
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    notification->SetKey(hashCode);
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request;
    record1->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record1);
    ASSERT_EQ(advancedNotificationService_->ExcuteSnoozeNotification(hashCode, delayTime),
        (int)ERR_ANS_NOTIFICATION_SNOOZE_NOTALLOWED);
}

/**
 * @tc.name: ExcuteSnoozeNotification_00003
 * @tc.desc: Test ExcuteSnoozeNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, ExcuteSnoozeNotification_00003, Function | SmallTest | Level1)
{
    std::string hashCode = "test123";
    int64_t delayTime = NotificationAnalyticsUtil::GetCurrentTime() + 60000;
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    liveViewContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::LOCAL_LIVE_VIEW));
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    notification->SetKey(hashCode);
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request;
    record1->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record1);
    ASSERT_EQ(advancedNotificationService_->ExcuteSnoozeNotification(hashCode, delayTime),
        (int)ERR_ANS_NOTIFICATION_SNOOZE_NOTALLOWED);
}

/**
 * @tc.name: ExcuteSnoozeNotification_00004
 * @tc.desc: Test ExcuteSnoozeNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, ExcuteSnoozeNotification_00004, Function | SmallTest | Level1)
{
    std::string hashCode = "test123";
    int64_t delayTime = NotificationAnalyticsUtil::GetCurrentTime() + 60000;
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    auto normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetContentType(1);
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    request->SetRemoveAllowed(false);
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bundleOption->SetBundleName("testName");
    notification->SetKey(hashCode);
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request;
    record1->notification = notification;
    record1->bundleOption = bundleOption;
    advancedNotificationService_->notificationList_.push_back(record1);
    ASSERT_EQ(advancedNotificationService_->ExcuteSnoozeNotification(hashCode, delayTime),
        (int)ERR_ANS_NOTIFICATION_SNOOZE_NOTALLOWED);
}

/**
 * @tc.name: ExcuteSnoozeNotification_00005
 * @tc.desc: Test ExcuteSnoozeNotification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, ExcuteSnoozeNotification_00005, Function | SmallTest | Level1)
{
    std::string hashCode = "test123";
    int64_t delayTime = NotificationAnalyticsUtil::GetCurrentTime() + 60000;
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bundleOption->SetBundleName("testName");
    auto normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetContentType(1);
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    notification->SetKey(hashCode);
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request;
    record1->notification = notification;
    record1->bundleOption = bundleOption;
    advancedNotificationService_->notificationList_.push_back(record1);
    ASSERT_EQ(advancedNotificationService_->ExcuteSnoozeNotification(hashCode, delayTime), (int)ERR_OK);
}

/**
 * @tc.name: SnoozeNotificationConsumed_00001
 * @tc.desc: Test SnoozeNotificationConsumed
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, SnoozeNotificationConsumed_00001, Function | SmallTest | Level1)
{
    int32_t uid = 50;
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    auto normalContent = std::make_shared<NotificationNormalContent>();
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("MyTestBundle", uid);
    normalContent->SetContentType(1);
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    notification->SetKey("test123");
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request;
    record1->notification = notification;
    record1->request->SetUpdateOnly(true);
    record1->bundleOption = bundleOption;
    advancedNotificationService_->SnoozeNotificationConsumed(nullptr);
    advancedNotificationService_->SnoozeNotificationConsumed(record1);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);

    advancedNotificationService_->notificationList_.push_back(record1);
    advancedNotificationService_->SetSilentReminderEnabledInner(bundleOption, true);
    advancedNotificationService_->SnoozeNotificationConsumed(record1);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);
}

/**
 * @tc.name: IsCanRecoverSnooze_00001
 * @tc.desc: Test IsCanRecoverSnooze
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, IsCanRecoverSnooze_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    auto normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetContentType(1);
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    int64_t delayTime = NotificationAnalyticsUtil::GetCurrentTime() + 60000;
    request->SetSnoozeDelayTime(delayTime);
    request->SetIsSnoozeTrigger(false);
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request;
    record1->notification = notification;
    ASSERT_EQ(advancedNotificationService_->IsCanRecoverSnooze(record1), true);
}

/**
 * @tc.name: IsCanRecoverSnooze_00002
 * @tc.desc: Test IsCanRecoverSnooze
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, IsCanRecoverSnooze_00002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    auto normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetContentType(1);
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    int64_t delayTime = NotificationAnalyticsUtil::GetCurrentTime() - 60000;
    request->SetSnoozeDelayTime(delayTime);
    request->SetIsSnoozeTrigger(false);
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request;
    record1->notification = notification;
    ASSERT_EQ(advancedNotificationService_->IsCanRecoverSnooze(record1), false);
}

/**
 * @tc.name: IsCanRecoverSnooze_00003
 * @tc.desc: Test IsCanRecoverSnooze
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, IsCanRecoverSnooze_00003, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    auto normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetContentType(1);
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    int64_t delayTime = NotificationAnalyticsUtil::GetCurrentTime() + 60000;
    request->SetSnoozeDelayTime(delayTime);
    request->SetIsSnoozeTrigger(true);
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request;
    record1->notification = notification;
    ASSERT_EQ(advancedNotificationService_->IsCanRecoverSnooze(record1), false);
}

/**
 * @tc.name: TriggerSnoozeDelay_00001
 * @tc.desc: Test TriggerSnoozeDelay
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, TriggerSnoozeDelay_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bundleOption->SetBundleName("testName");
    auto normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetContentType(1);
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    int64_t delayTime = NotificationAnalyticsUtil::GetCurrentTime() - 1;
    request->SetSnoozeDelayTime(delayTime);
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request;
    record1->notification = notification;
    record1->bundleOption = bundleOption;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record1);
    advancedNotificationService_->TriggerSnoozeDelay();
    ASSERT_EQ(advancedNotificationService_->snoozeDelayTimerList_.size(), 0);
}

/**
 * @tc.name: TriggerSnoozeDelay_00002
 * @tc.desc: Test TriggerSnoozeDelay
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, TriggerSnoozeDelay_00002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    auto normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetContentType(1);
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    int64_t delayTime = NotificationAnalyticsUtil::GetCurrentTime() + 60000;
    request->SetSnoozeDelayTime(delayTime);
    request->SetIsSnoozeTrigger(true);
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record1);
    advancedNotificationService_->TriggerSnoozeDelay();
    ASSERT_EQ(advancedNotificationService_->snoozeDelayTimerList_.size(), 1);
}

/**
 * @tc.name: InsertsnoozeDelayTimer_00001
 * @tc.desc: Test InsertsnoozeDelayTimer
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, InsertsnoozeDelayTimer_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->snoozeDelayTimerList_.clear();
    advancedNotificationService_->InsertsnoozeDelayTimer(nullptr);
    ASSERT_EQ(advancedNotificationService_->snoozeDelayTimerList_.size(), 0);
}

/**
 * @tc.name: StartSnoozeTimer_00001
 * @tc.desc: Test StartSnoozeTimer
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, StartSnoozeTimer_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    auto normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetContentType(1);
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    int64_t delayTime = NotificationAnalyticsUtil::GetCurrentTime() + 60000;
    request->SetSnoozeDelayTime(delayTime);
    request->SetIsSnoozeTrigger(true);
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record1);
    ASSERT_EQ(advancedNotificationService_->StartSnoozeTimer(), true);

    advancedNotificationService_->snoozeDelayTimerList_.clear();
    ASSERT_EQ(advancedNotificationService_->StartSnoozeTimer(), false);
}

/**
 * @tc.name: RemoveAllFromSnoozeDelayList_00001
 * @tc.desc: Test RemoveAllFromSnoozeDelayList
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, RemoveAllFromSnoozeDelayList_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request;
    record1->bundleOption = nullptr;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record1);

    auto record2 = std::make_shared<NotificationRecord>();
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bundleOption->SetBundleName("testBundle");
    bundleOption->SetUid(100);
    record2->request = request;
    record2->bundleOption = bundleOption;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record2);
    advancedNotificationService_->RemoveAllFromSnoozeDelayList(nullptr);
    advancedNotificationService_->RemoveAllFromSnoozeDelayList(bundleOption);

    ASSERT_EQ(advancedNotificationService_->snoozeDelayTimerList_.size(), 1);
}

/**
 * @tc.name: RemoveAllFromSnoozeDelayList_00002
 * @tc.desc: Test RemoveAllFromSnoozeDelayList
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, RemoveAllFromSnoozeDelayList_00002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    auto record = std::make_shared<NotificationRecord>();
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bundleOption->SetBundleName("testBundle");
    bundleOption->SetUid(100);
    sptr<NotificationBundleOption> bundleOption1 = new NotificationBundleOption();
    bundleOption1->SetBundleName("testBundle1");
    bundleOption1->SetUid(100);
    record->request = request;
    record->bundleOption = bundleOption;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record);
    advancedNotificationService_->RemoveAllFromSnoozeDelayList(bundleOption1);
    ASSERT_EQ(advancedNotificationService_->snoozeDelayTimerList_.size(), 1);
}

/**
 * @tc.name: RemoveAllFromSnoozeDelayList_00003
 * @tc.desc: Test RemoveAllFromSnoozeDelayList
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, RemoveAllFromSnoozeDelayList_00003, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    auto record = std::make_shared<NotificationRecord>();
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bundleOption->SetBundleName("testBundle");
    bundleOption->SetUid(101);
    sptr<NotificationBundleOption> bundleOption1 = new NotificationBundleOption();
    bundleOption1->SetBundleName("testBundle");
    bundleOption1->SetUid(100);
    record->request = request;
    record->bundleOption = bundleOption;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record);
    advancedNotificationService_->RemoveAllFromSnoozeDelayList(bundleOption1);
    ASSERT_EQ(advancedNotificationService_->snoozeDelayTimerList_.size(), 1);
}

/**
 * @tc.name: RemoveAllFromSnoozeDelayListByUser_00001
 * @tc.desc: Test RemoveAllFromSnoozeDelayListByUser
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, RemoveAllFromSnoozeDelayListByUser_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->snoozeDelayTimerList_.clear();
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    request->SetCreatorUserId(100);
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bundleOption->SetBundleName("testBundle");
    bundleOption->SetUid(100);

    sptr<NotificationRequest> request1(new (std::nothrow) NotificationRequest());
    request1->SetCreatorUserId(101);
    sptr<Notification> notification1(new (std::nothrow) Notification(request1));
    auto record1 = std::make_shared<NotificationRecord>();
    record1->request = request1;
    record1->bundleOption = bundleOption;
    record1->notification = notification1;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record1);

    auto record2 = std::make_shared<NotificationRecord>();
    record2->request = request;
    record2->bundleOption = bundleOption;
    record2->notification = notification;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record2);
    advancedNotificationService_->RemoveAllFromSnoozeDelayListByUser(100);

    ASSERT_EQ(advancedNotificationService_->snoozeDelayTimerList_.size(), 1);
}

/**
 * @tc.name: IsSetSnooze_00001
 * @tc.desc: Test IsSetSnooze
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, IsSetSnooze_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->snoozeDelayTimerList_.clear();
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    request->SetCreatorUserId(100);
    int64_t delayTime = NotificationAnalyticsUtil::GetCurrentTime() + 60000;
    request->SetSnoozeDelayTime(delayTime);
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    notification->SetKey("test111");
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bundleOption->SetBundleName("testBundle");
    bundleOption->SetUid(100);

    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->bundleOption = bundleOption;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record);
    ASSERT_EQ(advancedNotificationService_->IsSetSnooze("test123"), false);
}

/**
 * @tc.name: IsSetSnooze_00002
 * @tc.desc: Test IsSetSnooze
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, IsSetSnooze_00002, Function | SmallTest | Level1)
{
    advancedNotificationService_->snoozeDelayTimerList_.clear();
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    request->SetCreatorUserId(100);
    int64_t delayTime = NotificationAnalyticsUtil::GetCurrentTime() + 60000;
    request->SetSnoozeDelayTime(delayTime);
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    notification->SetKey("test123_test");
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bundleOption->SetBundleName("testBundle");
    bundleOption->SetUid(100);

    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->bundleOption = bundleOption;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService_->IsSetSnooze("test123"), true);
}

/**
 * @tc.name: IsSetSnooze_00003
 * @tc.desc: Test IsSetSnooze
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, IsSetSnooze_00003, Function | SmallTest | Level1)
{
    advancedNotificationService_->snoozeDelayTimerList_.clear();
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    request->SetCreatorUserId(100);
    int64_t delayTime = NotificationAnalyticsUtil::GetCurrentTime() + 60000;
    request->SetSnoozeDelayTime(delayTime);
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    notification->SetKey("test123_test");
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bundleOption->SetBundleName("testBundle");
    bundleOption->SetUid(100);

    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->bundleOption = bundleOption;
    record->notification = notification;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record);
    ASSERT_EQ(advancedNotificationService_->IsSetSnooze("test123"), true);
}

/**
 * @tc.name: IsSetSnooze_00004
 * @tc.desc: Test IsSetSnooze
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, IsSetSnooze_00004, Function | SmallTest | Level1)
{
    advancedNotificationService_->snoozeDelayTimerList_.clear();
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    request->SetCreatorUserId(100);
    request->SetUpdateOnly(true);
    int64_t delayTime = NotificationAnalyticsUtil::GetCurrentTime() + 60000;
    request->SetSnoozeDelayTime(delayTime);
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    notification->SetKey("test123_test");
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bundleOption->SetBundleName("testBundle");
    bundleOption->SetUid(100);

    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->bundleOption = bundleOption;
    record->notification = notification;

    ASSERT_EQ(advancedNotificationService_->AssignToNotificationList(record),
        (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.name: IsSetSnooze_00005
 * @tc.desc: Test IsSetSnooze
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, IsSetSnooze_00005, Function | SmallTest | Level1)
{
    advancedNotificationService_->snoozeDelayTimerList_.clear();
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    request->SetCreatorUserId(100);
    request->SetUpdateOnly(true);
    int64_t delayTime = NotificationAnalyticsUtil::GetCurrentTime() + 60000;
    request->SetSnoozeDelayTime(delayTime);
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    notification->SetKey("test123_test");
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bundleOption->SetBundleName("testBundle");
    bundleOption->SetUid(100);

    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->bundleOption = bundleOption;
    record->notification = notification;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record);
    ASSERT_EQ(advancedNotificationService_->AssignToNotificationList(record),
        (int)ERR_OK);
}
}  // namespace Notification
}  // namespace OHOS
