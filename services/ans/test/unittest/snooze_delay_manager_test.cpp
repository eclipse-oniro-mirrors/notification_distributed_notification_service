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
#include "singleton.h"
#include <functional>
#include <memory>
#include <thread>

#include "gtest/gtest.h"

#define private public
#include "advanced_notification_service.h"
#include "advanced_datashare_helper.h"
#include "ans_inner_errors.h"
#include "ans_service_errors.h"
#include "ans_log_wrapper.h"
#include "accesstoken_kit.h"
#include "mock_datashare.h"
#include "mock_time_service_client.h"
#include "notification_flags.h"
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

void AnsSnoozeDelayTest::TearDownTestCase()
{
    sptr<AdvancedNotificationService> instance = AdvancedNotificationService::GetInstance();
    if (instance != nullptr) {
        instance->SelfClean(false);
    }
}

void AnsSnoozeDelayTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
    advancedNotificationService_->CancelAll("");
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    GTEST_LOG_(INFO) << "SetUp end";
}

void AnsSnoozeDelayTest::TearDown()
{
    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
    advancedNotificationService_->timerImpl_.StopTimer();
    advancedNotificationService_->timerImpl_.DestroyTimer();
    advancedNotificationService_->SelfClean();
    NotificationPreferences::GetInstance()->StopCacheCleanupTimer();
    NotificationSubscriberManager::DestroyInstance();
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
        (int)ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);
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
        (int)ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);

    MockIsSystemApp(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    ASSERT_EQ(advancedNotificationService_->SnoozeNotification(hashCode, delayTime),
        (int)ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    ASSERT_EQ(advancedNotificationService_->SnoozeNotification(hashCode, delayTime), (int)ERR_ANS_INNER_NON_SYSTEM_APP);
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
    ASSERT_EQ(advancedNotificationService_->SnoozeNotification(hashCode, delayTime),
        (int)ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.name: SnoozeNotification_00004
 * @tc.desc: Test SnoozeNotification with invalid delayTime (zero)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, SnoozeNotification_00004, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    std::string hashCode = "test123";
    int64_t delayTime = 0;
    ASSERT_EQ(advancedNotificationService_->SnoozeNotification(hashCode, delayTime),
        (int)ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: SnoozeNotification_00005
 * @tc.desc: Test SnoozeNotification with invalid delayTime (negative)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, SnoozeNotification_00005, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    std::string hashCode = "test123";
    int64_t delayTime = -1;
    ASSERT_EQ(advancedNotificationService_->SnoozeNotification(hashCode, delayTime),
        (int)ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: SnoozeNotification_00006
 * @tc.desc: Test SnoozeNotification with delayTime exceeding MAX_DELAY_TIME_S
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, SnoozeNotification_00006, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    std::string hashCode = "test123";
    int64_t delayTime = NotificationConstant::MAX_DELAY_TIME_S + 1;
    ASSERT_EQ(advancedNotificationService_->SnoozeNotification(hashCode, delayTime),
        (int)ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: SnoozeNotification_00007
 * @tc.desc: Test SnoozeNotification with INT64_MAX delayTime to prevent multiplication overflow
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, SnoozeNotification_00007, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    std::string hashCode = "test123";
    int64_t delayTime = INT64_MAX;
    ASSERT_EQ(advancedNotificationService_->SnoozeNotification(hashCode, delayTime),
        (int)ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: SnoozeNotification_00008
 * @tc.desc: Test SnoozeNotification with boundary valid delayTime (MAX_DELAY_TIME_S)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, SnoozeNotification_00008, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    std::string hashCode = "test123";
    int64_t delayTime = NotificationConstant::MAX_DELAY_TIME_S;
    ASSERT_EQ(advancedNotificationService_->SnoozeNotification(hashCode, delayTime),
        (int)ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);
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
        (int)ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);
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
        (int)ERR_ANS_INNER_NOTIFICATION_SNOOZE_NOTALLOWED);
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
        (int)ERR_ANS_INNER_NOTIFICATION_SNOOZE_NOTALLOWED);
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
        (int)ERR_ANS_INNER_NOTIFICATION_SNOOZE_NOTALLOWED);
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
 * @tc.name: SnoozeNotificationConsumed_00002
 * @tc.desc: Test SnoozeNotificationConsumed
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, SnoozeNotificationConsumed_00002, Function | SmallTest | Level1)
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
    record1->request = nullptr;
    record1->notification = notification;
    record1->bundleOption = bundleOption;
    advancedNotificationService_->SnoozeNotificationConsumed(nullptr);
    advancedNotificationService_->SnoozeNotificationConsumed(record1);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);
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
    advancedNotificationService_->StartSnoozeTimer();
    advancedNotificationService_->snoozeDelayTimerList_.clear();
    ASSERT_EQ(advancedNotificationService_->StartSnoozeTimer(), false);
}

/**
 * @tc.name: RemoveAllFromSnoozeDelayList_00001
 * @tc.desc: Test RemoveAllFromSnoozeDelayList. Records with null bundleOption are erased
 *           and records matching the given bundle are removed.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, RemoveAllFromSnoozeDelayList_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->snoozeDelayTimerList_.clear();
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

    ASSERT_EQ(advancedNotificationService_->snoozeDelayTimerList_.size(), 0);
}

/**
 * @tc.name: RemoveAllFromSnoozeDelayList_00002
 * @tc.desc: Test RemoveAllFromSnoozeDelayList
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, RemoveAllFromSnoozeDelayList_00002, Function | SmallTest | Level1)
{
    advancedNotificationService_->snoozeDelayTimerList_.clear();
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
    advancedNotificationService_->snoozeDelayTimerList_.clear();
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
 * @tc.name: RemoveAllFromSnoozeDelayList_00004
 * @tc.desc: Test RemoveAllFromSnoozeDelayList when has nullptr
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, RemoveAllFromSnoozeDelayList_00004, Function | SmallTest | Level1)
{
    advancedNotificationService_->snoozeDelayTimerList_.clear();
    advancedNotificationService_->snoozeDelayTimerList_.push_back(nullptr);
    auto record0 = std::make_shared<NotificationRecord>();
    sptr<NotificationBundleOption> bundleOption0 = new NotificationBundleOption();
    bundleOption0->SetBundleName("testBundle");
    bundleOption0->SetUid(50);
    record0->bundleOption = bundleOption0;
    record0->request = nullptr;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record0);

    sptr<NotificationRequest> request1(new (std::nothrow) NotificationRequest());
    request1->SetOwnerUid(200);
    auto record1 = std::make_shared<NotificationRecord>();
    sptr<NotificationBundleOption> bundleOption1 = new NotificationBundleOption();
    bundleOption1->SetBundleName("testBundle1");
    bundleOption1->SetUid(100);
    record1->request = request1;
    record1->bundleOption = bundleOption1;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record1);

    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption();
    targetBundle->SetBundleName("targetBundle");
    advancedNotificationService_->RemoveAllFromSnoozeDelayList(targetBundle);

    ASSERT_EQ(advancedNotificationService_->snoozeDelayTimerList_.size(), 1);
}

/**
 * @tc.name: RemoveAllFromSnoozeDelayList_00005
 * @tc.desc: Test RemoveAllFromSnoozeDelayList when ownerUid matches
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, RemoveAllFromSnoozeDelayList_00005, Function | SmallTest | Level1)
{
    advancedNotificationService_->snoozeDelayTimerList_.clear();

    sptr<NotificationRequest> request1(new (std::nothrow) NotificationRequest());
    request1->SetOwnerUid(200);
    auto record1 = std::make_shared<NotificationRecord>();
    sptr<NotificationBundleOption> bundleOption1 = new NotificationBundleOption();
    bundleOption1->SetBundleName("testBundle1");
    bundleOption1->SetUid(100);
    record1->request = request1;
    record1->bundleOption = bundleOption1;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record1);

    sptr<NotificationRequest> request2(new (std::nothrow) NotificationRequest());
    request2->SetOwnerUid(300);
    auto record2 = std::make_shared<NotificationRecord>();
    sptr<NotificationBundleOption> bundleOption2 = new NotificationBundleOption();
    bundleOption2->SetBundleName("testBundle2");
    bundleOption2->SetUid(150);
    record2->request = request2;
    record2->bundleOption = bundleOption2;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record2);

    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption();
    targetBundle->SetBundleName("targetBundle");
    targetBundle->SetUid(200);

    advancedNotificationService_->RemoveAllFromSnoozeDelayList(targetBundle);

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
        (int)ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);
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

/**
 * @tc.name: SetNextSnoozeTimer_001
 * @tc.desc: Test SetNextSnoozeTimer when request is nullptr
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, SetNextSnoozeTimer_001, Function | SmallTest | Level1)
{
    advancedNotificationService_->snoozeDelayTimerList_.clear();
    advancedNotificationService_->snoozeDelayTimerList_.push_back(nullptr);
    auto record = std::make_shared<NotificationRecord>();
    record->request = nullptr;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record);
    advancedNotificationService_->SetNextSnoozeTimer(NotificationAnalyticsUtil::GetCurrentTime());
    ASSERT_EQ(advancedNotificationService_->snoozeDelayTimerList_.size(), 0);
}

/**
 * @tc.name: SnoozeNotificationConsumed_Dnd_00001
 * @tc.desc: Test CheckDoNotDisturbProfile with bundleOption set (simulating fixed SnoozeNotificationConsumed).
 *           Verifies DND silencing is applied when bundleOption is valid.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, SnoozeNotificationConsumed_Dnd_00001, Function | SmallTest | Level1)
{
    int32_t uid = 50;
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("MyTestBundle", uid);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetContentType(1);
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    request->SetNotificationControlFlags(0);
    auto flags = std::make_shared<NotificationFlags>();
    request->SetFlags(flags);
    sptr<Notification> notification(new Notification(request));
    notification->SetEnableSound(true);
    notification->SetEnableVibration(true);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    record->bundleOption = bundleOption;

    DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->SetIsDataShareReady(true);
    MockIsFailedToCreateDataShareHelper(false);
    MockIsFailedToQueryDataShareResultSet(false);
    MockIsFailedGoToFirstRow(0);
    MockGetStringValue("1");

    advancedNotificationService_->CheckDoNotDisturbProfile(record);

    int32_t controlFlags = record->request->GetNotificationControlFlags();
    EXPECT_TRUE((controlFlags & (1 << 14)) != 0);
    EXPECT_FALSE(record->notification->EnableSound());
    EXPECT_FALSE(record->notification->EnableVibrate());

    DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->SetIsDataShareReady(false);
}

/**
 * @tc.name: SnoozeNotificationConsumed_Dnd_00002
 * @tc.desc: Test SnoozeNotificationConsumed with DND mode enabled. Verifies the snooze flow
 *           completes successfully and the notification remains in the list.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, SnoozeNotificationConsumed_Dnd_00002, Function | SmallTest | Level1)
{
    int32_t uid = 50;
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("MyTestBundle", uid);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetContentType(1);
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    auto flags = std::make_shared<NotificationFlags>();
    request->SetFlags(flags);
    sptr<Notification> notification(new Notification(request));
    notification->SetKey("testDnd123");
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    record->bundleOption = bundleOption;

    advancedNotificationService_->notificationList_.clear();
    advancedNotificationService_->notificationList_.push_back(record);

    DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->SetIsDataShareReady(true);
    MockIsFailedToCreateDataShareHelper(false);
    MockIsFailedToQueryDataShareResultSet(false);
    MockIsFailedGoToFirstRow(0);
    MockGetStringValue("1");

    advancedNotificationService_->SnoozeNotificationConsumed(record);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);

    DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->SetIsDataShareReady(false);
    advancedNotificationService_->notificationList_.clear();
}

/**
 * @tc.name: SnoozeNotificationConsumed_DeviceFlags_00001
 * @tc.desc: Test SnoozeNotificationConsumed deep-copies device flags so peer deviceType entries are
 *           retained and the original record is not polluted by silent reminder flag clearing.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, SnoozeNotificationConsumed_DeviceFlags_00001, Function | SmallTest | Level1)
{
    int32_t uid = 50;
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("MyTestBundle", uid);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetContentType(1);
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    const uint32_t testReminderFlags = static_cast<uint32_t>(
        NotificationConstant::ReminderFlag::SOUND_FLAG | NotificationConstant::ReminderFlag::BANNER_FLAG);
    request->SetFlags(std::make_shared<NotificationFlags>(testReminderFlags));
    sptr<Notification> notification(new Notification(request));
    notification->SetKey("testDeviceFlags123");
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    record->bundleOption = bundleOption;

    auto srcDeviceFlags = std::make_shared<std::map<std::string, std::shared_ptr<NotificationFlags>>>();
    (*srcDeviceFlags)[NotificationConstant::CURRENT_DEVICE_TYPE] =
        std::make_shared<NotificationFlags>(testReminderFlags);
    (*srcDeviceFlags)["wearable"] = std::make_shared<NotificationFlags>(testReminderFlags);
    request->SetDeviceFlags(srcDeviceFlags);

    advancedNotificationService_->notificationList_.clear();
    advancedNotificationService_->notificationList_.push_back(record);
    advancedNotificationService_->SetSilentReminderEnabledInner(bundleOption, true);
    advancedNotificationService_->SnoozeNotificationConsumed(record);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);

    auto afterDeviceFlags = record->request->GetDeviceFlags();
    ASSERT_NE(afterDeviceFlags, nullptr);
    auto wearableIter = afterDeviceFlags->find("wearable");
    ASSERT_NE(wearableIter, afterDeviceFlags->end());
    ASSERT_NE(wearableIter->second, nullptr);
    EXPECT_EQ(wearableIter->second->GetReminderFlags(), testReminderFlags);

    advancedNotificationService_->notificationList_.clear();
}

/**
 * @tc.name: TriggerSnoozeDelay_00003
 * @tc.desc: Test TriggerSnoozeDelay skips null records and records with null request,
 *           and keeps the record whose snooze delay time is not reached.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, TriggerSnoozeDelay_00003, Function | SmallTest | Level1)
{
    advancedNotificationService_->snoozeDelayTimerList_.clear();
    advancedNotificationService_->snoozeDelayTimerList_.push_back(nullptr);
    auto nullRequestRecord = std::make_shared<NotificationRecord>();
    advancedNotificationService_->snoozeDelayTimerList_.push_back(nullRequestRecord);

    sptr<NotificationRequest> futureRequest(new (std::nothrow) NotificationRequest());
    futureRequest->SetSnoozeDelayTime(NotificationAnalyticsUtil::GetCurrentTime() + 60000);
    auto futureRecord = std::make_shared<NotificationRecord>();
    futureRecord->request = futureRequest;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(futureRecord);

    advancedNotificationService_->TriggerSnoozeDelay();
    ASSERT_EQ(advancedNotificationService_->snoozeDelayTimerList_.size(), 1);
    EXPECT_EQ(advancedNotificationService_->snoozeDelayTimerList_.front(), futureRecord);
}

/**
 * @tc.name: TriggerSnoozeDelay_00004
 * @tc.desc: Test TriggerSnoozeDelay marks due record triggered and consumes it even when
 *           the list contains null entries.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, TriggerSnoozeDelay_00004, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    auto normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetContentType(1);
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    request->SetSnoozeDelayTime(NotificationAnalyticsUtil::GetCurrentTime() - 60000);
    request->SetIsSnoozeTrigger(false);
    request->SetUpdateOnly(true);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("MyTestBundle", 50);
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    notification->SetKey("testSnoozeDue");
    auto dueRecord = std::make_shared<NotificationRecord>();
    dueRecord->request = request;
    dueRecord->notification = notification;
    dueRecord->bundleOption = bundleOption;
    advancedNotificationService_->snoozeDelayTimerList_.clear();
    advancedNotificationService_->snoozeDelayTimerList_.push_back(nullptr);
    advancedNotificationService_->snoozeDelayTimerList_.push_back(dueRecord);

    advancedNotificationService_->TriggerSnoozeDelay();
    EXPECT_EQ(dueRecord->request->GetIsSnoozeTrigger(), true);
    EXPECT_EQ(advancedNotificationService_->snoozeDelayTimerList_.size(), 0);
}

/**
 * @tc.name: StartSnoozeTimer_00002
 * @tc.desc: Test StartSnoozeTimer erases null entries and returns false when no valid
 *           trigger time exists.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, StartSnoozeTimer_00002, Function | SmallTest | Level1)
{
    advancedNotificationService_->snoozeDelayTimerList_.clear();
    advancedNotificationService_->snoozeDelayTimerList_.push_back(nullptr);
    auto nullRequestRecord = std::make_shared<NotificationRecord>();
    advancedNotificationService_->snoozeDelayTimerList_.push_back(nullRequestRecord);
    EXPECT_FALSE(advancedNotificationService_->StartSnoozeTimer());
    EXPECT_EQ(advancedNotificationService_->snoozeDelayTimerList_.size(), 0);
}

/**
 * @tc.name: RemoveAllFromSnoozeDelayListByUser_00002
 * @tc.desc: Test RemoveAllFromSnoozeDelayListByUser erases null and null-request records,
 *           keeps records whose notification is null, and removes matched user records.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, RemoveAllFromSnoozeDelayListByUser_00002, Function | SmallTest | Level1)
{
    advancedNotificationService_->snoozeDelayTimerList_.clear();
    advancedNotificationService_->snoozeDelayTimerList_.push_back(nullptr);

    auto nullRequestRecord = std::make_shared<NotificationRecord>();
    advancedNotificationService_->snoozeDelayTimerList_.push_back(nullRequestRecord);

    auto nullNotificationRecord = std::make_shared<NotificationRecord>();
    nullNotificationRecord->request = new (std::nothrow) NotificationRequest();
    advancedNotificationService_->snoozeDelayTimerList_.push_back(nullNotificationRecord);

    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    request->SetCreatorUserId(100);
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    auto matchedRecord = std::make_shared<NotificationRecord>();
    matchedRecord->request = request;
    matchedRecord->notification = notification;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(matchedRecord);

    advancedNotificationService_->RemoveAllFromSnoozeDelayListByUser(100);
    ASSERT_EQ(advancedNotificationService_->snoozeDelayTimerList_.size(), 1);
    EXPECT_EQ(advancedNotificationService_->snoozeDelayTimerList_.front(), nullNotificationRecord);
}

/**
 * @tc.name: IsSetSnooze_00006
 * @tc.desc: Test IsSetSnooze skips null records in both notificationList_ and
 *           snoozeDelayTimerList_ and still finds the matched key.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, IsSetSnooze_00006, Function | SmallTest | Level1)
{
    advancedNotificationService_->snoozeDelayTimerList_.clear();
    advancedNotificationService_->notificationList_.clear();
    advancedNotificationService_->notificationList_.push_back(nullptr);
    auto nullNotificationRecord = std::make_shared<NotificationRecord>();
    nullNotificationRecord->request = new (std::nothrow) NotificationRequest();
    advancedNotificationService_->notificationList_.push_back(nullNotificationRecord);

    advancedNotificationService_->snoozeDelayTimerList_.push_back(nullptr);
    auto nullRequestRecord = std::make_shared<NotificationRecord>();
    advancedNotificationService_->snoozeDelayTimerList_.push_back(nullRequestRecord);
    auto nullNotifRecord = std::make_shared<NotificationRecord>();
    nullNotifRecord->request = new (std::nothrow) NotificationRequest();
    advancedNotificationService_->snoozeDelayTimerList_.push_back(nullNotifRecord);

    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    sptr<Notification> notification(new (std::nothrow) Notification(request));
    notification->SetKey("test123_test");
    auto matchedRecord = std::make_shared<NotificationRecord>();
    matchedRecord->request = request;
    matchedRecord->notification = notification;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(matchedRecord);

    EXPECT_TRUE(advancedNotificationService_->IsSetSnooze("test123"));
    EXPECT_FALSE(advancedNotificationService_->IsSetSnooze("not_exist_key"));
}

/**
 * @tc.name: StartSnoozeTimer_00003
 * @tc.desc: Test StartSnoozeTimer returns false when the underlying timer fails to start
 *           with a valid due record in the snooze delay list.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, StartSnoozeTimer_00003, Function | SmallTest | Level1)
{
    advancedNotificationService_->snoozeDelayTimerList_.clear();
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    request->SetSnoozeDelayTime(NotificationAnalyticsUtil::GetCurrentTime() + 60000);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record);

    MockCreateTimerFailed(false);
    MockStartTimerFailed(true);
    EXPECT_FALSE(advancedNotificationService_->StartSnoozeTimer());

    ResetTimeServiceMock();
    advancedNotificationService_->snoozeDelayTimerList_.clear();
}

/**
 * @tc.name: StartSnoozeTimer_00004
 * @tc.desc: Test StartSnoozeTimer returns true and keeps a valid timer id when the
 *           underlying timer starts successfully.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsSnoozeDelayTest, StartSnoozeTimer_00004, Function | SmallTest | Level1)
{
    advancedNotificationService_->snoozeDelayTimerList_.clear();
    sptr<NotificationRequest> request(new (std::nothrow) NotificationRequest());
    request->SetSnoozeDelayTime(NotificationAnalyticsUtil::GetCurrentTime() + 60000);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    advancedNotificationService_->snoozeDelayTimerList_.push_back(record);

    MockCreateTimerFailed(false);
    MockStartTimerFailed(false);
    EXPECT_TRUE(advancedNotificationService_->StartSnoozeTimer());
    EXPECT_GT(advancedNotificationService_->timerImpl_.timerId_, static_cast<uint64_t>(0));

    ResetTimeServiceMock();
    advancedNotificationService_->snoozeDelayTimerList_.clear();
}

}  // namespace Notification
}  // namespace OHOS
