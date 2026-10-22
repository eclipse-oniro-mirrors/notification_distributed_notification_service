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

#include "errors.h"
#include "notification_content.h"
#include "notification_record.h"
#include "notification_request.h"
#include <chrono>
#include <ctime>
#include <functional>
#include <memory>
#include <thread>

#include "gtest/gtest.h"
#include <vector>

#define private public
#define protected public

#include "advanced_notification_service.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_service_errors.h"
#include "ans_log_wrapper.h"
#include "ans_notification.h"
#include "ans_ut_constant.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "iremote_object.h"
#include "mock_ipc_skeleton.h"
#include "notification_classification.h"
#include "notification_preferences.h"
#include "notification_subscriber.h"
#include "notification_subscriber_manager.h"
#include "notification_switch_changed_callback_data.h"
#include "mock_push_callback_stub.h"
#include "os_account_manager_helper.h"
#include "os_account_manager.h"
#include "system_event_observer.h"
#include "want_agent_info.h"
#include "want_agent_helper.h"
#include "want_params.h"
#include "bundle_manager_helper.h"
#include "ans_dialog_host_client.h"
#include "mock_badgequery_callback_stub.h"
#include "advanced_notification_inline.h"
#include "int_wrapper.h"

#undef protected
#undef private

extern void MockIsOsAccountExists(bool mockRet);
extern void MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase);

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Notification {
extern void MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);
extern void MockIsNonBundleName(bool isNonBundleName);
extern void MockIsVerfyPermisson(bool isVerify);

class AdvancedNotificationAggregationServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    void MockSystemApp();
    void MockNativeToken();
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AdvancedNotificationAggregationServiceTest::advancedNotificationService_ = nullptr;

void AdvancedNotificationAggregationServiceTest::SetUpTestCase()
{
    MockIsOsAccountExists(true);
}

void AdvancedNotificationAggregationServiceTest::TearDownTestCase() {}

void AdvancedNotificationAggregationServiceTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);
    advancedNotificationService_->CancelAll("");
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    GTEST_LOG_(INFO) << "SetUp end";
}

void AdvancedNotificationAggregationServiceTest::TearDown()
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

void AdvancedNotificationAggregationServiceTest::MockSystemApp()
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
}

void AdvancedNotificationAggregationServiceTest::MockNativeToken()
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(false);
    MockIsVerfyPermisson(true);
}

/**
 * @tc.name: SetNotificationSwitch_00001
 * @tc.desc: Test SetNotificationSwitch with invalid switchName (INVALID)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, SetNotificationSwitch_00001, Function | SmallTest | Level1)
{
    MockSystemApp();
    ErrCode result = advancedNotificationService_->SetNotificationSwitch(
        NotificationConstant::NotificationSwitch::INVALID, true, 100);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: SetNotificationSwitch_00002
 * @tc.desc: Test SetNotificationSwitch with empty switchName
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, SetNotificationSwitch_00002, Function | SmallTest | Level1)
{
    MockSystemApp();
    ErrCode result = advancedNotificationService_->SetNotificationSwitch("", true, 100);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: SetNotificationSwitch_00003
 * @tc.desc: Test SetNotificationSwitch with non-system app (HAP token, not system app)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, SetNotificationSwitch_00003, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    MockIsVerfyPermisson(true);

    ErrCode result = advancedNotificationService_->SetNotificationSwitch(
        NotificationConstant::NotificationSwitch::DEAL, true, 100);
    EXPECT_EQ(result, ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.name: SetNotificationSwitch_00004
 * @tc.desc: Test SetNotificationSwitch with permission denied
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, SetNotificationSwitch_00004, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    ErrCode result = advancedNotificationService_->SetNotificationSwitch(
        NotificationConstant::NotificationSwitch::DEAL, true, 100);
    EXPECT_EQ(result, ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.name: SetNotificationSwitch_00005
 * @tc.desc: Test SetNotificationSwitch with non-existent userId
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, SetNotificationSwitch_00005, Function | SmallTest | Level1)
{
    MockSystemApp();
    MockIsOsAccountExists(false);

    ErrCode result = advancedNotificationService_->SetNotificationSwitch(
        NotificationConstant::NotificationSwitch::DEAL, true, MAX_USER_ID);
    EXPECT_EQ(result, ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);

    MockIsOsAccountExists(true);
}

/**
 * @tc.name: SetNotificationSwitch_00006
 * @tc.desc: Test SetNotificationSwitch with valid params, native token, DB success
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, SetNotificationSwitch_00006, Function | SmallTest | Level1)
{
    MockNativeToken();
    MockIsOsAccountExists(true);

    ErrCode result = advancedNotificationService_->SetNotificationSwitch(
        NotificationConstant::NotificationSwitch::DEAL, true, 100);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: SetNotificationSwitch_00007
 * @tc.desc: Test SetNotificationSwitch with LOGISTICS switchName, enable=false
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, SetNotificationSwitch_00007, Function | SmallTest | Level1)
{
    MockNativeToken();
    MockIsOsAccountExists(true);

    ErrCode result = advancedNotificationService_->SetNotificationSwitch(
        NotificationConstant::NotificationSwitch::LOGISTICS, false, 100);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: GetNotificationSwitch_00001
 * @tc.desc: Test GetNotificationSwitch with invalid switchName (INVALID)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, GetNotificationSwitch_00001, Function | SmallTest | Level1)
{
    MockSystemApp();
    int32_t state = 0;
    ErrCode result = advancedNotificationService_->GetNotificationSwitch(
        NotificationConstant::NotificationSwitch::INVALID, 100, state);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: GetNotificationSwitch_00002
 * @tc.desc: Test GetNotificationSwitch with empty switchName
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, GetNotificationSwitch_00002, Function | SmallTest | Level1)
{
    MockSystemApp();
    int32_t state = 0;
    ErrCode result = advancedNotificationService_->GetNotificationSwitch("", 100, state);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: GetNotificationSwitch_00003
 * @tc.desc: Test GetNotificationSwitch with non-system app
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, GetNotificationSwitch_00003, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    MockIsVerfyPermisson(true);

    int32_t state = 0;
    ErrCode result = advancedNotificationService_->GetNotificationSwitch(
        NotificationConstant::NotificationSwitch::DEAL, 100, state);
    EXPECT_EQ(result, ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.name: GetNotificationSwitch_00004
 * @tc.desc: Test GetNotificationSwitch with permission denied
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, GetNotificationSwitch_00004, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    int32_t state = 0;
    ErrCode result = advancedNotificationService_->GetNotificationSwitch(
        NotificationConstant::NotificationSwitch::DEAL, 100, state);
    EXPECT_EQ(result, ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.name: GetNotificationSwitch_00005
 * @tc.desc: Test GetNotificationSwitch with non-existent userId
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, GetNotificationSwitch_00005, Function | SmallTest | Level1)
{
    MockSystemApp();
    MockIsOsAccountExists(false);

    int32_t state = 0;
    ErrCode result = advancedNotificationService_->GetNotificationSwitch(
        NotificationConstant::NotificationSwitch::DEAL, MAX_USER_ID, state);
    EXPECT_EQ(result, ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);

    MockIsOsAccountExists(true);
}

/**
 * @tc.name: GetNotificationSwitch_00006
 * @tc.desc: Test GetNotificationSwitch with valid params, native token, DB read success
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, GetNotificationSwitch_00006, Function | SmallTest | Level1)
{
    MockNativeToken();
    MockIsOsAccountExists(true);

    // First set a switch value so we can read it back
    ErrCode setResult = advancedNotificationService_->SetNotificationSwitch(
        NotificationConstant::NotificationSwitch::DEAL, true, 100);
    EXPECT_EQ(setResult, ERR_OK);

    int32_t state = 0;
    ErrCode result = advancedNotificationService_->GetNotificationSwitch(
        NotificationConstant::NotificationSwitch::DEAL, 100, state);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(state, static_cast<int32_t>(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON));
}

/**
 * @tc.name: TriggerUpdateAiExtNotification_00001
 * @tc.desc: Test TriggerUpdateAiExtNotification with null request
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, TriggerUpdateAiExtNotification_00001,
    Function | SmallTest | Level1)
{
    MockSystemApp();
    sptr<NotificationClassification> classification = new NotificationClassification("DEAL", "LOGISTICS");
    ErrCode result = advancedNotificationService_->TriggerUpdateAiExtNotification(nullptr, classification);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: TriggerUpdateAiExtNotification_00002
 * @tc.desc: Test TriggerUpdateAiExtNotification with non-system app (permission denied via SystemPermissionCheck)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, TriggerUpdateAiExtNotification_00002,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    MockIsVerfyPermisson(true);

    sptr<NotificationRequest> request = new NotificationRequest();
    sptr<NotificationClassification> classification = new NotificationClassification("DEAL", "LOGISTICS");
    ErrCode result = advancedNotificationService_->TriggerUpdateAiExtNotification(request, classification);
    EXPECT_EQ(result, ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.name: TriggerUpdateAiExtNotification_00003
 * @tc.desc: Test TriggerUpdateAiExtNotification with permission denied (no OHOS_PERMISSION_NOTIFICATION_CONTROLLER)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, TriggerUpdateAiExtNotification_00003, \
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    sptr<NotificationRequest> request = new NotificationRequest();
    sptr<NotificationClassification> classification = new NotificationClassification("DEAL", "LOGISTICS");
    ErrCode result = advancedNotificationService_->TriggerUpdateAiExtNotification(request, classification);
    EXPECT_EQ(result, ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.name: TriggerUpdateAiExtNotification_00004
 * @tc.desc: Test TriggerUpdateAiExtNotification with record not found in notificationList
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, TriggerUpdateAiExtNotification_00004, \
    Function | SmallTest | Level1)
{
    MockNativeToken();

    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetNotificationId(99999);
    sptr<NotificationClassification> classification = new NotificationClassification("DEAL", "LOGISTICS");
    // The request key won't match any record in the notification list
    ErrCode result = advancedNotificationService_->TriggerUpdateAiExtNotification(request, classification);
    // When record is not found, the ffrt lambda returns early without setting an error
    // The outer function returns ERR_OK since submitResult is ERR_OK
    EXPECT_EQ(result, ERR_OK);
}
}  // namespace Notification
}  // namespace OHOS

// ===== Appended by T012 (priority notification degrade): the arbitration cases of the
// delayed update path TriggerUpdateAiExtNotification. Everything below is tail appended:
// the existing cases above stay untouched, the extra headers are included after the
// original include block and the namespaces are reopened afterwards. =====
#include "ans_subscriber_listener.h"
#include "notification_classification_mgr.h"
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
#define private public
#define protected public
#include "priority_notification_degrade_manager.h"
#undef protected
#undef private
#endif

namespace OHOS {
namespace Notification {
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
namespace {
constexpr int64_t AGG_TEST_ONE_HOUR_MILLIS = 3600LL * 1000LL;

const std::string AGG_TEST_TYPE_OTHER = NotificationConstant::PriorityNotificationType::OTHER;
const std::string AGG_TEST_TYPE_URGENT = NotificationConstant::PriorityNotificationType::URGENT_MESSAGE;
const std::string AGG_TEST_TYPE_AT_ME = NotificationConstant::PriorityNotificationType::AT_ME;
const std::string AGG_TEST_TYPE_SCHEDULE = NotificationConstant::PriorityNotificationType::SCHEDULE_REMINDER;

const int32_t AGG_TEST_SOURCE_AI = static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI);
const int32_t AGG_TEST_SOURCE_KEYWORD =
    static_cast<int32_t>(NotificationConstant::PrioritySourceResult::KEYWORD);

int64_t AggTestNowMillis()
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return duration.count();
}

// Expire times are absolute epoch milliseconds: a future offset keeps every case on the
// registration path, away from the immediate degrade dispatch of an already past time.
int64_t AggTestFutureTime(int64_t offsetMillis)
{
    return AggTestNowMillis() + offsetMillis;
}

// Builds the tagging result the closed source delivers on the delayed update path: the
// aggregation strings plus the priority triple (type, expire time, source).
sptr<NotificationClassification> AggTestMakeClassification(
    const std::string &type, int64_t expiredTime, int32_t source)
{
    sptr<NotificationClassification> classification = new NotificationClassification("DEAL", "LOGISTICS");
    NotificationClassification::PriorityInfo priorityInfo;
    priorityInfo.SetPriorityNotificationType(type);
    priorityInfo.SetExpiredTime(expiredTime);
    priorityInfo.SetSource(source);
    classification->SetPriorityInfo(priorityInfo);
    return classification;
}

// Requests built with the same fields share the same base key, so the injected record
// (wrapping the cached request) is found for the incoming delayed update request. The
// content keeps the notification parcelable for the subscriber callback round trip.
sptr<NotificationRequest> AggTestMakeRequest()
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetNotificationId(8801);
    request->SetCreatorBundleName("com.example.aggregation.delayed");
    request->SetCreatorUid(200100);
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    return request;
}

// Injects a cached notification record so the delayed update finds it by the base key and
// returns the arbitration key (the notification key the classification cache is keyed by).
std::string AggTestInjectRecord(const sptr<AdvancedNotificationService> &service,
    const sptr<NotificationRequest> &cachedRequest)
{
    auto record = std::make_shared<NotificationRecord>();
    record->request = cachedRequest;
    record->notification = new Notification(cachedRequest);
    service->notificationList_.push_back(record);
    return record->notification->GetKey();
}

void AggTestExpectPriorityInfo(const NotificationClassification::PriorityInfo &priorityInfo,
    const std::string &type, int64_t expiredTime, int32_t source)
{
    EXPECT_EQ(priorityInfo.GetPriorityNotificationType(), type);
    EXPECT_EQ(priorityInfo.GetExpiredTime(), expiredTime);
    EXPECT_EQ(priorityInfo.GetSource(), source);
}

// Cleans the classification cache and resets the degrade manager singleton so every case
// starts from a new lifecycle and leaves nothing behind for the later cases.
void AggTestResetPriorityState()
{
    NotificationClassificationMgr::GetInstance().Clear();
    PriorityNotificationDegradeManager::DestroyInstance();
}
} // namespace

// A subscriber registered only for the system update callback: it counts the callbacks and
// captures the classification the server attached to the notification, so the delayed
// update callback chain (NotifySystemUpdate -> OnSystemUpdate) can be asserted end to end.
class AggTestSystemUpdateSubscriber : public NotificationSubscriber {
public:
    void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override {}
    void OnConnected() override {}
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override {}
    void OnDisconnected() override {}
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override {}
    void OnDied() override {}
    void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override {}
    void OnEnabledNotificationChanged(
        const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override {}
    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override {}
    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override {}
    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>> &requestList,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override {}

    void OnSystemUpdate(const std::shared_ptr<Notification> &notification) override
    {
        systemUpdateCount_++;
        if (notification != nullptr) {
            lastClassification_ = notification->GetNotificationClassification();
            if (notification->GetNotificationRequestPoint() != nullptr) {
                lastRequestType_ = notification->GetNotificationRequestPoint()
                    ->GetPriorityNotificationType();
            }
        }
    }

    int32_t GetSystemUpdateCount() const
    {
        return systemUpdateCount_;
    }

    sptr<NotificationClassification> GetLastClassification() const
    {
        return lastClassification_;
    }

    const std::string &GetLastRequestPriorityType() const
    {
        return lastRequestType_;
    }

private:
    int32_t systemUpdateCount_ {0};
    sptr<NotificationClassification> lastClassification_ {nullptr};
    std::string lastRequestType_;
};

// Registers the system update only subscriber with the classification distribution
// enabled. The registration goes through the inner entry directly (in memory, no IPC side
// paths) and the caller removes it at the end of the case.
void AggTestRegisterSubscriber(const std::shared_ptr<AggTestSystemUpdateSubscriber> &subscriber,
    sptr<IAnsSubscriber> &listener)
{
    listener = new SubscriberListener(subscriber);
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    info->AddAppUserId(SUBSCRIBE_USER_ALL);
    info->SetSubscribedFlags(NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_SYSTEM_UPDATE);
    info->SetEnableClassification(true);
    EXPECT_EQ(NotificationSubscriberManager::GetInstance()->AddSubscriberInner(listener, info), ERR_OK);
}

/**
 * @tc.name: TriggerUpdateAiExtNotification_00005
 * @tc.desc: Test the delayed update with no cached classification (AC-006): the
 *           arbitration applies, the triple lands into the classification cache, the
 *           cached request type is written back, the degrade registration is created and
 *           the system update callback carries the classification.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, TriggerUpdateAiExtNotification_00005,
    Function | SmallTest | Level1)
{
    AggTestResetPriorityState();
    MockNativeToken();
    sptr<NotificationRequest> cachedRequest = AggTestMakeRequest();
    std::string notificationKey = AggTestInjectRecord(advancedNotificationService_, cachedRequest);
    // The closed source already wrote its type into the incoming request of the delayed
    // update, the cached request still holds the default type.
    sptr<NotificationRequest> incomingRequest = AggTestMakeRequest();
    incomingRequest->SetInnerPriorityNotificationType(AGG_TEST_TYPE_URGENT);
    int64_t expireTime = AggTestFutureTime(AGG_TEST_ONE_HOUR_MILLIS);
    sptr<NotificationClassification> classification =
        AggTestMakeClassification(AGG_TEST_TYPE_URGENT, expireTime, AGG_TEST_SOURCE_KEYWORD);
    std::shared_ptr<AggTestSystemUpdateSubscriber> subscriber =
        std::make_shared<AggTestSystemUpdateSubscriber>();
    sptr<IAnsSubscriber> listener = nullptr;
    AggTestRegisterSubscriber(subscriber, listener);

    ErrCode result = advancedNotificationService_->TriggerUpdateAiExtNotification(
        incomingRequest, classification);

    EXPECT_EQ(result, ERR_OK);
    sptr<NotificationClassification> landed = NotificationClassificationMgr::GetInstance().Get(notificationKey);
    EXPECT_NE(landed, nullptr);
    if (landed != nullptr) {
        AggTestExpectPriorityInfo(landed->GetPriorityInfo(), AGG_TEST_TYPE_URGENT, expireTime,
            AGG_TEST_SOURCE_KEYWORD);
        EXPECT_EQ(landed->GetClassification(), "DEAL");
        EXPECT_EQ(landed->GetSubClassification(), "LOGISTICS");
    }
    EXPECT_EQ(cachedRequest->GetPriorityNotificationType(), AGG_TEST_TYPE_URGENT);
    EXPECT_EQ(PriorityNotificationDegradeManager::GetInstance()->GetEarliestExpiredTime(), expireTime);

    NotificationSubscriberManager::GetInstance()->WaitForFfrtQueue();
    EXPECT_EQ(subscriber->GetSystemUpdateCount(), 1);
    sptr<NotificationClassification> received = subscriber->GetLastClassification();
    EXPECT_NE(received, nullptr);
    if (received != nullptr) {
        AggTestExpectPriorityInfo(received->GetPriorityInfo(), AGG_TEST_TYPE_URGENT, expireTime,
            AGG_TEST_SOURCE_KEYWORD);
    }

    NotificationSubscriberManager::GetInstance()->RemoveSubscriberInner(listener, nullptr);
    AggTestResetPriorityState();
}

/**
 * @tc.name: TriggerUpdateAiExtNotification_00006
 * @tc.desc: Test the rule override on the delayed update path (AC-014): with an undegraded
 *           model result cached, the delayed rule family result fully overrides the
 *           triple, the registration is rescheduled to the new expire time, the cached
 *           request type takes the rule type and the callback carries the new value.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, TriggerUpdateAiExtNotification_00006,
    Function | SmallTest | Level1)
{
    AggTestResetPriorityState();
    MockNativeToken();
    sptr<NotificationRequest> cachedRequest = AggTestMakeRequest();
    std::string notificationKey = AggTestInjectRecord(advancedNotificationService_, cachedRequest);
    // The model result landed first through the synchronous consumption path: the closed
    // source wrote the model type into the cached request and the arbitration landed it.
    int64_t modelTime = AggTestFutureTime(2 * AGG_TEST_ONE_HOUR_MILLIS);
    cachedRequest->SetInnerPriorityNotificationType(AGG_TEST_TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto first = PriorityNotificationDegradeManager::GetInstance()->ApplyTaggingResult(
        notificationKey, cachedRequest, AggTestMakeClassification(AGG_TEST_TYPE_URGENT, modelTime,
            AGG_TEST_SOURCE_AI), effective);
    EXPECT_EQ(first, PriorityNotificationDegradeManager::ArbitrateResult::APPLY);
    EXPECT_EQ(PriorityNotificationDegradeManager::GetInstance()->GetEarliestExpiredTime(), modelTime);

    // The delayed update now carries the rule family result with an earlier expire time.
    int64_t ruleTime = AggTestFutureTime(AGG_TEST_ONE_HOUR_MILLIS);
    sptr<NotificationRequest> incomingRequest = AggTestMakeRequest();
    incomingRequest->SetInnerPriorityNotificationType(AGG_TEST_TYPE_SCHEDULE);
    sptr<NotificationClassification> classification =
        AggTestMakeClassification(AGG_TEST_TYPE_SCHEDULE, ruleTime, AGG_TEST_SOURCE_KEYWORD);
    std::shared_ptr<AggTestSystemUpdateSubscriber> subscriber =
        std::make_shared<AggTestSystemUpdateSubscriber>();
    sptr<IAnsSubscriber> listener = nullptr;
    AggTestRegisterSubscriber(subscriber, listener);

    ErrCode result = advancedNotificationService_->TriggerUpdateAiExtNotification(
        incomingRequest, classification);

    EXPECT_EQ(result, ERR_OK);
    sptr<NotificationClassification> landed = NotificationClassificationMgr::GetInstance().Get(notificationKey);
    EXPECT_NE(landed, nullptr);
    if (landed != nullptr) {
        AggTestExpectPriorityInfo(landed->GetPriorityInfo(), AGG_TEST_TYPE_SCHEDULE, ruleTime,
            AGG_TEST_SOURCE_KEYWORD);
    }
    EXPECT_EQ(cachedRequest->GetPriorityNotificationType(), AGG_TEST_TYPE_SCHEDULE);
    EXPECT_EQ(PriorityNotificationDegradeManager::GetInstance()->GetEarliestExpiredTime(), ruleTime);

    NotificationSubscriberManager::GetInstance()->WaitForFfrtQueue();
    EXPECT_EQ(subscriber->GetSystemUpdateCount(), 1);
    sptr<NotificationClassification> received = subscriber->GetLastClassification();
    EXPECT_NE(received, nullptr);
    if (received != nullptr) {
        AggTestExpectPriorityInfo(received->GetPriorityInfo(), AGG_TEST_TYPE_SCHEDULE, ruleTime,
            AGG_TEST_SOURCE_KEYWORD);
    }
    // R6: the callback payload request type always matches the classification type.
    EXPECT_EQ(subscriber->GetLastRequestPriorityType(), AGG_TEST_TYPE_SCHEDULE);

    NotificationSubscriberManager::GetInstance()->RemoveSubscriberInner(listener, nullptr);
    AggTestResetPriorityState();
}

/**
 * @tc.name: TriggerUpdateAiExtNotification_00007
 * @tc.desc: Test the delayed update against a rule locked cache (overwrite semantics):
 *           the delayed model result overwrites the locked triple, the cached request
 *           type takes the incoming type, the registration is rescheduled to the new
 *           expire time, the closed source side gets no error and the system update
 *           carries the landed new value to the classification subscribers.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, TriggerUpdateAiExtNotification_00007,
    Function | SmallTest | Level1)
{
    AggTestResetPriorityState();
    MockNativeToken();
    sptr<NotificationRequest> cachedRequest = AggTestMakeRequest();
    std::string notificationKey = AggTestInjectRecord(advancedNotificationService_, cachedRequest);
    // The rule result landed first through the synchronous consumption path.
    int64_t ruleTime = AggTestFutureTime(AGG_TEST_ONE_HOUR_MILLIS);
    cachedRequest->SetInnerPriorityNotificationType(AGG_TEST_TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto first = PriorityNotificationDegradeManager::GetInstance()->ApplyTaggingResult(
        notificationKey, cachedRequest, AggTestMakeClassification(AGG_TEST_TYPE_URGENT, ruleTime,
            AGG_TEST_SOURCE_KEYWORD), effective);
    EXPECT_EQ(first, PriorityNotificationDegradeManager::ArbitrateResult::APPLY);
    EXPECT_EQ(PriorityNotificationDegradeManager::GetInstance()->GetEarliestExpiredTime(), ruleTime);

    // The delayed model result arrives later with its own type and a later expire time.
    sptr<NotificationRequest> incomingRequest = AggTestMakeRequest();
    incomingRequest->SetInnerPriorityNotificationType(AGG_TEST_TYPE_AT_ME);
    int64_t laterTime = AggTestFutureTime(2 * AGG_TEST_ONE_HOUR_MILLIS);
    sptr<NotificationClassification> classification =
        AggTestMakeClassification(AGG_TEST_TYPE_AT_ME, laterTime, AGG_TEST_SOURCE_AI);
    std::shared_ptr<AggTestSystemUpdateSubscriber> subscriber =
        std::make_shared<AggTestSystemUpdateSubscriber>();
    sptr<IAnsSubscriber> listener = nullptr;
    AggTestRegisterSubscriber(subscriber, listener);

    ErrCode result = advancedNotificationService_->TriggerUpdateAiExtNotification(
        incomingRequest, classification);

    EXPECT_EQ(result, ERR_OK);
    sptr<NotificationClassification> landed = NotificationClassificationMgr::GetInstance().Get(notificationKey);
    EXPECT_NE(landed, nullptr);
    if (landed != nullptr) {
        AggTestExpectPriorityInfo(landed->GetPriorityInfo(), AGG_TEST_TYPE_AT_ME, laterTime,
            AGG_TEST_SOURCE_AI);
    }
    EXPECT_EQ(cachedRequest->GetPriorityNotificationType(), AGG_TEST_TYPE_AT_ME);
    EXPECT_EQ(PriorityNotificationDegradeManager::GetInstance()->GetEarliestExpiredTime(), laterTime);

    NotificationSubscriberManager::GetInstance()->WaitForFfrtQueue();
    // The accepted round still notifies the classification subscribers with the landed
    // new value, so the reclassification stays observable.
    EXPECT_EQ(subscriber->GetSystemUpdateCount(), 1);
    sptr<NotificationClassification> received = subscriber->GetLastClassification();
    EXPECT_NE(received, nullptr);
    if (received != nullptr) {
        AggTestExpectPriorityInfo(received->GetPriorityInfo(), AGG_TEST_TYPE_AT_ME, laterTime,
            AGG_TEST_SOURCE_AI);
        EXPECT_EQ(received->GetClassification(), "DEAL");
        EXPECT_EQ(received->GetSubClassification(), "LOGISTICS");
    }

    NotificationSubscriberManager::GetInstance()->RemoveSubscriberInner(listener, nullptr);
    AggTestResetPriorityState();
}

/**
 * @tc.name: TriggerUpdateAiExtNotification_00008
 * @tc.desc: Test the delayed update with a null classification against a determined
 *           cache (overwrite semantics): the round's null value directly overwrites
 *           the cache — the entry is removed, the cached request type is forced to
 *           OTHER (the closed source type written into the incoming request is never
 *           written back), the stale degrade registration is removed and no system
 *           update is distributed (a null round carries no payload at all).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, TriggerUpdateAiExtNotification_00008,
    Function | SmallTest | Level1)
{
    AggTestResetPriorityState();
    MockNativeToken();
    sptr<NotificationRequest> cachedRequest = AggTestMakeRequest();
    std::string notificationKey = AggTestInjectRecord(advancedNotificationService_, cachedRequest);
    // A rule result landed first through the synchronous consumption path.
    int64_t expireTime = AggTestFutureTime(AGG_TEST_ONE_HOUR_MILLIS);
    cachedRequest->SetInnerPriorityNotificationType(AGG_TEST_TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto first = PriorityNotificationDegradeManager::GetInstance()->ApplyTaggingResult(
        notificationKey, cachedRequest, AggTestMakeClassification(AGG_TEST_TYPE_URGENT, expireTime,
            AGG_TEST_SOURCE_KEYWORD), effective);
    EXPECT_EQ(first, PriorityNotificationDegradeManager::ArbitrateResult::APPLY);

    // The delayed update carries no classification this round (no priority triple), the
    // closed source still wrote the new type into the incoming request.
    sptr<NotificationRequest> incomingRequest = AggTestMakeRequest();
    incomingRequest->SetInnerPriorityNotificationType(AGG_TEST_TYPE_AT_ME);
    std::shared_ptr<AggTestSystemUpdateSubscriber> subscriber =
        std::make_shared<AggTestSystemUpdateSubscriber>();
    sptr<IAnsSubscriber> listener = nullptr;
    AggTestRegisterSubscriber(subscriber, listener);

    ErrCode result = advancedNotificationService_->TriggerUpdateAiExtNotification(incomingRequest, nullptr);

    EXPECT_EQ(result, ERR_OK);
    // Overwrite semantics: the round's null value directly overwrites the cache — the
    // entry is removed. The closed source wrote AT_ME into the incoming request, which
    // is never written back: the cached request is forced to OTHER instead.
    EXPECT_EQ(cachedRequest->GetPriorityNotificationType(), AGG_TEST_TYPE_OTHER);
    EXPECT_EQ(NotificationClassificationMgr::GetInstance().Get(notificationKey), nullptr);
    // The stale registration of the overwritten triple is removed.
    EXPECT_EQ(PriorityNotificationDegradeManager::GetInstance()->GetEarliestExpiredTime(), 0);

    NotificationSubscriberManager::GetInstance()->WaitForFfrtQueue();
    // A null round is a pure skip on the distribution side: no payload exists to carry,
    // so no system update is distributed and the captured classification stays null.
    EXPECT_EQ(subscriber->GetSystemUpdateCount(), 0);
    EXPECT_EQ(subscriber->GetLastClassification(), nullptr);

    NotificationSubscriberManager::GetInstance()->RemoveSubscriberInner(listener, nullptr);
    AggTestResetPriorityState();
}

/**
 * @tc.name: TriggerUpdateAiExtNotification_00009
 * @tc.desc: Test the degraded terminal revive on the delayed update path (R5): with the
 *           cache holding the terminal state and the cached request type consistent
 *           with it, a late model result revives the priority — the terminal triple is
 *           overwritten by the incoming one, the cached request type is written back,
 *           the schedule follows the new expire time and the system update carries the
 *           effective landed value (the new triple with the fresh aggregation labels).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, TriggerUpdateAiExtNotification_00009,
    Function | SmallTest | Level1)
{
    AggTestResetPriorityState();
    MockNativeToken();
    sptr<NotificationRequest> cachedRequest = AggTestMakeRequest();
    std::string notificationKey = AggTestInjectRecord(advancedNotificationService_, cachedRequest);
    // The degrade already happened: the cache holds the terminal state (type OTHER with
    // the expire time kept as the marker) and the cached request type is consistent with
    // it, the starting point the revive round overwrites.
    int64_t expireTime = AggTestFutureTime(AGG_TEST_ONE_HOUR_MILLIS);
    NotificationClassificationMgr::GetInstance().AddOrUpdate(
        notificationKey, AggTestMakeClassification(AGG_TEST_TYPE_OTHER, expireTime, AGG_TEST_SOURCE_KEYWORD));
    cachedRequest->SetInnerPriorityNotificationType(AGG_TEST_TYPE_OTHER);

    // A late model result arrives on the delayed update path and revives the terminal
    // state (R5): the terminal triple is overwritten by the incoming one.
    int64_t reviveTime = AggTestFutureTime(2 * AGG_TEST_ONE_HOUR_MILLIS);
    sptr<NotificationRequest> incomingRequest = AggTestMakeRequest();
    incomingRequest->SetInnerPriorityNotificationType(AGG_TEST_TYPE_SCHEDULE);
    sptr<NotificationClassification> classification =
        AggTestMakeClassification(AGG_TEST_TYPE_SCHEDULE, reviveTime, AGG_TEST_SOURCE_AI);
    std::shared_ptr<AggTestSystemUpdateSubscriber> subscriber =
        std::make_shared<AggTestSystemUpdateSubscriber>();
    sptr<IAnsSubscriber> listener = nullptr;
    AggTestRegisterSubscriber(subscriber, listener);

    ErrCode result = advancedNotificationService_->TriggerUpdateAiExtNotification(
        incomingRequest, classification);

    EXPECT_EQ(result, ERR_OK);
    // Revive semantics: the landed triple is the incoming one and the cached request
    // type is written back with the incoming type (the accepted handler), so both
    // carriers stay consistent.
    sptr<NotificationClassification> landed = NotificationClassificationMgr::GetInstance().Get(notificationKey);
    EXPECT_NE(landed, nullptr);
    if (landed != nullptr) {
        AggTestExpectPriorityInfo(landed->GetPriorityInfo(), AGG_TEST_TYPE_SCHEDULE, reviveTime,
            AGG_TEST_SOURCE_AI);
        EXPECT_EQ(cachedRequest->GetPriorityNotificationType(),
            landed->GetPriorityInfo().GetPriorityNotificationType());
    }
    EXPECT_EQ(cachedRequest->GetPriorityNotificationType(), AGG_TEST_TYPE_SCHEDULE);
    // The schedule follows the revived expire time.
    EXPECT_EQ(PriorityNotificationDegradeManager::GetInstance()->GetEarliestExpiredTime(), reviveTime);

    NotificationSubscriberManager::GetInstance()->WaitForFfrtQueue();
    // The accepted round notifies the classification subscribers with the effective
    // landed value (the new triple with the fresh aggregation labels).
    EXPECT_EQ(subscriber->GetSystemUpdateCount(), 1);
    sptr<NotificationClassification> received = subscriber->GetLastClassification();
    EXPECT_NE(received, nullptr);
    if (received != nullptr) {
        AggTestExpectPriorityInfo(received->GetPriorityInfo(), AGG_TEST_TYPE_SCHEDULE, reviveTime,
            AGG_TEST_SOURCE_AI);
        EXPECT_EQ(received->GetClassification(), "DEAL");
        EXPECT_EQ(received->GetSubClassification(), "LOGISTICS");
    }
    // R6: the callback payload request type always matches the classification type.
    EXPECT_EQ(subscriber->GetLastRequestPriorityType(), AGG_TEST_TYPE_SCHEDULE);

    NotificationSubscriberManager::GetInstance()->RemoveSubscriberInner(listener, nullptr);
    AggTestResetPriorityState();
}

/**
 * @tc.name: TriggerUpdateAiExtNotification_00010
 * @tc.desc: Test the aggregation only delayed update round (R6, AC-020): the round
 *           carries fresh aggregation labels but no priority dimension, so the landed
 *           triple keeps the cached one; the cached request type is written back with
 *           the effective type and the system update payload request type matches the
 *           classification type (the unset incoming type never leaks into the payload).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, TriggerUpdateAiExtNotification_00010,
    Function | SmallTest | Level1)
{
    AggTestResetPriorityState();
    MockNativeToken();
    sptr<NotificationRequest> cachedRequest = AggTestMakeRequest();
    std::string notificationKey = AggTestInjectRecord(advancedNotificationService_, cachedRequest);
    // The model result landed first through the synchronous consumption path: the cache
    // holds a determined priority triple and the cached request type is consistent.
    int64_t modelTime = AggTestFutureTime(2 * AGG_TEST_ONE_HOUR_MILLIS);
    cachedRequest->SetInnerPriorityNotificationType(AGG_TEST_TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto first = PriorityNotificationDegradeManager::GetInstance()->ApplyTaggingResult(
        notificationKey, cachedRequest, AggTestMakeClassification(AGG_TEST_TYPE_URGENT, modelTime,
            AGG_TEST_SOURCE_AI), effective);
    EXPECT_EQ(first, PriorityNotificationDegradeManager::ArbitrateResult::APPLY);

    // The delayed update round carries aggregation labels only (no priority dimension)
    // and its incoming request type stays the unset default.
    sptr<NotificationClassification> aggregationOnly = new NotificationClassification("DEAL", "LOGISTICS");
    sptr<NotificationRequest> incomingRequest = AggTestMakeRequest();
    incomingRequest->SetInnerPriorityNotificationType(AGG_TEST_TYPE_OTHER);
    std::shared_ptr<AggTestSystemUpdateSubscriber> subscriber =
        std::make_shared<AggTestSystemUpdateSubscriber>();
    sptr<IAnsSubscriber> listener = nullptr;
    AggTestRegisterSubscriber(subscriber, listener);

    ErrCode result = advancedNotificationService_->TriggerUpdateAiExtNotification(
        incomingRequest, aggregationOnly);

    EXPECT_EQ(result, ERR_OK);
    // Dimensional landing: the labels refresh while the cached triple is kept.
    sptr<NotificationClassification> landed = NotificationClassificationMgr::GetInstance().Get(notificationKey);
    EXPECT_NE(landed, nullptr);
    if (landed != nullptr) {
        AggTestExpectPriorityInfo(landed->GetPriorityInfo(), AGG_TEST_TYPE_URGENT, modelTime,
            AGG_TEST_SOURCE_AI);
        EXPECT_EQ(landed->GetClassification(), "DEAL");
        EXPECT_EQ(landed->GetSubClassification(), "LOGISTICS");
    }
    // The write back keeps the effective (cached) type on the real request carrier.
    EXPECT_EQ(cachedRequest->GetPriorityNotificationType(), AGG_TEST_TYPE_URGENT);
    EXPECT_EQ(PriorityNotificationDegradeManager::GetInstance()->GetEarliestExpiredTime(), modelTime);

    NotificationSubscriberManager::GetInstance()->WaitForFfrtQueue();
    EXPECT_EQ(subscriber->GetSystemUpdateCount(), 1);
    sptr<NotificationClassification> received = subscriber->GetLastClassification();
    EXPECT_NE(received, nullptr);
    if (received != nullptr) {
        AggTestExpectPriorityInfo(received->GetPriorityInfo(), AGG_TEST_TYPE_URGENT, modelTime,
            AGG_TEST_SOURCE_AI);
    }
    // R6: the payload request carries the effective type, never the unset incoming one.
    EXPECT_EQ(subscriber->GetLastRequestPriorityType(), AGG_TEST_TYPE_URGENT);

    NotificationSubscriberManager::GetInstance()->RemoveSubscriberInner(listener, nullptr);
    AggTestResetPriorityState();
}

/**
 * @tc.name: TriggerUpdateAiExtNotification_00011
 * @tc.desc: Test the expired-at-landing delayed update round (R6, S7): the incoming
 *           triple is already past, so the landing itself is the degrade (the terminal
 *           shape lands and the cached request type is forced to OTHER); the system
 *           update payload request type matches the degraded classification type (the
 *           un-degraded incoming type never leaks into the payload).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAggregationServiceTest, TriggerUpdateAiExtNotification_00011,
    Function | SmallTest | Level1)
{
    AggTestResetPriorityState();
    MockNativeToken();
    sptr<NotificationRequest> cachedRequest = AggTestMakeRequest();
    std::string notificationKey = AggTestInjectRecord(advancedNotificationService_, cachedRequest);
    // The closed source sends a priority triple whose expire time already passed.
    int64_t pastTime = AggTestNowMillis() - 1000;
    sptr<NotificationRequest> incomingRequest = AggTestMakeRequest();
    incomingRequest->SetInnerPriorityNotificationType(AGG_TEST_TYPE_URGENT);
    sptr<NotificationClassification> classification =
        AggTestMakeClassification(AGG_TEST_TYPE_URGENT, pastTime, AGG_TEST_SOURCE_KEYWORD);
    std::shared_ptr<AggTestSystemUpdateSubscriber> subscriber =
        std::make_shared<AggTestSystemUpdateSubscriber>();
    sptr<IAnsSubscriber> listener = nullptr;
    AggTestRegisterSubscriber(subscriber, listener);

    ErrCode result = advancedNotificationService_->TriggerUpdateAiExtNotification(
        incomingRequest, classification);

    EXPECT_EQ(result, ERR_OK);
    // Expired-at-landing normalization: the terminal shape (type OTHER with the expire
    // time kept as the marker) lands and the cached request type is forced to OTHER.
    sptr<NotificationClassification> landed = NotificationClassificationMgr::GetInstance().Get(notificationKey);
    EXPECT_NE(landed, nullptr);
    if (landed != nullptr) {
        AggTestExpectPriorityInfo(landed->GetPriorityInfo(), AGG_TEST_TYPE_OTHER, pastTime,
            AGG_TEST_SOURCE_KEYWORD);
    }
    EXPECT_EQ(cachedRequest->GetPriorityNotificationType(), AGG_TEST_TYPE_OTHER);
    // The terminal shape never registers.
    EXPECT_EQ(PriorityNotificationDegradeManager::GetInstance()->GetEarliestExpiredTime(), 0);

    NotificationSubscriberManager::GetInstance()->WaitForFfrtQueue();
    EXPECT_EQ(subscriber->GetSystemUpdateCount(), 1);
    sptr<NotificationClassification> received = subscriber->GetLastClassification();
    EXPECT_NE(received, nullptr);
    if (received != nullptr) {
        AggTestExpectPriorityInfo(received->GetPriorityInfo(), AGG_TEST_TYPE_OTHER, pastTime,
            AGG_TEST_SOURCE_KEYWORD);
    }
    // R6: the payload request carries the degraded type, never the incoming URGENT one.
    EXPECT_EQ(subscriber->GetLastRequestPriorityType(), AGG_TEST_TYPE_OTHER);

    NotificationSubscriberManager::GetInstance()->RemoveSubscriberInner(listener, nullptr);
    AggTestResetPriorityState();
}
#endif // ANS_FEATURE_PRIORITY_NOTIFICATION
}  // namespace Notification
}  // namespace OHOS
