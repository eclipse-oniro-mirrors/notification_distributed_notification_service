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
#include <cstdint>
#include <list>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "errors.h"
#include "notification_analytics_util.h"
#include "notification_classification.h"
#include "notification_classification_mgr.h"
#include "notification_constant.h"
#include "notification_content.h"
#include "notification_request.h"
#include "refbase.h"
#include "singleton.h"
#include "timer_impl.h"

#define private public
#define protected public
#include "priority_notification_degrade_manager.h"
#undef protected
#undef private

// Service side access of the schedule and due degrade cases (T011): seeding the service
// notification list follows the established pattern of snooze_delay_manager_test.cpp
// (private access to the service header).
#define private public
#include "advanced_notification_service.h"
#undef private

// The system update callback cases (FIX-9a) register a real subscriber through the
// subscriber manager inner entry, which is private: the same access pattern as the
// aggregation service tests. The subscriber header tree (the listener wrapper and the
// subscriber base class reach ians_manager.h, which reaches NotificationSubscribeInfo
// with its private setters) is parsed inside this block as a whole, so the flags setter
// stays reachable.
#define private public
#include "ans_subscriber_listener.h"
#include "notification_subscriber.h"
#include "notification_subscriber_manager.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace Notification {
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
// ===== DFX event stub: the production implementation of
// NotificationAnalyticsUtil::ReportModifyEvent is a weak symbol (notification_analytics_
// util.cpp), so this strong definition wins at link time and neutralizes every modify
// event reported inside this test binary, the same link time replacement approach as
// the mock_notification_analytics_util.cpp compiled into the other test targets. The
// priority notification degrade feature reports no analytics event (its SCENE_30
// reporting was removed by a requirement change), and no test of this binary asserts
// the real reporting side effects (flow control and the want cache). =====
void NotificationAnalyticsUtil::ReportModifyEvent(const HaMetaMessage &message, bool unFlowControl)
{
    return;
}

namespace {
constexpr int64_t ONE_HOUR_MILLIS = 3600LL * 1000LL;

const std::string TYPE_OTHER = NotificationConstant::PriorityNotificationType::OTHER;
const std::string TYPE_URGENT = NotificationConstant::PriorityNotificationType::URGENT_MESSAGE;
const std::string TYPE_AT_ME = NotificationConstant::PriorityNotificationType::AT_ME;
const std::string TYPE_SCHEDULE = NotificationConstant::PriorityNotificationType::SCHEDULE_REMINDER;

const int32_t SOURCE_PARAM_IN = static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PARAM_IN);
const int32_t SOURCE_KEYWORD = static_cast<int32_t>(NotificationConstant::PrioritySourceResult::KEYWORD);
const int32_t SOURCE_AI = static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI);
const int32_t SOURCE_PUSH_RULE = static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PUSH_RULE);
// Not a SetSource accepted value: the setter rejects it and keeps the default
// INVALID_RESULT, which is exactly how the incoherent shape is produced.
const int32_t SOURCE_INVALID = static_cast<int32_t>(NotificationConstant::PrioritySourceResult::INVALID_RESULT);

int64_t NowMillis()
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return duration.count();
}

// Expire times are absolute epoch milliseconds. The arbitration cases use far future times so
// the schedule sync only registers the record (an already past expire time lands
// as the degraded terminal and never reaches the schedule).
int64_t FutureTime(int64_t offsetMillis)
{
    return NowMillis() + offsetMillis;
}

sptr<NotificationClassification> MakeClassification(const std::string &type, int64_t expiredTime,
    int32_t source)
{
    sptr<NotificationClassification> classification = new NotificationClassification("DEAL", "LOGISTICS");
    NotificationClassification::PriorityInfo priorityInfo;
    priorityInfo.SetPriorityNotificationType(type);
    priorityInfo.SetExpiredTime(expiredTime);
    priorityInfo.SetSource(source);
    classification->SetPriorityInfo(priorityInfo);
    return classification;
}

sptr<NotificationRequest> MakeRequest(const std::string &type)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorBundleName("com.example.priority.degrade");
    request->SetCreatorUid(200100);
    request->SetInnerPriorityNotificationType(type);
    return request;
}

void ExpectPriorityInfo(const NotificationClassification::PriorityInfo &priorityInfo,
    const std::string &type, int64_t expiredTime, int32_t source)
{
    EXPECT_EQ(priorityInfo.GetPriorityNotificationType(), type);
    EXPECT_EQ(priorityInfo.GetExpiredTime(), expiredTime);
    EXPECT_EQ(priorityInfo.GetSource(), source);
}
} // namespace

using ArbitrateResult = PriorityNotificationDegradeManager::ArbitrateResult;

class PriorityNotificationDegradeManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() override
    {
        // A clean classification cache and a fresh manager instance keep every case on a new
        // lifecycle (the singleton holds the degrade registration list).
        NotificationClassificationMgr::GetInstance().Clear();
        PriorityNotificationDegradeManager::DestroyInstance();
        manager_ = PriorityNotificationDegradeManager::GetInstance();
    }

    void TearDown() override
    {
        NotificationClassificationMgr::GetInstance().Clear();
        // Drop the local reference first so DestroyInstance really destroys the instance: the
        // destructor stops the timer and clears the registration list.
        manager_.reset();
        PriorityNotificationDegradeManager::DestroyInstance();
    }

protected:
    std::shared_ptr<PriorityNotificationDegradeManager> manager_;
};

/**
 * @tc.name: ApplyTaggingResult_00001
 * @tc.desc: Test row 1 of the arbitration matrix (new lifecycle): with no cache record the
 *           triple lands into the classification cache, the degrade record is registered and
 *           the landed value is exposed as the effective classification.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00001, Function | SmallTest | Level1)
{
    std::string key = "test_key_new_lifecycle";
    int64_t expireTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;

    auto result = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, expireTime, SOURCE_KEYWORD), effective);

    EXPECT_EQ(result, ArbitrateResult::APPLY);
    sptr<NotificationClassification> landed = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(landed, nullptr);
    ExpectPriorityInfo(landed->GetPriorityInfo(), TYPE_URGENT, expireTime, SOURCE_KEYWORD);
    EXPECT_EQ(landed->GetClassification(), "DEAL");
    EXPECT_EQ(landed->GetSubClassification(), "LOGISTICS");
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), expireTime);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(1));
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_URGENT, expireTime, SOURCE_KEYWORD);
}

/**
 * @tc.name: ApplyTaggingResult_00002
 * @tc.desc: Test row 2 of the arbitration matrix (undetermined expire time): a cached record
 *           with expiredTime 0 is refreshed with the new triple and then registered.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00002, Function | SmallTest | Level1)
{
    std::string key = "test_key_undetermined";
    NotificationClassificationMgr::GetInstance().AddOrUpdate(
        key, MakeClassification(TYPE_AT_ME, 0, SOURCE_AI));
    int64_t expireTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;

    auto result = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, expireTime, SOURCE_KEYWORD), effective);

    EXPECT_EQ(result, ArbitrateResult::APPLY);
    sptr<NotificationClassification> landed = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(landed, nullptr);
    ExpectPriorityInfo(landed->GetPriorityInfo(), TYPE_URGENT, expireTime, SOURCE_KEYWORD);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), expireTime);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_URGENT, expireTime, SOURCE_KEYWORD);
}

/**
 * @tc.name: ApplyTaggingResult_00003
 * @tc.desc: Test row 3 of the arbitration matrix (KEYWORD locked, overwrite semantics):
 *           a later model result overwrites the locked triple, the cache, the
 *           registration and the request type all take the incoming values and the
 *           effective classification is the landed new value.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00003, Function | SmallTest | Level1)
{
    std::string key = "test_key_keyword_locked";
    int64_t lockedTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto first = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, lockedTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(first, ArbitrateResult::APPLY);

    // The delayed model result arrives later and the AI extension has already written its own
    // type into the cached request (synchronous write semantics).
    request->SetInnerPriorityNotificationType(TYPE_AT_ME);
    int64_t laterTime = FutureTime(2 * ONE_HOUR_MILLIS);
    auto second = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_AT_ME, laterTime, SOURCE_AI), effective);

    EXPECT_EQ(second, ArbitrateResult::APPLY);
    sptr<NotificationClassification> cached = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cached, nullptr);
    ExpectPriorityInfo(cached->GetPriorityInfo(), TYPE_AT_ME, laterTime, SOURCE_AI);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), laterTime);
    EXPECT_EQ(request->GetPriorityNotificationType(), TYPE_AT_ME);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_AT_ME, laterTime, SOURCE_AI);
}

/**
 * @tc.name: ApplyTaggingResult_00004
 * @tc.desc: Test row 3 of the arbitration matrix with the other deterministic sources
 *           (overwrite semantics): a cache locked by PUSH_RULE or PARAM_IN is
 *           overwritten by any later result as well.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00004, Function | SmallTest | Level1)
{
    std::string key = "test_key_push_rule_locked";
    int64_t lockedTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto first = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, lockedTime, SOURCE_PUSH_RULE), effective);
    EXPECT_EQ(first, ArbitrateResult::APPLY);

    request->SetInnerPriorityNotificationType(TYPE_AT_ME);
    int64_t laterTime = FutureTime(2 * ONE_HOUR_MILLIS);
    auto second = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_AT_ME, laterTime, SOURCE_AI),
        effective);
    EXPECT_EQ(second, ArbitrateResult::APPLY);
    sptr<NotificationClassification> cached = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cached, nullptr);
    ExpectPriorityInfo(cached->GetPriorityInfo(), TYPE_AT_ME, laterTime, SOURCE_AI);
    EXPECT_EQ(request->GetPriorityNotificationType(), TYPE_AT_ME);

    // A PARAM_IN locked cache is overwritten the same way.
    std::string paramKey = "test_key_param_in_locked";
    int64_t paramTime = FutureTime(ONE_HOUR_MILLIS);
    auto third = manager_->ApplyTaggingResult(
        paramKey, request, MakeClassification(TYPE_SCHEDULE, paramTime, SOURCE_PARAM_IN), effective);
    EXPECT_EQ(third, ArbitrateResult::APPLY);
    int64_t paramLaterTime = FutureTime(2 * ONE_HOUR_MILLIS);
    auto fourth = manager_->ApplyTaggingResult(
        paramKey, request, MakeClassification(TYPE_AT_ME, paramLaterTime, SOURCE_KEYWORD),
        effective);
    EXPECT_EQ(fourth, ArbitrateResult::APPLY);
    sptr<NotificationClassification> paramCached = NotificationClassificationMgr::GetInstance().Get(paramKey);
    ASSERT_NE(paramCached, nullptr);
    ExpectPriorityInfo(paramCached->GetPriorityInfo(), TYPE_AT_ME, paramLaterTime, SOURCE_KEYWORD);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(2));
}

/**
 * @tc.name: ApplyTaggingResult_00005
 * @tc.desc: Test row 4 of the arbitration matrix (rule overrides model): an undegraded model
 *           result is fully overridden by a rule family result, the registration is
 *           rescheduled to the new expire time and the request keeps the rule type.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00005, Function | SmallTest | Level1)
{
    std::string key = "test_key_rule_override";
    int64_t modelTime = FutureTime(2 * ONE_HOUR_MILLIS);
    int64_t ruleTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto first = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, modelTime, SOURCE_AI), effective);
    EXPECT_EQ(first, ArbitrateResult::APPLY);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), modelTime);

    // The rule result arrives later and the AI extension has already written the rule type
    // into the cached request (synchronous write semantics).
    request->SetInnerPriorityNotificationType(TYPE_SCHEDULE);
    auto second = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_SCHEDULE, ruleTime, SOURCE_KEYWORD), effective);

    EXPECT_EQ(second, ArbitrateResult::RULE_OVERRIDE);
    sptr<NotificationClassification> landed = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(landed, nullptr);
    ExpectPriorityInfo(landed->GetPriorityInfo(), TYPE_SCHEDULE, ruleTime, SOURCE_KEYWORD);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), ruleTime);
    EXPECT_EQ(request->GetPriorityNotificationType(), TYPE_SCHEDULE);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_SCHEDULE, ruleTime, SOURCE_KEYWORD);
}

/**
 * @tc.name: ApplyTaggingResult_00006
 * @tc.desc: Test row 5 of the arbitration matrix (repeated model result, overwrite
 *           semantics): a later model result against a determined model cache
 *           overwrites it and the schedule follows the new expire time.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00006, Function | SmallTest | Level1)
{
    std::string key = "test_key_repeated_model";
    int64_t modelTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto first = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, modelTime, SOURCE_AI), effective);
    EXPECT_EQ(first, ArbitrateResult::APPLY);

    request->SetInnerPriorityNotificationType(TYPE_AT_ME);
    int64_t laterTime = FutureTime(2 * ONE_HOUR_MILLIS);
    auto second = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_AT_ME, laterTime, SOURCE_AI),
        effective);

    EXPECT_EQ(second, ArbitrateResult::APPLY);
    sptr<NotificationClassification> cached = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cached, nullptr);
    ExpectPriorityInfo(cached->GetPriorityInfo(), TYPE_AT_ME, laterTime, SOURCE_AI);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), laterTime);
    EXPECT_EQ(request->GetPriorityNotificationType(), TYPE_AT_ME);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_AT_ME, laterTime, SOURCE_AI);
}

/**
 * @tc.name: ApplyTaggingResult_00007
 * @tc.desc: Test row 6 of the arbitration matrix (degraded terminal revive, R5): once
 *           the cache type is OTHER with the expire time kept as the terminal marker, a
 *           late model result revives the priority (the terminal triple is overwritten,
 *           the schedule follows the new expire time and the request type keeps the
 *           written value), a rule family result against the revived model cache keeps
 *           the RULE_OVERRIDE label, and an OTHER revive round is normalized to expire
 *           time 0 so the degraded state is kept with no registration left.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00007, Function | SmallTest | Level1)
{
    std::string key = "test_key_degraded";
    int64_t degradeTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto first = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, degradeTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(first, ArbitrateResult::APPLY);

    // The timer has fired: the degrade leaves type OTHER with the expire time kept as the
    // terminal marker (the two landing points of ProcessPriorityDegradeOnQueue).
    NotificationClassificationMgr::GetInstance().AddOrUpdate(
        key, MakeClassification(TYPE_OTHER, degradeTime, SOURCE_KEYWORD));
    request->SetInnerPriorityNotificationType(TYPE_OTHER);

    // A late model result revives the terminal state (R5): the terminal triple is
    // overwritten, the schedule follows the new expire time and the request type keeps
    // the value the AI extension wrote in.
    request->SetInnerPriorityNotificationType(TYPE_AT_ME);
    int64_t reviveTime = FutureTime(2 * ONE_HOUR_MILLIS);
    auto second = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_AT_ME, reviveTime, SOURCE_AI),
        effective);
    EXPECT_EQ(second, ArbitrateResult::APPLY);
    sptr<NotificationClassification> cached = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cached, nullptr);
    ExpectPriorityInfo(cached->GetPriorityInfo(), TYPE_AT_ME, reviveTime, SOURCE_AI);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), reviveTime);
    EXPECT_EQ(request->GetPriorityNotificationType(), TYPE_AT_ME);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_AT_ME, reviveTime, SOURCE_AI);

    // A rule family result against the revived model cache keeps the RULE_OVERRIDE
    // label and re-lands with the new expire time.
    request->SetInnerPriorityNotificationType(TYPE_SCHEDULE);
    int64_t ruleTime = FutureTime(3 * ONE_HOUR_MILLIS);
    auto third = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_SCHEDULE, ruleTime, SOURCE_PUSH_RULE),
        effective);
    EXPECT_EQ(third, ArbitrateResult::RULE_OVERRIDE);
    sptr<NotificationClassification> cachedAgain = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cachedAgain, nullptr);
    ExpectPriorityInfo(cachedAgain->GetPriorityInfo(), TYPE_SCHEDULE, ruleTime, SOURCE_PUSH_RULE);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), ruleTime);
    EXPECT_EQ(request->GetPriorityNotificationType(), TYPE_SCHEDULE);

    // An OTHER revive round is normalized to expire time 0: the degraded state is kept
    // and no registration stays.
    auto fourth = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_OTHER, FutureTime(4 * ONE_HOUR_MILLIS), SOURCE_AI),
        effective);
    EXPECT_EQ(fourth, ArbitrateResult::APPLY);
    sptr<NotificationClassification> cachedOther = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cachedOther, nullptr);
    ExpectPriorityInfo(cachedOther->GetPriorityInfo(), TYPE_OTHER, 0, SOURCE_AI);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), 0);
}

/**
 * @tc.name: ApplyTaggingResult_00008
 * @tc.desc: Test the null round without cache (overwrite semantics): there is nothing to
 *           clear, so the cache stays empty and the registration untouched, but the
 *           request type is forced to OTHER (the round's value is "no priority") and
 *           CLEARED is returned so no caller writes a type back.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00008, Function | SmallTest | Level1)
{
    std::string key = "test_key_null_no_cache";
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;

    auto result = manager_->ApplyTaggingResult(key, request, nullptr, effective);

    EXPECT_EQ(result, ArbitrateResult::CLEARED);
    EXPECT_EQ(effective, nullptr);
    EXPECT_EQ(NotificationClassificationMgr::GetInstance().Get(key), nullptr);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), 0);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(0));
    EXPECT_EQ(request->GetPriorityNotificationType(), TYPE_OTHER);
}

/**
 * @tc.name: ApplyTaggingResult_00009
 * @tc.desc: Test the null round against a determined cache (overwrite semantics): the
 *           round's null value directly overwrites the cache — the entry is removed,
 *           the request type is forced to OTHER, the stale degrade registration is
 *           removed, the effective classification is null and CLEARED is returned
 *           so no caller writes a type back over the overwrite.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00009, Function | SmallTest | Level1)
{
    std::string key = "test_key_null_with_cache";
    int64_t expireTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto first = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, expireTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(first, ArbitrateResult::APPLY);

    // The AI extension has already written its own type into the cached request for this
    // round (synchronous write semantics): the null round forces it to OTHER, so the
    // write back cannot resurrect a priority the fact source no longer holds.
    request->SetInnerPriorityNotificationType(TYPE_AT_ME);
    auto second = manager_->ApplyTaggingResult(key, request, nullptr, effective);

    EXPECT_EQ(second, ArbitrateResult::CLEARED);
    // The round's null value directly overwrites the cache: the entry is removed.
    EXPECT_EQ(NotificationClassificationMgr::GetInstance().Get(key), nullptr);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), 0);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(0));
    EXPECT_EQ(request->GetPriorityNotificationType(), TYPE_OTHER);
    EXPECT_EQ(effective, nullptr);
}

/**
 * @tc.name: ApplyTaggingResult_00010
 * @tc.desc: Test the null boundary with a polluted cache: a null cache entry (historical
 *           null pollution) is treated as no record, so the next real result takes the new
 *           lifecycle branch and lands normally.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00010, Function | SmallTest | Level1)
{
    std::string key = "test_key_null_pollution";
    NotificationClassificationMgr::GetInstance().AddOrUpdate(key, nullptr);
    int64_t expireTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_AT_ME);
    sptr<NotificationClassification> effective = nullptr;

    auto result = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_AT_ME, expireTime, SOURCE_AI), effective);

    EXPECT_EQ(result, ArbitrateResult::APPLY);
    sptr<NotificationClassification> landed = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(landed, nullptr);
    ExpectPriorityInfo(landed->GetPriorityInfo(), TYPE_AT_ME, expireTime, SOURCE_AI);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), expireTime);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_AT_ME, expireTime, SOURCE_AI);
}

/**
 * @tc.name: ApplyTaggingResult_00011
 * @tc.desc: Test scenario S1 (overwrite semantics): the rule result lands first through
 *           the synchronous consumption path, then the delayed model update overwrites
 *           it and the schedule follows the new expire time.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00011, Function | SmallTest | Level1)
{
    std::string key = "test_key_rule_first";
    int64_t ruleTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    // The synchronous consumption path runs off the server queue (NotifyConsumedInner).
    auto first = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, ruleTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(first, ArbitrateResult::APPLY);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), ruleTime);

    // The delayed update path runs on the server queue (TriggerUpdateAiExtNotification).
    request->SetInnerPriorityNotificationType(TYPE_AT_ME);
    int64_t laterTime = FutureTime(2 * ONE_HOUR_MILLIS);
    auto second = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_AT_ME, laterTime, SOURCE_AI),
        effective);

    EXPECT_EQ(second, ArbitrateResult::APPLY);
    sptr<NotificationClassification> cached = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cached, nullptr);
    ExpectPriorityInfo(cached->GetPriorityInfo(), TYPE_AT_ME, laterTime, SOURCE_AI);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), laterTime);
    EXPECT_EQ(request->GetPriorityNotificationType(), TYPE_AT_ME);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_AT_ME, laterTime, SOURCE_AI);
}

/**
 * @tc.name: ApplyTaggingResult_00012
 * @tc.desc: Test scenario S5a (update notification, overwrite semantics): republishing
 *           the same key re-consumes and re-tags the notification, and the re-tagging
 *           result overwrites the creation triple, reschedules the registration and is
 *           distributed as the effective classification.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00012, Function | SmallTest | Level1)
{
    std::string key = "test_key_update_notification";
    int64_t expireTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    // Creation phase: the rule result lands and the subscriber sees it on OnConsumed.
    auto first = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, expireTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(first, ArbitrateResult::APPLY);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_URGENT, expireTime, SOURCE_KEYWORD);

    // Update notification phase: the same key is republished, re-consumed and re-tagged
    // (a repeated rule result overwrites under the overwrite semantics) and the request
    // got the newly written type.
    request->SetInnerPriorityNotificationType(TYPE_SCHEDULE);
    int64_t updateTime = FutureTime(2 * ONE_HOUR_MILLIS);
    auto second = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_SCHEDULE, updateTime, SOURCE_KEYWORD),
        effective);

    EXPECT_EQ(second, ArbitrateResult::APPLY);
    sptr<NotificationClassification> cached = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cached, nullptr);
    ExpectPriorityInfo(cached->GetPriorityInfo(), TYPE_SCHEDULE, updateTime, SOURCE_KEYWORD);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), updateTime);
    EXPECT_EQ(request->GetPriorityNotificationType(), TYPE_SCHEDULE);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_SCHEDULE, updateTime, SOURCE_KEYWORD);
}

/**
 * @tc.name: ApplyTaggingResult_00013
 * @tc.desc: Test scenario S8 tail (overwrite semantics): after a rule overrode the model
 *           result, a further model result overwrites it again.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00013, Function | SmallTest | Level1)
{
    std::string key = "test_key_after_override";
    int64_t modelTime = FutureTime(2 * ONE_HOUR_MILLIS);
    int64_t ruleTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto first = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, modelTime, SOURCE_AI), effective);
    EXPECT_EQ(first, ArbitrateResult::APPLY);
    request->SetInnerPriorityNotificationType(TYPE_AT_ME);
    auto second = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_AT_ME, ruleTime, SOURCE_PUSH_RULE), effective);
    EXPECT_EQ(second, ArbitrateResult::RULE_OVERRIDE);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), ruleTime);

    // A further model result arrives after the override: it overwrites the rule result.
    request->SetInnerPriorityNotificationType(TYPE_URGENT);
    int64_t thirdTime = FutureTime(3 * ONE_HOUR_MILLIS);
    auto third = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, thirdTime, SOURCE_AI),
        effective);

    EXPECT_EQ(third, ArbitrateResult::APPLY);
    sptr<NotificationClassification> cached = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cached, nullptr);
    ExpectPriorityInfo(cached->GetPriorityInfo(), TYPE_URGENT, thirdTime, SOURCE_AI);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), thirdTime);
    EXPECT_EQ(request->GetPriorityNotificationType(), TYPE_URGENT);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_URGENT, thirdTime, SOURCE_AI);
}

/**
 * @tc.name: ApplyTaggingResult_00014
 * @tc.desc: Test scenario S5b (delete and restore): after the notification is deleted (the
 *           cache is removed and the degrade registration cleaned), a republished
 *           notification is a new lifecycle and lands a fresh triple.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00014, Function | SmallTest | Level1)
{
    std::string key = "test_key_delete_restore";
    int64_t firstTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto first = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, firstTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(first, ArbitrateResult::APPLY);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), firstTime);

    // Deletion: the existing cleanup removes the cache and the degrade registration.
    NotificationClassificationMgr::GetInstance().Remove(key);
    manager_->Remove(key);
    EXPECT_EQ(NotificationClassificationMgr::GetInstance().Get(key), nullptr);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), 0);

    // Restore: republishing is a new lifecycle and lands a fresh triple.
    int64_t secondTime = FutureTime(2 * ONE_HOUR_MILLIS);
    request->SetInnerPriorityNotificationType(TYPE_AT_ME);
    auto second = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_AT_ME, secondTime, SOURCE_AI), effective);
    EXPECT_EQ(second, ArbitrateResult::APPLY);
    sptr<NotificationClassification> landed = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(landed, nullptr);
    ExpectPriorityInfo(landed->GetPriorityInfo(), TYPE_AT_ME, secondTime, SOURCE_AI);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), secondTime);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_AT_ME, secondTime, SOURCE_AI);
}

/**
 * @tc.name: ApplyTaggingResult_00015
 * @tc.desc: Test scenario E2 end to end (revive semantics, R5): after the degrade
 *           completed, a further update notification revives the priority state — the
 *           effective classification and the request type carry the new triple and the
 *           schedule follows the new expire time — and the following cancel cleans up
 *           without crash.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00015, Function | SmallTest | Level1)
{
    std::string key = "test_key_e2_terminal";
    int64_t expireTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    // Creation phase: the rule result lands.
    auto first = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, expireTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(first, ArbitrateResult::APPLY);
    // Update notification phase (overwrite semantics): the update re-tagging overwrites
    // the creation triple.
    request->SetInnerPriorityNotificationType(TYPE_AT_ME);
    int64_t updateTime = FutureTime(2 * ONE_HOUR_MILLIS);
    auto second = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_AT_ME, updateTime, SOURCE_AI),
        effective);
    EXPECT_EQ(second, ArbitrateResult::APPLY);

    // Degrade phase: the timer fired, the terminal state is type OTHER with the expire time
    // kept and the registration stripped (what TriggerDegrade and the queue degrade leave).
    NotificationClassificationMgr::GetInstance().AddOrUpdate(
        key, MakeClassification(TYPE_OTHER, updateTime, SOURCE_AI));
    request->SetInnerPriorityNotificationType(TYPE_OTHER);
    manager_->Remove(key);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), 0);

    // Re-update phase (revive semantics, R5): the terminal state is overwritten by the
    // re-tagging — the request type keeps the written value, the effective value exposes
    // the new triple and the schedule follows the new expire time.
    request->SetInnerPriorityNotificationType(TYPE_SCHEDULE);
    int64_t reviveTime = FutureTime(3 * ONE_HOUR_MILLIS);
    auto third = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_SCHEDULE, reviveTime, SOURCE_AI),
        effective);
    EXPECT_EQ(third, ArbitrateResult::APPLY);
    sptr<NotificationClassification> cached = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cached, nullptr);
    ExpectPriorityInfo(cached->GetPriorityInfo(), TYPE_SCHEDULE, reviveTime, SOURCE_AI);
    EXPECT_EQ(request->GetPriorityNotificationType(), TYPE_SCHEDULE);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_SCHEDULE, reviveTime, SOURCE_AI);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), reviveTime);

    // Cancel phase: the cleanup is defensive only and must not crash.
    manager_->Remove(key);
    NotificationClassificationMgr::GetInstance().Remove(key);
    EXPECT_EQ(NotificationClassificationMgr::GetInstance().Get(key), nullptr);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), 0);
}

/**
 * @tc.name: ApplyTaggingResult_00016
 * @tc.desc: Test the accepted overwrite with a null cache request (overwrite semantics):
 *           the landing and the schedule sync need no request identity for the triple
 *           itself, so a later result still overwrites the locked triple without any
 *           crash while the request type is not touched (there is no carrier to update).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00016, Function | SmallTest | Level1)
{
    std::string key = "test_key_null_request";
    int64_t lockedTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto first = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, lockedTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(first, ArbitrateResult::APPLY);

    int64_t laterTime = FutureTime(2 * ONE_HOUR_MILLIS);
    auto second = manager_->ApplyTaggingResult(
        key, nullptr, MakeClassification(TYPE_AT_ME, laterTime, SOURCE_AI),
        effective);

    EXPECT_EQ(second, ArbitrateResult::APPLY);
    sptr<NotificationClassification> cached = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cached, nullptr);
    ExpectPriorityInfo(cached->GetPriorityInfo(), TYPE_AT_ME, laterTime, SOURCE_AI);
    // The registration no longer requires a request identity (the per key cleanup is
    // keyed by the notification key), so the reschedule happens normally.
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), laterTime);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(1));
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_AT_ME, laterTime, SOURCE_AI);
}

// ===== Schedule and due degrade cases (T011) =====
// The real timer cannot be started in the unit test environment (no time service), so
// the schedule is observed through the registration list and GetEarliestExpiredTime,
// and TriggerDegrade is called directly to simulate the timer expiry. The service side
// landing points are covered through the real queue entries: the service singleton is
// reachable in this target (advanced_notification_priority_manager_service_test.cpp
// already drives it through AdvancedNotificationService::GetInstance()).

namespace {
// Request with an explicit bundle identity and receiver user, for the registration and
// service record seeding cases. The slot and the basic text content keep the
// request parcelable for the subscriber callback round trip (the AggTestMakeRequest
// pattern: without a valid content type the request read of the dispatch copy is
// rejected and the callback is skipped silently).
sptr<NotificationRequest> MakeScheduleRequest(const std::string &bundleName, int32_t uid,
    int32_t userId, int32_t notificationId, const std::string &type)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorBundleName(bundleName);
    request->SetCreatorUid(uid);
    request->SetReceiverUserId(userId);
    request->SetNotificationId(notificationId);
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    request->SetContent(std::make_shared<NotificationContent>(normalContent));
    request->SetInnerPriorityNotificationType(type);
    return request;
}

// Seeds one notification record into the service notification list. The key looked up
// by the queue inner degrade entry is the base key the Notification constructor
// computes for the request.
void SeedServiceRecord(const sptr<AdvancedNotificationService> &service,
    const sptr<NotificationRequest> &request)
{
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = new Notification(request);
    service->notificationList_.push_back(record);
}

// Registers one determined future expire time through the real arbitration path.
void RegisterFutureRecord(const std::shared_ptr<PriorityNotificationDegradeManager> &manager,
    const std::string &key, const sptr<NotificationRequest> &request, int64_t expireTime)
{
    sptr<NotificationClassification> effective = nullptr;
    auto result = manager->ApplyTaggingResult(key, request,
        MakeClassification(TYPE_URGENT, expireTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(result, ArbitrateResult::APPLY);
}
} // namespace

/**
 * @tc.name: SyncDegradeSchedule_00001
 * @tc.desc: Test AC-001: after the tagging result lands, the registration list is kept
 *           ascending by the absolute expire time and GetEarliestExpiredTime returns
 *           the smallest one; the stored value is the absolute time point itself (kept
 *           verbatim, not a now based relative offset).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, SyncDegradeSchedule_00001, Function | SmallTest | Level1)
{
    int64_t lateTime = FutureTime(3 * ONE_HOUR_MILLIS);
    int64_t earlyTime = FutureTime(ONE_HOUR_MILLIS);
    int64_t middleTime = FutureTime(2 * ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);

    // Registered out of order: late, early, middle.
    RegisterFutureRecord(manager_, "test_key_schedule_late", request, lateTime);
    RegisterFutureRecord(manager_, "test_key_schedule_early", request, earlyTime);
    RegisterFutureRecord(manager_, "test_key_schedule_middle", request, middleTime);

    ASSERT_EQ(manager_->degradeList_.size(), static_cast<size_t>(3));
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), earlyTime);
    EXPECT_EQ(manager_->degradeList_.front().key, "test_key_schedule_early");
    EXPECT_EQ(manager_->degradeList_.back().key, "test_key_schedule_late");
    int64_t previous = 0;
    for (const auto &record : manager_->degradeList_) {
        EXPECT_GE(record.expiredTime, previous);
        previous = record.expiredTime;
    }
}

/**
 * @tc.name: TriggerDegrade_00001
 * @tc.desc: Test AC-002: on the timer expiry every due registration is processed in
 *           batch (the missing notification records are skipped defensively without
 *           any crash), the timer is re-armed to the next earliest time and removing
 *           the last registration destroys the timer.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, TriggerDegrade_00001, Function | SmallTest | Level1)
{
    sptr<AdvancedNotificationService> service = AdvancedNotificationService::GetInstance();
    service->notificationList_.clear();

    // Two registrations whose expire time already passed, simulating what the timer
    // firing finds in the list (seeded directly: the registration path itself would
    // degrade them immediately).
    PriorityNotificationDegradeManager::DegradeRecord firstDue;
    firstDue.key = "test_key_due_first";
    firstDue.expiredTime = NowMillis() - 2 * ONE_HOUR_MILLIS;
    manager_->degradeList_.push_back(firstDue);
    PriorityNotificationDegradeManager::DegradeRecord secondDue;
    secondDue.key = "test_key_due_second";
    secondDue.expiredTime = NowMillis() - ONE_HOUR_MILLIS;
    manager_->degradeList_.push_back(secondDue);

    // A still future registration through the real path: the schedule sync sorts the
    // whole list ascending, so the due records end up in front of the future one.
    int64_t futureTime = FutureTime(ONE_HOUR_MILLIS);
    RegisterFutureRecord(manager_, "test_key_due_future", MakeRequest(TYPE_URGENT), futureTime);
    ASSERT_EQ(manager_->degradeList_.size(), static_cast<size_t>(3));
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), firstDue.expiredTime);

    // Timer expiry: both due records are dispatched (their notification records do not
    // exist, the defensive path only skips them) and the timer is re-armed.
    manager_->TriggerDegrade();
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(1));
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), futureTime);
    EXPECT_EQ(manager_->degradeList_.front().key, "test_key_due_future");

    // The last registration is removed: the list is empty and the timer is destroyed.
    manager_->Remove("test_key_due_future");
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(0));
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), 0);
}

/**
 * @tc.name: ProcessPriorityDegradeOnQueue_00001
 * @tc.desc: Test AC-003 through the queue inner entry: the degrade sets the cached
 *           request type and the classification cache type to OTHER, keeps the expire
 *           time as the terminal marker and leaves the aggregation dimension
 *           untouched.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ProcessPriorityDegradeOnQueue_00001, Function | SmallTest | Level1)
{
    sptr<AdvancedNotificationService> service = AdvancedNotificationService::GetInstance();
    service->notificationList_.clear();
    sptr<NotificationRequest> request = MakeScheduleRequest(
        "com.example.degrade.onqueue", 200100, 100, 1, TYPE_URGENT);
    std::string key = request->GetBaseKey("");
    // FIX-5 expiry defense: the queue entry only degrades a cache whose expire time
    // is already due, so the preset uses a past time. Seeded directly: a past time
    // through the arbitration would land as the degraded terminal and consume the
    // assertion target. The seeded registration mirrors an in-flight due dispatch.
    int64_t expireTime = NowMillis() - ONE_HOUR_MILLIS;
    NotificationClassificationMgr::GetInstance().AddOrUpdate(
        key, MakeClassification(TYPE_URGENT, expireTime, SOURCE_KEYWORD));
    PriorityNotificationDegradeManager::DegradeRecord pendingRecord;
    pendingRecord.key = key;
    pendingRecord.expiredTime = expireTime;
    manager_->degradeList_.push_back(pendingRecord);
    SeedServiceRecord(service, request);

    EXPECT_EQ(service->ProcessPriorityDegradeOnQueue(key), true);

    // Landing point 1: the cached request type is degraded to OTHER.
    EXPECT_EQ(request->GetPriorityNotificationType(), TYPE_OTHER);
    // Landing point 2: the classification cache type is degraded to OTHER with the
    // expire time kept as the terminal marker and the aggregation dimension untouched.
    sptr<NotificationClassification> cached = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cached, nullptr);
    ExpectPriorityInfo(cached->GetPriorityInfo(), TYPE_OTHER, expireTime, SOURCE_KEYWORD);
    EXPECT_EQ(cached->GetClassification(), "DEAL");
    EXPECT_EQ(cached->GetSubClassification(), "LOGISTICS");
    // The queue inner entry does not touch the schedule (the caller strips the
    // registration): the pending registration is still observable.
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), expireTime);
}

/**
 * @tc.name: ProcessPriorityDegrade_00001
 * @tc.desc: Test AC-003 through the external entry: the synchronous submit onto the
 *           server queue (the cross queue dispatch used by the timer callback thread
 *           and the subscriber queue) completes within the call and both landing
 *           points are degraded.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ProcessPriorityDegrade_00001, Function | SmallTest | Level1)
{
    sptr<AdvancedNotificationService> service = AdvancedNotificationService::GetInstance();
    service->notificationList_.clear();
    sptr<NotificationRequest> request = MakeScheduleRequest(
        "com.example.degrade.external", 200100, 100, 1, TYPE_URGENT);
    std::string key = request->GetBaseKey("");
    // FIX-5 expiry defense: the same due time preset as the queue inner entry case,
    // seeded directly so the expired-at-landing normalization of the arbitration path
    // cannot consume the assertion target before the external entry runs.
    int64_t expireTime = NowMillis() - ONE_HOUR_MILLIS;
    NotificationClassificationMgr::GetInstance().AddOrUpdate(
        key, MakeClassification(TYPE_URGENT, expireTime, SOURCE_KEYWORD));
    SeedServiceRecord(service, request);

    EXPECT_EQ(service->ProcessPriorityDegrade(key), true);

    EXPECT_EQ(request->GetPriorityNotificationType(), TYPE_OTHER);
    sptr<NotificationClassification> cached = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cached, nullptr);
    ExpectPriorityInfo(cached->GetPriorityInfo(), TYPE_OTHER, expireTime, SOURCE_KEYWORD);
}

/**
 * @tc.name: ProcessPriorityDegradeOnQueue_00002
 * @tc.desc: Test the AC-004 defensive path: with the request type already OTHER and no
 *           classification cached, the degrade only cleans the registration up (no
 *           callback payload is built, nothing lands) and returns true; a key without
 *           a notification record returns false through both entries without any
 *           crash.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ProcessPriorityDegradeOnQueue_00002, Function | SmallTest | Level1)
{
    sptr<AdvancedNotificationService> service = AdvancedNotificationService::GetInstance();
    service->notificationList_.clear();

    // Already OTHER without a cached classification: only cleanup, no callback.
    sptr<NotificationRequest> request = MakeScheduleRequest(
        "com.example.degrade.defensive", 200100, 100, 1, TYPE_OTHER);
    std::string key = request->GetBaseKey("");
    SeedServiceRecord(service, request);
    EXPECT_EQ(service->ProcessPriorityDegradeOnQueue(key), true);
    EXPECT_EQ(request->GetPriorityNotificationType(), TYPE_OTHER);
    EXPECT_EQ(NotificationClassificationMgr::GetInstance().Get(key), nullptr);

    // The notification was removed before the timer fired: the record does not exist.
    EXPECT_EQ(service->ProcessPriorityDegradeOnQueue("test_key_degrade_missing"), false);
    EXPECT_EQ(service->ProcessPriorityDegrade("test_key_degrade_missing"), false);
}

/**
 * @tc.name: ApplyTaggingResult_00017
 * @tc.desc: Test AC-008 (S7): when the landed expire time is already in the past, the
 *           landing itself is the degrade — the expired-at-landing normalization lands
 *           the triple directly as the degraded terminal (type OTHER with the expire
 *           time kept as the terminal marker, the request carrier degraded as well),
 *           the effective value carries the terminal out for the normal round
 *           distribution, and no registration is left for the timer. The outcome is
 *           queue context independent (checked in both the subscriber queue and the
 *           server queue contexts).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00017, Function | SmallTest | Level1)
{
    sptr<AdvancedNotificationService> service = AdvancedNotificationService::GetInstance();
    service->notificationList_.clear();
    int64_t pastTime = NowMillis() - 1000;

    // Subscriber queue context (NotifyConsumedInner).
    sptr<NotificationRequest> requestSub = MakeScheduleRequest(
        "com.example.degrade.sub", 200100, 100, 1, TYPE_URGENT);
    std::string keySub = requestSub->GetBaseKey("");
    SeedServiceRecord(service, requestSub);
    sptr<NotificationClassification> effective = nullptr;
    auto resultSub = manager_->ApplyTaggingResult(keySub, requestSub,
        MakeClassification(TYPE_URGENT, pastTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(resultSub, ArbitrateResult::APPLY);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(0));
    EXPECT_EQ(requestSub->GetPriorityNotificationType(), TYPE_OTHER);
    sptr<NotificationClassification> cachedSub = NotificationClassificationMgr::GetInstance().Get(keySub);
    ASSERT_NE(cachedSub, nullptr);
    ExpectPriorityInfo(cachedSub->GetPriorityInfo(), TYPE_OTHER, pastTime, SOURCE_KEYWORD);
    // The effective value carries the terminal out for the normal round distribution.
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_OTHER, pastTime, SOURCE_KEYWORD);

    // Server queue context (TriggerUpdateAiExtNotification).
    sptr<NotificationRequest> requestSvr = MakeScheduleRequest(
        "com.example.degrade.svr", 200200, 100, 2, TYPE_URGENT);
    std::string keySvr = requestSvr->GetBaseKey("");
    SeedServiceRecord(service, requestSvr);
    auto resultSvr = manager_->ApplyTaggingResult(keySvr, requestSvr,
        MakeClassification(TYPE_URGENT, pastTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(resultSvr, ArbitrateResult::APPLY);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(0));
    EXPECT_EQ(requestSvr->GetPriorityNotificationType(), TYPE_OTHER);
    sptr<NotificationClassification> cachedSvr = NotificationClassificationMgr::GetInstance().Get(keySvr);
    ASSERT_NE(cachedSvr, nullptr);
    ExpectPriorityInfo(cachedSvr->GetPriorityInfo(), TYPE_OTHER, pastTime, SOURCE_KEYWORD);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_OTHER, pastTime, SOURCE_KEYWORD);

    // Nothing is scheduled for the timer.
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), 0);
}

/**
 * @tc.name: Remove_00001
 * @tc.desc: Test AC-007 (single key removal): removing a middle entry keeps the
 *           earliest time, removing the earliest entry reschedules the timer to the
 *           next one, removing an unregistered key is a defensive no-op and the last
 *           removal empties the list and destroys the timer.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, Remove_00001, Function | SmallTest | Level1)
{
    int64_t earlyTime = FutureTime(ONE_HOUR_MILLIS);
    int64_t middleTime = FutureTime(2 * ONE_HOUR_MILLIS);
    int64_t lateTime = FutureTime(3 * ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    RegisterFutureRecord(manager_, "test_key_remove_late", request, lateTime);
    RegisterFutureRecord(manager_, "test_key_remove_early", request, earlyTime);
    RegisterFutureRecord(manager_, "test_key_remove_middle", request, middleTime);
    ASSERT_EQ(manager_->degradeList_.size(), static_cast<size_t>(3));
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), earlyTime);

    // Removing a middle entry keeps the earliest time (no reschedule).
    manager_->Remove("test_key_remove_middle");
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(2));
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), earlyTime);

    // Removing the earliest entry reschedules the timer to the next earliest time.
    manager_->Remove("test_key_remove_early");
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(1));
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), lateTime);

    // Removing an unregistered key is a defensive no-op.
    manager_->Remove("test_key_remove_early");
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(1));

    // The last removal empties the list and destroys the timer.
    manager_->Remove("test_key_remove_late");
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(0));
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), 0);
}

// ===== FIX-9a appended cases: the new behavior of the FIX-4b/4c/5 fix clusters and the
// gate scoring test items (TEST-04/06/07, FUNC-002). Everything is tail appended: the
// existing cases above stay untouched. =====
namespace {
// Classification with explicit aggregation labels, for the dimension split case: the
// aggregation dimension of the incoming result differs from the cached one.
sptr<NotificationClassification> MakeTaggedClassification(const std::string &classificationLabel,
    const std::string &subClassificationLabel, const std::string &type, int64_t expiredTime,
    int32_t source)
{
    sptr<NotificationClassification> classification =
        new NotificationClassification(classificationLabel, subClassificationLabel);
    NotificationClassification::PriorityInfo priorityInfo;
    priorityInfo.SetPriorityNotificationType(type);
    priorityInfo.SetExpiredTime(expiredTime);
    priorityInfo.SetSource(source);
    classification->SetPriorityInfo(priorityInfo);
    return classification;
}

// A subscriber registered only for the system update callback (the T012 subscriber
// pattern): it counts the callbacks and captures the classification the server attached
// to the notification, so the degrade callback chain (NotifySystemUpdate ->
// OnSystemUpdate) can be asserted end to end.
class DegradeTestSystemUpdateSubscriber : public NotificationSubscriber {
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

private:
    int32_t systemUpdateCount_ {0};
    sptr<NotificationClassification> lastClassification_ {nullptr};
};

// Registers the subscriber for the system update callbacks with the classification
// distribution enabled, through the manager inner entry (in memory, no IPC side paths,
// the same registration shape as the aggregation service tests).
void RegisterSystemUpdateSubscriber(const std::shared_ptr<DegradeTestSystemUpdateSubscriber> &subscriber,
    sptr<IAnsSubscriber> &listener)
{
    listener = new SubscriberListener(subscriber);
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    info->AddAppUserId(SUBSCRIBE_USER_ALL);
    info->SetSubscribedFlags(NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_SYSTEM_UPDATE);
    info->SetEnableClassification(true);
    EXPECT_EQ(NotificationSubscriberManager::GetInstance()->AddSubscriberInner(listener, info), ERR_OK);
}
} // namespace

/**
 * @tc.name: ApplyTaggingResult_00018
 * @tc.desc: Test the wholesale overwrite landing (overwrite semantics): against a cache
 *           holding an undegraded triple with the aggregation labels A1/B1, an incoming
 *           result carrying the labels A2/B2 overwrites both dimensions — the cache
 *           entry and the effective classification become the landed new value (the new
 *           labels combined with the new triple), the request type keeps the incoming
 *           one and the registration is rescheduled to the new expire time. The same
 *           wholesale overwrite happens against a KEYWORD locked cache.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00018, Function | SmallTest | Level1)
{
    std::string key = "test_key_dimension_split";
    int64_t modelTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    // Creation: the model result lands the triple with the aggregation labels A1/B1.
    auto first = manager_->ApplyTaggingResult(key, request,
        MakeTaggedClassification("A1", "B1", TYPE_URGENT, modelTime, SOURCE_AI), effective);
    EXPECT_EQ(first, ArbitrateResult::APPLY);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), modelTime);

    // Re-tagging: the repeated model result carries different aggregation labels and a
    // different triple, both dimensions overwrite the cache entry.
    request->SetInnerPriorityNotificationType(TYPE_AT_ME);
    int64_t laterTime = FutureTime(2 * ONE_HOUR_MILLIS);
    auto second = manager_->ApplyTaggingResult(key, request,
        MakeTaggedClassification("A2", "B2", TYPE_AT_ME, laterTime, SOURCE_AI), effective);

    EXPECT_EQ(second, ArbitrateResult::APPLY);
    // The landed value carries the new labels combined with the new triple.
    sptr<NotificationClassification> cached = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cached, nullptr);
    EXPECT_EQ(cached->GetClassification(), "A2");
    EXPECT_EQ(cached->GetSubClassification(), "B2");
    ExpectPriorityInfo(cached->GetPriorityInfo(), TYPE_AT_ME, laterTime, SOURCE_AI);
    ASSERT_NE(effective, nullptr);
    EXPECT_EQ(effective->GetClassification(), "A2");
    EXPECT_EQ(effective->GetSubClassification(), "B2");
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_AT_ME, laterTime, SOURCE_AI);
    // The request type keeps the incoming one (the caller write back of the accepted round).
    EXPECT_EQ(request->GetPriorityNotificationType(), TYPE_AT_ME);
    // The registration is rescheduled to the new expire time.
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), laterTime);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(1));

    // The same wholesale overwrite against a KEYWORD locked cache.
    std::string lockedKey = "test_key_dimension_split_locked";
    int64_t lockedTime = FutureTime(3 * ONE_HOUR_MILLIS);
    sptr<NotificationRequest> lockedRequest = MakeRequest(TYPE_URGENT);
    auto lockedFirst = manager_->ApplyTaggingResult(lockedKey, lockedRequest,
        MakeTaggedClassification("A1", "B1", TYPE_URGENT, lockedTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(lockedFirst, ArbitrateResult::APPLY);
    lockedRequest->SetInnerPriorityNotificationType(TYPE_AT_ME);
    int64_t lockedLaterTime = FutureTime(2 * ONE_HOUR_MILLIS);
    auto lockedSecond = manager_->ApplyTaggingResult(lockedKey, lockedRequest,
        MakeTaggedClassification("A2", "B2", TYPE_AT_ME, lockedLaterTime,
            SOURCE_KEYWORD),
        effective);
    EXPECT_EQ(lockedSecond, ArbitrateResult::APPLY);
    sptr<NotificationClassification> lockedCached =
        NotificationClassificationMgr::GetInstance().Get(lockedKey);
    ASSERT_NE(lockedCached, nullptr);
    EXPECT_EQ(lockedCached->GetClassification(), "A2");
    EXPECT_EQ(lockedCached->GetSubClassification(), "B2");
    ExpectPriorityInfo(lockedCached->GetPriorityInfo(), TYPE_AT_ME, lockedLaterTime, SOURCE_KEYWORD);
    ASSERT_NE(effective, nullptr);
    EXPECT_EQ(effective->GetClassification(), "A2");
    EXPECT_EQ(effective->GetSubClassification(), "B2");
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_AT_ME, lockedLaterTime, SOURCE_KEYWORD);
    EXPECT_EQ(lockedRequest->GetPriorityNotificationType(), TYPE_AT_ME);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(2));
}

/**
 * @tc.name: ApplyTaggingResult_00019
 * @tc.desc: Test the null round overwrite across the cache states (overwrite
 *           semantics): against a determined, a degraded terminal and an
 *           undetermined cache the null round removes the entry, forces the
 *           request type to OTHER, strips the stale registration and returns
 *           CLEARED (the clear intent took effect whatever the overwritten cache
 *           state was; the terminal entry does not survive a null round either).
 *           The effective value is null in every branch (the landed null value).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00019, Function | SmallTest | Level1)
{
    // (a) Determined cache (the row 3 state): CLEARED, the entry is removed.
    std::string lockedKey = "test_key_null_determined";
    int64_t lockedTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> lockedRequest = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto lockedFirst = manager_->ApplyTaggingResult(lockedKey, lockedRequest,
        MakeClassification(TYPE_URGENT, lockedTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(lockedFirst, ArbitrateResult::APPLY);
    lockedRequest->SetInnerPriorityNotificationType(TYPE_AT_ME);
    auto lockedSecond =
        manager_->ApplyTaggingResult(lockedKey, lockedRequest, nullptr, effective);
    EXPECT_EQ(lockedSecond, ArbitrateResult::CLEARED);
    EXPECT_EQ(lockedRequest->GetPriorityNotificationType(), TYPE_OTHER);
    EXPECT_EQ(NotificationClassificationMgr::GetInstance().Get(lockedKey), nullptr);
    EXPECT_EQ(effective, nullptr);
    // The stale registration of the overwritten triple is stripped.
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), 0);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(0));

    // (b) Degraded terminal cache (the row 6 state): CLEARED, the terminal entry
    // is removed as well.
    std::string terminalKey = "test_key_null_terminal";
    int64_t terminalTime = FutureTime(2 * ONE_HOUR_MILLIS);
    NotificationClassificationMgr::GetInstance().AddOrUpdate(
        terminalKey, MakeClassification(TYPE_OTHER, terminalTime, SOURCE_KEYWORD));
    sptr<NotificationRequest> terminalRequest = MakeRequest(TYPE_AT_ME);
    auto terminal =
        manager_->ApplyTaggingResult(terminalKey, terminalRequest, nullptr, effective);
    EXPECT_EQ(terminal, ArbitrateResult::CLEARED);
    EXPECT_EQ(terminalRequest->GetPriorityNotificationType(), TYPE_OTHER);
    EXPECT_EQ(NotificationClassificationMgr::GetInstance().Get(terminalKey), nullptr);
    EXPECT_EQ(effective, nullptr);

    // (c) Undetermined cache: the entry is removed the same way and the request type
    // is forced to OTHER (a type only update no longer survives a null round).
    std::string undeterminedKey = "test_key_null_undetermined";
    NotificationClassificationMgr::GetInstance().AddOrUpdate(
        undeterminedKey, MakeClassification(TYPE_AT_ME, 0, SOURCE_AI));
    sptr<NotificationRequest> undeterminedRequest = MakeRequest(TYPE_AT_ME);
    undeterminedRequest->SetInnerPriorityNotificationType(TYPE_URGENT);
    auto undetermined =
        manager_->ApplyTaggingResult(undeterminedKey, undeterminedRequest, nullptr, effective);
    EXPECT_EQ(undetermined, ArbitrateResult::CLEARED);
    EXPECT_EQ(undeterminedRequest->GetPriorityNotificationType(), TYPE_OTHER);
    EXPECT_EQ(NotificationClassificationMgr::GetInstance().Get(undeterminedKey), nullptr);
    EXPECT_EQ(effective, nullptr);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), 0);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(0));
}

/**
 * @tc.name: ApplyTaggingResult_00020
 * @tc.desc: Test the SEC-08 expire time horizon clamp: an incoming result whose expire
 *           time is beyond now + PRIORITY_EXPIRE_TIME_MAX_HORIZON_MS is clamped to the
 *           bound before landing, so the landed triple, the effective classification and
 *           the degrade registration all carry the clamped time (a forged extreme stays
 *           bounded instead of locking the priority state forever), while a value inside
 *           the horizon (71 hours) lands verbatim.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00020, Function | SmallTest | Level1)
{
    // Beyond the horizon: now + 144h gets clamped to now + 72h.
    std::string clampKey = "test_key_expire_clamped";
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    int64_t forgedTime = NowMillis() + 2 * PRIORITY_EXPIRE_TIME_MAX_HORIZON_MS;
    int64_t before = NowMillis();
    auto clamped = manager_->ApplyTaggingResult(clampKey, request,
        MakeClassification(TYPE_URGENT, forgedTime, SOURCE_KEYWORD), effective);
    int64_t after = NowMillis();

    EXPECT_EQ(clamped, ArbitrateResult::APPLY);
    // The clamp bound is computed inside the call, so the landed time sits between the
    // horizon offsets observed before and after the call (the production read and
    // NowMillis use the same clock source: system_clock epoch milliseconds).
    sptr<NotificationClassification> landed = NotificationClassificationMgr::GetInstance().Get(clampKey);
    ASSERT_NE(landed, nullptr);
    int64_t landedTime = landed->GetPriorityInfo().GetExpiredTime();
    EXPECT_LT(landedTime, forgedTime);
    EXPECT_GE(landedTime, before + PRIORITY_EXPIRE_TIME_MAX_HORIZON_MS);
    EXPECT_LE(landedTime, after + PRIORITY_EXPIRE_TIME_MAX_HORIZON_MS);
    ExpectPriorityInfo(landed->GetPriorityInfo(), TYPE_URGENT, landedTime, SOURCE_KEYWORD);
    // The effective value and the registration carry the clamped time as well.
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_URGENT, landedTime, SOURCE_KEYWORD);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), landedTime);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(1));

    // Inside the horizon (71h < 72h): the value lands verbatim, no clamp.
    std::string legalKey = "test_key_expire_legal";
    int64_t legalTime = NowMillis() + PRIORITY_EXPIRE_TIME_MAX_HORIZON_MS - ONE_HOUR_MILLIS;
    auto legal = manager_->ApplyTaggingResult(legalKey, request,
        MakeClassification(TYPE_SCHEDULE, legalTime, SOURCE_PARAM_IN), effective);
    EXPECT_EQ(legal, ArbitrateResult::APPLY);
    sptr<NotificationClassification> legalLanded =
        NotificationClassificationMgr::GetInstance().Get(legalKey);
    ASSERT_NE(legalLanded, nullptr);
    ExpectPriorityInfo(legalLanded->GetPriorityInfo(), TYPE_SCHEDULE, legalTime, SOURCE_PARAM_IN);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(2));
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), legalTime);
}

/**
 * @tc.name: ApplyTaggingResult_00021
 * @tc.desc: Test the rule override with a non positive new expire time (TEST-04): the
 *           rule family result fully overrides the undegraded model triple (row 4) and
 *           the registration of the key is removed instead of rescheduled, because the
 *           landed undetermined (not positive) expire time means the closed source did
 *           not hand out a validity window, so nothing is scheduled for the timer.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00021, Function | SmallTest | Level1)
{
    // Zero expire time: the model registration is removed after the override.
    std::string zeroKey = "test_key_override_zero_time";
    int64_t modelTime = FutureTime(2 * ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto model = manager_->ApplyTaggingResult(zeroKey, request,
        MakeClassification(TYPE_URGENT, modelTime, SOURCE_AI), effective);
    EXPECT_EQ(model, ArbitrateResult::APPLY);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), modelTime);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(1));

    request->SetInnerPriorityNotificationType(TYPE_SCHEDULE);
    auto overridden = manager_->ApplyTaggingResult(zeroKey, request,
        MakeClassification(TYPE_SCHEDULE, 0, SOURCE_KEYWORD), effective);
    EXPECT_EQ(overridden, ArbitrateResult::RULE_OVERRIDE);
    // The triple is fully overridden (three values) and exposed as the effective value.
    sptr<NotificationClassification> landed =
        NotificationClassificationMgr::GetInstance().Get(zeroKey);
    ASSERT_NE(landed, nullptr);
    ExpectPriorityInfo(landed->GetPriorityInfo(), TYPE_SCHEDULE, 0, SOURCE_KEYWORD);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_SCHEDULE, 0, SOURCE_KEYWORD);
    // The undetermined new expire time removes the registration: no timer entry left.
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(0));
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), 0);

    // Negative expire time (the in process .so variant of the same undetermined state).
    std::string negativeKey = "test_key_override_negative_time";
    auto negativeModel = manager_->ApplyTaggingResult(negativeKey, request,
        MakeClassification(TYPE_URGENT, modelTime, SOURCE_AI), effective);
    EXPECT_EQ(negativeModel, ArbitrateResult::APPLY);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(1));
    auto negativeOverridden = manager_->ApplyTaggingResult(negativeKey, request,
        MakeClassification(TYPE_SCHEDULE, -ONE_HOUR_MILLIS, SOURCE_PUSH_RULE), effective);
    EXPECT_EQ(negativeOverridden, ArbitrateResult::RULE_OVERRIDE);
    sptr<NotificationClassification> negativeLanded =
        NotificationClassificationMgr::GetInstance().Get(negativeKey);
    ASSERT_NE(negativeLanded, nullptr);
    ExpectPriorityInfo(negativeLanded->GetPriorityInfo(), TYPE_SCHEDULE, -ONE_HOUR_MILLIS,
        SOURCE_PUSH_RULE);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(0));
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), 0);
}

/**
 * @tc.name: ApplyTaggingResult_00022
 * @tc.desc: Test the OTHER landing normalization (terminal predicate soundness): a
 *           payload round landing type OTHER with a determined expire time is
 *           normalized to expireTime 0 (the expire time is the degrade moment and is
 *           meaningless for an already OTHER type, and the (OTHER, determined time)
 *           shape is the degrade terminal marker), so a natively tagged OTHER stays
 *           undetermined and a later priority tagging overwrites it (the OTHER to
 *           priority transition stays legal instead of being locked out as a false
 *           terminal).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00022, Function | SmallTest | Level1)
{
    std::string key = "test_key_native_other_normalized";
    sptr<NotificationRequest> request = MakeRequest(TYPE_OTHER);
    sptr<NotificationClassification> effective = nullptr;

    int64_t nativeTime = FutureTime(ONE_HOUR_MILLIS);
    auto native = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_OTHER, nativeTime, SOURCE_AI), effective);

    EXPECT_EQ(native, ArbitrateResult::APPLY);
    sptr<NotificationClassification> landed = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(landed, nullptr);
    ExpectPriorityInfo(landed->GetPriorityInfo(), TYPE_OTHER, 0, SOURCE_AI);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_OTHER, 0, SOURCE_AI);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), 0);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(0));

    request->SetInnerPriorityNotificationType(TYPE_URGENT);
    int64_t priorityTime = FutureTime(2 * ONE_HOUR_MILLIS);
    auto priority = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, priorityTime, SOURCE_KEYWORD), effective);

    EXPECT_EQ(priority, ArbitrateResult::APPLY);
    sptr<NotificationClassification> overwritten = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(overwritten, nullptr);
    ExpectPriorityInfo(overwritten->GetPriorityInfo(), TYPE_URGENT, priorityTime, SOURCE_KEYWORD);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), priorityTime);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_URGENT, priorityTime, SOURCE_KEYWORD);
}

// ===== Consistent classification retention cases (2026-10-21 rule): when the incoming
// priority type is identical to the landed cached one and the cached expire time is
// determined, the landed expire time keeps the initial cached value (the incoming source
// and the aggregation labels still land), so a repeated tagging of an unchanged
// classification never refreshes the degrade moment. =====

/**
 * @tc.name: ApplyTaggingResult_00023
 * @tc.desc: Test the consistent retention against a rule locked cache (row 8): a later
 *           model round whose type is identical to the landed rule triple keeps the
 *           initial expire time (the incoming source still lands, the aggregation
 *           labels still overwrite per the orthogonal dimensions), so the degrade
 *           moment is not refreshed and the registration is not rescheduled.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00023, Function | SmallTest | Level1)
{
    std::string key = "test_key_consistent_retention";
    int64_t initialTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    // Creation: the rule result lands the initial triple with the labels A1/B1.
    auto first = manager_->ApplyTaggingResult(key, request,
        MakeTaggedClassification("A1", "B1", TYPE_URGENT, initialTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(first, ArbitrateResult::APPLY);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), initialTime);

    // Re-tagging with the identical type: the later model round carries a later expire
    // time and different aggregation labels, but the degrade moment keeps the initial
    // value (the classification result did not change).
    int64_t laterTime = FutureTime(3 * ONE_HOUR_MILLIS);
    auto second = manager_->ApplyTaggingResult(key, request,
        MakeTaggedClassification("A2", "B2", TYPE_URGENT, laterTime, SOURCE_AI), effective);

    EXPECT_EQ(second, ArbitrateResult::APPLY);
    sptr<NotificationClassification> cached = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cached, nullptr);
    // The aggregation dimension still overwrites (orthogonal dimensions).
    EXPECT_EQ(cached->GetClassification(), "A2");
    EXPECT_EQ(cached->GetSubClassification(), "B2");
    // The type is unchanged, the expire time keeps the initial value and the source
    // takes the incoming one.
    ExpectPriorityInfo(cached->GetPriorityInfo(), TYPE_URGENT, initialTime, SOURCE_AI);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_URGENT, initialTime, SOURCE_AI);
    // The registration is not rescheduled to the later incoming time.
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), initialTime);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(1));
}

/**
 * @tc.name: ApplyTaggingResult_00024
 * @tc.desc: Test the consistent retention on the rule override row (row 9): a rule
 *           family round whose type is identical to the landed model triple keeps the
 *           initial (model landed) expire time, so the override refreshes neither the
 *           type (identical) nor the degrade moment, while the source takes the rule
 *           one and the registration is not rescheduled.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00024, Function | SmallTest | Level1)
{
    std::string key = "test_key_retention_rule_override";
    int64_t modelTime = FutureTime(2 * ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto first = manager_->ApplyTaggingResult(key, request,
        MakeClassification(TYPE_URGENT, modelTime, SOURCE_AI), effective);
    EXPECT_EQ(first, ArbitrateResult::APPLY);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), modelTime);

    // The rule family round carries the identical type with its own expire time: the
    // label is RULE_OVERRIDE but the degrade moment keeps the initial model time.
    int64_t ruleTime = FutureTime(ONE_HOUR_MILLIS);
    auto second = manager_->ApplyTaggingResult(key, request,
        MakeClassification(TYPE_URGENT, ruleTime, SOURCE_KEYWORD), effective);

    EXPECT_EQ(second, ArbitrateResult::RULE_OVERRIDE);
    sptr<NotificationClassification> landed = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(landed, nullptr);
    ExpectPriorityInfo(landed->GetPriorityInfo(), TYPE_URGENT, modelTime, SOURCE_KEYWORD);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_URGENT, modelTime, SOURCE_KEYWORD);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), modelTime);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(1));
}

/**
 * @tc.name: ApplyTaggingResult_00025
 * @tc.desc: Test the consistent retention boundary with an undetermined cached expire
 *           time (row 7): a cached triple whose expire time is not positive has no
 *           initial degrade moment to keep, so the incoming expire time lands verbatim
 *           even though the type is identical.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00025, Function | SmallTest | Level1)
{
    std::string key = "test_key_retention_undetermined";
    NotificationClassificationMgr::GetInstance().AddOrUpdate(
        key, MakeClassification(TYPE_URGENT, 0, SOURCE_KEYWORD));
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;

    int64_t expireTime = FutureTime(ONE_HOUR_MILLIS);
    auto result = manager_->ApplyTaggingResult(key, request,
        MakeClassification(TYPE_URGENT, expireTime, SOURCE_AI), effective);

    EXPECT_EQ(result, ArbitrateResult::APPLY);
    sptr<NotificationClassification> landed = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(landed, nullptr);
    ExpectPriorityInfo(landed->GetPriorityInfo(), TYPE_URGENT, expireTime, SOURCE_AI);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_URGENT, expireTime, SOURCE_AI);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), expireTime);
}

/**
 * @tc.name: ApplyTaggingResult_00026
 * @tc.desc: Test the consistent retention with an earlier incoming expire time: the
 *           retention is unconditional in the "initial value wins" direction — even an
 *           incoming expire time earlier than the initial one is discarded, the landed
 *           triple and the registration keep the initial moment.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00026, Function | SmallTest | Level1)
{
    std::string key = "test_key_retention_earlier_incoming";
    int64_t initialTime = FutureTime(2 * ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto first = manager_->ApplyTaggingResult(key, request,
        MakeClassification(TYPE_URGENT, initialTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(first, ArbitrateResult::APPLY);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), initialTime);

    int64_t earlierTime = FutureTime(ONE_HOUR_MILLIS);
    auto second = manager_->ApplyTaggingResult(key, request,
        MakeClassification(TYPE_URGENT, earlierTime, SOURCE_AI), effective);

    EXPECT_EQ(second, ArbitrateResult::APPLY);
    sptr<NotificationClassification> cached = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cached, nullptr);
    ExpectPriorityInfo(cached->GetPriorityInfo(), TYPE_URGENT, initialTime, SOURCE_AI);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_URGENT, initialTime, SOURCE_AI);
    // The registration keeps the initial (later) moment, not the earlier incoming one.
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), initialTime);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(1));
}

/**
 * @tc.name: ApplyTaggingResult_00027
 * @tc.desc: Test the consistent retention on the incoherent undetermined shape (row 7
 *           sub form): a cached triple with a determined expire time and an INVALID
 *           source is normalized to UNDETERMINED, but its expire time is still a
 *           determined initial moment, so a same type round keeps it — the retention
 *           condition does not consult the cache state normalization result.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00027, Function | SmallTest | Level1)
{
    std::string key = "test_key_retention_incoherent";
    int64_t initialTime = FutureTime(ONE_HOUR_MILLIS);
    // The incoherent shape (type != OTHER, T > 0, INVALID source): produced by the
    // parcel normalization of an out of range source or by an in process .so round
    // which filled the type and the time but left the source unset.
    NotificationClassificationMgr::GetInstance().AddOrUpdate(
        key, MakeClassification(TYPE_URGENT, initialTime, SOURCE_INVALID));
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;

    int64_t laterTime = FutureTime(3 * ONE_HOUR_MILLIS);
    auto result = manager_->ApplyTaggingResult(key, request,
        MakeClassification(TYPE_URGENT, laterTime, SOURCE_AI), effective);

    EXPECT_EQ(result, ArbitrateResult::APPLY);
    sptr<NotificationClassification> landed = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(landed, nullptr);
    // The type is unchanged, the expire time keeps the initial determined moment
    // (the incoherent shape is still a determined initial moment) and the source
    // takes the incoming one.
    ExpectPriorityInfo(landed->GetPriorityInfo(), TYPE_URGENT, initialTime, SOURCE_AI);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_URGENT, initialTime, SOURCE_AI);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), initialTime);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(1));
}

/**
 * @tc.name: ApplyTaggingResult_00028
 * @tc.desc: Test the partial round with only the priority dimension set (dimensional
 *           landing): a round carrying only the priority triple (the aggregation
 *           dimension unset, e.g. the B loop feedback of a priority rule refresh)
 *           overwrites the priority triple and reschedules, while the cached
 *           aggregation labels are kept — no empty aggregation overwrite — and the
 *           effective value exposes the merged dimensional result.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00028, Function | SmallTest | Level1)
{
    std::string key = "test_key_priority_only";
    int64_t firstTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto first = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, firstTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(first, ArbitrateResult::APPLY);

    // A priority rule refresh feeds back only the priority triple: the aggregation
    // dimension is unset, so the empty aggregation strings must not overwrite the
    // cached DEAL/LOGISTICS labels.
    request->SetInnerPriorityNotificationType(TYPE_AT_ME);
    int64_t secondTime = FutureTime(2 * ONE_HOUR_MILLIS);
    sptr<NotificationClassification> priorityOnly = new NotificationClassification();
    NotificationClassification::PriorityInfo priorityInfo;
    priorityInfo.SetPriorityNotificationType(TYPE_AT_ME);
    priorityInfo.SetExpiredTime(secondTime);
    priorityInfo.SetSource(SOURCE_AI);
    priorityOnly->SetPriorityInfo(priorityInfo);
    auto second = manager_->ApplyTaggingResult(key, request, priorityOnly, effective);

    EXPECT_EQ(second, ArbitrateResult::APPLY);
    sptr<NotificationClassification> cached = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cached, nullptr);
    ExpectPriorityInfo(cached->GetPriorityInfo(), TYPE_AT_ME, secondTime, SOURCE_AI);
    EXPECT_EQ(cached->GetClassification(), "DEAL");
    EXPECT_EQ(cached->GetSubClassification(), "LOGISTICS");
    EXPECT_EQ(cached->IsClassificationSet(), true);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), secondTime);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_AT_ME, secondTime, SOURCE_AI);
    EXPECT_EQ(effective->GetClassification(), "DEAL");
    EXPECT_EQ(effective->GetSubClassification(), "LOGISTICS");
}

/**
 * @tc.name: ApplyTaggingResult_00029
 * @tc.desc: Test the partial round with only the aggregation dimension set (dimensional
 *           landing): a round carrying only the aggregation labels (the priority
 *           dimension unset) keeps the cached triple untouched — the determined triple
 *           is not reset to the unset default, the schedule is not rescheduled and the
 *           terminal marker of a degraded cache is preserved (zero touch on the priority
 *           dimension) — while the aggregation labels land.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ApplyTaggingResult_00029, Function | SmallTest | Level1)
{
    // (a) Determined cache: the aggregation only round keeps the triple and the schedule.
    std::string key = "test_key_aggregation_only";
    int64_t firstTime = FutureTime(ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
    sptr<NotificationClassification> effective = nullptr;
    auto first = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, firstTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(first, ArbitrateResult::APPLY);

    sptr<NotificationClassification> aggregationOnly = new NotificationClassification("SHOPPING", "FOOD");
    auto second = manager_->ApplyTaggingResult(key, request, aggregationOnly, effective);

    EXPECT_EQ(second, ArbitrateResult::APPLY);
    sptr<NotificationClassification> cached = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cached, nullptr);
    ExpectPriorityInfo(cached->GetPriorityInfo(), TYPE_URGENT, firstTime, SOURCE_KEYWORD);
    EXPECT_EQ(cached->GetClassification(), "SHOPPING");
    EXPECT_EQ(cached->GetSubClassification(), "FOOD");
    EXPECT_EQ(cached->IsPriorityInfoSet(), true);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), firstTime);
    ASSERT_NE(effective, nullptr);
    ExpectPriorityInfo(effective->GetPriorityInfo(), TYPE_URGENT, firstTime, SOURCE_KEYWORD);

    // (b) Degraded terminal cache: the aggregation only round keeps the terminal triple
    // verbatim (the expire time marker is not normalized away) and nothing registers.
    std::string terminalKey = "test_key_aggregation_only_terminal";
    int64_t terminalTime = FutureTime(3 * ONE_HOUR_MILLIS);
    NotificationClassificationMgr::GetInstance().AddOrUpdate(
        terminalKey, MakeClassification(TYPE_OTHER, terminalTime, SOURCE_KEYWORD));
    sptr<NotificationClassification> terminalEffective = nullptr;
    sptr<NotificationClassification> aggregationOnlyTerminal = new NotificationClassification("SHOPPING", "FOOD");
    auto terminal = manager_->ApplyTaggingResult(
        terminalKey, request, aggregationOnlyTerminal, terminalEffective);
    EXPECT_EQ(terminal, ArbitrateResult::APPLY);
    sptr<NotificationClassification> terminalCached =
        NotificationClassificationMgr::GetInstance().Get(terminalKey);
    ASSERT_NE(terminalCached, nullptr);
    ExpectPriorityInfo(terminalCached->GetPriorityInfo(), TYPE_OTHER, terminalTime, SOURCE_KEYWORD);
    EXPECT_EQ(terminalCached->GetClassification(), "SHOPPING");
    EXPECT_EQ(terminalCached->GetSubClassification(), "FOOD");
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), firstTime);
}

/**
 * @tc.name: ProcessPriorityDegradeOnQueue_00003
 * @tc.desc: Test the FIX-5 expiry defense (LOGIC-N02-03): when the cached expire time is
 *           still in the future or undetermined (0), the queue inner degrade entry skips
 *           the terminal degrade to protect the new lifecycle (a stale dispatch must not
 *           terminally degrade a republished notification): the request and the cache
 *           stay untouched, the registration stays observable and the call returns true.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ProcessPriorityDegradeOnQueue_00003, Function | SmallTest | Level1)
{
    sptr<AdvancedNotificationService> service = AdvancedNotificationService::GetInstance();
    service->notificationList_.clear();

    // Future expire time: the cached triple belongs to a new lifecycle, skip the degrade.
    sptr<NotificationRequest> request = MakeScheduleRequest(
        "com.example.degrade.defense", 200100, 100, 5, TYPE_URGENT);
    std::string key = request->GetBaseKey("");
    int64_t futureTime = FutureTime(ONE_HOUR_MILLIS);
    NotificationClassificationMgr::GetInstance().AddOrUpdate(
        key, MakeClassification(TYPE_URGENT, futureTime, SOURCE_KEYWORD));
    PriorityNotificationDegradeManager::DegradeRecord pendingRecord;
    pendingRecord.key = key;
    pendingRecord.expiredTime = futureTime;
    manager_->degradeList_.push_back(pendingRecord);
    SeedServiceRecord(service, request);

    EXPECT_EQ(service->ProcessPriorityDegradeOnQueue(key), true);
    EXPECT_EQ(request->GetPriorityNotificationType(), TYPE_URGENT);
    sptr<NotificationClassification> cached = NotificationClassificationMgr::GetInstance().Get(key);
    ASSERT_NE(cached, nullptr);
    ExpectPriorityInfo(cached->GetPriorityInfo(), TYPE_URGENT, futureTime, SOURCE_KEYWORD);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), futureTime);

    // Undetermined expire time (0, e.g. after a policy reset): skip as well.
    sptr<NotificationRequest> resetRequest = MakeScheduleRequest(
        "com.example.degrade.defense", 200100, 100, 6, TYPE_URGENT);
    std::string resetKey = resetRequest->GetBaseKey("");
    NotificationClassificationMgr::GetInstance().AddOrUpdate(
        resetKey, MakeClassification(TYPE_URGENT, 0, SOURCE_AI));
    SeedServiceRecord(service, resetRequest);

    EXPECT_EQ(service->ProcessPriorityDegradeOnQueue(resetKey), true);
    EXPECT_EQ(resetRequest->GetPriorityNotificationType(), TYPE_URGENT);
    sptr<NotificationClassification> resetCached =
        NotificationClassificationMgr::GetInstance().Get(resetKey);
    ASSERT_NE(resetCached, nullptr);
    ExpectPriorityInfo(resetCached->GetPriorityInfo(), TYPE_URGENT, 0, SOURCE_AI);
}

/**
 * @tc.name: DegradeClassificationCache_00001
 * @tc.desc: Test the compare-and-land guard of the degrade landing (LOGIC-N02-01): the
 *           landing re-reads the cache under the manager lock and gives up when the
 *           triple no longer matches the caller's snapshot, so a stale degrade task
 *           whose snapshot was taken before a concurrent revive never overwrites the
 *           revived triple (latest-round-wins); a matching snapshot still lands the
 *           terminal shape and a concurrently cleared entry gives up as well.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, DegradeClassificationCache_00001,
    Function | SmallTest | Level1)
{
    // A matching snapshot lands the terminal shape (OTHER with the expire time kept).
    std::string matchKey = "test_key_degrade_compare_match";
    int64_t dueTime = NowMillis() - ONE_HOUR_MILLIS;
    NotificationClassificationMgr::GetInstance().AddOrUpdate(
        matchKey, MakeClassification(TYPE_URGENT, dueTime, SOURCE_AI));
    sptr<NotificationClassification> snapshot = NotificationClassificationMgr::GetInstance().Get(matchKey);
    ASSERT_NE(snapshot, nullptr);
    sptr<NotificationClassification> degraded = manager_->DegradeClassificationCache(matchKey, snapshot);
    ASSERT_NE(degraded, nullptr);
    ExpectPriorityInfo(degraded->GetPriorityInfo(), TYPE_OTHER, dueTime, SOURCE_AI);

    // A stale snapshot gives way to a newer round: the revive lands a different type
    // with a future expire time before the degrade task lands, so the compare-and-land
    // gives up and both the cache and the registration keep the revived triple.
    std::string staleKey = "test_key_degrade_compare_stale";
    NotificationClassificationMgr::GetInstance().AddOrUpdate(
        staleKey, MakeClassification(TYPE_URGENT, dueTime, SOURCE_AI));
    sptr<NotificationClassification> staleSnapshot = NotificationClassificationMgr::GetInstance().Get(staleKey);
    ASSERT_NE(staleSnapshot, nullptr);
    int64_t revivedTime = FutureTime(2 * ONE_HOUR_MILLIS);
    sptr<NotificationRequest> request = MakeRequest(TYPE_AT_ME);
    sptr<NotificationClassification> effective = nullptr;
    auto revived = manager_->ApplyTaggingResult(
        staleKey, request, MakeClassification(TYPE_AT_ME, revivedTime, SOURCE_AI), effective);
    EXPECT_EQ(revived, ArbitrateResult::APPLY);

    EXPECT_EQ(manager_->DegradeClassificationCache(staleKey, staleSnapshot), nullptr);
    sptr<NotificationClassification> landed = NotificationClassificationMgr::GetInstance().Get(staleKey);
    ASSERT_NE(landed, nullptr);
    ExpectPriorityInfo(landed->GetPriorityInfo(), TYPE_AT_ME, revivedTime, SOURCE_AI);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), revivedTime);

    // A concurrently cleared entry gives up the landing as well.
    NotificationClassificationMgr::GetInstance().Remove(staleKey);
    EXPECT_EQ(manager_->DegradeClassificationCache(staleKey, landed), nullptr);
}

/**
 * @tc.name: RemoveHook_RemoveNotificationList_00001
 * @tc.desc: Test the notification deletion cleanup hook: removing a notification record
 *           through the service removal wrapper clears the whole priority state of the
 *           key — the classification cache entry, the degrade registration (so the timer
 *           never fires for a deleted notification) and the notification list entry —
 *           keeping the registration a mirror of the cache.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, RemoveHook_RemoveNotificationList_00001,
    Function | SmallTest | Level1)
{
    sptr<AdvancedNotificationService> service = AdvancedNotificationService::GetInstance();
    service->notificationList_.clear();

    // Seed a live notification record and register a future degrade for its key
    // through the real arbitration path.
    sptr<NotificationRequest> request = MakeScheduleRequest(
        "com.example.removehook", 200100, 100, 7, TYPE_URGENT);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = new Notification(request);
    service->notificationList_.push_back(record);
    std::string key = record->notification->GetKey();
    int64_t expireTime = FutureTime(2 * ONE_HOUR_MILLIS);
    sptr<NotificationClassification> effective = nullptr;
    auto registered = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, expireTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(registered, ArbitrateResult::APPLY);
    ASSERT_NE(NotificationClassificationMgr::GetInstance().Get(key), nullptr);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), expireTime);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(1));

    service->RemoveNotificationList(record);

    EXPECT_EQ(NotificationClassificationMgr::GetInstance().Get(key), nullptr);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), 0);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(0));
    EXPECT_TRUE(service->notificationList_.empty());
}

/**
 * @tc.name: RemoveHook_RemoveFromNotificationList_00002
 * @tc.desc: Test the notification deletion cleanup hook on the core removal primitive
 *           most public cancel APIs funnel into: removing by key clears the
 *           classification cache entry, the degrade registration and the notification
 *           list entry, and reports success with the removed notification as the out
 *           parameter.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, RemoveHook_RemoveFromNotificationList_00002,
    Function | SmallTest | Level1)
{
    sptr<AdvancedNotificationService> service = AdvancedNotificationService::GetInstance();
    service->notificationList_.clear();

    sptr<NotificationRequest> request = MakeScheduleRequest(
        "com.example.removehook", 200100, 100, 8, TYPE_URGENT);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = new Notification(request);
    service->notificationList_.push_back(record);
    std::string key = record->notification->GetKey();
    int64_t expireTime = FutureTime(3 * ONE_HOUR_MILLIS);
    sptr<NotificationClassification> effective = nullptr;
    auto registered = manager_->ApplyTaggingResult(
        key, request, MakeClassification(TYPE_URGENT, expireTime, SOURCE_KEYWORD), effective);
    EXPECT_EQ(registered, ArbitrateResult::APPLY);
    ASSERT_NE(NotificationClassificationMgr::GetInstance().Get(key), nullptr);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), expireTime);

    sptr<Notification> removed = nullptr;
    auto result = service->RemoveFromNotificationList(key, removed, /*isCancel=*/true,
        NotificationConstant::APP_CANCEL_REASON_DELETE);

    EXPECT_EQ(result, ERR_OK);
    ASSERT_NE(removed, nullptr);
    EXPECT_EQ(NotificationClassificationMgr::GetInstance().Get(key), nullptr);
    EXPECT_EQ(manager_->GetEarliestExpiredTime(), 0);
    EXPECT_EQ(manager_->degradeList_.size(), static_cast<size_t>(0));
    EXPECT_TRUE(service->notificationList_.empty());
}

/**
 * @tc.name: ProcessPriorityDegrade_00002
 * @tc.desc: Test AC-004 end to end through a real subscriber (FUNC-002): on a successful
 *           degrade the SUBSCRIBE_ON_SYSTEM_UPDATE subscriber with the classification
 *           distribution enabled receives exactly one system update callback whose
 *           classification carries the degraded state (type OTHER with the expire time
 *           and the source kept), while the defensive paths (the request already OTHER
 *           without a cached classification, and a missing notification record) cause
 *           no callback at all.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ProcessPriorityDegrade_00002, Function | SmallTest | Level1)
{
    sptr<AdvancedNotificationService> service = AdvancedNotificationService::GetInstance();
    service->notificationList_.clear();
    std::shared_ptr<DegradeTestSystemUpdateSubscriber> subscriber =
        std::make_shared<DegradeTestSystemUpdateSubscriber>();
    sptr<IAnsSubscriber> listener = nullptr;
    RegisterSystemUpdateSubscriber(subscriber, listener);

    // Success scenario: a due cached triple and a live record degrade through the
    // external entry (the cross queue synchronous submit of the timer callback thread).
    sptr<NotificationRequest> request = MakeScheduleRequest(
        "com.example.degrade.callback", 200100, 100, 8, TYPE_URGENT);
    std::string key = request->GetBaseKey("");
    int64_t expireTime = NowMillis() - ONE_HOUR_MILLIS;
    NotificationClassificationMgr::GetInstance().AddOrUpdate(
        key, MakeClassification(TYPE_URGENT, expireTime, SOURCE_KEYWORD));
    SeedServiceRecord(service, request);

    EXPECT_EQ(service->ProcessPriorityDegrade(key), true);
    EXPECT_EQ(request->GetPriorityNotificationType(), TYPE_OTHER);
    NotificationSubscriberManager::GetInstance()->WaitForFfrtQueue();
    EXPECT_EQ(subscriber->GetSystemUpdateCount(), 1);
    sptr<NotificationClassification> received = subscriber->GetLastClassification();
    ASSERT_NE(received, nullptr);
    ExpectPriorityInfo(received->GetPriorityInfo(), TYPE_OTHER, expireTime, SOURCE_KEYWORD);
    EXPECT_EQ(received->GetClassification(), "DEAL");
    EXPECT_EQ(received->GetSubClassification(), "LOGISTICS");

    // Defensive scenarios: already OTHER without a cached classification (cleanup only)
    // and a missing notification record: no further callback.
    sptr<NotificationRequest> otherRequest = MakeScheduleRequest(
        "com.example.degrade.callback", 200100, 100, 9, TYPE_OTHER);
    std::string otherKey = otherRequest->GetBaseKey("");
    SeedServiceRecord(service, otherRequest);
    EXPECT_EQ(service->ProcessPriorityDegradeOnQueue(otherKey), true);
    EXPECT_EQ(service->ProcessPriorityDegradeOnQueue("test_key_degrade_callback_missing"), false);
    NotificationSubscriberManager::GetInstance()->WaitForFfrtQueue();
    EXPECT_EQ(subscriber->GetSystemUpdateCount(), 1);

    NotificationSubscriberManager::GetInstance()->RemoveSubscriberInner(listener, nullptr);
}

/**
 * @tc.name: ConcurrentAccess_00001
 * @tc.desc: Test the concurrency equivalence of the arbitration and the removal
 *           (TEST-06): two threads hammering ApplyTaggingResult (the real arbitration
 *           path) and the co-located notification deletion hooks (the classification
 *           cache removal plus the degrade registration removal) on a shared key and a
 *           different key complete without deadlock or crash (the lock order discipline
 *           DM mutex_ -> classification manager mutex and timerMutex_ -> mutex_), and
 *           the terminal state is a legal interleaving: the schedule stays ascending
 *           with at most one registration per key, the accessor agrees with the head
 *           and the un-raced key keeps its registered triple.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(PriorityNotificationDegradeManagerTest, ConcurrentAccess_00001, Function | SmallTest | Level1)
{
    const std::string sharedKey = "test_key_concurrent_shared";
    const std::string otherKey = "test_key_concurrent_other";
    const int64_t sharedTime = FutureTime(ONE_HOUR_MILLIS);
    const int64_t otherTime = FutureTime(2 * ONE_HOUR_MILLIS);
    constexpr int32_t CONCURRENT_ITERATIONS = 100;

    auto start = std::chrono::steady_clock::now();
    // Tagging thread: the real arbitration path on the shared key (racing the deletion
    // hooks) and on another key (nobody removes it: the deterministic reference state).
    std::thread taggingThread([this, &sharedKey, &otherKey, &sharedTime, &otherTime] {
        sptr<NotificationRequest> request = MakeRequest(TYPE_URGENT);
        for (int32_t i = 0; i < CONCURRENT_ITERATIONS; ++i) {
            sptr<NotificationClassification> effective = nullptr;
            manager_->ApplyTaggingResult(sharedKey, request,
                MakeClassification(TYPE_URGENT, sharedTime, SOURCE_KEYWORD), effective);
            manager_->ApplyTaggingResult(otherKey, request,
                MakeClassification(TYPE_AT_ME, otherTime, SOURCE_AI), effective);
        }
    });
    // Removal thread: mirrors the co-located deletion hooks (the classification cache
    // removal first, then the degrade registration removal, both real production paths).
    std::thread removalThread([this, &sharedKey] {
        for (int32_t i = 0; i < CONCURRENT_ITERATIONS; ++i) {
            NotificationClassificationMgr::GetInstance().Remove(sharedKey);
            manager_->Remove(sharedKey);
            manager_->Remove("test_key_concurrent_unknown");
        }
    });
    taggingThread.join();
    removalThread.join();
    auto elapsed = std::chrono::steady_clock::now() - start;
    // No deadlock: the whole concurrent phase finished well within a generous bound (a
    // lock order inversion would hang the joins forever and fail by timeout).
    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 30000);

    // The un-raced key keeps its landed triple and registration deterministically.
    sptr<NotificationClassification> otherCached =
        NotificationClassificationMgr::GetInstance().Get(otherKey);
    ASSERT_NE(otherCached, nullptr);
    ExpectPriorityInfo(otherCached->GetPriorityInfo(), TYPE_AT_ME, otherTime, SOURCE_AI);
    EXPECT_EQ(otherCached->GetClassification(), "DEAL");
    EXPECT_EQ(otherCached->GetSubClassification(), "LOGISTICS");
    int32_t sharedCount = 0;
    bool otherRegistered = false;
    int64_t previousTime = 0;
    for (const auto &record : manager_->degradeList_) {
        // The list stays ascending by the absolute expire time.
        EXPECT_GE(record.expiredTime, previousTime);
        previousTime = record.expiredTime;
        if (record.key == sharedKey) {
            sharedCount++;
            EXPECT_EQ(record.expiredTime, sharedTime);
        }
        if (record.key == otherKey) {
            otherRegistered = true;
            EXPECT_EQ(record.expiredTime, otherTime);
        }
        EXPECT_TRUE(record.key == sharedKey || record.key == otherKey);
    }
    // At most one registration per key (the schedule sync drops the previous one of the
    // key before re-registering, the removal drops all of them).
    EXPECT_LE(sharedCount, 1);
    EXPECT_TRUE(otherRegistered);
    // The accessor agrees with the list head.
    if (manager_->degradeList_.empty()) {
        EXPECT_EQ(manager_->GetEarliestExpiredTime(), 0);
    } else {
        EXPECT_EQ(manager_->GetEarliestExpiredTime(), manager_->degradeList_.front().expiredTime);
    }
    // The shared key raced the deletion hooks: the cache and the registration may or may
    // not both exist, but the cache, whenever present, holds exactly the tagged triple.
    sptr<NotificationClassification> sharedCached =
        NotificationClassificationMgr::GetInstance().Get(sharedKey);
    if (sharedCached != nullptr) {
        ExpectPriorityInfo(sharedCached->GetPriorityInfo(), TYPE_URGENT, sharedTime, SOURCE_KEYWORD);
    }
}
#endif // ANS_FEATURE_PRIORITY_NOTIFICATION
} // namespace Notification
} // namespace OHOS
