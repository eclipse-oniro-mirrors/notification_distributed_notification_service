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
#include <memory>
#include <vector>

#include "gtest/gtest.h"

#define private public
#include "advanced_notification_service.h"
#include "ans_inner_errors.h"
#include "ans_service_errors.h"
#include "notification_preferences.h"
#include "notification_constant.h"
#include "notification_live_view_content.h"
#include "notification_request.h"
#include "notification_content.h"
#include "notification_json_convert.h"
#include "nlohmann/json.hpp"
#include "want.h"
#include "want_agent_helper.h"
#include "accesstoken_kit.h"
#include "aes_gcm_helper.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);

constexpr int32_t TEST_CREATOR_UID = 100;
constexpr int32_t TEST_NOTIFICATION_ID = 1;
constexpr int64_t TEST_FUTURE_OFFSET_MS = 3600 * 1000;
constexpr int64_t TEST_PAST_OFFSET_MS = 1000;

class AnsLiveViewRecoveryBranchTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp();
    void TearDown();

private:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AnsLiveViewRecoveryBranchTest::advancedNotificationService_ = nullptr;

void AnsLiveViewRecoveryBranchTest::SetUp()
{
    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
    NotificationPreferences::GetInstance()->DeleteKvFromDb("ans_recover_fail_count", TEST_CREATOR_UID);
    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
    ASSERT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->CancelAll("");
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
}

void AnsLiveViewRecoveryBranchTest::TearDown()
{
    delete advancedNotificationService_;
    advancedNotificationService_ = nullptr;
}

static int32_t SetRawLiveViewRecordToDb(const std::string &secureKey, const std::string &plainValue,
    int32_t userId)
{
    std::string encryptValue;
    int32_t encryptRet = AesGcmHelper::Encrypt(plainValue, encryptValue);
    if (encryptRet != ERR_OK) {
        return encryptRet;
    }
    return NotificationPreferences::GetInstance()->SetKvToDb(secureKey, encryptValue, userId);
}

static bool LiveViewKvExists(const std::string &key, int32_t userId)
{
    std::string value;
    return NotificationPreferences::GetInstance()->GetKvFromDb(key, value, userId) == ERR_OK;
}

static sptr<NotificationRequest> BuildRecoverableLiveViewRequest(int32_t userId, const std::string &label)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request->SetNotificationId(TEST_NOTIFICATION_ID);
    request->SetLabel(label);
    request->SetCreatorUid(TEST_CREATOR_UID);
    request->SetCreatorUserId(TEST_CREATOR_UID);
    request->SetReceiverUserId(userId);
    request->SetCreatorBundleName("recover_test");
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    liveContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW));
    request->SetContent(std::make_shared<NotificationContent>(liveContent));
    auto epoch = std::chrono::system_clock::now().time_since_epoch();
    auto curTime = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    int64_t futureTime = curTime + TEST_FUTURE_OFFSET_MS;
    request->SetUpdateDeadLine(futureTime);
    request->SetFinishDeadLine(futureTime);
    return request;
}

static sptr<NotificationRequest> WriteLiveViewRowWithOverrides(int32_t userId, const std::string &label,
    const nlohmann::json &overrides)
{
    sptr<NotificationRequest> request = BuildRecoverableLiveViewRequest(userId, label);
    if (request == nullptr) {
        return nullptr;
    }
    nlohmann::json jsonObject;
    if (!NotificationJsonConverter::ConvertToJson(request, jsonObject)) {
        return nullptr;
    }
    jsonObject["wantAgent"] = "";
    jsonObject["removalWantAgent"] = "";
    for (const auto &item : overrides.items()) {
        if (item.value().is_null()) {
            jsonObject.erase(item.key());
        } else {
            jsonObject[item.key()] = item.value();
        }
    }
    if (SetRawLiveViewRecordToDb(request->GetSecureKey(), jsonObject.dump(), userId) != ERR_OK) {
        return nullptr;
    }
    return request;
}

static std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> CreateLiveViewTestWantAgent()
{
    AAFwk::Want want;
    want.SetBundle("com.ohos.launcher");
    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    wants.push_back(std::make_shared<AAFwk::Want>(want));
    std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> flags;
    AbilityRuntime::WantAgent::WantAgentInfo info(TEST_CREATOR_UID,
        AbilityRuntime::WantAgent::WantAgentConstant::OperationType::START_ABILITY, flags, wants, nullptr);
    return AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(info);
}


/**
 * @tc.name: LiveViewLegacyPlainKeyCleanupTest001
 * @tc.desc: Test a legacy plain-key row (ans_live_view_*) is deleted with all related keys (AC-1.2)
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewRecoveryBranchTest, LiveViewLegacyPlainKeyCleanupTest001, Function | SmallTest | Level1)
{
    int32_t userId = TEST_CREATOR_UID;
    sptr<NotificationRequest> request = BuildRecoverableLiveViewRequest(userId, "legacy_plain_row");
    ASSERT_NE(request, nullptr);
    ASSERT_EQ(NotificationPreferences::GetInstance()->SetKvToDb(
        request->GetKey(), "not-a-json", userId), ERR_OK);

    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    (void)advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsdb, userId);
    ASSERT_EQ(requestsdb.size(), 0);
    ASSERT_FALSE(LiveViewKvExists(request->GetKey(), userId));
    ASSERT_FALSE(LiveViewKvExists(request->GetSecureKey(), userId));
    ASSERT_FALSE(LiveViewKvExists("lock_screen_picture" + request->GetKey(), userId));
}

/**
 * @tc.name: LiveViewDecryptFailureCleanupTest001
 * @tc.desc: Test a secure row that cannot be decrypted is removed (AC-1.2)
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewRecoveryBranchTest, LiveViewDecryptFailureCleanupTest001, Function | SmallTest | Level1)
{
    int32_t userId = TEST_CREATOR_UID;
    sptr<NotificationRequest> request = BuildRecoverableLiveViewRequest(userId, "decrypt_fail_row");
    ASSERT_NE(request, nullptr);
    ASSERT_EQ(NotificationPreferences::GetInstance()->SetKvToDb(
        request->GetSecureKey(), "garbage-not-encrypted", userId), ERR_OK);

    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    (void)advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsdb, userId);
    ASSERT_EQ(requestsdb.size(), 0);
    ASSERT_FALSE(LiveViewKvExists(request->GetSecureKey(), userId));
}

/**
 * @tc.name: LiveViewExpiredPlainKeyTest001
 * @tc.desc: Test an expired legacy plain-key row reports its base key (AC-2.1)
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewRecoveryBranchTest, LiveViewExpiredPlainKeyTest001, Function | SmallTest | Level1)
{
    int32_t userId = TEST_CREATOR_UID;
    sptr<NotificationRequest> request = BuildRecoverableLiveViewRequest(userId, "expired_plain_row");
    ASSERT_NE(request, nullptr);
    nlohmann::json jsonObject;
    ASSERT_TRUE(NotificationJsonConverter::ConvertToJson(request, jsonObject));
    jsonObject["wantAgent"] = "";
    auto epoch = std::chrono::system_clock::now().time_since_epoch();
    auto curTime = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    jsonObject["updateDeadLine"] = curTime - TEST_PAST_OFFSET_MS;
    jsonObject["finishDeadLine"] = curTime - TEST_PAST_OFFSET_MS;
    ASSERT_EQ(NotificationPreferences::GetInstance()->SetKvToDb(
        request->GetKey(), jsonObject.dump(), userId), ERR_OK);

    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    std::vector<std::string> removedBaseKeys;
    (void)advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsdb, userId, &removedBaseKeys);
    ASSERT_EQ(requestsdb.size(), 0);
    ASSERT_EQ(removedBaseKeys.size(), 1);
    ASSERT_EQ(removedBaseKeys[0], request->GetBaseKey(""));
    ASSERT_FALSE(LiveViewKvExists(request->GetKey(), userId));
    ASSERT_FALSE(LiveViewKvExists(request->GetSecureKey(), userId));
}

/**
 * @tc.name: LiveViewExpiryMatrixTest001
 * @tc.desc: Test the three-deadline expiry predicate branches (AC-2.1/AC-2.3)
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewRecoveryBranchTest, LiveViewExpiryMatrixTest001, Function | SmallTest | Level1)
{
    int32_t userId = TEST_CREATOR_UID;
    auto epoch = std::chrono::system_clock::now().time_since_epoch();
    auto curTime = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    int64_t pastTime = curTime - TEST_PAST_OFFSET_MS;
    int64_t futureTime = curTime + TEST_FUTURE_OFFSET_MS;
    struct ExpiryCase {
        std::string label;
        nlohmann::json overrides;
        bool deleted;
    };
    std::vector<ExpiryCase> cases = {
        {"expire_update", {{"updateDeadLine", pastTime}, {"finishDeadLine", futureTime},
            {"triggerDeadLine", nullptr}}, true},
        {"expire_finish", {{"updateDeadLine", futureTime}, {"finishDeadLine", pastTime},
            {"triggerDeadLine", nullptr}}, true},
        {"expire_trigger", {{"updateDeadLine", futureTime}, {"finishDeadLine", futureTime},
            {"triggerDeadLine", pastTime}}, true},
        {"keep_trigger_future", {{"updateDeadLine", futureTime}, {"finishDeadLine", futureTime},
            {"triggerDeadLine", futureTime}}, false},
        {"expire_no_deadline", {{"updateDeadLine", nullptr}, {"finishDeadLine", nullptr},
            {"triggerDeadLine", nullptr}}, true},
        {"expire_string_deadline", {{"updateDeadLine", "invalid"}, {"finishDeadLine", nullptr},
            {"triggerDeadLine", nullptr}}, true},
    };
    for (const auto &expiryCase : cases) {
        sptr<NotificationRequest> request = WriteLiveViewRowWithOverrides(userId, expiryCase.label,
            expiryCase.overrides);
        ASSERT_NE(request, nullptr);
        std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
        (void)advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsdb, userId);
        if (expiryCase.deleted) {
            EXPECT_EQ(requestsdb.size(), 0) << expiryCase.label;
            EXPECT_FALSE(LiveViewKvExists(request->GetSecureKey(), userId)) << expiryCase.label;
        } else {
            EXPECT_EQ(requestsdb.size(), 1) << expiryCase.label;
            NotificationPreferences::GetInstance()->DeleteKvFromDb(request->GetSecureKey(), userId);
        }
    }
}

/**
 * @tc.name: LiveViewExpiryGateTest001
 * @tc.desc: Test non-live-view rows skip the two-phase expiry check (AC-2.1 gate branches)
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewRecoveryBranchTest, LiveViewExpiryGateTest001, Function | SmallTest | Level1)
{
    int32_t userId = TEST_CREATOR_UID;
    auto epoch = std::chrono::system_clock::now().time_since_epoch();
    auto curTime = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    int64_t pastTime = curTime - TEST_PAST_OFFSET_MS;
    auto checkKept = [this, userId](sptr<NotificationRequest> request) {
        EXPECT_NE(request, nullptr);
        std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
        (void)advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsdb, userId);
        EXPECT_EQ(requestsdb.size(), 1);
        NotificationPreferences::GetInstance()->DeleteKvFromDb(request->GetSecureKey(), userId);
    };

    sptr<NotificationRequest> slotRequest = WriteLiveViewRowWithOverrides(userId, "gate_slot_mismatch",
        {{"slotType", static_cast<int32_t>(NotificationConstant::SlotType::SOCIAL_COMMUNICATION)},
        {"updateDeadLine", pastTime}, {"finishDeadLine", pastTime}});
    checkKept(slotRequest);

    sptr<NotificationRequest> contentTypeRequest = WriteLiveViewRowWithOverrides(userId,
        "gate_content_type_mismatch",
        {{"notificationContentType", static_cast<int32_t>(NotificationContent::Type::BASIC_TEXT)},
        {"updateDeadLine", pastTime}, {"finishDeadLine", pastTime}});
    checkKept(contentTypeRequest);
}

/**
 * @tc.name: LiveViewValidWantAgentKeptTest001
 * @tc.desc: Test a parseable WantAgent keeps the row (AC-1.1 negative branch)
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewRecoveryBranchTest, LiveViewValidWantAgentKeptTest001, Function | SmallTest | Level1)
{
    int32_t userId = TEST_CREATOR_UID;
    auto agent = CreateLiveViewTestWantAgent();
    if (agent == nullptr) {
        GTEST_SKIP() << "WantAgent is unavailable in this test environment";
    }
    sptr<NotificationRequest> request = BuildRecoverableLiveViewRequest(userId, "valid_agent_row");
    ASSERT_NE(request, nullptr);
    nlohmann::json jsonObject;
    ASSERT_TRUE(NotificationJsonConverter::ConvertToJson(request, jsonObject));
    jsonObject["wantAgent"] = AbilityRuntime::WantAgent::WantAgentHelper::ToStringWithEnvelope(agent);
    ASSERT_EQ(SetRawLiveViewRecordToDb(request->GetSecureKey(), jsonObject.dump(), userId), ERR_OK);

    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    ASSERT_EQ(advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsdb, userId), ERR_OK);
    ASSERT_EQ(requestsdb.size(), 1);
    ASSERT_EQ(requestsdb[0].request->GetLabel(), "valid_agent_row");
    NotificationPreferences::GetInstance()->DeleteKvFromDb(request->GetSecureKey(), userId);
}

}  // namespace Notification
}  // namespace OHOS
