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
#include "ans_result_data_synchronizer.h"
#include "ans_ut_constant.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "iremote_object.h"
#include "mock_ipc_skeleton.h"
#include "notification_classification.h"
#include "notification_constant.h"
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
namespace {
constexpr int32_t MAX_USER_ID = 10737;
}

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
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService_->CancelAll("",
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
    }
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