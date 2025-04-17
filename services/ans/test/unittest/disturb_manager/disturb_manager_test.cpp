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

#include "errors.h"
#include "notification_content.h"
#include "notification_record.h"
#include "notification_request.h"
#include <chrono>
#include <functional>
#include <gtest/gtest.h>
#include <memory>
#include <thread>

#include <vector>

#define private public

#include "accesstoken_kit.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_notification.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "disturb_manager.h"
#include "iremote_object.h"
#include "notification_preferences.h"
#include "notification_subscriber.h"
#include "notification_subscriber_manager.h"
#include "system_event_observer.h"
#include "notification_constant.h"
#include "want_agent_info.h"
#include "want_agent_helper.h"
#include "want_params.h"
#include "bundle_manager_helper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::Media;

extern void MockVerifyNativeToken(bool mockRet);
extern void MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase);
namespace OHOS {
namespace Notification {
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);
extern void MockIsVerfyPermisson(bool isVerify);

class DisturbManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp();
    void TearDown();

private:
    std::shared_ptr<DisturbManager> disturbManager_;
};

void DisturbManagerTest::SetUp()
{
    disturbManager_ = std::make_shared<DisturbManager>();
}

void DisturbManagerTest::TearDown()
{
    disturbManager_ = nullptr;
}

/**
 * @tc.number    : DisturbManagerTest_20000
 * @tc.name      : DisturbManagerTest_20000
 * @tc.desc      : Test invalid userId return ERR_ANS_INVALID_PARAM
 * @tc.require   : #I61RF2
 */
HWTEST_F(DisturbManagerTest, DisturbManagerTest_20000, Function | SmallTest | Level1)
{
    int32_t userId = -2;

    sptr<NotificationDoNotDisturbDate> date = nullptr;
    ASSERT_EQ(disturbManager_->GetDoNotDisturbDateByUserSyncQueue(userId, date), ERR_ANS_INVALID_PARAM);
    ASSERT_EQ(disturbManager_->SetDoNotDisturbDateByUserSyncQueue(userId, date), ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : DisturbManagerTest
 * @tc.name      : CheckSystemAndControllerPermission_0100
 * @tc.desc      : Test CheckSystemAndControllerPermission return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(DisturbManagerTest, CheckSystemAndControllerPermission_0100, Function | SmallTest | Level1)
{
    MockVerifyNativeToken(false);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    ASSERT_EQ(disturbManager_->CheckSystemAndControllerPermission(), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : DisturbManagerTest
 * @tc.name      : CheckSystemAndControllerPermission_0200
 * @tc.desc      : Test CheckSystemAndControllerPermission return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(DisturbManagerTest, CheckSystemAndControllerPermission_0200, Function | SmallTest | Level1)
{
    MockVerifyNativeToken(false);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    ASSERT_EQ(disturbManager_->CheckSystemAndControllerPermission(), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : DisturbManagerTest_21000
 * @tc.name    : DisturbManagerTest_21000
 * @tc.desc    : Test SetDoNotDisturbDate function and GetActiveUserId is false
 */
HWTEST_F(DisturbManagerTest, DisturbManagerTest_21000, Function | SmallTest | Level1)
{
    sptr<NotificationDoNotDisturbDate> date = nullptr;
    MockQueryForgroundOsAccountId(false, 1);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);

    ASSERT_EQ(disturbManager_->SetDoNotDisturbDate(date), ERR_ANS_GET_ACTIVE_USER_FAILED);
}

/**
 * @tc.number  : DisturbManagerTest_22000
 * @tc.name    : DisturbManagerTest_22000
 * @tc.desc    : Test GetDoNotDisturbDateSyncQueue function and GetActiveUserId is false
 */
HWTEST_F(DisturbManagerTest, DisturbManagerTest_22000, Function | SmallTest | Level1)
{
    sptr<NotificationDoNotDisturbDate> date = nullptr;
    MockQueryForgroundOsAccountId(false, 1);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);

    ASSERT_EQ(disturbManager_->GetDoNotDisturbDateSyncQueue(date), ERR_ANS_GET_ACTIVE_USER_FAILED);
}

/**
 * @tc.number    : DisturbManagerTest_03600
 * @tc.name      : ANS_AddDoNotDisturbProfiles_0100
 * @tc.desc      : Test AddDoNotDisturbProfiles function
 */
HWTEST_F(DisturbManagerTest, DisturbManagerTest_03600, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(true, 1);
    sptr<NotificationDoNotDisturbProfile> date = nullptr;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles = { date };
    auto ret = disturbManager_->AddDoNotDisturbProfilesSyncQueue(profiles);
    ASSERT_EQ(ret, (int)ERR_OK);
}


/**
 * @tc.number    : DisturbManagerTest_04200
 * @tc.name      : ANS_AddDoNotDisturbProfiles_0100
 * @tc.desc      : Test AddDoNotDisturbProfiles function
 */
HWTEST_F(DisturbManagerTest, DisturbManagerTest_04200, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(true, 1);
    sptr<NotificationDoNotDisturbProfile> date = nullptr;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles = { date };
    auto ret = disturbManager_->RemoveDoNotDisturbProfilesSyncQueue(profiles);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.number    : DisturbManagerTest_10500
 * @tc.name      : ANS_SetDisturbMode_10500
 * @tc.desc      : Test SetDisturbMode function
 */
HWTEST_F(DisturbManagerTest, DisturbManagerTest_10500, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(true, 1);
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
    ASSERT_EQ((int)disturbManager_->SetDoNotDisturbDate(date), (int)ERR_OK);

    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();
    date = new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::ONCE, beginDate, endDate);
    ASSERT_EQ((int)disturbManager_->SetDoNotDisturbDate(date), (int)ERR_OK);

    timePoint = std::chrono::system_clock::now();
    beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    endDate = endDuration.count();
    date = new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::DAILY, beginDate, endDate);
    ASSERT_EQ((int)disturbManager_->SetDoNotDisturbDate(date), (int)ERR_OK);

    timePoint = std::chrono::system_clock::now();
    beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    endDate = endDuration.count();
    date = new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::CLEARLY, beginDate, endDate);
    ASSERT_EQ((int)disturbManager_->SetDoNotDisturbDate(date), (int)ERR_OK);
}


/**
 * @tc.number    : DisturbManagerTest_10600
 * @tc.name      : ANS_GetDisturbMode_10600
 * @tc.desc      : Test GetDisturbMode function
 */
HWTEST_F(DisturbManagerTest, DisturbManagerTest_10600, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(true, 1);
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);

    ASSERT_EQ((int)disturbManager_->SetDoNotDisturbDate(date), (int)ERR_OK);

    sptr<NotificationDoNotDisturbDate> result = nullptr;
    ASSERT_EQ((int)disturbManager_->GetDoNotDisturbDateSyncQueue(result), (int)ERR_OK);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->GetDoNotDisturbType(), NotificationConstant::DoNotDisturbType::NONE);
    ASSERT_EQ(result->GetBeginDate(), 0);
    ASSERT_EQ(result->GetEndDate(), 0);
}

/**
 * @tc.number    : DisturbManagerTest_10700
 * @tc.name      : ANS_GetDisturbMode_10700
 * @tc.desc      : Test GetDisturbMode function
 */
HWTEST_F(DisturbManagerTest, DisturbManagerTest_10700, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(true, 1);
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
    ASSERT_EQ((int)disturbManager_->SetDoNotDisturbDate(date), (int)ERR_OK);

    sptr<NotificationDoNotDisturbDate> result = nullptr;
    ASSERT_EQ((int)disturbManager_->GetDoNotDisturbDateSyncQueue(result), (int)ERR_OK);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->GetDoNotDisturbType(), NotificationConstant::DoNotDisturbType::ONCE);
    ASSERT_EQ(result->GetBeginDate(), beginDate);
    ASSERT_EQ(result->GetEndDate(), endDate);
}

/**
 * @tc.number    : DisturbManagerTest_10800
 * @tc.name      : ANS_GetDisturbMode_10800
 * @tc.desc      : Test GetDisturbMode function
 */
HWTEST_F(DisturbManagerTest, DisturbManagerTest_10800, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(true, 1);
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

    ASSERT_EQ((int)disturbManager_->SetDoNotDisturbDate(date), (int)ERR_OK);
    sptr<NotificationDoNotDisturbDate> result = nullptr;
    ASSERT_EQ((int)disturbManager_->GetDoNotDisturbDateSyncQueue(result), (int)ERR_OK);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->GetDoNotDisturbType(), NotificationConstant::DoNotDisturbType::DAILY);
    ASSERT_EQ(result->GetBeginDate(), beginDate);
    ASSERT_EQ(result->GetEndDate(), endDate);
}

/**
 * @tc.number    : DisturbManagerTest_10900
 * @tc.name      : ANS_GetDisturbMode_10900
 * @tc.desc      : Test GetDisturbMode function
 */
HWTEST_F(DisturbManagerTest, DisturbManagerTest_10900, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(true, 1);
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
    ASSERT_EQ((int)disturbManager_->SetDoNotDisturbDate(date), (int)ERR_OK);

    sptr<NotificationDoNotDisturbDate> result = nullptr;
    ASSERT_EQ((int)disturbManager_->GetDoNotDisturbDateSyncQueue(result), (int)ERR_OK);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->GetDoNotDisturbType(), NotificationConstant::DoNotDisturbType::CLEARLY);
    ASSERT_EQ(result->GetBeginDate(), beginDate);
    ASSERT_EQ(result->GetEndDate(), endDate);
}

/**
 * @tc.number    : DisturbManagerTest_14200
 * @tc.name      : ANS_DoesSupportDoNotDisturbMode_0100
 * @tc.desc      : Test DoesSupportDoNotDisturbMode function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(DisturbManagerTest, DisturbManagerTest_14200, Function | SmallTest | Level1)
{
    MockVerifyNativeToken(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    bool doesSupport = true;
    ASSERT_EQ(disturbManager_->DoesSupportDoNotDisturbModeInner(doesSupport), (int)ERR_OK);
}

/**
 * @tc.number    : DisturbManagerTest_15000
 * @tc.name      : ANS_GetDoNotDisturbDateByUserSyncQueue_0100
 * @tc.desc      : Test GetDoNotDisturbDateByUserSyncQueue function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(DisturbManagerTest, DisturbManagerTest_15000, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    sptr<NotificationDoNotDisturbDate> date = nullptr;
    ASSERT_EQ(disturbManager_->GetDoNotDisturbDateByUserSyncQueue(userId, date), (int)ERR_OK);
}

/**
 * @tc.name: HandleRemoveDoNotDisturbProfiles_0100
 * @tc.desc: test HandleRemoveDoNotDisturbProfiles when ReadParcelableVector return false.
 * @tc.type: FUNC
 */
 HWTEST_F(DisturbManagerTest, HandleRemoveDoNotDisturbProfiles_0100, TestSize.Level1)
 {
     MessageParcel data;
     MessageParcel reply;
     ErrCode ret = disturbManager_->HandleRemoveDoNotDisturbProfiles(data, reply);
     EXPECT_EQ(ret, ERR_ANS_PARCELABLE_FAILED);
 }

 
/**
 * @tc.name: HandleAddDoNotDisturbProfiles_0100
 * @tc.desc: test HandleAddDoNotDisturbProfiles when ReadParcelableVector return false.
 * @tc.type: FUNC
 */
HWTEST_F(DisturbManagerTest, HandleAddDoNotDisturbProfiles_0100, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = disturbManager_->HandleAddDoNotDisturbProfiles(data, reply);
    EXPECT_EQ(ret, ERR_ANS_PARCELABLE_FAILED);
}

}
}