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

#include <thread>
#include "gtest/gtest.h"

#define private public

#include "advanced_notification_service.h"
#include "advanced_datashare_helper.h"
#include "notification_check_request.h"

#include "ans_ut_constant.h"
#include "mock_ipc_skeleton.h"
#include "mock_bundle_mgr.h"
#include "mock_accesstoken_kit.h"
#include "mock_time_service_client.h"
#include "mock_datashare.h"

#include "bool_wrapper.h"
#include "string_wrapper.h"
#include "mock_push_callback_stub.h"

extern void MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase);

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {

class AdvancedNotificationServiceUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AdvancedNotificationServiceUnitTest::advancedNotificationService_ = nullptr;

void AdvancedNotificationServiceUnitTest::SetUpTestCase() {}

void AdvancedNotificationServiceUnitTest::TearDownTestCase() {}

void AdvancedNotificationServiceUnitTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();

    GTEST_LOG_(INFO) << "SetUp end";
}

void AdvancedNotificationServiceUnitTest::TearDown()
{
    advancedNotificationService_ = nullptr;
    GTEST_LOG_(INFO) << "TearDown";
}

/**
 * @tc.name: PrepareNotificationRequest_100
 * @tc.desc: Test PrepareNotificationRequest when GetClientBundleName returns an empty string.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PrepareNotificationRequest_100, Function | SmallTest | Level1)
{
    MockIsNonBundleName(true);

    auto ret = advancedNotificationService_->PrepareNotificationRequest(nullptr);

    ASSERT_EQ(ret.GetErrCode(), (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: PrepareNotificationRequest_200
 * @tc.desc: Test PrepareNotificationRequest when request is nullptr.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PrepareNotificationRequest_200, Function | SmallTest | Level1)
{
    MockIsNonBundleName(false);

    auto ret = advancedNotificationService_->PrepareNotificationRequest(nullptr);

    ASSERT_EQ(ret.GetErrCode(), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: PrepareNotificationRequest_300
 * @tc.desc: Test PrepareNotificationRequest when notification is agent notification and  the caller is not subsystem
 *           or system app.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PrepareNotificationRequest_300, Function | SmallTest | Level1)
{
    MockIsNonBundleName(false);
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetIsAgentNotification(true);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);

    auto ret = advancedNotificationService_->PrepareNotificationRequest(req);

    ASSERT_EQ(ret.GetErrCode(), (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: PrepareNotificationRequest_400
 * @tc.desc: Test PrepareNotificationRequest when notification is agent notification and  the caller is without
 *           permission. This test case must be executed in the context of an application to accurately reflect
 *           the scenario, and cannot be run as a standalone sub-system.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PrepareNotificationRequest_400, Function | SmallTest | Level1)
{
    MockIsNonBundleName(false);
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetIsAgentNotification(true);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    auto ret = advancedNotificationService_->PrepareNotificationRequest(req);

    ASSERT_EQ(ret.GetErrCode(), (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: PrepareNotificationRequest_500
 * @tc.desc: Test PrepareNotificationRequest when notification is agent notification and  request's
 *           owner userId is not SUBSCRIBE_USER_INIT(-1).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PrepareNotificationRequest_500, Function | SmallTest | Level1)
{
    MockIsNonBundleName(false);
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetIsAgentNotification(true);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    req->SetOwnerUserId(0);

    auto ret = advancedNotificationService_->PrepareNotificationRequest(req);

    ASSERT_EQ(ret.GetErrCode(), (int)ERR_ANS_INVALID_UID);
}

/**
 * @tc.name: PrepareNotificationRequest_600
 * @tc.desc: Test PrepareNotificationRequest when notification is agent notification and  request's
 *           owner userId is SUBSCRIBE_USER_INIT(-1) and owner uid is less than DEFAULT_UID(0).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PrepareNotificationRequest_600, Function | SmallTest | Level1)
{
    MockIsNonBundleName(false);
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetIsAgentNotification(true);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    req->SetOwnerUserId(TEST_SUBSCRIBE_USER_INIT);
    req->SetOwnerUid(-1);

    auto ret = advancedNotificationService_->PrepareNotificationRequest(req);

    ASSERT_EQ(ret.GetErrCode(), (int)ERR_ANS_GET_ACTIVE_USER_FAILED);
}

/**
 * @tc.name: PrepareNotificationRequest_700
 * @tc.desc: Test PrepareNotificationRequest when notification is agent notification and  request's
 *           owner userId is SUBSCRIBE_USER_INIT(-1) and owner uid equals to DEFAULT_UID(0).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PrepareNotificationRequest_700, Function | SmallTest | Level1)
{
    MockIsNonBundleName(false);
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetIsAgentNotification(true);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    req->SetOwnerUserId(TEST_SUBSCRIBE_USER_INIT);
    req->SetOwnerUid(0); // DEFAULT_UID

    auto ret = advancedNotificationService_->PrepareNotificationRequest(req);

    ASSERT_EQ(ret.GetErrCode(), (int)ERR_OK);
}

/**
 * @tc.name: PrepareNotificationRequest_800
 * @tc.desc: Test PrepareNotificationRequest when notification is agent notification and  request's
 *           owner userId is not SUBSCRIBE_USER_INIT(-1) and owner uid equals to SYSTEM_APP_UID(100).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PrepareNotificationRequest_800, Function | SmallTest | Level1)
{
    MockIsNonBundleName(false);
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetIsAgentNotification(true);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    req->SetOwnerUserId(TEST_SUBSCRIBE_USER_INIT);
    req->SetOwnerUid(SYSTEM_APP_UID); // SYSTEM_APP_UID

    auto ret = advancedNotificationService_->PrepareNotificationRequest(req);

    ASSERT_EQ(ret.GetErrCode(), (int)ERR_OK);
}

/**
 * @tc.name: PrepareNotificationRequest_900
 * @tc.desc: Test PrepareNotificationRequest when notification is not agent notification and uid in
 *           bundleOption of request is less than DEFAULT_UID(0).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PrepareNotificationRequest_900, Function | SmallTest | Level1)
{
    MockIsNonBundleName(false);
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetIsAgentNotification(false);
    std::shared_ptr<NotificationBundleOption> bundleOption =
        std::make_shared<NotificationBundleOption>("bundle", -1);
    req->SetBundleOption(bundleOption);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);

    auto ret = advancedNotificationService_->PrepareNotificationRequest(req);

    ASSERT_EQ(ret.GetErrCode(), (int)ERR_ANS_INVALID_UID);
}

/**
 * @tc.name: PrepareNotificationRequest_1000
 * @tc.desc: Test PrepareNotificationRequest when notification is not agent notification and uid in
 *           bundleOption of request equals to DEFAULT_UID(0).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PrepareNotificationRequest_1000, Function | SmallTest | Level1)
{
    MockIsNonBundleName(false);
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetIsAgentNotification(false);
    std::shared_ptr<NotificationBundleOption> bundleOption =
        std::make_shared<NotificationBundleOption>("bundle", 0);
    req->SetBundleOption(bundleOption);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    req->SetOwnerUserId(0);

    auto ret = advancedNotificationService_->PrepareNotificationRequest(req);

    ASSERT_EQ(ret.GetErrCode(), (int)ERR_ANS_INVALID_UID);
}

/**
 * @tc.name: PrepareNotificationRequest_1100
 * @tc.desc: Test PrepareNotificationRequest when notification is not agent notification and uid in
 *           bundleOption of request equals to DEFAULT_UID(0).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PrepareNotificationRequest_1100, Function | SmallTest | Level1)
{
    MockIsNonBundleName(false);
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetIsAgentNotification(false);
    std::shared_ptr<NotificationBundleOption> bundleOption =
        std::make_shared<NotificationBundleOption>("bundle", SYSTEM_APP_UID);
    req->SetBundleOption(bundleOption);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    req->SetOwnerUserId(SYSTEM_APP_UID);

    auto ret = advancedNotificationService_->PrepareNotificationRequest(req);

    ASSERT_EQ(ret.GetErrCode(), (int)ERR_OK);
}

/**
 * @tc.name: PrepareNotificationRequest_1200
 * @tc.desc: Test PrepareNotificationRequest when notification is not agent notification and bundle in
 *           bundleOption of request is empty and uid in bundleOption of request equals to DEFAULT_UID(0).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PrepareNotificationRequest_1200, Function | SmallTest | Level1)
{
    MockIsNonBundleName(false);
    sptr<NotificationRequest> req = new NotificationRequest();
    req->SetIsAgentNotification(false);
    std::shared_ptr<NotificationBundleOption> bundleOption =
        std::make_shared<NotificationBundleOption>("", 0);
    req->SetBundleOption(bundleOption);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    req->SetOwnerUserId(0);

    auto ret = advancedNotificationService_->PrepareNotificationRequest(req);

    ASSERT_EQ(ret.GetErrCode(), (int)ERR_OK);
}

/**
 * @tc.name: AssignToNotificationList_100
 * @tc.desc: Test AssignToNotificationList.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, AssignToNotificationList_100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    auto ret = advancedNotificationService_->AssignToNotificationList(record);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: AssignToNotificationList_200
 * @tc.desc: Test AssignToNotificationList when NotificationRequest's updateOnly is true but notification ID not exists.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, AssignToNotificationList_200, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetUpdateOnly(true);
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    auto ret = advancedNotificationService_->AssignToNotificationList(record);

    ASSERT_EQ(ret, (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.name: AssignToNotificationList_300
 * @tc.desc: Test AssignToNotificationList when NotificationRequest's updateOnly is true and notification ID exists.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, AssignToNotificationList_300, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    auto ret = advancedNotificationService_->AssignToNotificationList(record);
    request->SetUpdateOnly(true);

    ret = advancedNotificationService_->AssignToNotificationList(record);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: AssignToNotificationList_400
 * @tc.desc: Test AssignToNotificationList when notification ID exists and notification alerts once.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, AssignToNotificationList_400, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    request->SetNotificationId(1);
    request->SetAlertOneTime(true);
    auto flags = std::make_shared<NotificationFlags>();
    request->SetFlags(flags);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    auto ret = advancedNotificationService_->AssignToNotificationList(record);

    ret = advancedNotificationService_->AssignToNotificationList(record);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: PrepareNotificationInfoTest_100
 * @tc.desc: Test PrepareNotificationInfo when request is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PrepareNotificationInfoTest_100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    auto ret = advancedNotificationService_->PrepareNotificationInfo(nullptr, bundleOption);

    ASSERT_EQ(ret.GetErrCode(), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: PrepareNotificationInfoTest_200
 * @tc.desc: Test PrepareNotificationInfo when caller is not system app
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PrepareNotificationInfoTest_200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::CUSTOM);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    auto ret = advancedNotificationService_->PrepareNotificationInfo(request, bundleOption);

    ASSERT_EQ(ret.GetErrCode(), (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: PrepareNotificationInfoTest_300
 * @tc.desc: Test PrepareNotificationInfo when PrepareNotificationRequest failed to check permission.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PrepareNotificationInfoTest_300, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetIsAgentNotification(true);
    MockIsNonBundleName(true);

    auto ret = advancedNotificationService_->PrepareNotificationInfo(request, bundleOption);

    ASSERT_EQ(ret.GetErrCode(), (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: PrepareNotificationInfoTest_400
 * @tc.desc: Test PrepareNotificationInfo when PrepareNotificationRequest failed to check permission.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PrepareNotificationInfoTest_400, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetIsAgentNotification(true);
    MockIsNonBundleName(false);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    request->SetOwnerUserId(TEST_SUBSCRIBE_USER_INIT);
    request->SetOwnerUid(0); // DEFAULT_UID

    auto ret = advancedNotificationService_->PrepareNotificationInfo(request, bundleOption);

    ASSERT_EQ(ret.GetErrCode(), (int)ERR_OK);
}

/**
 * @tc.name: PrepareNotificationInfoTest_500
 * @tc.desc: Test PrepareNotificationInfo when PrepareNotificationRequest failed to check permission.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PrepareNotificationInfoTest_500, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = nullptr;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetIsAgentNotification(false);
    std::shared_ptr<NotificationBundleOption> bundleOption =
        std::make_shared<NotificationBundleOption>("bundle", SYSTEM_APP_UID);
    request->SetBundleOption(bundleOption);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    request->SetOwnerUserId(SYSTEM_APP_UID);

    auto ret = advancedNotificationService_->PrepareNotificationInfo(request, bundle);

    ASSERT_EQ(ret.GetErrCode(), (int)ERR_OK);
}

/**
 * @tc.name: StartFinishTimer_100
 * @tc.desc: Test StartFinishTimer when Timer failed to create.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, StartFinishTimer_100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    MockCreateTimerFailed(true);

    auto ret = advancedNotificationService_->StartFinishTimer(record, duration.count(),
        NotificationConstant::TRIGGER_EIGHT_HOUR_REASON_DELETE);

    ASSERT_EQ(ret, (int)ERR_ANS_TASK_ERR);
    MockCreateTimerFailed(false);
}

/**
 * @tc.name: StartFinishTimer_200
 * @tc.desc: Test StartFinishTimer when Timer succeeded to create.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, StartFinishTimer_200, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    MockCreateTimerFailed(false);

    auto ret = advancedNotificationService_->StartFinishTimer(record, duration.count(),
        NotificationConstant::TRIGGER_EIGHT_HOUR_REASON_DELETE);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: StartUpdateTimer_100
 * @tc.desc: Test StartUpdateTimer when Timer failed to create.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, StartUpdateTimer_100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    MockCreateTimerFailed(true);

    auto ret = advancedNotificationService_->StartUpdateTimer(record, duration.count(),
        NotificationConstant::MAX_UPDATE_TIME);

    ASSERT_EQ(ret, (int)ERR_ANS_TASK_ERR);
    MockCreateTimerFailed(false);
}

/**
 * @tc.name: StartUpdateTimer_200
 * @tc.desc: Test StartUpdateTimer when Timer succeeded to create.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, StartUpdateTimer_200, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    MockCreateTimerFailed(false);

    auto ret = advancedNotificationService_->StartUpdateTimer(record, duration.count(),
        NotificationConstant::MAX_UPDATE_TIME);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: SetUpdateTimer_100
 * @tc.desc: Test SetUpdateTimer when Timer failed to create.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, SetUpdateTimer_100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    MockCreateTimerFailed(true);

    auto ret = advancedNotificationService_->SetUpdateTimer(record);

    ASSERT_EQ(ret, (int)ERR_ANS_TASK_ERR);
    MockCreateTimerFailed(false);
}

/**
 * @tc.name: SetUpdateTimer_200
 * @tc.desc: Test SetUpdateTimer when Timer succeeded to create.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, SetUpdateTimer_200, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    MockCreateTimerFailed(false);

    auto ret = advancedNotificationService_->SetUpdateTimer(record);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: StartArchiveTimer_100
 * @tc.desc: Test StartArchiveTimer when trigger auto delete at once.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, StartArchiveTimer_100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    request->SetNotificationId(1);
    request->SetAutoDeletedTime(0);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToNotificationList(record);

    advancedNotificationService_->StartArchiveTimer(record);

    ASSERT_FALSE(advancedNotificationService_->IsNotificationExists(record->notification->GetKey()));
}

/**
 * @tc.name: StartArchiveTimer_200
 * @tc.desc: Test StartArchiveTimer when timer failed to create.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, StartArchiveTimer_200, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    MockCreateTimerFailed(true);

    advancedNotificationService_->StartArchiveTimer(record);

    ASSERT_EQ(record->notification->GetArchiveTimer(), NotificationConstant::INVALID_TIMER_ID);
    MockCreateTimerFailed(false);
}

/**
 * @tc.name: StartAutoDeletedTimer_100
 * @tc.desc: Test StartAutoDeletedTimer when timer failed to create.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, StartAutoDeletedTimer_100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    MockCreateTimerFailed(true);

    auto ret = advancedNotificationService_->StartAutoDeletedTimer(record);

    ASSERT_EQ(ret, (int)ERR_ANS_TASK_ERR);
    MockCreateTimerFailed(false);
}

/**
 * @tc.name: StartAutoDeletedTimer_200
 * @tc.desc: Test StartAutoDeletedTimer when timer succeeded to create.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, StartAutoDeletedTimer_200, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    auto ret = advancedNotificationService_->StartAutoDeletedTimer(record);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: StartAutoDeletedTimer_300
 * @tc.desc: Test StartAutoDeletedTimer when timer succeeded to create and cancel origin timer.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, StartAutoDeletedTimer_300, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    record->notification->SetAutoDeletedTimer(1);

    auto ret = advancedNotificationService_->StartAutoDeletedTimer(record);
    advancedNotificationService_->TriggerAutoDelete("hashCode", 27);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: ReportDoNotDisturbModeChanged_100
 * @tc.desc: Test ReportDoNotDisturbModeChanged.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, ReportDoNotDisturbModeChanged_100, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    std::string enable = "1";

    advancedNotificationService_->ReportDoNotDisturbModeChanged(userId, enable);
    enable = "0";
    advancedNotificationService_->ReportDoNotDisturbModeChanged(userId, enable);

    ASSERT_EQ(advancedNotificationService_->doNotDisturbEnableRecord_.size(), 1);
}

/**
 * @tc.name: DoNotDisturbUpdataReminderFlags_100
 * @tc.desc: Test DoNotDisturbUpdataReminderFlags when notificationFlags is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, DoNotDisturbUpdataReminderFlags_100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    advancedNotificationService_->DoNotDisturbUpdataReminderFlags(record);

    ASSERT_EQ(record->request->GetFlags(), nullptr);
}

/**
 * @tc.name: ChangeNotificationByControlFlags_100
 * @tc.desc: Test ChangeNotificationByControlFlags when notificationFlags is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, ChangeNotificationByControlFlags_100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    advancedNotificationService_->ChangeNotificationByControlFlags(record, false);

    ASSERT_EQ(record->request->GetFlags(), nullptr);
}

/**
 * @tc.name: ChangeNotificationByControlFlagsFor3rdApp_100
 * @tc.desc: Test ChangeNotificationByControlFlagsFor3rdApp when notificationFlags is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest,
    ChangeNotificationByControlFlagsFor3rdApp_100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->ChangeNotificationByControlFlagsFor3rdApp(record);
    ASSERT_EQ(record->request->GetNotificationControlFlags(), 0);
}

/**
 * @tc.name: CheckPublishPreparedNotification_100
 * @tc.desc: Test CheckPublishPreparedNotification when notificationSvrQueue_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, CheckPublishPreparedNotification_100, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationRecord> record = nullptr;
    advancedNotificationService_->notificationSvrQueue_ = nullptr;

    auto ret = advancedNotificationService_->CheckPublishPreparedNotification(record, false);

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: CheckPublishPreparedNotification_200
 * @tc.desc: Test CheckPublishPreparedNotification when record is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, CheckPublishPreparedNotification_200, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationRecord> record = nullptr;

    auto ret = advancedNotificationService_->CheckPublishPreparedNotification(record, false);

    ASSERT_EQ(ret, (int)ERR_ANS_NO_MEMORY);
}

/**
 * @tc.name: CheckPublishPreparedNotification_300
 * @tc.desc: Test CheckPublishPreparedNotification when isSystemApp is false and slot type is
             NotificationConstant::SlotType::EMERGENCY_INFORMATION.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, CheckPublishPreparedNotification_300, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::EMERGENCY_INFORMATION);
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    auto ret = advancedNotificationService_->CheckPublishPreparedNotification(record, false);

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: ReplyDistributeOperation_100
 * @tc.desc: Test ReplyDistributeOperation when caller is not system app.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, ReplyDistributeOperation_100, Function | SmallTest | Level1)
{
    std::string hashCode;
    int32_t result = 0;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    auto ret = advancedNotificationService_->ReplyDistributeOperation(hashCode, result);

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: ReplyDistributeOperation_200
 * @tc.desc: Test ReplyDistributeOperation when caller has no permission.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, ReplyDistributeOperation_200, Function | SmallTest | Level1)
{
    std::string hashCode;
    int32_t result = 0;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    auto ret = advancedNotificationService_->ReplyDistributeOperation(hashCode, result);

    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: ReplyDistributeOperation_300
 * @tc.desc: Test ReplyDistributeOperation when hashCode is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, ReplyDistributeOperation_300, Function | SmallTest | Level1)
{
    std::string hashCode;
    int32_t result = 0;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);

    auto ret = advancedNotificationService_->ReplyDistributeOperation(hashCode, result);

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: ReplyDistributeOperation_400
 * @tc.desc: Test ReplyDistributeOperation when hashCode is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, ReplyDistributeOperation_400, Function | SmallTest | Level1)
{
    std::string hashCode = "hashCode";
    int32_t result = 0;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);

    auto ret = advancedNotificationService_->ReplyDistributeOperation(hashCode, result);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: GetNotificationRequestByHashCode_100
 * @tc.desc: Test GetNotificationRequestByHashCode when caller is not system app.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, GetNotificationRequestByHashCode_100, Function | SmallTest | Level1)
{
    std::string hashCode = "hashCode";
    sptr<NotificationRequest> request= nullptr;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    auto ret = advancedNotificationService_->GetNotificationRequestByHashCode(hashCode, request);

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: GetNotificationRequestByHashCode_200
 * @tc.desc: Test GetNotificationRequestByHashCode when caller has no permission.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, GetNotificationRequestByHashCode_200, Function | SmallTest | Level1)
{
    std::string hashCode = "hashCode";
    sptr<NotificationRequest> request= nullptr;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    auto ret = advancedNotificationService_->GetNotificationRequestByHashCode(hashCode, request);

    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: GetNotificationRequestByHashCode_300
 * @tc.desc: Test GetNotificationRequestByHashCode when notificationSvrQueue_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, GetNotificationRequestByHashCode_300, Function | SmallTest | Level1)
{
    std::string hashCode = "hashCode";
    sptr<NotificationRequest> request= nullptr;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;

    auto ret = advancedNotificationService_->GetNotificationRequestByHashCode(hashCode, request);

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetNotificationRequestByHashCode_400
 * @tc.desc: Test GetNotificationRequestByHashCode.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, GetNotificationRequestByHashCode_400, Function | SmallTest | Level1)
{
    std::string hashCode = "hashCode";
    sptr<NotificationRequest> request= nullptr;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);

    auto ret = advancedNotificationService_->GetNotificationRequestByHashCode(hashCode, request);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: QueryDoNotDisturbProfile_100
 * @tc.desc: Test QueryDoNotDisturbProfile when dataShareHelper failed to be created.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, QueryDoNotDisturbProfile_100, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    std::string enable;
    std::string profileId;
    DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->SetIsDataShareReady(true);
    MockIsFailedToCreateDataShareHelper(true);
    MockGetStringValue("1");

    advancedNotificationService_->QueryDoNotDisturbProfile(userId, enable, profileId);

    ASSERT_EQ(enable, "");
    DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->SetIsDataShareReady(false);
}

/**
 * @tc.name: QueryIntelligentExperienceEnable_100
 * @tc.desc: Test QueryIntelligentExperienceEnable when dataShareHelper failed to be created.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, QueryIntelligentExperienceEnable_100, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    std::string enable = "";
    DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->SetIsDataShareReady(true);
    MockIsFailedToCreateDataShareHelper(true);
    MockGetStringValue("1");

    advancedNotificationService_->QueryIntelligentExperienceEnable(userId, enable);

    ASSERT_EQ(enable, "");
    DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->SetIsDataShareReady(false);
}

/**
 * @tc.name: QueryDoNotDisturbProfile_200
 * @tc.desc: Test QueryDoNotDisturbProfile when dataShareHelper failed to Query.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, QueryDoNotDisturbProfile_200, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    std::string enable = "";
    std::string profileId;
    DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->SetIsDataShareReady(true);
    MockIsFailedToCreateDataShareHelper(false);
    MockIsFailedToQueryDataShareResultSet(false);
    MockGetStringValue("");
    MockIsFailedGoToFirstRow(0);

    advancedNotificationService_->QueryDoNotDisturbProfile(userId, enable, profileId);

    ASSERT_EQ(enable, "");
    DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->SetIsDataShareReady(false);
}

/**
 * @tc.name: QueryDoNotDisturbProfile_300
 * @tc.desc: Test QueryDoNotDisturbProfile when dataShareHelper succeeded to Query.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, QueryDoNotDisturbProfile_300, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    std::string enable;
    std::string profileId;
    DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->SetIsDataShareReady(true);
    DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->Init();
    MockIsFailedToCreateDataShareHelper(false);
    MockIsFailedToQueryDataShareResultSet(false);
    MockIsFailedGoToFirstRow(0);
    MockGetStringValue("1");
    for (auto dataObserver : DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->dataObservers_) {
        dataObserver.second->OnChange();
    }
    advancedNotificationService_->QueryDoNotDisturbProfile(userId, enable, profileId);

    ASSERT_EQ(enable, "1");
    DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->SetIsDataShareReady(false);
}

/**
 * @tc.name: QueryIntelligentExperienceEnable_200
 * @tc.desc: Test QueryIntelligentExperienceEnable when dataShareHelper succeeded to query.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, QueryIntelligentExperienceEnable_200, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    std::string enable = "";
    DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->SetIsDataShareReady(true);
    MockIsFailedToCreateDataShareHelper(false);
    MockIsFailedToQueryDataShareResultSet(false);
    MockIsFailedGoToFirstRow(0);
    MockGetStringValue("1"); // INTELLIGENT_EXPERIENCE

    advancedNotificationService_->QueryIntelligentExperienceEnable(userId, enable);

    ASSERT_EQ(enable, "1");
    DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->SetIsDataShareReady(false);
}

/**
 * @tc.name: CheckDoNotDisturbProfile_100
 * @tc.desc: test CheckDoNotDisturbProfile when under the DoNotDisturbMode and classification is ANS_VERIFICATION_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, CheckDoNotDisturbProfile_100, Function | SmallTest | Level1)
{
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto request = new (std::nothrow) NotificationRequest();
    request->SetNotificationControlFlags(0);
    request->SetReceiverUserId(0); // FIRST_USERID
    request->SetClassification("ANS_VERIFICATION_CODE"); // ANS_VERIFICATION_CODE
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    DelayedSingleton<AdvancedDatashareHelper>::GetInstance()->SetIsDataShareReady(true);
    MockIsFailedToCreateDataShareHelper(false);
    MockIsFailedToQueryDataShareResultSet(false);
    MockIsFailedGoToFirstRow(0);
    MockGetStringValue("1");

    advancedNotificationService_->CheckDoNotDisturbProfile(record);
    int32_t expect = (1 << 31) | (1 << 14); // CONTROL_BY_INTELLIGENT_EXPERIENCE | CONTROL_BY_DO_NOT_DISTURB_MODE
    ASSERT_EQ(record->request->GetNotificationControlFlags(), expect);
}

/**
 * @tc.name: GetNotificationKeys_100
 * @tc.desc: test GetNotificationKeys when record exists in delayNotificationList_.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, GetNotificationKeys_100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetOwnerUid(SYSTEM_APP_UID);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    std::vector<std::string> expect;
    expect.push_back(record->notification->GetKey());

    advancedNotificationService_->AddToDelayNotificationList(record);
    auto res = advancedNotificationService_->GetNotificationKeys(bundle);

    ASSERT_EQ(res, expect);
}

/**
 * @tc.name: GetNotificationKeysByBundle_100
 * @tc.desc: test GetNotificationKeysByBundle when bundleOption is nullptr and record exists in delayNotificationList_
 *           and notificationList_.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, GetNotificationKeysByBundle_100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    sptr<NotificationRequest> request1 = new (std::nothrow) NotificationRequest();
    request1->SetNotificationId(1);
    auto record1 = advancedNotificationService_->MakeNotificationRecord(request1, bundle);

    std::vector<std::string> expect;

    advancedNotificationService_->AddToNotificationList(record1);
    auto res = advancedNotificationService_->GetNotificationKeysByBundle(nullptr);

    ASSERT_EQ(res, expect);
}

/**
 * @tc.name: GetNotificationKeysByBundle_200
 * @tc.desc: test GetNotificationKeysByBundle when bundleOption is not nullptr and record exists in
 *           delayNotificationList_ and notificationList_.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, GetNotificationKeysByBundle_200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle1 = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    sptr<NotificationRequest> request1 = new (std::nothrow) NotificationRequest();
    request1->SetNotificationId(1);
    auto record1 = advancedNotificationService_->MakeNotificationRecord(request1, bundle1);

    sptr<NotificationBundleOption> bundle2 = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationRequest> request2 = new (std::nothrow) NotificationRequest();
    request2->SetNotificationId(2);
    auto record2 = advancedNotificationService_->MakeNotificationRecord(request2, bundle2);

    sptr<NotificationBundleOption> bundle3 = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationRequest> request3 = new (std::nothrow) NotificationRequest();
    request3->SetOwnerUid(NON_SYSTEM_APP_UID);
    request2->SetNotificationId(3);
    auto record3 = advancedNotificationService_->MakeNotificationRecord(request3, bundle3);

    std::vector<std::string> expect;
    expect.push_back(record2->notification->GetKey());
    expect.push_back(record3->notification->GetKey());

    advancedNotificationService_->AddToNotificationList(record1);
    advancedNotificationService_->AddToNotificationList(record2);
    advancedNotificationService_->AddToDelayNotificationList(record3);
    auto res = advancedNotificationService_->GetNotificationKeysByBundle(bundle2);

    ASSERT_EQ(res, expect);
}

/**
 * @tc.name: RemoveFromNotificationList_100
 * @tc.desc: test RemoveFromNotificationList when notification in notificationList_ is unremovable.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, RemoveFromNotificationList_100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    record->notification->SetRemoveAllowed(false);
    advancedNotificationService_->AddToNotificationList(record);
    auto bundleOption = record->bundleOption;
    NotificationKey notificationKey = {.id = request->GetNotificationId(), .label = request->GetLabel()};

    auto res = advancedNotificationService_->RemoveFromNotificationList(bundleOption, notificationKey,
        record->notification, 8, false);

    ASSERT_EQ(res, (int)ERR_ANS_NOTIFICATION_IS_UNALLOWED_REMOVEALLOWED);
}

/**
 * @tc.name: RemoveFromNotificationList_200
 * @tc.desc: test RemoveFromNotificationList when notification in notificationList_ is local liveview.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, RemoveFromNotificationList_200, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(1);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(localLiveViewContent);
    request->SetContent(content);
    int creatorUid = 1;
    request->SetCreatorUid(creatorUid);
    int ownerUid = 2;
    request->SetOwnerUid(ownerUid);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", creatorUid);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToNotificationList(record);
    auto bundleOption = record->bundleOption;
    NotificationKey notificationKey = {.id = request->GetNotificationId(), .label = request->GetLabel()};


    auto res = advancedNotificationService_->RemoveFromNotificationList(bundleOption, notificationKey,
        record->notification, 8, false);

    ASSERT_EQ(res, (int)ERR_OK);
}

/**
 * @tc.name: RemoveFromNotificationList_300
 * @tc.desc: test RemoveFromNotificationList when notification in delayNotificationList_.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, RemoveFromNotificationList_300, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToDelayNotificationList(record);
    auto bundleOption = record->bundleOption;
    NotificationKey notificationKey = {.id = request->GetNotificationId(), .label = request->GetLabel()};

    auto res = advancedNotificationService_->RemoveFromNotificationList(bundleOption, notificationKey,
        record->notification, 8, false);

    ASSERT_EQ(res, (int)ERR_OK);
}

/**
 * @tc.name: RemoveFromNotificationList_400
 * @tc.desc: test RemoveFromNotificationList when notification in notificationList_ is unremovable.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, RemoveFromNotificationList_400, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    record->notification->SetRemoveAllowed(false);
    advancedNotificationService_->AddToNotificationList(record);
    std::string key = record->notification->GetKey();

    auto res = advancedNotificationService_->RemoveFromNotificationList(key, record->notification, false, 8);

    ASSERT_EQ(res, (int)ERR_ANS_NOTIFICATION_IS_UNALLOWED_REMOVEALLOWED);
}

/**
 * @tc.name: RemoveFromNotificationListForDeleteAll_100
 * @tc.desc: test RemoveFromNotificationListForDeleteAll when notification in notificationList_ is unremovable.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, RemoveFromNotificationListForDeleteAll_100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    record->notification->SetRemoveAllowed(false);
    advancedNotificationService_->AddToNotificationList(record);
    std::string key = record->notification->GetKey();
    int32_t userId = record->notification->GetUserId();

    auto res = advancedNotificationService_->RemoveFromNotificationListForDeleteAll(key, userId, record->notification);

    ASSERT_EQ(res, (int)ERR_ANS_NOTIFICATION_IS_UNALLOWED_REMOVEALLOWED);
}

/**
 * @tc.name: RemoveFromNotificationListForDeleteAll_200
 * @tc.desc: test RemoveFromNotificationListForDeleteAll when notification in notificationList_ is unremovable.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, RemoveFromNotificationListForDeleteAll_200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    record->notification->SetRemoveAllowed(true);
    record->request->SetUnremovable(true);
    advancedNotificationService_->AddToNotificationList(record);
    std::string key = record->notification->GetKey();
    int32_t userId = record->notification->GetUserId();

    auto res = advancedNotificationService_->RemoveFromNotificationListForDeleteAll(key, userId, record->notification);

    ASSERT_EQ(res, (int)ERR_ANS_NOTIFICATION_IS_UNREMOVABLE);
}

/**
 * @tc.name: RemoveFromDelayedNotificationList_100
 * @tc.desc: test RemoveFromDelayedNotificationList when notification in delayNotificationList_.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, RemoveFromDelayedNotificationList_100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToDelayNotificationList(record);
    std::string key = record->notification->GetKey();

    auto res1 = advancedNotificationService_->RemoveFromDelayedNotificationList(key);
    auto res2 = advancedNotificationService_->RemoveFromDelayedNotificationList(key + "1");

    ASSERT_TRUE(res1);
    ASSERT_FALSE(res2);
}

/**
 * @tc.name: GetFromDelayedNotificationList_100
 * @tc.desc: test GetFromDelayedNotificationList when notification in delayNotificationList_.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, GetFromDelayedNotificationList_100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(1);
    request->SetOwnerUid(SYSTEM_APP_UID);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(localLiveViewContent);
    request->SetContent(content);
    request->SetUpdateByOwnerAllowed(true);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToDelayNotificationList(record);

    auto res1 = advancedNotificationService_->GetFromDelayedNotificationList(SYSTEM_APP_UID, 1);
    auto res2 = advancedNotificationService_->GetFromDelayedNotificationList(SYSTEM_APP_UID, 2);

    ASSERT_EQ(res1, record);
    ASSERT_EQ(res2, nullptr);
}

/**
 * @tc.name: GetAllNotificationsBySlotType_100
 * @tc.desc: test GetAllNotificationsBySlotType when caller is not subsystem and system app.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, GetAllNotificationsBySlotType_100, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    auto res = advancedNotificationService_->GetAllNotificationsBySlotType(notifications, slotType);

    ASSERT_EQ(res, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: GetAllNotificationsBySlotType_200
 * @tc.desc: test GetAllNotificationsBySlotType when caller has no permission.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, GetAllNotificationsBySlotType_200, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    auto res = advancedNotificationService_->GetAllNotificationsBySlotType(notifications, slotType);

    ASSERT_EQ(res, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: GetAllNotificationsBySlotType_300
 * @tc.desc: test GetAllNotificationsBySlotType when notificationSvrQueue_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, GetAllNotificationsBySlotType_300, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;

    auto res = advancedNotificationService_->GetAllNotificationsBySlotType(notifications, slotType);

    ASSERT_EQ(res, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetAllNotificationsBySlotType_400
 * @tc.desc: test GetAllNotificationsBySlotType.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, GetAllNotificationsBySlotType_400, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    advancedNotificationService_->notificationList_.clear();
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToNotificationList(record);

    auto res = advancedNotificationService_->GetAllNotificationsBySlotType(notifications, slotType);

    ASSERT_EQ(res, (int)ERR_OK);
    ASSERT_EQ(notifications.size(), 0);
}

/**
 * @tc.name: GetAllNotificationsBySlotType_500
 * @tc.desc: test GetAllNotificationsBySlotType.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, GetAllNotificationsBySlotType_500, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetReceiverUserId(100);
    advancedNotificationService_->notificationList_.clear();
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToNotificationList(record);

    auto res = advancedNotificationService_->GetAllNotificationsBySlotType(notifications, slotType);

    ASSERT_EQ(res, (int)ERR_OK);
    ASSERT_EQ(notifications.size(), 1);
}

/**
 * @tc.name: GetAllNotificationsBySlotType_600
 * @tc.desc: test GetAllNotificationsBySlotType when caller has no permission.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, GetAllNotificationsBySlotType_600, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(true, 100);
    std::vector<sptr<Notification>> notifications;
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    auto res = advancedNotificationService_->GetAllNotificationsBySlotType(notifications, slotType);
    ASSERT_EQ(res, (int)ERR_OK);
}

/**
 * @tc.name: GetAllNotificationsBySlotType_700
 * @tc.desc: test GetAllNotificationsBySlotType when caller has no permission.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, GetAllNotificationsBySlotType_700, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(false, 0);
    std::vector<sptr<Notification>> notifications;
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    auto res = advancedNotificationService_->GetAllNotificationsBySlotType(notifications, slotType);
    ASSERT_EQ(res, (int)ERR_ANS_GET_ACTIVE_USER_FAILED);
    MockQueryForgroundOsAccountId(true, 0);
}

/**
 * @tc.name: IsSystemUser_100
 * @tc.desc: test IsSystemUser when userId belongs to system user.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, IsSystemUser_100, Function | SmallTest | Level1)
{
    int32_t userId = 1;

    auto res = advancedNotificationService_->IsSystemUser(userId);

    ASSERT_TRUE(res);
}

/**
 * @tc.name: PublishInNotificationList_100
 * @tc.desc: test PublishInNotificationList when notifications in notificationList_ exceed MAX_ACTIVE_NUM(1000).
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PublishInNotificationList_100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = nullptr;
    sptr<NotificationRequest> request = nullptr;
    for (auto i = 0; i < MAX_ACTIVE_NUM; ++i) {
        bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE + std::to_string(i), SYSTEM_APP_UID + i);
        request = new (std::nothrow) NotificationRequest();
        request->SetNotificationId(i);
        request->SetOwnerBundleName(TEST_DEFUALT_BUNDLE + std::to_string(i));
        auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
        advancedNotificationService_->AddToNotificationList(record);
    }
    bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE + "10", SYSTEM_APP_UID + 10);
    request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(MAX_ACTIVE_NUM + 1);
    request->SetOwnerBundleName(TEST_DEFUALT_BUNDLE + "10");
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    auto res = advancedNotificationService_->PublishInNotificationList(record);

    request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(10);
    ASSERT_FALSE(advancedNotificationService_->IsNotificationExists(request->GetKey()));
}

/**
 * @tc.name: PublishInNotificationList_200
 * @tc.desc: test PublishInNotificationList when notifications in notificationList_ exceed MAX_ACTIVE_NUM(1000).
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PublishInNotificationList_200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = nullptr;
    sptr<NotificationRequest> request = nullptr;
    for (auto i = 0; i < MAX_ACTIVE_NUM; ++i) {
        bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE + std::to_string(i), SYSTEM_APP_UID + i);
        request = new (std::nothrow) NotificationRequest();
        request->SetNotificationId(i);
        request->SetOwnerBundleName(TEST_DEFUALT_BUNDLE + std::to_string(i));
        auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
        advancedNotificationService_->AddToNotificationList(record);
    }
    bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE + std::to_string(MAX_ACTIVE_NUM),
        SYSTEM_APP_UID + MAX_ACTIVE_NUM);
    request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(MAX_ACTIVE_NUM + 1);
    request->SetOwnerBundleName(TEST_DEFUALT_BUNDLE + std::to_string(MAX_ACTIVE_NUM));
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    auto res = advancedNotificationService_->PublishInNotificationList(record);

    request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(0);
    ASSERT_FALSE(advancedNotificationService_->IsNotificationExists(request->GetKey()));
}

/**
 * @tc.name: RegisterPushCallback_100
 * @tc.desc: test RegisterPushCallback when notifications in notificationList_ exceed MAX_ACTIVE_NUM(1000).
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, RegisterPushCallback_100, Function | SmallTest | Level1)
{
    sptr<IRemoteObject> pushCallback;
    sptr<NotificationCheckRequest> notificationCheckRequest;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);

    auto res = advancedNotificationService_->RegisterPushCallback(pushCallback, notificationCheckRequest);

    ASSERT_EQ(res, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: FillExtraInfoToJson_100
 * @tc.desc: test FillExtraInfoToJson when extraInfo is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, FillExtraInfoToJson_100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetExtraInfo(nullptr);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    sptr<NotificationCheckRequest> checkRequest = new (std::nothrow) NotificationCheckRequest(
        NotificationContent::Type::BASIC_TEXT,
        NotificationConstant::SlotType::SOCIAL_COMMUNICATION,
        {});
    nlohmann::json jsonObject;

    advancedNotificationService_->FillExtraInfoToJson(request, checkRequest, jsonObject);

    ASSERT_FALSE(jsonObject.contains("extraInfo"));
}

/**
 * @tc.name: FillExtraInfoToJson_200
 * @tc.desc: test FillExtraInfoToJson when extraInfo is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, FillExtraInfoToJson_200, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    extraInfo->SetParam("key1", nullptr);
    liveViewContent->SetExtraInfo(extraInfo);
    request->SetContent(content);
    sptr<NotificationCheckRequest> checkRequest = new (std::nothrow) NotificationCheckRequest(
        NotificationContent::Type::BASIC_TEXT,
        NotificationConstant::SlotType::SOCIAL_COMMUNICATION,
        {"key1", "key2"});
    nlohmann::json jsonObject;

    advancedNotificationService_->FillExtraInfoToJson(request, checkRequest, jsonObject);

    ASSERT_TRUE(jsonObject.contains("extraInfo"));
}

/**
 * @tc.name: CreatePushCheckJson_100
 * @tc.desc: test CreatePushCheckJson when notification is an agent notification.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, CreatePushCheckJson_100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    std::string bundle = "bundle";
    request->SetIsAgentNotification(true);
    request->SetOwnerBundleName(bundle);
    sptr<NotificationCheckRequest> checkRequest = nullptr;
    nlohmann::json jsonObject;

    advancedNotificationService_->CreatePushCheckJson(request, checkRequest, jsonObject);

    ASSERT_EQ(jsonObject["pkgName"], bundle);
}

/**
 * @tc.name: CreatePushCheckJson_200
 * @tc.desc: test CreatePushCheckJson when notification is not an agent notification.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, CreatePushCheckJson_200, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    std::string bundle = "bundle";
    request->SetIsAgentNotification(false);
    request->SetCreatorBundleName(bundle);
    sptr<NotificationCheckRequest> checkRequest = nullptr;
    nlohmann::json jsonObject;

    advancedNotificationService_->CreatePushCheckJson(request, checkRequest, jsonObject);

    ASSERT_EQ(jsonObject["pkgName"], bundle);
}

/**
 * @tc.name: CreatePushCheckJson_300
 * @tc.desc: test CreatePushCheckJson when notification is common liveview but
 *           not an agent notification.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, CreatePushCheckJson_300, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    std::string bundle = "bundle";
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request->SetIsAgentNotification(false);
    request->SetCreatorBundleName(bundle);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    extraInfo->SetParam("key1", nullptr);
    liveViewContent->SetExtraInfo(extraInfo);
    request->SetContent(content);
    sptr<NotificationCheckRequest> checkRequest = new (std::nothrow) NotificationCheckRequest(
        NotificationContent::Type::BASIC_TEXT,
        NotificationConstant::SlotType::SOCIAL_COMMUNICATION,
        {"key1", "key2"});
    nlohmann::json jsonObject;

    advancedNotificationService_->CreatePushCheckJson(request, checkRequest, jsonObject);

    ASSERT_EQ(jsonObject["pkgName"], bundle);
    ASSERT_TRUE(jsonObject.contains("extraInfo"));
}

/**
 * @tc.name: PushCheck_100
 * @tc.desc: test PushCheck when notification is common liveview.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, PushCheck_100, Function | SmallTest | Level1)
{
    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    sptr<IRemoteObject> pushCallback = pushCallbackProxy->AsObject();
    sptr<NotificationCheckRequest> notificationCheckRequest = new (std::nothrow)NotificationCheckRequest();
    notificationCheckRequest->SetUid(SYSTEM_APP_UID);
    notificationCheckRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    sptr<IPushCallBack> pushCallBack = iface_cast<IPushCallBack>(pushCallback);
    advancedNotificationService_->pushCallBacks_.insert_or_assign(
        notificationCheckRequest->GetSlotType(), pushCallBack);
    advancedNotificationService_->checkRequests_.insert_or_assign(
        notificationCheckRequest->GetSlotType(), notificationCheckRequest);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(1);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    sptr<AAFwk::IInterface> value = AAFwk::String::Box("EVENTS");
    extraInfo->SetParam("event", value);
    liveViewContent->SetExtraInfo(extraInfo);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetCreatorUid(NON_SYSTEM_APP_UID);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    MockOnCheckNotification(ERR_INVALID_STATE);

    auto ret = advancedNotificationService_->PushCheck(request);
    ASSERT_EQ(ret.GetErrCode(), (int)ERR_OK);

    MockIsVerfyPermisson(false);
    ret = advancedNotificationService_->PushCheck(request);
    ASSERT_EQ(ret.GetErrCode(), (int)ERR_INVALID_STATE);
    MockOnCheckNotification(ERR_OK);
}

/**
 * @tc.name: CheckSoundPermission_100
 * @tc.desc: test CheckSoundPermission when sound length exceeds maximum.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, CheckSoundPermission_100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    std::string sound = "1";
    for (int i = 0; i < 20; i++) {
        sound += sound;
    }
    sound += "."; // sound length larger than 2048
    request->SetSound(sound);
    std::string bundle = "bundle";
    int32_t uid = 10;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundle, uid);

    auto ret = advancedNotificationService_->CheckSoundPermission(request, bundleOption);

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: CheckSoundPermission_200
 * @tc.desc: test CheckSoundPermission.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, CheckSoundPermission_200, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    std::string sound = "1";
    request->SetSound(sound);
    std::string bundle = "bundle";
    int32_t uid = 10;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundle, uid);

    auto ret = advancedNotificationService_->CheckSoundPermission(request, bundleOption);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: CheckLongTermLiveView_100
 * @tc.desc: test CheckLongTermLiveView when system update only is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, CheckLongTermLiveView_100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto additionalData = std::make_shared<AAFwk::WantParams>();
    additionalData->SetParam("SYSTEM_UPDATE_ONLY", nullptr);
    request->SetAdditionalData(additionalData);

    auto ret = advancedNotificationService_->CheckLongTermLiveView(request, "");

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: CheckLongTermLiveView_200
 * @tc.desc: test CheckLongTermLiveView when notification doesn't exist.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, CheckLongTermLiveView_200, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto additionalData = std::make_shared<AAFwk::WantParams>();
    sptr<AAFwk::IInterface> value = AAFwk::Boolean::Box(true);
    additionalData->SetParam("SYSTEM_UPDATE_ONLY", value);
    request->SetAdditionalData(additionalData);

    auto ret = advancedNotificationService_->CheckLongTermLiveView(request, "");

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
/**
 * @tc.name: RegisterSwingCallback_100
 * @tc.desc: test RegisterSwingCallback when caller is not subsystem and system app.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, RegisterSwingCallback_100, Function | SmallTest | Level1)
{
    sptr<IRemoteObject> swingCallback = nullptr;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    auto ret = advancedNotificationService_->RegisterSwingCallback(swingCallback);

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: RegisterSwingCallback_200
 * @tc.desc: test RegisterSwingCallback when caller has no permission.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, RegisterSwingCallback_200, Function | SmallTest | Level1)
{
    sptr<IRemoteObject> swingCallback = nullptr;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(false);

    auto ret = advancedNotificationService_->RegisterSwingCallback(swingCallback);

    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: RegisterSwingCallback_300
 * @tc.desc: test RegisterSwingCallback when caller has no permission.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, RegisterSwingCallback_300, Function | SmallTest | Level1)
{
    sptr<IRemoteObject> swingCallback = nullptr;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);

    auto ret = advancedNotificationService_->RegisterSwingCallback(swingCallback);

    ASSERT_EQ(ret, (int)ERR_INVALID_VALUE);
}
#endif

/**
 * @tc.name: UpdateNotificationTimerByUid_100
 * @tc.desc: test UpdateNotificationTimerByUid when caller is not subsystem and system app.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, UpdateNotificationTimerByUid_100, Function | SmallTest | Level1)
{
    int32_t uid = SYSTEM_APP_UID;
    bool isPaused = false;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    auto ret = advancedNotificationService_->UpdateNotificationTimerByUid(uid, isPaused);

    ASSERT_EQ(ret, (int)ERR_ANS_NOT_SYSTEM_SERVICE);
}

/**
 * @tc.name: UpdateNotificationTimerByUid_200
 * @tc.desc: test UpdateNotificationTimerByUid when notificationSvrQueue_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, UpdateNotificationTimerByUid_200, Function | SmallTest | Level1)
{
    int32_t uid = SYSTEM_APP_UID;
    bool isPaused = false;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    IPCSkeleton::SetCallingUid(1096); // RESSCHED_UID
    advancedNotificationService_->notificationSvrQueue_ = nullptr;

    auto ret = advancedNotificationService_->UpdateNotificationTimerByUid(uid, isPaused);

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: UpdateNotificationTimerByUid_300
 * @tc.desc: test UpdateNotificationTimerByUid.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, UpdateNotificationTimerByUid_300, Function | SmallTest | Level1)
{
    int32_t uid = SYSTEM_APP_UID;
    bool isPaused = false;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    IPCSkeleton::SetCallingUid(1096); // RESSCHED_UID

    auto ret = advancedNotificationService_->UpdateNotificationTimerByUid(uid, isPaused);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: DisableNotificationFeature_100
 * @tc.desc: test DisableNotificationFeature when caller is not subsystem and system app.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, DisableNotificationFeature_100, Function | SmallTest | Level1)
{
    sptr<NotificationDisable> notificationDisable = new (std::nothrow) NotificationDisable();
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    auto ret = advancedNotificationService_->DisableNotificationFeature(notificationDisable);

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: DisableNotificationFeature_200
 * @tc.desc: test DisableNotificationFeature when caller has no permission.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, DisableNotificationFeature_200, Function | SmallTest | Level1)
{
    sptr<NotificationDisable> notificationDisable = new (std::nothrow) NotificationDisable();
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    auto ret = advancedNotificationService_->DisableNotificationFeature(notificationDisable);

    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: DisableNotificationFeature_300
 * @tc.desc: test DisableNotificationFeature when notificationSvrQueue_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, DisableNotificationFeature_300, Function | SmallTest | Level1)
{
    sptr<NotificationDisable> notificationDisable = new (std::nothrow) NotificationDisable();
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;

    auto ret = advancedNotificationService_->DisableNotificationFeature(notificationDisable);

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: DisableNotificationFeature_400
 * @tc.desc: test DisableNotificationFeature when disabiled is true.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceUnitTest, DisableNotificationFeature_400, Function | SmallTest | Level1)
{
    sptr<NotificationDisable> notificationDisable = new (std::nothrow) NotificationDisable();
    notificationDisable->SetDisabled(true);
    std::vector<std::string> bundleList = {"bundle1", "bundle2"};
    notificationDisable->SetBundleList(bundleList);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);

    auto ret = advancedNotificationService_->DisableNotificationFeature(notificationDisable);

    ASSERT_EQ(ret, (int)ERR_OK);
}
}
}
