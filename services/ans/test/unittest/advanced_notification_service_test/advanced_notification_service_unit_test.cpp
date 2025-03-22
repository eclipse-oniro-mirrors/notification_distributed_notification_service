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

#include "ans_ut_constant.h"
#include "mock_ipc_skeleton.h"
#include "mock_bundle_mgr.h"
#include "mock_accesstoken_kit.h"
#include "mock_time_service_client.h"

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

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
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

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
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

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
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

    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
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

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_UID);
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

    ASSERT_EQ(ret, (int)ERR_ANS_GET_ACTIVE_USER_FAILED);
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

    ASSERT_EQ(ret, (int)ERR_OK);
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

    ASSERT_EQ(ret, (int)ERR_OK);
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

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_UID);
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

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_UID);
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

    ASSERT_EQ(ret, (int)ERR_OK);
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

    ASSERT_EQ(ret, (int)ERR_OK);
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

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
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

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
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

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
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

    ASSERT_EQ(ret, (int)ERR_OK);
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

    ASSERT_EQ(ret, (int)ERR_OK);
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
}
}