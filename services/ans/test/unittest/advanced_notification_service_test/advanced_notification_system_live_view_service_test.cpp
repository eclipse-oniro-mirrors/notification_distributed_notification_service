/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <unordered_map>
#include "gtest/gtest.h"

#define private public

#include "advanced_notification_service.h"
#include "ans_service_errors.h"
#include "live_publish_process.h"
#include "notification_local_live_view_subscriber.h"
#include "notification_local_live_view_subscriber_manager.h"
#include "advanced_datashare_helper.h"
#include "iremote_broker.h"
#include "notification_check_request.h"
#include "notification_constant.h"
#include "notification_content.h"
#include "nlohmann/json.hpp"
#include "os_account_manager.h"

#include "ans_ut_constant.h"
#include "mock_ipc_skeleton.h"
#include "mock_bundle_mgr.h"
#include "mock_accesstoken_kit.h"
#include "mock_notification_rdb_data_mgr.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace AccountSA {
// The real QueryActiveOsAccountIds depends on the device os_account service, which
// is not healthy on the x86 emulator. Mock it locally so the default user recovery
// deterministically enumerates one active user.
ErrCode OsAccountManager::QueryActiveOsAccountIds(std::vector<int32_t> &ids)
{
    ids = {100};
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

namespace OHOS {
namespace Notification {
namespace {
constexpr int32_t RECOVER_TEST_USER_ID = 100;
constexpr int32_t RECOVER_TEST_SECOND_USER_ID = 101;

// An expired live view row still counts as a processed recovery entry: the record is
// cleaned from DB and the batch is reported as success.
std::string BuildExpiredLiveViewRow()
{
    nlohmann::json row = {
        { "slotType", static_cast<int32_t>(NotificationConstant::SlotType::LIVE_VIEW) },
        { "notificationContentType", static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW) },
        { "updateDeadLine", 1 },
        { "finishDeadLine", 1 },
        { "triggerDeadLine", 1 },
    };
    return row.dump();
}

void SetRecoverDbRows(const std::vector<std::string> &labels)
{
    std::unordered_map<std::string, std::string> rows;
    for (const auto &label : labels) {
        rows[REQUEST_STORAGE_KEY_PREFIX + "_" + label] = BuildExpiredLiveViewRow();
    }
    MockSetDataValues(rows);
}

void ResetRecoverDbMock()
{
    std::unordered_map<std::string, std::string> emptyRows;
    MockSetDataValues(emptyRows);
    MockSetDataValue("");
    MockInit(true);
    MockQueryData(0);
    MockQueryDataBeginWithKey(true);
    MockInsertData(true);
    MockDeleteData(true);
    MockDeleteBatchData(true);
}

void WaitForRecoverQueue(const sptr<AdvancedNotificationService> &service)
{
    service->notificationSvrQueue_.SyncSubmit(std::function<void()>([] {}));
}
}  // namespace

class AdvancedNotificationSysLiveviewServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    class TestAnsSubscriber : public NotificationLocalLiveViewSubscriber {
    public:
        void OnConnected() override
        {}
        void OnDisconnected() override
        {}
        void OnDied() override
        {}
        void OnResponse(int32_t notificationId, sptr<NotificationButtonOption> buttonOption) override
        {}
    };

    static sptr<AdvancedNotificationService> advancedNotificationService_;
    static TestAnsSubscriber testAnsSubscriber_;
};

sptr<AdvancedNotificationService> AdvancedNotificationSysLiveviewServiceTest::advancedNotificationService_ = nullptr;
AdvancedNotificationSysLiveviewServiceTest::TestAnsSubscriber
    AdvancedNotificationSysLiveviewServiceTest::testAnsSubscriber_;

void AdvancedNotificationSysLiveviewServiceTest::SetUpTestCase() {}

void AdvancedNotificationSysLiveviewServiceTest::TearDownTestCase()
{
    sptr<AdvancedNotificationService> instance = AdvancedNotificationService::GetInstance();
    if (instance != nullptr) {
        instance->SelfClean(false);
    }
    BrokerRegistration &registration = BrokerRegistration::Get();
    std::lock_guard<std::mutex> lockGuard(registration.creatorMutex_);
    registration.isUnloading = true;
    registration.objects_.clear();
    registration.creators_.clear();
}

void AdvancedNotificationSysLiveviewServiceTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();

    GTEST_LOG_(INFO) << "SetUp end";
}

void AdvancedNotificationSysLiveviewServiceTest::TearDown()
{
    advancedNotificationService_ = nullptr;
    GTEST_LOG_(INFO) << "TearDown";
}

/**
 * @tc.name: GetNotificationById_100
 * @tc.desc: Test GetNotificationById when NotificationBundleOption is nullptr.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationSysLiveviewServiceTest, GetNotificationById_100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = nullptr;
    int32_t notificationId = 0;
    sptr<Notification> notification = nullptr;

    auto ret = advancedNotificationService_->GetNotificationById(bundle, notificationId, notification);

    ASSERT_EQ(ret, (int)ERR_ANS_INNER_INVALID_BUNDLE);
}

/**
 * @tc.name: GetNotificationById_200
 * @tc.desc: Test GetNotificationById when notification list is not empty and notificaiton exists.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationSysLiveviewServiceTest, GetNotificationById_200, Function | SmallTest | Level1)
{
    auto agentBundle = std::make_shared<NotificationBundleOption>(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetAgentBundle(agentBundle);
    request->SetNotificationId(0);
    sptr<NotificationBundleOption> bundle =
        new (std::nothrow) NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToNotificationList(record);
    int32_t notificationId = 0;
    sptr<Notification> notification = nullptr;

    auto ret = advancedNotificationService_->GetNotificationById(bundle, notificationId, notification);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: GetNotificationById_300
 * @tc.desc: Test GetNotificationById when notification list is not empty and notificaiton doesn't exist.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationSysLiveviewServiceTest, GetNotificationById_300, Function | SmallTest | Level1)
{
    auto agentBundle = std::make_shared<NotificationBundleOption>(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetAgentBundle(agentBundle);
    request->SetNotificationId(0);
    sptr<NotificationBundleOption> bundle =
        new (std::nothrow) NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToNotificationList(record);
    int32_t notificationId = 0;
    sptr<Notification> notification = nullptr;

    auto ret = advancedNotificationService_->GetNotificationById(bundle, notificationId, notification);

    ASSERT_EQ(ret, (int)ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.name: SubscribeLocalLiveView_100
 * @tc.desc: Test SubscribeLocalLiveView when isNative is false and caller is not subsystem or system app.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationSysLiveviewServiceTest, SubscribeLocalLiveView_100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    const sptr<IAnsSubscriberLocalLiveView> subscriber = nullptr;
    const sptr<NotificationSubscribeInfo> info = nullptr;
    const bool isNative = false;

    auto ret = advancedNotificationService_->SubscribeLocalLiveView(subscriber, info, isNative);

    ASSERT_EQ(ret, (int)ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.name: SubscribeLocalLiveView_200
 * @tc.desc: Test SubscribeLocalLiveView when isNative is false and caller is subsystem.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationSysLiveviewServiceTest, SubscribeLocalLiveView_200, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    const sptr<IAnsSubscriberLocalLiveView> subscriber = nullptr;
    const sptr<NotificationSubscribeInfo> info = nullptr;
    const bool isNative = false;

    auto ret = advancedNotificationService_->SubscribeLocalLiveView(subscriber, info, isNative);

    ASSERT_EQ(ret, (int)ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: SubscribeLocalLiveView_300
 * @tc.desc: Test SubscribeLocalLiveView with a valid subscriber and isNative reaches the live
 *           publish process null check and records the caller uid in the subscribe state map.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationSysLiveviewServiceTest, SubscribeLocalLiveView_300, Function | SmallTest | Level1)
{
    constexpr int32_t testUid = 20031001;
    IPCSkeleton::SetCallingUid(testUid);
    auto livePublishProcess = LivePublishProcess::GetInstance();
    ASSERT_NE(livePublishProcess, nullptr);
    livePublishProcess->localLiveViewSubscribedMap_.clear();

    const sptr<IAnsSubscriberLocalLiveView> subscriber = testAnsSubscriber_.GetImpl();
    ASSERT_NE(subscriber, nullptr);
    const sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    auto ret = advancedNotificationService_->SubscribeLocalLiveView(subscriber, info, true);

    EXPECT_EQ(ret, (int)ERR_OK);
    EXPECT_TRUE(livePublishProcess->GetLiveViewSubscribeState(testUid));

    NotificationLocalLiveViewSubscriberManager::GetInstance()->RemoveLocalLiveViewSubscriber(
        subscriber, nullptr);
    livePublishProcess->localLiveViewSubscribedMap_.clear();
    IPCSkeleton::SetCallingUid(1);
}

/**
 * @tc.name: RemoveSystemLiveViewNotifications_100
 * @tc.desc: Test RemoveSystemLiveViewNotifications runs the live publish process null check
 *           and erases the recorded caller uid/pid from the subscribe state map.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationSysLiveviewServiceTest, RemoveSystemLiveViewNotifications_100,
    Function | SmallTest | Level1)
{
    constexpr int32_t testUid = 20031002;
    constexpr int32_t testPid = 20031003;
    auto livePublishProcess = LivePublishProcess::GetInstance();
    ASSERT_NE(livePublishProcess, nullptr);
    livePublishProcess->localLiveViewSubscribedMap_.clear();
    livePublishProcess->AddLiveViewSubscriber(testUid, testPid);
    EXPECT_TRUE(livePublishProcess->GetLiveViewSubscribeState(testUid));

    auto ret = advancedNotificationService_->RemoveSystemLiveViewNotifications("testBundle", testUid, testPid);

    EXPECT_EQ(ret, (int)ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);
    EXPECT_FALSE(livePublishProcess->GetLiveViewSubscribeState(testUid));

    livePublishProcess->localLiveViewSubscribedMap_.clear();
}

/**
 * @tc.name: RemoveSystemLiveViewNotificationsOfSa_100
 * @tc.desc: Test RemoveSystemLiveViewNotificationsOfSa when notification create by uid exists in both
 *           notification list and delay notification list.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationSysLiveviewServiceTest, RemoveSystemLiveViewNotificationsOfSa_100,
    Function | SmallTest | Level1)
{
    int32_t uid = SYSTEM_APP_UID;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, uid);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetCreatorUid(uid);
    request->SetInProgress(true);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    sptr<NotificationRequest> request1 = new (std::nothrow) NotificationRequest();
    request1->SetCreatorUid(uid + 1);
    request1->SetInProgress(false);
    auto record1 = advancedNotificationService_->MakeNotificationRecord(request1, bundle);
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request2 = new (std::nothrow) NotificationRequest();
    request2->SetSlotType(slotType);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request2->SetContent(content);
    request2->SetCreatorUid(uid);
    request2->SetInProgress(true);
    auto record2 = advancedNotificationService_->MakeNotificationRecord(request2, bundle);

    advancedNotificationService_->AddToDelayNotificationList(record);
    advancedNotificationService_->AddToDelayNotificationList(record1);
    advancedNotificationService_->AddToNotificationList(record);
    advancedNotificationService_->AddToNotificationList(record2);

    auto ret = advancedNotificationService_->RemoveSystemLiveViewNotificationsOfSa(uid);

    auto key = record->notification->GetKey();
    ASSERT_EQ(false, advancedNotificationService_->IsNotificationExistsInDelayList(key));
    auto key2 = record2->notification->GetKey();
    ASSERT_TRUE(advancedNotificationService_->IsNotificationExists(key2));
}

/**
 * @tc.name: RecoverLiveViewIdempotent_100
 * @tc.desc: Test the same user recovers only once per process lifetime. The second round must be skipped,
 *           proved by the replay marker not being written again.
 * @tc.type: FUNC
 * @tc.require: issue#4502
 */
HWTEST_F(AdvancedNotificationSysLiveviewServiceTest, RecoverLiveViewIdempotent_100, Function | SmallTest | Level1)
{
    ResetRecoverDbMock();
    SetRecoverDbRows({"recover_once"});
    advancedNotificationService_->recoveredLiveViewUserIds_.clear();
    advancedNotificationService_->recoverReplayUserIds_.clear();

    advancedNotificationService_->RecoverLiveViewFromDb(RECOVER_TEST_USER_ID);
    WaitForRecoverQueue(advancedNotificationService_);
    EXPECT_EQ(advancedNotificationService_->recoveredLiveViewUserIds_.count(RECOVER_TEST_USER_ID), 1U);
    EXPECT_EQ(advancedNotificationService_->recoverReplayUserIds_.count(RECOVER_TEST_USER_ID), 1U);

    advancedNotificationService_->recoverReplayUserIds_.clear();
    advancedNotificationService_->RecoverLiveViewFromDb(RECOVER_TEST_USER_ID);
    WaitForRecoverQueue(advancedNotificationService_);
    EXPECT_EQ(advancedNotificationService_->recoveredLiveViewUserIds_.count(RECOVER_TEST_USER_ID), 1U);
    EXPECT_EQ(advancedNotificationService_->recoveredLiveViewUserIds_.size(), 1U);
    EXPECT_TRUE(advancedNotificationService_->recoverReplayUserIds_.empty());
    ResetRecoverDbMock();
}

/**
 * @tc.name: RecoverLiveViewIdempotent_200
 * @tc.desc: Test the default all-user recovery and a later single-user recovery are deduplicated.
 * @tc.type: FUNC
 * @tc.require: issue#4502
 */
HWTEST_F(AdvancedNotificationSysLiveviewServiceTest, RecoverLiveViewIdempotent_200, Function | SmallTest | Level1)
{
    ResetRecoverDbMock();
    SetRecoverDbRows({"recover_all_user"});
    advancedNotificationService_->recoveredLiveViewUserIds_.clear();
    advancedNotificationService_->recoverReplayUserIds_.clear();

    advancedNotificationService_->RecoverLiveViewFromDb();
    WaitForRecoverQueue(advancedNotificationService_);
    EXPECT_EQ(advancedNotificationService_->recoveredLiveViewUserIds_.count(RECOVER_TEST_USER_ID), 1U);

    advancedNotificationService_->recoverReplayUserIds_.clear();
    advancedNotificationService_->RecoverLiveViewFromDb(RECOVER_TEST_USER_ID);
    WaitForRecoverQueue(advancedNotificationService_);
    EXPECT_EQ(advancedNotificationService_->recoveredLiveViewUserIds_.count(RECOVER_TEST_USER_ID), 1U);
    EXPECT_TRUE(advancedNotificationService_->recoverReplayUserIds_.empty());
    ResetRecoverDbMock();
}

/**
 * @tc.name: RecoverLiveViewIdempotent_300
 * @tc.desc: Test users recover independently: skipping one recovered user must not affect another user.
 * @tc.type: FUNC
 * @tc.require: issue#4502
 */
HWTEST_F(AdvancedNotificationSysLiveviewServiceTest, RecoverLiveViewIdempotent_300, Function | SmallTest | Level1)
{
    ResetRecoverDbMock();
    SetRecoverDbRows({"recover_multi_user"});
    advancedNotificationService_->recoveredLiveViewUserIds_.clear();
    advancedNotificationService_->recoverReplayUserIds_.clear();

    advancedNotificationService_->RecoverLiveViewFromDb(RECOVER_TEST_USER_ID);
    WaitForRecoverQueue(advancedNotificationService_);
    advancedNotificationService_->RecoverLiveViewFromDb(RECOVER_TEST_SECOND_USER_ID);
    WaitForRecoverQueue(advancedNotificationService_);
    EXPECT_EQ(advancedNotificationService_->recoveredLiveViewUserIds_.count(RECOVER_TEST_USER_ID), 1U);
    EXPECT_EQ(advancedNotificationService_->recoveredLiveViewUserIds_.count(RECOVER_TEST_SECOND_USER_ID), 1U);

    advancedNotificationService_->recoverReplayUserIds_.clear();
    advancedNotificationService_->RecoverLiveViewFromDb(RECOVER_TEST_USER_ID);
    WaitForRecoverQueue(advancedNotificationService_);
    EXPECT_TRUE(advancedNotificationService_->recoverReplayUserIds_.empty());
    EXPECT_EQ(advancedNotificationService_->recoveredLiveViewUserIds_.size(), 2U);
    ResetRecoverDbMock();
}

/**
 * @tc.name: RecoverLiveViewIdempotent_400
 * @tc.desc: Test a failed batch DB query does not record the user as recovered, so a retry still recovers.
 * @tc.type: FUNC
 * @tc.require: issue#4502
 */
HWTEST_F(AdvancedNotificationSysLiveviewServiceTest, RecoverLiveViewIdempotent_400, Function | SmallTest | Level1)
{
    ResetRecoverDbMock();
    SetRecoverDbRows({"recover_retry"});
    advancedNotificationService_->recoveredLiveViewUserIds_.clear();
    advancedNotificationService_->recoverReplayUserIds_.clear();

    MockQueryDataBeginWithKey(false);
    advancedNotificationService_->RecoverLiveViewFromDb(RECOVER_TEST_USER_ID);
    WaitForRecoverQueue(advancedNotificationService_);
    EXPECT_EQ(advancedNotificationService_->recoveredLiveViewUserIds_.count(RECOVER_TEST_USER_ID), 0U);

    MockQueryDataBeginWithKey(true);
    advancedNotificationService_->RecoverLiveViewFromDb(RECOVER_TEST_USER_ID);
    WaitForRecoverQueue(advancedNotificationService_);
    EXPECT_EQ(advancedNotificationService_->recoveredLiveViewUserIds_.count(RECOVER_TEST_USER_ID), 1U);
    ResetRecoverDbMock();
}

/**
 * @tc.name: RecoverLiveViewIdempotent_500
 * @tc.desc: Test user stopped or removed releases the recovery state so the same user can recover again.
 * @tc.type: FUNC
 * @tc.require: issue#4502
 */
HWTEST_F(AdvancedNotificationSysLiveviewServiceTest, RecoverLiveViewIdempotent_500, Function | SmallTest | Level1)
{
    ResetRecoverDbMock();
    SetRecoverDbRows({"recover_user_lifecycle"});
    advancedNotificationService_->recoveredLiveViewUserIds_.clear();
    advancedNotificationService_->recoverReplayUserIds_.clear();

    advancedNotificationService_->RecoverLiveViewFromDb(RECOVER_TEST_USER_ID);
    WaitForRecoverQueue(advancedNotificationService_);
    ASSERT_EQ(advancedNotificationService_->recoveredLiveViewUserIds_.count(RECOVER_TEST_USER_ID), 1U);
    ASSERT_EQ(advancedNotificationService_->recoverReplayUserIds_.count(RECOVER_TEST_USER_ID), 1U);

    ResetRecoverDbMock();
    advancedNotificationService_->OnUserStopped(RECOVER_TEST_USER_ID);
    WaitForRecoverQueue(advancedNotificationService_);
    EXPECT_EQ(advancedNotificationService_->recoveredLiveViewUserIds_.count(RECOVER_TEST_USER_ID), 0U);
    EXPECT_EQ(advancedNotificationService_->recoverReplayUserIds_.count(RECOVER_TEST_USER_ID), 0U);

    SetRecoverDbRows({"recover_user_lifecycle"});
    advancedNotificationService_->RecoverLiveViewFromDb(RECOVER_TEST_USER_ID);
    WaitForRecoverQueue(advancedNotificationService_);
    EXPECT_EQ(advancedNotificationService_->recoveredLiveViewUserIds_.count(RECOVER_TEST_USER_ID), 1U);

    ResetRecoverDbMock();
    advancedNotificationService_->OnResourceRemove(RECOVER_TEST_USER_ID);
    WaitForRecoverQueue(advancedNotificationService_);
    EXPECT_EQ(advancedNotificationService_->recoveredLiveViewUserIds_.count(RECOVER_TEST_USER_ID), 0U);
    EXPECT_EQ(advancedNotificationService_->recoverReplayUserIds_.count(RECOVER_TEST_USER_ID), 0U);
    ResetRecoverDbMock();
}
}  // namespace Notification
}  // namespace OHOS
