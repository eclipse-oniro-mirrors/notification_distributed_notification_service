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

#include "ans_ut_constant.h"
#include "mock_ipc_skeleton.h"
#include "mock_bundle_mgr.h"
#include "mock_accesstoken_kit.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {
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
}  // namespace Notification
}  // namespace OHOS
