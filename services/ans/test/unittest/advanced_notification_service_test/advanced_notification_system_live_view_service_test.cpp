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
#include "advanced_datashare_helper.h"
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
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AdvancedNotificationSysLiveviewServiceTest::advancedNotificationService_ = nullptr;

void AdvancedNotificationSysLiveviewServiceTest::SetUpTestCase() {}

void AdvancedNotificationSysLiveviewServiceTest::TearDownTestCase() {}

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

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
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

    ASSERT_EQ(ret, (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);
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

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
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

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
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