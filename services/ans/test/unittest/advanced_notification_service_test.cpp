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

#include "notification_content.h"
#include "notification_record.h"
#include <chrono>
#include <functional>
#include <memory>
#include <thread>

#include "gtest/gtest.h"
#include <vector>

#define private public

#include "advanced_notification_service.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_notification.h"
#include "ans_ut_constant.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "iremote_object.h"
#include "mock_ipc_skeleton.h"
#include "notification_preferences.h"
#include "notification_subscriber.h"
#include "notification_subscriber_manager.h"
#include "mock_push_callback_stub.h"
#include "system_event_observer.h"
#include "notification_constant.h"
#include "want_agent_info.h"
#include "want_agent_helper.h"
#include "want_params.h"
#include "bundle_manager_helper.h"

extern void MockIsOsAccountExists(bool mockRet);

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Notification {
extern void MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);
extern void MockIsNonBundleName(bool isNonBundleName);
extern void MockIsVerfyPermisson(bool isVerify);

class AdvancedNotificationServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    void TestAddSlot(NotificationConstant::SlotType type);
    void TestAddLiveViewSlot(bool isForceControl);
    void MockSystemApp();

private:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AdvancedNotificationServiceTest::advancedNotificationService_ = nullptr;

void AdvancedNotificationServiceTest::SetUpTestCase()
{
    MockIsOsAccountExists(true);
}

void AdvancedNotificationServiceTest::TearDownTestCase() {}

void AdvancedNotificationServiceTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    NotificationPreferences::GetInstance().ClearNotificationInRestoreFactorySettings();
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);
    advancedNotificationService_->CancelAll();
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    GTEST_LOG_(INFO) << "SetUp end";
}

void AdvancedNotificationServiceTest::TearDown()
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

class TestAnsSubscriber : public NotificationSubscriber {
public:
    void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override
    {}
    void OnConnected() override
    {}
    void OnDisconnected() override
    {}
    void OnDied() override
    {}
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override
    {}
    void OnBadgeEnabledChanged(
        const sptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnEnabledNotificationChanged(
        const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override
    {}
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>>
        &requestList, const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override
    {}
};

void AdvancedNotificationServiceTest::TestAddSlot(NotificationConstant::SlotType type)
{
    MockSystemApp();
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(type);
    slots.push_back(slot);
    EXPECT_EQ(advancedNotificationService_->AddSlots(slots), (int)ERR_OK);
}

void AdvancedNotificationServiceTest::MockSystemApp()
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
}

void AdvancedNotificationServiceTest::TestAddLiveViewSlot(bool isForceControl)
{
    MockSystemApp();
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::LIVE_VIEW);
    slot->SetForceControl(isForceControl);
    slots.push_back(slot);
    EXPECT_EQ(advancedNotificationService_->AddSlots(slots), (int)ERR_OK);
}

/**
 * @tc.number    : ANS_Publish_00100
 * @tc.name      : ANSPublish00100
 * @tc.desc      : Publish a normal text type notification.
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00100, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest(1);
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("req's label");
    req->SetCreatorUid(1);
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    SleepForFC();
}

/**
 * @tc.number    : ANS_Publish_Update_Flow_00100
 * @tc.name      : ANSPublish00100
 * @tc.desc      : Publish a normal text type notification 30 times,trigger flow.
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceUpdateFlowTest_00100, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest(1);
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("req's label update flow");
    req->SetCreatorUid(1);
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    int count = 30;
    for (uint64_t i = 1; i <= 30; ++i) {
        if (i <= 21) {
            EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
        } else {
            EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_ANS_OVER_MAX_UPDATE_PERSECOND);
        }
    }
    SleepForFC();
}


/**
 * @tc.number    : ANS_Publish_00200
 * @tc.name      : ANSPublish00200
 * @tc.desc      : Publish a normal text type notification twice.
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00200, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest(1);
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("req's label");
    req->SetCreatorUid(1);
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    SleepForFC();
}

/**
 * @tc.number    : ANS_Publish_00300
 * @tc.name      : ANSPublish00300
 * @tc.desc      : When slotType is CUSTOM and not systemApp, the notification publish fails,
 * and the notification publish interface returns ERR_ANS_NON_SYSTEM_APP.
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00300, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::CUSTOM);
    req->SetLabel("req's label");
    req->SetCreatorUid(1);
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_ANS_NON_SYSTEM_APP);
    SleepForFC();
}

/**
 * @tc.number    : ANS_Publish_00400
 * @tc.name      : ANSPublish00400
 * @tc.desc      : When the obtained bundleName is empty, the notification publish interface returns
 * ERR_ANS_INVALID_BUNDLE.
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00400, Function | SmallTest | Level1)
{
    MockIsNonBundleName(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    req->SetLabel("req's label");
    req->SetCreatorUid(1);
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_ANS_INVALID_BUNDLE);
    MockIsNonBundleName(false);
    SleepForFC();
}

/**
 * @tc.number    : ANS_Publish_00500
 * @tc.name      : ANSPublish00500
 * @tc.desc      : When the obtained bundleName does not have a corresponding slot in the database,
 * create the corresponding slot and publish a notification.
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00500, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SERVICE_REMINDER);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    req->SetLabel("req's label");
    req->SetCreatorUid(1);
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    SleepForFC();
}

/**
 * @tc.number    : ANS_Publish_00600
 * @tc.name      : ANSPublish00600
 * @tc.desc      : When the obtained bundleName have a corresponding slot in the database,
 * the test publish interface can successfully publish a notification of normal text type.
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00600, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    req->SetLabel("req's label");
    req->SetCreatorUid(1);
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    SleepForFC();
}

/**
 * @tc.number    : ANS_Publish_00700
 * @tc.name      : ANSPublish00700
 * @tc.desc      : When the obtained bundleName have a corresponding slot in the database,
 * create the corresponding slot and publish a notification.
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00700, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    req->SetLabel("req's label");
    req->SetCreatorUid(1);
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    SleepForFC();
}

/**
 * @tc.number    : ANS_Publish_00800
 * @tc.name      : ANSPublish00800
 * @tc.desc      : Create a slot of type SOCIAL_COMMUNICATION and successfully publish a notification
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00800, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    req->SetLabel("req's label");
    req->SetCreatorUid(1);
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    SleepForFC();
}

/**
 * @tc.number    : ANS_Publish_00900
 * @tc.name      : ANSPublish00900
 * @tc.desc      : Create a slot of type SERVICE_REMINDER and successfully publish a notification
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00900, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SERVICE_REMINDER);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::SERVICE_REMINDER);
    req->SetLabel("req's label");
    req->SetCreatorUid(1);
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    SleepForFC();
}

/**
 * @tc.number    : ANS_Publish_01000
 * @tc.name      : ANSPublish01000
 * @tc.desc      : Create a slot of type CONTENT_INFORMATION and successfully publish a notification
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_01000, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    req->SetLabel("req's label");
    req->SetCreatorUid(1);
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    SleepForFC();
}

/**
 * @tc.number    : ANS_Publish_01100
 * @tc.name      : ANSPublish01100
 * @tc.desc      : Create a slot of type OTHER and successfully publish a notification
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_01100, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("req's label");
    req->SetCreatorUid(1);
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    SleepForFC();
}

/**
 * @tc.number    : ANS_Publish_01200
 * @tc.name      : ANSPublish01200
 * @tc.desc      : Create a slot of type CUSTOM and successfully publish a notification
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_01200, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::CUSTOM);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::CUSTOM);
    req->SetLabel("req's label");
    req->SetCreatorUid(1);
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_ANS_NON_SYSTEM_APP);
    SleepForFC();
}

/**
 * @tc.number    : ANS_Publish_01300
 * @tc.name      : ANSPublish01300
 * @tc.desc      : When a bundle is not allowed to publish a notification, the notification publishing interface
 returns
 * ERR_ANS_NOT_ALLOWED
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_01300, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    req->SetLabel("req's label");
    req->SetCreatorUid(1);
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    EXPECT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(
                  std::string(), new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), false),
        (int)ERR_OK);
    IPCSkeleton::SetCallingTokenID(NON_NATIVE_TOKEN);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_ANS_NOT_ALLOWED);
    SleepForFC();
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_01600
 * @tc.name      : ANS_GetSlot_0200
 * @tc.desc      : Test GetSlots function when add two identical data
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_01600, Function | SmallTest | Level1)
{
    MockSystemApp();
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::OTHER);
    sptr<NotificationSlot> slot1 = new NotificationSlot(NotificationConstant::OTHER);
    slots.push_back(slot0);
    slots.push_back(slot1);
    std::vector<sptr<NotificationSlot>> slotsResult;
    advancedNotificationService_->AddSlots(slots);
    advancedNotificationService_->GetSlots(slotsResult);
    EXPECT_EQ((int)slots.size(), 2);
    EXPECT_EQ((int)slotsResult.size(), 1);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_01800
 * @tc.name      : ANS_SetNotificationBadgeNum_0100
 * @tc.desc      : Test SetNotificationBadgeNum function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_01800, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    EXPECT_EQ((int)advancedNotificationService_->SetNotificationBadgeNum(2), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_01900
 * @tc.name      : ANS_GetBundleImportance_0100
 * @tc.desc      : Test GetBundleImportance function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_01900, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    int importance;
    EXPECT_EQ((int)advancedNotificationService_->GetBundleImportance(importance), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_02200
 * @tc.name      : ANS_UpdateSlots_0100
 * @tc.desc      : Test UpdateSlots function when no slot
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_02200, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::OTHER);
    slots.push_back(slot0);
    EXPECT_EQ((int)advancedNotificationService_->UpdateSlots(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), slots),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_02300
 * @tc.name      : ANS_UpdateSlots_0200
 * @tc.desc      : Test UpdateSlots function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_02300, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::OTHER);
    slots.push_back(slot0);
    EXPECT_EQ((int)advancedNotificationService_->UpdateSlots(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), slots),
        (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_02700
 * @tc.name      : ANS_SetShowBadgeEnabledForBundle_0100
 * @tc.desc      : Test the SetShowBadgeEnabledForBundle function when the parameter is wrong
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_02700, Function | SmallTest | Level1)
{
    EXPECT_EQ(advancedNotificationService_->SetShowBadgeEnabledForBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), true),
        (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_02800
 * @tc.name      : ANS_GetShowBadgeEnabledForBundle_0100
 * @tc.desc      : Test GetShowBadgeEnabledForBundle function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_02800, Function | SmallTest | Level1)
{
    EXPECT_EQ(advancedNotificationService_->SetShowBadgeEnabledForBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), true),
        (int)ERR_OK);
    bool allow = false;
    EXPECT_EQ((int)advancedNotificationService_->GetShowBadgeEnabledForBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), allow),
        (int)ERR_OK);
    EXPECT_TRUE(allow);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_02900
 * @tc.name      : ANS_GetActiveNotifications_0100
 * @tc.desc      : Test GetActiveNotifications function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_02900, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationRequest>> notifications;
    EXPECT_EQ((int)advancedNotificationService_->GetActiveNotifications(notifications), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_03700
 * @tc.name      : ANS_Delete_0100
 * @tc.desc      : Test Delete function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_03700, Function | SmallTest | Level1)
{
    const std::string key = "key";
    EXPECT_EQ((int)advancedNotificationService_->Delete(key, NotificationConstant::CANCEL_REASON_DELETE),
              (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_03800
 * @tc.name      : ANS_DeleteByBundle_0100
 * @tc.desc      : Test DeleteByBundle function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_03800, Function | SmallTest | Level1)
{
    EXPECT_EQ(advancedNotificationService_->DeleteByBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID)),
        ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_03900
 * @tc.name      : ANS_DeleteAll_0100
 * @tc.desc      : Test DeleteAll function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_03900, Function | SmallTest | Level1)
{
    EXPECT_EQ(advancedNotificationService_->DeleteAll(), ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_04000
 * @tc.name      : ANS_GetSlotsByBundle_0100
 * @tc.desc      : Test GetSlotsByBundle function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_04000, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    EXPECT_EQ(advancedNotificationService_->GetSlotsByBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), slots),
        ERR_OK);
    EXPECT_EQ(slots.size(), (size_t)1);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_04100
 * @tc.name      : ANS_GetSpecialActiveNotifications_0100
 * @tc.desc      : Test GetSpecialActiveNotifications function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_04100, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    req->SetLabel("req's label");
    req->SetCreatorUid(1);
    req->SetAlertOneTime(true);
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);

    std::vector<sptr<Notification>> allNotifications;
    EXPECT_EQ(advancedNotificationService_->GetAllActiveNotifications(allNotifications), (int)ERR_OK);
    EXPECT_EQ(allNotifications.size(), (size_t)1);
    std::vector<std::string> keys;
    for (auto notification : allNotifications) {
        keys.push_back(notification->GetKey());
    }
    std::vector<sptr<Notification>> specialActiveNotifications;
    EXPECT_EQ(
        advancedNotificationService_->GetSpecialActiveNotifications(keys, specialActiveNotifications), (int)ERR_OK);
    EXPECT_EQ(specialActiveNotifications.size(), (size_t)1);
    SleepForFC();
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_04600
 * @tc.name      : ANS_Publish_0500
 * @tc.desc      : publish function when NotificationsEnabled is false
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_04600, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> req = new NotificationRequest(1);
    req->SetCreatorUid(1);
    req->SetSlotType(NotificationConstant::OTHER);
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    EXPECT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(
                  std::string(), new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), false),
        (int)ERR_OK);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    EXPECT_EQ(advancedNotificationService_->Publish(std::string(), req), (int)ERR_ANS_NOT_ALLOWED);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_04700
 * @tc.name      : ANS_Cancel_0100
 * @tc.desc      : public two notification to cancel one of them
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_04700, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    std::string label = "testLabel";
    {
        sptr<NotificationRequest> req = new NotificationRequest(1);
        req->SetSlotType(NotificationConstant::OTHER);
        req->SetLabel(label);
        req->SetCreatorUid(1);
        EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    }
    {
        sptr<NotificationRequest> req = new NotificationRequest(2);
        req->SetSlotType(NotificationConstant::OTHER);
        req->SetLabel(label);
        req->SetCreatorUid(1);
        EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    }
    EXPECT_EQ(advancedNotificationService_->Cancel(1, label), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_04800
 * @tc.name      : ANS_Cancel_0200
 * @tc.desc      : Test Cancel function when notification no exists
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_04800, Function | SmallTest | Level1)
{
    int32_t notificationId = 0;
    std::string label = "testLabel";
    EXPECT_EQ((int)advancedNotificationService_->Cancel(notificationId, label), (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_04900
 * @tc.name      : ANS_CancelAll_0100
 * @tc.desc      : Test CancelAll function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_04900, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    sptr<NotificationRequest> req = new NotificationRequest(1);
    req->SetSlotType(NotificationConstant::OTHER);
    EXPECT_EQ(advancedNotificationService_->CancelAll(), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_05000
 * @tc.name      : ANS_Cancel_0100
 * @tc.desc      : Test Cancel function when unremovable is true
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_05000, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    int32_t notificationId = 2;
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(notificationId);
    req->SetSlotType(NotificationConstant::OTHER);
    req->SetLabel(label);
    req->SetUnremovable(true);
    req->SetCreatorUid(1);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    EXPECT_EQ(advancedNotificationService_->Cancel(notificationId, label), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_05100
 * @tc.name      : ANS_AddSlots_0100
 * @tc.desc      : Test AddSlots function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_05100, Function | SmallTest | Level1)
{
    MockSystemApp();
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::OTHER);
    sptr<NotificationSlot> slot1 = new NotificationSlot(NotificationConstant::OTHER);
    slots.push_back(slot0);
    slots.push_back(slot1);
    EXPECT_EQ(advancedNotificationService_->AddSlots(slots), ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_05200
 * @tc.name      : ANS_RemoveSlotByType_0100
 * @tc.desc      : Test RemoveSlotByType function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_05200, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    EXPECT_EQ(advancedNotificationService_->RemoveSlotByType(NotificationConstant::OTHER), ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_05300
 * @tc.name      : ANS_RemoveSlotByType_0200
 * @tc.desc      : Test RemoveSlotByType function when no type
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_05300, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    EXPECT_EQ((int)advancedNotificationService_->RemoveSlotByType(NotificationConstant::CUSTOM), 0);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_05600
 * @tc.name      : ANS_GetSlot_0100
 * @tc.desc      : Test GetSlot function for data
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_05600, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::OTHER);
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::OTHER);
    slots.push_back(slot0);
    advancedNotificationService_->AddSlots(slots);
    EXPECT_EQ((int)advancedNotificationService_->GetSlotByType(NotificationConstant::OTHER, slot), ERR_OK);
    EXPECT_EQ(slot->GetName(), slot0->GetName());
    EXPECT_EQ(slot->GetId(), slot0->GetId());
    EXPECT_EQ(slot->GetLevel(), slot0->GetLevel());
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_05900
 * @tc.name      : ANS_SetNotificationBadgeNum_0100
 * @tc.desc      : Test SetNotificationBadgeNum function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_05900, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    EXPECT_EQ((int)advancedNotificationService_->SetNotificationBadgeNum(2), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_06000
 * @tc.name      : ANS_GetBundleImportance_0100
 * @tc.desc      : Test GetBundleImportance function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_06000, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    int importance = 0;
    EXPECT_EQ((int)advancedNotificationService_->GetBundleImportance(importance), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_06300
 * @tc.name      : ANS_UpdateSlots_0100
 * @tc.desc      : Test UpdateSlots function when no slot
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_06300, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::OTHER);
    slots.push_back(slot0);
    EXPECT_EQ((int)advancedNotificationService_->UpdateSlots(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), slots),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_06400
 * @tc.name      : ANS_UpdateSlots_0200
 * @tc.desc      : Test UpdateSlots function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_06400, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    sptr<NotificationSlot> slot0 = new NotificationSlot(NotificationConstant::OTHER);
    slots.push_back(slot0);
    EXPECT_EQ((int)advancedNotificationService_->UpdateSlots(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), slots),
        (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_06800
 * @tc.name      : ANS_SetShowBadgeEnabledForBundle_0100
 * @tc.desc      : Test the SetShowBadgeEnabledForBundle function when the parameter is wrong
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_06800, Function | SmallTest | Level1)
{
    EXPECT_EQ(advancedNotificationService_->SetShowBadgeEnabledForBundle(
                  new NotificationBundleOption("", SYSTEM_APP_UID), true),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_06900
 * @tc.name      : ANS_GetShowBadgeEnabledForBundle_0100
 * @tc.desc      : Test GetShowBadgeEnabledForBundle function when no bundle
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_06900, Function | SmallTest | Level1)
{
    bool allow = false;
    EXPECT_EQ((int)advancedNotificationService_->GetShowBadgeEnabledForBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), allow),
        (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_07000
 * @tc.name      : ANS_GetActiveNotifications_0100
 * @tc.desc      : Test GetActiveNotifications function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_07000, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationRequest>> notifications;
    EXPECT_EQ((int)advancedNotificationService_->GetActiveNotifications(notifications), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_07800
 * @tc.name      : ANS_Delete_0100
 * @tc.desc      : Test Delete function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_07800, Function | SmallTest | Level1)
{
    const std::string key = "key";
    EXPECT_EQ((int)advancedNotificationService_->Delete(key, NotificationConstant::CANCEL_REASON_DELETE),
              (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_07900
 * @tc.name      : ANS_DeleteByBundle_0100
 * @tc.desc      : Test DeleteByBundle function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_07900, Function | SmallTest | Level1)
{
    EXPECT_EQ(advancedNotificationService_->DeleteByBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID)),
        ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_08000
 * @tc.name      : ANS_DeleteAll_0100
 * @tc.desc      : Test DeleteAll function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_08000, Function | SmallTest | Level1)
{
    EXPECT_EQ(advancedNotificationService_->DeleteAll(), ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_08300
 * @tc.name      : ANS_Subscribe_0100
 * @tc.desc      : Test Subscribe function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_08300, Function | SmallTest | Level1)
{
    auto subscriber = new TestAnsSubscriber();
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    EXPECT_NE((int)advancedNotificationService_->Subscribe(subscriber->GetImpl(), info), (int)ERR_OK);
    EXPECT_EQ((int)advancedNotificationService_->Subscribe(nullptr, info), (int)ERR_ANS_INVALID_PARAM);
    EXPECT_NE((int)advancedNotificationService_->Unsubscribe(subscriber->GetImpl(), nullptr), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_08600
 * @tc.name      : ANS_GetShowBadgeEnabledForBundle_0200
 * @tc.desc      : Test GetShowBadgeEnabledForBundle function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_08600, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    EXPECT_EQ((int)advancedNotificationService_->SetShowBadgeEnabledForBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), true),
        (int)ERR_OK);
    bool allow = false;
    EXPECT_EQ((int)advancedNotificationService_->GetShowBadgeEnabledForBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), allow),
        (int)ERR_OK);
    EXPECT_TRUE(allow);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_08700
 * @tc.name      : ANS_GetSlotByType_0100
 * @tc.desc      : Test GetSlotByType function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_08700, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    EXPECT_EQ((int)advancedNotificationService_->GetSlotByType(NotificationConstant::OTHER, slot), (int)ERR_OK);
    EXPECT_EQ(slot->GetType(), NotificationConstant::SlotType::OTHER);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_09000
 * @tc.name      : ANS_GetAllActiveNotifications_0100
 * @tc.desc      : Test GetAllActiveNotifications function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_09000, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;
    EXPECT_EQ(advancedNotificationService_->GetAllActiveNotifications(notifications), ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_09200
 * @tc.name      : ANS_SetNotificationsEnabledForAllBundles_0200
 * @tc.desc      : Test SetNotificationsEnabledForAllBundles function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_09200, Function | SmallTest | Level1)
{
    EXPECT_EQ(
        (int)advancedNotificationService_->SetNotificationsEnabledForAllBundles(std::string(), true), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_09300
 * @tc.name      : ANS_SetNotificationsEnabledForSpecialBundle_0100
 * @tc.desc      : Test SetNotificationsEnabledForSpecialBundle function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_09300, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<Notification>> notifications;
    EXPECT_EQ((int)advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(
                  std::string(), new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), true),
        (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_09500
 * @tc.name      : ANS_IsAllowedNotify_0100
 * @tc.desc      : Test IsAllowedNotify function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_09500, Function | SmallTest | Level1)
{
    EXPECT_EQ(
        (int)advancedNotificationService_->SetNotificationsEnabledForAllBundles(std::string(), true), (int)ERR_OK);
    bool allowed = false;
    EXPECT_EQ((int)advancedNotificationService_->IsAllowedNotify(allowed), (int)ERR_OK);
    EXPECT_TRUE(allowed);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_09600
 * @tc.name      : ANS_IsAllowedNotifySelf_0100
 * @tc.desc      : Test IsAllowedNotifySelf function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_09600, Function | SmallTest | Level1)
{
    MockSystemApp();
    EXPECT_EQ(
        (int)advancedNotificationService_->SetNotificationsEnabledForAllBundles(std::string(), true), (int)ERR_OK);
    bool allowed = false;
    EXPECT_EQ((int)advancedNotificationService_->IsAllowedNotifySelf(allowed), (int)ERR_OK);
    EXPECT_TRUE(allowed);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_09700
 * @tc.name      : ANS_IsSpecialBundleAllowedNotify_0100
 * @tc.desc      : Test IsSpecialBundleAllowedNotify function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_09700, Function | SmallTest | Level1)
{
    EXPECT_EQ(
        (int)advancedNotificationService_->SetNotificationsEnabledForAllBundles(std::string(), true), (int)ERR_OK);
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    bool allowed = true;
    EXPECT_EQ((int)advancedNotificationService_->IsSpecialBundleAllowedNotify(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), allowed),
        (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_09800
 * @tc.name      : ANS_IsSpecialBundleAllowedNotify_0200
 * @tc.desc      : Test IsSpecialBundleAllowedNotify function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_09800, Function | SmallTest | Level1)
{
    EXPECT_EQ(
        (int)advancedNotificationService_->SetNotificationsEnabledForAllBundles(std::string(), true), (int)ERR_OK);
    std::vector<sptr<Notification>> notifications;
    bool allowed = true;
    EXPECT_EQ((int)advancedNotificationService_->IsSpecialBundleAllowedNotify(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), allowed),
        (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_09900
 * @tc.name      : ANS_GetSlotsByBundle_0200
 * @tc.desc      : Test GetSlotsByBundle function when no bundle
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_09900, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    EXPECT_EQ((int)advancedNotificationService_->GetSlotsByBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), slots),
        (int)ERR_OK);
}

inline std::shared_ptr<PixelMap> MakePixelMap(int32_t width, int32_t height)
{
    const int32_t PIXEL_BYTES = 4;
    std::shared_ptr<PixelMap> pixelMap = std::make_shared<PixelMap>();
    if (pixelMap == nullptr) {
        return nullptr;
    }
    ImageInfo info;
    info.size.width = width;
    info.size.height = height;
    info.pixelFormat = PixelFormat::ARGB_8888;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap->SetImageInfo(info);
    int32_t rowDataSize = width * PIXEL_BYTES;
    uint32_t bufferSize = rowDataSize * height;
    void *buffer = malloc(bufferSize);
    if (buffer != nullptr) {
        pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
    }
    return pixelMap;
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_10000
 * @tc.name      : ANS_Publish_With_PixelMap
 * @tc.desc      : Publish a notification with pixelMap.
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_10000, Function | SmallTest | Level1)
{
    const int BIG_PICTURE_WIDTH = 400;
    const int BIG_PICTURE_HEIGHT = 300;
    const int ICON_SIZE = 36;

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest(1);
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("label");
    std::shared_ptr<NotificationPictureContent> pictureContent = std::make_shared<NotificationPictureContent>();
    EXPECT_NE(pictureContent, nullptr);
    pictureContent->SetText("notification text");
    pictureContent->SetTitle("notification title");
    std::shared_ptr<PixelMap> bigPicture = MakePixelMap(BIG_PICTURE_WIDTH, BIG_PICTURE_HEIGHT);
    EXPECT_NE(bigPicture, nullptr);
    pictureContent->SetBigPicture(bigPicture);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(pictureContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    std::shared_ptr<PixelMap> littleIcon = MakePixelMap(ICON_SIZE, ICON_SIZE);
    req->SetLittleIcon(littleIcon);
    std::shared_ptr<PixelMap> bigIcon = MakePixelMap(ICON_SIZE, ICON_SIZE);
    req->SetBigIcon(bigIcon);
    EXPECT_EQ(advancedNotificationService_->Publish("label", req), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_10100
 * @tc.name      : ANS_Publish_With_PixelMap_Oversize_00100
 * @tc.desc      : Publish a notification with oversize pixelMap.
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_10100, Function | SmallTest | Level1)
{
    const int BIG_PICTURE_WIDTH = 1024;
    const int BIG_PICTURE_HEIGHT = 1024;
    const int ICON_SIZE = 36;

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest(1);
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("label");
    std::shared_ptr<NotificationPictureContent> pictureContent = std::make_shared<NotificationPictureContent>();
    EXPECT_NE(pictureContent, nullptr);
    pictureContent->SetText("notification text");
    pictureContent->SetTitle("notification title");
    std::shared_ptr<PixelMap> bigPicture = MakePixelMap(BIG_PICTURE_WIDTH, BIG_PICTURE_HEIGHT);
    EXPECT_NE(bigPicture, nullptr);
    pictureContent->SetBigPicture(bigPicture);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(pictureContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    std::shared_ptr<PixelMap> littleIcon = MakePixelMap(ICON_SIZE, ICON_SIZE);
    req->SetLittleIcon(littleIcon);
    std::shared_ptr<PixelMap> bigIcon = MakePixelMap(ICON_SIZE, ICON_SIZE);
    req->SetBigIcon(bigIcon);
    EXPECT_EQ(advancedNotificationService_->Publish("label", req), (int)ERR_ANS_PICTURE_OVER_SIZE);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_10200
 * @tc.name      : ANS_Publish_With_PixelMap_Oversize_00200
 * @tc.desc      : Publish a notification with oversize pixelMap.
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_10200, Function | SmallTest | Level1)
{
    const int BIG_PICTURE_WIDTH = 400;
    const int BIG_PICTURE_HEIGHT = 300;
    const int ICON_SIZE = 256;

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest(1);
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("label");
    std::shared_ptr<NotificationPictureContent> pictureContent = std::make_shared<NotificationPictureContent>();
    EXPECT_NE(pictureContent, nullptr);
    pictureContent->SetText("notification text");
    pictureContent->SetTitle("notification title");
    std::shared_ptr<PixelMap> bigPicture = MakePixelMap(BIG_PICTURE_WIDTH, BIG_PICTURE_HEIGHT);
    EXPECT_NE(bigPicture, nullptr);
    pictureContent->SetBigPicture(bigPicture);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(pictureContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    std::shared_ptr<PixelMap> littleIcon = MakePixelMap(ICON_SIZE, ICON_SIZE);
    req->SetLittleIcon(littleIcon);
    std::shared_ptr<PixelMap> bigIcon = MakePixelMap(ICON_SIZE, ICON_SIZE);
    req->SetBigIcon(bigIcon);
    EXPECT_EQ(advancedNotificationService_->Publish("label", req), (int)ERR_ANS_ICON_OVER_SIZE);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_10300
 * @tc.name      : ANS_Cancel_By_Group_10300
 * @tc.desc      : Cancel notification by group name.
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_10300, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest(1);
    ASSERT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("label");
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    ASSERT_NE(normalContent, nullptr);
    normalContent->SetText("text");
    normalContent->SetTitle("title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    ASSERT_NE(content, nullptr);
    req->SetContent(content);
    std::string groupName = "group";
    req->SetGroupName(groupName);
    EXPECT_EQ(advancedNotificationService_->Publish("label", req), (int)ERR_OK);
    EXPECT_EQ(advancedNotificationService_->CancelGroup(groupName), (int)ERR_OK);
    SleepForFC();
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_10400
 * @tc.name      : ANS_Remove_By_Group_10400
 * @tc.desc      : Remove notification by group name.
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_10400, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest(1);
    ASSERT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("label");
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    ASSERT_NE(normalContent, nullptr);
    normalContent->SetText("text");
    normalContent->SetTitle("title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    ASSERT_NE(content, nullptr);
    req->SetContent(content);
    std::string groupName = "group";
    req->SetGroupName(groupName);
    EXPECT_EQ(advancedNotificationService_->Publish("label", req), (int)ERR_OK);

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    EXPECT_EQ(advancedNotificationService_->RemoveGroupByBundle(bundleOption, groupName), (int)ERR_OK);
    SleepForFC();
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_10500
 * @tc.name      : ANS_SetDisturbMode_10500
 * @tc.desc      : Test SetDisturbMode function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_10500, Function | SmallTest | Level1)
{
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
    EXPECT_EQ((int)advancedNotificationService_->SetDoNotDisturbDate(date), (int)ERR_OK);

    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();
    date = new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::ONCE, beginDate, endDate);
    EXPECT_EQ((int)advancedNotificationService_->SetDoNotDisturbDate(date), (int)ERR_OK);

    timePoint = std::chrono::system_clock::now();
    beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    endDate = endDuration.count();
    date = new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::DAILY, beginDate, endDate);
    EXPECT_EQ((int)advancedNotificationService_->SetDoNotDisturbDate(date), (int)ERR_OK);

    timePoint = std::chrono::system_clock::now();
    beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    endDate = endDuration.count();
    date = new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::CLEARLY, beginDate, endDate);
    EXPECT_EQ((int)advancedNotificationService_->SetDoNotDisturbDate(date), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_10600
 * @tc.name      : ANS_GetDisturbMode_10600
 * @tc.desc      : Test GetDisturbMode function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_10600, Function | SmallTest | Level1)
{
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);

    EXPECT_EQ((int)advancedNotificationService_->SetDoNotDisturbDate(date), (int)ERR_OK);

    sptr<NotificationDoNotDisturbDate> result = nullptr;
    EXPECT_EQ((int)advancedNotificationService_->GetDoNotDisturbDate(result), (int)ERR_OK);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetDoNotDisturbType(), NotificationConstant::DoNotDisturbType::NONE);
    EXPECT_EQ(result->GetBeginDate(), 0);
    EXPECT_EQ(result->GetEndDate(), 0);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_10700
 * @tc.name      : ANS_GetDisturbMode_10700
 * @tc.desc      : Test GetDisturbMode function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_10700, Function | SmallTest | Level1)
{
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
    EXPECT_EQ((int)advancedNotificationService_->SetDoNotDisturbDate(date), (int)ERR_OK);

    sptr<NotificationDoNotDisturbDate> result = nullptr;
    EXPECT_EQ((int)advancedNotificationService_->GetDoNotDisturbDate(result), (int)ERR_OK);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetDoNotDisturbType(), NotificationConstant::DoNotDisturbType::ONCE);
    EXPECT_EQ(result->GetBeginDate(), beginDate);
    EXPECT_EQ(result->GetEndDate(), endDate);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_10800
 * @tc.name      : ANS_GetDisturbMode_10800
 * @tc.desc      : Test GetDisturbMode function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_10800, Function | SmallTest | Level1)
{
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

    EXPECT_EQ((int)advancedNotificationService_->SetDoNotDisturbDate(date), (int)ERR_OK);
    sptr<NotificationDoNotDisturbDate> result = nullptr;
    EXPECT_EQ((int)advancedNotificationService_->GetDoNotDisturbDate(result), (int)ERR_OK);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetDoNotDisturbType(), NotificationConstant::DoNotDisturbType::DAILY);
    EXPECT_EQ(result->GetBeginDate(), beginDate);
    EXPECT_EQ(result->GetEndDate(), endDate);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_10900
 * @tc.name      : ANS_GetDisturbMode_10900
 * @tc.desc      : Test GetDisturbMode function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_10900, Function | SmallTest | Level1)
{
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
    EXPECT_EQ((int)advancedNotificationService_->SetDoNotDisturbDate(date), (int)ERR_OK);

    sptr<NotificationDoNotDisturbDate> result = nullptr;
    EXPECT_EQ((int)advancedNotificationService_->GetDoNotDisturbDate(result), (int)ERR_OK);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetDoNotDisturbType(), NotificationConstant::DoNotDisturbType::CLEARLY);
    EXPECT_EQ(result->GetBeginDate(), beginDate);
    EXPECT_EQ(result->GetEndDate(), endDate);
}

/**
 * @tc.number    : ANS_Publish_01500
 * @tc.name      : ANSPublish01500
 * @tc.desc      : publish a continuous task notification
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_11000, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("req's label");
    EXPECT_EQ(advancedNotificationService_->PublishContinuousTaskNotification(req), (int)ERR_OK);
    SleepForFC();
}

/**
 * @tc.number    : ANS_Publish_01600
 * @tc.name      : ANSPublish01600
 * @tc.desc      : publish a continuous task notification
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_11100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("req's label");
    EXPECT_EQ(advancedNotificationService_->PublishContinuousTaskNotification(req), (int)ERR_ANS_NOT_SYSTEM_SERVICE);
    SleepForFC();
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_11200
 * @tc.name      : ANS_Cancel_0300
 * @tc.desc      : public two notification to cancel one of them
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_11200, Function | SmallTest | Level1)
{
    std::string label = "testLabel";
    {
        sptr<NotificationRequest> req = new NotificationRequest(1);
        req->SetSlotType(NotificationConstant::OTHER);
        req->SetLabel(label);
        EXPECT_EQ(advancedNotificationService_->PublishContinuousTaskNotification(req), (int)ERR_OK);
    }
    EXPECT_EQ(advancedNotificationService_->CancelContinuousTaskNotification(label, 1), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_11300
 * @tc.name      : ANS_Cancel_0400
 * @tc.desc      : public two notification to cancel one of them
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_11300, Function | SmallTest | Level1)
{
    std::string label = "testLabel";
    {
        sptr<NotificationRequest> req = new NotificationRequest(1);
        req->SetSlotType(NotificationConstant::OTHER);
        req->SetLabel(label);
        EXPECT_EQ(advancedNotificationService_->PublishContinuousTaskNotification(req), (int)ERR_OK);
    }
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    EXPECT_EQ(
        advancedNotificationService_->CancelContinuousTaskNotification(label, 1), (int)ERR_ANS_NOT_SYSTEM_SERVICE);
}

/**
 * @tc.name: AdvancedNotificationServiceTest_12000
 * @tc.desc: Send enable notification hisysevent and enable notification error hisysevent.
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_12000, Function | SmallTest | Level1)
{
    // bundleName is empty
    EXPECT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(
        std::string(), new NotificationBundleOption(std::string(), -1), true),
        (int)ERR_ANS_INVALID_PARAM);

    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    req->SetLabel("req's label");
    std::string label = "enable's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    EXPECT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(
        std::string(), new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), false),
        (int)ERR_OK);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_ANS_NOT_ALLOWED);
    SleepForFC();
}

/**
 * @tc.name: AdvancedNotificationServiceTest_12100
 * @tc.desc: Send enable notification slot hisysevent.
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_12100, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    req->SetLabel("req's label");
    std::string label = "enable's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    auto result = advancedNotificationService_->SetEnabledForBundleSlot(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID),
        NotificationConstant::SlotType::SOCIAL_COMMUNICATION,
        false, false);
    EXPECT_EQ(result, (int)ERR_OK);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_ENABLED);
    SleepForFC();
}

/**
 * @tc.name: AdvancedNotificationServiceTest_12200
 * @tc.desc: Send remove notification hisysevent.
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_12200, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    int32_t notificationId = 1;
    std::string label = "testRemove";
    sptr<NotificationRequest> req = new NotificationRequest(notificationId);
    req->SetSlotType(NotificationConstant::OTHER);
    req->SetLabel(label);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);

    auto result = advancedNotificationService_->RemoveNotification(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID),
        notificationId, label, NotificationConstant::CANCEL_REASON_DELETE);
    EXPECT_EQ(result, (int)ERR_OK);
}

/**
 * @tc.name: AdvancedNotificationServiceTest_12300
 * @tc.desc: SA publish notification, Failed to publish when creatorUid default.
 * @tc.type: FUNC
 * @tc.require: I5P1GU
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_12300, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    req->SetLabel("req's label");
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), ERR_ANS_INVALID_UID);
    SleepForFC();

    req->SetCreatorUid(1);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), 0);
}

/*
 * @tc.name: AdvancedNotificationServiceTest_12400
 * @tc.desc: DLP App publish notification failed.
 * @tc.type: FUNC
 * @tc.require: I582TY
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_12400, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new (std::nothrow) NotificationRequest(1);
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("req's label");
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    EXPECT_NE(advancedNotificationService_->Publish(label, req), ERR_ANS_DLP_HAP);
    SleepForFC();

    EXPECT_EQ(advancedNotificationService_->Publish(label, req), ERR_OK);
}

/*
 * @tc.name: AdvancedNotificationServiceTest_12500
 * @tc.desc: When the user removed event is received and the userid is less than or equal to 100,
 * the notification cannot be deleted
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_12500, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new (std::nothrow) NotificationRequest(1);
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("req's label");
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    req->SetCreatorUserId(DEFAULT_USER_ID);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), ERR_OK);
    SleepForFC();

    EventFwk::Want want;
    EventFwk::CommonEventData data;
    data.SetWant(want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED));
    data.SetCode(DEFAULT_USER_ID);
    advancedNotificationService_->systemEventObserver_->OnReceiveEvent(data);

    EXPECT_EQ(advancedNotificationService_->IsNotificationExists(req->GetBaseKey("")), true);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_12600
 * @tc.name      : ANS_CancelAsBundle_0100
 * @tc.desc      : Test CancelAsBundle function when the result is ERR_ANS_NOTIFICATION_NOT_EXISTS
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_12600, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    int32_t notificationId = 1;
    std::string representativeBundle = "RepresentativeBundle";
    int32_t userId = 1;
    int result = ERR_ANS_NOTIFICATION_NOT_EXISTS;
    EXPECT_EQ(advancedNotificationService_->CancelAsBundle(notificationId, representativeBundle, userId), result);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_12700
 * @tc.name      : ANS_CanPublishAsBundle_0100
 * @tc.desc      : Test CanPublishAsBundle function when the result is ERR_INVALID_OPERATION
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_12700, Function | SmallTest | Level1)
{
    std::string representativeBundle = "RepresentativeBundle";
    bool canPublish = true;
    int result = ERR_INVALID_OPERATION;
    EXPECT_EQ(advancedNotificationService_->CanPublishAsBundle(representativeBundle, canPublish), result);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_12800
 * @tc.name      : ANS_PublishAsBundle_0100
 * @tc.desc      : Test PublishAsBundle function when the result is ERR_INVALID_OPERATION
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_12800, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> notification = nullptr;
    std::string representativeBundle = "RepresentativeBundle";
    int result = ERR_INVALID_OPERATION;
    EXPECT_EQ(advancedNotificationService_->PublishAsBundle(notification, representativeBundle), result);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_12900
 * @tc.name      : ANS_HasNotificationPolicyAccessPermission_0100
 * @tc.desc      : Test HasNotificationPolicyAccessPermission function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_12900, Function | SmallTest | Level1)
{
    bool granted = true;
    EXPECT_EQ(advancedNotificationService_->HasNotificationPolicyAccessPermission(granted), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_13000
 * @tc.name      : ANS_GetShowBadgeEnabled_0100
 * @tc.desc      : Test GetShowBadgeEnabled function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_13000, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    bool enabled = false;
    EXPECT_EQ(advancedNotificationService_->GetShowBadgeEnabled(enabled), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_13100
 * @tc.name      : ANS_RequestEnableNotification_0100
 * @tc.desc      : Test whether to pop dialog
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_13100, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    std::string deviceId = "DeviceId";
    sptr<AnsDialogCallback> callback = nullptr;
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(advancedNotificationService_->RequestEnableNotification(deviceId, callback, callerToken),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_13200
 * @tc.name      : ANS_PublishReminder_0100
 * @tc.desc      : Test PublishReminder function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_13200, Function | SmallTest | Level1)
{
    sptr<ReminderRequest> reminder = nullptr;
    EXPECT_EQ(advancedNotificationService_->PublishReminder(reminder), ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_13300
 * @tc.name      : ANS_CancelReminder_0100
 * @tc.desc      : Test CancelReminder function when the result is ERR_NO_INIT
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_13300, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    int32_t reminderId = 1;
    EXPECT_EQ(advancedNotificationService_->CancelReminder(reminderId), (int)ERR_NO_INIT);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_13400
 * @tc.name      : ANS_CancelAllReminders_0100
 * @tc.desc      : Test CancelAllReminders function when the result is ERR_NO_INIT
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_13400, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    EXPECT_EQ(advancedNotificationService_->CancelAllReminders(), (int)ERR_NO_INIT);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_13500
 * @tc.name      : ANS_GetValidReminders_0100
 * @tc.desc      : Test GetValidReminders function when the result is ERR_NO_INIT
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_13500, Function | SmallTest | Level1)
{
    std::vector<sptr<ReminderRequest>> reminders;
    EXPECT_EQ(advancedNotificationService_->GetValidReminders(reminders), (int)ERR_NO_INIT);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_13600
 * @tc.name      : ANS_ActiveNotificationDump_0100
 * @tc.desc      : Test ActiveNotificationDump function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_13600, Function | SmallTest | Level1)
{
    std::string bundle = "Bundle";
    int32_t userId = 2;
    std::vector<std::string> dumpInfo;
    EXPECT_EQ(advancedNotificationService_->ActiveNotificationDump(bundle, userId, 0, dumpInfo), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_13700
 * @tc.name      : ANS_RecentNotificationDump_0100
 * @tc.desc      : Test RecentNotificationDump function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_13700, Function | SmallTest | Level1)
{
    std::string bundle = "Bundle";
    int32_t userId = 3;
    std::vector<std::string> dumpInfo;
    EXPECT_EQ(advancedNotificationService_->RecentNotificationDump(bundle, userId, 0, dumpInfo), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_13800
 * @tc.name      : ANS_SetRecentNotificationCount_0100
 * @tc.desc      : Test SetRecentNotificationCount function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_13800, Function | SmallTest | Level1)
{
    std::string arg = "Arg";
    EXPECT_EQ(advancedNotificationService_->SetRecentNotificationCount(arg), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_13900
 * @tc.name      : ANS_RemoveAllSlots_0100
 * @tc.desc      : Test RemoveAllSlots function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_13900, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    EXPECT_EQ(advancedNotificationService_->RemoveAllSlots(), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_14200
 * @tc.name      : ANS_DoesSupportDoNotDisturbMode_0100
 * @tc.desc      : Test DoesSupportDoNotDisturbMode function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_14200, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    bool doesSupport = true;
    EXPECT_EQ(advancedNotificationService_->DoesSupportDoNotDisturbMode(doesSupport), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_14300
 * @tc.name      : ANS_IsDistributedEnabled_0100
 * @tc.desc      : Test IsDistributedEnabled function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_14300, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    bool enabled = true;
    EXPECT_EQ(advancedNotificationService_->IsDistributedEnabled(enabled), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_14400
 * @tc.name      : ANS_EnableDistributed_0100
 * @tc.desc      : Test EnableDistributed function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_14400, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    bool enabled = true;
    EXPECT_EQ(advancedNotificationService_->EnableDistributed(enabled), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_14600
 * @tc.name      : ANS_EnableDistributedSelf_0100
 * @tc.desc      : Test EnableDistributedSelf function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_14600, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    bool enabled = true;
    EXPECT_EQ(advancedNotificationService_->EnableDistributedSelf(enabled), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_14800
 * @tc.name      : ANS_IsSpecialUserAllowedNotify_0100
 * @tc.desc      : Test IsSpecialUserAllowedNotify function when the result is ERR_ANS_INVALID_PARAM
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_14800, Function | SmallTest | Level1)
{
    int32_t userId = 3;
    bool allowed = true;
    EXPECT_EQ(advancedNotificationService_->IsSpecialUserAllowedNotify(userId, allowed), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_14900
 * @tc.name      : ANS_SetNotificationsEnabledByUser_0100
 * @tc.desc      : Test SetNotificationsEnabledByUser function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_14900, Function | SmallTest | Level1)
{
    int32_t userId = 3;
    bool enabled = true;
    EXPECT_EQ(advancedNotificationService_->SetNotificationsEnabledByUser(userId, enabled), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_15000
 * @tc.name      : ANS_GetDoNotDisturbDate_0100
 * @tc.desc      : Test GetDoNotDisturbDate function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_15000, Function | SmallTest | Level1)
{
    int32_t userId = 3;
    sptr<NotificationDoNotDisturbDate> date = nullptr;
    EXPECT_EQ(advancedNotificationService_->GetDoNotDisturbDate(userId, date), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_15200
 * @tc.name      : ANS_GetHasPoppedDialog_0100
 * @tc.desc      : Test GetHasPoppedDialog function when the result is ERR_ANS_INVALID_PARAM
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_15200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool hasPopped = true;
    EXPECT_EQ(advancedNotificationService_->GetHasPoppedDialog(bundleOption, hasPopped), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_15300
 * @tc.name      : ANS_ShellDump_0100
 * @tc.desc      : Test ShellDump function when the result is ERR_ANS_INVALID_PARAM
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_15300, Function | SmallTest | Level1)
{
    std::string cmd = "CMD";
    std::string bundle = "Bundle";
    int32_t userId = 4;
    std::vector<std::string> dumpInfo;
    EXPECT_EQ(advancedNotificationService_->ShellDump(cmd, bundle, userId, 0, dumpInfo), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_15400
 * @tc.name      : ANS_Dump_0100
 * @tc.desc      : Test Dump function when the result is ERR_OK
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_15400, Function | SmallTest | Level1)
{
    int fd = 1;
    std::vector<std::u16string> args;
    EXPECT_EQ(advancedNotificationService_->Dump(fd, args), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_15500
 * @tc.name      : OnReceiveEvent_0100
 * @tc.desc      : Test OnReceiveEvent function userid<DEFAULT_USER_ID
 * @tc.require   : I5TIQR
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_15500, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new (std::nothrow) NotificationRequest(1);
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("req's label");
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    req->SetCreatorUserId(DEFAULT_USER_ID);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), ERR_OK);
    SleepForFC();

    EventFwk::Want want;
    EventFwk::CommonEventData data;
    data.SetWant(want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED));
    data.SetCode(50);
    advancedNotificationService_->systemEventObserver_->OnReceiveEvent(data);

    EXPECT_EQ(advancedNotificationService_->IsNotificationExists(req->GetBaseKey("")), true);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_15600
 * @tc.name      : OnReceiveEvent_0200
 * @tc.desc      : Test OnReceiveEvent function when userid>DEFAULT_USER_ID
 * @tc.require   : I5TIQR
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_15600, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new (std::nothrow) NotificationRequest(1);
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("req's label");
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    req->SetCreatorUserId(DEFAULT_USER_ID);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), ERR_OK);
    SleepForFC();

    EventFwk::Want want;
    EventFwk::CommonEventData data;
    data.SetWant(want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED));
    data.SetCode(200);
    advancedNotificationService_->systemEventObserver_->OnReceiveEvent(data);

    EXPECT_EQ(advancedNotificationService_->IsNotificationExists(req->GetBaseKey("")), true);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_15700
 * @tc.name      : PrepareNotificationRequest_0100
 * @tc.desc      : Test PrepareNotificationRequest function when notification is agent.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_15700, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "PrepareNotificationRequest_0100 test start";
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);

    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("req's label");
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);

    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);

    req->SetContent(content);
    req->SetIsAgentNotification(true);
    EXPECT_EQ(advancedNotificationService_->PrepareNotificationRequest(req), ERR_OK);
    GTEST_LOG_(INFO) << "PrepareNotificationRequest_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_15800
 * @tc.name      : GenerateBundleOption_0100
 * @tc.desc      : Test GenerateBundleOption function when bundle name is null.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_15800, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GenerateBundleOption_0100 test start";
    MockSystemApp();
    MockIsNonBundleName(true);
    EXPECT_EQ(advancedNotificationService_->GenerateBundleOption(), nullptr);
    MockIsNonBundleName(false);
    GTEST_LOG_(INFO) << "GenerateBundleOption_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_16000
 * @tc.name      : CancelPreparedNotification_1000
 * @tc.desc      : Test CancelPreparedNotification function.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16000, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "CancelPreparedNotification_1000 test start";

    int32_t notificationId = 0;
    std::string label = "testLabel";
    sptr<NotificationBundleOption> bundleOption = nullptr;
    EXPECT_EQ(advancedNotificationService_->CancelPreparedNotification(notificationId, label, bundleOption),
        ERR_ANS_INVALID_BUNDLE);

    GTEST_LOG_(INFO) << "CancelPreparedNotification_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_16100
 * @tc.name      : PrepareNotificationInfo_1000
 * @tc.desc      : Test PrepareNotificationInfo function.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16100, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "CancelPreparedNotification_1000 test start";

    sptr<NotificationRequest> req = new (std::nothrow) NotificationRequest(1);
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("req's label");
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    req->SetCreatorUserId(DEFAULT_USER_ID);
    req->SetIsAgentNotification(true);
    advancedNotificationService_->Publish(label, req);
    SleepForFC();

    GTEST_LOG_(INFO) << "CancelPreparedNotification_1000 test end";
}


/**
 * @tc.number    : AdvancedNotificationServiceTest_16200
 * @tc.name      : ANS_CancelAsBundle_0200
 * @tc.desc      : Test CancelAsBundle function
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16200, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_CancelAsBundle_0200 test start";

    TestAddSlot(NotificationConstant::SlotType::OTHER);
    int32_t notificationId = 1;
    std::string representativeBundle = "RepresentativeBundle";
    int32_t userId = 1;
    int result = ERR_ANS_NOTIFICATION_NOT_EXISTS;
    EXPECT_EQ(advancedNotificationService_->CancelAsBundle(notificationId, representativeBundle, userId), result);

    GTEST_LOG_(INFO) << "ANS_CancelAsBundle_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_16300
 * @tc.name      : ANS_CancelAsBundle_0300
 * @tc.desc      : Test CancelAsBundle function when uid is less than 0.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16300, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_CancelAsBundle_0300 test start";

    TestAddSlot(NotificationConstant::SlotType::OTHER);
    int32_t notificationId = 1;
    std::string representativeBundle = "RepresentativeBundle";
    int32_t userId = 0;
    int result = ERR_ANS_INVALID_UID;
    EXPECT_EQ(advancedNotificationService_->CancelAsBundle(notificationId, representativeBundle, userId), result);

    GTEST_LOG_(INFO) << "ANS_CancelAsBundle_0300 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_16500
 * @tc.name      : ANS_CancelAsBundle_0400
 * @tc.desc      : Test CancelAsBundle function
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16500, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_CancelAsBundle_0400 test start";

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    int32_t notificationId = 1;

    int result = ERR_ANS_NOTIFICATION_NOT_EXISTS;
    EXPECT_EQ(advancedNotificationService_->CancelAsBundle(bundleOption, notificationId), result);

    GTEST_LOG_(INFO) << "ANS_CancelAsBundle_0400 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_16400
 * @tc.name      : ANS_AddSlots_0100
 * @tc.desc      : Test AddSlots function whith not system app
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16400, Function | SmallTest | Level1)
{
    MockSystemApp();
    GTEST_LOG_(INFO) << "ANS_AddSlots_0100 test start";
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    slots.push_back(slot);
    EXPECT_EQ(advancedNotificationService_->AddSlots(slots), ERR_OK);

    GTEST_LOG_(INFO) << "ANS_AddSlots_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_16600
 * @tc.name      : ANS_AddSlots_0300
 * @tc.desc      : Test AddSlots function with bundle option is null
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16600, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_AddSlots_0300 test start";
    MockIsNonBundleName(true);
    MockSystemApp();
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    slots.push_back(slot);
    EXPECT_EQ(advancedNotificationService_->AddSlots(slots), ERR_ANS_INVALID_BUNDLE);
    MockIsNonBundleName(false);
    GTEST_LOG_(INFO) << "ANS_AddSlots_0300 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_16700
 * @tc.name      : ANS_AddSlots_0400
 * @tc.desc      : Test AddSlots function with invalid bundle option
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16700, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_AddSlots_0400 test start";

    std::vector<sptr<NotificationSlot>> slots;
    EXPECT_EQ(advancedNotificationService_->AddSlots(slots), ERR_ANS_INVALID_PARAM);

    GTEST_LOG_(INFO) << "ANS_AddSlots_0400 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_16800
 * @tc.name      : ANS_GetSlots_0100
 * @tc.desc      : Test GetSlots function with bundle option is null
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16800, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_GetSlots_0100 test start";
    MockIsNonBundleName(true);
    MockSystemApp();
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    slots.push_back(slot);
    EXPECT_EQ(advancedNotificationService_->GetSlots(slots), ERR_ANS_INVALID_BUNDLE);
    MockIsNonBundleName(false);
    GTEST_LOG_(INFO) << "ANS_GetSlots_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_16900
 * @tc.name      : ANS_GetActiveNotifications_0100
 * @tc.desc      : Test function with bundle option is null
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_16900, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_GetActiveNotifications_0100 test start";

    MockIsNonBundleName(true);
    MockSystemApp();
    std::vector<sptr<NotificationRequest>> notifications;
    EXPECT_EQ(advancedNotificationService_->GetActiveNotifications(notifications), ERR_ANS_INVALID_BUNDLE);
    uint64_t num = 1;
    EXPECT_EQ(advancedNotificationService_->GetActiveNotificationNums(num), ERR_ANS_INVALID_BUNDLE);
    EXPECT_EQ(advancedNotificationService_->SetNotificationBadgeNum(num), ERR_ANS_INVALID_BUNDLE);
    int32_t importance = 2;
    EXPECT_EQ(advancedNotificationService_->GetBundleImportance(importance), ERR_ANS_INVALID_BUNDLE);
    bool allow = true;
    EXPECT_EQ(advancedNotificationService_->GetShowBadgeEnabled(allow), ERR_ANS_INVALID_BUNDLE);

    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::OTHER);
    EXPECT_EQ(advancedNotificationService_->GetSlotByType(NotificationConstant::OTHER, slot), ERR_ANS_INVALID_BUNDLE);
    EXPECT_EQ(advancedNotificationService_->RemoveSlotByType(NotificationConstant::OTHER), ERR_ANS_INVALID_BUNDLE);

    std::string deviceId = "DeviceId";
    bool needPop = false;
    EXPECT_EQ(advancedNotificationService_->IsAllowedNotifySelf(needPop), ERR_ANS_INVALID_BUNDLE);
    sptr<NotificationBundleOption> bundleOption;
    EXPECT_EQ(advancedNotificationService_->IsAllowedNotifySelf(bundleOption, needPop), ERR_ANS_INVALID_BUNDLE);

    EXPECT_EQ(advancedNotificationService_->GetAppTargetBundle(bundleOption, bundleOption), ERR_ANS_INVALID_BUNDLE);

    int32_t reminderId = 1;
    EXPECT_EQ(advancedNotificationService_->CancelReminder(reminderId), ERR_ANS_INVALID_BUNDLE);

    EXPECT_EQ(advancedNotificationService_->CancelAllReminders(), ERR_ANS_INVALID_BUNDLE);

    std::vector<sptr<ReminderRequest>> reminders;
    EXPECT_EQ(advancedNotificationService_->GetValidReminders(reminders), ERR_ANS_INVALID_BUNDLE);

    EXPECT_EQ(advancedNotificationService_->RemoveAllSlots(), ERR_ANS_INVALID_BUNDLE);

    EXPECT_EQ(advancedNotificationService_->AddSlotByType(NotificationConstant::SlotType::OTHER),
        ERR_ANS_INVALID_BUNDLE);

    std::string groupName = "name";
    EXPECT_EQ(advancedNotificationService_->CancelGroup(groupName), ERR_ANS_INVALID_BUNDLE);

    bool enabled = true;
    EXPECT_EQ(advancedNotificationService_->EnableDistributedSelf(enabled), ERR_ANS_INVALID_BUNDLE);
    MockIsNonBundleName(false);
    GTEST_LOG_(INFO) << "ANS_GetActiveNotifications_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_17000
 * @tc.name      : ANS_GetSetActiveNotifications_0100
 * @tc.desc      : Test SetNotificationAgent and GetNotificationAgent function with bundle option is null
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_17000, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_GetActiveNotifications_0100 test start";

    std::string agent = "agent";
    EXPECT_EQ(advancedNotificationService_->SetNotificationAgent(agent), ERR_INVALID_OPERATION);
    EXPECT_EQ(advancedNotificationService_->GetNotificationAgent(agent), ERR_INVALID_OPERATION);

    GTEST_LOG_(INFO) << "ANS_GetActiveNotifications_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_17100
 * @tc.name      : ANS_GetSetActiveNotifications_0100
 * @tc.desc      : Test function with NON_SYSTEM_APP_UID
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_17100, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_GetActiveNotifications_0100 test start";

    std::string key = "key";
    int32_t removeReason = 0;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    EXPECT_EQ(advancedNotificationService_->Delete(key, removeReason), ERR_ANS_NOTIFICATION_NOT_EXISTS);

    EXPECT_EQ(advancedNotificationService_->DeleteByBundle(bundleOption), ERR_OK);

    EXPECT_EQ(advancedNotificationService_->DeleteAll(), ERR_OK);

    bool enable = true;
    bool isForceControl = false;
    EXPECT_EQ(advancedNotificationService_->SetShowBadgeEnabledForBundle(bundleOption, enable), ERR_OK);

    EXPECT_EQ(advancedNotificationService_->GetShowBadgeEnabledForBundle(bundleOption, enable), ERR_OK);

    std::vector<sptr<Notification>> notifications;
    EXPECT_EQ(advancedNotificationService_->GetAllActiveNotifications(notifications), ERR_OK);

    std::vector<std::string> keys;
    EXPECT_EQ(advancedNotificationService_->GetSpecialActiveNotifications(keys, notifications),
        ERR_OK);

    EXPECT_EQ(advancedNotificationService_->SetNotificationsEnabledForAllBundles(key, enable),
        ERR_OK);

    EXPECT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(
        std::string(), bundleOption, enable), ERR_OK);

    EXPECT_EQ(advancedNotificationService_->IsAllowedNotify(enable), ERR_ANS_INVALID_PARAM);

    int32_t notificationId = 1;
    EXPECT_EQ(advancedNotificationService_->RemoveNotification(bundleOption, notificationId,
        key, removeReason), ERR_ANS_NOTIFICATION_NOT_EXISTS);

    EXPECT_EQ(advancedNotificationService_->RemoveAllNotifications(bundleOption), ERR_OK);

    uint64_t num = 1;
    EXPECT_EQ(advancedNotificationService_->GetSlotNumAsBundle(bundleOption, num), ERR_OK);

    std::string groupName = "group";
    EXPECT_EQ(advancedNotificationService_->RemoveGroupByBundle(bundleOption, groupName), ERR_OK);

    sptr<NotificationDoNotDisturbDate> date = nullptr;
    EXPECT_EQ(advancedNotificationService_->SetDoNotDisturbDate(date), ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(advancedNotificationService_->GetDoNotDisturbDate(date), ERR_OK);

    EXPECT_EQ(advancedNotificationService_->DoesSupportDoNotDisturbMode(enable), ERR_OK);

    EXPECT_EQ(advancedNotificationService_->EnableDistributed(enable), ERR_OK);

    EXPECT_EQ(advancedNotificationService_->EnableDistributedByBundle(bundleOption, enable), ERR_OK);

    EXPECT_EQ(advancedNotificationService_->IsDistributedEnableByBundle(bundleOption, enable), ERR_OK);

    NotificationConstant::RemindType remindType = NotificationConstant::RemindType::DEVICE_ACTIVE_REMIND;
    EXPECT_EQ(advancedNotificationService_->GetDeviceRemindType(remindType), ERR_OK);

    int32_t userId = 1;
    EXPECT_EQ(advancedNotificationService_->IsSpecialUserAllowedNotify(userId, enable), ERR_ANS_INVALID_PARAM);

    EXPECT_EQ(advancedNotificationService_->SetNotificationsEnabledByUser(userId, enable), ERR_OK);

    EXPECT_EQ(advancedNotificationService_->DeleteAllByUser(userId), ERR_OK);

    EXPECT_EQ(advancedNotificationService_->SetDoNotDisturbDate(userId, date), ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(advancedNotificationService_->GetDoNotDisturbDate(userId, date), ERR_OK);

    EXPECT_EQ(advancedNotificationService_->SetEnabledForBundleSlot(bundleOption,
        NotificationConstant::SlotType::OTHER, enable, false), ERR_OK);

    EXPECT_EQ(advancedNotificationService_->GetEnabledForBundleSlot(bundleOption,
        NotificationConstant::SlotType::OTHER, enable), ERR_OK);

    EXPECT_EQ(advancedNotificationService_->SetSyncNotificationEnabledWithoutApp(userId, enable), ERR_OK);

    EXPECT_EQ(advancedNotificationService_->GetSyncNotificationEnabledWithoutApp(userId, enable), ERR_OK);

    GTEST_LOG_(INFO) << "ANS_GetActiveNotifications_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_17200
 * @tc.name      : ANS_DeleteAll_0100
 * @tc.desc      : Test DeleteAll function
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_17200, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_GetActiveNotifications_0100 test start";

    TestAddSlot(NotificationConstant::SlotType::OTHER);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    sptr<NotificationRequest> req = new NotificationRequest(1);
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("req's label");
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    SleepForFC();
    req->SetCreatorUserId(SUBSCRIBE_USER_INIT);
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(req);

    EXPECT_EQ(advancedNotificationService_->DeleteAll(), ERR_OK);

    GTEST_LOG_(INFO) << "ANS_GetActiveNotifications_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_17300
 * @tc.name      : ANS_GetSlotsByBundle_0100
 * @tc.desc      : Test GetSlotsByBundle function
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_17300, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_GetSlotsByBundle_0100 test start";
    std::vector<sptr<NotificationSlot>> slots;
    EXPECT_EQ(advancedNotificationService_->GetSlotsByBundle(
                  new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), slots),
        ERR_OK);

    EXPECT_EQ(advancedNotificationService_->UpdateSlots(
                new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID), slots),
        ERR_ANS_INVALID_PARAM);

    GTEST_LOG_(INFO) << "ANS_GetSlotsByBundle_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_17400
 * @tc.name      : Subscribe_1000
 * @tc.desc      : Test Subscribe function.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_17400, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "Subscribe_1000 test start";

    auto subscriber = new TestAnsSubscriber();
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    EXPECT_NE(advancedNotificationService_->Subscribe(subscriber->GetImpl(), info), ERR_OK);
    EXPECT_NE(advancedNotificationService_->Unsubscribe(subscriber->GetImpl(), info), ERR_OK);

    GTEST_LOG_(INFO) << "Subscribe_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_17500
 * @tc.name      : Unsubscribe_1000
 * @tc.desc      : Test Subscribe function.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_17500, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "Unsubscribe_1000 test start";

    auto subscriber = new TestAnsSubscriber();
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    EXPECT_NE(advancedNotificationService_->Subscribe(subscriber->GetImpl(), info), ERR_OK);
    EXPECT_EQ(advancedNotificationService_->Unsubscribe(nullptr, info), ERR_ANS_INVALID_PARAM);

    GTEST_LOG_(INFO) << "Unsubscribe_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_17600
 * @tc.name      : GetAppTargetBundle_1000
 * @tc.desc      : Test GetAppTargetBundle function.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_17600, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetAppTargetBundle_1000 test start";

    sptr<NotificationBundleOption> bundleOption = nullptr;

    EXPECT_EQ(advancedNotificationService_->GetAppTargetBundle(bundleOption, bundleOption), ERR_OK);

    GTEST_LOG_(INFO) << "GetAppTargetBundle_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_17700
 * @tc.name      : GetAppTargetBundle_2000
 * @tc.desc      : Test GetAppTargetBundle function.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_17700, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetAppTargetBundle_2000 test start";
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationBundleOption> targetBundle = nullptr;
    bundleOption->SetBundleName("test");
    EXPECT_EQ(advancedNotificationService_->GetAppTargetBundle(bundleOption, targetBundle), ERR_OK);

    GTEST_LOG_(INFO) << "GetAppTargetBundle_2000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_17800
 * @tc.name      : GetAppTargetBundle_3000
 * @tc.desc      : Test GetAppTargetBundle function.
 * @tc.require   : #I60KYN
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_17800, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetAppTargetBundle_3000 test start";

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    sptr<NotificationBundleOption> targetBundle = nullptr;
    bundleOption->SetBundleName("test");
    EXPECT_EQ(advancedNotificationService_->GetAppTargetBundle(bundleOption, targetBundle), ERR_OK);

    GTEST_LOG_(INFO) << "GetAppTargetBundle_3000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_17900
 * @tc.name      : PublishReminder_1000
 * @tc.desc      : Test PublishReminder function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_17900, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetAppTargetBundle_1000 test start";

    int32_t reminderId = 1;
    sptr<ReminderRequest> reminder = new ReminderRequest(reminderId);
    reminder->InitNotificationRequest();
    EXPECT_EQ(advancedNotificationService_->PublishReminder(reminder), ERR_REMINDER_NOTIFICATION_NOT_ENABLE);

    GTEST_LOG_(INFO) << "GetAppTargetBundle_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_18000
 * @tc.name      : PublishReminder_2000
 * @tc.desc      : Test PublishReminder function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18000, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetAppTargetBundle_2000 test start";

    MockIsNonBundleName(true);
    int32_t reminderId = 1;
    sptr<ReminderRequest> reminder = new ReminderRequest(reminderId);
    reminder->InitNotificationRequest();
    EXPECT_EQ(advancedNotificationService_->PublishReminder(reminder), ERR_ANS_INVALID_BUNDLE);
    MockIsNonBundleName(false);
    GTEST_LOG_(INFO) << "GetAppTargetBundle_2000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_18100
 * @tc.name      : ActiveNotificationDump_1000
 * @tc.desc      : Test ActiveNotificationDump function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18100, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ActiveNotificationDump_1000 test start";

    std::string bundle = "Bundle";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;

    EXPECT_EQ(advancedNotificationService_->ActiveNotificationDump(bundle, userId, userId, dumpInfo), ERR_OK);

    GTEST_LOG_(INFO) << "ActiveNotificationDump_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_18200
 * @tc.name      : RecentNotificationDump_1000
 * @tc.desc      : Test RecentNotificationDump function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18200, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "RecentNotificationDump_1000 test start";

    std::string bundle = "Bundle";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;

    EXPECT_EQ(advancedNotificationService_->RecentNotificationDump(bundle, userId, userId, dumpInfo), ERR_OK);

    GTEST_LOG_(INFO) << "RecentNotificationDump_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_18300
 * @tc.name      : DistributedNotificationDump_1000
 * @tc.desc      : Test DistributedNotificationDump function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18300, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "DistributedNotificationDump_1000 test start";

    std::string bundle = "Bundle";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;

    EXPECT_EQ(advancedNotificationService_->DistributedNotificationDump(bundle, userId, userId, dumpInfo), ERR_OK);

    GTEST_LOG_(INFO) << "DistributedNotificationDump_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_18400
 * @tc.name      : SetRecentNotificationCount_1000
 * @tc.desc      : Test SetRecentNotificationCount function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18400, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "SetRecentNotificationCount_1000 test start";

    std::string arg = "1100";
    EXPECT_EQ(advancedNotificationService_->SetRecentNotificationCount(arg), ERR_ANS_INVALID_PARAM);

    GTEST_LOG_(INFO) << "SetRecentNotificationCount_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_18500
 * @tc.name      : OnBundleRemoved_1000
 * @tc.desc      : Test OnBundleRemoved function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18500, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "OnBundleRemoved_1000 test start";

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->OnBundleRemoved(bundleOption);

    GTEST_LOG_(INFO) << "OnBundleRemoved_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_18600
 * @tc.name      : OnScreenOn_1000
 * @tc.desc      : Test OnScreenOn function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18600, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "OnScreenOn_1000 test start";

    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->OnScreenOn();
    advancedNotificationService_->OnScreenOff();

    GTEST_LOG_(INFO) << "OnScreenOn_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_18700
 * @tc.name      : AddSlotByType_1000
 * @tc.desc      : Test AddSlotByType function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18700, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AddSlotByType_1000 test start";
    MockSystemApp();
    EXPECT_EQ(advancedNotificationService_->AddSlotByType(NotificationConstant::SlotType::SERVICE_REMINDER),
        ERR_OK);

    GTEST_LOG_(INFO) << "AddSlotByType_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_18800
 * @tc.name      : GetSlotNumAsBundle_1000
 * @tc.desc      : Test GetSlotNumAsBundle function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18800, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetSlotNumAsBundle_1000 test start";

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    uint64_t num = 1;
    EXPECT_EQ(advancedNotificationService_->GetSlotNumAsBundle(bundleOption, num), ERR_OK);

    GTEST_LOG_(INFO) << "GetSlotNumAsBundle_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_18900
 * @tc.name      : CancelGroup_1000
 * @tc.desc      : Test CancelGroup function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_18900, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "CancelGroup_1000 test start";

    std::string groupName = "";
    EXPECT_EQ(advancedNotificationService_->CancelGroup(groupName), ERR_ANS_INVALID_PARAM);

    GTEST_LOG_(INFO) << "CancelGroup_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19000
 * @tc.name      : RemoveGroupByBundle_1000
 * @tc.desc      : Test RemoveGroupByBundle function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19000, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "RemoveGroupByBundle_1000 test start";

    std::string groupName = "group";
    sptr<NotificationBundleOption> bundleOption = nullptr;
    EXPECT_EQ(advancedNotificationService_->RemoveGroupByBundle(bundleOption, groupName), ERR_ANS_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RemoveGroupByBundle_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19100
 * @tc.name      : ANS_IsDistributedEnabled_0100
 * @tc.desc      : Test IsDistributedEnabled function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19100, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "ANS_IsDistributedEnabled_0100 test start";

    bool enabled = false;
    EXPECT_EQ(advancedNotificationService_->IsDistributedEnabled(enabled), ERR_OK);

    GTEST_LOG_(INFO) << "ANS_IsDistributedEnabled_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19200
 * @tc.name      : EnableDistributedByBundle_0100
 * @tc.desc      : Test EnableDistributedByBundle function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19200, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "EnableDistributedByBundle_0100 test start";

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    bool enabled = false;
    EXPECT_EQ(advancedNotificationService_->EnableDistributedByBundle(bundleOption, enabled), ERR_OK);

    GTEST_LOG_(INFO) << "EnableDistributedByBundle_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19300
 * @tc.name      : IsDistributedEnableByBundle_0100
 * @tc.desc      : Test IsDistributedEnableByBundle function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19300, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsDistributedEnableByBundle_0100 test start";

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    bool enabled = true;
    EXPECT_EQ(advancedNotificationService_->IsDistributedEnableByBundle(bundleOption, enabled), ERR_OK);

    GTEST_LOG_(INFO) << "IsDistributedEnableByBundle_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19400
 * @tc.name      : IsDistributedEnableByBundle_0200
 * @tc.desc      : Test IsDistributedEnableByBundle function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19400, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsDistributedEnableByBundle_0200 test start";

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    bool enabled = false;
    EXPECT_EQ(advancedNotificationService_->IsDistributedEnableByBundle(bundleOption, enabled), ERR_OK);

    GTEST_LOG_(INFO) << "IsDistributedEnableByBundle_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19500
 * @tc.name      : GetDeviceRemindType_0100
 * @tc.desc      : Test GetDeviceRemindType function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19500, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetDeviceRemindType_0100 test start";

    NotificationConstant::RemindType remindType = NotificationConstant::RemindType::DEVICE_ACTIVE_REMIND;
    EXPECT_EQ(advancedNotificationService_->GetDeviceRemindType(remindType), ERR_OK);

    GTEST_LOG_(INFO) << "GetDeviceRemindType_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19600
 * @tc.name      : GetLocalNotificationKeys_0100
 * @tc.desc      : Test GetLocalNotificationKeys function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19600, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetLocalNotificationKeys_0100 test start";

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->GetLocalNotificationKeys(bundleOption);

    GTEST_LOG_(INFO) << "GetLocalNotificationKeys_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19700
 * @tc.name      : CheckDistributedNotificationType_0100
 * @tc.desc      : Test CheckDistributedNotificationType function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19700, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "CheckDistributedNotificationType_0100 test start";

    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_EQ(advancedNotificationService_->CheckDistributedNotificationType(req), true);

    GTEST_LOG_(INFO) << "CheckDistributedNotificationType_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19800
 * @tc.name      : CheckDistributedNotificationType_0200
 * @tc.desc      : Test CheckDistributedNotificationType function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19800, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "CheckDistributedNotificationType_0200 test start";

    sptr<NotificationRequest> req = new NotificationRequest();
    std::vector<std::string> devices;
    devices.push_back("a");
    devices.push_back("b");
    devices.push_back("c");
    req->GetNotificationDistributedOptions().SetDevicesSupportDisplay(devices);
    EXPECT_EQ(advancedNotificationService_->CheckDistributedNotificationType(req), true);

    GTEST_LOG_(INFO) << "CheckDistributedNotificationType_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19900
 * @tc.name      : OnDistributedPublish_0100
 * @tc.desc      : Test OnDistributedPublish function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19900, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "CheckDistributedNotificationType_0100 test start";

    std::string deviceId = "DeviceId";
    std::string bundleName = "BundleName";
    sptr<NotificationRequest> request = new NotificationRequest();

    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->OnDistributedPublish(deviceId, bundleName, request);

    GTEST_LOG_(INFO) << "CheckDistributedNotificationType_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_20000
 * @tc.name      : OnDistributedUpdate_0100
 * @tc.desc      : Test OnDistributedUpdate function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_20000, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "OnDistributedUpdate_0100 test start";

    std::string deviceId = "DeviceId";
    std::string bundleName = "BundleName";
    sptr<NotificationRequest> request = new NotificationRequest();

    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->OnDistributedUpdate(deviceId, bundleName, request);

    GTEST_LOG_(INFO) << "OnDistributedUpdate_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_20100
 * @tc.name      : OnDistributedDelete_0100
 * @tc.desc      : Test OnDistributedDelete function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_20100, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "OnDistributedDelete_0100 test start";

    std::string deviceId = "DeviceId";
    std::string bundleName = "BundleName";
    std::string label = "testLabel";
    int32_t id = 1;

    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->OnDistributedDelete(deviceId, bundleName, label, id);

    GTEST_LOG_(INFO) << "OnDistributedDelete_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_20200
 * @tc.name      : CheckPublishWithoutApp_0100
 * @tc.desc      : Test CheckPublishWithoutApp function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_20200, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "CheckPublishWithoutApp_0100 test start";

    int32_t userId = 1;
    sptr<NotificationRequest> request = new NotificationRequest();
    EXPECT_EQ(advancedNotificationService_->CheckPublishWithoutApp(userId, request), false);

    GTEST_LOG_(INFO) << "CheckPublishWithoutApp_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_20300
 * @tc.name      : CheckPublishWithoutApp_0200
 * @tc.desc      : Test CheckPublishWithoutApp function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_20300, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "CheckPublishWithoutApp_0200 test start";

    int32_t userId = SYSTEM_APP_UID;
    sptr<NotificationRequest> request = new NotificationRequest();
    EXPECT_EQ(advancedNotificationService_->CheckPublishWithoutApp(userId, request), false);

    GTEST_LOG_(INFO) << "CheckPublishWithoutApp_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_20400
 * @tc.name      : TriggerRemoveWantAgent_0100
 * @tc.desc      : Test TriggerRemoveWantAgent function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_20400, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "TriggerRemoveWantAgent_0100 test start";

    sptr<NotificationRequest> request = new NotificationRequest();
    AbilityRuntime::WantAgent::WantAgentInfo paramsInfo;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(paramsInfo);

    request->SetRemovalWantAgent(wantAgent);
    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->TriggerRemoveWantAgent(request);

    GTEST_LOG_(INFO) << "TriggerRemoveWantAgent_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_20500
 * @tc.name      : DeleteAllByUser_0100
 * @tc.desc      : Test DeleteAllByUser function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_20500, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "DeleteAllByUser_0100 test start";

    int32_t userId = -2;
    EXPECT_EQ(advancedNotificationService_->DeleteAllByUser(userId), ERR_ANS_INVALID_PARAM);

    sptr<NotificationDoNotDisturbDate> date = nullptr;
    EXPECT_EQ(advancedNotificationService_->SetDoNotDisturbDate(userId, date), ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(advancedNotificationService_->GetDoNotDisturbDate(userId, date), ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(advancedNotificationService_->SetDoNotDisturbDateByUser(userId, date), ERR_ANS_INVALID_PARAM);
    GTEST_LOG_(INFO) << "DeleteAllByUser_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_20600
 * @tc.name      : OnResourceRemove_0100
 * @tc.desc      : Test OnResourceRemove function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_20600, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "OnResourceRemove_0100 test start";

    int32_t userId = -2;
    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->OnResourceRemove(userId);

    GTEST_LOG_(INFO) << "OnResourceRemove_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_20700
 * @tc.name      : OnBundleDataCleared_0100
 * @tc.desc      : Test OnBundleDataCleared function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_20700, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "OnBundleDataCleared_0100 test start";

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->OnBundleDataCleared(bundleOption);

    GTEST_LOG_(INFO) << "OnBundleDataCleared_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_20900
 * @tc.name      : GetDumpInfo_0100
 * @tc.desc      : Test GetDumpInfo function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_20900, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetDumpInfo_0100 test start";

    std::vector<std::u16string> args;
    args.push_back(Str8ToStr16("args"));
    std::string result = "result";
    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->GetDumpInfo(args, result);

    GTEST_LOG_(INFO) << "GetDumpInfo_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_21000
 * @tc.name      : GetDumpInfo_0200
 * @tc.desc      : Test GetDumpInfo function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21000, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetDumpInfo_0200 test start";

    std::vector<std::u16string> args;
    args.push_back(Str8ToStr16("-h"));
    std::string result = "result";
    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->GetDumpInfo(args, result);

    GTEST_LOG_(INFO) << "GetDumpInfo_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_21100
 * @tc.name      : SendFlowControlOccurHiSysEvent_0100
 * @tc.desc      : Test SendFlowControlOccurHiSysEvent function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21100, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "SendFlowControlOccurHiSysEvent_0100 test start";

    std::shared_ptr<NotificationRecord> record = nullptr;
    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->SendFlowControlOccurHiSysEvent(record);

    GTEST_LOG_(INFO) << "SendFlowControlOccurHiSysEvent_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_21200
 * @tc.name      : SendFlowControlOccurHiSysEvent_0200
 * @tc.desc      : Test SendFlowControlOccurHiSysEvent function
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21200, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "SendFlowControlOccurHiSysEvent_0200 test start";

    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = new NotificationRequest();
    record->bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    ASSERT_NE(nullptr, advancedNotificationService_);
    advancedNotificationService_->SendFlowControlOccurHiSysEvent(record);

    GTEST_LOG_(INFO) << "SendFlowControlOccurHiSysEvent_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_21300
 * @tc.name      : PrepareNotificationRequest_0200
 * @tc.desc      : Test PrepareNotificationRequest function when uid < 0.
 * @tc.require   : issueI62D8C
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21300, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "PrepareNotificationRequest_0200 test start";
    sptr<NotificationRequest> req = new NotificationRequest();
    int32_t myNotificationId = 10;
    bool isAgentTrue = true;
    NotificationRequest notificationRequest(myNotificationId);
    notificationRequest.SetIsAgentNotification(isAgentTrue);

    std::shared_ptr<BundleManagerHelper> bundleManager = nullptr;

    EXPECT_EQ(advancedNotificationService_->PrepareNotificationRequest(req), ERR_OK);
    GTEST_LOG_(INFO) << "PrepareNotificationRequest_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_21400
 * @tc.name      : PrepareNotificationInfo_2000
 * @tc.desc      : Test PrepareNotificationInfo function.
 * @tc.require   : issueI62D8C
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21400, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "PrepareNotificationInfo_2000 test start";

    sptr<NotificationRequest> req = new (std::nothrow) NotificationRequest(1);
    EXPECT_NE(req, nullptr);
    sptr<NotificationBundleOption> bundleOption = nullptr;

    EXPECT_EQ(advancedNotificationService_->PrepareNotificationInfo(req, bundleOption), ERR_OK);

    GTEST_LOG_(INFO) << "PrepareNotificationInfo_2000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_21500
 * @tc.name      : PublishPreparedNotification_1000
 * @tc.desc      : Test PublishPreparedNotification function.
 * @tc.require   : issueI62D8C
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21500, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "PublishPreparedNotification_1000 test start";

    sptr<NotificationRequest> req = new (std::nothrow) NotificationRequest();
    sptr<Notification> notification = new (std::nothrow) Notification(req);
    EXPECT_NE(notification, nullptr);
    sptr<NotificationBundleOption> bundleOption = nullptr;

    EXPECT_EQ(advancedNotificationService_->PublishPreparedNotification(req, bundleOption), ERR_ANS_INVALID_PARAM);

    GTEST_LOG_(INFO) << "PublishPreparedNotification_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_21600
 * @tc.name      : RegisterPushCallback_0100
 * @tc.desc      : Test RegisterPushCallback function.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21600, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "RegisterPushCallback_0100 test start";

    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    sptr<IRemoteObject> pushCallback = pushCallbackProxy->AsObject();
    sptr<NotificationCheckRequest> checkRequest = new (std::nothrow) NotificationCheckRequest();
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    EXPECT_EQ(advancedNotificationService_->RegisterPushCallback(pushCallback, checkRequest), ERR_OK);

    advancedNotificationService_->UnregisterPushCallback();

    GTEST_LOG_(INFO) << "RegisterPushCallback_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_21700
 * @tc.name      : RegisterPushCallback_0200
 * @tc.desc      : Test RegisterPushCallback function.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21700, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "RegisterPushCallback_0200 test start";

    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    sptr<IRemoteObject> pushCallback = pushCallbackProxy->AsObject();
    sptr<NotificationCheckRequest> checkRequest = new (std::nothrow) NotificationCheckRequest();
    EXPECT_EQ(advancedNotificationService_->RegisterPushCallback(pushCallback, checkRequest),
        (int)ERR_OK);
    advancedNotificationService_->UnregisterPushCallback();


    GTEST_LOG_(INFO) << "RegisterPushCallback_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_21800
 * @tc.name      : RegisterPushCallback_0200
 * @tc.desc      : Test RegisterPushCallback function.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21800, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "RegisterPushCallback_0300 test start";

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    sptr<IRemoteObject> pushCallback = pushCallbackProxy->AsObject();
    sptr<IPushCallBack> pushCallBack = iface_cast<IPushCallBack>(pushCallback);
    sptr<NotificationCheckRequest> checkRequest = new (std::nothrow) NotificationCheckRequest();

    advancedNotificationService_->pushCallBacks_.insert_or_assign(checkRequest->GetSlotType(), pushCallBack);

    EXPECT_EQ(advancedNotificationService_->RegisterPushCallback(pushCallback, checkRequest), (int)ERR_OK);

    advancedNotificationService_->UnregisterPushCallback();

    GTEST_LOG_(INFO) << "RegisterPushCallback_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_21900
 * @tc.name      : UnregisterPushCallback_0100
 * @tc.desc      : Test UnregisterPushCallback function.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_21900, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "UnregisterPushCallback_0100 test start";

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    sptr<IRemoteObject> pushCallback = pushCallbackProxy->AsObject();
    sptr<IPushCallBack> pushCallBack = iface_cast<IPushCallBack>(pushCallback);
    sptr<NotificationCheckRequest> checkRequest = new (std::nothrow) NotificationCheckRequest();

    advancedNotificationService_->pushCallBacks_.insert_or_assign(checkRequest->GetSlotType(), pushCallBack);

    EXPECT_EQ(advancedNotificationService_->UnregisterPushCallback(), ERR_OK);

    GTEST_LOG_(INFO) << "UnregisterPushCallback_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_22000
 * @tc.name      : UnregisterPushCallback_0200
 * @tc.desc      : Test UnregisterPushCallback function.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_22000, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "UnregisterPushCallback_0200 test start";
    EXPECT_EQ(advancedNotificationService_->UnregisterPushCallback(), (int)ERR_ANS_NON_SYSTEM_APP);

    GTEST_LOG_(INFO) << "UnregisterPushCallback_0200 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_22100
 * @tc.name      : UnregisterPushCallback_0300
 * @tc.desc      : Test UnregisterPushCallback function.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_22100, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "UnregisterPushCallback_0300 test start";

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    EXPECT_EQ(advancedNotificationService_->UnregisterPushCallback(), (int)ERR_INVALID_OPERATION);

    GTEST_LOG_(INFO) << "UnregisterPushCallback_0300 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_22500
 * @tc.name      : PushCheck_0100
 * @tc.desc      : Test PushCheck function.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_22500, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "PushCheck_0100 test start";

    sptr<NotificationRequest> req = new (std::nothrow) NotificationRequest();
    EXPECT_EQ(advancedNotificationService_->PushCheck(req), ERR_ANS_PUSH_CHECK_UNREGISTERED);

    GTEST_LOG_(INFO) << "PushCheck_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_220000
 * @tc.name      : TimeToString_1000
 * @tc.desc      : Test TimeToString function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_220000, Function | SmallTest | Level1)
{
    int64_t time = 60;
    int64_t ret = 20;
    std::string result = advancedNotificationService_->TimeToString(time);
    EXPECT_EQ(result.size(), ret);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00001
 * @tc.name      : PrepareNotificationRequest
 * @tc.desc      : Test PrepareNotificationRequest function.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00001 test start";
    EXPECT_EQ(advancedNotificationService_->PrepareNotificationRequest(nullptr), ERR_ANS_INVALID_PARAM);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00001 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00002
 * @tc.name      : IsNotificationExists
 * @tc.desc      : Test IsNotificationExists function.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00002, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00002 test start";
    std::string key = "aa";
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    EXPECT_NE(request, nullptr);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    EXPECT_NE(notification, nullptr);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    EXPECT_EQ(advancedNotificationService_->IsNotificationExists(key), false);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00002 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00003
 * @tc.name      : UpdateInNotificationList
 * @tc.desc      : Test UpdateInNotificationList function and notificationList_ is not empty.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00003, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00003 test start";
    std::string key = "aa";
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    EXPECT_NE(request, nullptr);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    EXPECT_NE(notification, nullptr);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    advancedNotificationService_->UpdateInNotificationList(record);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00003 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00004
 * @tc.name      : SetBadgeNumber
 * @tc.desc      : Test SetBadgeNumber function and handler_ is nullptr.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00004, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00004 test start";
    int32_t badgeNumber = 1;
    EXPECT_EQ(advancedNotificationService_->SetBadgeNumber(badgeNumber), ERR_OK);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00004 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00005
 * @tc.name      : SetBadgeNumber
 * @tc.desc      : Test SetBadgeNumber function and handler_ is not nullptr.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00005, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00005 test start";
    int32_t badgeNumber = 1;
    advancedNotificationService_->runner_ = OHOS::AppExecFwk::EventRunner::Create("NotificationSvrMain");
    advancedNotificationService_->handler_ =
        std::make_shared<OHOS::AppExecFwk::EventHandler>(advancedNotificationService_->runner_);
    EXPECT_EQ(advancedNotificationService_->SetBadgeNumber(badgeNumber), ERR_OK);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00005 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00006
 * @tc.name      : ResetPushCallbackProxy
 * @tc.desc      : Test ResetPushCallbackProxy function and pushCallBack_ is nullptr.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00006, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00006 test start";
    EXPECT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->ResetPushCallbackProxy();
    ASSERT_EQ(advancedNotificationService_->pushCallBacks_.empty(), true);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00006 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00007
 * @tc.name      : ResetPushCallbackProxy
 * @tc.desc      : Test ResetPushCallbackProxy function and pushCallBack_ is not nullptr.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00007, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00007 test start";
    EXPECT_NE(advancedNotificationService_, nullptr);
    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    sptr<IRemoteObject> pushCallback = pushCallbackProxy->AsObject();
    sptr<IPushCallBack> pushCallBack = iface_cast<IPushCallBack>(pushCallback);
    sptr<NotificationCheckRequest> checkRequest = new (std::nothrow) NotificationCheckRequest();

    advancedNotificationService_->pushCallBacks_.insert_or_assign(checkRequest->GetSlotType(), pushCallBack);
    advancedNotificationService_->ResetPushCallbackProxy();
    ASSERT_TRUE(advancedNotificationService_->pushCallBacks_.empty());
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00007 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00008
 * @tc.name      : SendEnableNotificationSlotHiSysEvent
 * @tc.desc      : Test SendEnableNotificationSlotHiSysEvent function and bundleOption is nullptr.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00008, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00008 test start";
    sptr<NotificationBundleOption> bundleOption = nullptr;
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::CONTENT_INFORMATION;
    bool enabled = false;
    ErrCode errCode = ERR_OK;
    EXPECT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->SendEnableNotificationSlotHiSysEvent(bundleOption, slotType, enabled, errCode);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00008 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00009
 * @tc.name      : SendEnableNotificationSlotHiSysEvent
 * @tc.desc      : Test SendEnableNotificationSlotHiSysEvent function and errCode != ERR_OK.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00009, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00009 test start";
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::CONTENT_INFORMATION;
    bool enabled = false;
    ErrCode errCode = ERR_ANS_TASK_ERR;
    EXPECT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->SendEnableNotificationSlotHiSysEvent(bundleOption, slotType, enabled, errCode);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00009 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00010
 * @tc.name      : SendRemoveHiSysEvent
 * @tc.desc      : Test SendRemoveHiSysEvent function and errCode is ERR_OK bundleOption is not nullptr.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00010, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00010 test start";
    int32_t notificationId = 1;
    std::string label = "aa";
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    ErrCode errCode = ERR_OK;
    EXPECT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->SendRemoveHiSysEvent(notificationId, label, bundleOption, errCode);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00010 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00011
 * @tc.name      : SendEnableNotificationHiSysEvent
 * @tc.desc      : Test SendEnableNotificationHiSysEvent function andbundleOption is nullptr.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00011, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00011 test start";
    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool enabled = false;
    ErrCode errCode = ERR_ANS_TASK_ERR;
    EXPECT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->SendEnableNotificationHiSysEvent(bundleOption, enabled, errCode);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00011 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00012
 * @tc.name      : SendCancelHiSysEvent
 * @tc.desc      : Test SendCancelHiSysEvent function and errCode is ERR_OK bundleOption is not nullptr.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00012, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00012 test start";
    int32_t notificationId = 1;
    std::string label = "aa";
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    ErrCode errCode = ERR_OK;
    EXPECT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->SendCancelHiSysEvent(notificationId, label, bundleOption, errCode);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00012 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00013
 * @tc.name      : SendPublishHiSysEvent
 * @tc.desc      : Test SendPublishHiSysEvent function and request is nullptr.
 * @tc.require   : #I6Z5I4
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00013, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00013 test start";
    sptr<NotificationRequest> request = nullptr;
    ErrCode errCode = ERR_OK;
    EXPECT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->SendPublishHiSysEvent(request, errCode);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00013 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00014
 * @tc.name      : GetTargetRecordList
 * @tc.desc      : Test GetTargetRecordList function and get empty.
 * @tc.require   : #I8B8PI
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00014, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00014 test start";
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = new NotificationRequest();
    record->bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    std::string bundleName = "testBundle";
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    auto contentType = NotificationContent::Type::LOCAL_LIVE_VIEW;
    advancedNotificationService_->notificationList_.clear();
    std::vector<std::shared_ptr<NotificationRecord>> recordList;
    EXPECT_EQ(advancedNotificationService_->GetTargetRecordList(bundleName, slotType, contentType, recordList),
        ERR_ANS_NOTIFICATION_NOT_EXISTS);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00014 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00015
 * @tc.name      : GetTargetRecordList
 * @tc.desc      : Test GetTargetRecordList function and get success.
 * @tc.require   : #I8B8PI
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00015, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00015 test start";
    std::string bundleName = "testBundle";
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    auto contentType = NotificationContent::Type::LOCAL_LIVE_VIEW;

    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    EXPECT_NE(request, nullptr);
    request->SetSlotType(slotType);
    auto liveContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    request->SetOwnerBundleName(bundleName);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    EXPECT_NE(notification, nullptr);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    std::vector<std::shared_ptr<NotificationRecord>> recordList;
    EXPECT_EQ(advancedNotificationService_->GetTargetRecordList(bundleName, slotType, contentType, recordList),
        ERR_OK);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00015 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00016
 * @tc.name      : RemoveNotificationFromRecordList
 * @tc.desc      : Test RemoveNotificationFromRecordList function and remove success.
 * @tc.require   : #I8B8PI
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00016, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00016 test start";
    std::string bundleName = "testBundle";
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    auto contentType = NotificationContent::Type::LOCAL_LIVE_VIEW;

    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    EXPECT_NE(request, nullptr);
    request->SetSlotType(slotType);
    auto liveContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    request->SetOwnerBundleName(bundleName);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    EXPECT_NE(notification, nullptr);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    std::vector<std::shared_ptr<NotificationRecord>> recordList;
    recordList.push_back(record);
    EXPECT_EQ(advancedNotificationService_->RemoveNotificationFromRecordList(recordList), ERR_OK);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00016 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00017
 * @tc.name      : RemoveSystemLiveViewNotifications
 * @tc.desc      : Test RemoveNotificationFromRecordList function and remove success.
 * @tc.require   : #I8B8PI
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00017, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00016 test start";
    std::string bundleName = "testBundle";
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    EXPECT_NE(request, nullptr);
    request->SetSlotType(slotType);
    auto liveContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    request->SetOwnerBundleName(bundleName);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    EXPECT_NE(notification, nullptr);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    int32_t uid = 0;
    EXPECT_EQ(advancedNotificationService_->RemoveSystemLiveViewNotifications(bundleName, uid), ERR_OK);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00017 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00018
 * @tc.name      : RemoveSystemLiveViewNotifications
 * @tc.desc      : Test RemoveNotificationFromRecordList function and remove success.
 * @tc.require   : #I8B8PI
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00018, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00018 test start";
    std::string bundleName = "testBundle";
    int32_t uid = 0;
    EXPECT_EQ(advancedNotificationService_->RemoveSystemLiveViewNotifications(bundleName, uid),
        ERR_ANS_NOTIFICATION_NOT_EXISTS);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00018 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00019
 * @tc.name      : RemoveSystemLiveViewNotifications
 * @tc.desc      : Test RemoveNotificationFromRecordList function and remove success.
 * @tc.require   : #I8B8PI
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00019, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00019 test start";
    std::string bundleName = "testBundle";
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    EXPECT_NE(request, nullptr);
    request->SetSlotType(slotType);
    auto liveContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    request->SetOwnerBundleName(bundleName);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    EXPECT_NE(notification, nullptr);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->notificationList_.push_back(record);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    int32_t uid = 0;
    EXPECT_EQ(advancedNotificationService_->RemoveSystemLiveViewNotifications(bundleName, uid), ERR_ANS_INVALID_PARAM);
    GTEST_LOG_(INFO) << "AdvancedNotificationServiceTest_00019 test end";
}
/**
 * @tc.number    : IsLiveViewCanRecoverTest_0001
 * @tc.name      : IsLiveViewCanRecover
 * @tc.desc      : Test IsLiveViewCanRecover and liveview is nullptr.
 */
HWTEST_F(AdvancedNotificationServiceTest, IsLiveViewCanRecoverTest_0001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsLiveViewCanRecoverTest_0001 test start";
    EXPECT_EQ(advancedNotificationService_->IsLiveViewCanRecover(nullptr), false);
    GTEST_LOG_(INFO) << "IsLiveViewCanRecoverTest_0001 test end";
}

/**
 * @tc.number    : IsLiveViewCanRecoverTest_0002
 * @tc.name      : IsLiveViewCanRecover
 * @tc.desc      : Test IsLiveViewCanRecover and liveview status is invalid.
 */
HWTEST_F(AdvancedNotificationServiceTest, IsLiveViewCanRecoverTest_0002, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsLiveViewCanRecoverTest_0002 test start";
    sptr<NotificationRequest> request = new NotificationRequest();
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    request->SetContent(content);

    EXPECT_EQ(advancedNotificationService_->IsLiveViewCanRecover(request), false);
    GTEST_LOG_(INFO) << "IsLiveViewCanRecoverTest_0002 test end";
}

/**
 * @tc.number    : IsLiveViewCanRecoverTest_0003
 * @tc.name      : IsLiveViewCanRecover
 * @tc.desc      : Test IsLiveViewCanRecover and liveview is expired.
 */
HWTEST_F(AdvancedNotificationServiceTest, IsLiveViewCanRecoverTest_0003, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsLiveViewCanRecoverTest_0003 test start";
    sptr<NotificationRequest> request = new NotificationRequest();
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    request->SetContent(content);
    request->SetFinishDeadLine(0);

    EXPECT_EQ(advancedNotificationService_->IsLiveViewCanRecover(request), false);
    GTEST_LOG_(INFO) << "IsLiveViewCanRecoverTest_0003 test end";
}

/**
 * @tc.number    : IsLiveViewCanRecoverTest_0004
 * @tc.name      : IsLiveViewCanRecover
 * @tc.desc      : Test IsLiveViewCanRecover and liveview status is create and not expired.
 */
HWTEST_F(AdvancedNotificationServiceTest, IsLiveViewCanRecoverTest_0004, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsLiveViewCanRecoverTest_0004 test start";
    sptr<NotificationRequest> request = new NotificationRequest();
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    request->SetContent(content);

    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    request->SetFinishDeadLine(duration.count() + NotificationConstant::MAX_FINISH_TIME);
    request->SetUpdateDeadLine(duration.count() + NotificationConstant::MAX_UPDATE_TIME);

    EXPECT_EQ(advancedNotificationService_->IsLiveViewCanRecover(request), true);
    GTEST_LOG_(INFO) << "IsLiveViewCanRecoverTest_0004 test end";
}

/**
 * @tc.number    : FillNotificationRecordTest_0001
 * @tc.name      : FillNotificationRecord
 * @tc.desc      : Test FillNotificationRecord and request is nullptr.
 */
HWTEST_F(AdvancedNotificationServiceTest, FillNotificationRecordTest_0001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FillNotificationRecordTest_0001 test start";
    AdvancedNotificationService::NotificationRequestDb requestDbObj = { .request = nullptr, .bundleOption = nullptr};
    auto record = std::make_shared<NotificationRecord>();

    EXPECT_NE(advancedNotificationService_->FillNotificationRecord(requestDbObj, record), ERR_OK);
    GTEST_LOG_(INFO) << "FillNotificationRecordTest_0001 test end";
}

/**
 * @tc.number    : FillNotificationRecordTest_0002
 * @tc.name      : FillNotificationRecord
 * @tc.desc      : Test FillNotificationRecord and request/bundleOption is valid.
 */
HWTEST_F(AdvancedNotificationServiceTest, FillNotificationRecordTest_0002, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FillNotificationRecordTest_0002 test start";
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    std::string bundleName = "BundleName";
    int32_t uid = 10;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(bundleName, uid);
    AdvancedNotificationService::NotificationRequestDb requestDbObj =
        { .request = request, .bundleOption = bundleOption };
    auto record = std::make_shared<NotificationRecord>();

    EXPECT_EQ(advancedNotificationService_->FillNotificationRecord(requestDbObj, record), ERR_OK);
    GTEST_LOG_(INFO) << "FillNotificationRecordTest_0002 test end";
}

/**
 * @tc.number    : RecoverLiveViewFromDb_0001
 * @tc.name      : RecoverLiveViewFromDb
 * @tc.desc      : Test RecoverLiveViewFromDb.
 */
HWTEST_F(AdvancedNotificationServiceTest, RecoverLiveViewFromDb_0001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "RecoverLiveViewFromDb_0001 test start";
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest(1);
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    request->SetContent(content);
    request->SetCreatorUid(0);
    request->SetCreatorUserId(1);
    request->SetLabel("test");
    request->SetReceiverUserId(100);

    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    request->SetFinishDeadLine(duration.count() + NotificationConstant::MAX_FINISH_TIME);
    request->SetUpdateDeadLine(duration.count() + NotificationConstant::MAX_UPDATE_TIME);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    std::string bundleName = "BundleName_01";
    int32_t uid = 10;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(bundleName, uid);
    AdvancedNotificationService::NotificationRequestDb requestDbObj =
        { .request = request, .bundleOption = bundleOption };
    auto result = advancedNotificationService_->SetNotificationRequestToDb(requestDbObj);
    EXPECT_EQ(result, ERR_OK);

    advancedNotificationService_->RecoverLiveViewFromDb();
    EXPECT_NE(advancedNotificationService_->notificationList_.size(), 0);

    advancedNotificationService_->notificationList_.clear();
    result = advancedNotificationService_->DeleteNotificationRequestFromDb(request->GetKey(), 0);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RecoverLiveViewFromDb_0001 test end";
}

/**
 * @tc.number    : RecoverLiveViewFromDb_0002
 * @tc.name      : RecoverLiveViewFromDb
 * @tc.desc      : Test RecoverLiveViewFromDb and liveView can't recover from db.
 */
HWTEST_F(AdvancedNotificationServiceTest, RecoverLiveViewFromDb_0002, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "RecoverLiveViewFromDb_0002 test start";
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest(1);
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    request->SetContent(content);
    request->SetCreatorUid(1);
    request->SetCreatorUserId(2);
    request->SetLabel("test_2");

    std::string bundleName = "BundleName_02";
    int32_t uid = 11;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(bundleName, uid);
    AdvancedNotificationService::NotificationRequestDb requestDbObj =
        { .request = request, .bundleOption = bundleOption };
    auto result = advancedNotificationService_->SetNotificationRequestToDb(requestDbObj);
    EXPECT_EQ(result, ERR_OK);

    advancedNotificationService_->RecoverLiveViewFromDb();
    EXPECT_EQ(advancedNotificationService_->notificationList_.size(), 0);

    result = advancedNotificationService_->DeleteNotificationRequestFromDb(request->GetKey(), 0);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RecoverLiveViewFromDb_0002 test end";
}

/**
 * @tc.number    : IsNeedPushCheckTest_0001
 * @tc.name      : IsNeedPushCheckTest
 * @tc.desc      : Test live view notification need pushCheck.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedPushCheckTest_0001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0001 test start";
    sptr<NotificationRequest> request = new NotificationRequest();
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto status = NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE;
    liveViewContent->SetLiveViewStatus(status);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    EXPECT_EQ(advancedNotificationService_->IsNeedPushCheck(request), true);

    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0001 test end";
}

/**
 * @tc.number    : IsNeedPushCheckTest_0002
 * @tc.name      : IsNeedPushCheckTest
 * @tc.desc      : Test notification except live view registered need push check.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedPushCheckTest_0002, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0002 test start";

    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    sptr<IRemoteObject> pushCallback = pushCallbackProxy->AsObject();
    sptr<IPushCallBack> pushCallBack = iface_cast<IPushCallBack>(pushCallback);

    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);

    advancedNotificationService_->pushCallBacks_.clear();
    advancedNotificationService_->checkRequests_.clear();
    sptr<NotificationCheckRequest> notificationCheckRequest = new (std::nothrow)NotificationCheckRequest();
    notificationCheckRequest->SetSlotType(NotificationConstant::SlotType::CUSTOM);
    notificationCheckRequest->SetContentType(NotificationContent::Type::BASIC_TEXT);
    advancedNotificationService_->pushCallBacks_.insert_or_assign(
        notificationCheckRequest->GetSlotType(), pushCallBack);
    advancedNotificationService_->checkRequests_.insert_or_assign(
        notificationCheckRequest->GetSlotType(), notificationCheckRequest);

    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::CUSTOM);
    EXPECT_EQ(advancedNotificationService_->IsNeedPushCheck(request), true);
    advancedNotificationService_->pushCallBacks_.clear();
    advancedNotificationService_->checkRequests_.clear();

    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0002 test end";
}

/**
 * @tc.number    : IsNeedPushCheckTest_0003
 * @tc.name      : IsNeedPushCheckTest
 * @tc.desc      : Test notification except live view unregistered don't need push check.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedPushCheckTest_0003, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0003 test start";
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::CUSTOM);
    EXPECT_EQ(advancedNotificationService_->IsNeedPushCheck(request), false);

    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0003 test end";
}

/**
 * @tc.number    : IsNeedPushCheckTest_0004
 * @tc.name      : IsNeedPushCheckTest
 * @tc.desc      : Test notification published by system app don't need push check.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedPushCheckTest_0004, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0004 test start";

    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::CUSTOM);
    EXPECT_EQ(advancedNotificationService_->IsNeedPushCheck(request), false);

    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0004 test end";
}

/**
 * @tc.number    : IsNeedPushCheckTest_0005
 * @tc.name      : IsNeedPushCheckTest
 * @tc.desc      : Test live view notification except create status don't need pushCheck.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedPushCheckTest_0005, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0005 test start";
    sptr<NotificationRequest> request = new NotificationRequest();
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto status = NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE;
    liveViewContent->SetLiveViewStatus(status);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    EXPECT_EQ(advancedNotificationService_->IsNeedPushCheck(request), false);

    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0005 test end";
}

/**
 * @tc.number    : IsNeedPushCheckTest_0006
 * @tc.name      : IsNeedPushCheckTest
 * @tc.desc      : Test notification except live view registered but has inconsistent contentType dont't need push check.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedPushCheckTest_0006, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0006 test start";

    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    sptr<IRemoteObject> pushCallback = pushCallbackProxy->AsObject();
    sptr<IPushCallBack> pushCallBack = iface_cast<IPushCallBack>(pushCallback);

    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);

    sptr<NotificationCheckRequest> notificationCheckRequest = new (std::nothrow)NotificationCheckRequest();
    notificationCheckRequest->SetSlotType(NotificationConstant::SlotType::CUSTOM);
    notificationCheckRequest->SetContentType(NotificationContent::Type::PICTURE);
    advancedNotificationService_->pushCallBacks_.insert_or_assign(
        notificationCheckRequest->GetSlotType(), pushCallBack);
    advancedNotificationService_->checkRequests_.insert_or_assign(
        notificationCheckRequest->GetSlotType(), notificationCheckRequest);

    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::CUSTOM);
    EXPECT_EQ(advancedNotificationService_->IsNeedPushCheck(request), false);
    advancedNotificationService_->pushCallBacks_.clear();
    advancedNotificationService_->checkRequests_.clear();

    GTEST_LOG_(INFO) << "IsNeedPushCheckTest_0006 test end";
}
/**
 * @tc.number    : PushCheckTest_0001
 * @tc.name      : PushCheckTest
 * @tc.desc      : Test registerer of push check is allowed.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, PushCheckTest_0001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "PushCheckTest_0001 test start";

    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    sptr<IRemoteObject> pushCallback = pushCallbackProxy->AsObject();
    sptr<NotificationCheckRequest> notificationCheckRequest = new (std::nothrow)NotificationCheckRequest();
    notificationCheckRequest->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<IPushCallBack> pushCallBack = iface_cast<IPushCallBack>(pushCallback);
    advancedNotificationService_->pushCallBacks_.insert_or_assign(
        notificationCheckRequest->GetSlotType(), pushCallBack);
    advancedNotificationService_->checkRequests_.insert_or_assign(
        notificationCheckRequest->GetSlotType(), notificationCheckRequest);

    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);

    EXPECT_EQ(advancedNotificationService_->PushCheck(request), ERR_OK);

    advancedNotificationService_->pushCallBacks_.clear();
    advancedNotificationService_->checkRequests_.clear();

    GTEST_LOG_(INFO) << "PushCheckTest_0001 test end";
}

/**
 * @tc.number    : GetActiveNotificationByFilter_0001
 * @tc.name      : GetActiveNotificationByFilter
 * @tc.desc      : Test get non-existent live view notification request by filter.
 * @tc.require   : #I6Z5OV
 */
HWTEST_F(AdvancedNotificationServiceTest, GetActiveNotificationByFilter_0001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetActiveNotificationByFilter_0001 test start";

    TestAddSlot(NotificationConstant::SlotType::LIVE_VIEW);
    sptr<NotificationRequest> req;

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    int32_t notificationId = 1;
    std::string label = "GetActiveNotificationByFilter's label";
    std::vector<std::string> extraInfoKeys;

    EXPECT_EQ(advancedNotificationService_->GetActiveNotificationByFilter(bundleOption, notificationId, label,
        extraInfoKeys, req), (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);

    GTEST_LOG_(INFO) << "GetActiveNotificationByFilter_0001 test end";
}

/**
 * @tc.number    : IsAllowedRemoveSlot_0001
 * @tc.name      : IsAllowedRemoveSlot
 * @tc.desc      : Test IsAllowedRemoveSlot and slotType is not liveView.
 */
HWTEST_F(AdvancedNotificationServiceTest, IsAllowedRemoveSlot_0001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0001 test start";
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    EXPECT_EQ(advancedNotificationService_->IsAllowedRemoveSlot(bundleOption, NotificationConstant::SlotType::OTHER),
        (int)ERR_OK);
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0001 test end";
}

/**
 * @tc.number    : IsAllowedRemoveSlot_0002
 * @tc.name      : IsAllowedRemoveSlot
 * @tc.desc      : Test IsAllowedRemoveSlot and slot is not exist.
 */
HWTEST_F(AdvancedNotificationServiceTest, IsAllowedRemoveSlot_0002, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0002 test start";
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    EXPECT_EQ(advancedNotificationService_->IsAllowedRemoveSlot(bundleOption,
        NotificationConstant::SlotType::LIVE_VIEW), (int)ERR_OK);
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0002 test end";
}

/**
 * @tc.number    : IsAllowedRemoveSlot_0003
 * @tc.name      : IsAllowedRemoveSlot
 * @tc.desc      : Test IsAllowedRemoveSlot and slot is forcecontrol is false
 */
HWTEST_F(AdvancedNotificationServiceTest, IsAllowedRemoveSlot_0003, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0003 test start";
    TestAddLiveViewSlot(false);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    EXPECT_EQ(advancedNotificationService_->IsAllowedRemoveSlot(bundleOption,
        NotificationConstant::SlotType::LIVE_VIEW), (int)ERR_OK);
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0003 test end";
}

/**
 * @tc.number    : IsAllowedRemoveSlot_0004
 * @tc.name      : IsAllowedRemoveSlot
 * @tc.desc      : Test IsAllowedRemoveSlot and caller not sa or systemapp
 */
HWTEST_F(AdvancedNotificationServiceTest, IsAllowedRemoveSlot_0004, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0004 test start";
    TestAddLiveViewSlot(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    EXPECT_EQ(advancedNotificationService_->IsAllowedRemoveSlot(bundleOption,
        NotificationConstant::SlotType::LIVE_VIEW), (int)ERR_ANS_NON_SYSTEM_APP);
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0004 test end";
}

/**
 * @tc.number    : IsAllowedRemoveSlot_0005
 * @tc.name      : IsAllowedRemoveSlot
 * @tc.desc      : Test IsAllowedRemoveSlot and caller is systemapp
 */
HWTEST_F(AdvancedNotificationServiceTest, IsAllowedRemoveSlot_0005, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0005 test start";
    TestAddLiveViewSlot(true);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    EXPECT_EQ(advancedNotificationService_->IsAllowedRemoveSlot(bundleOption,
        NotificationConstant::SlotType::LIVE_VIEW), (int)ERR_OK);
    GTEST_LOG_(INFO) << "IsAllowedRemoveSlot_0005 test end";
}

/**
 * @tc.name: NotificationSvrQueue_00001
 * @tc.desc: Test notificationSvrQueue is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, NotificationSvrQueue_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto request = new (std::nothrow) NotificationRequest();

    auto ret = advancedNotificationService_->CancelPreparedNotification(1, "label", bundle);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    std::vector<sptr<NotificationRequest>> requests;
    ret = advancedNotificationService_->GetActiveNotifications(requests);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    uint64_t num = 0;
    ret = advancedNotificationService_->GetActiveNotificationNums(num);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    int importance = 0;
    ret = advancedNotificationService_->GetBundleImportance(importance);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    std::vector<sptr<Notification>> notifications;
    ret = advancedNotificationService_->GetAllActiveNotifications(notifications);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    std::vector<std::string> keys;
    ret = advancedNotificationService_->GetSpecialActiveNotifications(keys, notifications);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    bool enabled = false;
    ret = advancedNotificationService_->IsDistributedEnabled(enabled);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->EnableDistributed(enabled);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: NotificationSvrQueue_00002
 * @tc.desc: Test notificationSvrQueue is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, NotificationSvrQueue_00002, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto request = new (std::nothrow) NotificationRequest();

    auto ret = advancedNotificationService_->EnableDistributedSelf(true);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    bool enable = false;
    ret = advancedNotificationService_->IsDistributedEnableByBundle(bundle, enable);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->GetHasPoppedDialog(bundle, enable);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->SetSyncNotificationEnabledWithoutApp(1, enable);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    ret = advancedNotificationService_->GetSyncNotificationEnabledWithoutApp(1, enable);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    advancedNotificationService_->FillActionButtons(request);
    request->SetIsCoverActionButtons(true);
    advancedNotificationService_->FillActionButtons(request);
}

/**
 * @tc.name: AssignToNotificationList_00001
 * @tc.desc: Test AssignToNotificationList
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, AssignToNotificationList_00001, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    auto ret = advancedNotificationService_->AssignToNotificationList(record);

    ret = advancedNotificationService_->AssignToNotificationList(record);
    EXPECT_EQ(ret, (int)ERR_OK);
    EXPECT_EQ(advancedNotificationService_->notificationList_.size(), 1);
}

/**
 * @tc.name: StartArchiveTimer_00001
 * @tc.desc: Test StartArchiveTimer
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, StartArchiveTimer_00001, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetAutoDeletedTime(NotificationConstant::NO_DELAY_DELETE_TIME);
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->StartArchiveTimer(record);
    EXPECT_EQ(request->GetAutoDeletedTime(), 0);
}

/**
 * @tc.name: Filter_00001
 * @tc.desc: Test Filter
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, Filter_00001, Function | SmallTest | Level1)
{
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto request = new (std::nothrow) NotificationRequest();
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    advancedNotificationService_->notificationSlotFilter_ = nullptr;
    auto ret = advancedNotificationService_->Filter(record, true);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: ChangeNotificationByControlFlags_00001
 * @tc.desc: Test ChangeNotificationByControlFlags
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, ChangeNotificationByControlFlags_00001, Function | SmallTest | Level1)
{
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto request = new (std::nothrow) NotificationRequest();
    uint32_t notificationControlFlags = 0;
    notificationControlFlags |= NotificationConstant::ReminderFlag::SOUND_FLAG;
    notificationControlFlags |= NotificationConstant::ReminderFlag::LOCKSCREEN_FLAG;
    notificationControlFlags |= NotificationConstant::ReminderFlag::BANNER_FLAG;
    notificationControlFlags |= NotificationConstant::ReminderFlag::LIGHTSCREEN_FLAG;
    notificationControlFlags |= NotificationConstant::ReminderFlag::VIBRATION_FLAG;
    notificationControlFlags |= NotificationConstant::ReminderFlag::STATUSBAR_ICON_FLAG;
    request->SetNotificationControlFlags(notificationControlFlags);

    std::shared_ptr<NotificationFlags> flags = std::make_shared<NotificationFlags>();
    flags->SetSoundEnabled(NotificationConstant::FlagStatus::OPEN);
    flags->SetVibrationEnabled(NotificationConstant::FlagStatus::OPEN);
    flags->SetLockScreenVisblenessEnabled(true);
    flags->SetBannerEnabled(true);
    flags->SetLightScreenEnabled(true);
    flags->SetStatusIconEnabled(true);
    request->SetFlags(flags);

    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->ChangeNotificationByControlFlags(record);

    u_int32_t reminderFlags = flags->GetReminderFlags();
    EXPECT_EQ(reminderFlags, 0);
}

/**
 * @tc.name: CheckPublishPreparedNotification_00001
 * @tc.desc: Test CheckPublishPreparedNotification
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, CheckPublishPreparedNotification_00001, Function | SmallTest | Level1)
{
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto request = new (std::nothrow) NotificationRequest();
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    auto ret = advancedNotificationService_->CheckPublishPreparedNotification(record, true);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: GetRecordFromNotificationList_00001
 * @tc.desc: Test GetRecordFromNotificationList
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, GetRecordFromNotificationList_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    request->SetLabel("label");
    request->SetNotificationId(1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    auto ret = advancedNotificationService_->AssignToNotificationList(record);

    auto res = advancedNotificationService_->GetRecordFromNotificationList(
        1, SYSTEM_APP_UID, "label", TEST_DEFUALT_BUNDLE);
    EXPECT_NE(res, nullptr);
}

/**
 * @tc.name: RegisterPushCallback_00001
 * @tc.desc: Test RegisterPushCallback
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, RegisterPushCallback_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    sptr<IRemoteObject> pushCallback = nullptr;
    sptr<NotificationCheckRequest> request = nullptr;

    auto ret = advancedNotificationService_->RegisterPushCallback(pushCallback, request);
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);

    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->RegisterPushCallback(pushCallback, request);
    EXPECT_EQ(ret, (int)ERR_INVALID_VALUE);

    auto pushCallbackProxy = new (std::nothrow)MockPushCallBackStub();
    EXPECT_NE(pushCallbackProxy, nullptr);
    pushCallback = pushCallbackProxy->AsObject();
    ret = advancedNotificationService_->RegisterPushCallback(pushCallback, request);
    EXPECT_EQ(ret, (int)ERR_INVALID_VALUE);
}

/**
 * @tc.name: UnregisterPushCallback_00001
 * @tc.desc: Test UnregisterPushCallback
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, UnregisterPushCallback_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    auto ret = advancedNotificationService_->UnregisterPushCallback();
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: FillExtraInfoToJson_00001
 * @tc.desc: Test FillExtraInfoToJson
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, FillExtraInfoToJson_00001, Function | SmallTest | Level1)
{
    auto request = new NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);

    sptr<NotificationCheckRequest> checkRequest = new NotificationCheckRequest();
    std::vector<std::string> extraKeys = {"key1"};
    checkRequest->SetExtraKeys(extraKeys);
    nlohmann::json obj;
    advancedNotificationService_->FillExtraInfoToJson(request, checkRequest, obj);
    EXPECT_EQ(liveViewContent->GetExtraInfo(), nullptr);

    std::shared_ptr<AAFwk::WantParams> extraInfo = std::make_shared<AAFwk::WantParams>();
    liveViewContent->SetExtraInfo(extraInfo);
    advancedNotificationService_->FillExtraInfoToJson(request, checkRequest, obj);
}

/**
 * @tc.name: CreateDialogManager_00001
 * @tc.desc: Test CreateDialogManager
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, CreateDialogManager_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->dialogManager_ = nullptr;
    bool ret = advancedNotificationService_->CreateDialogManager();
    EXPECT_EQ(ret, true);

    ret = advancedNotificationService_->CreateDialogManager();
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number    : IsNeedNotifyConsumed_00001
 * @tc.name      : IsNeedNotifyConsumed
 * @tc.desc      : Test IsNeedNotifyConsumed function.
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedNotifyConsumed_00001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsNeedNotifyConsumed_00001 test start";
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    EXPECT_EQ(advancedNotificationService_->IsNeedNotifyConsumed(request), true);
    GTEST_LOG_(INFO) << "IsNeedNotifyConsumed_00001 test end";
}

/**
 * @tc.number    : IsNeedNotifyConsumed_00002
 * @tc.name      : IsNeedNotifyConsumed
 * @tc.desc      : Test IsNeedNotifyConsumed function.
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedNotifyConsumed_00002, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsNeedNotifyConsumed_00002 test start";
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    EXPECT_EQ(advancedNotificationService_->IsNeedNotifyConsumed(request), true);
    GTEST_LOG_(INFO) << "IsNeedNotifyConsumed_00002 test end";
}

/**
 * @tc.number    : GetAllNotificationEnabledBundles_0001
 * @tc.name      : GetAllNotificationEnabledBundles
 * @tc.desc      : Test GetAllNotificationEnabledBundles function if not systemapp.
 * @tc.require   : #I92VGR
 */
HWTEST_F(AdvancedNotificationServiceTest, GetAllNotificationEnabledBundles_0001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetAllNotificationEnabledBundles_0001 test start";

    std::vector<NotificationBundleOption> vec;
    EXPECT_EQ(advancedNotificationService_->GetAllNotificationEnabledBundles(vec), ERR_ANS_NON_SYSTEM_APP);

    GTEST_LOG_(INFO) << "GetAllNotificationEnabledBundles_0001 test end";
}

/**
 * @tc.number    : IsNeedNotifyConsumed_00003
 * @tc.name      : IsNeedNotifyConsumed
 * @tc.desc      : Test IsNeedNotifyConsumed function.
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedNotifyConsumed_00003, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "IsNeedNotifyConsumed_00003 test start";
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetAutoDeletedTime(0);
    EXPECT_EQ(advancedNotificationService_->IsNeedNotifyConsumed(request), false);
    GTEST_LOG_(INFO) << "IsNeedNotifyConsumed_00003 test end";
}

/**
 * @tc.number    : SetBadgeNumberByBundle_00001
 * @tc.name      : SetBadgeNumberByBundle
 * @tc.desc      : Test SetBadgeNumberByBundle with valid parameters, expect error code ERR_OK.
 */
HWTEST_F(AdvancedNotificationServiceTest, SetBadgeNumberByBundle_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    MockIsSystemApp(true);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    ASSERT_NE(bundleOption, nullptr);
    std::string bundleName = "invalidBundleName";
    bundleOption->SetBundleName(bundleName);
    int32_t badgeNumber = 1;
    EXPECT_EQ(advancedNotificationService_->SetBadgeNumberByBundle(bundleOption, badgeNumber), ERR_OK);
}

/**
 * @tc.number    : SetBadgeNumberByBundle_00002
 * @tc.name      : SetBadgeNumberByBundle
 * @tc.desc      : Test SetBadgeNumberByBundle with nullptr bundle option, expect error code ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(AdvancedNotificationServiceTest, SetBadgeNumberByBundle_00002, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    MockIsSystemApp(true);
    sptr<NotificationBundleOption> bundleOption = nullptr;
    int32_t badgeNumber = 1;
    EXPECT_EQ(advancedNotificationService_->SetBadgeNumberByBundle(bundleOption, badgeNumber), ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: QueryDoNotDisturbProfile_0100
 * @tc.desc: test QueryDoNotDisturbProfile successfully called
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, QueryDoNotDisturbProfile_0100, TestSize.Level1)
{
    std::string enable;
    std::string profileId;
    EXPECT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->QueryDoNotDisturbProfile(enable, profileId);
}

/**
 * @tc.name: CheckDoNotDisturbProfile_0100
 * @tc.desc: test CheckDoNotDisturbProfile successfully called
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, CheckDoNotDisturbProfile_0100, TestSize.Level1)
{
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto request = new (std::nothrow) NotificationRequest();
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    EXPECT_NE(advancedNotificationService_, nullptr);
    advancedNotificationService_->CheckDoNotDisturbProfile(record);
}

/**
 * @tc.name: DoNotDisturbUpdataReminderFlags_0100
 * @tc.desc: test DoNotDisturbUpdataReminderFlags can turn off all reminders.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, DoNotDisturbUpdataReminderFlags_0100, TestSize.Level1)
{
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto request = new (std::nothrow) NotificationRequest();
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    std::shared_ptr<NotificationFlags> flagsSet = std::make_shared<NotificationFlags>();
    record->request->SetFlags(flagsSet);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    record->request = request;
    record->notification = notification;
    advancedNotificationService_->DoNotDisturbUpdataReminderFlags(record);
    auto flags = record->request->GetFlags();
    EXPECT_NE(flags, nullptr);
    auto res = flags->IsStatusIconEnabled();
    EXPECT_EQ(res, false);
}

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
/**
 * @tc.name: RegisterSwingCallback_00001
 * @tc.desc: Test RegisterSwingCallback
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, RegisterSwingCallback_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    sptr<IRemoteObject> swingCallback = nullptr;
    auto ret = advancedNotificationService_->RegisterSwingCallback(swingCallback);
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: RegisterSwingCallback_00002
 * @tc.desc: Test RegisterSwingCallback
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, RegisterSwingCallback_00002, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    MockIsVerfyPermisson(true);
    sptr<IRemoteObject> swingCallback = nullptr;
    auto ret = advancedNotificationService_->RegisterSwingCallback(swingCallback);
    EXPECT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}
#endif

/**
 * @tc.number    : AddExcludeDate_00001
 * @tc.name      : Test AddExcludeDate
 * @tc.desc      : Test AddExcludeDate function when the result is ERR_NO_INIT
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AddExcludeDate_00001, Function | SmallTest | Level1)
{
    int32_t reminderId = 10;
    uint64_t time = 124325;
    EXPECT_EQ(advancedNotificationService_->AddExcludeDate(reminderId, time), (int)ERR_REMINDER_PERMISSION_DENIED);
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    MockIsNonBundleName(true);
    EXPECT_EQ(advancedNotificationService_->AddExcludeDate(reminderId, time), (int)ERR_ANS_INVALID_BUNDLE);
    MockIsNonBundleName(false);
    EXPECT_EQ(advancedNotificationService_->AddExcludeDate(reminderId, time), (int)ERR_NO_INIT);
    MockIsVerfyPermisson(false);
}

/**
 * @tc.number    : DelExcludeDates_00002
 * @tc.name      : Test DelExcludeDates
 * @tc.desc      : Test DelExcludeDates function when the result is ERR_NO_INIT
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, DelExcludeDates_00002, Function | SmallTest | Level1)
{
    int32_t reminderId = 10;
    EXPECT_EQ(advancedNotificationService_->DelExcludeDates(reminderId), (int)ERR_REMINDER_PERMISSION_DENIED);
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    MockIsNonBundleName(true);
    EXPECT_EQ(advancedNotificationService_->DelExcludeDates(reminderId), (int)ERR_ANS_INVALID_BUNDLE);
    MockIsNonBundleName(false);
    EXPECT_EQ(advancedNotificationService_->DelExcludeDates(reminderId), (int)ERR_NO_INIT);
    MockIsVerfyPermisson(false);
}

/**
 * @tc.number    : GetExcludeDates_00001
 * @tc.name      : Test GetExcludeDates
 * @tc.desc      : Test GetExcludeDates function when the result is ERR_NO_INIT
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, GetExcludeDates_00001, Function | SmallTest | Level1)
{
    int32_t reminderId = 10;
    std::vector<uint64_t> times;
    EXPECT_EQ(advancedNotificationService_->GetExcludeDates(reminderId, times), (int)ERR_REMINDER_PERMISSION_DENIED);
    TestAddSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    MockIsNonBundleName(true);
    EXPECT_EQ(advancedNotificationService_->GetExcludeDates(reminderId, times), (int)ERR_ANS_INVALID_BUNDLE);
    MockIsNonBundleName(false);
    EXPECT_EQ(advancedNotificationService_->GetExcludeDates(reminderId, times), (int)ERR_NO_INIT);
    MockIsVerfyPermisson(false);
}
}  // namespace Notification
}  // namespace OHOS
