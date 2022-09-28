/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <functional>
#include <thread>

#include "gtest/gtest.h"

#define private public

#include "advanced_notification_service.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_ut_constant.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "mock_ipc_skeleton.h"
#include "notification_preferences.h"
#include "notification_subscriber.h"
#include "system_event_observer.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Notification {
class AdvancedNotificationServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    void TestAddSlot(NotificationConstant::SlotType type);

private:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AdvancedNotificationServiceTest::advancedNotificationService_ = nullptr;

void AdvancedNotificationServiceTest::SetUpTestCase()
{
    advancedNotificationService_ = AdvancedNotificationService::GetInstance();
    IPCSkeleton::SetCallingTokenID(NON_NATIVE_TOKEN);
}

void AdvancedNotificationServiceTest::TearDownTestCase()
{
    advancedNotificationService_ = nullptr;
}

void AdvancedNotificationServiceTest::SetUp()
{
    NotificationPreferences::GetInstance().ClearNotificationInRestoreFactorySettings();
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);
    advancedNotificationService_->CancelAll();
}

void AdvancedNotificationServiceTest::TearDown()
{}

inline void SleepForFC()
{
    // For ANS Flow Control
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

class TestAnsSubscriber : public NotificationSubscriber {
public:
    void OnConnected() override
    {}
    void OnDisconnected() override
    {}
    void OnDied() override
    {}
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
    void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override
    {}
    void OnEnabledNotificationChanged(
        const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnCanceled(const std::shared_ptr<Notification> &request) override
    {}
    void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override
    {}
    void OnConsumed(const std::shared_ptr<Notification> &request) override
    {}
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
};

void AdvancedNotificationServiceTest::TestAddSlot(NotificationConstant::SlotType type)
{
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(type);
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
}

/**
 * @tc.number    : ANS_Publish_00200
 * @tc.name      : ANSPublish00200
 * @tc.desc      : Publish a normal text type notification twice.
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00200, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
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
    IPCSkeleton::SetCallingUid(NON_SYSTEM_APP_UID);
    IPCSkeleton::SetCallingTokenID(NON_NATIVE_TOKEN);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::CUSTOM);
    req->SetLabel("req's label");
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
    IPCSkeleton::SetCallingUid(NON_BUNDLE_NAME_UID);
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
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_ANS_INVALID_BUNDLE);
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
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
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
}

/**
 * @tc.number    : ANS_Publish_00900
 * @tc.name      : ANSPublish00900
 * @tc.desc      : Create a slot of type SERVICE_REMINDER and successfully publish a notification
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00900, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::SERVICE_REMINDER);
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::SERVICE_REMINDER);
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
}

/**
 * @tc.number    : ANS_Publish_01000
 * @tc.name      : ANSPublish01000
 * @tc.desc      : Create a slot of type CONTENT_INFORMATION and successfully publish a notification
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_01000, Function | SmallTest | Level1)
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
    sptr<NotificationRequest> req = new NotificationRequest();
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::CUSTOM);
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
 * @tc.number    : AdvancedNotificationServiceTest_02000
 * @tc.name      : ANS_SetPrivateNotificationsAllowed_0100
 * @tc.desc      : Test SetPrivateNotificationsAllowed function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_02000, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    EXPECT_EQ((int)advancedNotificationService_->SetPrivateNotificationsAllowed(true), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_02100
 * @tc.name      : ANS_GetPrivateNotificationsAllowed_0100
 * @tc.desc      : Test GetPrivateNotificationsAllowed function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_02100, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    EXPECT_EQ((int)advancedNotificationService_->SetPrivateNotificationsAllowed(true), (int)ERR_OK);
    bool allow = false;
    EXPECT_EQ((int)advancedNotificationService_->GetPrivateNotificationsAllowed(allow), (int)ERR_OK);
    EXPECT_TRUE(allow);
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
    req->SetSlotType(NotificationConstant::OTHER);
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    EXPECT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(
                  std::string(), new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), false),
        (int)ERR_OK);
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
    std::string label = "testLabel";
    {
        sptr<NotificationRequest> req = new NotificationRequest(1);
        req->SetSlotType(NotificationConstant::OTHER);
        req->SetLabel(label);
        EXPECT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    }
    {
        sptr<NotificationRequest> req = new NotificationRequest(2);
        req->SetSlotType(NotificationConstant::OTHER);
        req->SetLabel(label);
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
    int32_t notificationId = 2;
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(notificationId);
    req->SetSlotType(NotificationConstant::OTHER);
    req->SetLabel(label);
    req->SetUnremovable(true);
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
    EXPECT_EQ((int)advancedNotificationService_->RemoveSlotByType(NotificationConstant::CUSTOM),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST);
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
 * @tc.number    : AdvancedNotificationServiceTest_06100
 * @tc.name      : ANS_SetPrivateNotificationsAllowed_0100
 * @tc.desc      : Test SetPrivateNotificationsAllowed function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_06100, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    EXPECT_EQ((int)advancedNotificationService_->SetPrivateNotificationsAllowed(true), (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_06200
 * @tc.name      : ANS_GetPrivateNotificationsAllowed_0100
 * @tc.desc      : Test GetPrivateNotificationsAllowed function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_06200, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    EXPECT_EQ((int)advancedNotificationService_->SetPrivateNotificationsAllowed(true), (int)ERR_OK);
    bool allow = false;
    EXPECT_EQ((int)advancedNotificationService_->GetPrivateNotificationsAllowed(allow), (int)ERR_OK);
    EXPECT_TRUE(allow);
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
    EXPECT_EQ((int)advancedNotificationService_->Subscribe(subscriber->GetImpl(), info), (int)ERR_OK);
    EXPECT_EQ((int)advancedNotificationService_->Subscribe(nullptr, info), (int)ERR_ANS_INVALID_PARAM);
    EXPECT_EQ((int)advancedNotificationService_->Unsubscribe(subscriber->GetImpl(), nullptr), (int)ERR_OK);
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
    sptr<NotificationSlot> slot;
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
    IPCSkeleton::SetCallingUid(SYSTEM_SERVICE_UID);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
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
    IPCSkeleton::SetCallingTokenID(NON_NATIVE_TOKEN);
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
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    IPCSkeleton::SetCallingUid(SYSTEM_SERVICE_UID);
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
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    IPCSkeleton::SetCallingUid(SYSTEM_SERVICE_UID);
    std::string label = "testLabel";
    {
        sptr<NotificationRequest> req = new NotificationRequest(1);
        req->SetSlotType(NotificationConstant::OTHER);
        req->SetLabel(label);
        EXPECT_EQ(advancedNotificationService_->PublishContinuousTaskNotification(req), (int)ERR_OK);
    }
    IPCSkeleton::SetCallingTokenID(NON_NATIVE_TOKEN);
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
        false);
    EXPECT_EQ(result, (int)ERR_OK);
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
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
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
    IPCSkeleton::SetCallingTokenID(DLP_NATIVE_TOKEN);
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
    EXPECT_EQ(advancedNotificationService_->Publish(label, req), ERR_ANS_DLP_HAP);
    SleepForFC();

    IPCSkeleton::SetCallingTokenID(NON_NATIVE_TOKEN);
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

    std::stringstream key;
    key << "_" << req->GetCreatorUserId() << "_" << req->GetCreatorUid() << "_"
        << req->GetLabel() << "_" << req->GetNotificationId();

    EXPECT_EQ(advancedNotificationService_->IsNotificationExists(key.str()), true);
}
/**
 * @tc.number    : AdvancedNotificationServiceTest_15500
 * @tc.name      : OnReceiveEvent_0100
 * @tc.desc      : Test OnReceiveEvent function userid<DEFAULT_USER_ID
 * @tc.require   : I5TIQR
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_15500, Function | SmallTest | Level1)
{
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

    std::stringstream key;
    key << "_" << req->GetCreatorUserId() << "_" << req->GetCreatorUid() << "_"
        << req->GetLabel() << "_" << req->GetNotificationId();

    EXPECT_EQ(advancedNotificationService_->IsNotificationExists(key.str()), true);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_15600
 * @tc.name      : OnReceiveEvent_0200
 * @tc.desc      : Test OnReceiveEvent function when userid>DEFAULT_USER_ID
 * @tc.require   : I5TIQR
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_15600, Function | SmallTest | Level1)
{
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

    std::stringstream key;
    key << "_" << req->GetCreatorUserId() << "_" << req->GetCreatorUid() << "_"
        << req->GetLabel() << "_" << req->GetNotificationId();

    EXPECT_EQ(advancedNotificationService_->IsNotificationExists(key.str()), true);
}
}  // namespace Notification
}  // namespace OHOS