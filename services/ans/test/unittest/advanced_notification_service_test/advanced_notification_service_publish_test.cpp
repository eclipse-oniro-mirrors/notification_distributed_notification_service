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

#include "errors.h"
#include "notification_content.h"
#include "notification_record.h"
#include "notification_request.h"
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
#include "ans_result_data_synchronizer.h"
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
#include "mock_bundle_mgr.h"

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
    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
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
    ASSERT_EQ(advancedNotificationService_->AddSlots(slots), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->AddSlots(slots), (int)ERR_OK);
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
 * @tc.number    : ANS_Publish_00100
 * @tc.name      : ANSPublish00100
 * @tc.desc      : Publish a normal text type notification.
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_00100, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
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

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_ANS_NON_SYSTEM_APP);
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
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_ANS_INVALID_BUNDLE);
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

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
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

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
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

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
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

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
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

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
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

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
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

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_ANS_NON_SYSTEM_APP);
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
    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(
                  std::string(), new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), false),
        (int)ERR_OK);
    IPCSkeleton::SetCallingTokenID(NON_NATIVE_TOKEN);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_ANS_NOT_ALLOWED);
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
    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(
                  std::string(), new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), false),
        (int)ERR_OK);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    ASSERT_EQ(advancedNotificationService_->Publish(std::string(), req), (int)ERR_ANS_NOT_ALLOWED);
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

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
    std::string label = "testLabel";
    {
        sptr<NotificationRequest> req = new NotificationRequest(1);
        req->SetSlotType(NotificationConstant::OTHER);
        req->SetLabel(label);
        req->SetCreatorUid(1);
        ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    }
    {
        sptr<NotificationRequest> req = new NotificationRequest(2);
        req->SetSlotType(NotificationConstant::OTHER);
        req->SetLabel(label);
        req->SetCreatorUid(1);
        ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    }
    int32_t result = ERR_OK;
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService_->Cancel(1, label, "",
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
        ASSERT_EQ(synchronizer->GetResultCode(), result);
    } else {
        ASSERT_EQ(ret, result);
    }
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_14700
 * @tc.name      : ANS_Cancel_0100
 * @tc.desc      : public two notification to cancel one of them
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_14700, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
    std::string label = "testLabel";
    {
        sptr<NotificationRequest> req = new NotificationRequest(1);
        req->SetSlotType(NotificationConstant::OTHER);
        req->SetLabel(label);
        req->SetCreatorUid(1);
        ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    }
    {
        sptr<NotificationRequest> req = new NotificationRequest(2);
        req->SetSlotType(NotificationConstant::OTHER);
        req->SetLabel(label);
        req->SetCreatorUid(1);
        ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    }
    ASSERT_EQ(advancedNotificationService_->Cancel(1, label, ""), (int)ERR_OK);
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
    int32_t result = ERR_ANS_NOTIFICATION_NOT_EXISTS;
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService_->Cancel(notificationId, label, "",
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
        ASSERT_EQ(synchronizer->GetResultCode(), result);
    } else {
        ASSERT_EQ(ret, result);
    }
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_14800
 * @tc.name      : ANS_Cancel_0200
 * @tc.desc      : Test Cancel function when notification no exists
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_14800, Function | SmallTest | Level1)
{
    int32_t notificationId = 0;
    std::string label = "testLabel";
    ASSERT_EQ((int)advancedNotificationService_->Cancel(
        notificationId, label, ""), (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);
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
    int32_t result = ERR_OK;
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService_->CancelAll("",
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
        ASSERT_EQ(synchronizer->GetResultCode(), result);
    } else {
        ASSERT_EQ(ret, result);
    }
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_14900
 * @tc.name      : ANS_CancelAll_0100
 * @tc.desc      : Test CancelAll function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_14900, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    sptr<NotificationRequest> req = new NotificationRequest(1);
    req->SetSlotType(NotificationConstant::OTHER);
    ASSERT_EQ(advancedNotificationService_->CancelAll(""), (int)ERR_OK);
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

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
    int32_t notificationId = 2;
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(notificationId);
    req->SetSlotType(NotificationConstant::OTHER);
    req->SetLabel(label);
    req->SetUnremovable(true);
    req->SetCreatorUid(1);
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    int32_t result = ERR_OK;
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService_->Cancel(notificationId, label, "",
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
        ASSERT_EQ(synchronizer->GetResultCode(), result);
    } else {
        ASSERT_EQ(ret, result);
    }
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_15000
 * @tc.name      : ANS_Cancel_0100
 * @tc.desc      : Test Cancel function when unremovable is true
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_15000, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
    int32_t notificationId = 2;
    std::string label = "testLabel";
    sptr<NotificationRequest> req = new NotificationRequest(notificationId);
    req->SetSlotType(NotificationConstant::OTHER);
    req->SetLabel(label);
    req->SetUnremovable(true);
    req->SetCreatorUid(1);
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    ASSERT_EQ(advancedNotificationService_->Cancel(notificationId, label, ""), (int)ERR_OK);
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

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish("label", req), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish("label", req), (int)ERR_ANS_PICTURE_OVER_SIZE);
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
    ASSERT_EQ(advancedNotificationService_->Publish("label", req), (int)ERR_ANS_ICON_OVER_SIZE);
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

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish("label", req), (int)ERR_OK);
    ASSERT_EQ(advancedNotificationService_->CancelGroup(groupName, ""), (int)ERR_OK);
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

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish("label", req), (int)ERR_OK);

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    ASSERT_EQ(advancedNotificationService_->RemoveGroupByBundle(bundleOption, groupName), (int)ERR_OK);
    SleepForFC();
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
    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(
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
    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(
        std::string(), new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), false),
        (int)ERR_OK);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_ANS_NOT_ALLOWED);
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
    ASSERT_EQ(result, (int)ERR_OK);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_ENABLED);
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
    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    int32_t notificationId = 1;
    std::string label = "testRemove";
    sptr<NotificationRequest> req = new NotificationRequest(notificationId);
    req->SetSlotType(NotificationConstant::OTHER);
    req->SetLabel(label);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);

    auto result = advancedNotificationService_->RemoveNotification(
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID),
        notificationId, label, NotificationConstant::CANCEL_REASON_DELETE);
    ASSERT_EQ(result, (int)ERR_OK);
}

/**
 * @tc.name: AdvancedNotificationServiceTest_12300
 * @tc.desc: SA publish notification, Failed to publish when creatorUid default.
 * @tc.type: FUNC
 * @tc.require: I5P1GU
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_12300, Function | SmallTest | Level1)
{
    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, 1), true), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), ERR_ANS_INVALID_UID);
    SleepForFC();

    req->SetCreatorUid(1);
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), 0);
}

/*
 * @tc.name: AdvancedNotificationServiceTest_12400
 * @tc.desc: DLP App publish notification failed.
 * @tc.type: FUNC
 * @tc.require: I582TY
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_12400, Function | SmallTest | Level1)
{
    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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

    ASSERT_EQ(advancedNotificationService_->Publish(label, req), ERR_OK);
}

/*
 * @tc.name: AdvancedNotificationServiceTest_12500
 * @tc.desc: When the user removed event is received and the userid is less than or equal to 100,
 * the notification cannot be deleted
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_12500, Function | SmallTest | Level1)
{
    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), ERR_OK);
    SleepForFC();

    EventFwk::Want want;
    EventFwk::CommonEventData data;
    data.SetWant(want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED));
    data.SetCode(DEFAULT_USER_ID);
    advancedNotificationService_->systemEventObserver_->OnReceiveEvent(data);

    ASSERT_EQ(advancedNotificationService_->IsNotificationExists(req->GetBaseKey("")), true);
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

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), ERR_OK);
    SleepForFC();

    EventFwk::Want want;
    EventFwk::CommonEventData data;
    data.SetWant(want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED));
    data.SetCode(50);
    advancedNotificationService_->systemEventObserver_->OnReceiveEvent(data);

    ASSERT_EQ(advancedNotificationService_->IsNotificationExists(req->GetBaseKey("")), true);
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

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), ERR_OK);
    SleepForFC();

    EventFwk::Want want;
    EventFwk::CommonEventData data;
    data.SetWant(want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED));
    data.SetCode(200);
    advancedNotificationService_->systemEventObserver_->OnReceiveEvent(data);

    ASSERT_EQ(advancedNotificationService_->IsNotificationExists(req->GetBaseKey("")), true);
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

    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);
    SleepForFC();
    req->SetCreatorUserId(SUBSCRIBE_USER_INIT);
    std::shared_ptr<Notification> notification = std::make_shared<Notification>(req);

    ASSERT_EQ(advancedNotificationService_->DeleteAll(), ERR_OK);

    GTEST_LOG_(INFO) << "ANS_GetActiveNotifications_0100 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_04100
 * @tc.name      : ANS_GetSpecialActiveNotifications_0100
 * @tc.desc      : Test GetSpecialActiveNotifications function
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_04100, Function | SmallTest | Level1)
{
    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->Publish(label, req), (int)ERR_OK);

    std::vector<sptr<Notification>> allNotifications;
    ASSERT_EQ(advancedNotificationService_->GetAllActiveNotifications(allNotifications), (int)ERR_OK);
    int32_t result = ERR_OK;
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService_->GetAllActiveNotifications(
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
        allNotifications = synchronizer->GetNotifications();
        ASSERT_EQ(synchronizer->GetResultCode(), result);
    } else {
        ASSERT_EQ(ret, result);
    }
    ASSERT_EQ(allNotifications.size(), (size_t)1);
    std::vector<std::string> keys;
    for (auto notification : allNotifications) {
        keys.push_back(notification->GetKey());
    }
    std::vector<sptr<Notification>> specialActiveNotifications;
    ASSERT_EQ(
        advancedNotificationService_->GetSpecialActiveNotifications(keys, specialActiveNotifications), (int)ERR_OK);
    ASSERT_EQ(specialActiveNotifications.size(), (size_t)1);
    SleepForFC();
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
    ASSERT_EQ(advancedNotificationService_->PublishContinuousTaskNotification(req), (int)ERR_OK);
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
    ASSERT_EQ(advancedNotificationService_->PublishContinuousTaskNotification(req), (int)ERR_ANS_NOT_SYSTEM_SERVICE);
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
        ASSERT_EQ(advancedNotificationService_->PublishContinuousTaskNotification(req), (int)ERR_OK);
    }
    ASSERT_EQ(advancedNotificationService_->CancelContinuousTaskNotification(label, 1), (int)ERR_OK);
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
        ASSERT_EQ(advancedNotificationService_->PublishContinuousTaskNotification(req), (int)ERR_OK);
    }
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    ASSERT_EQ(
        advancedNotificationService_->CancelContinuousTaskNotification(label, 1), (int)ERR_ANS_NOT_SYSTEM_SERVICE);
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
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService_->CancelAsBundle(notificationId, representativeBundle, userId,
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
        ASSERT_EQ(synchronizer->GetResultCode(), result);
    } else {
        ASSERT_EQ(ret, result);
    }
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_112600
 * @tc.name      : ANS_CancelAsBundle_0100
 * @tc.desc      : Test CancelAsBundle function when the result is ERR_ANS_NOTIFICATION_NOT_EXISTS
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_112600, Function | SmallTest | Level1)
{
    TestAddSlot(NotificationConstant::SlotType::OTHER);
    int32_t notificationId = 1;
    std::string representativeBundle = "RepresentativeBundle";
    int32_t userId = 1;
    int result = ERR_ANS_NOTIFICATION_NOT_EXISTS;
    ASSERT_EQ(advancedNotificationService_->CancelAsBundle(notificationId, representativeBundle, userId), result);
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
    ASSERT_EQ(advancedNotificationService_->CanPublishAsBundle(representativeBundle, canPublish), result);
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
    ASSERT_EQ(advancedNotificationService_->PublishAsBundle(notification, representativeBundle), result);
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

    ASSERT_EQ(advancedNotificationService_->PublishPreparedNotification(req, bundleOption).GetErrCode(),
        ERR_ANS_INVALID_PARAM);

    GTEST_LOG_(INFO) << "PublishPreparedNotification_1000 test end";
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_19000
 * @tc.name      : ANS_Publish_With_PixelMap
 * @tc.desc      : Publish a notification with pixelMap.
 */
HWTEST_F(AdvancedNotificationServiceTest, AdvancedNotificationServiceTest_19000, Function | SmallTest | Level1)
{
    ASSERT_EQ(advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(std::string(),
        new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID), true), (int)ERR_OK);
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
    pictureContent->SetBigPicture(nullptr);
    EXPECT_EQ(nullptr, pictureContent->GetBigPicture());
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(pictureContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);

    req->SetLittleIcon(nullptr);
    EXPECT_EQ(nullptr, req->GetLittleIcon());
    req->SetBigIcon(nullptr);
    EXPECT_EQ(nullptr, req->GetBigIcon());
    req->SetOverlayIcon(nullptr);
    EXPECT_EQ(nullptr, req->GetOverlayIcon());
    ASSERT_EQ(advancedNotificationService_->Publish("label", req), (int)ERR_OK);
}

/**
 * @tc.number    : OnReceiveEvent_0200
 * @tc.name      : OnReceiveEvent_0200
 * @tc.desc      : Test OnReceiveEvent COMMON_EVENT_PACKAGE_REMOVED
 * @tc.require   : I5TIQR
 */
HWTEST_F(AdvancedNotificationServiceTest, OnReceiveEvent_0200, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    int notificationId = 1;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(notificationId);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AssignToNotificationList(record);

    EventFwk::Want want;
    EventFwk::CommonEventData data;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED)
        .SetElementName("test", "")
        .SetParam(AppExecFwk::Constants::UID, 1);
    data.SetWant(want);
    data.SetCode(200);
    advancedNotificationService_->systemEventObserver_->OnReceiveEvent(data);
    SleepForFC();
    ASSERT_EQ(advancedNotificationService_->IsNotificationExists(request->GetBaseKey("")), false);
}

/**
 * @tc.number    : OnReceiveEvent_0300
 * @tc.name      : OnReceiveEvent_0300
 * @tc.desc      : Test OnReceiveEvent COMMON_EVENT_PACKAGE_REMOVED
 * @tc.require   : I5TIQR
 */
HWTEST_F(AdvancedNotificationServiceTest, OnReceiveEvent_0300, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    int notificationId = 1;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(notificationId);
    request->SetReceiverUserId(SUBSCRIBE_USER_INIT);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AssignToNotificationList(record);

    EventFwk::Want want;
    EventFwk::CommonEventData data;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    data.SetWant(want);
    data.SetCode(SUBSCRIBE_USER_INIT);
    advancedNotificationService_->systemEventObserver_->OnReceiveEvent(data);
    ASSERT_EQ(advancedNotificationService_->IsNotificationExists(request->GetBaseKey("")), true);
}

/**
 * @tc.number    : OnReceiveEvent_0400
 * @tc.name      : OnReceiveEvent_0400
 * @tc.desc      : Test OnReceiveEvent COMMON_EVENT_PACKAGE_REMOVED
 * @tc.require   : I5TIQR
 */
HWTEST_F(AdvancedNotificationServiceTest, OnReceiveEvent_0400, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest(1);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    request->SetContent(content);
    request->SetCreatorUid(1);
    request->SetCreatorUserId(0);
    request->SetLabel("test1");

    std::string bundleName = "test";
    int32_t uid = 0;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(bundleName, uid);
    AdvancedNotificationService::NotificationRequestDb requestDbObj =
        { .request = request, .bundleOption = bundleOption };
    auto result = advancedNotificationService_->SetNotificationRequestToDb(requestDbObj);
    ASSERT_EQ(result, ERR_OK);

    EventFwk::Want want;
    EventFwk::CommonEventData data;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    data.SetWant(want);
    data.SetCode(0);
    advancedNotificationService_->systemEventObserver_->OnReceiveEvent(data);
    SleepForFC();
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);
}

/**
 * @tc.number    : OnReceiveEvent_0500
 * @tc.name      : OnReceiveEvent_0500
 * @tc.desc      : Test OnReceiveEvent COMMON_EVENT_PACKAGE_REMOVED
 * @tc.require   : I5TIQR
 */
HWTEST_F(AdvancedNotificationServiceTest, OnReceiveEvent_0500, Function | SmallTest | Level1)
{
    int notificationId = 1;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(notificationId);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    advancedNotificationService_->AssignToNotificationList(record);

    EventFwk::Want want;
    EventFwk::CommonEventData data;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED)
        .SetElementName("test", "")
        .SetParam("ohos.aafwk.param.targetUid", 1);
    data.SetWant(want);
    data.SetCode(0);
    advancedNotificationService_->systemEventObserver_->OnReceiveEvent(data);

    SleepForFC();
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);
}

/**
 * @tc.number    : OnReceiveEvent_0600
 * @tc.name      : OnReceiveEvent_0600
 * @tc.desc      : Test OnReceiveEvent COMMON_EVENT_PACKAGE_REMOVED
 * @tc.require   : I5TIQR
 */
HWTEST_F(AdvancedNotificationServiceTest, OnReceiveEvent_0600, Function | SmallTest | Level1)
{
    MockSetBundleInfoEnabled(true);
    EventFwk::Want want;
    EventFwk::CommonEventData data;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED)
        .SetElementName("test", "")
        .SetParam("uid", 1);
    data.SetWant(want);
    data.SetCode(0);
    advancedNotificationService_->systemEventObserver_->OnReceiveEvent(data);

    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    SleepForFC();
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    ASSERT_EQ(static_cast<int32_t>(state), 3);
}

/**
 * @tc.number    : OnReceiveEvent_0700
 * @tc.name      : OnReceiveEvent_0700
 * @tc.desc      : Test OnReceiveEvent COMMON_EVENT_PACKAGE_REMOVED
 * @tc.require   : I5TIQR
 */
HWTEST_F(AdvancedNotificationServiceTest, OnReceiveEvent_0700, Function | SmallTest | Level1)
{
    MockSetBundleInfoEnabled(true);
    EventFwk::Want want;
    EventFwk::CommonEventData data;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED)
        .SetElementName("test", "")
        .SetParam("uid", 1);
    data.SetWant(want);
    data.SetCode(0);
    advancedNotificationService_->systemEventObserver_->OnReceiveEvent(data);

    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    SleepForFC();
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    ASSERT_EQ(static_cast<int32_t>(state), 3);
}

/**
 * @tc.number    : OnReceiveEvent_0800
 * @tc.name      : OnReceiveEvent_0800
 * @tc.desc      : Test OnReceiveEvent COMMON_EVENT_PACKAGE_REMOVED
 * @tc.require   : I5TIQR
 */
HWTEST_F(AdvancedNotificationServiceTest, OnReceiveEvent_0800, Function | SmallTest | Level1)
{
    MockSetBundleInfoEnabled(true);
    EventFwk::Want want;
    EventFwk::CommonEventData data;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED);
    data.SetWant(want);
    data.SetCode(0);
    advancedNotificationService_->systemEventObserver_->OnReceiveEvent(data);

    SleepForFC();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    ASSERT_EQ(static_cast<int32_t>(state), 3);
}

/**
 * @tc.number    : OnReceiveEvent_0900
 * @tc.name      : OnReceiveEvent_0900
 * @tc.desc      : Test OnReceiveEvent COMMON_EVENT_PACKAGE_REMOVED
 * @tc.require   : I5TIQR
 */
HWTEST_F(AdvancedNotificationServiceTest, OnReceiveEvent_0900, Function | SmallTest | Level1)
{
    AdvancedNotificationService advancedNotificationService;
    MockSetBundleInfoEnabled(true);
    EventFwk::Want want;
    EventFwk::CommonEventData data;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED);
    data.SetWant(want);
    data.SetCode(0);
    advancedNotificationService.systemEventObserver_->callbacks_.onBootSystemCompleted = nullptr;
    advancedNotificationService.systemEventObserver_->OnReceiveEvent(data);

    SleepForFC();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    ASSERT_EQ(static_cast<int32_t>(state), 0);
}

/**
 * @tc.number    : OnReceiveEvent_1000
 * @tc.name      : OnReceiveEvent_1000
 * @tc.desc      : Test OnReceiveEvent COMMON_EVENT_PACKAGE_REMOVED
 * @tc.require   : I5TIQR
 */
HWTEST_F(AdvancedNotificationServiceTest, OnReceiveEvent_1000, Function | SmallTest | Level1)
{
    AdvancedNotificationService advancedNotificationService;
    MockSetBundleInfoEnabled(true);
    EventFwk::Want want;
    EventFwk::CommonEventData data;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED)
        .SetElementName("test", "")
        .SetParam("uid", 1);
    data.SetWant(want);
    data.SetCode(0);
    advancedNotificationService.systemEventObserver_->callbacks_.onBundleAdd = nullptr;
    advancedNotificationService.systemEventObserver_->OnReceiveEvent(data);

    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    SleepForFC();
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    ASSERT_EQ(static_cast<int32_t>(state), 0);
}

/**
 * @tc.number    : OnReceiveEvent_1100
 * @tc.name      : OnReceiveEvent_1100
 * @tc.desc      : Test OnReceiveEvent COMMON_EVENT_PACKAGE_CHANGED
 * @tc.require   : I5TIQR
 */
HWTEST_F(AdvancedNotificationServiceTest, OnReceiveEvent_1100, Function | SmallTest | Level1)
{
    AdvancedNotificationService advancedNotificationService;
    MockSetBundleInfoEnabled(true);
    EventFwk::Want want;
    EventFwk::CommonEventData data;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED)
        .SetElementName("test", "")
        .SetParam("uid", 1);
    data.SetWant(want);
    data.SetCode(0);
    advancedNotificationService.systemEventObserver_->callbacks_.onBundleUpdate = nullptr;
    advancedNotificationService.systemEventObserver_->OnReceiveEvent(data);

    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    SleepForFC();
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    ASSERT_EQ(static_cast<int32_t>(state), 0);
}

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
/**
 * @tc.number    : OnReceiveEvent_1200
 * @tc.name      : OnReceiveEvent_1200
 * @tc.desc      : Test OnReceiveEvent COMMON_EVENT_SCREEN
 * @tc.require   : I5TIQR
 */
HWTEST_F(AdvancedNotificationServiceTest, OnReceiveEvent_1200, Function | SmallTest | Level1)
{
    AdvancedNotificationService advancedNotificationService;
    MockSetBundleInfoEnabled(true);
    EventFwk::Want want;
    EventFwk::CommonEventData data;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    data.SetWant(want);
    data.SetCode(0);
    advancedNotificationService.systemEventObserver_->OnReceiveEvent(data);
    ASSERT_EQ(advancedNotificationService.localScreenOn_, true);
}

/**
 * @tc.number    : OnReceiveEvent_1300
 * @tc.name      : OnReceiveEvent_1300
 * @tc.desc      : Test OnReceiveEvent COMMON_EVENT_SCREEN
 * @tc.require   : I5TIQR
 */
HWTEST_F(AdvancedNotificationServiceTest, OnReceiveEvent_1300, Function | SmallTest | Level1)
{
    AdvancedNotificationService advancedNotificationService;
    MockSetBundleInfoEnabled(true);
    EventFwk::Want want;
    EventFwk::CommonEventData data;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    data.SetWant(want);
    data.SetCode(0);
    advancedNotificationService.systemEventObserver_->OnReceiveEvent(data);
    ASSERT_EQ(advancedNotificationService.localScreenOn_, false);
}
#endif

/**
 * @tc.number    : CheckNotificationRequestLineWantAgents_0100
 * @tc.name      : CheckNotificationRequestLineWantAgents_0100
 * @tc.desc      : Test CheckNotificationRequestLineWantAgents method when request has local wantAgent
 * @tc.require   : I5TIQR
 */
HWTEST_F(AdvancedNotificationServiceTest, CheckNotificationRequestLineWantAgents_0100, Level1)
{
    AdvancedNotificationService advancedNotificationService;
    const std::shared_ptr<NotificationMultiLineContent> multiLineContent =
        std::make_shared<NotificationMultiLineContent>();
    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    std::shared_ptr<AbilityRuntime::WantAgent::LocalPendingWant> localPendingWant =
        std::make_shared<AbilityRuntime::WantAgent::LocalPendingWant>("TestBundleName", want, 0);
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        std::make_shared<AbilityRuntime::WantAgent::WantAgent>(localPendingWant);
    std::vector<std::shared_ptr<AbilityRuntime::WantAgent::WantAgent>> lineWantAgents;
    lineWantAgents.emplace_back(wantAgent);
    lineWantAgents.emplace_back(wantAgent);
    lineWantAgents.emplace_back(wantAgent);
    multiLineContent->AddSingleLine("test1");
    multiLineContent->AddSingleLine("test2");
    multiLineContent->AddSingleLine("test3");
    multiLineContent->SetLineWantAgents(lineWantAgents);
    const std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(multiLineContent);
    MockIsSystemApp(false);

    ASSERT_EQ(advancedNotificationService.CheckNotificationRequestLineWantAgents(content, true, true), ERR_OK);
}

/**
 * @tc.number    : PublishPreparedNotificationInner_0100
 * @tc.name      : PublishPreparedNotificationInner_0100
 * @tc.desc      : Test PublishPreparedNotificationInner method when bundleOption is nullptr
 */
HWTEST_F(AdvancedNotificationServiceTest, PublishPreparedNotificationInner_0100, Level1)
{
    AdvancedNotificationService advancedNotificationService;
    AdvancedNotificationService::PublishNotificationParameter parameter;
    parameter.request = sptr<NotificationRequest>(new (std::nothrow) NotificationRequest());
    auto ret = advancedNotificationService.PublishPreparedNotificationInner(parameter);
    EXPECT_EQ(ret.GetErrCode(), ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : Filter_0100
 * @tc.name      : Filter_0100
 * @tc.desc      : Test Filter method return ERR_ANS_INVALID_PARAM
 */
HWTEST_F(AdvancedNotificationServiceTest, Filter_0100, Level1)
{
    AdvancedNotificationService advancedNotificationService;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto record = advancedNotificationService.MakeNotificationRecord(request, bundle);
    ASSERT_NE(record, nullptr);

    advancedNotificationService.notificationSlotFilter_ = nullptr;
    bool isRecover = false;
    auto ret = advancedNotificationService.Filter(record, isRecover);
    EXPECT_EQ(ret.GetErrCode(), ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : Filter_0200
 * @tc.name      : Filter_0200
 * @tc.desc      : Test Filter method return ERR_ANS_NOTIFICATION_NOT_EXISTS
 */
HWTEST_F(AdvancedNotificationServiceTest, Filter_0200, Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);

    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    ASSERT_NE(record, nullptr);

    advancedNotificationService_->notificationSlotFilter_ = nullptr;
    bool isRecover = false;
    auto ret = advancedNotificationService_->Filter(record, isRecover);
    EXPECT_EQ(ret.GetErrCode(), ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.number    : IsNeedPushCheck_0100
 * @tc.name      : IsNeedPushCheck_0100
 * @tc.desc      : Test IsNeedPushCheck method return false
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedPushCheck_0100, Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);

    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    auto ret = advancedNotificationService_->IsNeedPushCheck(request);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number    : IsNeedPushCheck_0200
 * @tc.name      : IsNeedPushCheck_0200
 * @tc.desc      : Test IsNeedPushCheck method return true
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedPushCheck_0200, Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    auto ret = advancedNotificationService_->IsNeedPushCheck(request);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number    : TriggerAutoDelete_0100
 * @tc.name      : TriggerAutoDelete_0100
 * @tc.desc      : Test TriggerAutoDelete method when triggerNotificationList_ is empty
 */
HWTEST_F(AdvancedNotificationServiceTest, TriggerAutoDelete_0100, Level1)
{
    std::string hashCode = "hashCode";
    int32_t reason = 0;
    advancedNotificationService_->TriggerAutoDelete(hashCode, reason);
    EXPECT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 0);
}

/**
 * @tc.number    : TriggerAutoDelete_0200
 * @tc.name      : TriggerAutoDelete_0200
 * @tc.desc      : Test TriggerAutoDelete when the notification key_ does not equal the hashCode
 */
HWTEST_F(AdvancedNotificationServiceTest, TriggerAutoDelete_0200, Level1)
{
    std::string hashCode = "hashCode";
    int32_t reason = 0;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    record->notification = notificationOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    advancedNotificationService_->TriggerAutoDelete(hashCode, reason);
    EXPECT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 1);
}

/**
 * @tc.number    : TriggerAutoDelete_0300
 * @tc.name      : TriggerAutoDelete_0300
 * @tc.desc      : Test TriggerAutoDelete method when the notification key_ equals the hashCode
 */
HWTEST_F(AdvancedNotificationServiceTest, TriggerAutoDelete_0300, Level1)
{
    std::string hashCode = "hashCode";
    int32_t reason = 0;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    notificationOne->SetKey(hashCode);
    record->notification = notificationOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    advancedNotificationService_->TriggerAutoDelete(hashCode, reason);
    EXPECT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 0);
}

/**
 * @tc.number    : IsNeedNotifyConsumed_0100
 * @tc.name      : IsNeedNotifyConsumed_0100
 * @tc.desc      : Test IsNeedNotifyConsumed method return true
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedNotifyConsumed_0100, Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    auto ret = advancedNotificationService_->IsNeedNotifyConsumed(request);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number    : IsNeedNotifyConsumed_0200
 * @tc.name      : IsNeedNotifyConsumed_0200
 * @tc.desc      : Test IsNeedNotifyConsumed method return true
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedNotifyConsumed_0200, Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetDistributedCollaborate(true);
    request->SetDistributedHashCode("distributedHashCode");

    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    ASSERT_NE(reqOne, nullptr);
    reqOne->SetDistributedCollaborate(true);
    reqOne->SetDistributedHashCode("distributedHashCode");
    sptr<Notification> notificationOne(new (std::nothrow) Notification(nullptr));
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;
    record->request = reqOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    auto ret = advancedNotificationService_->IsNeedNotifyConsumed(request);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number    : IsNeedNotifyConsumed_0300
 * @tc.name      : IsNeedNotifyConsumed_0300
 * @tc.desc      : Test IsNeedNotifyConsumed method return false
 */
HWTEST_F(AdvancedNotificationServiceTest, IsNeedNotifyConsumed_0300, Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContentOne = std::make_shared<NotificationLiveViewContent>();
    liveViewContentOne->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    std::shared_ptr<NotificationContent> contentOne = std::make_shared<NotificationContent>(liveViewContentOne);
    request->SetContent(contentOne);
    request->SetDistributedCollaborate(true);
    request->SetDistributedHashCode("distributedHashCode");

    sptr<NotificationRequest> reqOne = new (std::nothrow) NotificationRequest();
    ASSERT_NE(reqOne, nullptr);
    auto liveViewContentTwo = std::make_shared<NotificationLiveViewContent>();
    liveViewContentTwo->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_CREATE);
    std::shared_ptr<NotificationContent> contentTwo = std::make_shared<NotificationContent>(liveViewContentTwo);
    reqOne->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    reqOne->SetContent(contentTwo);
    reqOne->SetDistributedCollaborate(true);
    reqOne->SetDistributedHashCode("distributedHashCode");
    sptr<Notification> notificationOne(new (std::nothrow) Notification(nullptr));
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;
    record->request = reqOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    auto ret = advancedNotificationService_->IsNeedNotifyConsumed(request);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number    : GetRecordFromNotificationList_0100
 * @tc.name      : GetRecordFromNotificationList_0100
 * @tc.desc      : Test GetRecordFromNotificationList method when triggerNotificationList_ is empty
 */
HWTEST_F(AdvancedNotificationServiceTest, GetRecordFromNotificationList_0100, Level1)
{
    int32_t notificationId = 0;
    int32_t uid = 1001;
    std::string label = "";
    std::string bundleName = "";
    int32_t userId = 100;
    auto ret =
        advancedNotificationService_->GetRecordFromNotificationList(notificationId, uid, label, bundleName, userId);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.number    : GetRecordFromNotificationList_0200
 * @tc.name      : GetRecordFromNotificationList_0200
 * @tc.desc      : Test GetRecordFromNotificationList method when triggerNotificationList_ is not empty
 */
HWTEST_F(AdvancedNotificationServiceTest, GetRecordFromNotificationList_0200, Level1)
{
    int32_t notificationId = 0;
    int32_t uid = 1001;
    std::string label = "label";
    std::string bundleName = "bundleName";
    int32_t userId = 100;

    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    ASSERT_NE(reqOne, nullptr);
    reqOne->SetLabel(label);
    reqOne->SetNotificationId(notificationId);
    reqOne->SetReceiverUserId(userId);
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));

    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(bundleName, uid);
    record->bundleOption = bundle;
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    auto ret =
        advancedNotificationService_->GetRecordFromNotificationList(notificationId, uid, label, bundleName, userId);
    ASSERT_NE(ret, nullptr);
}

/**
 * @tc.number    : RemoveFromNotificationList_0100
 * @tc.name      : RemoveFromNotificationList_0100
 * @tc.desc      : Test RemoveFromNotificationList method when the notification key_ does not equal the key
 */
HWTEST_F(AdvancedNotificationServiceTest, RemoveFromNotificationList_0100, Level1)
{
    std::string key = "notificationKey";
    sptr<Notification> notification;
    bool isCancel = false;
    int32_t removeReason = -1;

    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);

    auto ret =
        advancedNotificationService_->RemoveFromNotificationList(key, notification, isCancel, removeReason);
    EXPECT_EQ(ret, ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.number    : RemoveFromNotificationList_0200
 * @tc.name      : RemoveFromNotificationList_0200
 * @tc.desc      : Test RemoveFromNotificationList method when the notification key_ equals the key
 */
HWTEST_F(AdvancedNotificationServiceTest, RemoveFromNotificationList_0200, Level1)
{
    std::string key = "notificationKey";
    sptr<Notification> notification;
    bool isCancel = false;
    int32_t removeReason = -1;

    sptr<NotificationRequest> reqOne(new (std::nothrow) NotificationRequest());
    sptr<Notification> notificationOne(new (std::nothrow) Notification(reqOne));
    ASSERT_NE(notificationOne, nullptr);
    notificationOne->SetKey(key);
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);

    auto ret =
        advancedNotificationService_->RemoveFromNotificationList(key, notification, isCancel, removeReason);
    EXPECT_EQ(ret, ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.number    : RemoveFromNotificationListForDeleteAll_0100
 * @tc.name      : RemoveFromNotificationListForDeleteAll_0100
 * @tc.desc      : Test RemoveFromNotificationListForDeleteAll method when request has local wantAgent
 */
HWTEST_F(AdvancedNotificationServiceTest, RemoveFromNotificationListForDeleteAll_0100, Level1)
{
    std::string key = "";
    int32_t userId = 100;
    sptr<Notification> notification = nullptr;
    bool removeAll = false;
    sptr<Notification> notificationOne(new (std::nothrow) Notification(nullptr));
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    auto ret =
        advancedNotificationService_->RemoveFromNotificationListForDeleteAll(key, userId, notification, removeAll);
    EXPECT_EQ(ret, ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.number    : RemoveFromNotificationListForDeleteAll_0200
 * @tc.name      : RemoveFromNotificationListForDeleteAll_0200
 * @tc.desc      : Test RemoveFromNotificationListForDeleteAll method when the notification key_ does not equal the key
 */
HWTEST_F(AdvancedNotificationServiceTest, RemoveFromNotificationListForDeleteAll_0200, Level1)
{
    std::string key = "key";
    int32_t userId = 0;
    sptr<Notification> notification = nullptr;
    bool removeAll = false;
    sptr<Notification> notificationOne(new (std::nothrow) Notification(nullptr));
    ASSERT_NE(notificationOne, nullptr);
    notificationOne->SetKey(key);
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notificationOne;
    advancedNotificationService_->triggerNotificationList_.push_back(record);

    auto ret =
        advancedNotificationService_->RemoveFromNotificationListForDeleteAll(key, userId, notification, removeAll);
    EXPECT_EQ(ret, ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.number    : GetRemoveListForRemoveNtfBySlot_0100
 * @tc.name      : GetRemoveListForRemoveNtfBySlot_0100
 * @tc.desc      : Verify that notification with matching bundle and slot type are correctly removed
 */
HWTEST_F(AdvancedNotificationServiceTest, GetRemoveListForRemoveNtfBySlot_0100, Level1)
{
    std::string key = "key";
    std::string bundleName = "bundleName";
    int32_t uid = 2001001;
    sptr<Notification> notification(new (std::nothrow) Notification(nullptr));
    ASSERT_NE(notification, nullptr);
    notification->SetKey(key);

    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    ASSERT_NE(record, nullptr);
    record->notification = notification;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(bundleName, uid);
    record->bundleOption = bundle;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    record->request = request;

    advancedNotificationService_->triggerNotificationList_.clear();
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::LIVE_VIEW);
    ASSERT_NE(slot, nullptr);

    std::vector<std::shared_ptr<NotificationRecord>> removeList;
    EXPECT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 1);
    advancedNotificationService_->GetRemoveListForRemoveNtfBySlot(bundle, slot, removeList);
    EXPECT_EQ(advancedNotificationService_->triggerNotificationList_.size(), 0);
}

/**
 * @tc.number    : GetRemoveListForRemoveNtfBySlot_0200
 * @tc.name      : GetRemoveListForRemoveNtfBySlot_0200
 * @tc.desc      : Verify that notification with non-matching bundle are not removed
 */
HWTEST_F(AdvancedNotificationServiceTest, GetRemoveListForRemoveNtfBySlot_0200, Level1)
{
    std::string key = "key";
    std::string bundleName = "bundleName";
    std::string bundleNameOther = "bundleName.other";
    int32_t uid = 2001001;
    int32_t uidOther = 2001002;
    sptr<Notification> notification(new (std::nothrow) Notification(nullptr));
    ASSERT_NE(notification, nullptr);
    notification->SetKey(key);

    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    ASSERT_NE(record, nullptr);
    record->notification = notification;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(bundleName, uid);
    ASSERT_NE(bundle, nullptr);
    record->bundleOption = bundle;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    record->request = request;

    advancedNotificationService_->triggerNotificationList_.clear();
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::LIVE_VIEW);
    ASSERT_NE(slot, nullptr);

    std::vector<std::shared_ptr<NotificationRecord>> removeList;
    sptr<NotificationBundleOption> bundleOther = new NotificationBundleOption(bundleNameOther, uid);
    ASSERT_NE(bundleOther, nullptr);
    advancedNotificationService_->GetRemoveListForRemoveNtfBySlot(bundleOther, slot, removeList);
    EXPECT_NE(advancedNotificationService_->triggerNotificationList_.size(), 0);

    bundleOther = new NotificationBundleOption(bundleName, uidOther);
    ASSERT_NE(bundleOther, nullptr);
    advancedNotificationService_->GetRemoveListForRemoveNtfBySlot(bundleOther, slot, removeList);
    EXPECT_NE(advancedNotificationService_->triggerNotificationList_.size(), 0);
}

/**
 * @tc.number    : GetRemoveListForRemoveNtfBySlot_0300
 * @tc.name      : GetRemoveListForRemoveNtfBySlot_0300
 * @tc.desc      : Verify that notifications with matching bundle but non-matching slot type are not removed
 */
HWTEST_F(AdvancedNotificationServiceTest, GetRemoveListForRemoveNtfBySlot_0300, Level1)
{
    std::string key = "key";
    std::string bundleName = "bundleName";
    int32_t uid = 2001001;
    sptr<Notification> notification(new (std::nothrow) Notification(nullptr));
    ASSERT_NE(notification, nullptr);
    notification->SetKey(key);

    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    ASSERT_NE(record, nullptr);
    record->notification = notification;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(bundleName, uid);
    ASSERT_NE(bundle, nullptr);
    record->bundleOption = bundle;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    record->request = request;

    advancedNotificationService_->triggerNotificationList_.clear();
    advancedNotificationService_->triggerNotificationList_.push_back(record);
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::CUSTOMER_SERVICE);
    ASSERT_NE(slot, nullptr);

    std::vector<std::shared_ptr<NotificationRecord>> removeList;
    advancedNotificationService_->GetRemoveListForRemoveNtfBySlot(bundle, slot, removeList);
    EXPECT_NE(advancedNotificationService_->triggerNotificationList_.size(), 0);
}

/**
 * @tc.number    : NotificationTriggerGetTriggerType_0100
 * @tc.name      : NotificationTriggerGetTriggerType_0100
 * @tc.desc      : Verify the setter and getter methods for NotificationTrigger TriggerType property
 */
HWTEST_F(AdvancedNotificationServiceTest, NotificationTriggerGetTriggerType_0100, Level1)
{
    sptr<NotificationTrigger> notificationTrigger = new (std::nothrow) NotificationTrigger();
    ASSERT_NE(notificationTrigger, nullptr);

    NotificationConstant::TriggerType type = NotificationConstant::TriggerType::TRIGGER_TYPE_FENCE;
    notificationTrigger->SetTriggerType(type);
    EXPECT_EQ(notificationTrigger->GetTriggerType(), type);
}

/**
 * @tc.number    : NotificationTriggerGetConfigPath_0100
 * @tc.name      : NotificationTriggerGetConfigPath_0100
 * @tc.desc      : Verify the setter and getter methods for NotificationTrigger ConfigPath property
 */
HWTEST_F(AdvancedNotificationServiceTest, NotificationTriggerGetConfigPath_0100, Level1)
{
    sptr<NotificationTrigger> notificationTrigger = new (std::nothrow) NotificationTrigger();
    ASSERT_NE(notificationTrigger, nullptr);

    NotificationConstant::ConfigPath configPath = NotificationConstant::ConfigPath::CONFIG_PATH_DEVICE_CONFIG;
    notificationTrigger->SetConfigPath(configPath);
    EXPECT_EQ(notificationTrigger->GetConfigPath(), configPath);
}

/**
 * @tc.number    : NotificationTriggerGetGeofence_0100
 * @tc.name      : NotificationTriggerGetGeofence_0100
 * @tc.desc      : Verify the setter and getter methods for NotificationTrigger Geofence property
 */
HWTEST_F(AdvancedNotificationServiceTest, NotificationTriggerGetGeofence_0100, Level1)
{
    sptr<NotificationTrigger> notificationTrigger = new (std::nothrow) NotificationTrigger();
    ASSERT_NE(notificationTrigger, nullptr);

    std::shared_ptr<NotificationGeofence> condition = std::make_shared<NotificationGeofence>();
    ASSERT_NE(condition, nullptr);
    notificationTrigger->SetGeofence(condition);
    EXPECT_NE(notificationTrigger->GetGeofence(), nullptr);
}

/**
 * @tc.number    : NotificationTriggerGetDisplayTime_0100
 * @tc.name      : NotificationTriggerGetDisplayTime_0100
 * @tc.desc      : Verify the setter and getter methods for NotificationTrigger DisplayTime property
 */
HWTEST_F(AdvancedNotificationServiceTest, NotificationTriggerGetDisplayTime_0100, Level1)
{
    sptr<NotificationTrigger> notificationTrigger = new (std::nothrow) NotificationTrigger();
    ASSERT_NE(notificationTrigger, nullptr);

    int32_t displayTime = 1;
    notificationTrigger->SetDisplayTime(displayTime);
    EXPECT_EQ(notificationTrigger->GetDisplayTime(), displayTime);
}

/**
 * @tc.number    : NotificationTriggerMarshalling_0100
 * @tc.name      : NotificationTriggerMarshalling_0100
 * @tc.desc      : Verify serialization and deserialization of NotificationTrigger with all properties
 */
HWTEST_F(AdvancedNotificationServiceTest, NotificationTriggerMarshalling_0100, Level1)
{
    sptr<NotificationTrigger> notificationTrigger = new (std::nothrow) NotificationTrigger();
    ASSERT_NE(notificationTrigger, nullptr);

    NotificationConstant::TriggerType type = NotificationConstant::TriggerType::TRIGGER_TYPE_FENCE;
    notificationTrigger->SetTriggerType(type);
    NotificationConstant::ConfigPath configPath = NotificationConstant::ConfigPath::CONFIG_PATH_DEVICE_CONFIG;
    notificationTrigger->SetConfigPath(configPath);
    std::shared_ptr<NotificationGeofence> condition = std::make_shared<NotificationGeofence>();
    notificationTrigger->SetGeofence(condition);
    int32_t displayTime = 1;
    notificationTrigger->SetDisplayTime(displayTime);

    Parcel parcel;
    bool ret = notificationTrigger->Marshalling(parcel);
    ASSERT_EQ(ret, true);
    sptr<NotificationTrigger> notificationTriggerOther = notificationTrigger->Unmarshalling(parcel);
    ASSERT_NE(notificationTriggerOther, nullptr);
    EXPECT_EQ(notificationTriggerOther->GetTriggerType(), type);
    EXPECT_EQ(notificationTriggerOther->GetConfigPath(), configPath);
    EXPECT_NE(notificationTriggerOther->GetGeofence(), nullptr);
    EXPECT_EQ(notificationTriggerOther->GetDisplayTime(), displayTime);
}

/**
 * @tc.number    : NotificationTriggerMarshalling_0200
 * @tc.name      : NotificationTriggerMarshalling_0200
 * @tc.desc      : Verify serialization and deserialization of NotificationTrigger without Geofence property
 */
HWTEST_F(AdvancedNotificationServiceTest, NotificationTriggerMarshalling_0200, Level1)
{
    sptr<NotificationTrigger> notificationTrigger = new (std::nothrow) NotificationTrigger();
    ASSERT_NE(notificationTrigger, nullptr);

    NotificationConstant::TriggerType type = NotificationConstant::TriggerType::TRIGGER_TYPE_FENCE;
    notificationTrigger->SetTriggerType(type);
    NotificationConstant::ConfigPath configPath = NotificationConstant::ConfigPath::CONFIG_PATH_DEVICE_CONFIG;
    notificationTrigger->SetConfigPath(configPath);
    int32_t displayTime = 1;
    notificationTrigger->SetDisplayTime(displayTime);

    Parcel parcel;
    bool ret = notificationTrigger->Marshalling(parcel);
    ASSERT_EQ(ret, true);
    sptr<NotificationTrigger> notificationTriggerOther = notificationTrigger->Unmarshalling(parcel);
    ASSERT_NE(notificationTriggerOther, nullptr);
    EXPECT_EQ(notificationTriggerOther->GetTriggerType(), type);
    EXPECT_EQ(notificationTriggerOther->GetConfigPath(), configPath);
    EXPECT_EQ(notificationTriggerOther->GetGeofence(), nullptr);
    EXPECT_EQ(notificationTriggerOther->GetDisplayTime(), displayTime);
}

/**
 * @tc.number    : NotificationTriggerToJson_0100
 * @tc.name      : NotificationTriggerToJson_0100
 * @tc.desc      : Verify JSON serialization and deserialization of NotificationTrigger with all properties
 */
HWTEST_F(AdvancedNotificationServiceTest, NotificationTriggerToJson_0100, Level1)
{
    sptr<NotificationTrigger> notificationTrigger = new (std::nothrow) NotificationTrigger();
    ASSERT_NE(notificationTrigger, nullptr);

    NotificationConstant::TriggerType type = NotificationConstant::TriggerType::TRIGGER_TYPE_FENCE;
    notificationTrigger->SetTriggerType(type);
    NotificationConstant::ConfigPath configPath = NotificationConstant::ConfigPath::CONFIG_PATH_DEVICE_CONFIG;
    notificationTrigger->SetConfigPath(configPath);
    std::shared_ptr<NotificationGeofence> condition = std::make_shared<NotificationGeofence>();
    notificationTrigger->SetGeofence(condition);
    int32_t displayTime = 1;
    notificationTrigger->SetDisplayTime(displayTime);

    nlohmann::json jsonObject;
    bool ret = notificationTrigger->ToJson(jsonObject);
    ASSERT_EQ(ret, true);
    sptr<NotificationTrigger> notificationTriggerOther = notificationTrigger->FromJson(jsonObject);
    ASSERT_NE(notificationTriggerOther, nullptr);
    EXPECT_EQ(notificationTriggerOther->GetTriggerType(), type);
    EXPECT_EQ(notificationTriggerOther->GetConfigPath(), configPath);
    EXPECT_NE(notificationTriggerOther->GetGeofence(), nullptr);
    EXPECT_EQ(notificationTriggerOther->GetDisplayTime(), displayTime);
}

/**
 * @tc.number    : NotificationTriggerToJson_0200
 * @tc.name      : NotificationTriggerToJson_0200
 * @tc.desc      : Verify JSON serialization and deserialization of NotificationTrigger without Geofence property
 */
HWTEST_F(AdvancedNotificationServiceTest, NotificationTriggerToJson_0200, Level1)
{
    sptr<NotificationTrigger> notificationTrigger = new (std::nothrow) NotificationTrigger();
    ASSERT_NE(notificationTrigger, nullptr);

    NotificationConstant::TriggerType type = NotificationConstant::TriggerType::TRIGGER_TYPE_FENCE;
    notificationTrigger->SetTriggerType(type);
    NotificationConstant::ConfigPath configPath = NotificationConstant::ConfigPath::CONFIG_PATH_DEVICE_CONFIG;
    notificationTrigger->SetConfigPath(configPath);
    int32_t displayTime = 1;
    notificationTrigger->SetDisplayTime(displayTime);

    nlohmann::json jsonObject;
    bool ret = notificationTrigger->ToJson(jsonObject);
    ASSERT_EQ(ret, true);
    sptr<NotificationTrigger> notificationTriggerOther = notificationTrigger->FromJson(jsonObject);
    ASSERT_NE(notificationTriggerOther, nullptr);
    EXPECT_EQ(notificationTriggerOther->GetTriggerType(), type);
    EXPECT_EQ(notificationTriggerOther->GetConfigPath(), configPath);
    EXPECT_EQ(notificationTriggerOther->GetGeofence(), nullptr);
    EXPECT_EQ(notificationTriggerOther->GetDisplayTime(), displayTime);
}

/**
 * @tc.number    : NotificationTriggerDump_0100
 * @tc.name      : NotificationTriggerDump_0100
 * @tc.desc      : Verify Dump method of NotificationTrigger outputs correct information including display time
 */
HWTEST_F(AdvancedNotificationServiceTest, NotificationTriggerDump_0100, Level1)
{
    sptr<NotificationTrigger> notificationTrigger = new (std::nothrow) NotificationTrigger();
    ASSERT_NE(notificationTrigger, nullptr);

    NotificationConstant::TriggerType type = NotificationConstant::TriggerType::TRIGGER_TYPE_FENCE;
    notificationTrigger->SetTriggerType(type);
    NotificationConstant::ConfigPath configPath = NotificationConstant::ConfigPath::CONFIG_PATH_DEVICE_CONFIG;
    notificationTrigger->SetConfigPath(configPath);
    int32_t displayTime = 100;
    notificationTrigger->SetDisplayTime(displayTime);

    std::string triggerDump = notificationTrigger->Dump();
    auto it = triggerDump.find(std::to_string(displayTime));
    bool result = it != std::string::npos ? true : false;
    EXPECT_EQ(result, true);
}
}  // namespace Notification
}  // namespace OHOS
