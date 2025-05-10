/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "ans_dialog_callback_stub.h"
#include "errors.h"
#include "notification_slot.h"
#include "refbase.h"
#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <new>

#define private public
#define protected public
#include "ans_notification.h"
#include "ans_subscriber_proxy.h"
#include "ans_manager_proxy.h"
#undef private
#undef protected
#include "ans_inner_errors.h"
#include "ipc_types.h"
#include "mock_i_remote_object.h"
#include "notification.h"
#include "singleton.h"
#include "notification_subscriber.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;

extern void MockWriteInterfaceToken(bool mockRet);

namespace OHOS {
namespace Notification {
class AnsNotificationUnitTest : public testing::Test {
public:
    AnsNotificationUnitTest() {}

    virtual ~AnsNotificationUnitTest() {}

    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
    std::shared_ptr<AnsNotification> ans_;
    sptr<AnsManagerInterface> ansManagerProxy_{nullptr};
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    void UpdateStatuts(bool isEnable, int status) {}
#endif
};

void AnsNotificationUnitTest::SetUpTestCase()
{
    MockWriteInterfaceToken(true);
}

void AnsNotificationUnitTest::TearDownTestCase() {}

void AnsNotificationUnitTest::SetUp()
{
    if (!ans_) {
        ans_ = DelayedSingleton<AnsNotification>::GetInstance();
    }
}

void AnsNotificationUnitTest::TearDown() {}

class TestAnsSubscriber : public NotificationSubscriber {
public:
    void OnConnected() override
    {}
    void OnDisconnected() override
    {}
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
    void OnDied() override
    {}
    void OnEnabledNotificationChanged(
        const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override
    {}
    void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int deleteReason) override
    {}
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override
    {}
    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>>
        &requestList, const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override
    {}
};

/*
 * @tc.name: GetAnsManagerProxy_0100
 * @tc.desc: test GetAnsManagerProxy return false.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetAnsManagerProxy_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool res = ans_->GetAnsManagerProxy();
    EXPECT_EQ(res, false);
}

/*
 * @tc.name: AddSlotByType_0100
 * @tc.desc: test AddSlotByType ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, AddSlotByType_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::CUSTOM;
    ErrCode ret1 = ans_->AddSlotByType(slotType);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret3 = ans_->RemoveNotificationSlot(slotType);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: RemoveAllSlots_0100
 * @tc.desc: test RemoveAllSlots ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, RemoveAllSlots_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    ErrCode ret1 = ans_->RemoveAllSlots();
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: GetNotificationSlot_0100
 * @tc.desc: test GetNotificationSlot ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetNotificationSlot_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::CUSTOM;
    sptr<NotificationSlot> slot = new NotificationSlot();
    ErrCode ret1 = ans_->GetNotificationSlot(slotType, slot);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    std::vector<sptr<NotificationSlot>> slots;
    slots.emplace_back(slot);
    ErrCode ret2 = ans_->GetNotificationSlots(slots);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    std::vector<NotificationSlot> nslots;
    NotificationSlot notificationSlot;
    nslots.emplace_back(notificationSlot);
    ErrCode ret3 = ans_->AddNotificationSlots(nslots);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: GetNotificationSlotNumAsBundle_0100
 * @tc.desc: test GetNotificationSlotNumAsBundle ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetNotificationSlotNumAsBundle_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationBundleOption bundleOptions;
    std::string bundleName = "bundleName";
    bundleOptions.SetBundleName(bundleName);
    uint64_t num = 10;
    ErrCode ret1 = ans_->GetNotificationSlotNumAsBundle(bundleOptions, num);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: GetNotificationSlotFlagsAsBundle_0100
 * @tc.desc: test GetNotificationSlotFlagsAsBundle.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetNotificationSlotFlagsAsBundle_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationBundleOption bundleOptions;
    std::string bundleName = "bundleName";
    bundleOptions.SetBundleName(bundleName);
    uint32_t num = 10;
    ErrCode ret1 = ans_->GetNotificationSlotFlagsAsBundle(bundleOptions, num);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: GetNotificationSlotFlagsAsBundle_0200
 * @tc.desc: test GetNotificationSlotFlagsAsBundle.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetNotificationSlotFlagsAsBundle_0200, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationBundleOption bundleOptions;
    bundleOptions.SetBundleName("");
    uint32_t num = 10;
    ErrCode ret1 = ans_->GetNotificationSlotFlagsAsBundle(bundleOptions, num);
    EXPECT_EQ(ret1, ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: SetNotificationSlotFlagsAsBundle_0200
 * @tc.desc: test GetNotificationSlotFlagsAsBundle.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SetNotificationSlotFlagsAsBundle_0200, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationBundleOption bundleOptions;
    bundleOptions.SetBundleName("");
    uint64_t num = 10;
    ErrCode ret1 = ans_->SetNotificationSlotFlagsAsBundle(bundleOptions, num);
    EXPECT_EQ(ret1, ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: CanPopEnableNotificationDialog_0100
 * @tc.desc: test CanPopEnableNotificationDialog.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, CanPopEnableNotificationDialog_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    sptr<AnsDialogHostClient> client = nullptr;
    bool enable = true;
    std::string bundleName = "";
    ErrCode ret1 = ans_->CanPopEnableNotificationDialog(client, enable, bundleName);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: RemoveNotifications_0100
 * @tc.desc: test RemoveNotifications.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, RemoveNotifications_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::vector<std::string> hashCodes = {"data1", "data2"};
    ErrCode ret1 = ans_->RemoveNotifications(hashCodes, 1);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: GetNotificationSlotForBundle_0100
 * @tc.desc: test GetNotificationSlotForBundle.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetNotificationSlotForBundle_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationBundleOption bundleOptions;
    bundleOptions.SetBundleName("name");
    sptr<NotificationSlot> slot = new NotificationSlot();
    ErrCode ret1 = ans_->GetNotificationSlotForBundle(bundleOptions,
        NotificationConstant::SlotType::CONTENT_INFORMATION, slot);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: GetNotificationSlotForBundle_0200
 * @tc.desc: test GetNotificationSlotForBundle.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetNotificationSlotForBundle_0200, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationBundleOption bundleOptions;
    bundleOptions.SetBundleName("");
    sptr<NotificationSlot> slot = new NotificationSlot();
    ErrCode ret1 = ans_->GetNotificationSlotForBundle(bundleOptions,
        NotificationConstant::SlotType::CONTENT_INFORMATION, slot);
    EXPECT_EQ(ret1, ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: GetEnabledForBundleSlotSelf_0100
 * @tc.desc: test GetEnabledForBundleSlotSelf.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetEnabledForBundleSlotSelf_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    bool enable = true;
    ErrCode ret1 = ans_->GetEnabledForBundleSlotSelf(
        NotificationConstant::SlotType::CONTENT_INFORMATION, enable);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: RegisterPushCallback_0100
 * @tc.desc: test RegisterPushCallback.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, RegisterPushCallback_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    sptr<AnsDialogHostClient> callback = new AnsDialogHostClient();
    sptr<NotificationCheckRequest> checkRequest = nullptr;
    ErrCode ret1 = ans_->RegisterPushCallback(callback->AsObject(), checkRequest);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: UnregisterPushCallback_0100
 * @tc.desc: test UnregisterPushCallback.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, UnregisterPushCallback_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    ErrCode ret1 = ans_->UnregisterPushCallback();
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SetAdditionConfig_0100
 * @tc.desc: test SetAdditionConfig.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SetAdditionConfig_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string key = "key";
    std::string value = "value";
    ErrCode ret1 = ans_->SetAdditionConfig(key, value);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SetAdditionConfig_0200
 * @tc.desc: test SetAdditionConfig.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SetAdditionConfig_0200, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string key = "";
    std::string value = "value";
    ErrCode ret1 = ans_->SetAdditionConfig(key, value);
    EXPECT_EQ(ret1, ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: CancelAsBundleWithAgent_0100
 * @tc.desc: test CancelAsBundleWithAgent.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, CancelAsBundleWithAgent_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    int32_t id = 1;
    NotificationBundleOption bundleOption = NotificationBundleOption();
    ErrCode ret1 = ans_->CancelAsBundleWithAgent(bundleOption, id);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SetTargetDeviceStatus_0100
 * @tc.desc: test SetAdditionConfig.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SetTargetDeviceStatus_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string deviceType = "device";
    const uint32_t status = 1;
    ErrCode ret1 = ans_->SetTargetDeviceStatus(deviceType, status);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: PublishNotification_0100
 * @tc.desc: test PublishNotification ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, PublishNotification_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string label = "this is label";
    NotificationRequest request;
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    request.SetContent(content);
    ErrCode ret1 = ans_->PublishNotification(label, request);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    int32_t notificationId = 10;
    ErrCode ret3 = ans_->CancelNotification(label, notificationId);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret4 = ans_->CancelAllNotifications();
    EXPECT_EQ(ret4, ERR_ANS_SERVICE_NOT_CONNECTED);
    std::string representativeBundle = "this is representativeBundle";
    int32_t userId = 5;
    ErrCode ret5 = ans_->CancelAsBundle(notificationId, representativeBundle, userId);
    EXPECT_EQ(ret5, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: GetActiveNotificationNums_0100
 * @tc.desc: test GetActiveNotificationNums ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetActiveNotificationNums_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    uint64_t num = 4;
    ErrCode ret1 = ans_->GetActiveNotificationNums(num);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    std::vector<sptr<NotificationRequest>> request;
    ErrCode ret2 = ans_->GetActiveNotifications(request);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: CanPublishNotificationAsBundle_0100
 * @tc.desc: test CanPublishNotificationAsBundle ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, CanPublishNotificationAsBundle_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string representativeBundle = "this is representativeBundle";
    bool canPublish = true;
    ErrCode ret1 = ans_->CanPublishNotificationAsBundle(representativeBundle, canPublish);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    std::string representativeBundle0 = "";
    ErrCode ret2 = ans_->CanPublishNotificationAsBundle(representativeBundle0, canPublish);
    EXPECT_EQ(ret2, ERR_ANS_INVALID_PARAM);
    NotificationRequest request;
    ErrCode ret3 = ans_->PublishNotificationAsBundle(representativeBundle0, request);
    EXPECT_EQ(ret3, ERR_ANS_INVALID_PARAM);
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    request.SetContent(content);
    ErrCode ret5 = ans_->PublishNotificationAsBundle(representativeBundle, request);
    EXPECT_EQ(ret5, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SetNotificationBadgeNum_0100
 * @tc.desc: test SetNotificationBadgeNum ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SetNotificationBadgeNum_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    ErrCode ret1 = ans_->SetNotificationBadgeNum();
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    int32_t num = 3;
    ErrCode ret2 = ans_->SetNotificationBadgeNum(num);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: IsAllowedNotify_0100
 * @tc.desc: test IsAllowedNotify ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, IsAllowedNotify_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    bool allowed = true;
    ErrCode ret1 = ans_->IsAllowedNotify(allowed);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret2 = ans_->IsAllowedNotifySelf(allowed);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    ErrCode ret3 = ans_->IsAllowedNotify(bundleOption, allowed);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: RequestEnableNotification_0100
 * @tc.desc: test RequestEnableNotification ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, RequestEnableNotification_0100, Function | MediumTest | Level1)
{
    ans_->GetAnsManagerProxy();
    std::string deviceId = "this is deviceId";
    sptr<IRemoteObject> callerToken = nullptr;
    sptr<AnsDialogHostClient> client = nullptr;
    AnsDialogHostClient::CreateIfNullptr(client);
    client = AnsDialogHostClient::GetInstance();
    ErrCode ret1 = ans_->RequestEnableNotification(deviceId, client, callerToken);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    bool hasPermission = true;
    ErrCode ret3 = ans_->HasNotificationPolicyAccessPermission(hasPermission);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: GetBundleImportance_0100
 * @tc.desc: test GetBundleImportance ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetBundleImportance_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationSlot::NotificationLevel importance = NotificationSlot::NotificationLevel::LEVEL_NONE;
    ErrCode ret1 = ans_->GetBundleImportance(importance);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: RemoveNotification_0100
 * @tc.desc: test RemoveNotification ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, RemoveNotification_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string key = "";
    int32_t removeReason = 10;
    ErrCode ret1 = ans_->RemoveNotification(key, removeReason);
    EXPECT_EQ(ret1, ERR_ANS_INVALID_PARAM);
    std::string key1 = "this is key1";
    ErrCode ret2 = ans_->RemoveNotification(key1, removeReason);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    int32_t notificationId = 2;
    std::string label = "this is label";
    ErrCode ret3 = ans_->RemoveNotification(bundleOption, notificationId, label, removeReason);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret4 = ans_->RemoveAllNotifications(bundleOption);
    EXPECT_EQ(ret4, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret5 = ans_->RemoveNotificationsByBundle(bundleOption);
    EXPECT_EQ(ret5, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret6 = ans_->RemoveNotifications();
    EXPECT_EQ(ret6, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: GetNotificationSlotsForBundle_0100
 * @tc.desc: test GetNotificationSlotsForBundle ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetNotificationSlotsForBundle_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    sptr<NotificationSlot> slot = new NotificationSlot();
    std::vector<sptr<NotificationSlot>> slots;
    slots.emplace_back(slot);
    ErrCode ret1 = ans_->GetNotificationSlotsForBundle(bundleOption, slots);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret2 = ans_->UpdateNotificationSlots(bundleOption, slots);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SetNotificationsEnabledForAllBundles_0100
 * @tc.desc: test SetNotificationsEnabledForAllBundles ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SetNotificationsEnabledForAllBundles_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string deviceId = "this is deviceId";
    bool enabled = true;
    ErrCode ret1 = ans_->SetNotificationsEnabledForAllBundles(deviceId, enabled);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret2 = ans_->SetNotificationsEnabledForDefaultBundle(deviceId, enabled);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    ErrCode ret3 = ans_->SetNotificationsEnabledForSpecifiedBundle(bundleOption, deviceId, enabled);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret4 = ans_->SetShowBadgeEnabledForBundle(bundleOption, enabled);
    EXPECT_EQ(ret4, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret5 = ans_->GetShowBadgeEnabledForBundle(bundleOption, enabled);
    EXPECT_EQ(ret5, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret6 = ans_->GetShowBadgeEnabled(enabled);
    EXPECT_EQ(ret6, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: CancelGroup_0100
 * @tc.desc: test CancelGroup ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, CancelGroup_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string groupName = "this is groupName";
    ErrCode ret1 = ans_->CancelGroup(groupName);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    ErrCode ret2 = ans_->RemoveGroupByBundle(bundleOption, groupName);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SetDoNotDisturbDate_0100
 * @tc.desc: test SetDoNotDisturbDate ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SetDoNotDisturbDate_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationDoNotDisturbDate doNotDisturbDate;
    ErrCode ret1 = ans_->SetDoNotDisturbDate(doNotDisturbDate);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret2 = ans_->GetDoNotDisturbDate(doNotDisturbDate);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    bool doesSupport = true;
    ErrCode ret3 = ans_->DoesSupportDoNotDisturbMode(doesSupport);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: PublishContinuousTaskNotification_0100
 * @tc.desc: test PublishContinuousTaskNotification ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, PublishContinuousTaskNotification_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationRequest request;
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    request.SetContent(content);
    ErrCode ret1 = ans_->PublishContinuousTaskNotification(request);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    std::string label = "this is label";
    int32_t notificationId = 3;
    ErrCode ret2 = ans_->CancelContinuousTaskNotification(label, notificationId);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: IsDistributedEnabled_0100
 * @tc.desc: test IsDistributedEnabled ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, IsDistributedEnabled_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    bool enabled = true;
    ErrCode ret1 = ans_->IsDistributedEnabled(enabled);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret2 = ans_->EnableDistributed(enabled);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    NotificationBundleOption bundleOption;
    ErrCode ret3 = ans_->EnableDistributedByBundle(bundleOption, enabled);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret4 = ans_->EnableDistributedSelf(enabled);
    EXPECT_EQ(ret4, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret5 = ans_->IsDistributedEnableByBundle(bundleOption, enabled);
    EXPECT_EQ(ret5, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: IsSupportTemplate_0100
 * @tc.desc: test IsSupportTemplate ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, IsSupportTemplate_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string templateName = "this is templateName";
    bool support = true;
    ErrCode ret1 = ans_->IsSupportTemplate(templateName, support);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    int32_t userId = -1;
    bool allowed = true;
    ErrCode ret2 = ans_->IsAllowedNotify(userId, allowed);
    EXPECT_EQ(ret2, ERR_ANS_INVALID_PARAM);
    int32_t userId1 = 2;
    ErrCode ret3 = ans_->IsAllowedNotify(userId1, allowed);
    EXPECT_EQ(ret3, ERR_ANS_SERVICE_NOT_CONNECTED);
    bool enabled = true;
    ErrCode ret4 = ans_->SetNotificationsEnabledForAllBundles(userId, enabled);
    EXPECT_EQ(ret4, ERR_ANS_INVALID_PARAM);
    ErrCode ret5 = ans_->SetNotificationsEnabledForAllBundles(userId1, enabled);
    EXPECT_EQ(ret5, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret6 = ans_->RemoveNotifications(userId);
    EXPECT_EQ(ret6, ERR_ANS_INVALID_PARAM);
    ErrCode ret7 = ans_->RemoveNotifications(userId1);
    EXPECT_EQ(ret7, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SetDoNotDisturbDate_0200
 * @tc.desc: test SetDoNotDisturbDate ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SetDoNotDisturbDate_0200, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    int32_t userId = -1;
    NotificationDoNotDisturbDate doNotDisturbDate;
    ErrCode ret1 = ans_->SetDoNotDisturbDate(userId, doNotDisturbDate);
    EXPECT_EQ(ret1, ERR_ANS_INVALID_PARAM);
    int32_t userId1 = 2;
    ErrCode ret2 = ans_->SetDoNotDisturbDate(userId1, doNotDisturbDate);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret3 = ans_->GetDoNotDisturbDate(userId, doNotDisturbDate);
    EXPECT_EQ(ret3, ERR_ANS_INVALID_PARAM);
    ErrCode ret4 = ans_->GetDoNotDisturbDate(userId1, doNotDisturbDate);
    EXPECT_EQ(ret4, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SetEnabledForBundleSlot_0100
 * @tc.desc: test SetEnabledForBundleSlot ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SetEnabledForBundleSlot_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject_ = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject_);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject_);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    NotificationBundleOption bundleOption;
    std::string bundleName = "bundleName";
    bundleOption.SetBundleName(bundleName);
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::CUSTOM;
    bool enabled = true;
    bool isForceControl = false;
    ErrCode ret1 = ans_->SetEnabledForBundleSlot(bundleOption, slotType, enabled, isForceControl);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret2 = ans_->GetEnabledForBundleSlot(bundleOption, slotType, enabled);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: ShellDump_0100
 * @tc.desc: test ShellDump ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, ShellDump_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string cmd = "this is cmd";
    std::string bundle = "this is bundle";
    int32_t userId = 1;
    std::vector<std::string> dumpInfo;
    ErrCode ret1 = ans_->ShellDump(cmd, bundle, userId, 0, dumpInfo);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SetSyncNotificationEnabledWithoutApp_0100
 * @tc.desc: test SetSyncNotificationEnabledWithoutApp ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SetSyncNotificationEnabledWithoutApp_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    int32_t userId = -1;
    bool enabled = true;
    ErrCode ret1 = ans_->SetSyncNotificationEnabledWithoutApp(userId, enabled);
    EXPECT_EQ(ret1, ERR_ANS_INVALID_PARAM);
    int32_t userId1 = 2;
    ErrCode ret2 = ans_->SetSyncNotificationEnabledWithoutApp(userId1, enabled);
    EXPECT_EQ(ret2, ERR_ANS_SERVICE_NOT_CONNECTED);
    ErrCode ret3 = ans_->GetSyncNotificationEnabledWithoutApp(userId, enabled);
    EXPECT_EQ(ret3, ERR_ANS_INVALID_PARAM);
    ErrCode ret4 = ans_->GetSyncNotificationEnabledWithoutApp(userId1, enabled);
    EXPECT_EQ(ret4, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SubscribeNotification_0100
 * @tc.desc: test SubscribeNotification return false.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SubscribeNotification_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject_ = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject_);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject_);
    ASSERT_NE(nullptr, proxy);
    bool res = ans_->GetAnsManagerProxy();
    EXPECT_EQ(res, false);

    auto subscriber = TestAnsSubscriber();
    NotificationSubscribeInfo info;
    ErrCode ret1 = ans_->SubscribeNotification(subscriber, info);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SubscribeNotification_0200
 * @tc.desc: test SubscribeNotification return false.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SubscribeNotification_0200, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool res = ans_->GetAnsManagerProxy();
    EXPECT_EQ(res, false);

    auto subscriber = TestAnsSubscriber();
    ErrCode ret1 = ans_->SubscribeNotification(subscriber);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SubscribeNotification_0300
 * @tc.desc: test SubscribeNotification return false.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SubscribeNotification_0300, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject_ = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject_);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject_);
    ASSERT_NE(nullptr, proxy);
    bool res = ans_->GetAnsManagerProxy();
    EXPECT_EQ(res, false);

    auto subscriber = std::make_shared<TestAnsSubscriber>();
    sptr<NotificationSubscribeInfo> info = new (std::nothrow) NotificationSubscribeInfo();
    ErrCode ret1 = ans_->SubscribeNotification(subscriber, info);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SubscribeNotification_0400
 * @tc.desc: test SubscribeNotification return false.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SubscribeNotification_0400, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool res = ans_->GetAnsManagerProxy();
    EXPECT_EQ(res, false);

    ErrCode ret1 = ans_->SubscribeNotification(nullptr);
    EXPECT_EQ(ret1, ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: GetAllActiveNotifications_0100
 * @tc.desc: test GetAllActiveNotifications return false.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetAllActiveNotifications_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool res = ans_->GetAnsManagerProxy();
    EXPECT_EQ(res, false);

    std::vector<sptr<Notification>> notification;
    ErrCode ret1 = ans_->GetAllActiveNotifications(notification);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: GetAllActiveNotifications_0200
 * @tc.desc: test GetAllActiveNotifications return false.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, GetAllActiveNotifications_0200, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool res = ans_->GetAnsManagerProxy();
    EXPECT_EQ(res, false);

    std::vector<std::string> key;
    std::vector<sptr<Notification>> notification;
    ErrCode ret1 = ans_->GetAllActiveNotifications(key, notification);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: UnSubscribeNotification_0100
 * @tc.desc: test UnSubscribeNotification return false.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, UnSubscribeNotification_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool res = ans_->GetAnsManagerProxy();
    EXPECT_EQ(res, false);

    auto subscriber = TestAnsSubscriber();
    ErrCode ret1 = ans_->UnSubscribeNotification(subscriber);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: UnSubscribeNotification_0200
 * @tc.desc: test UnSubscribeNotification return false.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, UnSubscribeNotification_0200, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool res = ans_->GetAnsManagerProxy();
    EXPECT_EQ(res, false);

    auto subscriber = TestAnsSubscriber();
    NotificationSubscribeInfo info;
    ErrCode ret1 = ans_->UnSubscribeNotification(subscriber, info);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: UnSubscribeNotification_0300
 * @tc.desc: test UnSubscribeNotification return false.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, UnSubscribeNotification_0300, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool res = ans_->GetAnsManagerProxy();
    EXPECT_EQ(res, false);

    auto subscriber = std::make_shared<TestAnsSubscriber>();
    ErrCode ret1 = ans_->UnSubscribeNotification(subscriber);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: UnSubscribeNotification_0400
 * @tc.desc: test UnSubscribeNotification return false.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, UnSubscribeNotification_0400, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool res = ans_->GetAnsManagerProxy();
    EXPECT_EQ(res, false);

    auto subscriber = std::make_shared<TestAnsSubscriber>();
    sptr<NotificationSubscribeInfo> info = new (std::nothrow) NotificationSubscribeInfo();
    ErrCode ret1 = ans_->UnSubscribeNotification(subscriber, info);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SetNotificationsEnabledForSpecifiedBundle_0100
 * @tc.desc: test SetNotificationsEnabledForSpecifiedBundle ErrCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, SetNotificationsEnabledForSpecifiedBundle_0100, Function | MediumTest | Level1)
{
    std::string deviceId = "this is deviceId";
    bool enabled = true;
    NotificationBundleOption bundleOption;
    std::string bundleName = "";
    bundleOption.SetBundleName(bundleName);
    ErrCode ret3 = ans_->SetNotificationsEnabledForSpecifiedBundle(bundleOption, deviceId, enabled);
    EXPECT_EQ(ret3, ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: GetAllNotificationEnabledBundles_0100
 * @tc.desc: test GetAllNotificationEnabledBundles ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I92VGR
 */
HWTEST_F(AnsNotificationUnitTest, GetAllNotificationEnabledBundles_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::vector<NotificationBundleOption> bundleOption;
    ErrCode ret = ans_->GetAllNotificationEnabledBundles(bundleOption);
    EXPECT_EQ(ret, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: CancelGroup_0200
 * @tc.desc: test CancelGroup ErrCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitTest, CancelGroup_0200, Function | MediumTest | Level1)
{
    std::string groupName = "";
    ErrCode ret1 = ans_->CancelGroup(groupName);
    EXPECT_EQ(ret1, ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: SetSmartReminderEnabled_0100
 * @tc.desc: test SetSmartReminderEnabled with parameters, expect errorCode ERR_ANS_SERVICE_NOT_CONNECTED
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, SetSmartReminderEnabled_0100, TestSize.Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool ret = ans_->GetAnsManagerProxy();
    EXPECT_EQ(ret, false);
    ErrCode res = ans_->SetSmartReminderEnabled("testDeviceType", true);
    EXPECT_EQ(res, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/**
 * @tc.name: IsSmartReminderEnabled_0100
 * @tc.desc: test IsSmartReminderEnabled with parameters, expect errorCode ERR_ANS_SERVICE_NOT_CONNECTED
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, IsSmartReminderEnabled_0100, TestSize.Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool ret = ans_->GetAnsManagerProxy();
    EXPECT_EQ(ret, false);
    bool enable = true;
    ErrCode result = ans_->IsSmartReminderEnabled("testDeviceType1111", enable);
    EXPECT_EQ(result, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SetBadgeNumberByBundle_0100
 * @tc.desc: test SetBadgeNumberByBundle with empty bundleOption, expect ErrCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, SetBadgeNumberByBundle_0100, TestSize.Level1)
{
    NotificationBundleOption bundleOption;
    int32_t badgeNumber = 0;
    ErrCode res = ans_->SetBadgeNumberByBundle(bundleOption, badgeNumber);
    EXPECT_EQ(res, ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: SetBadgeNumberByBundle_0200
 * @tc.desc: test SetBadgeNumberByBundle with invalid AnsManagerProxy, expect ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, SetBadgeNumberByBundle_0200, TestSize.Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool ret = ans_->GetAnsManagerProxy();
    EXPECT_EQ(ret, false);

    NotificationBundleOption bundleOption;
    std::string bundleName = "bundleName";
    bundleOption.SetBundleName(bundleName);
    int32_t badgeNumber = 0;
    ErrCode res = ans_->SetBadgeNumberByBundle(bundleOption, badgeNumber);
    EXPECT_EQ(res, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: SetDistributedEnabledByBundle_0100
 * @tc.desc: test SetDistributedEnabledByBundle with parameters, expect errorCode ERR_ANS_SERVICE_NOT_CONNECTED
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, SetDistributedEnabledByBundle_0100, TestSize.Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool ret = ans_->GetAnsManagerProxy();
    EXPECT_EQ(ret, false);

    NotificationBundleOption bundleOption;
    std::string bundleName = "bundleName";
    bundleOption.SetBundleName(bundleName);
    bundleOption.SetUid(1);
    std::string deviceType = "testDeviceType";

    ErrCode res = ans_->SetDistributedEnabledByBundle(bundleOption, deviceType, true);
    EXPECT_EQ(res, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/**
 * @tc.name: SetDistributedEnabledByBundle_0200
 * @tc.desc: test SetDistributedEnabledByBundle with parameters, expect errorCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, SetDistributedEnabledByBundle_0200, TestSize.Level1)
{
    NotificationBundleOption bundleOption;
    std::string deviceType = "testDeviceType";
    ErrCode ret = ans_->SetDistributedEnabledByBundle(bundleOption, deviceType, true);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetDistributedEnabledByBundle_0300
 * @tc.desc: test SetDistributedEnabledByBundle with parameters, expect errorCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, SetDistributedEnabledByBundle_0300, TestSize.Level1)
{
    NotificationBundleOption bundleOption;
    bundleOption.SetBundleName("");
    bundleOption.SetUid(1);
    std::string deviceType = "testDeviceType";
    ErrCode ret = ans_->SetDistributedEnabledByBundle(bundleOption, deviceType, true);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}


/**
 * @tc.name: IsDistributedEnabledByBundle_0100
 * @tc.desc: test IsDistributedEnabledByBundle with parameters, expect errorCode ERR_ANS_SERVICE_NOT_CONNECTED
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, IsDistributedEnabledByBundle_0100, TestSize.Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool ret = ans_->GetAnsManagerProxy();
    EXPECT_EQ(ret, false);

    NotificationBundleOption bundleOption;
    std::string bundleName = "bundleName";
    bundleOption.SetBundleName(bundleName);
    bundleOption.SetUid(1);
    std::string deviceType = "testDeviceType1111";
    bool enable = true;
    ErrCode result = ans_->IsDistributedEnabledByBundle(bundleOption, deviceType, enable);
    EXPECT_EQ(result, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/**
 * @tc.name: IsDistributedEnabledByBundle_0200
 * @tc.desc: test IsDistributedEnabledByBundle with parameters, expect errorCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, IsDistributedEnabledByBundle_0200, TestSize.Level1)
{
    MockWriteInterfaceToken(true);
    NotificationBundleOption bundleOption;
    std::string deviceType = "testDeviceType";

    bool enable = true;
    ErrCode ret = ans_->IsDistributedEnabledByBundle(bundleOption, deviceType, enable);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: IsDistributedEnabledByBundle_0300
 * @tc.desc: test IsDistributedEnabledByBundle with parameters, expect errorCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, IsDistributedEnabledByBundle_0300, TestSize.Level1)
{
    MockWriteInterfaceToken(true);
    NotificationBundleOption bundleOption;
    bundleOption.SetBundleName("");
    bundleOption.SetUid(1);
    std::string deviceType = "testDeviceType";

    bool enable = true;
    ErrCode ret = ans_->IsDistributedEnabledByBundle(bundleOption, deviceType, enable);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: AddDoNotDisturbProfiles_0100
 * @tc.desc: test AddDoNotDisturbProfiles ErrCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, AddDoNotDisturbProfiles_0100, TestSize.Level1)
{
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    profiles.clear();
    ErrCode ret1 = ans_->AddDoNotDisturbProfiles(profiles);
    EXPECT_EQ(ret1, ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: AddDoNotDisturbProfiles_0200
 * @tc.desc: test AddDoNotDisturbProfiles ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, AddDoNotDisturbProfiles_0200, TestSize.Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool res = ans_->GetAnsManagerProxy();
    EXPECT_EQ(res, false);

    int32_t id = 1;
    std::string name = "Name";
    std::vector<NotificationBundleOption> trustlist;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> disturbProfile =
        new (std::nothrow) NotificationDoNotDisturbProfile(id, name, trustlist);
    profiles.emplace_back(disturbProfile);

    ErrCode ret1 = ans_->AddDoNotDisturbProfiles(profiles);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: RemoveDoNotDisturbProfiles_0100
 * @tc.desc: test RemoveDoNotDisturbProfiles ErrCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, RemoveDoNotDisturbProfiles_0100, TestSize.Level1)
{
    vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    profiles.clear();
    ErrCode ret1 = ans_->RemoveDoNotDisturbProfiles(profiles);
    EXPECT_EQ(ret1, ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: RemoveDoNotDisturbProfiles_0200
 * @tc.desc: test RemoveDoNotDisturbProfiles ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, RemoveDoNotDisturbProfiles_0200, TestSize.Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool res = ans_->GetAnsManagerProxy();
    EXPECT_EQ(res, false);

    int32_t id = 1;
    std::string name = "Name";
    std::vector<NotificationBundleOption> trustlist;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> disturbProfile =
        new (std::nothrow) NotificationDoNotDisturbProfile(id, name, trustlist);
    profiles.emplace_back(disturbProfile);

    ErrCode ret1 = ans_->RemoveDoNotDisturbProfiles(profiles);
    EXPECT_EQ(ret1, ERR_ANS_SERVICE_NOT_CONNECTED);
}

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
/*
 * @tc.name: RegisterSwingCallback_0100
 * @tc.desc: test RegisterSwingCallback with parameters, expect errorCode ERR_ANS_SERVICE_NOT_CONNECTED
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, RegisterSwingCallback_0100, TestSize.Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool ret = ans_->GetAnsManagerProxy();
    EXPECT_EQ(ret, false);
    std::function<void(bool, int)> swingCbFunc =
        std::bind(&AnsNotificationUnitTest::UpdateStatuts, this, std::placeholders::_1, std::placeholders::_2);
    ErrCode res = ans_->RegisterSwingCallback(swingCbFunc);
    EXPECT_EQ(res, ERR_ANS_SERVICE_NOT_CONNECTED);
}
#endif

/*
 * @tc.name: IsNeedSilentInDoNotDisturbMode_0100
 * @tc.desc: test IsNeedSilentInDoNotDisturbMode.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, IsNeedSilentInDoNotDisturbMode_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    std::string phoneNumber = "11111111111";
    int32_t callerType = 0;
    ErrCode ret = ans_->IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType);
    EXPECT_EQ(ret, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: DisableNotificationFeature_0100
 * @tc.desc: test DisableNotificationFeature.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, DisableNotificationFeature_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool ret = ans_->GetAnsManagerProxy();
    EXPECT_FALSE(ret);

    NotificationDisable notificationDisable;
    ErrCode res = ans_->DisableNotificationFeature(notificationDisable);
    EXPECT_EQ(res, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: PublishNotificationForIndirectProxy_0100
 * @tc.desc: test PublishNotificationForIndirectProxy.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, PublishNotificationForIndirectProxy_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool ret = ans_->GetAnsManagerProxy();
    EXPECT_FALSE(ret);

    NotificationRequest request;
    ErrCode res = ans_->PublishNotificationForIndirectProxy(request);
    EXPECT_EQ(res, ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: GetNotificationSettings_0100
 * @tc.desc: test GetNotificationSetting.
 * @tc.type: FUNC
 */
HWTEST_F(AnsNotificationUnitTest, GetNotificationSettings_0100, Function | MediumTest | Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    ans_->GetAnsManagerProxy();
    uint32_t slotFlags = 0;
    ErrCode result = ans_->GetNotificationSettings(slotFlags);
    EXPECT_EQ(result, ERR_ANS_SERVICE_NOT_CONNECTED);
}
}  // namespace Notification
}  // namespace OHOS
