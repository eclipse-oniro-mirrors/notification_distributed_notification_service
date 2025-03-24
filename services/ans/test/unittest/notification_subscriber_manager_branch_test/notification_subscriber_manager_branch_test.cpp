/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <functional>
#include <gtest/gtest.h>

#include "ans_inner_errors.h"
#include "ans_ut_constant.h"
#define private public
#define protected public
#include "advanced_notification_service.h"
#include "notification_subscriber_manager.h"
#undef private
#undef protected
#include "ans_inner_errors.h"
#include "mock_ipc_skeleton.h"

extern void MockGetUserId(bool mockRet);
extern void MockGetBundleName(bool mockRet);
extern void MockGetNotificationSlotRet(bool mockRet);
extern void MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase);

using namespace OHOS::Security::AccessToken;
using namespace testing::ext;
namespace OHOS {
namespace Notification {
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);
extern void MockIsVerfyPermisson(bool isVerify);

class NotificationSubscriberManagerBranchTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.number    : NotificationSubscriberManager_00100
 * @tc.name      : NotificationSubscriberManager_00100
 * @tc.desc      : test NotifyConsumed function and notificationSubQueue_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00100, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationSubscriberManager> notificationSubscriberManager =
        std::make_shared<NotificationSubscriberManager>();
    ASSERT_NE(nullptr, notificationSubscriberManager);
    sptr<Notification> notification = nullptr;
    sptr<NotificationSortingMap> notificationMap = nullptr;
    notificationSubscriberManager->notificationSubQueue_ = nullptr;
    notificationSubscriberManager->NotifyConsumed(notification, notificationMap);
}

/**
 * @tc.number    : NotificationSubscriberManager_00200
 * @tc.name      : NotificationSubscriberManager_00200
 * @tc.desc      : test NotifyCanceled function and notificationSubQueue_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00200, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationSubscriberManager> notificationSubscriberManager =
        std::make_shared<NotificationSubscriberManager>();
    ASSERT_NE(nullptr, notificationSubscriberManager);
    sptr<Notification> notification = nullptr;
    sptr<NotificationSortingMap> notificationMap = nullptr;
    int32_t deleteReason = 1;
    notificationSubscriberManager->notificationSubQueue_ = nullptr;
    notificationSubscriberManager->NotifyCanceled(notification, notificationMap, deleteReason);
}

/**
 * @tc.number    : NotificationSubscriberManager_00300
 * @tc.name      : NotificationSubscriberManager_00300
 * @tc.desc      : test NotifyUpdated function and notificationSubQueue_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00300, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationSubscriberManager> notificationSubscriberManager =
        std::make_shared<NotificationSubscriberManager>();
    ASSERT_NE(nullptr, notificationSubscriberManager);
    sptr<NotificationSortingMap> notificationMap = nullptr;
    notificationSubscriberManager->notificationSubQueue_ = nullptr;
    notificationSubscriberManager->NotifyUpdated(notificationMap);
}

/**
 * @tc.number    : NotificationSubscriberManager_00400
 * @tc.name      : NotificationSubscriberManager_00400
 * @tc.desc      : test NotifyDoNotDisturbDateChanged function and notificationSubQueue_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00400, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationSubscriberManager> notificationSubscriberManager =
        std::make_shared<NotificationSubscriberManager>();
    ASSERT_NE(nullptr, notificationSubscriberManager);
    sptr<NotificationDoNotDisturbDate> date = nullptr;
    notificationSubscriberManager->notificationSubQueue_ = nullptr;
    notificationSubscriberManager->NotifyDoNotDisturbDateChanged(0, date);
}

/**
 * @tc.number    : NotificationSubscriberManager_00500
 * @tc.name      : NotificationSubscriberManager_00500
 * @tc.desc      : test NotifyEnabledNotificationChanged function and notificationSubQueue_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00500, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationSubscriberManager> notificationSubscriberManager =
        std::make_shared<NotificationSubscriberManager>();
    ASSERT_NE(nullptr, notificationSubscriberManager);
    sptr<EnabledNotificationCallbackData> callbackData = nullptr;
    notificationSubscriberManager->notificationSubQueue_ = nullptr;
    notificationSubscriberManager->NotifyEnabledNotificationChanged(callbackData);
}

/**
 * @tc.number    : NotificationSubscriberManager_00600
 * @tc.name      : NotificationSubscriberManager_00600
 * @tc.desc      : test OnRemoteDied function and record == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00600, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationSubscriberManager> notificationSubscriberManager =
        std::make_shared<NotificationSubscriberManager>();
    ASSERT_NE(nullptr, notificationSubscriberManager);
    wptr<IRemoteObject> object = nullptr;
    notificationSubscriberManager->OnRemoteDied(object);
}

/**
 * @tc.number    : NotificationSubscriberManager_00700
 * @tc.name      : NotificationSubscriberManager_00700
 * @tc.desc      : test AddRecordInfo function and subscribeInfo == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00700, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationSubscriberManager> notificationSubscriberManager =
        std::make_shared<NotificationSubscriberManager>();
    ASSERT_NE(nullptr, notificationSubscriberManager);
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager->CreateSubscriberRecord(nullptr);
    sptr<NotificationSubscribeInfo> subscribeInfo = nullptr;
    notificationSubscriberManager->AddRecordInfo(record, subscribeInfo);
}

/**
 * @tc.number    : NotificationSubscriberManager_00800
 * @tc.name      : NotificationSubscriberManager_00800
 * @tc.desc      : test RemoveSubscriberInner function and record == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00800, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<AnsSubscriberInterface> subscriber = nullptr;
    sptr<NotificationSubscribeInfo> subscribeInfo = nullptr;
    ASSERT_EQ(ERR_ANS_INVALID_PARAM, notificationSubscriberManager.RemoveSubscriberInner(subscriber, subscribeInfo));
}

/**
 * @tc.number  : AdvancedNotificationService_00200
 * @tc.name    : AdvancedNotificationService_00200
 * @tc.desc    : test ActiveNotificationDump function and userId != SUBSCRIBE_USER_INIT
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_00200, Function | SmallTest | Level1)
{
    std::string bundle = "<bundle>";
    int32_t userId = 1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    record->request = new NotificationRequest();
    advancedNotificationService.notificationList_.push_back(record);
    MockGetUserId(false);
    ASSERT_EQ(advancedNotificationService.ActiveNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_00300
 * @tc.name    : AdvancedNotificationService_00300
 * @tc.desc    : test ActiveNotificationDump function and bundle != record->notification->GetBundleName().
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_00300, Function | SmallTest | Level1)
{
    std::string bundle = "<bundle>";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    record->request = new NotificationRequest();
    advancedNotificationService.notificationList_.push_back(record);
    MockGetUserId(false);
    MockGetBundleName(false);
    ASSERT_EQ(advancedNotificationService.ActiveNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
/**
 * @tc.number  : AdvancedNotificationService_00400
 * @tc.name    : AdvancedNotificationService_00400
 * @tc.desc    : test ActiveNotificationDump function and record->deviceId is not empty.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_00400, Function | SmallTest | Level1)
{
    std::string bundle = "";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    record->request = new NotificationRequest();
    record->deviceId = "<deviceId>";
    advancedNotificationService.notificationList_.push_back(record);
    MockGetUserId(false);
    MockGetBundleName(false);
    ASSERT_EQ(advancedNotificationService.ActiveNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_00500
 * @tc.name    : AdvancedNotificationService_00500
 * @tc.desc    : test ActiveNotificationDump function and record->request->GetOwnerUid() > 0.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_00500, Function | SmallTest | Level1)
{
    std::string bundle = "";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    record->request = new NotificationRequest();
    int32_t uid = 1;
    record->request->SetOwnerUid(uid);
    record->deviceId = "";
    advancedNotificationService.notificationList_.push_back(record);
    MockGetUserId(false);
    MockGetBundleName(false);
    ASSERT_EQ(advancedNotificationService.ActiveNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_00600
 * @tc.name    : AdvancedNotificationService_00600
 * @tc.desc    : test ActiveNotificationDump function and record->request->GetOwnerUid() < 0.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_00600, Function | SmallTest | Level1)
{
    std::string bundle = "";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    record->request = new NotificationRequest();
    int32_t uid = -1;
    record->request->SetOwnerUid(uid);
    record->deviceId = "";
    advancedNotificationService.notificationList_.push_back(record);
    std::shared_ptr<NotificationRecord> record1 = std::make_shared<NotificationRecord>();
    record1->notification = new Notification();
    record1->request = new NotificationRequest();
    record1->request->SetOwnerUid(uid);
    record1->request->SetReceiverUserId(0);
    advancedNotificationService.notificationList_.push_back(record1);
    MockGetUserId(false);
    MockGetBundleName(false);
    ASSERT_EQ(advancedNotificationService.ActiveNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_00700
 * @tc.name    : AdvancedNotificationService_00700
 * @tc.desc    : test DistributedNotificationDump function and record->notification == nullptr.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_00700, Function | SmallTest | Level1)
{
    std::string bundle = "<bundle>";
    int32_t userId = 1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = nullptr;
    advancedNotificationService.notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

+/**
+ * @tc.number  : AdvancedNotificationService_01300
+ * @tc.name    : AdvancedNotificationService_01200
+ * @tc.desc    : test DistributedNotificationDump function and recvUserId != record->notification->GetRecvUserId().
+ */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01300, Function | SmallTest | Level1)
{
    std::string bundle = "<bundle>";
    int32_t userId = 1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    record->request = new NotificationRequest();
    record->request->SetReceiverUserId(2);
    MockGetUserId(false);
    advancedNotificationService.notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_00800
 * @tc.name    : AdvancedNotificationService_00800
 * @tc.desc    : test DistributedNotificationDump function and userId != SUBSCRIBE_USER_INIT.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_00800, Function | SmallTest | Level1)
{
    std::string bundle = "<bundle>";
    int32_t userId = 1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    MockGetUserId(false);
    advancedNotificationService.notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_00900
 * @tc.name    : AdvancedNotificationService_00900
 * @tc.desc    : test DistributedNotificationDump function and bundle is not empty.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_00900, Function | SmallTest | Level1)
{
    std::string bundle = "<bundle>";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    MockGetUserId(false);
    MockGetBundleName(false);
    advancedNotificationService.notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_01000
 * @tc.name    : AdvancedNotificationService_01000
 * @tc.desc    : test DistributedNotificationDump function and record->deviceId is empty.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01000, Function | SmallTest | Level1)
{
    std::string bundle = "";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    record->deviceId = "";
    MockGetUserId(false);
    MockGetBundleName(false);
    advancedNotificationService.notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_01100
 * @tc.name    : AdvancedNotificationService_01100
 * @tc.desc    : test DistributedNotificationDump function and record->request->GetOwnerUid() > 0.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01100, Function | SmallTest | Level1)
{
    std::string bundle = "";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    record->request = new NotificationRequest();
    int32_t uid = 1;
    record->request->SetOwnerUid(uid);
    record->deviceId = "<deviceId>";
    MockGetUserId(false);
    MockGetBundleName(false);
    advancedNotificationService.notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_01200
 * @tc.name    : AdvancedNotificationService_01200
 * @tc.desc    : test DistributedNotificationDump function and record->request->GetOwnerUid() < 0.
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01200, Function | SmallTest | Level1)
{
    std::string bundle = "";
    int32_t userId = -1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new Notification();
    record->request = new NotificationRequest();
    int32_t uid = -1;
    record->request->SetOwnerUid(uid);
    record->deviceId = "<deviceId>";
    MockGetUserId(false);
    MockGetBundleName(false);
    advancedNotificationService.notificationList_.push_back(record);
    ASSERT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, 0, dumpInfo), ERR_OK);
}
#endif

/**
 * @tc.number  : AdvancedNotificationService_01400
 * @tc.name    : AdvancedNotificationService_01400
 * @tc.desc    : Test PrepareNotificationRequest function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01400, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> req = new NotificationRequest();
    bool isAgentTrue = true;
    req->SetIsAgentNotification(isAgentTrue);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.PrepareNotificationRequest(req), ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_01500
 * @tc.name    : AdvancedNotificationService_01500
 * @tc.desc    : Test CancelAsBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01500, Function | SmallTest | Level1)
{
    int32_t notificationId = 1;
    std::string representativeBundle = "<representativeBundle>";
    int32_t userId = 2;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.CancelAsBundle(notificationId, representativeBundle, userId),
        ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_01600
 * @tc.name    : AdvancedNotificationService_01600
 * @tc.desc    : Test AddSlots function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01600, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.AddSlots(slots), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_01700
 * @tc.name    : AdvancedNotificationService_01700
 * @tc.desc    : Test Delete function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01700, Function | SmallTest | Level1)
{
    std::string key = "<key>";
    int32_t removeReason = 1;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.Delete(key, removeReason), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_01800
 * @tc.name    : AdvancedNotificationService_01800
 * @tc.desc    : Test DeleteByBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01800, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption =  new NotificationBundleOption();

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.DeleteByBundle(bundleOption), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_01900
 * @tc.name    : AdvancedNotificationService_01900
 * @tc.desc    : Test DeleteAll function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01900, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.DeleteAll(), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_02000
 * @tc.name    : AdvancedNotificationService_02000
 * @tc.desc    : Test GetSlotsByBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02000, Function | SmallTest | Level1)
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);

    sptr<NotificationBundleOption> bundleOption = nullptr;
    std::vector<sptr<NotificationSlot>> slots;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetSlotsByBundle(bundleOption, slots), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_02100
 * @tc.name    : AdvancedNotificationService_02100
 * @tc.desc    : Test UpdateSlots function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02100, Function | SmallTest | Level1)
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);

    sptr<NotificationBundleOption> bundleOption = nullptr;
    std::vector<sptr<NotificationSlot>> slots;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.UpdateSlots(bundleOption, slots), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_02200
 * @tc.name    : AdvancedNotificationService_02200
 * @tc.desc    : Test SetShowBadgeEnabledForBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02200, Function | SmallTest | Level1)
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.SetShowBadgeEnabledForBundle(bundleOption, enabled),
        ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_02300
 * @tc.name    : AdvancedNotificationService_02300
 * @tc.desc    : Test GetShowBadgeEnabledForBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02300, Function | SmallTest | Level1)
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);

    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetShowBadgeEnabledForBundle(bundleOption, enabled),
        ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_02400
 * @tc.name    : AdvancedNotificationService_02400
 * @tc.desc    : Test Unsubscribe function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02400, Function | SmallTest | Level1)
{
    sptr<AnsSubscriberInterface> subscriber = nullptr;
    sptr<NotificationSubscribeInfo> info = nullptr;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.Unsubscribe(subscriber, info), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_02500
 * @tc.name    : AdvancedNotificationService_02500
 * @tc.desc    : Test GetAllActiveNotifications function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02500, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetAllActiveNotifications(notifications), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_02600
 * @tc.name    : AdvancedNotificationService_02600
 * @tc.desc    : Test GetSpecialActiveNotifications function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02600, Function | SmallTest | Level1)
{
    std::vector<std::string> key;
    std::vector<sptr<Notification>> notifications;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(
        advancedNotificationService.GetSpecialActiveNotifications(key, notifications), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_02700
 * @tc.name    : AdvancedNotificationService_02700
 * @tc.desc    : Test SetNotificationsEnabledForAllBundles function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02700, Function | SmallTest | Level1)
{
    std::string deviceId = "<deviceId>";
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.SetNotificationsEnabledForAllBundles(deviceId, enabled),
        ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_02800
 * @tc.name    : AdvancedNotificationService_02800
 * @tc.desc    : Test SetNotificationsEnabledForAllBundles function and GetActiveUserId is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02800, Function | SmallTest | Level1)
{
    std::string deviceId = "<deviceId>";
    bool enabled = true;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockQueryForgroundOsAccountId(false, 1);

    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.SetNotificationsEnabledForAllBundles(deviceId, enabled),
        ERR_ANS_GET_ACTIVE_USER_FAILED);
}

/**
 * @tc.number  : AdvancedNotificationService_02900
 * @tc.name    : AdvancedNotificationService_02900
 * @tc.desc    : Test SetNotificationsEnabledForSpecialBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02900, Function | SmallTest | Level1)
{
    std::string deviceId = "<deviceId>";
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.SetNotificationsEnabledForSpecialBundle(deviceId, bundleOption, enabled),
        ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_03000
 * @tc.name    : AdvancedNotificationService_03000
 * @tc.desc    : Test IsAllowedNotify function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03000, Function | SmallTest | Level1)
{
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.IsAllowedNotify(enabled), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_03100
 * @tc.name    : AdvancedNotificationService_03100
 * @tc.desc    : Test IsAllowedNotify function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03100, Function | SmallTest | Level1)
{
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockQueryForgroundOsAccountId(false, 1);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.IsAllowedNotify(enabled), ERR_ANS_GET_ACTIVE_USER_FAILED);
}

/**
 * @tc.number  : AdvancedNotificationService_03200
 * @tc.name    : AdvancedNotificationService_03200
 * @tc.desc    : Test IsSpecialBundleAllowedNotify function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool allowed = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(
        advancedNotificationService.IsSpecialBundleAllowedNotify(bundleOption, allowed), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_03300
 * @tc.name    : AdvancedNotificationService_03300
 * @tc.desc    : Test IsSpecialBundleAllowedNotify function and targetBundle == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03300, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool allowed = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(
        advancedNotificationService.IsSpecialBundleAllowedNotify(bundleOption, allowed), ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_03400
 * @tc.name    : AdvancedNotificationService_03400
 * @tc.desc    : Test IsSpecialBundleAllowedNotify function and GetActiveUserId is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03400, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    MockQueryForgroundOsAccountId(false, 1);
    bool allowed = true;

    int32_t uid = 2;
    bundleOption->SetUid(uid);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.IsSpecialBundleAllowedNotify(bundleOption, allowed),
        ERR_ANS_GET_ACTIVE_USER_FAILED);
}

/**
 * @tc.number  : AdvancedNotificationService_03500
 * @tc.name    : AdvancedNotificationService_03500
 * @tc.desc    : Test RemoveNotification function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03500, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    int32_t notificationId = 1;
    std::string label = "<label>";
    int32_t removeReason = 1;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.RemoveNotification(bundleOption, notificationId, label, removeReason),
        ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_03600
 * @tc.name    : AdvancedNotificationService_03600
 * @tc.desc    : Test RemoveNotification function and bundle is nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03600, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    int32_t notificationId = 0;
    std::string label = "<label>";
    int32_t removeReason = 1;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    bundleOption->SetUid(notificationId);

    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.RemoveNotification(bundleOption, notificationId, label, removeReason),
        ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_03700
 * @tc.name    : AdvancedNotificationService_03700
 * @tc.desc    : Test RemoveAllNotifications function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03700, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.RemoveAllNotifications(bundleOption), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_03800
 * @tc.name    : AdvancedNotificationService_03800
 * @tc.desc    : Test RemoveAllNotifications function and bundle is nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03800, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int32_t notificationId = 0;
    bundleOption->SetUid(notificationId);

    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.RemoveAllNotifications(bundleOption), ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_03900
 * @tc.name    : AdvancedNotificationService_03900
 * @tc.desc    : Test GetSlotNumAsBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_03900, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    uint64_t num = 1;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetSlotNumAsBundle(bundleOption, num), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_04000
 * @tc.name    : AdvancedNotificationService_04000
 * @tc.desc    : Test GetSlotNumAsBundle function and bundle is nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_04000, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    uint64_t num = 1;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int32_t notificationId = 0;
    bundleOption->SetUid(notificationId);

    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetSlotNumAsBundle(bundleOption, num), ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_04100
 * @tc.name    : AdvancedNotificationService_04100
 * @tc.desc    : Test RemoveGroupByBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_04100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    std::string groupName = "<groupName>";

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.RemoveGroupByBundle(bundleOption, groupName), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_04200
 * @tc.name    : AdvancedNotificationService_04200
 * @tc.desc    : Test RemoveGroupByBundle function and groupName is empty
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_04200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    std::string groupName = "";

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.RemoveGroupByBundle(bundleOption, groupName), ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number  : AdvancedNotificationService_04300
 * @tc.name    : AdvancedNotificationService_04300
 * @tc.desc    : Test RemoveGroupByBundle function and bundle is nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_04300, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    std::string groupName = "<groupName>";

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int32_t notificationId = 0;
    bundleOption->SetUid(notificationId);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.RemoveGroupByBundle(bundleOption, groupName), ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_04900
 * @tc.name    : AdvancedNotificationService_04900
 * @tc.desc    : Test EnableDistributed function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_04900, Function | SmallTest | Level1)
{
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.EnableDistributed(enabled), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_05000
 * @tc.name    : AdvancedNotificationService_05000
 * @tc.desc    : Test EnableDistributedByBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_05000, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.EnableDistributedByBundle(bundleOption, enabled), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_05100
 * @tc.name    : AdvancedNotificationService_05100
 * @tc.desc    : Test EnableDistributedByBundle function and bundle == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_05100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int32_t notificationId = 0;
    bundleOption->SetUid(notificationId);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.EnableDistributedByBundle(bundleOption, enabled), ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_05200
 * @tc.name    : AdvancedNotificationService_05200
 * @tc.desc    : Test IsDistributedEnableByBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_05200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.IsDistributedEnableByBundle(bundleOption, enabled), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_05300
 * @tc.name    : AdvancedNotificationService_05300
 * @tc.desc    : Test IsDistributedEnableByBundle function and bundle == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_05300, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int32_t notificationId = 0;
    bundleOption->SetUid(notificationId);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.IsDistributedEnableByBundle(bundleOption, enabled), ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_05400
 * @tc.name    : AdvancedNotificationService_05400
 * @tc.desc    : Test GetDeviceRemindType function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_05400, Function | SmallTest | Level1)
{
    NotificationConstant::RemindType remindType = NotificationConstant::RemindType::DEVICE_ACTIVE_REMIND;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetDeviceRemindType(remindType), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_05500
 * @tc.name    : AdvancedNotificationService_05500
 * @tc.desc    : Test IsSpecialUserAllowedNotify function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_05500, Function | SmallTest | Level1)
{
    int32_t userId = 1;
    bool allowed = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.IsSpecialUserAllowedNotify(userId, allowed), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_05600
 * @tc.name    : AdvancedNotificationService_05600
 * @tc.desc    : Test SetNotificationsEnabledByUser function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_05600, Function | SmallTest | Level1)
{
    int32_t userId = 1;
    bool allowed = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.SetNotificationsEnabledByUser(userId, allowed), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_05900
 * @tc.name    : AdvancedNotificationService_05900
 * @tc.desc    : Test SetEnabledForBundleSlot function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_05900, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::OTHER;
    bool enabled = true;
    bool isForceControl = false;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.SetEnabledForBundleSlot(bundleOption, slotType, enabled, isForceControl),
        ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_06000
 * @tc.name    : AdvancedNotificationService_06000
 * @tc.desc    : Test SetEnabledForBundleSlot function and bundle == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06000, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::OTHER;
    bool enabled = true;
    bool isForceControl = false;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int32_t notificationId = 0;
    bundleOption->SetUid(notificationId);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.SetEnabledForBundleSlot(bundleOption, slotType, enabled, isForceControl),
        ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_06100
 * @tc.name    : AdvancedNotificationService_06100
 * @tc.desc    : Test GetEnabledForBundleSlot function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::OTHER;
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetEnabledForBundleSlot(bundleOption, slotType, enabled),
        ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_06200
 * @tc.name    : AdvancedNotificationService_06200
 * @tc.desc    : Test GetEnabledForBundleSlot function and bundle == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::OTHER;
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int32_t notificationId = 0;
    bundleOption->SetUid(notificationId);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetEnabledForBundleSlot(bundleOption, slotType, enabled),
        ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_06300
 * @tc.name    : AdvancedNotificationService_06300
 * @tc.desc    : Test GetEnabledForBundleSlot function and result != ERR_OK
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06300, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::OTHER;
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int32_t notificationId = 1;
    bundleOption->SetUid(notificationId);
    MockGetNotificationSlotRet(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetEnabledForBundleSlot(bundleOption, slotType, enabled),
        ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number  : AdvancedNotificationService_06400
 * @tc.name    : AdvancedNotificationService_06400
 * @tc.desc    : Test GetEnabledForBundleSlot function and slot == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06400, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::OTHER;
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    int32_t notificationId = 1;
    bundleOption->SetUid(notificationId);
    MockGetNotificationSlotRet(true);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetEnabledForBundleSlot(bundleOption, slotType, enabled),
        ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number  : AdvancedNotificationService_06500
 * @tc.name    : AdvancedNotificationService_06500
 * @tc.desc    : Test SetSyncNotificationEnabledWithoutApp function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06500, Function | SmallTest | Level1)
{
    int32_t userId = 1;
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.SetSyncNotificationEnabledWithoutApp(userId, enabled),
        ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_06600
 * @tc.name    : AdvancedNotificationService_06600
 * @tc.desc    : Test GetSyncNotificationEnabledWithoutApp function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06600, Function | SmallTest | Level1)
{
    int32_t userId = 1;
    bool enabled = true;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetSyncNotificationEnabledWithoutApp(userId, enabled),
        ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number  : AdvancedNotificationService_06700
 * @tc.name    : AdvancedNotificationService_06700
 * @tc.desc    : Test GetEnabledForBundleSlotSelf function and slot == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06700, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::OTHER;
    bool enabled = true;

    MockGetNotificationSlotRet(true);
    AdvancedNotificationService advancedNotificationService;
    EXPECT_NE(advancedNotificationService.GetEnabledForBundleSlotSelf(slotType, enabled), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_06800
 * @tc.name    : AdvancedNotificationService_06800
 * @tc.desc    : Test GetEnabledForBundleSlotSelf function and GetNotificationSlot false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06800, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::OTHER;
    bool enabled = true;

    MockGetNotificationSlotRet(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.GetEnabledForBundleSlotSelf(slotType, enabled), ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.number  : AdvancedNotificationService_06900
 * @tc.name    : AdvancedNotificationService_06900
 * @tc.desc    : Test IsNeedSilentInDoNotDisturbMode function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_06900, Function | SmallTest | Level1)
{
    std::string phoneNumber = "11111111111";
    int32_t callerType = 0;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    AdvancedNotificationService advancedNotificationService;
    ASSERT_EQ(advancedNotificationService.IsNeedSilentInDoNotDisturbMode(
        phoneNumber, callerType), ERR_ANS_GET_ACTIVE_USER_FAILED);
}
}  // namespace Notification
}  // namespace OHOS
