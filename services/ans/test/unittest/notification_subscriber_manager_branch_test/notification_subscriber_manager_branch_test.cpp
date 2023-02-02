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
extern void MockVerifyNativeToken(bool mockRet);
extern void MockVerifyCallerPermission(bool mockRet);

using namespace testing::ext;
namespace OHOS {
namespace Notification {
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
 * @tc.desc      : test NotifyConsumed function and handler_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00100, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<Notification> notification = nullptr;
    sptr<NotificationSortingMap> notificationMap = nullptr;
    notificationSubscriberManager.handler_ = nullptr;
    notificationSubscriberManager.NotifyConsumed(notification, notificationMap);
}

/**
 * @tc.number    : NotificationSubscriberManager_00200
 * @tc.name      : NotificationSubscriberManager_00200
 * @tc.desc      : test NotifyCanceled function and handler_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00200, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<Notification> notification = nullptr;
    sptr<NotificationSortingMap> notificationMap = nullptr;
    int32_t deleteReason = 1;
    notificationSubscriberManager.handler_ = nullptr;
    notificationSubscriberManager.NotifyCanceled(notification, notificationMap, deleteReason);
}

/**
 * @tc.number    : NotificationSubscriberManager_00300
 * @tc.name      : NotificationSubscriberManager_00300
 * @tc.desc      : test NotifyUpdated function and handler_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00300, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSortingMap> notificationMap = nullptr;
    notificationSubscriberManager.handler_ = nullptr;
    notificationSubscriberManager.NotifyUpdated(notificationMap);
}

/**
 * @tc.number    : NotificationSubscriberManager_00400
 * @tc.name      : NotificationSubscriberManager_00400
 * @tc.desc      : test NotifyDoNotDisturbDateChanged function and handler_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00400, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationDoNotDisturbDate> date = nullptr;
    notificationSubscriberManager.handler_ = nullptr;
    notificationSubscriberManager.NotifyDoNotDisturbDateChanged(date);
}

/**
 * @tc.number    : NotificationSubscriberManager_00500
 * @tc.name      : NotificationSubscriberManager_00500
 * @tc.desc      : test NotifyEnabledNotificationChanged function and handler_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00500, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<EnabledNotificationCallbackData> callbackData = nullptr;
    notificationSubscriberManager.handler_ = nullptr;
    notificationSubscriberManager.NotifyEnabledNotificationChanged(callbackData);
}

/**
 * @tc.number    : NotificationSubscriberManager_00600
 * @tc.name      : NotificationSubscriberManager_00600
 * @tc.desc      : test OnRemoteDied function and record == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00600, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    wptr<IRemoteObject> object = nullptr;
    notificationSubscriberManager.OnRemoteDied(object);
}

/**
 * @tc.number    : NotificationSubscriberManager_00700
 * @tc.name      : NotificationSubscriberManager_00700
 * @tc.desc      : test AddRecordInfo function and subscribeInfo == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00700, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(nullptr);
    sptr<NotificationSubscribeInfo> subscribeInfo = nullptr;
    notificationSubscriberManager.AddRecordInfo(record, subscribeInfo);
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
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, notificationSubscriberManager.RemoveSubscriberInner(subscriber, subscribeInfo));
}

/**
 * @tc.number  : AdvancedNotificationService_00100
 * @tc.name    : AdvancedNotificationService_00100
 * @tc.desc    : test ActiveNotificationDump function and record->notification == nullptr record->request == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_00100, Function | SmallTest | Level1)
{
    std::string bundle = "<bundle>";
    int32_t userId = 1;
    std::vector<std::string> dumpInfo;
    AdvancedNotificationService advancedNotificationService;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = nullptr;
    record->request = nullptr;
    advancedNotificationService.notificationList_.push_back(record);
    EXPECT_EQ(advancedNotificationService.ActiveNotificationDump(bundle, userId, dumpInfo), ERR_OK);
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
    EXPECT_EQ(advancedNotificationService.ActiveNotificationDump(bundle, userId, dumpInfo), ERR_OK);
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
    EXPECT_EQ(advancedNotificationService.ActiveNotificationDump(bundle, userId, dumpInfo), ERR_OK);
}

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
    EXPECT_EQ(advancedNotificationService.ActiveNotificationDump(bundle, userId, dumpInfo), ERR_OK);
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
    EXPECT_EQ(advancedNotificationService.ActiveNotificationDump(bundle, userId, dumpInfo), ERR_OK);
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
    MockGetUserId(false);
    MockGetBundleName(false);
    EXPECT_EQ(advancedNotificationService.ActiveNotificationDump(bundle, userId, dumpInfo), ERR_OK);
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
    EXPECT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, dumpInfo), ERR_OK);
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
    EXPECT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, dumpInfo), ERR_OK);
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
    EXPECT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, dumpInfo), ERR_OK);
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
    EXPECT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, dumpInfo), ERR_OK);
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
    EXPECT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, dumpInfo), ERR_OK);
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
    EXPECT_EQ(advancedNotificationService.DistributedNotificationDump(bundle, userId, dumpInfo), ERR_OK);
}

/**
 * @tc.number  : AdvancedNotificationService_01300
 * @tc.name    : AdvancedNotificationService_01300
 * @tc.desc    : Test CheckPermission function and result is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01300, Function | SmallTest | Level1)
{
    std::string permission = "<permission>";
    AdvancedNotificationService advancedNotificationService;
    MockVerifyNativeToken(false);
    MockVerifyCallerPermission(false);
    EXPECT_EQ(advancedNotificationService.CheckPermission(permission), false);
}

/**
 * @tc.number  : AdvancedNotificationService_01400
 * @tc.name    : AdvancedNotificationService_01400
 * @tc.desc    : Test PrepareNotificationRequest function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01400, Function | SmallTest | Level1)
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);

    sptr<NotificationRequest> req = new NotificationRequest();
    bool isAgentTrue = true;
    req->SetIsAgentNotification(isAgentTrue);

    MockVerifyNativeToken(false);
    MockVerifyCallerPermission(false);
    AdvancedNotificationService advancedNotificationService;
    EXPECT_EQ(advancedNotificationService.PrepareNotificationRequest(req), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number  : AdvancedNotificationService_01500
 * @tc.name    : AdvancedNotificationService_01500
 * @tc.desc    : Test CancelAsBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01500, Function | SmallTest | Level1)
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);

    int32_t notificationId = 1;
    std::string representativeBundle = "<representativeBundle>";
    int32_t userId = 2;

    MockVerifyNativeToken(false);
    MockVerifyCallerPermission(false);
    AdvancedNotificationService advancedNotificationService;
    EXPECT_EQ(advancedNotificationService.CancelAsBundle(notificationId, representativeBundle, userId),
        ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number  : AdvancedNotificationService_01600
 * @tc.name    : AdvancedNotificationService_01600
 * @tc.desc    : Test AddSlots function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01600, Function | SmallTest | Level1)
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);

    std::vector<sptr<NotificationSlot>> slots;

    MockVerifyNativeToken(false);
    MockVerifyCallerPermission(false);
    AdvancedNotificationService advancedNotificationService;
    EXPECT_EQ(advancedNotificationService.AddSlots(slots), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number  : AdvancedNotificationService_01700
 * @tc.name    : AdvancedNotificationService_01700
 * @tc.desc    : Test Delete function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01700, Function | SmallTest | Level1)
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);

    std::string key = "<key>";
    int32_t removeReason = 1;

    MockVerifyNativeToken(false);
    MockVerifyCallerPermission(false);
    AdvancedNotificationService advancedNotificationService;
    EXPECT_EQ(advancedNotificationService.Delete(key, removeReason), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number  : AdvancedNotificationService_01800
 * @tc.name    : AdvancedNotificationService_01800
 * @tc.desc    : Test DeleteByBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01800, Function | SmallTest | Level1)
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);

    sptr<NotificationBundleOption> bundleOption = nullptr;

    MockVerifyNativeToken(false);
    MockVerifyCallerPermission(false);
    AdvancedNotificationService advancedNotificationService;
    EXPECT_EQ(advancedNotificationService.DeleteByBundle(bundleOption), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number  : AdvancedNotificationService_01900
 * @tc.name    : AdvancedNotificationService_01900
 * @tc.desc    : Test DeleteAll function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_01900, Function | SmallTest | Level1)
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);

    MockVerifyNativeToken(false);
    MockVerifyCallerPermission(false);
    AdvancedNotificationService advancedNotificationService;
    EXPECT_EQ(advancedNotificationService.DeleteAll(), ERR_ANS_PERMISSION_DENIED);
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

    MockVerifyNativeToken(false);
    MockVerifyCallerPermission(false);
    AdvancedNotificationService advancedNotificationService;
    EXPECT_EQ(advancedNotificationService.GetSlotsByBundle(bundleOption, slots), ERR_ANS_PERMISSION_DENIED);
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

    MockVerifyNativeToken(false);
    MockVerifyCallerPermission(false);
    AdvancedNotificationService advancedNotificationService;
    EXPECT_EQ(advancedNotificationService.UpdateSlots(bundleOption, slots), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.number  : AdvancedNotificationService_02200
 * @tc.name    : AdvancedNotificationService_02200
 * @tc.desc    : Test SetShowBadgeEnabledForBundle function and CheckPermission is false
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, AdvancedNotificationService_02200, Function | SmallTest | Level1)
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);

    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool enabled = true;

    MockVerifyNativeToken(false);
    MockVerifyCallerPermission(false);
    AdvancedNotificationService advancedNotificationService;
    EXPECT_EQ(advancedNotificationService.SetShowBadgeEnabledForBundle(bundleOption, enabled),
        ERR_ANS_PERMISSION_DENIED);
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

    MockVerifyNativeToken(false);
    MockVerifyCallerPermission(false);
    AdvancedNotificationService advancedNotificationService;
    EXPECT_EQ(advancedNotificationService.GetShowBadgeEnabledForBundle(bundleOption, enabled),
        ERR_ANS_PERMISSION_DENIED);
}
}  // namespace Notification
}  // namespace OHOS
