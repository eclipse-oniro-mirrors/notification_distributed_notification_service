/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#define private public
#define protected public
#include "ans_notification.h"
#include "ans_subscriber_proxy.h"
#include "ans_manager_proxy.h"
#include "ians_manager.h"
#undef private
#undef protected
#include "ians_dialog_callback.h"
#include "ans_inner_errors.h"
#include "ipc_types.h"
#include "notification.h"
#include "notification_request.h"
#include "singleton.h"
#include "notification_subscriber.h"

extern void MockGetAnsManagerProxy(OHOS::sptr<OHOS::Notification::IAnsManager> mockRet);

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;

namespace OHOS {
namespace Notification {
class MockAnsManagerInterface : public IAnsManager {
public:
    MockAnsManagerInterface() = default;
    virtual ~MockAnsManagerInterface()
    {};
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }

    ErrCode Publish(const std::string &label, const sptr<NotificationRequest> &notification) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode PublishNotificationForIndirectProxy(const sptr<NotificationRequest> &notification) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode Cancel(int notificationId, const std::string &label, const std::string &instanceKey) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CancelAll(const std::string &instanceKey) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CancelAsBundle(
        int32_t notificationId, const std::string &representativeBundle, int32_t userId) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CancelAsBundle(
        const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CancelAsBundle(
        const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId, int32_t userId) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode AddSlotByType(int32_t slotTypeInt) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode AddSlots(const std::vector<sptr<NotificationSlot>> &slots) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RemoveSlotByType(int32_t slotTypeInt) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RemoveAllSlots() override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetSlotByType(int32_t slotTypeInt, sptr<NotificationSlot> &slot) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetSlots(std::vector<sptr<NotificationSlot>> &slots) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetSlotNumAsBundle(const sptr<NotificationBundleOption> &bundleOption, uint64_t &num) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetActiveNotifications(std::vector<sptr<NotificationRequest>> &notifications,
        const std::string &instanceKey) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetActiveNotificationNums(uint64_t &num) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetAllActiveNotifications(std::vector<sptr<Notification>> &notifications) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetSpecialActiveNotifications(
        const std::vector<std::string> &key, std::vector<sptr<Notification>> &notifications) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CanPublishAsBundle(const std::string &representativeBundle, bool &canPublish) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode PublishAsBundle(
        const sptr<NotificationRequest> &notification, const std::string &representativeBundle) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetNotificationBadgeNum(int num) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetBundleImportance(int &importance) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode HasNotificationPolicyAccessPermission(bool &granted) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode Delete(const std::string &key, int32_t removeReason) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RemoveNotification(const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId,
        const std::string &label, int32_t removeReason) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RemoveAllNotifications(const sptr<NotificationBundleOption> &bundleOption) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RemoveNotifications(const std::vector<std::string> &hashcodes, int32_t removeReason) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RemoveDistributedNotifications(const std::vector<std::string>& hashcodes,
        const int32_t slotTypeInt, const int32_t deleteTypeInt,
        const int32_t removeReason, const std::string& deviceId) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode DeleteByBundle(const sptr<NotificationBundleOption> &bundleOption) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode DeleteAll() override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetSlotsByBundle(
        const sptr<NotificationBundleOption> &bundleOption, std::vector<sptr<NotificationSlot>> &slots) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetSlotByBundle(
        const sptr<NotificationBundleOption> &bundleOption, int32_t slotTypeInt,
        sptr<NotificationSlot> &slot) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode UpdateSlots(
        const sptr<NotificationBundleOption> &bundleOption, const std::vector<sptr<NotificationSlot>> &slots) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RequestEnableNotification(const std::string &deviceId,
        const sptr<IAnsDialogCallback>& ansDialogCallback) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RequestEnableNotification(const std::string &deviceId,
        const sptr<IAnsDialogCallback>& ansDialogCallback,
        const sptr<IRemoteObject>& callerToken) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RequestEnableNotification(const std::string& bundleName, int32_t uid) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetNotificationsEnabledForBundle(const std::string &deviceId, bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetNotificationsEnabledForAllBundles(const std::string &deviceId, bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetNotificationsEnabledForSpecialBundle(
        const std::string &deviceId, const sptr<NotificationBundleOption> &bundleOption,
        bool enabled, bool updateUnEnableTime) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetShowBadgeEnabledForBundle(const sptr<NotificationBundleOption> &bundleOption, bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetShowBadgeEnabledForBundle(const sptr<NotificationBundleOption> &bundleOption, bool &enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetShowBadgeEnabled(bool &enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode Subscribe(const sptr<IAnsSubscriber>& subscriber) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode Subscribe(const sptr<IAnsSubscriber> &subscriber,
        const sptr<NotificationSubscribeInfo> &info) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SubscribeSelf(const sptr<IAnsSubscriber> &subscriber) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetAllNotificationEnabledBundles(std::vector<NotificationBundleOption> &bundleOption)override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetTargetDeviceStatus(const std::string &deviceType, int32_t &status)
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetAllLiveViewEnabledBundles(std::vector<NotificationBundleOption> &bundleOption) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetAllDistribuedEnabledBundles(const std::string& deviceType,
        std::vector<NotificationBundleOption> &bundleOption) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SubscribeLocalLiveView(const sptr<IAnsSubscriberLocalLiveView> &subscriber,
        bool isNatives) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SubscribeLocalLiveView(const sptr<IAnsSubscriberLocalLiveView>& subscriber,
        const sptr<NotificationSubscribeInfo>& info, bool isNatives) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode Unsubscribe(const sptr<IAnsSubscriber>& subscriber) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode Unsubscribe(const sptr<IAnsSubscriber>& subscriber, const sptr<NotificationSubscribeInfo>& info) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsAllowedNotify(bool &allowed) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsAllowedNotifySelf(bool &allowed) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CanPopEnableNotificationDialog(const sptr<IAnsDialogCallback> &callback,
        bool &canPop, std::string &bundleName) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RemoveEnableNotificationDialog() override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsSpecialBundleAllowedNotify(const sptr<NotificationBundleOption> &bundleOption, bool &allowed) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetDoNotDisturbDate(const sptr<NotificationDoNotDisturbDate> &date) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetDoNotDisturbDate(sptr<NotificationDoNotDisturbDate> &date) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode AddDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RemoveDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode DoesSupportDoNotDisturbMode(bool &doesSupport) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsNeedSilentInDoNotDisturbMode(const std::string &phoneNumber, int32_t callerType) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CancelGroup(const std::string &groupName, const std::string &instanceKey) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RemoveGroupByBundle(
        const sptr<NotificationBundleOption> &bundleOption, const std::string &groupName) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsDistributedEnabled(bool &enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode EnableDistributed(bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode EnableDistributedByBundle(const sptr<NotificationBundleOption> &bundleOption, bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode EnableDistributedSelf(bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsDistributedEnableByBundle(const sptr<NotificationBundleOption> &bundleOption, bool &enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetDistributedEnabled(const std::string &deviceType, bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsDistributedEnabled(const std::string &deviceType, bool &enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetDistributedAbility(int32_t &abilityId)
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetDistributedAuthStatus(
    const std::string &deviceType, const std::string &deviceId, int32_t userId, bool &isAuth)
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetDistributedAuthStatus(
        const std::string &deviceType, const std::string &deviceId, int32_t userId, bool isAuth)
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetDistributedDevicelist(std::vector<std::string> &deviceTypes) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetDeviceRemindType(int32_t& remindTypeInt) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode PublishContinuousTaskNotification(const sptr<NotificationRequest> &request) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CancelContinuousTaskNotification(const std::string &label, int32_t notificationId) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsSupportTemplate(const std::string &templateName, bool &support) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsSpecialUserAllowedNotify(int32_t userId, bool &allowed) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetNotificationsEnabledByUser(int32_t userId, bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode DeleteAllByUser(int32_t userId) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetDoNotDisturbDate(int32_t userId, const sptr<NotificationDoNotDisturbDate> &date) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetDoNotDisturbDate(int32_t userId, sptr<NotificationDoNotDisturbDate> &date) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetEnabledForBundleSlot(const sptr<NotificationBundleOption> &bundleOption,
        int32_t slotTypeInt, bool enabled, bool isForceControl) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetEnabledForBundleSlot(const sptr<NotificationBundleOption> &bundleOption,
        int32_t slotTypeInt, bool &enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetEnabledForBundleSlotSelf(int32_t slotTypeInt, bool &enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode ShellDump(const std::string &cmd, const std::string &bundle, int32_t userId, int32_t recvUserId,
        std::vector<std::string> &dumpInfo) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetSyncNotificationEnabledWithoutApp(const int32_t userId, const bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetSyncNotificationEnabledWithoutApp(const int32_t userId, bool &enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetBadgeNumber(int32_t badgeNumber, const std::string &instanceKey) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetBadgeNumberByBundle(const sptr<NotificationBundleOption>& bundleOption, int32_t badgeNumber) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetBadgeNumberForDhByBundle(
        const sptr<NotificationBundleOption>& bundleOption, int32_t badgeNumber) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetSlotFlagsAsBundle(const sptr<NotificationBundleOption>& bundleOption, uint32_t &slotFlags) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetSlotFlagsAsBundle(const sptr<NotificationBundleOption>& bundleOption, uint32_t slotFlags) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetNotificationSettings(uint32_t &slotFlags) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RegisterPushCallback(const sptr<IRemoteObject> &pushCallback,
        const sptr<NotificationCheckRequest> &notificationCheckRequest) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode UnregisterPushCallback() override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetActiveNotificationByFilter(const sptr<NotificationBundleOption> &bundleOption,
        int32_t notificationId, const std::string &label, int32_t userId, const std::vector<std::string>& extraInfoKeys,
        sptr<NotificationRequest> &request) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode TriggerLocalLiveView(const sptr<NotificationBundleOption> &bundleOption,
        const int32_t notificationId, const sptr<NotificationButtonOption> &buttonOption) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetDistributedEnabledByBundle(const sptr<NotificationBundleOption> &bundleOption,
        const std::string &deviceType, const bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetDistributedBundleOption(const std::vector<sptr<DistributedBundleOption>> &bundles,
        const std::string &deviceType) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetAdditionConfig(const std::string &key, const std::string &value) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsDistributedEnabledByBundle(const sptr<NotificationBundleOption> &bundleOption,
        const std::string &deviceType, bool &enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsSmartReminderEnabled(const std::string &deviceType, bool &enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetSmartReminderEnabled(const std::string &deviceType, const bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetDistributedEnabledBySlot(
        int32_t slotTypeInt, const std::string &deviceType, bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsDistributedEnabledBySlot(
        int32_t slotTypeInt, const std::string &deviceType, bool &enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CancelAsBundleWithAgent(const sptr<NotificationBundleOption> &bundleOption, const int32_t id) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetTargetDeviceStatus(const std::string &deviceType, uint32_t status,
        const std::string& deviceId) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetTargetDeviceStatus(const std::string &deviceType, uint32_t status,
        uint32_t controlFlag, const std::string& deviceId, int32_t userId) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetTargetDeviceBundleList(const std::string& deviceType, const std::string& deviceId,
        int operatorType, const std::vector<std::string>& bundleList,
        const std::vector<std::string>& labelList) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetTargetDeviceSwitch(const std::string& deviceType, const std::string& deviceId,
        bool notificaitonEnable, bool liveViewEnable) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetDoNotDisturbProfile(int64_t id, sptr<NotificationDoNotDisturbProfile> &profile) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    ErrCode RegisterSwingCallback(const sptr<IRemoteObject> &swingCallback) override
    {
        return ERR_ANS_INVALID_PARAM;
    }
#endif

    ErrCode UpdateNotificationTimerByUid(const int32_t uid, const bool isPaused) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode AllowUseReminder(const std::string& bundleName, bool& isAllowUseReminder) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode DisableNotificationFeature(const sptr<NotificationDisable> &notificationDisable) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode DistributeOperation(const sptr<NotificationOperationInfo>& operationInfo,
        const sptr<IAnsOperationCallback>& operationCallback) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode ReplyDistributeOperation(const std::string& hashCode, const int32_t result) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetNotificationRequestByHashCode(
        const std::string& hashCode, sptr<NotificationRequest>& notificationRequest) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetHashCodeRule(const uint32_t type) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetAllNotificationsBySlotType(std::vector<sptr<Notification>> &notifications,
        int32_t slotTypeInt) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode PublishWithMaxCapacity(const std::string& label, const sptr<NotificationRequest>& notification) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode PublishNotificationForIndirectProxyWithMaxCapacity(const sptr<NotificationRequest>& notification) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode PublishAsBundleWithMaxCapacity(
        const sptr<NotificationRequest>& notification, const std::string& representativeBundle) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetSilentReminderEnabled(const sptr<NotificationBundleOption> &bundleOption,
    const bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsSilentReminderEnabled(const sptr<NotificationBundleOption> &bundleOption,
    int32_t &enableStatusInt) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetTargetDeviceBundleList(const std::string& deviceType, const std::string& deviceId,
        std::vector<std::string>& bundleList, std::vector<std::string>& labelList) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetMutilDeviceStatus(const std::string &deviceType, const uint32_t status,
        std::string& deviceId, int32_t& userId) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetCheckConfig(int32_t response, const std::string& requestId, const std::string& key,
        const std::string& value) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetLiveViewConfig(const std::vector<std::string>& bundleList) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetDefaultSlotForBundle(const sptr<NotificationBundleOption> &bundleOption,
        int32_t slotTypeInt, bool enabled, bool isForceControl) override
    {
        return ERR_ANS_INVALID_PARAM;
    }
};

class AnsNotificationBranchTest : public testing::Test {
public:
    AnsNotificationBranchTest() {}

    virtual ~AnsNotificationBranchTest() {}

    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();
};

void AnsNotificationBranchTest::SetUpTestCase()
{
    MockGetAnsManagerProxy(nullptr);
}

void AnsNotificationBranchTest::TearDownTestCase() {}

void AnsNotificationBranchTest::SetUp() {}

/*
 * @tc.name: RemoveNotifications_0100
 * @tc.desc: Test RemoveNotifications and hashcodes is empty
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationBranchTest, RemoveNotifications_0100, Function | MediumTest | Level1)
{
    auto ansNotification = std::make_shared<AnsNotification>();
    EXPECT_NE(ansNotification, nullptr);
    std::vector<std::string> hashcodes;
    int32_t removeReason = 1;
    ErrCode ret = ansNotification->RemoveNotifications(hashcodes, removeReason);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: RemoveNotifications_0200
 * @tc.desc: 1.Test RemoveNotifications and hashcodes is not empty
 *           2.GetAnsManagerProxy is false
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationBranchTest, RemoveNotifications_0200, Function | MediumTest | Level1)
{
    auto ansNotification = std::make_shared<AnsNotification>();
    EXPECT_NE(ansNotification, nullptr);
    std::string hashcode = "aa";
    std::vector<std::string> hashcodes;
    hashcodes.emplace_back(hashcode);
    int32_t removeReason = 1;
    ErrCode ret = ansNotification->RemoveNotifications(hashcodes, removeReason);
    EXPECT_EQ(ret, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: RemoveNotifications_0300
 * @tc.desc: 1.Test RemoveNotifications and hashcodes is not empty
 *           2.GetAnsManagerProxy is true
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationBranchTest, RemoveNotifications_0300, Function | MediumTest | Level1)
{
    auto ansNotification = std::make_shared<AnsNotification>();
    EXPECT_NE(ansNotification, nullptr);
    std::string hashcode = "aa";
    std::vector<std::string> hashcodes;
    hashcodes.emplace_back(hashcode);
    int32_t removeReason = 1;
    ansNotification->RemoveNotifications(hashcodes, removeReason);
}

/*
 * @tc.name: RegisterPushCallback_0100
 * @tc.desc: 1.Test RegisterPushCallback
 *           2.GetAnsManagerProxy is false
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationBranchTest, RegisterPushCallback_0100, Function | MediumTest | Level1)
{
    auto ansNotification = std::make_shared<AnsNotification>();
    EXPECT_NE(ansNotification, nullptr);
    sptr<IRemoteObject> pushCallback = nullptr;
    sptr<NotificationCheckRequest> checkRequest = new (std::nothrow) NotificationCheckRequest();
    ErrCode ret = ansNotification->RegisterPushCallback(pushCallback, checkRequest);
    EXPECT_EQ(ret, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: RegisterPushCallback_0200
 * @tc.desc: 1.Test RegisterPushCallback
 *           2.GetAnsManagerProxy is true
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationBranchTest, RegisterPushCallback_0200, Function | MediumTest | Level1)
{
    auto ansNotification = std::make_shared<AnsNotification>();
    EXPECT_NE(ansNotification, nullptr);
    sptr<IRemoteObject> pushCallback = nullptr;
    sptr<NotificationCheckRequest> checkRequest = new (std::nothrow) NotificationCheckRequest();
    ansNotification->RegisterPushCallback(pushCallback, checkRequest);
}

/*
 * @tc.name: UnregisterPushCallback_0100
 * @tc.desc: 1.Test UnregisterPushCallback
 *           2.GetAnsManagerProxy is false
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationBranchTest, UnregisterPushCallback_0100, Function | MediumTest | Level1)
{
    auto ansNotification = std::make_shared<AnsNotification>();
    EXPECT_NE(ansNotification, nullptr);
    ErrCode ret = ansNotification->UnregisterPushCallback();
    EXPECT_EQ(ret, ERR_ANS_SERVICE_NOT_CONNECTED);
}

/*
 * @tc.name: UnregisterPushCallback_0200
 * @tc.desc: 1.Test UnregisterPushCallback
 *           2.GetAnsManagerProxy is true
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationBranchTest, UnregisterPushCallback_0200, Function | MediumTest | Level1)
{
    auto ansNotification = std::make_shared<AnsNotification>();
    EXPECT_NE(ansNotification, nullptr);
    ansNotification->UnregisterPushCallback();
}

/*
 * @tc.name: CanPublishLiveViewContent_0100
 * @tc.desc: CanPublishLiveViewContent
 * @tc.type: FUNC
 * @tc.require: issule
 */
HWTEST_F(AnsNotificationBranchTest, CanPublishLiveViewContent_0100, Function | MediumTest | Level1)
{
    NotificationRequest request;
    auto notification = std::make_shared<AnsNotification>();
    EXPECT_TRUE(notification->CanPublishLiveViewContent(request));
}

/*
 * @tc.name: CanPublishLiveViewContent_0110
 * @tc.desc: CanPublishLiveViewContent
 * @tc.type: FUNC
 * @tc.require: issule
 */
HWTEST_F(AnsNotificationBranchTest, CanPublishLiveViewContent_0110, Function | MediumTest | Level1)
{
    NotificationRequest request;
    request.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_BUTT);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request.SetContent(content);

    auto notification = std::make_shared<AnsNotification>();
    EXPECT_FALSE(notification->CanPublishLiveViewContent(request));
}

/*
 * @tc.name: CanPublishLiveViewContent_0120
 * @tc.desc: CanPublishLiveViewContent
 * @tc.type: FUNC
 * @tc.require: issule
 */
HWTEST_F(AnsNotificationBranchTest, CanPublishLiveViewContent_0120, Function | MediumTest | Level1)
{
    NotificationRequest request;
    request.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request.SetContent(content);

    auto notification = std::make_shared<AnsNotification>();
    EXPECT_TRUE(notification->CanPublishLiveViewContent(request));
}

/*
 * @tc.name: CanPublishLiveViewContent_0130
 * @tc.desc: CanPublishLiveViewContent
 * @tc.type: FUNC
 * @tc.require: issule
 */
HWTEST_F(AnsNotificationBranchTest, CanPublishLiveViewContent_0130, Function | MediumTest | Level1)
{
    NotificationRequest request;
    request.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request.SetContent(content);

    auto notification = std::make_shared<AnsNotification>();
    EXPECT_TRUE(notification->CanPublishLiveViewContent(request));
}

/*
 * @tc.name: CanPublishLiveViewContent_0140
 * @tc.desc: CanPublishLiveViewContent
 * @tc.type: FUNC
 * @tc.require: issule
 */
HWTEST_F(AnsNotificationBranchTest, CanPublishLiveViewContent_0140, Function | MediumTest | Level1)
{
    NotificationRequest request;
    request.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request.SetContent(content);
    request.notificationContent_ = nullptr;

    auto notification = std::make_shared<AnsNotification>();
    EXPECT_FALSE(notification->CanPublishLiveViewContent(request));
}

/*
 * @tc.name: CanPublishLiveViewContent_0150
 * @tc.desc: CanPublishLiveViewContent
 * @tc.type: FUNC
 * @tc.require: issule
 */
HWTEST_F(AnsNotificationBranchTest, CanPublishLiveViewContent_0150, Function | MediumTest | Level1)
{
    NotificationRequest request;
    request.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    content->content_ = nullptr;
    request.SetContent(content);

    auto notification = std::make_shared<AnsNotification>();
    EXPECT_FALSE(notification->CanPublishLiveViewContent(request));
}

/*
 * @tc.name: SetNotificationSlotFlagsAsBundle_0001
 * @tc.desc: SetNotificationSlotFlagsAsBundle
 * @tc.type: FUNC
 * @tc.require: issule
 */
HWTEST_F(AnsNotificationBranchTest, SetNotificationSlotFlagsAsBundle_0001, Function | MediumTest | Level1)
{
    NotificationBundleOption bundle;
    uint32_t slotFlags = 1;
    auto notification = std::make_shared<AnsNotification>();
    ErrCode ret = notification->SetNotificationSlotFlagsAsBundle(bundle, slotFlags);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
    ret = notification->GetNotificationSlotFlagsAsBundle(bundle, slotFlags);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: PublishNotification_0001
 * @tc.desc: PublishNotification
 * @tc.type: FUNC
 * @tc.require: issule
 */
HWTEST_F(AnsNotificationBranchTest, PublishNotification_0001, Function | MediumTest | Level1)
{
    auto notification = std::make_shared<AnsNotification>();
    MockGetAnsManagerProxy(new (std::nothrow) MockAnsManagerInterface());
    NotificationRequest req;
    std::shared_ptr<NotificationMediaContent> mediaContent = std::make_shared<NotificationMediaContent>();
    auto content = std::make_shared<NotificationContent>(mediaContent);
    content->content_ = nullptr;
    req.SetContent(content);

    auto ret = notification->PublishNotification("label", req);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
    ret = notification->PublishNotificationAsBundle("label", req);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);

    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto content1 = std::make_shared<NotificationContent>(liveViewContent);
    content1->content_ = nullptr;
    req.SetContent(content1);
    req.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    ret = notification->PublishNotification("label", req);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
    ret = notification->PublishNotificationAsBundle("label", req);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

}  // namespace Notification
}  // namespace OHOS
