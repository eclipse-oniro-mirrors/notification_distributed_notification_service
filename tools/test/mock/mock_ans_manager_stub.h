/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_TOOLS_MOCK_ANS_MANAGER_STUB_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_TOOLS_MOCK_ANS_MANAGER_STUB_H

#include "gmock/gmock.h"

#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_manager_stub.h"

namespace OHOS {
namespace Notification {
class MockAnsManagerStub : public AnsManagerStub {
public:

    std::string GetCmd();
    std::string GetBundle();
    int32_t GetUserId();

    /**
     * @brief Obtains specific datas via specified dump option.
     *
     * @param cmd Indicates the specified dump command.
     * @param bundle Indicates the specified bundle name.
     * @param userId Indicates the specified userId.
     * @param dumpInfo Indicates the container containing datas.
     * @return Returns check result.
     */
    virtual ErrCode ShellDump(const std::string &cmd, const std::string &bundle, int32_t userId, int32_t recvUserId,
        std::vector<std::string> &dumpInfo) override;

    ErrCode Publish(const std::string &label, const sptr<NotificationRequest> &notification) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode PublishNotificationForIndirectProxy(const sptr<NotificationRequest>& notification) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode Cancel(int notificationId, const std::string& label, const std::string& instanceKey) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CancelAll(const std::string& instanceKey) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CancelAsBundle(int32_t notificationId, const std::string& representativeBundle, int32_t userId) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CancelAsBundle(const sptr<NotificationBundleOption>& bundleOption, int32_t notificationId) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CancelAsBundle(
        const sptr<NotificationBundleOption>& bundleOption, int32_t notificationId, int32_t userId) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode AddSlotByType(int32_t slotTypeInt) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode AddSlots(const std::vector<sptr<NotificationSlot>>& slots) override
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

    ErrCode GetSlotByType(int32_t slotTypeInt, sptr<NotificationSlot>& slot) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetSlots(std::vector<sptr<NotificationSlot>>& slots) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetSlotNumAsBundle(const sptr<NotificationBundleOption>& bundleOption, uint64_t& num) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetActiveNotifications(
        std::vector<sptr<NotificationRequest>>& notifications, const std::string& instanceKey) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetActiveNotificationNums(uint64_t& num) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetAllActiveNotifications(std::vector<sptr<Notification>>& notifications) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetSpecialActiveNotifications(
        const std::vector<std::string>& key, std::vector<sptr<Notification>>& notifications) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CanPublishAsBundle(const std::string& representativeBundle, bool& canPublish) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode PublishAsBundle(
        const sptr<NotificationRequest>& notification, const std::string& representativeBundle) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetNotificationBadgeNum(int num) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetBundleImportance(int& importance) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode HasNotificationPolicyAccessPermission(bool& granted) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode Delete(const std::string& key, int32_t removeReason) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RemoveNotification(const sptr<NotificationBundleOption>& bundleOption, int32_t notificationId,
        const std::string& label, int32_t removeReason) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RemoveAllNotifications(const sptr<NotificationBundleOption>& bundleOption) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RemoveDistributedNotifications(const std::vector<std::string>& hashcodes,
        const int32_t slotTypeInt, const int32_t deleteTypeInt, const int32_t removeReason,
        const std::string& deviceId = "") override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RemoveNotifications(const std::vector<std::string>& hashcodes, int32_t removeReason) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode DeleteByBundle(const sptr<NotificationBundleOption>& bundleOption) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode DeleteAll() override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetSlotsByBundle(
        const sptr<NotificationBundleOption>& bundleOption, std::vector<sptr<NotificationSlot>>& slots) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetSlotByBundle(const sptr<NotificationBundleOption>& bundleOption, int32_t slotTypeInt,
        sptr<NotificationSlot>& slot) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode UpdateSlots(const sptr<NotificationBundleOption>& bundleOption,
        const std::vector<sptr<NotificationSlot>>& slots) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RequestEnableNotification(
        const std::string& deviceId, const sptr<IAnsDialogCallback>& ansDialogCallback) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RequestEnableNotification(const std::string& deviceId,
        const sptr<IAnsDialogCallback>& ansDialogCallback, const sptr<IRemoteObject>& callerToken) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RequestEnableNotification(const std::string& bundleName, int32_t uid) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetNotificationsEnabledForBundle(const std::string& deviceId, bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetNotificationsEnabledForAllBundles(const std::string& deviceId, bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetNotificationsEnabledForSpecialBundle(
        const std::string& deviceId, const sptr<NotificationBundleOption>& bundleOption, bool enabled,
        bool updateUnEnableTime) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetShowBadgeEnabledForBundle(const sptr<NotificationBundleOption>& bundleOption, bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetShowBadgeEnabledForBundle(const sptr<NotificationBundleOption>& bundleOption, bool& enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetShowBadgeEnabled(bool& enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode Subscribe(const sptr<IAnsSubscriber>& subscriber) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode Subscribe(const sptr<IAnsSubscriber>& subscriber, const sptr<NotificationSubscribeInfo>& info) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SubscribeSelf(const sptr<IAnsSubscriber>& subscriber) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetAllNotificationEnabledBundles(std::vector<NotificationBundleOption>& bundleOption) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetTargetDeviceStatus(const std::string& deviceType, int32_t& status)
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetAllLiveViewEnabledBundles(std::vector<NotificationBundleOption>& bundleOption) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetAllDistribuedEnabledBundles(
        const std::string& deviceType, std::vector<NotificationBundleOption>& bundleOption) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SubscribeLocalLiveView(const sptr<IAnsSubscriberLocalLiveView>& subscriber, bool isNatives) override
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

    ErrCode Unsubscribe(
        const sptr<IAnsSubscriber>& subscriber, const sptr<NotificationSubscribeInfo>& info) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsAllowedNotify(bool& allowed) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsAllowedNotifySelf(bool& allowed) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CanPopEnableNotificationDialog(
        const sptr<IAnsDialogCallback>& callback, bool& canPop, std::string& bundleName) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RemoveEnableNotificationDialog() override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsSpecialBundleAllowedNotify(const sptr<NotificationBundleOption>& bundleOption, bool& allowed) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetDoNotDisturbDate(const sptr<NotificationDoNotDisturbDate>& date) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetDoNotDisturbDate(sptr<NotificationDoNotDisturbDate>& date) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode AddDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>>& profiles) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RemoveDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>>& profiles) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode DoesSupportDoNotDisturbMode(bool& doesSupport) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsNeedSilentInDoNotDisturbMode(const std::string& phoneNumber, int32_t callerType) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CancelGroup(const std::string& groupName, const std::string& instanceKey) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RemoveGroupByBundle(
        const sptr<NotificationBundleOption>& bundleOption, const std::string& groupName) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsDistributedEnabled(bool& enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode EnableDistributed(bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode EnableDistributedByBundle(const sptr<NotificationBundleOption>& bundleOption, bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode EnableDistributedSelf(bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsDistributedEnableByBundle(const sptr<NotificationBundleOption>& bundleOption, bool& enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetDeviceRemindType(int32_t& remindTypeInt) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode PublishContinuousTaskNotification(const sptr<NotificationRequest>& request) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CancelContinuousTaskNotification(const std::string& label, int32_t notificationId) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsSupportTemplate(const std::string& templateName, bool& support) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsSpecialUserAllowedNotify(int32_t userId, bool& allowed) override
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

    ErrCode SetDoNotDisturbDate(int32_t userId, const sptr<NotificationDoNotDisturbDate>& date) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetDoNotDisturbDate(int32_t userId, sptr<NotificationDoNotDisturbDate>& date) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetEnabledForBundleSlot(const sptr<NotificationBundleOption>& bundleOption, int32_t slotTypeInt,
        bool enabled, bool isForceControl) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetEnabledForBundleSlot(
        const sptr<NotificationBundleOption>& bundleOption, int32_t slotTypeInt, bool& enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetEnabledForBundleSlotSelf(int32_t slotTypeInt, bool& enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetSyncNotificationEnabledWithoutApp(const int32_t userId, const bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetSyncNotificationEnabledWithoutApp(const int32_t userId, bool& enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetBadgeNumber(int32_t badgeNumber, const std::string& instanceKey) override
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

    ErrCode GetSlotFlagsAsBundle(const sptr<NotificationBundleOption>& bundleOption, uint32_t& slotFlags) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetSlotFlagsAsBundle(const sptr<NotificationBundleOption>& bundleOption, uint32_t slotFlags) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetNotificationSettings(uint32_t& slotFlags) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode RegisterPushCallback(const sptr<IRemoteObject>& pushCallback,
        const sptr<NotificationCheckRequest>& notificationCheckRequest) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode UnregisterPushCallback() override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetActiveNotificationByFilter(const sptr<NotificationBundleOption>& bundleOption,
        int32_t notificationId, const std::string& label, int32_t userId, const std::vector<std::string>& extraInfoKeys,
        sptr<NotificationRequest>& request) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode TriggerLocalLiveView(const sptr<NotificationBundleOption>& bundleOption, const int32_t notificationId,
        const sptr<NotificationButtonOption>& buttonOption) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetDistributedEnabledByBundle(const sptr<NotificationBundleOption>& bundleOption,
        const std::string& deviceType, const bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetDistributedBundleOption(const std::vector<sptr<DistributedBundleOption>> &bundles,
        const std::string &deviceType) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetAdditionConfig(const std::string& key, const std::string& value) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsDistributedEnabledByBundle(
        const sptr<NotificationBundleOption>& bundleOption, const std::string& deviceType, bool& enabled) override
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

    ErrCode IsSmartReminderEnabled(const std::string& deviceType, bool& enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetSmartReminderEnabled(const std::string& deviceType, const bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetDistributedEnabledBySlot(int32_t slotTypeInt, const std::string& deviceType, bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode IsDistributedEnabledBySlot(int32_t slotTypeInt, const std::string& deviceType, bool& enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CancelAsBundleWithAgent(const sptr<NotificationBundleOption>& bundleOption, const int32_t id) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetTargetDeviceStatus(
        const std::string& deviceType, uint32_t status, const std::string& deviceId) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetTargetDeviceStatus(const std::string& deviceType, uint32_t status, uint32_t controlFlag,
        const std::string& deviceId, int32_t userId) override
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

    ErrCode GetDoNotDisturbProfile(int64_t id, sptr<NotificationDoNotDisturbProfile>& profile) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode NotificationExtensionSubscribe(
        const std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode NotificationExtensionUnsubscribe() override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetSubscribeInfo(std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetRingtoneInfoByBundle(const sptr<NotificationBundleOption> &bundle,
        const sptr<NotificationRingtoneInfo> &ringtoneInfo) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetRingtoneInfoByBundle(const sptr<NotificationBundleOption> &bundle,
        sptr<NotificationRingtoneInfo> &ringtoneInfo) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    ErrCode RegisterSwingCallback(const sptr<IRemoteObject>& swingCallback) override
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

    ErrCode DisableNotificationFeature(const sptr<NotificationDisable>& notificationDisable) override
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

    ErrCode GetAllNotificationsBySlotType(
        std::vector<sptr<Notification>>& notifications, int32_t slotTypeInt) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode PublishWithMaxCapacity(const std::string& label, const sptr<NotificationRequest>& notification) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode PublishNotificationForIndirectProxyWithMaxCapacity(
        const sptr<NotificationRequest>& notification) override
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
    ErrCode IsUserGranted(bool &enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetUserGrantedState(const sptr<NotificationBundleOption> &targetBundle, bool &enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetUserGrantedState(const sptr<NotificationBundleOption> &targetBundle, bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetReminderInfoByBundles(const std::vector<sptr<NotificationBundleOption>> &bundles,
        std::vector<NotificationReminderInfo> &reminderInfo) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetReminderInfoByBundles(const std::vector<sptr<NotificationReminderInfo>> &reminderInfo) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetUserGrantedEnabledBundlesForSelf(std::vector<sptr<NotificationBundleOption>>& bundles) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode SetUserGrantedBundleState(const sptr<NotificationBundleOption>& bundleOption,
        const std::vector<sptr<NotificationBundleOption>>& enabledBundles, bool enabled) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetUserGrantedEnabledBundles(const sptr<NotificationBundleOption>& bundleOption,
        std::vector<sptr<NotificationBundleOption>>& enabledBundles) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode GetAllSubscriptionBundles(std::vector<sptr<NotificationBundleOption>>& bundles) override
    {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode CanOpenSubscribeSettings() override
    {
        return ERR_ANS_INVALID_PARAM;
    }
private:
    std::string cmd_;
    std::string bundle_;
    int32_t userId_;
};
}  // namespace EventFwk
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_TOOLS_MOCK_ANS_MANAGER_STUB_H
