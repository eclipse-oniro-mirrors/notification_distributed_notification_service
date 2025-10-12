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

#ifndef OHOS_NOTIFICATION_MOCK_ANS_MANAGER_PROXY_H
#define OHOS_NOTIFICATION_MOCK_ANS_MANAGER_PROXY_H

#include "gmock/gmock.h"

#include <iremote_proxy.h>
#include "ians_manager.h"

namespace OHOS {
namespace Notification {
class MockAnsManagerProxy : public IAnsManager {
public:
    MockAnsManagerProxy() = default;
    virtual ~MockAnsManagerProxy() {};

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }

    ErrCode GetBundleImportance(int32_t& importance)
    {
        importance = NotificationSlot::LEVEL_HIGH + 1;
        return ERR_OK;
    }

    MOCK_METHOD2(Publish, ErrCode(const std::string&, const sptr<NotificationRequest>&));
    MOCK_METHOD2(PublishWithMaxCapacity, ErrCode(const std::string&, const sptr<NotificationRequest>&));
    MOCK_METHOD1(PublishNotificationForIndirectProxy, ErrCode(const sptr<NotificationRequest>&));
    MOCK_METHOD1(PublishNotificationForIndirectProxyWithMaxCapacity, ErrCode(const sptr<NotificationRequest>&));
    MOCK_METHOD3(Cancel, ErrCode(int32_t, const std::string&, const std::string&));
    MOCK_METHOD1(CancelAll, ErrCode(const std::string&));
    MOCK_METHOD3(CancelAsBundle, ErrCode(int32_t, const std::string&, int32_t));
    MOCK_METHOD2(CancelAsBundle, ErrCode(const sptr<NotificationBundleOption>&, int32_t));
    MOCK_METHOD3(CancelAsBundle, ErrCode(const sptr<NotificationBundleOption>&, int32_t, int32_t));
    MOCK_METHOD1(AddSlotByType, ErrCode(int32_t));
    MOCK_METHOD1(AddSlots, ErrCode(const std::vector<sptr<NotificationSlot>>&));
    MOCK_METHOD1(RemoveSlotByType, ErrCode(int32_t));
    MOCK_METHOD0(RemoveAllSlots, ErrCode());
    MOCK_METHOD2(GetSlotByType, ErrCode(int32_t, sptr<NotificationSlot>&));
    MOCK_METHOD1(GetSlots, ErrCode(std::vector<sptr<NotificationSlot>>&));
    MOCK_METHOD2(GetSlotNumAsBundle, ErrCode(const sptr<NotificationBundleOption>&, uint64_t&));
    MOCK_METHOD2(GetActiveNotifications, ErrCode(std::vector<sptr<NotificationRequest>>&, const std::string&));
    MOCK_METHOD1(GetActiveNotificationNums, ErrCode(uint64_t&));
    MOCK_METHOD1(GetAllActiveNotifications, ErrCode(std::vector<sptr<Notification>>&));
    MOCK_METHOD2(GetAllNotificationsBySlotType, ErrCode(std::vector<sptr<Notification>>&, int32_t));
    MOCK_METHOD2(GetSpecialActiveNotifications,
        ErrCode(const std::vector<std::string>&, std::vector<sptr<Notification>>&));
    MOCK_METHOD6(GetActiveNotificationByFilter, ErrCode(
        const sptr<NotificationBundleOption>&,
        int32_t,
        const std::string&,
        int32_t,
        const std::vector<std::string>&,
        sptr<NotificationRequest>&));
    MOCK_METHOD2(CanPublishAsBundle, ErrCode(const std::string&, bool&));
    MOCK_METHOD2(PublishAsBundle, ErrCode(const sptr<NotificationRequest>&, const std::string&));
    MOCK_METHOD2(PublishAsBundleWithMaxCapacity, ErrCode(const sptr<NotificationRequest>&, const std::string&));
    MOCK_METHOD1(SetNotificationBadgeNum, ErrCode(int32_t));
    MOCK_METHOD1(HasNotificationPolicyAccessPermission, ErrCode(bool&));
    MOCK_METHOD3(TriggerLocalLiveView,
        ErrCode(const sptr<NotificationBundleOption>&, int32_t, const sptr<NotificationButtonOption>&));
    MOCK_METHOD4(RemoveNotification, ErrCode(
        const sptr<NotificationBundleOption>&, int32_t, const std::string&, int32_t));
    MOCK_METHOD1(RemoveAllNotifications, ErrCode(const sptr<NotificationBundleOption>&));
    MOCK_METHOD2(RemoveNotifications, ErrCode(const std::vector<std::string>&, int32_t));
    MOCK_METHOD2(Delete, ErrCode(const std::string&, int32_t));
    MOCK_METHOD1(DeleteByBundle, ErrCode(const sptr<NotificationBundleOption>&));
    MOCK_METHOD0(DeleteAll, ErrCode());
    MOCK_METHOD2(GetSlotsByBundle,
        ErrCode(const sptr<NotificationBundleOption>&, std::vector<sptr<NotificationSlot>>&));
    MOCK_METHOD3(GetSlotByBundle, ErrCode(const sptr<NotificationBundleOption>&, int32_t, sptr<NotificationSlot>&));
    MOCK_METHOD2(UpdateSlots,
        ErrCode(const sptr<NotificationBundleOption>&, const std::vector<sptr<NotificationSlot>>&));
    MOCK_METHOD2(RequestEnableNotification, ErrCode(const std::string&, const sptr<IAnsDialogCallback>&));
    MOCK_METHOD3(RequestEnableNotification,
        ErrCode(const std::string&, const sptr<IAnsDialogCallback>&, const sptr<IRemoteObject>&));
    MOCK_METHOD2(RequestEnableNotification, ErrCode(const std::string&, int32_t));
    MOCK_METHOD2(SetNotificationsEnabledForBundle, ErrCode(const std::string&, bool));
    MOCK_METHOD2(SetNotificationsEnabledForAllBundles, ErrCode(const std::string&, bool));
    MOCK_METHOD4(SetNotificationsEnabledForSpecialBundle,
        ErrCode(const std::string&, const sptr<NotificationBundleOption>&, bool, bool));
    MOCK_METHOD2(SetShowBadgeEnabledForBundle, ErrCode(const sptr<NotificationBundleOption>&, bool));
    MOCK_METHOD2(GetShowBadgeEnabledForBundle, ErrCode(const sptr<NotificationBundleOption>&, bool&));
    MOCK_METHOD1(GetShowBadgeEnabled, ErrCode(bool&));
    MOCK_METHOD1(Subscribe, ErrCode(const sptr<IAnsSubscriber>&));
    MOCK_METHOD2(Subscribe, ErrCode(const sptr<IAnsSubscriber>&, const sptr<NotificationSubscribeInfo>&));
    MOCK_METHOD1(SubscribeSelf, ErrCode(const sptr<IAnsSubscriber>&));
    MOCK_METHOD2(SubscribeLocalLiveView, ErrCode(const sptr<IAnsSubscriberLocalLiveView>&, bool));
    MOCK_METHOD3(SubscribeLocalLiveView,
        ErrCode(const sptr<IAnsSubscriberLocalLiveView>&, const sptr<NotificationSubscribeInfo>&, bool));
    MOCK_METHOD1(Unsubscribe, ErrCode(const sptr<IAnsSubscriber>&));
    MOCK_METHOD2(Unsubscribe, ErrCode(const sptr<IAnsSubscriber>&, const sptr<NotificationSubscribeInfo>&));
    MOCK_METHOD1(IsAllowedNotify, ErrCode(bool&));
    MOCK_METHOD1(IsAllowedNotifySelf, ErrCode(bool&));
    MOCK_METHOD3(CanPopEnableNotificationDialog,
        ErrCode(const sptr<IAnsDialogCallback>&, bool&, std::string&));
    MOCK_METHOD0(RemoveEnableNotificationDialog, ErrCode());
    MOCK_METHOD2(IsSpecialBundleAllowedNotify, ErrCode(const sptr<NotificationBundleOption>&, bool&));
    MOCK_METHOD1(SetDoNotDisturbDate, ErrCode(const sptr<NotificationDoNotDisturbDate>&));
    MOCK_METHOD1(GetDoNotDisturbDate, ErrCode(sptr<NotificationDoNotDisturbDate>&));
    MOCK_METHOD1(AddDoNotDisturbProfiles, ErrCode(const std::vector<sptr<NotificationDoNotDisturbProfile>>&));
    MOCK_METHOD1(RemoveDoNotDisturbProfiles, ErrCode(const std::vector<sptr<NotificationDoNotDisturbProfile>>&));
    MOCK_METHOD1(DoesSupportDoNotDisturbMode, ErrCode(bool&));
    MOCK_METHOD2(IsNeedSilentInDoNotDisturbMode, ErrCode(const std::string&, int32_t));
    MOCK_METHOD2(CancelGroup, ErrCode(const std::string&, const std::string&));
    MOCK_METHOD2(RemoveGroupByBundle, ErrCode(const sptr<NotificationBundleOption>&, const std::string&));
    MOCK_METHOD1(IsDistributedEnabled, ErrCode(bool&));
    MOCK_METHOD3(SetDistributedEnabledBySlot, ErrCode(int32_t, const std::string&, bool));
    MOCK_METHOD3(IsDistributedEnabledBySlot, ErrCode(int32_t, const std::string&, bool&));
    MOCK_METHOD1(EnableDistributed, ErrCode(bool));
    MOCK_METHOD2(EnableDistributedByBundle, ErrCode(const sptr<NotificationBundleOption>&, bool));
    MOCK_METHOD1(EnableDistributedSelf, ErrCode(bool));
    MOCK_METHOD2(IsDistributedEnableByBundle, ErrCode(const sptr<NotificationBundleOption>&, bool&));
    MOCK_METHOD1(GetDeviceRemindType, ErrCode(int32_t&));
    MOCK_METHOD1(PublishContinuousTaskNotification, ErrCode(const sptr<NotificationRequest>&));
    MOCK_METHOD2(CancelContinuousTaskNotification, ErrCode(const std::string&, int32_t));
    MOCK_METHOD2(IsSupportTemplate, ErrCode(const std::string&, bool&));
    MOCK_METHOD2(IsSpecialUserAllowedNotify, ErrCode(int32_t, bool&));
    MOCK_METHOD2(SetNotificationsEnabledByUser, ErrCode(int32_t, bool));
    MOCK_METHOD1(DeleteAllByUser, ErrCode(int32_t));
    MOCK_METHOD2(SetDoNotDisturbDate, ErrCode(int32_t, const sptr<NotificationDoNotDisturbDate>&));
    MOCK_METHOD2(GetDoNotDisturbDate, ErrCode(int32_t, sptr<NotificationDoNotDisturbDate>&));
    MOCK_METHOD4(SetEnabledForBundleSlot,
        ErrCode(const sptr<NotificationBundleOption>& bundleOption, int32_t, bool, bool));
    MOCK_METHOD3(GetEnabledForBundleSlot, ErrCode(const sptr<NotificationBundleOption>&, int32_t, bool&));
    MOCK_METHOD2(GetEnabledForBundleSlotSelf, ErrCode(int32_t, bool&));
    MOCK_METHOD5(ShellDump,
        ErrCode(const std::string&, const std::string&, int32_t, int32_t, std::vector<std::string>&));
    MOCK_METHOD2(SetSyncNotificationEnabledWithoutApp, ErrCode(int32_t, bool));
    MOCK_METHOD2(GetSyncNotificationEnabledWithoutApp, ErrCode(int32_t, bool&));
    MOCK_METHOD2(SetBadgeNumber, ErrCode(int32_t, const std::string&));
    MOCK_METHOD2(SetBadgeNumberByBundle, ErrCode(const sptr<NotificationBundleOption>&, int32_t));
    MOCK_METHOD2(SetBadgeNumberForDhByBundle, ErrCode(const sptr<NotificationBundleOption>&, int32_t));
    MOCK_METHOD2(GetSlotFlagsAsBundle, ErrCode(const sptr<NotificationBundleOption>&, uint32_t&));
    MOCK_METHOD2(SetSlotFlagsAsBundle, ErrCode(const sptr<NotificationBundleOption>&, uint32_t));
    MOCK_METHOD1(GetNotificationSettings, ErrCode(uint32_t&));
    MOCK_METHOD1(GetAllNotificationEnabledBundles, ErrCode(std::vector<NotificationBundleOption>&));
    MOCK_METHOD1(GetAllLiveViewEnabledBundles, ErrCode(std::vector<NotificationBundleOption>&));
    MOCK_METHOD2(GetAllDistribuedEnabledBundles, ErrCode(const std::string&, std::vector<NotificationBundleOption>&));
    MOCK_METHOD2(RegisterPushCallback, ErrCode(const sptr<IRemoteObject>&, const sptr<NotificationCheckRequest>&));
    MOCK_METHOD0(UnregisterPushCallback, ErrCode());
    MOCK_METHOD2(SetAdditionConfig, ErrCode(const std::string&, const std::string&));
    MOCK_METHOD3(SetDistributedEnabledByBundle,
        ErrCode(const sptr<NotificationBundleOption>&, const std::string&, bool));
    MOCK_METHOD2(SetDistributedBundleOption,
        ErrCode(const std::vector<sptr<DistributedBundleOption>>&, const std::string &));
    MOCK_METHOD2(SetDistributedEnabled, ErrCode(const std::string&, bool));
    MOCK_METHOD2(IsDistributedEnabled, ErrCode(const std::string&, bool&));
    MOCK_METHOD1(GetDistributedAbility, ErrCode(int32_t&));
    MOCK_METHOD4(GetDistributedAuthStatus, ErrCode(const std::string&, const std::string&, int32_t, bool&));
    MOCK_METHOD4(SetDistributedAuthStatus, ErrCode(const std::string&, const std::string&, int32_t, bool));
    MOCK_METHOD2(IsSmartReminderEnabled, ErrCode(const std::string&, bool&));
    MOCK_METHOD2(SetSmartReminderEnabled, ErrCode(const std::string&, bool));
    MOCK_METHOD3(IsDistributedEnabledByBundle,
        ErrCode(const sptr<NotificationBundleOption>&, const std::string&, bool&));
    MOCK_METHOD2(CancelAsBundleWithAgent, ErrCode(const sptr<NotificationBundleOption>&, int32_t));
    MOCK_METHOD3(SetTargetDeviceStatus, ErrCode(const std::string&, uint32_t, const std::string&));
    MOCK_METHOD5(SetTargetDeviceStatus, ErrCode(const std::string&, uint32_t, uint32_t, const std::string&, int32_t));
    MOCK_METHOD2(GetDoNotDisturbProfile, ErrCode(int64_t, sptr<NotificationDoNotDisturbProfile>&));
    MOCK_METHOD2(AllowUseReminder, ErrCode(const std::string&, bool&));
    MOCK_METHOD2(UpdateNotificationTimerByUid, ErrCode(int32_t, bool));
    MOCK_METHOD1(DisableNotificationFeature, ErrCode(const sptr<NotificationDisable>&));
    MOCK_METHOD2(GetTargetDeviceStatus, ErrCode(const std::string&, int32_t&));
    MOCK_METHOD2(DistributeOperation,
        ErrCode(const sptr<NotificationOperationInfo>&, const sptr<IAnsOperationCallback>&));
    MOCK_METHOD2(ReplyDistributeOperation, ErrCode(const std::string&, int32_t));
    MOCK_METHOD2(GetNotificationRequestByHashCode, ErrCode(const std::string&, sptr<NotificationRequest>&));
    MOCK_METHOD5(SetTargetDeviceBundleList, ErrCode(const std::string&, const std::string&, int32_t,
        const std::vector<std::string>&, const std::vector<std::string>&));
    MOCK_METHOD4(SetTargetDeviceSwitch, ErrCode(const std::string&, const std::string&, bool, bool));
    MOCK_METHOD1(SetHashCodeRule, ErrCode(uint32_t));
    MOCK_METHOD5(RemoveDistributedNotifications, ErrCode(const std::vector<std::string>& hashcodes,
        const int32_t, const int32_t, const int32_t, const std::string&));
    MOCK_METHOD2(SetSilentReminderEnabled, ErrCode(const sptr<NotificationBundleOption> &bundleOption,
        const bool enabled));
    MOCK_METHOD2(IsSilentReminderEnabled, ErrCode(const sptr<NotificationBundleOption> &bundleOption,
        int32_t &enableStatusInt));
    MOCK_METHOD1(GetDistributedDevicelist, ErrCode(std::vector<std::string>& deviceList));
    MOCK_METHOD4(GetMutilDeviceStatus, ErrCode(const std::string&, const uint32_t, std::string&, int32_t&));
    MOCK_METHOD4(GetTargetDeviceBundleList, ErrCode(const std::string&, const std::string&,
        std::vector<std::string>&, std::vector<std::string>&));
    MOCK_METHOD4(SetCheckConfig, ErrCode(int32_t, const std::string&, const std::string&, const std::string&));
    MOCK_METHOD1(GetLiveViewConfig, ErrCode(const std::vector<std::string>&));
    MOCK_METHOD4(SetDefaultSlotForBundle, ErrCode(const sptr<NotificationBundleOption> &, int32_t, bool, bool));
    MOCK_METHOD1(NotificationExtensionSubscribe,
        ErrCode(const std::vector<sptr<NotificationExtensionSubscriptionInfo>>&));
    MOCK_METHOD0(NotificationExtensionUnsubscribe, ErrCode());
    MOCK_METHOD1(GetSubscribeInfo, ErrCode(std::vector<sptr<NotificationExtensionSubscriptionInfo>>&));
    MOCK_METHOD1(IsUserGranted, ErrCode(bool &enabled));
    MOCK_METHOD2(GetUserGrantedState, ErrCode(const sptr<NotificationBundleOption> &targetBundle, bool &enabled));
    MOCK_METHOD2(SetUserGrantedState, ErrCode(const sptr<NotificationBundleOption> &targetBundle, bool enabled));
    MOCK_METHOD2(GetReminderInfoByBundles, ErrCode(const std::vector<sptr<NotificationBundleOption>>&,
        std::vector<NotificationReminderInfo>&));
    MOCK_METHOD1(SetReminderInfoByBundles, ErrCode(const std::vector<sptr<NotificationReminderInfo>>&));
    MOCK_METHOD2(GetUserGrantedEnabledBundles, ErrCode(const sptr<NotificationBundleOption>& bundleOption,
        std::vector<sptr<NotificationBundleOption>>& enabledBundles));
    MOCK_METHOD1(GetUserGrantedEnabledBundlesForSelf, ErrCode(std::vector<sptr<NotificationBundleOption>>& bundles));
    MOCK_METHOD3(SetUserGrantedBundleState, ErrCode(const sptr<NotificationBundleOption>& bundleOption,
        const std::vector<sptr<NotificationBundleOption>>& enabledBundles, bool enabled));
    MOCK_METHOD1(SetShowBadgeEnabledForBundles,
        ErrCode(const std::map<sptr<NotificationBundleOption>, bool> &bundleOptions));
    MOCK_METHOD2(GetShowBadgeEnabledForBundles, ErrCode(const std::vector<sptr<NotificationBundleOption>> &bundles,
        std::map<sptr<NotificationBundleOption>, bool> &bundleEnable));
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    MOCK_METHOD1(RegisterSwingCallback, ErrCode(const sptr<IRemoteObject>&));
#endif
    MOCK_METHOD2(ProxyForUnaware, ErrCode(const std::vector<int32_t>&, bool));
    MOCK_METHOD2(SetRingtoneInfoByBundle, ErrCode(const sptr<NotificationBundleOption> &bundle,
        const sptr<NotificationRingtoneInfo> &ringtoneInfo));
    MOCK_METHOD2(GetRingtoneInfoByBundle, ErrCode(const sptr<NotificationBundleOption> &bundle,
        sptr<NotificationRingtoneInfo> &ringtoneInfo));
};
} // namespace Notification
} // namespace OHOS
#endif // OHOS_NOTIFICATION_MOCK_ANS_MANAGER_PROXY_H
