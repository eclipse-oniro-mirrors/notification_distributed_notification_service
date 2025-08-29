/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "notification_helper.h"
#include "ans_notification.h"
#include "singleton.h"
#include <memory>

namespace OHOS {
namespace Notification {
ErrCode NotificationHelper::AddNotificationSlot(const NotificationSlot &slot)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->AddNotificationSlot(slot);
}

ErrCode NotificationHelper::AddSlotByType(const NotificationConstant::SlotType &slotType)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->AddSlotByType(slotType);
}

ErrCode NotificationHelper::AddNotificationSlots(const std::vector<NotificationSlot> &slots)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->AddNotificationSlots(slots);
}

ErrCode NotificationHelper::RemoveNotificationSlot(const NotificationConstant::SlotType &slotType)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->RemoveNotificationSlot(slotType);
}

ErrCode NotificationHelper::RemoveAllSlots()
{
    return DelayedSingleton<AnsNotification>::GetInstance()->RemoveAllSlots();
}

ErrCode NotificationHelper::GetNotificationSlot(
    const NotificationConstant::SlotType &slotType, sptr<NotificationSlot> &slot)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationSlot(slotType, slot);
}

ErrCode NotificationHelper::GetNotificationSlots(std::vector<sptr<NotificationSlot>> &slots)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationSlots(slots);
}

ErrCode NotificationHelper::GetNotificationSlotNumAsBundle(const NotificationBundleOption &bundleOption, uint64_t &num)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationSlotNumAsBundle(bundleOption, num);
}

ErrCode NotificationHelper::GetNotificationSlotFlagsAsBundle(const NotificationBundleOption &bundleOption,
    uint32_t &slotFlags)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationSlotFlagsAsBundle(bundleOption, slotFlags);
}

ErrCode NotificationHelper::GetNotificationSettings(uint32_t &slotFlags)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationSettings(slotFlags);
}

ErrCode NotificationHelper::SetNotificationSlotFlagsAsBundle(const NotificationBundleOption &bundleOption,
    uint32_t slotFlags)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetNotificationSlotFlagsAsBundle(bundleOption, slotFlags);
}

ErrCode NotificationHelper::PublishNotification(const NotificationRequest &request,
    const std::string &instanceKey)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->PublishNotification(
        request, instanceKey);
}

ErrCode NotificationHelper::PublishNotification(const std::string &label,
    const NotificationRequest &request, const std::string &instanceKey)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->PublishNotification(
        label, request, instanceKey);
}

ErrCode NotificationHelper::PublishNotificationForIndirectProxy(const NotificationRequest &request)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->PublishNotificationForIndirectProxy(request);
}

ErrCode NotificationHelper::CancelNotification(int32_t notificationId, const std::string &instanceKey)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->CancelNotification(
        notificationId, instanceKey);
}

ErrCode NotificationHelper::CancelNotification(const std::string &label, int32_t notificationId,
    const std::string &instanceKey)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->CancelNotification(
        label, notificationId, instanceKey);
}

ErrCode NotificationHelper::CancelAllNotifications(const std::string &instanceKey)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->CancelAllNotifications(instanceKey);
}

ErrCode NotificationHelper::CancelAsBundle(
    int32_t notificationId, const std::string &representativeBundle, int32_t userId)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->CancelAsBundle(
        notificationId, representativeBundle, userId);
}

ErrCode NotificationHelper::CancelAsBundle(
    const NotificationBundleOption &bundleOption, int32_t notificationId)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->CancelAsBundle(
        bundleOption, notificationId);
}

ErrCode NotificationHelper::GetActiveNotificationNums(uint64_t &num)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetActiveNotificationNums(num);
}

ErrCode NotificationHelper::GetActiveNotifications(
    std::vector<sptr<NotificationRequest>> &request, const std::string &instanceKey)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetActiveNotifications(
        request, instanceKey);
}

ErrCode NotificationHelper::CanPublishNotificationAsBundle(const std::string &representativeBundle, bool &canPublish)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->CanPublishNotificationAsBundle(
        representativeBundle, canPublish);
}

ErrCode NotificationHelper::PublishNotificationAsBundle(
    const std::string &representativeBundle, const NotificationRequest &request)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->PublishNotificationAsBundle(representativeBundle, request);
}

ErrCode NotificationHelper::SetNotificationBadgeNum()
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetNotificationBadgeNum();
}

ErrCode NotificationHelper::SetNotificationBadgeNum(int32_t num)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetNotificationBadgeNum(num);
}

ErrCode NotificationHelper::IsAllowedNotify(bool &allowed)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->IsAllowedNotify(allowed);
}

ErrCode NotificationHelper::IsAllowedNotifySelf(bool &allowed)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->IsAllowedNotifySelf(allowed);
}

ErrCode NotificationHelper::CanPopEnableNotificationDialog(sptr<AnsDialogHostClient> &hostClient,
    bool &canPop, std::string &bundleName)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->CanPopEnableNotificationDialog(
        hostClient, canPop, bundleName);
}

ErrCode NotificationHelper::RemoveEnableNotificationDialog()
{
    return DelayedSingleton<AnsNotification>::GetInstance()->RemoveEnableNotificationDialog();
}

ErrCode NotificationHelper::RequestEnableNotification(std::string &deviceId,
    sptr<AnsDialogHostClient> &hostClient,
    sptr<IRemoteObject> &callerToken)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->RequestEnableNotification(
        deviceId, hostClient, callerToken);
}

ErrCode NotificationHelper::RequestEnableNotification(const std::string bundleName, const int32_t uid)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->RequestEnableNotification(
        bundleName, uid);
}

ErrCode NotificationHelper::HasNotificationPolicyAccessPermission(bool &hasPermission)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->HasNotificationPolicyAccessPermission(hasPermission);
}

ErrCode NotificationHelper::GetBundleImportance(NotificationSlot::NotificationLevel &importance)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetBundleImportance(importance);
}

ErrCode NotificationHelper::SubscribeNotification(const NotificationSubscriber &subscriber)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SubscribeNotification(subscriber);
}

ErrCode NotificationHelper::SubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SubscribeNotification(subscriber, nullptr);
}

ErrCode NotificationHelper::SubscribeNotificationSelf(const NotificationSubscriber &subscriber)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SubscribeNotificationSelf(subscriber);
}

ErrCode NotificationHelper::SubscribeNotificationSelf(const std::shared_ptr<NotificationSubscriber> &subscriber)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SubscribeNotificationSelf(subscriber);
}

ErrCode NotificationHelper::SubscribeLocalLiveViewNotification(const NotificationLocalLiveViewSubscriber &subscriber,
    const bool isNative)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SubscribeLocalLiveViewNotification(subscriber, isNative);
}

ErrCode NotificationHelper::SubscribeNotification(
    const NotificationSubscriber &subscriber, const NotificationSubscribeInfo &subscribeInfo)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SubscribeNotification(subscriber, subscribeInfo);
}

ErrCode NotificationHelper::SubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber,
    const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SubscribeNotification(subscriber, subscribeInfo);
}

ErrCode NotificationHelper::UnSubscribeNotification(NotificationSubscriber &subscriber)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->UnSubscribeNotification(subscriber);
}

ErrCode NotificationHelper::UnSubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->UnSubscribeNotification(subscriber);
}

ErrCode NotificationHelper::UnSubscribeNotification(
    NotificationSubscriber &subscriber, NotificationSubscribeInfo subscribeInfo)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->UnSubscribeNotification(subscriber, subscribeInfo);
}

ErrCode NotificationHelper::UnSubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber,
    const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->UnSubscribeNotification(subscriber, subscribeInfo);
}

ErrCode NotificationHelper::TriggerLocalLiveView(const NotificationBundleOption &bundleOption,
    const int32_t notificationId, const NotificationButtonOption &buttonOption)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->TriggerLocalLiveView(
        bundleOption, notificationId, buttonOption);
}

ErrCode NotificationHelper::RemoveNotification(const std::string &key, int32_t removeReason)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->RemoveNotification(key, removeReason);
}

ErrCode NotificationHelper::RemoveNotification(const NotificationBundleOption &bundleOption,
    const int32_t notificationId, const std::string &label, int32_t removeReason)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->RemoveNotification(bundleOption,
        notificationId, label, removeReason);
}

ErrCode NotificationHelper::RemoveAllNotifications(const NotificationBundleOption &bundleOption)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->RemoveAllNotifications(bundleOption);
}

ErrCode NotificationHelper::RemoveNotifications(const std::vector<std::string> hashcodes, int32_t removeReason)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->RemoveNotifications(hashcodes, removeReason);
}

ErrCode NotificationHelper::RemoveNotificationsByBundle(const NotificationBundleOption &bundleOption)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->RemoveNotificationsByBundle(bundleOption);
}

ErrCode NotificationHelper::RemoveNotifications()
{
    return DelayedSingleton<AnsNotification>::GetInstance()->RemoveNotifications();
}

ErrCode NotificationHelper::RemoveDistributedNotifications(const std::vector<std::string>& hashcodes,
    const NotificationConstant::SlotType& slotType,
    const NotificationConstant::DistributedDeleteType& deleteType,
    const int32_t removeReason, const std::string& deviceId)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->RemoveDistributedNotifications(
        hashcodes, slotType, deleteType, removeReason, deviceId);
}

ErrCode NotificationHelper::GetNotificationSlotsForBundle(
    const NotificationBundleOption &bundleOption, std::vector<sptr<NotificationSlot>> &slots)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationSlotsForBundle(bundleOption, slots);
}

ErrCode NotificationHelper::GetNotificationSlotForBundle(
    const NotificationBundleOption &bundleOption, const NotificationConstant::SlotType &slotType,
    sptr<NotificationSlot> &slot)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationSlotForBundle(bundleOption, slotType, slot);
}

ErrCode NotificationHelper::UpdateNotificationSlots(
    const NotificationBundleOption &bundleOption, const std::vector<sptr<NotificationSlot>> &slots)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->UpdateNotificationSlots(bundleOption, slots);
}

ErrCode NotificationHelper::GetAllActiveNotifications(std::vector<sptr<Notification>> &notification)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetAllActiveNotifications(notification);
}

ErrCode NotificationHelper::GetAllNotificationsBySlotType(std::vector<sptr<Notification>> &notifications,
    const NotificationConstant::SlotType slotType)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetAllNotificationsBySlotType(notifications, slotType);
}

ErrCode NotificationHelper::GetAllActiveNotifications(
    const std::vector<std::string> key, std::vector<sptr<Notification>> &notification)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetAllActiveNotifications(key, notification);
}

ErrCode NotificationHelper::GetActiveNotificationByFilter(
    const LiveViewFilter &filter, sptr<NotificationRequest> &request)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetActiveNotificationByFilter(filter, request);
}

ErrCode NotificationHelper::IsAllowedNotify(const NotificationBundleOption &bundleOption, bool &allowed)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->IsAllowedNotify(bundleOption, allowed);
}

ErrCode NotificationHelper::SetNotificationsEnabledForAllBundles(const std::string &deviceId, bool enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetNotificationsEnabledForAllBundles(deviceId, enabled);
}

ErrCode NotificationHelper::SetNotificationsEnabledForDefaultBundle(const std::string &deviceId, bool enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetNotificationsEnabledForDefaultBundle(deviceId, enabled);
}

ErrCode NotificationHelper::SetNotificationsEnabledForSpecifiedBundle(
    const NotificationBundleOption &bundleOption, std::string &deviceId, bool enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetNotificationsEnabledForSpecifiedBundle(
        bundleOption, deviceId, enabled);
}

ErrCode NotificationHelper::SetShowBadgeEnabledForBundle(const NotificationBundleOption &bundleOption, bool enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetShowBadgeEnabledForBundle(bundleOption, enabled);
}

ErrCode NotificationHelper::GetShowBadgeEnabledForBundle(const NotificationBundleOption &bundleOption, bool &enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetShowBadgeEnabledForBundle(bundleOption, enabled);
}

ErrCode NotificationHelper::GetShowBadgeEnabled(bool &enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetShowBadgeEnabled(enabled);
}

ErrCode NotificationHelper::CancelGroup(const std::string &groupName, const std::string &instanceKey)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->CancelGroup(
        groupName, instanceKey);
}

ErrCode NotificationHelper::RemoveGroupByBundle(
    const NotificationBundleOption &bundleOption, const std::string &groupName)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->RemoveGroupByBundle(bundleOption, groupName);
}

ErrCode NotificationHelper::SetDoNotDisturbDate(const NotificationDoNotDisturbDate &doNotDisturbDate)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetDoNotDisturbDate(doNotDisturbDate);
}

ErrCode NotificationHelper::GetDoNotDisturbDate(NotificationDoNotDisturbDate &doNotDisturbDate)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetDoNotDisturbDate(doNotDisturbDate);
}

ErrCode NotificationHelper::AddDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->AddDoNotDisturbProfiles(profiles);
}

ErrCode NotificationHelper::RemoveDoNotDisturbProfiles(
    const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->RemoveDoNotDisturbProfiles(profiles);
}

ErrCode NotificationHelper::DoesSupportDoNotDisturbMode(bool &doesSupport)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->DoesSupportDoNotDisturbMode(doesSupport);
}

ErrCode NotificationHelper::IsNeedSilentInDoNotDisturbMode(const std::string &phoneNumber, int32_t callerType)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType);
}

ErrCode NotificationHelper::IsDistributedEnabled(bool &enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->IsDistributedEnabled(enabled);
}

ErrCode NotificationHelper::EnableDistributed(const bool enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->EnableDistributed(enabled);
}

ErrCode NotificationHelper::EnableDistributedByBundle(const NotificationBundleOption &bundleOption, const bool enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->EnableDistributedByBundle(bundleOption, enabled);
}

ErrCode NotificationHelper::EnableDistributedSelf(const bool enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->EnableDistributedSelf(enabled);
}

ErrCode NotificationHelper::IsDistributedEnableByBundle(const NotificationBundleOption &bundleOption, bool &enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->IsDistributedEnableByBundle(bundleOption, enabled);
}

ErrCode NotificationHelper::GetDeviceRemindType(NotificationConstant::RemindType &remindType)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetDeviceRemindType(remindType);
}

ErrCode NotificationHelper::PublishContinuousTaskNotification(const NotificationRequest &request)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->PublishContinuousTaskNotification(request);
}

ErrCode NotificationHelper::CancelContinuousTaskNotification(const std::string &label, int32_t notificationId)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->CancelContinuousTaskNotification(label, notificationId);
}

ErrCode NotificationHelper::IsSupportTemplate(const std::string &templateName, bool &support)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->IsSupportTemplate(templateName, support);
}

ErrCode NotificationHelper::IsAllowedNotify(const int32_t &userId, bool &allowed)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->IsAllowedNotify(userId, allowed);
}

ErrCode NotificationHelper::SetNotificationsEnabledForAllBundles(const int32_t &userId, bool enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetNotificationsEnabledForAllBundles(
        userId, enabled);
}

ErrCode NotificationHelper::RemoveNotifications(const int32_t &userId)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->RemoveNotifications(userId);
}

ErrCode NotificationHelper::SetDoNotDisturbDate(const int32_t &userId,
    const NotificationDoNotDisturbDate &doNotDisturbDate)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetDoNotDisturbDate(userId, doNotDisturbDate);
}

ErrCode NotificationHelper::GetDoNotDisturbDate(const int32_t &userId, NotificationDoNotDisturbDate &doNotDisturbDate)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetDoNotDisturbDate(userId, doNotDisturbDate);
}

ErrCode NotificationHelper::SetEnabledForBundleSlot(const NotificationBundleOption &bundleOption,
    const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetEnabledForBundleSlot(bundleOption,
        slotType, enabled, isForceControl);
}

ErrCode NotificationHelper::GetEnabledForBundleSlot(
    const NotificationBundleOption &bundleOption, const NotificationConstant::SlotType &slotType, bool &enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetEnabledForBundleSlot(bundleOption, slotType, enabled);
}

ErrCode NotificationHelper::GetEnabledForBundleSlotSelf(const NotificationConstant::SlotType &slotType, bool &enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetEnabledForBundleSlotSelf(slotType, enabled);
}

ErrCode NotificationHelper::SetSyncNotificationEnabledWithoutApp(const int32_t userId, const bool enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetSyncNotificationEnabledWithoutApp(
        userId, enabled);
}

ErrCode NotificationHelper::GetSyncNotificationEnabledWithoutApp(const int32_t userId, bool &enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetSyncNotificationEnabledWithoutApp(
        userId, enabled);
}

ErrCode NotificationHelper::SetBadgeNumber(int32_t badgeNumber, const std::string &instanceKey)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetBadgeNumber(badgeNumber, instanceKey);
}

ErrCode NotificationHelper::SetBadgeNumberByBundle(const NotificationBundleOption &bundleOption, int32_t badgeNumber)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetBadgeNumberByBundle(bundleOption, badgeNumber);
}

ErrCode NotificationHelper::SetBadgeNumberForDhByBundle(
    const NotificationBundleOption &bundleOption, int32_t badgeNumber)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetBadgeNumberForDhByBundle(bundleOption, badgeNumber);
}

ErrCode NotificationHelper::GetAllNotificationEnabledBundles(std::vector<NotificationBundleOption> &bundleOption)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetAllNotificationEnabledBundles(bundleOption);
}

ErrCode NotificationHelper::GetAllLiveViewEnabledBundles(std::vector<NotificationBundleOption> &bundleOption)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetAllLiveViewEnabledBundles(bundleOption);
}

ErrCode NotificationHelper::GetAllDistribuedEnabledBundles(const std::string& deviceType,
    std::vector<NotificationBundleOption> &bundleOption)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetAllDistribuedEnabledBundles(deviceType, bundleOption);
}

ErrCode NotificationHelper::RegisterPushCallback(const sptr<IRemoteObject> &pushCallback,
    const sptr<NotificationCheckRequest> &notificationCheckRequest)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->RegisterPushCallback(pushCallback,
        notificationCheckRequest);
}

ErrCode NotificationHelper::UnregisterPushCallback()
{
    return DelayedSingleton<AnsNotification>::GetInstance()->UnregisterPushCallback();
}

ErrCode NotificationHelper::SetDistributedEnabledByBundle(const NotificationBundleOption &bundleOption,
    const std::string &deviceType, const bool enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetDistributedEnabledByBundle(bundleOption,
        deviceType, enabled);
}

ErrCode NotificationHelper::SetDistributedBundleOption(const std::vector<DistributedBundleOption> &bundles,
    const std::string &deviceType)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetDistributedBundleOption(bundles, deviceType);
}

ErrCode NotificationHelper::IsDistributedEnabledByBundle(const NotificationBundleOption &bundleOption,
    const std::string &deviceType, bool &enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->IsDistributedEnabledByBundle(bundleOption,
        deviceType, enabled);
}

ErrCode NotificationHelper::SetDistributedEnabled(const std::string &deviceType, const bool &enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetDistributedEnabled(deviceType, enabled);
}

ErrCode NotificationHelper::IsDistributedEnabled(const std::string &deviceType, bool &enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->IsDistributedEnabled(deviceType, enabled);
}

ErrCode NotificationHelper::GetDistributedAbility(int32_t &abilityId)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetDistributedAbility(abilityId);
}

ErrCode NotificationHelper::GetDistributedAuthStatus(
    const std::string &deviceType, const std::string &deviceId, int32_t userId, bool &isAuth)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetDistributedAuthStatus(
        deviceType, deviceId, userId, isAuth);
}

ErrCode NotificationHelper::SetDistributedAuthStatus(
    const std::string &deviceType, const std::string &deviceId, int32_t userId, bool isAuth)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetDistributedAuthStatus(
        deviceType, deviceId, userId, isAuth);
}

ErrCode NotificationHelper::SetSmartReminderEnabled(const std::string &deviceType, const bool enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetSmartReminderEnabled(deviceType, enabled);
}

ErrCode NotificationHelper::IsSmartReminderEnabled(const std::string &deviceType, bool &enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->IsSmartReminderEnabled(deviceType, enabled);
}

ErrCode NotificationHelper::SetSilentReminderEnabled(const NotificationBundleOption &bundleOption, const bool enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetSilentReminderEnabled(bundleOption, enabled);
}

ErrCode NotificationHelper::IsSilentReminderEnabled(const NotificationBundleOption &bundleOption, int32_t &enableStatus)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->IsSilentReminderEnabled(bundleOption, enableStatus);
}

ErrCode NotificationHelper::SetDistributedEnabledBySlot(
    const NotificationConstant::SlotType &slotType, const std::string &deviceType, const bool enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetDistributedEnabledBySlot(slotType, deviceType, enabled);
}

ErrCode NotificationHelper::IsDistributedEnabledBySlot(
    const NotificationConstant::SlotType &slotType, const std::string &deviceType, bool &enabled)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->IsDistributedEnabledBySlot(slotType, deviceType, enabled);
}

ErrCode NotificationHelper::CancelAsBundleWithAgent(const NotificationBundleOption &bundleOption, const int32_t id)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->CancelAsBundleWithAgent(bundleOption, id);
}

ErrCode NotificationHelper::SetAdditionConfig(const std::string &key, const std::string &value)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetAdditionConfig(key, value);
}

ErrCode NotificationHelper::SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status,
    const std::string deviceId)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetTargetDeviceStatus(deviceType, status, deviceId);
}

ErrCode NotificationHelper::SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status,
    const uint32_t controlFlag, const std::string deviceId, int32_t userId)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetTargetDeviceStatus(deviceType, status, controlFlag,
        deviceId, userId);
}

ErrCode NotificationHelper::SetTargetDeviceBundleList(const std::string& deviceType, const std::string& deviceId,
    int operatorType, const std::vector<std::string>& bundleList, const std::vector<std::string>& labelList)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetTargetDeviceBundleList(deviceType, deviceId,
        operatorType, bundleList, labelList);
}

ErrCode NotificationHelper::SetTargetDeviceSwitch(const std::string& deviceType, const std::string& deviceId,
    bool notificaitonEnable, bool liveViewEnable)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetTargetDeviceSwitch(deviceType, deviceId,
        notificaitonEnable, liveViewEnable);
}

ErrCode NotificationHelper::RegisterSwingCallback(const std::function<void(bool, int)> swingCbFunc)
{
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    return DelayedSingleton<AnsNotification>::GetInstance()->RegisterSwingCallback(swingCbFunc);
#else
    return ERR_OK;
#endif
}
ErrCode NotificationHelper::GetDoNotDisturbProfile(int64_t id, sptr<NotificationDoNotDisturbProfile> &profile)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetDoNotDisturbProfile(id, profile);
}

ErrCode NotificationHelper::DistributeOperation(sptr<NotificationOperationInfo>& operationInfo,
    const sptr<IAnsOperationCallback> &callback)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->DistributeOperation(operationInfo, callback);
}

ErrCode NotificationHelper::GetNotificationRequestByHashCode(
    const std::string& hashCode, sptr<NotificationRequest>& notificationRequest)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationRequestByHashCode(
        hashCode, notificationRequest);
}

ErrCode NotificationHelper::ReplyDistributeOperation(const std::string& hashCode, const int32_t result)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->ReplyDistributeOperation(hashCode, result);
}

ErrCode NotificationHelper::UpdateNotificationTimerByUid(const int32_t uid, const bool isPaused)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->UpdateNotificationTimerByUid(uid, isPaused);
}

ErrCode NotificationHelper::AllowUseReminder(const std::string& bundleName, bool& isAllowUseReminder)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->AllowUseReminder(bundleName, isAllowUseReminder);
}

ErrCode NotificationHelper::DisableNotificationFeature(const NotificationDisable &notificationDisable)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->DisableNotificationFeature(notificationDisable);
}

ErrCode NotificationHelper::SetHashCodeRule(const uint32_t type)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetHashCodeRule(type);
}

ErrCode NotificationHelper::GetDistributedDevicelist(std::vector<std::string> &deviceTypes)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetDistributedDevicelist(deviceTypes);
}

ErrCode NotificationHelper::GetMutilDeviceStatus(const std::string &deviceType, const uint32_t status,
    std::string& deviceId, int32_t& userId)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetMutilDeviceStatus(deviceType, status, deviceId, userId);
}

ErrCode NotificationHelper::GetTargetDeviceBundleList(const std::string& deviceType, const std::string& deviceId,
    std::vector<std::string>& bundleList, std::vector<std::string>& labelList)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetTargetDeviceBundleList(deviceType, deviceId,
        bundleList, labelList);
}

ErrCode NotificationHelper::SetDefaultSlotForBundle(const NotificationBundleOption& bundleOption,
    const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetDefaultSlotForBundle(bundleOption,
        slotType, enabled, isForceControl);
}

ErrCode NotificationHelper::SetCheckConfig(int32_t response, const std::string& requestId,
    const std::string& key, const std::string& value)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->SetCheckConfig(response, requestId, key, value);
}

ErrCode NotificationHelper::GetLiveViewConfig(const std::vector<std::string>& bundleList)
{
    return DelayedSingleton<AnsNotification>::GetInstance()->GetLiveViewConfig(bundleList);
}
}  // namespace Notification
}  // namespace OHOS
