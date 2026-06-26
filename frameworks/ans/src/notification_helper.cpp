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
#include "ans_service_errors.h"
#include "singleton.h"
#include <memory>

namespace OHOS {
namespace Notification {
ErrCode NotificationHelper::AddNotificationSlot(const NotificationSlot &slot)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->AddNotificationSlot(slot);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::AddSlotByType(const NotificationConstant::SlotType &slotType)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->AddSlotByType(slotType);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::AddNotificationSlots(const std::vector<NotificationSlot> &slots)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->AddNotificationSlots(slots);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RemoveNotificationSlot(const NotificationConstant::SlotType &slotType)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RemoveNotificationSlot(slotType);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RemoveAllSlots()
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RemoveAllSlots();
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetNotificationSlot(
    const NotificationConstant::SlotType &slotType, sptr<NotificationSlot> &slot)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationSlot(slotType, slot);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetNotificationSlots(std::vector<sptr<NotificationSlot>> &slots)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationSlots(slots);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetNotificationSlotNumAsBundle(const NotificationBundleOption &bundleOption, uint64_t &num)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationSlotNumAsBundle(bundleOption, num);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetNotificationSlotFlagsAsBundle(const NotificationBundleOption &bundleOption,
    uint32_t &slotFlags)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationSlotFlagsAsBundle(bundleOption, slotFlags);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetNotificationSettings(uint32_t &slotFlags)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationSettings(slotFlags);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetNotificationSlotFlagsAsBundle(const NotificationBundleOption &bundleOption,
    uint32_t slotFlags)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetNotificationSlotFlagsAsBundle(bundleOption, slotFlags);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::PublishNotification(const NotificationRequest &request,
    const std::string &instanceKey)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->PublishNotification(
            request, instanceKey);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::PublishNotification(const std::string &label,
    const NotificationRequest &request, const std::string &instanceKey)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->PublishNotification(
            label, request, instanceKey);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::PublishNotificationForIndirectProxy(const NotificationRequest &request)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->PublishNotificationForIndirectProxy(request);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::CancelNotification(int32_t notificationId, const std::string &instanceKey)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->CancelNotification(
            notificationId, instanceKey);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::CancelNotification(const std::string &label, int32_t notificationId,
    const std::string &instanceKey)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->CancelNotification(
            label, notificationId, instanceKey);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::CancelAllNotifications(const std::string &instanceKey)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->CancelAllNotifications(instanceKey);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::CancelAsBundle(
    int32_t notificationId, const std::string &representativeBundle, int32_t userId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->CancelAsBundle(
            notificationId, representativeBundle, userId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::CancelAsBundle(
    const NotificationBundleOption &bundleOption, int32_t notificationId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->CancelAsBundle(
            bundleOption, notificationId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetActiveNotificationNums(uint64_t &num)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetActiveNotificationNums(num);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetActiveNotifications(
    std::vector<sptr<NotificationRequest>> &request, const std::string &instanceKey)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetActiveNotifications(
            request, instanceKey);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::CanPublishNotificationAsBundle(const std::string &representativeBundle, bool &canPublish)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->CanPublishNotificationAsBundle(
            representativeBundle, canPublish);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::PublishNotificationAsBundle(
    const std::string &representativeBundle, const NotificationRequest &request)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->PublishNotificationAsBundle(representativeBundle, request);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetNotificationBadgeNum()
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetNotificationBadgeNum();
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetNotificationBadgeNum(int32_t num)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetNotificationBadgeNum(num);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsAllowedNotify(bool &allowed)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsAllowedNotify(allowed);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsAllowedNotifySelf(bool &allowed)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsAllowedNotifySelf(allowed);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::CanPopEnableNotificationDialog(sptr<AnsDialogHostClient> &hostClient,
    bool &canPop, std::string &bundleName)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->CanPopEnableNotificationDialog(
            hostClient, canPop, bundleName);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RemoveEnableNotificationDialog()
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RemoveEnableNotificationDialog();
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RequestEnableNotification(std::string &deviceId,
    sptr<AnsDialogHostClient> &hostClient,
    sptr<IRemoteObject> &callerToken)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RequestEnableNotification(
            deviceId, hostClient, callerToken);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RequestEnableNotification(const std::string bundleName, const int32_t uid)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RequestEnableNotification(
            bundleName, uid);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::HasNotificationPolicyAccessPermission(bool &hasPermission)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->HasNotificationPolicyAccessPermission(hasPermission);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetBundleImportance(NotificationSlot::NotificationLevel &importance)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetBundleImportance(importance);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SubscribeNotification(const NotificationSubscriber &subscriber)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SubscribeNotification(subscriber);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SubscribeNotification(subscriber, nullptr);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SubscribeNotificationSelf(const NotificationSubscriber &subscriber)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SubscribeNotificationSelf(subscriber);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SubscribeNotificationSelf(const std::shared_ptr<NotificationSubscriber> &subscriber)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SubscribeNotificationSelf(subscriber);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SubscribeLocalLiveViewNotification(const NotificationLocalLiveViewSubscriber &subscriber,
    const bool isNative)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SubscribeLocalLiveViewNotification(subscriber, isNative);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SubscribeNotificationV26(const std::shared_ptr<NotificationSubscriber> &subscriber,
    const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SubscribeNotificationV26(subscriber, subscribeInfo);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SubscribeNotification(
    const NotificationSubscriber &subscriber, const NotificationSubscribeInfo &subscribeInfo)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SubscribeNotification(subscriber, subscribeInfo);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber,
    const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SubscribeNotification(subscriber, subscribeInfo);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::UnSubscribeNotification(NotificationSubscriber &subscriber)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->UnSubscribeNotification(subscriber);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::UnSubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->UnSubscribeNotification(subscriber);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::UnSubscribeNotification(
    NotificationSubscriber &subscriber, NotificationSubscribeInfo subscribeInfo)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->UnSubscribeNotification(subscriber, subscribeInfo);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::UnSubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber,
    const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->UnSubscribeNotification(subscriber, subscribeInfo);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::TriggerLocalLiveView(const NotificationBundleOption &bundleOption,
    const int32_t notificationId, const NotificationButtonOption &buttonOption)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->TriggerLocalLiveView(
            bundleOption, notificationId, buttonOption);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RemoveNotification(const std::string &key, int32_t removeReason)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RemoveNotification(key, removeReason);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RemoveNotification(const NotificationBundleOption &bundleOption,
    const int32_t notificationId, const std::string &label, int32_t removeReason)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RemoveNotification(bundleOption,
            notificationId, label, removeReason);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RemoveAllNotifications(const NotificationBundleOption &bundleOption)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RemoveAllNotifications(bundleOption);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RemoveNotifications(const std::vector<std::string> hashcodes, int32_t removeReason)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RemoveNotifications(hashcodes, removeReason);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RemoveNotificationsByBundle(const NotificationBundleOption &bundleOption)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RemoveNotificationsByBundle(bundleOption);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RemoveNotifications()
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RemoveNotifications();
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RemoveDistributedNotifications(const std::vector<std::string>& hashcodes,
    const NotificationConstant::SlotType& slotType,
    const NotificationConstant::DistributedDeleteType& deleteType,
    const int32_t removeReason, const std::string& deviceId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RemoveDistributedNotifications(
            hashcodes, slotType, deleteType, removeReason, deviceId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetNotificationSlotsForBundle(
    const NotificationBundleOption &bundleOption, std::vector<sptr<NotificationSlot>> &slots)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationSlotsForBundle(bundleOption, slots);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetNotificationSlotForBundle(
    const NotificationBundleOption &bundleOption, const NotificationConstant::SlotType &slotType,
    sptr<NotificationSlot> &slot)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationSlotForBundle(bundleOption, slotType, slot);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::UpdateNotificationSlots(
    const NotificationBundleOption &bundleOption, const std::vector<sptr<NotificationSlot>> &slots)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->UpdateNotificationSlots(bundleOption, slots);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetAllActiveNotifications(std::vector<sptr<Notification>> &notification)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetAllActiveNotifications(notification);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetAllNotificationsBySlotType(std::vector<sptr<Notification>> &notifications,
    const NotificationConstant::SlotType slotType)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetAllNotificationsBySlotType(notifications, slotType);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetAllNotificationsBySlotType(std::vector<sptr<Notification>> &notifications,
    const NotificationConstant::SlotType slotType, int32_t userId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetAllNotificationsBySlotType(
            notifications, slotType, userId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetAllActiveNotifications(
    const std::vector<std::string> key, std::vector<sptr<Notification>> &notification)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetAllActiveNotifications(key, notification);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetActiveNotificationByFilter(
    const LiveViewFilter &filter, sptr<NotificationRequest> &request)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetActiveNotificationByFilter(filter, request);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetNotificationParameters(int32_t notificationId, const std::string &label,
    sptr<NotificationParameters> &parameters)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationParameters(
            notificationId, label, parameters);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsAllowedNotify(const NotificationBundleOption &bundleOption, bool &allowed)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsAllowedNotify(bundleOption, allowed);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetNotificationsEnabledForAllBundles(const std::string &deviceId, bool enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetNotificationsEnabledForAllBundles(deviceId, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetNotificationsEnabledForDefaultBundle(const std::string &deviceId, bool enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetNotificationsEnabledForDefaultBundle(deviceId, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetNotificationsEnabledForSpecifiedBundle(
    const NotificationBundleOption &bundleOption, std::string &deviceId, bool enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetNotificationsEnabledForSpecifiedBundle(
            bundleOption, deviceId, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetShowBadgeEnabledForBundle(const NotificationBundleOption &bundleOption, bool enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetShowBadgeEnabledForBundle(bundleOption, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetShowBadgeEnabledForBundles(
    const std::vector<std::pair<NotificationBundleOption, bool>> &params)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetShowBadgeEnabledForBundles(params);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetShowBadgeEnabledForBundle(const NotificationBundleOption &bundleOption, bool &enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetShowBadgeEnabledForBundle(bundleOption, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetShowBadgeEnabledForBundles(const std::vector<NotificationBundleOption> &bundleOptions,
    std::map<sptr<NotificationBundleOption>, bool> &bundleEnable)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetShowBadgeEnabledForBundles(
            bundleOptions, bundleEnable);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetShowBadgeEnabled(bool &enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetShowBadgeEnabled(enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::CancelGroup(const std::string &groupName, const std::string &instanceKey)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->CancelGroup(
            groupName, instanceKey);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RemoveGroupByBundle(
    const NotificationBundleOption &bundleOption, const std::string &groupName)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RemoveGroupByBundle(bundleOption, groupName);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetDoNotDisturbDate(const NotificationDoNotDisturbDate &doNotDisturbDate)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetDoNotDisturbDate(doNotDisturbDate);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetDoNotDisturbDate(NotificationDoNotDisturbDate &doNotDisturbDate)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetDoNotDisturbDate(doNotDisturbDate);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::AddDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->AddDoNotDisturbProfiles(profiles);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::AddDoNotDisturbProfiles(
    const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles, const int32_t userId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->AddDoNotDisturbProfiles(profiles, userId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RemoveDoNotDisturbProfiles(
    const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RemoveDoNotDisturbProfiles(profiles);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RemoveDoNotDisturbProfiles(
    const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles, const int32_t userId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RemoveDoNotDisturbProfiles(profiles, userId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::DoesSupportDoNotDisturbMode(bool &doesSupport)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->DoesSupportDoNotDisturbMode(doesSupport);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsNeedSilentInDoNotDisturbMode(const std::string &phoneNumber, int32_t callerType)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsNeedSilentInDoNotDisturbMode(
    const std::string &phoneNumber, int32_t callerType, const int32_t userId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsNeedSilentInDoNotDisturbMode(
            phoneNumber, callerType, userId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsDistributedEnabled(bool &enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsDistributedEnabled(enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::EnableDistributed(const bool enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->EnableDistributed(enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::EnableDistributedByBundle(const NotificationBundleOption &bundleOption, const bool enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->EnableDistributedByBundle(bundleOption, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::EnableDistributedSelf(const bool enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->EnableDistributedSelf(enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsDistributedEnableByBundle(const NotificationBundleOption &bundleOption, bool &enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsDistributedEnableByBundle(bundleOption, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetDeviceRemindType(NotificationConstant::RemindType &remindType)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetDeviceRemindType(remindType);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::PublishContinuousTaskNotification(const NotificationRequest &request)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->PublishContinuousTaskNotification(request);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::CancelContinuousTaskNotification(const std::string &label, int32_t notificationId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->CancelContinuousTaskNotification(label, notificationId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsSupportTemplate(const std::string &templateName, bool &support)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsSupportTemplate(templateName, support);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsAllowedNotify(const int32_t &userId, bool &allowed)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsAllowedNotify(userId, allowed);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetNotificationsEnabledForAllBundles(const int32_t &userId, bool enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetNotificationsEnabledForAllBundles(
            userId, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RemoveNotifications(const int32_t &userId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RemoveNotifications(userId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetDoNotDisturbDate(const int32_t &userId,
    const NotificationDoNotDisturbDate &doNotDisturbDate)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetDoNotDisturbDate(userId, doNotDisturbDate);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetDoNotDisturbDate(const int32_t &userId, NotificationDoNotDisturbDate &doNotDisturbDate)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetDoNotDisturbDate(userId, doNotDisturbDate);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetEnabledForBundleSlot(const NotificationBundleOption &bundleOption,
    const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetEnabledForBundleSlot(bundleOption,
            slotType, enabled, isForceControl);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetEnabledForBundleSlot(
    const NotificationBundleOption &bundleOption, const NotificationConstant::SlotType &slotType, bool &enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetEnabledForBundleSlot(bundleOption, slotType, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetEnabledForBundleSlotSelf(const NotificationConstant::SlotType &slotType, bool &enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetEnabledForBundleSlotSelf(slotType, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetSyncNotificationEnabledWithoutApp(const int32_t userId, const bool enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetSyncNotificationEnabledWithoutApp(
            userId, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetSyncNotificationEnabledWithoutApp(const int32_t userId, bool &enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetSyncNotificationEnabledWithoutApp(
            userId, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetBadgeNumber(int32_t badgeNumber, const std::string &instanceKey)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetBadgeNumber(badgeNumber, instanceKey);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetBadgeNumberByBundle(const NotificationBundleOption &bundleOption, int32_t badgeNumber)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetBadgeNumberByBundle(bundleOption, badgeNumber);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetBadgeNumberForDhByBundle(
    const NotificationBundleOption &bundleOption, int32_t badgeNumber)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetBadgeNumberForDhByBundle(bundleOption, badgeNumber);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetAllNotificationEnabledBundles(std::vector<NotificationBundleOption> &bundleOption)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetAllNotificationEnabledBundles(bundleOption);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetAllNotificationEnabledBundles(
    std::vector<NotificationBundleOption> &bundleOption, const int32_t userId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetAllNotificationEnabledBundles(bundleOption, userId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetAllLiveViewEnabledBundles(std::vector<NotificationBundleOption> &bundleOption)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetAllLiveViewEnabledBundles(bundleOption);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetAllLiveViewEnabledBundles(
    std::vector<NotificationBundleOption> &bundleOption, const int32_t userId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetAllLiveViewEnabledBundles(bundleOption, userId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetAllDistribuedEnabledBundles(const std::string& deviceType,
    std::vector<NotificationBundleOption> &bundleOption)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetAllDistribuedEnabledBundles(deviceType, bundleOption);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RegisterPushCallback(const sptr<IRemoteObject> &pushCallback,
    const sptr<NotificationCheckRequest> &notificationCheckRequest)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RegisterPushCallback(pushCallback,
            notificationCheckRequest);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::UnregisterPushCallback()
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->UnregisterPushCallback();
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetDistributedEnabledByBundle(const NotificationBundleOption &bundleOption,
    const std::string &deviceType, const bool enabled, const bool isNotification)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetDistributedEnabledByBundle(bundleOption,
            deviceType, enabled, isNotification);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetDistributedBundleListByType(const bool isNotification,
    std::vector<DistributedBundleOption> &enableList)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetDistributedBundleListByType(isNotification, enableList);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetDistributedBundleInfo(const std::vector<NotificationBundleOption>& bundleOption,
    std::vector<DistributedNotificationBundleInfo>& bundleInfoList)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetDistributedBundleInfo(bundleOption,
            bundleInfoList);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetDistributedBundleOption(const std::vector<DistributedBundleOption> &bundles,
    const std::string &deviceType)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetDistributedBundleOption(bundles, deviceType);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsDistributedEnabledByBundle(const NotificationBundleOption &bundleOption,
    const std::string &deviceType, bool isNotification, int32_t &enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsDistributedEnabledByBundle(bundleOption,
            deviceType, isNotification, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetDistributedEnabled(const std::string &deviceType, const bool &enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetDistributedEnabled(deviceType, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsDistributedEnabled(const std::string &deviceType, bool &enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsDistributedEnabled(deviceType, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetDistributedAbility(int32_t &abilityId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetDistributedAbility(abilityId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetDistributedAuthStatus(
    const std::string &deviceType, const std::string &deviceId, int32_t userId, bool &isAuth)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetDistributedAuthStatus(
            deviceType, deviceId, userId, isAuth);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetDistributedAuthStatus(
    const std::string &deviceType, const std::string &deviceId, int32_t userId, bool isAuth)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetDistributedAuthStatus(
            deviceType, deviceId, userId, isAuth);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::UpdateDistributedDeviceList(const std::string &deviceType)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->UpdateDistributedDeviceList(deviceType);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetSmartReminderEnabled(const std::string &deviceType, const bool enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetSmartReminderEnabled(deviceType, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsSmartReminderEnabled(const std::string &deviceType, bool &enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsSmartReminderEnabled(deviceType, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetSilentReminderEnabled(const NotificationBundleOption &bundleOption, const bool enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetSilentReminderEnabled(bundleOption, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsSilentReminderEnabled(const NotificationBundleOption &bundleOption, int32_t &enableStatus)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsSilentReminderEnabled(bundleOption, enableStatus);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetDistributedEnabledBySlot(
    const NotificationConstant::SlotType &slotType, const std::string &deviceType, const bool enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetDistributedEnabledBySlot(slotType, deviceType, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsDistributedEnabledBySlot(
    const NotificationConstant::SlotType &slotType, const std::string &deviceType, bool &enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsDistributedEnabledBySlot(slotType, deviceType, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetBundlePriorityConfig(
    const NotificationBundleOption &bundleOption, const std::string &value)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetBundlePriorityConfig(bundleOption, value);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetBundlePriorityConfig(const NotificationBundleOption &bundleOption, std::string &value)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetBundlePriorityConfig(bundleOption, value);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::CancelAsBundleWithAgent(const NotificationBundleOption &bundleOption, const int32_t id)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->CancelAsBundleWithAgent(bundleOption, id);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetAdditionConfig(const std::string &key, const std::string &value)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetAdditionConfig(key, value);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::UpdateInnerConfig(const std::string &configKey, const std::string &configValue)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->UpdateInnerConfig(configKey, configValue);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetPriorityEnabled(const bool enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetPriorityEnabled(enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetPriorityEnabledByBundle(
    const NotificationBundleOption &bundleOption, const NotificationConstant::PriorityEnableStatus enableStatus)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetPriorityEnabledByBundle(bundleOption, enableStatus);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsPriorityEnabled(bool &enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsPriorityEnabled(enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsPriorityEnabledByBundle(
    const NotificationBundleOption &bundleOption, NotificationConstant::PriorityEnableStatus &enableStatus)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsPriorityEnabledByBundle(bundleOption, enableStatus);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetPriorityEnabledByBundles(const std::vector<NotificationBundleOption> &bundleOptions,
    std::map<sptr<NotificationBundleOption>, bool> &priorityEnable)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetPriorityEnabledByBundles(
            bundleOptions, priorityEnable);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetPriorityEnabledByBundles(
    const std::map<sptr<NotificationBundleOption>, bool> &priorityEnable)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetPriorityEnabledByBundles(priorityEnable);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsPriorityIntelligentEnabled(bool &enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsPriorityIntelligentEnabled(enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetPriorityIntelligentEnabled(const bool enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetPriorityIntelligentEnabled(enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetPriorityStrategyByBundles(const std::vector<NotificationBundleOption> &bundleOptions,
    std::map<sptr<NotificationBundleOption>, int64_t> &strategies)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetPriorityStrategyByBundles(
            bundleOptions, strategies);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetPriorityStrategyByBundles(
    const std::map<sptr<NotificationBundleOption>, int64_t> &strategies)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetPriorityStrategyByBundles(strategies);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::TriggerUpdatePriorityType(const NotificationRequest &request)
{
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->TriggerUpdatePriorityType(request);
    return InnerErrorToNative(result);
#else
    return ERR_OK;
#endif
}

ErrCode NotificationHelper::TriggerUpdateAiExtNotification(const sptr<NotificationRequest> &request,
    const sptr<NotificationClassification> &notificationClassification)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->TriggerUpdateAiExtNotification(
            request, notificationClassification);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status,
    const std::string deviceId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetTargetDeviceStatus(deviceType, status, deviceId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status,
    const uint32_t controlFlag, const std::string deviceId, int32_t userId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetTargetDeviceStatus(deviceType, status, controlFlag,
            deviceId, userId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetTargetDeviceBundleList(const std::string& deviceType, const std::string& deviceId,
    int operatorType, const std::vector<std::string>& bundleList, const std::vector<std::string>& labelList)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetTargetDeviceBundleList(deviceType, deviceId,
            operatorType, bundleList, labelList);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetDeviceDistributedBundleList(DistributedBundleChangeType type,
    const std::vector<NotificationDistributedBundle>& bundles)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetDeviceDistributedBundleList(type, bundles);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetTargetDeviceAbility(const std::string& deviceType, const int32_t ability)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetTargetDeviceAbility(deviceType, ability);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetLocalDistributedBundleList(const std::string& deviceType,
    std::vector<NotificationDistributedBundle>& bundles)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetLocalDistributedBundleList(deviceType, bundles);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetTargetDeviceSwitch(const std::string& deviceType, const std::string& deviceId,
    bool notificaitonEnable, bool liveViewEnable)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetTargetDeviceSwitch(deviceType, deviceId,
            notificaitonEnable, liveViewEnable);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RegisterSwingCallback(const std::function<void(bool, int)> swingCbFunc)
{
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RegisterSwingCallback(swingCbFunc);
    return InnerErrorToNative(result);
#else
    return ERR_OK;
#endif
}
ErrCode NotificationHelper::GetDoNotDisturbProfile(int64_t id, sptr<NotificationDoNotDisturbProfile> &profile)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetDoNotDisturbProfile(id, profile);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetDoNotDisturbProfile(
    int64_t id, sptr<NotificationDoNotDisturbProfile> &profile, const int32_t userId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetDoNotDisturbProfile(id, profile, userId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::DistributeOperation(sptr<NotificationOperationInfo>& operationInfo,
    const sptr<IAnsOperationCallback> &callback)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->DistributeOperation(operationInfo, callback);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetNotificationRequestByHashCode(
    const std::string& hashCode, sptr<NotificationRequest>& notificationRequest)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationRequestByHashCode(
            hashCode, notificationRequest);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::ReplyDistributeOperation(const std::string& hashCode, const int32_t result)
{
    InnerErrorCode svcResult =
        DelayedSingleton<AnsNotification>::GetInstance()->ReplyDistributeOperation(hashCode, result);
    return InnerErrorToNative(svcResult);
}

ErrCode NotificationHelper::UpdateNotificationTimerByUid(const int32_t uid, const bool isPaused)
{
    InnerErrorCode svcResult =
        DelayedSingleton<AnsNotification>::GetInstance()->UpdateNotificationTimerByUid(uid, isPaused);
    return InnerErrorToNative(svcResult);
}

ErrCode NotificationHelper::AllowUseReminder(const std::string& bundleName, bool& isAllowUseReminder)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->AllowUseReminder(bundleName, isAllowUseReminder);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::AllowUseReminder(
    const std::string& bundleName, const int32_t userId, bool& isAllowUseReminder)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->AllowUseReminder(bundleName, userId, isAllowUseReminder);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::DisableNotificationFeature(const NotificationDisable &notificationDisable)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->DisableNotificationFeature(notificationDisable);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetHashCodeRule(const uint32_t type)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetHashCodeRule(type);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetHashCodeRule(const uint32_t type, const int32_t userId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetHashCodeRule(type, userId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetDistributedDevicelist(std::vector<std::string> &deviceTypes)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetDistributedDevicelist(deviceTypes);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetMutilDeviceStatus(const std::string &deviceType, const uint32_t status,
    std::string& deviceId, int32_t& userId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetMutilDeviceStatus(deviceType, status, deviceId, userId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetTargetDeviceBundleList(const std::string& deviceType, const std::string& deviceId,
    std::vector<std::string>& bundleList, std::vector<std::string>& labelList)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetTargetDeviceBundleList(deviceType, deviceId,
            bundleList, labelList);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetDefaultSlotForBundle(const NotificationBundleOption& bundleOption,
    const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetDefaultSlotForBundle(bundleOption,
            slotType, enabled, isForceControl);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetCheckConfig(int32_t response, const std::string& requestId,
    const std::string& key, const std::string& value)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetCheckConfig(response, requestId, key, value);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetLiveViewConfig(const std::vector<std::string>& bundleList)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetLiveViewConfig(bundleList);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::NotificationExtensionSubscribe(
    const std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->NotificationExtensionSubscribe(infos);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::NotificationExtensionUnsubscribe()
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->NotificationExtensionUnsubscribe();
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetSubscribeInfo(std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetSubscribeInfo(infos);
    return InnerErrorToNative(result);
}


ErrCode NotificationHelper::SetRingtoneInfoByBundle(const NotificationBundleOption &bundle,
    const NotificationRingtoneInfo &ringtoneInfo)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetRingtoneInfoByBundle(bundle, ringtoneInfo);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetRingtoneInfoByBundle(const NotificationBundleOption &bundle,
    NotificationRingtoneInfo &ringtoneInfo)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetRingtoneInfoByBundle(bundle, ringtoneInfo);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsUserGranted(bool& enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsUserGranted(enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetUserGrantedState(const NotificationBundleOption& targetBundle, bool& enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetUserGrantedState(targetBundle, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetUserGrantedState(const NotificationBundleOption& targetBundle, bool enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetUserGrantedState(targetBundle, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetUserGrantedEnabledBundles(
    const NotificationBundleOption& targetBundle, std::vector<sptr<NotificationBundleOption>>& enabledBundles)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetUserGrantedEnabledBundles(targetBundle, enabledBundles);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetUserGrantedEnabledBundlesForSelf(std::vector<sptr<NotificationBundleOption>>& bundles)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetUserGrantedEnabledBundlesForSelf(bundles);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetUserGrantedBundleState(const NotificationBundleOption& targetBundle,
    const std::vector<sptr<NotificationBundleOption>>& enabledBundles, bool enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetUserGrantedBundleState(
            targetBundle, enabledBundles, enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetReminderInfoByBundles(
    const std::vector<NotificationBundleOption> &bundles, std::vector<NotificationReminderInfo> &reminderInfo)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetReminderInfoByBundles(bundles, reminderInfo);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetReminderInfoByBundles(const std::vector<NotificationReminderInfo> &reminderInfo)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetReminderInfoByBundles(reminderInfo);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetGeofenceEnabled(bool enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetGeofenceEnabled(enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsGeofenceEnabled(bool &enabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsGeofenceEnabled(enabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::ClearDelayNotification(const std::vector<std::string> &triggerKeys,
    const std::vector<int32_t> &userIds)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->ClearDelayNotification(triggerKeys, userIds);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::PublishDelayedNotification(const std::string &triggerKey, int32_t userId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->PublishDelayedNotification(triggerKey, userId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::ProxyForUnaware(const std::vector<int32_t>& uidList, bool isProxy)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->ProxyForUnaware(uidList, isProxy);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetAllSubscriptionBundles(std::vector<sptr<NotificationBundleOption>>& bundles)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetAllSubscriptionBundles(bundles);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::CanOpenSubscribeSettings()
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->CanOpenSubscribeSettings();
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetBadgeNumber(int32_t &badgeNumber)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetBadgeNumber(badgeNumber);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::RegisterBadgeQueryCallback(const std::shared_ptr<IBadgeQueryCallback> &badgeQueryCallback)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->RegisterBadgeQueryCallback(badgeQueryCallback);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::UnRegisterBadgeQueryCallback(const std::shared_ptr<IBadgeQueryCallback> &badgeQueryCallback)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->UnRegisterBadgeQueryCallback(badgeQueryCallback);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsDoNotDisturbEnabled(int32_t userId, bool& isEnabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsDoNotDisturbEnabled(userId, isEnabled);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::IsNotifyAllowedInDoNotDisturb(int32_t userId, bool& isAllowed)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->IsNotifyAllowedInDoNotDisturb(userId, isAllowed);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetNotificationSwitch(
    const NotificationBundleOption &bundleOption, NotificationConstant::SWITCH_STATE &state)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationSwitch(bundleOption, state);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetStatisticsByBundle(const std::vector<NotificationBundleOption> &bundleOptions,
    std::vector<NotificationStatistics> &statistics)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetStatisticsByBundle(bundleOptions, statistics);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SnoozeNotification(const std::string &hashCode, const int64_t delayTime)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SnoozeNotification(hashCode, delayTime);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::SetNotificationSwitch(const std::string &switchName, bool switchState, int32_t userId)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->SetNotificationSwitch(switchName, switchState, userId);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetNotificationSwitch(
    const std::string &switchName, int32_t userId, NotificationConstant::SWITCH_STATE &switchState)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetNotificationSwitch(switchName, userId, switchState);
    return InnerErrorToNative(result);
}

ErrCode NotificationHelper::GetEnabledForBundleSlots(const std::vector<NotificationBundleOption> &bundleOptions,
    const NotificationConstant::SlotType &slotType,
    std::map<sptr<NotificationBundleOption>, bool> &slotEnabled)
{
    InnerErrorCode result =
        DelayedSingleton<AnsNotification>::GetInstance()->GetEnabledForBundleSlots(
            bundleOptions, slotType, slotEnabled);
    return InnerErrorToNative(result);
}
}  // namespace Notification
}  // namespace OHOS
