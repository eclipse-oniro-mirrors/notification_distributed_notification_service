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

#include "ans_manager_stub.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "message_option.h"
#include "message_parcel.h"
#include "parcel.h"
#include "reminder_request_alarm.h"
#include "reminder_request_calendar.h"
#include "reminder_request_timer.h"

namespace OHOS {
namespace Notification {
ErrCode AnsManagerStub::Publish(const std::string &label, const sptr<NotificationRequest> &notification)
{
    ANS_LOGE("AnsManagerStub::Publish called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetNotificationRequestByHashCode(
    const std::string& hashCode, sptr<NotificationRequest>& notificationRequest)
{
    ANS_LOGE("AnsManagerStub::Publish called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::PublishNotificationForIndirectProxy(const sptr<NotificationRequest> &notification)
{
    ANS_LOGE("AnsManagerStub::PublishNotificationForIndirectProxy called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::Cancel(int notificationId, const std::string &label, const std::string &instanceKey)
{
    ANS_LOGE("AnsManagerStub::Cancel called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::CancelAll(const std::string &instanceKey)
{
    ANS_LOGE("AnsManagerStub::CancelAll called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::CancelAsBundle(int32_t notificationId, const std::string &representativeBundle, int32_t userId)
{
    ANS_LOGE("AnsManagerStub::CancelAsBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::CancelAsBundle(const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId)
{
    ANS_LOGE("AnsManagerStub::CancelAsBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::CancelAsBundle(
    const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId, int32_t userId)
{
    ANS_LOGE("AnsManagerStub::CancelAsBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::AddSlotByType(NotificationConstant::SlotType slotType)
{
    ANS_LOGE("AnsManagerStub::AddSlotByType called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::AddSlots(const std::vector<sptr<NotificationSlot>> &slots)
{
    ANS_LOGE("AnsManagerStub::AddSlots called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::RemoveSlotByType(const NotificationConstant::SlotType &slotType)
{
    ANS_LOGE("AnsManagerStub::RemoveSlotByType called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::RemoveAllSlots()
{
    ANS_LOGE("AnsManagerStub::RemoveAllSlots called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetSlotByType(const NotificationConstant::SlotType &slotType, sptr<NotificationSlot> &slot)
{
    ANS_LOGE("AnsManagerStub::GetSlotByType called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetSlots(std::vector<sptr<NotificationSlot>> &slots)
{
    ANS_LOGE("AnsManagerStub::GetSlots called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetSlotNumAsBundle(const sptr<NotificationBundleOption> &bundleOption, uint64_t &num)
{
    ANS_LOGE("AnsManagerStub::GetSlotNumAsBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetActiveNotifications(
    std::vector<sptr<NotificationRequest>> &notifications, const std::string &instanceKey)
{
    ANS_LOGE("AnsManagerStub::GetActiveNotifications called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetActiveNotificationNums(uint64_t &num)
{
    ANS_LOGE("AnsManagerStub::GetActiveNotificationNums called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetAllActiveNotifications(std::vector<sptr<Notification>> &notifications)
{
    ANS_LOGE("AnsManagerStub::GetAllActiveNotifications called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetSpecialActiveNotifications(
    const std::vector<std::string> &key, std::vector<sptr<Notification>> &notifications)
{
    ANS_LOGE("AnsManagerStub::GetSpecialActiveNotifications called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetActiveNotificationByFilter(
    const sptr<NotificationBundleOption> &bundleOption, const int32_t notificationId, const std::string &label,
    std::vector<std::string> extraInfoKeys, sptr<NotificationRequest> &request)
{
    ANS_LOGE("AnsManagerStub::GetActiveNotificationByFilter called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::CanPublishAsBundle(const std::string &representativeBundle, bool &canPublish)
{
    ANS_LOGE("AnsManagerStub::CanPublishAsBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::PublishAsBundle(
    const sptr<NotificationRequest> notification, const std::string &representativeBundle)
{
    ANS_LOGE("AnsManagerStub::PublishAsBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetNotificationBadgeNum(int num)
{
    ANS_LOGE("AnsManagerStub::SetNotificationBadgeNum called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetBundleImportance(int &importance)
{
    ANS_LOGE("AnsManagerStub::GetBundleImportance called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetSlotFlagsAsBundle(const sptr<NotificationBundleOption> &bundleOption, uint32_t &slotFlags)
{
    ANS_LOGE("AnsManagerStub::GetSlotFlagsAsBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetSlotFlagsAsBundle(const sptr<NotificationBundleOption> &bundleOption, uint32_t slotFlags)
{
    ANS_LOGE("AnsManagerStub::SetSlotFlagsAsBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::HasNotificationPolicyAccessPermission(bool &granted)
{
    ANS_LOGE("AnsManagerStub::HasNotificationPolicyAccessPermission called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::TriggerLocalLiveView(const sptr<NotificationBundleOption> &bundleOption,
    const int32_t notificationId, const sptr<NotificationButtonOption> &buttonOption)
{
    ANS_LOGE("AnsManagerStub::TriggerLocalLiveView called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::RemoveNotification(const sptr<NotificationBundleOption> &bundleOption,
    int notificationId, const std::string &label, int32_t removeReason)
{
    ANS_LOGE("AnsManagerStub::RemoveNotification called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::RemoveAllNotifications(const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGE("AnsManagerStub::RemoveAllNotifications called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::RemoveNotifications(const std::vector<std::string> &keys, int32_t removeReason)
{
    ANS_LOGD("called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::Delete(const std::string &key, int32_t removeReason)
{
    ANS_LOGE("AnsManagerStub::Delete called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::DeleteByBundle(const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGE("AnsManagerStub::DeleteByBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::DeleteAll()
{
    ANS_LOGE("AnsManagerStub::DeleteAll called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetSlotsByBundle(
    const sptr<NotificationBundleOption> &bundleOption, std::vector<sptr<NotificationSlot>> &slots)
{
    ANS_LOGE("AnsManagerStub::GetSlotsByBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetSlotByBundle(
    const sptr<NotificationBundleOption> &bundleOption, const NotificationConstant::SlotType &slotType,
    sptr<NotificationSlot> &slot)
{
    ANS_LOGE("AnsManagerStub::GetSlotByBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::UpdateSlots(
    const sptr<NotificationBundleOption> &bundleOption, const std::vector<sptr<NotificationSlot>> &slots)
{
    ANS_LOGE("AnsManagerStub::UpdateSlots called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::RequestEnableNotification(const std::string &deviceId,
    const sptr<IAnsDialogCallback> &callback,
    const sptr<IRemoteObject> &callerToken)
{
    ANS_LOGE("AnsManagerStub::RequestEnableNotification called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::RequestEnableNotification(const std::string bundleName, const int32_t uid)
{
    ANS_LOGE("AnsManagerStub::RequestEnableNotification called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetNotificationsEnabledForBundle(const std::string &bundle, bool enabled)
{
    ANS_LOGE("AnsManagerStub::SetNotificationsEnabledForBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetNotificationsEnabledForAllBundles(const std::string &deviceId, bool enabled)
{
    ANS_LOGE("AnsManagerStub::SetNotificationsEnabledForAllBundles called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetNotificationsEnabledForSpecialBundle(
    const std::string &deviceId, const sptr<NotificationBundleOption> &bundleOption, bool enabled)
{
    ANS_LOGE("AnsManagerStub::SetNotificationsEnabledForSpecialBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetShowBadgeEnabledForBundle(const sptr<NotificationBundleOption> &bundleOption, bool enabled)
{
    ANS_LOGE("AnsManagerStub::SetShowBadgeEnabledForBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetShowBadgeEnabledForBundle(const sptr<NotificationBundleOption> &bundleOption, bool &enabled)
{
    ANS_LOGE("AnsManagerStub::GetShowBadgeEnabledForBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetShowBadgeEnabled(bool &enabled)
{
    ANS_LOGE("AnsManagerStub::GetShowBadgeEnabled called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::Subscribe(const sptr<AnsSubscriberInterface> &subscriber,
    const sptr<NotificationSubscribeInfo> &info)
{
    ANS_LOGE("AnsManagerStub::Subscribe called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SubscribeSelf(const sptr<AnsSubscriberInterface> &subscriber)
{
    ANS_LOGE("AnsManagerStub::SubscribeSelf called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SubscribeLocalLiveView(const sptr<AnsSubscriberLocalLiveViewInterface> &subscriber,
    const sptr<NotificationSubscribeInfo> &info, const bool isNative)
{
    ANS_LOGE("AnsManagerStub::SubscribeLocalLiveView called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::Unsubscribe(const sptr<AnsSubscriberInterface> &subscriber,
    const sptr<NotificationSubscribeInfo> &info)
{
    ANS_LOGE("AnsManagerStub::Unsubscribe called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::IsAllowedNotify(bool &allowed)
{
    ANS_LOGE("AnsManagerStub::IsAllowedNotify called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::IsAllowedNotifySelf(bool &allowed)
{
    ANS_LOGE("AnsManagerStub::IsAllowedNotifySelf called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::CanPopEnableNotificationDialog(const sptr<IAnsDialogCallback> &callback,
    bool &canPop, std::string &bundleName)
{
    ANS_LOGE("AnsManagerStub::CanPopEnableNotificationDialog called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::RemoveEnableNotificationDialog()
{
    ANS_LOGE("AnsManagerStub::RemoveEnableNotificationDialog called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::IsSpecialBundleAllowedNotify(const sptr<NotificationBundleOption> &bundleOption, bool &allowed)
{
    ANS_LOGE("AnsManagerStub::IsSpecialBundleAllowedNotify called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::CancelGroup(const std::string &groupName, const std::string &instanceKey)
{
    ANS_LOGE("AnsManagerStub::CancelGroup called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::RemoveGroupByBundle(
    const sptr<NotificationBundleOption> &bundleOption, const std::string &groupName)
{
    ANS_LOGE("AnsManagerStub::RemoveGroupByBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetDoNotDisturbDate(const sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGE("AnsManagerStub::SetDoNotDisturbDate called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetDoNotDisturbDate(sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGE("AnsManagerStub::GetDoNotDisturbDate called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::AddDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    ANS_LOGD("Called.");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::RemoveDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    ANS_LOGD("Called.");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::DoesSupportDoNotDisturbMode(bool &doesSupport)
{
    ANS_LOGE("AnsManagerStub::DoesSupportDoNotDisturbMode called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::IsNeedSilentInDoNotDisturbMode(const std::string &phoneNumber, int32_t callerType)
{
    ANS_LOGE("AnsManagerStub::IsNeedSilentInDoNotDisturbMode called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::IsDistributedEnabled(bool &enabled)
{
    ANS_LOGE("AnsManagerStub::IsDistributedEnabled called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::EnableDistributed(bool enabled)
{
    ANS_LOGE("AnsManagerStub::EnableDistributed called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::EnableDistributedByBundle(const sptr<NotificationBundleOption> &bundleOption, bool enabled)
{
    ANS_LOGE("AnsManagerStub::EnableDistributedByBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::EnableDistributedSelf(bool enabled)
{
    ANS_LOGE("AnsManagerStub::EnableDistributedSelf called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::IsDistributedEnableByBundle(const sptr<NotificationBundleOption> &bundleOption, bool &enabled)
{
    ANS_LOGE("AnsManagerStub::IsDistributedEnableByBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetDeviceRemindType(NotificationConstant::RemindType &remindType)
{
    ANS_LOGE("AnsManagerStub::GetDeviceRemindType called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::PublishContinuousTaskNotification(const sptr<NotificationRequest> &request)
{
    ANS_LOGE("AnsManagerStub::PublishContinuousTaskNotification called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::CancelContinuousTaskNotification(const std::string &label, int32_t notificationId)
{
    ANS_LOGE("AnsManagerStub::CancelContinuousTaskNotification called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::IsSupportTemplate(const std::string &templateName, bool &support)
{
    ANS_LOGE("AnsManagerStub::IsSupportTemplate called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::IsSpecialUserAllowedNotify(const int32_t &userId, bool &allowed)
{
    ANS_LOGE("AnsManagerStub::IsSpecialUserAllowedNotify called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetNotificationsEnabledByUser(const int32_t &deviceId, bool enabled)
{
    ANS_LOGE("AnsManagerStub::SetNotificationsEnabledByUser called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::DeleteAllByUser(const int32_t &userId)
{
    ANS_LOGE("AnsManagerStub::DeleteAllByUser called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetDoNotDisturbDate(const int32_t &userId, const sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGE("AnsManagerStub::SetDoNotDisturbDate called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetDoNotDisturbDate(const int32_t &userId, sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGE("AnsManagerStub::GetDoNotDisturbDate called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetEnabledForBundleSlot(const sptr<NotificationBundleOption> &bundleOption,
    const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl)
{
    ANS_LOGE("AnsManagerStub::SetEnabledForBundleSlot called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetEnabledForBundleSlot(
    const sptr<NotificationBundleOption> &bundleOption, const NotificationConstant::SlotType &slotType, bool &enabled)
{
    ANS_LOGE("AnsManagerStub::GetEnabledForBundleSlot called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetEnabledForBundleSlotSelf(const NotificationConstant::SlotType &slotType, bool &enabled)
{
    ANS_LOGE("AnsManagerStub::GetEnabledForBundleSlotSelf called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::ShellDump(const std::string &cmd, const std::string &bundle, int32_t userId,
    int32_t recvUserId, std::vector<std::string> &dumpInfo)
{
    ANS_LOGE("AnsManagerStub::ShellDump called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetSyncNotificationEnabledWithoutApp(const int32_t userId, const bool enabled)
{
    ANS_LOGE("AnsManagerStub::SetSyncNotificationEnabledWithoutApp called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetSyncNotificationEnabledWithoutApp(const int32_t userId, bool &enabled)
{
    ANS_LOGE("AnsManagerStub::GetSyncNotificationEnabledWithoutApp called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetBadgeNumber(int32_t badgeNumber, const std::string &instanceKey)
{
    ANS_LOGE("AnsManagerStub::SetBadgeNumber called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetBadgeNumberByBundle(const sptr<NotificationBundleOption> &bundleOption, int32_t badgeNumber)
{
    ANS_LOGD("Called.");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetBadgeNumberForDhByBundle(
    const sptr<NotificationBundleOption> &bundleOption, int32_t badgeNumber)
{
    ANS_LOGD("Called.");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetAllNotificationEnabledBundles(std::vector<NotificationBundleOption> &bundleOption)
{
    ANS_LOGE("AnsManagerStub::GetAllNotificationEnabledBundles called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::RegisterPushCallback(
    const sptr<IRemoteObject>& pushCallback, const sptr<NotificationCheckRequest> &notificationCheckRequest)
{
    ANS_LOGE("RegisterPushCallback called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::UnregisterPushCallback()
{
    ANS_LOGE("UnregisterPushCallback called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetDistributedEnabledByBundle(const sptr<NotificationBundleOption> &bundleOption,
    const std::string &deviceType, const bool enabled)
{
    ANS_LOGE("SetDistributedEnabledByBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetTargetDeviceStatus(const std::string &deviceType, int32_t &status)
{
    ANS_LOGE("GetTargetDeviceStatus called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::DistributeOperation(sptr<NotificationOperationInfo>& operationInfo,
    const sptr<OperationCallbackInterface> &callback)
{
    ANS_LOGE("DistributeOperation called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::ReplyDistributeOperation(const std::string& hashCode, const int32_t result)
{
    ANS_LOGE("ReplyDistributeOperation called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetAllLiveViewEnabledBundles(std::vector<NotificationBundleOption> &bundleOption)
{
    ANS_LOGE("AnsManagerStub::GetAllLiveViewEnabledBundles called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetAllDistribuedEnabledBundles(const std::string& deviceType,
    std::vector<NotificationBundleOption> &bundleOption)
{
    ANS_LOGE("AnsManagerStub::GetAllDistribuedEnabledBundles called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::IsDistributedEnabledByBundle(const sptr<NotificationBundleOption> &bundleOption,
    const std::string &deviceType, bool &enabled)
{
    ANS_LOGE("IsDistributedEnabledByBundle called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetSmartReminderEnabled(const std::string &deviceType, const bool enabled)
{
    ANS_LOGE("SetSmartReminderEnabled called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::IsSmartReminderEnabled(const std::string &deviceType, bool &enabled)
{
    ANS_LOGE("IsSmartReminderEnabled called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetDistributedEnabledBySlot(
    const NotificationConstant::SlotType &slotType, const std::string &deviceType, const bool enabled)
{
    ANS_LOGE("SetDistributedEnabledBySlot called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::IsDistributedEnabledBySlot(
    const NotificationConstant::SlotType &slotType, const std::string &deviceType, bool &enabled)
{
    ANS_LOGE("IsDistributedEnabledBySlot called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetAdditionConfig(const std::string &key, const std::string &value)
{
    ANS_LOGE("Called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::CancelAsBundleWithAgent(const sptr<NotificationBundleOption> &bundleOption, const int32_t id)
{
    ANS_LOGE("Called.");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status)
{
    ANS_LOGE("SetTargetDeviceStatus called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status,
    const uint32_t controlFlag)
{
    ANS_LOGE("SetTargetDeviceStatus called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetDoNotDisturbProfile(int32_t id, sptr<NotificationDoNotDisturbProfile> &profile)
{
    ANS_LOGE("GetDoNotDisturbProfile called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::AllowUseReminder(const std::string& bundleName, bool& isAllowUseReminder)
{
    ANS_LOGE("AllowUseReminder called!");
    return ERR_INVALID_OPERATION;
}

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
ErrCode AnsManagerStub::RegisterSwingCallback(const sptr<IRemoteObject>& swingCallback)
{
    ANS_LOGE("RegisterSwingCallback called!");
    return ERR_INVALID_OPERATION;
}
#endif

ErrCode AnsManagerStub::UpdateNotificationTimerByUid(const int32_t uid, const bool isPaused)
{
    ANS_LOGE("UpdateNotificationTimerByUid called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::DisableNotificationFeature(const sptr<NotificationDisable> &notificationDisable)
{
    ANS_LOGE("DisableNotificationFeature called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::SetHashCodeRule(const uint32_t type)
{
    ANS_LOGE("SetHashCodeRule called!");
    return ERR_INVALID_OPERATION;
}

ErrCode AnsManagerStub::GetAllNotificationsBySlotType(std::vector<sptr<Notification>> &notifications,
    const NotificationConstant::SlotType slotType)
{
    ANS_LOGE("AnsManagerStub::GetAllNotificationsBySlotType called!");
    return ERR_INVALID_OPERATION;
}
}  // namespace Notification
}  // namespace OHOS
