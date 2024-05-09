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

#include "ans_manager_stub.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_subscriber_local_live_view_interface.h"
#include "message_option.h"
#include "message_parcel.h"
#include "notification_bundle_option.h"
#include "notification_button_option.h"
#include "parcel.h"
#include "reminder_request_alarm.h"
#include "reminder_request_calendar.h"
#include "reminder_request_timer.h"

namespace OHOS {
namespace Notification {
const std::map<NotificationInterfaceCode, std::function<ErrCode(AnsManagerStub *, MessageParcel &, MessageParcel &)>>
    AnsManagerStub::interfaces_ = {
        {NotificationInterfaceCode::PUBLISH_NOTIFICATION,
            std::bind(
                &AnsManagerStub::HandlePublish, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::CANCEL_NOTIFICATION,
            std::bind(
                &AnsManagerStub::HandleCancel, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::CANCEL_ALL_NOTIFICATIONS,
            std::bind(
                &AnsManagerStub::HandleCancelAll, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::CANCEL_AS_BUNDLE_OPTION,
            std::bind(
                &AnsManagerStub::HandleCancelAsBundleOption, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::CANCEL_AS_BUNDLE_AND_USER,
            std::bind(
                &AnsManagerStub::HandleCancelAsBundleAndUser, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::CANCEL_AS_BUNDLE,
            std::bind(&AnsManagerStub::HandleCancelAsBundle, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::ADD_SLOT_BY_TYPE,
            std::bind(&AnsManagerStub::HandleAddSlotByType, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::ADD_SLOTS,
            std::bind(
                &AnsManagerStub::HandleAddSlots, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::REMOVE_SLOT_BY_TYPE,
            std::bind(&AnsManagerStub::HandleRemoveSlotByType, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::REMOVE_ALL_SLOTS,
            std::bind(&AnsManagerStub::HandleRemoveAllSlots, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::GET_SLOT_BY_TYPE,
            std::bind(&AnsManagerStub::HandleGetSlotByType, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::GET_SLOTS,
            std::bind(
                &AnsManagerStub::HandleGetSlots, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::GET_SLOT_NUM_AS_BUNDLE,
            std::bind(&AnsManagerStub::HandleGetSlotNumAsBundle, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::GET_ACTIVE_NOTIFICATIONS,
            std::bind(&AnsManagerStub::HandleGetActiveNotifications, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::GET_ACTIVE_NOTIFICATION_NUMS,
            std::bind(&AnsManagerStub::HandleGetActiveNotificationNums, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::GET_ALL_ACTIVE_NOTIFICATIONS,
            std::bind(&AnsManagerStub::HandleGetAllActiveNotifications, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::GET_SPECIAL_ACTIVE_NOTIFICATIONS,
            std::bind(&AnsManagerStub::HandleGetSpecialActiveNotifications, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::GET_ACTIVE_NOTIFICATION_BY_FILTER,
            std::bind(&AnsManagerStub::HandleGetActiveNotificationByFilter, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::SET_NOTIFICATION_AGENT,
            std::bind(&AnsManagerStub::HandleSetNotificationAgent, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::GET_NOTIFICATION_AGENT,
            std::bind(&AnsManagerStub::HandleGetNotificationAgent, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::CAN_PUBLISH_AS_BUNDLE,
            std::bind(&AnsManagerStub::HandleCanPublishAsBundle, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::PUBLISH_AS_BUNDLE,
            std::bind(&AnsManagerStub::HandlePublishAsBundle, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::SET_NOTIFICATION_BADGE_NUM,
            std::bind(&AnsManagerStub::HandleSetNotificationBadgeNum, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::GET_BUNDLE_IMPORTANCE,
            std::bind(&AnsManagerStub::HandleGetBundleImportance, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::IS_NOTIFICATION_POLICY_ACCESS_GRANTED,
            std::bind(&AnsManagerStub::HandleIsNotificationPolicyAccessGranted, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::REMOVE_NOTIFICATION,
            std::bind(&AnsManagerStub::HandleRemoveNotification, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::REMOVE_ALL_NOTIFICATIONS,
            std::bind(&AnsManagerStub::HandleRemoveAllNotifications, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::REMOVE_NOTIFICATIONS_BY_KEYS,
            std::bind(&AnsManagerStub::HandleRemoveNotifications, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::DELETE_NOTIFICATION,
            std::bind(
                &AnsManagerStub::HandleDelete, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::DELETE_NOTIFICATION_BY_BUNDLE,
            std::bind(&AnsManagerStub::HandleDeleteByBundle, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::DELETE_ALL_NOTIFICATIONS,
            std::bind(
                &AnsManagerStub::HandleDeleteAll, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::GET_SLOTS_BY_BUNDLE,
            std::bind(&AnsManagerStub::HandleGetSlotsByBundle, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::UPDATE_SLOTS,
            std::bind(&AnsManagerStub::HandleUpdateSlots, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::REQUEST_ENABLE_NOTIFICATION,
            std::bind(&AnsManagerStub::HandleRequestEnableNotification, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::SET_NOTIFICATION_ENABLED_FOR_BUNDLE,
            std::bind(&AnsManagerStub::HandleSetNotificationsEnabledForBundle, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::SET_NOTIFICATION_ENABLED_FOR_ALL_BUNDLE,
            std::bind(&AnsManagerStub::HandleSetNotificationsEnabledForAllBundles, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::SET_NOTIFICATION_ENABLED_FOR_SPECIAL_BUNDLE,
            std::bind(&AnsManagerStub::HandleSetNotificationsEnabledForSpecialBundle, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::SET_SHOW_BADGE_ENABLED_FOR_BUNDLE,
            std::bind(&AnsManagerStub::HandleSetShowBadgeEnabledForBundle, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::GET_SHOW_BADGE_ENABLED_FOR_BUNDLE,
            std::bind(&AnsManagerStub::HandleGetShowBadgeEnabledForBundle, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::GET_SHOW_BADGE_ENABLED,
            std::bind(&AnsManagerStub::HandleGetShowBadgeEnabled, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::SUBSCRIBE_NOTIFICATION,
            std::bind(
                &AnsManagerStub::HandleSubscribe, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::UNSUBSCRIBE_NOTIFICATION,
            std::bind(&AnsManagerStub::HandleUnsubscribe, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::IS_ALLOWED_NOTIFY,
            std::bind(&AnsManagerStub::HandleIsAllowedNotify, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::IS_ALLOWED_NOTIFY_SELF,
            std::bind(&AnsManagerStub::HandleIsAllowedNotifySelf, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::IS_SPECIAL_BUNDLE_ALLOWED_NOTIFY,
            std::bind(&AnsManagerStub::HandleIsSpecialBundleAllowedNotify, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::SET_DO_NOT_DISTURB_DATE,
            std::bind(&AnsManagerStub::HandleSetDoNotDisturbDate, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::GET_DO_NOT_DISTURB_DATE,
            std::bind(&AnsManagerStub::HandleGetDoNotDisturbDate, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::DOES_SUPPORT_DO_NOT_DISTURB_MODE,
            std::bind(&AnsManagerStub::HandleDoesSupportDoNotDisturbMode, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::CANCEL_GROUP,
            std::bind(&AnsManagerStub::HandleCancelGroup, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::REMOVE_GROUP_BY_BUNDLE,
            std::bind(&AnsManagerStub::HandleRemoveGroupByBundle, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::IS_DISTRIBUTED_ENABLED,
            std::bind(&AnsManagerStub::HandleIsDistributedEnabled, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::ENABLE_DISTRIBUTED,
            std::bind(&AnsManagerStub::HandleEnableDistributed, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::ENABLE_DISTRIBUTED_BY_BUNDLE,
            std::bind(&AnsManagerStub::HandleEnableDistributedByBundle, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::ENABLE_DISTRIBUTED_SELF,
            std::bind(&AnsManagerStub::HandleEnableDistributedSelf, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::IS_DISTRIBUTED_ENABLED_BY_BUNDLE,
            std::bind(&AnsManagerStub::HandleIsDistributedEnableByBundle, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::GET_DEVICE_REMIND_TYPE,
            std::bind(&AnsManagerStub::HandleGetDeviceRemindType, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::SHELL_DUMP,
            std::bind(
                &AnsManagerStub::HandleShellDump, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::PUBLISH_CONTINUOUS_TASK_NOTIFICATION,
            std::bind(
                &AnsManagerStub::HandlePublishContinuousTaskNotification, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::CANCEL_CONTINUOUS_TASK_NOTIFICATION,
            std::bind(
                &AnsManagerStub::HandleCancelContinuousTaskNotification, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::PUBLISH_REMINDER,
            std::bind(&AnsManagerStub::HandlePublishReminder, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::CANCEL_REMINDER,
            std::bind(&AnsManagerStub::HandleCancelReminder, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::CANCEL_ALL_REMINDERS,
            std::bind(
                &AnsManagerStub::HandleCancelAllReminders, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::GET_ALL_VALID_REMINDERS,
            std::bind(&AnsManagerStub::HandleGetValidReminders, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::IS_SUPPORT_TEMPLATE,
            std::bind(
                &AnsManagerStub::HandleIsSupportTemplate, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::IS_SPECIAL_USER_ALLOWED_NOTIFY,
            std::bind(&AnsManagerStub::HandleIsSpecialUserAllowedNotifyByUser, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::SET_NOTIFICATION_ENABLED_BY_USER,
            std::bind(&AnsManagerStub::HandleSetNotificationsEnabledByUser, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::DELETE_ALL_NOTIFICATIONS_BY_USER,
            std::bind(&AnsManagerStub::HandleDeleteAllByUser, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::SET_DO_NOT_DISTURB_DATE_BY_USER,
            std::bind(&AnsManagerStub::HandleSetDoNotDisturbDateByUser, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::GET_DO_NOT_DISTURB_DATE_BY_USER,
            std::bind(&AnsManagerStub::HandleGetDoNotDisturbDateByUser, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::SET_ENABLED_FOR_BUNDLE_SLOT,
            std::bind(&AnsManagerStub::HandleSetEnabledForBundleSlot, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::GET_ENABLED_FOR_BUNDLE_SLOT,
            std::bind(&AnsManagerStub::HandleGetEnabledForBundleSlot, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::GET_ENABLED_FOR_BUNDLE_SLOT_SELF,
            std::bind(&AnsManagerStub::HandleGetEnabledForBundleSlotSelf, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::SET_DISTRIBUTED_ENABLED_BY_BUNDLE,
            std::bind(&AnsManagerStub::HandleSetDistributedEnabledByBundle, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::GET_DISTRIBUTED_ENABLED_BY_BUNDLE,
            std::bind(&AnsManagerStub::HandleIsDistributedEnabledByBundle, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::SET_SMART_REMINDER_ENABLED,
            std::bind(&AnsManagerStub::HandleSetSmartReminderEnabled, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::GET_SMART_REMINDER_ENABLED,
            std::bind(&AnsManagerStub::HandleIsSmartReminderEnabled, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::SET_SYNC_NOTIFICATION_ENABLED_WITHOUT_APP,
            std::bind(&AnsManagerStub::HandleDistributedSetEnabledWithoutApp, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::GET_SYNC_NOTIFICATION_ENABLED_WITHOUT_APP,
            std::bind(&AnsManagerStub::HandleDistributedGetEnabledWithoutApp, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::SET_BADGE_NUMBER,
            std::bind(&AnsManagerStub::HandleSetBadgeNumber, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::SET_BADGE_NUMBER_BY_BUNDLE,
            std::bind(&AnsManagerStub::HandleSetBadgeNumberByBundle, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::GET_ALL_NOTIFICATION_ENABLE_STATUS,
            std::bind(&AnsManagerStub::HandleGetAllNotificationEnableStatus, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::REGISTER_PUSH_CALLBACK,
            std::bind(&AnsManagerStub::HandleRegisterPushCallback, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::UNREGISTER_PUSH_CALLBACK,
            std::bind(&AnsManagerStub::HandleUnregisterPushCallback, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::SUBSCRIBE_LOCAL_LIVE_VIEW_NOTIFICATION,
            std::bind(&AnsManagerStub::HandleSubscribeLocalLiveView, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::TRIGGER_LOCAL_LIVE_VIEW_NOTIFICATION,
            std::bind(&AnsManagerStub::HandleTriggerLocalLiveView, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::SUBSCRIBE_NOTIFICATION_SELF,
            std::bind(&AnsManagerStub::HandleSubscribeSelf, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::SET_SLOTFLAGS_BY_BUNDLE,
            std::bind(&AnsManagerStub::HandleSetSlotFlagsAsBundle, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::GET_SLOTFLAGS_BY_BUNDLE,
            std::bind(&AnsManagerStub::HandleGetSlotFlagsAsBundle, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::SET_NOTIFICATION_AGENT_RELATIONSHIP,
            std::bind(&AnsManagerStub::HandleSetAdditionConfig, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::CANCEL_AS_BUNDLE_WITH_AGENT,
            std::bind(&AnsManagerStub::HandleCancelAsBundleWithAgent, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::GET_SLOT_BY_BUNDLE,
            std::bind(&AnsManagerStub::HandleGetSlotByBundle, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
        {NotificationInterfaceCode::ADD_DO_NOTDISTURB_PROFILES,
            std::bind(&AnsManagerStub::HandleAddDoNotDisturbProfiles, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::REMOVE_DO_NOT_DISTURB_PROFILES,
            std::bind(&AnsManagerStub::HandleRemoveDoNotDisturbProfiles, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::SET_TARGET_DEVICE_STATUS,
            std::bind(&AnsManagerStub::HandleSetTargetDeviceStatus, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3)},
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
        {NotificationInterfaceCode::REGISTER_SWING_CALLBACK,
            std::bind(&AnsManagerStub::HandleRegisterSwingCallback, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
#endif
        {NotificationInterfaceCode::ADD_EXCLUDE_DATE_REMINDER,
            std::bind(&AnsManagerStub::HandleAddExcludeDate, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::DEL_EXCLUDE_DATES_REMINDER,
            std::bind(&AnsManagerStub::HandleDelExcludeDates, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
        {NotificationInterfaceCode::GET_EXCLUDE_DATES_REMINDER,
            std::bind(&AnsManagerStub::HandleGetExcludeDates, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3)},
};

AnsManagerStub::AnsManagerStub()
{}

AnsManagerStub::~AnsManagerStub()
{}

int32_t AnsManagerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &flags)
{
    std::u16string descriptor = AnsManagerStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        ANS_LOGE("[OnRemoteRequest] fail: invalid interface token!");
        return OBJECT_NULL;
    }

    auto it = interfaces_.find(static_cast<NotificationInterfaceCode>(code));
    if (it == interfaces_.end()) {
        ANS_LOGE("[OnRemoteRequest] fail: unknown code!");
        return IPCObjectStub::OnRemoteRequest(code, data, reply, flags);
    }

    auto fun = it->second;
    if (fun == nullptr) {
        ANS_LOGE("[OnRemoteRequest] fail: not find function!");
        return IPCObjectStub::OnRemoteRequest(code, data, reply, flags);
    }

    ErrCode result = fun(this, data, reply);
    if (SUCCEEDED(result)) {
        return NO_ERROR;
    }

    ANS_LOGE("[OnRemoteRequest] fail: Failed to call interface %{public}u, err:%{public}d", code, result);
    return result;
}

ErrCode AnsManagerStub::HandlePublish(MessageParcel &data, MessageParcel &reply)
{
    std::string label;
    if (!data.ReadString(label)) {
        ANS_LOGE("[HandlePublish] fail: read label failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<NotificationRequest> notification = data.ReadParcelable<NotificationRequest>();
    if (!notification) {
        ANS_LOGE("[HandlePublish] fail: notification ReadParcelable failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = Publish(label, notification);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandlePublish] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleCancel(MessageParcel &data, MessageParcel &reply)
{
    int32_t notificationId = 0;
    if (!data.ReadInt32(notificationId)) {
        ANS_LOGE("[HandleCancel] fail: read notificationId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    std::string label;
    if (!data.ReadString(label)) {
        ANS_LOGE("[HandleCancel] fail: read label failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = Cancel(notificationId, label);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleCancel] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleCancelAll(MessageParcel &data, MessageParcel &reply)
{
    ErrCode result = CancelAll();
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleCancelAll] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleCancelAsBundleOption(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadStrongParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleCancelAsBundle] fail: read BundleOption failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    int32_t notificationId = 0;
    if (!data.ReadInt32(notificationId)) {
        ANS_LOGE("[HandleCancelAsBundle] fail: read notificationId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    ErrCode result = CancelAsBundle(bundleOption, notificationId);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleCancelAsBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleCancelAsBundle(MessageParcel &data, MessageParcel &reply)
{
    int32_t notificationId = 0;
    if (!data.ReadInt32(notificationId)) {
        ANS_LOGE("[HandleCancelAsBundle] fail: read notificationId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    std::string representativeBundle;
    if (!data.ReadString(representativeBundle)) {
        ANS_LOGE("[HandleCancelAsBundle] fail: read representativeBundle failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t userId = 0;
    if (!data.ReadInt32(userId)) {
        ANS_LOGE("[HandleCancelAsBundle] fail: read userId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = CancelAsBundle(notificationId, representativeBundle, userId);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleCancelAsBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleCancelAsBundleAndUser(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadStrongParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleCancelAsBundle] fail: read BundleOption failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    int32_t notificationId = 0;
    if (!data.ReadInt32(notificationId)) {
        ANS_LOGE("[HandleCancelAsBundle] fail: read notificationId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t userId = 0;
    if (!data.ReadInt32(userId)) {
        ANS_LOGE("[HandleCancelAsBundle] fail: read userId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    ErrCode result = CancelAsBundle(bundleOption, notificationId, userId);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleCancelAsBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleAddSlotByType(MessageParcel &data, MessageParcel &reply)
{
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(data.ReadInt32());
    ErrCode result = AddSlotByType(slotType);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleAddSlotByType] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleAddSlots(MessageParcel &data, MessageParcel &reply)
{
    std::vector<sptr<NotificationSlot>> slots;
    if (!ReadParcelableVector(slots, data)) {
        ANS_LOGE("[HandleAddSlots] fail: read slotsSize failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    ErrCode result = AddSlots(slots);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleAddSlots] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleRemoveSlotByType(MessageParcel &data, MessageParcel &reply)
{
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(data.ReadInt32());

    ErrCode result = RemoveSlotByType(slotType);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleRemoveSlotByType] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleRemoveAllSlots(MessageParcel &data, MessageParcel &reply)
{
    ErrCode result = RemoveAllSlots();
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleRemoveAllSlots] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetSlots(MessageParcel &data, MessageParcel &reply)
{
    std::vector<sptr<NotificationSlot>> slots;
    ErrCode result = GetSlots(slots);
    if (!WriteParcelableVector(slots, reply, result)) {
        ANS_LOGE("[HandleGetSlots] fail: write slots failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetSlotByType(MessageParcel &data, MessageParcel &reply)
{
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(data.ReadInt32());

    sptr<NotificationSlot> slot = nullptr;
    ErrCode result = GetSlotByType(slotType, slot);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleGetSlotByType] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteParcelable(slot)) {
        ANS_LOGE("[HandleGetSlotByType] fail: write slot failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetSlotNumAsBundle(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadStrongParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleGetSlotNumAsBundle] fail: read bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    uint64_t num = 0;
    ErrCode result = GetSlotNumAsBundle(bundleOption, num);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleGetSlotNumAsBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteUint64(num)) {
        ANS_LOGE("[HandleGetSlotNumAsBundle] fail: write enabled failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSetSlotFlagsAsBundle(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadStrongParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleSetSlotFlagsAsBundle] fail: read bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t slotFlags = 0;
    if (!data.ReadInt32(slotFlags)) {
        ANS_LOGE("[HandleSetSlotFlagsAsBundle] fail: read notification failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetSlotFlagsAsBundle(bundleOption, slotFlags);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetSlotFlagsAsBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetSlotFlagsAsBundle(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadStrongParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleGetSlotFlagsAsBundle] fail: read bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    uint32_t slotFlags = 0;
    ErrCode result = GetSlotFlagsAsBundle(bundleOption, slotFlags);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleGetSlotFlagsAsBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteUint32(slotFlags)) {
        ANS_LOGE("[HandleGetSlotFlagsAsBundle] fail: write enabled failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetActiveNotifications(MessageParcel &data, MessageParcel &reply)
{
    std::vector<sptr<NotificationRequest>> notifications;
    ErrCode result = GetActiveNotifications(notifications);
    if (!WriteParcelableVector(notifications, reply, result)) {
        ANS_LOGE("[HandleGetActiveNotifications] fail: write notifications failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetActiveNotificationNums(MessageParcel &data, MessageParcel &reply)
{
    uint64_t num = 0;
    ErrCode result = GetActiveNotificationNums(num);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleGetActiveNotificationNums] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteUint64(num)) {
        ANS_LOGE("[HandleGetActiveNotificationNums] fail: write num failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetAllActiveNotifications(MessageParcel &data, MessageParcel &reply)
{
    std::vector<sptr<Notification>> notifications;
    ErrCode result = GetAllActiveNotifications(notifications);
    if (!WriteParcelableVector(notifications, reply, result)) {
        ANS_LOGE("[HandleGetAllActiveNotifications] fail: write notifications failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetSpecialActiveNotifications(MessageParcel &data, MessageParcel &reply)
{
    std::vector<std::string> key;
    if (!data.ReadStringVector(&key)) {
        ANS_LOGE("[HandleGetSpecialActiveNotifications] fail: read key failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    std::vector<sptr<Notification>> notifications;
    ErrCode result = GetSpecialActiveNotifications(key, notifications);
    if (!WriteParcelableVector(notifications, reply, result)) {
        ANS_LOGE("[HandleGetSpecialActiveNotifications] fail: write notifications failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetActiveNotificationByFilter(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleGetActiveNotificationByFilter] fail: read bundleOption failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t notificationId = 0;
    if (!data.ReadInt32(notificationId)) {
        ANS_LOGE("[HandleGetActiveNotificationByFilter] fail: read notificationId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    std::string label;
    if (!data.ReadString(label)) {
        ANS_LOGE("[HandleGetActiveNotificationByFilter] fail: read label failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    std::vector<std::string> extraInfoKeys;
    if (!data.ReadStringVector(&extraInfoKeys)) {
        ANS_LOGE("[HandleGetActiveNotificationByFilter] fail: read extraInfoKeys failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<NotificationRequest> request;
    ErrCode result = GetActiveNotificationByFilter(bundleOption, notificationId, label, extraInfoKeys, request);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleGetActiveNotificationByFilter] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteParcelable(request)) {
        ANS_LOGE("[HandleGetActiveNotificationByFilter] fail: get extra info by filter failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerStub::HandleSetNotificationAgent(MessageParcel &data, MessageParcel &reply)
{
    std::string agent;
    if (!data.ReadString(agent)) {
        ANS_LOGE("[HandleSetNotificationAgent] fail: read agent failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetNotificationAgent(agent);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetNotificationAgent] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetNotificationAgent(MessageParcel &data, MessageParcel &reply)
{
    std::string agent;
    ErrCode result = GetNotificationAgent(agent);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleGetNotificationAgent] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteString(agent)) {
        ANS_LOGE("[HandleGetNotificationAgent] fail: write agent failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleCanPublishAsBundle(MessageParcel &data, MessageParcel &reply)
{
    std::string representativeBundle;
    if (!data.ReadString(representativeBundle)) {
        ANS_LOGE("[HandleCanPublishAsBundle] fail: read representativeBundle failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool canPublish = false;
    ErrCode result = CanPublishAsBundle(representativeBundle, canPublish);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleCanPublishAsBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteBool(canPublish)) {
        ANS_LOGE("[HandleCanPublishAsBundle] fail: write canPublish failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandlePublishAsBundle(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationRequest> notification = data.ReadParcelable<NotificationRequest>();
    if (!notification) {
        ANS_LOGE("[HandlePublishAsBundle] fail: read notification failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    std::string representativeBundle;
    if (!data.ReadString(representativeBundle)) {
        ANS_LOGE("[HandlePublishAsBundle] fail: read representativeBundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = PublishAsBundle(notification, representativeBundle);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandlePublishAsBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSetNotificationBadgeNum(MessageParcel &data, MessageParcel &reply)
{
    int32_t num = 0;
    if (!data.ReadInt32(num)) {
        ANS_LOGE("[HandleSetNotificationBadgeNum] fail: read notification failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetNotificationBadgeNum(num);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetNotificationBadgeNum] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetBundleImportance(MessageParcel &data, MessageParcel &reply)
{
    int32_t importance = 0;
    ErrCode result = GetBundleImportance(importance);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleGetBundleImportance] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteInt32(importance)) {
        ANS_LOGE("[HandleGetBundleImportance] fail: write importance failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSetDoNotDisturbDate(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationDoNotDisturbDate> date = data.ReadParcelable<NotificationDoNotDisturbDate>();
    if (date == nullptr) {
        ANS_LOGE("[HandleSetDoNotDisturbDate] fail: read date failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetDoNotDisturbDate(date);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetDoNotDisturbDate] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetDoNotDisturbDate(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationDoNotDisturbDate> date = nullptr;

    ErrCode result = GetDoNotDisturbDate(date);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetDoNotDisturbDate] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (result == ERR_OK) {
        if (!reply.WriteParcelable(date)) {
            ANS_LOGE("[HandleSetDoNotDisturbDate] fail: write date failed.");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleDoesSupportDoNotDisturbMode(MessageParcel &data, MessageParcel &reply)
{
    bool support = false;

    ErrCode result = DoesSupportDoNotDisturbMode(support);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleDoesSupportDoNotDisturbMode] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteBool(support)) {
        ANS_LOGE("[HandleDoesSupportDoNotDisturbMode] fail: write doesSupport failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandlePublishContinuousTaskNotification(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationRequest> request = data.ReadParcelable<NotificationRequest>();
    if (!request) {
        ANS_LOGE("[HandlePublishContinuousTaskNotification] fail: notification ReadParcelable failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = PublishContinuousTaskNotification(request);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandlePublishContinuousTaskNotification] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleCancelContinuousTaskNotification(MessageParcel &data, MessageParcel &reply)
{
    std::string label;
    if (!data.ReadString(label)) {
        ANS_LOGE("[HandleCancelContinuousTaskNotification] fail: read label failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t notificationId = 0;
    if (!data.ReadInt32(notificationId)) {
        ANS_LOGE("[HandleCancelContinuousTaskNotification] fail: read notificationId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = CancelContinuousTaskNotification(label, notificationId);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleCancelContinuousTaskNotification] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleIsNotificationPolicyAccessGranted(MessageParcel &data, MessageParcel &reply)
{
    bool granted = false;
    ErrCode result = HasNotificationPolicyAccessPermission(granted);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleIsNotificationPolicyAccessGranted] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteBool(granted)) {
        ANS_LOGE("[HandleIsNotificationPolicyAccessGranted] fail: write granted failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleTriggerLocalLiveView(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadStrongParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleTriggerLocalLiveView] fail: read bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t notificationId = 0;
    if (!data.ReadInt32(notificationId)) {
        ANS_LOGE("[HandleTriggerLocalLiveView] fail: read notificationId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<NotificationButtonOption> buttonOption = data.ReadStrongParcelable<NotificationButtonOption>();
    if (buttonOption == nullptr) {
        ANS_LOGE("[HandleTriggerLocalLiveView] fail: read button failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = TriggerLocalLiveView(bundleOption, notificationId, buttonOption);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleTriggerLocalLiveView] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleRemoveNotification(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadStrongParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleRemoveNotification] fail: read bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t notificationId = 0;
    if (!data.ReadInt32(notificationId)) {
        ANS_LOGE("[HandleRemoveNotification] fail: read notificationId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    std::string label;
    if (!data.ReadString(label)) {
        ANS_LOGE("[HandleRemoveNotification] fail: read label failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t removeReason = 0;
    if (!data.ReadInt32(removeReason)) {
        ANS_LOGE("[HandleRemoveNotification] fail: read removeReason failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = RemoveNotification(bundleOption, notificationId, label, removeReason);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleRemoveNotification] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleRemoveAllNotifications(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadStrongParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleRemoveAllNotifications] fail: read bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = RemoveAllNotifications(bundleOption);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleRemoveAllNotifications] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleRemoveNotifications(MessageParcel &data, MessageParcel &reply)
{
    int32_t keysSize = 0;
    if (!data.ReadInt32(keysSize)) {
        ANS_LOGE("read keys size failed.");
        return false;
    }

    std::vector<std::string> keys;
    if (!data.ReadStringVector(&keys)) {
        ANS_LOGE("read keys failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t removeReason = 0;
    if (!data.ReadInt32(removeReason)) {
        ANS_LOGE("read removeReason failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = RemoveNotifications(keys, removeReason);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}


ErrCode AnsManagerStub::HandleDelete(MessageParcel &data, MessageParcel &reply)
{
    std::string key;
    if (!data.ReadString(key)) {
        ANS_LOGE("[HandleDelete] fail: read key failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t removeReason = 0;
    if (!data.ReadInt32(removeReason)) {
        ANS_LOGE("[HandleDelete] fail: read removeReason failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = Delete(key, removeReason);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleDelete] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleDeleteByBundle(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadStrongParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleDeleteByBundle] fail: read bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = DeleteByBundle(bundleOption);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleDeleteByBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleDeleteAll(MessageParcel &data, MessageParcel &reply)
{
    ErrCode result = DeleteAll();
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleDeleteAll] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetSlotsByBundle(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleGetSlotsByBundle] fail: read bundleOption failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    std::vector<sptr<NotificationSlot>> slots;
    ErrCode result = GetSlotsByBundle(bundleOption, slots);
    if (!WriteParcelableVector(slots, reply, result)) {
        ANS_LOGE("[HandleGetSlotsByBundle] fail: write slots failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetSlotByBundle(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleGetSlotByBundle] fail: read bundleOption failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(data.ReadInt32());

    sptr<NotificationSlot> slot = nullptr;
    ErrCode result = GetSlotByBundle(bundleOption, slotType, slot);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleGetSlotByBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteParcelable(slot)) {
        ANS_LOGE("[HandleGetSlotByBundle] fail: write slot failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleUpdateSlots(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleUpdateSlots] fail: read bundleOption failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    std::vector<sptr<NotificationSlot>> slots;
    if (!ReadParcelableVector(slots, data)) {
        ANS_LOGE("[HandleUpdateSlots] fail: read slots failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = UpdateSlots(bundleOption, slots);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleUpdateSlots] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleRequestEnableNotification(MessageParcel &data, MessageParcel &reply)
{
    ANS_LOGD("enter");
    std::string deviceId;
    if (!data.ReadString(deviceId)) {
        ANS_LOGE("[HandleRequestEnableNotification] fail: read deviceId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        ANS_LOGE("[HandleRequestEnableNotification] fail: read callback failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool hasCallerToken = false;
    if (!data.ReadBool(hasCallerToken)) {
        ANS_LOGE("fail: read hasCallerToken failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<IRemoteObject> callerToken = nullptr;
    if (hasCallerToken) {
        callerToken = data.ReadRemoteObject();
    }

    ErrCode result = RequestEnableNotification(deviceId,
        iface_cast<AnsDialogCallback>(callback), callerToken);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleRequestEnableNotification] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSetNotificationsEnabledForBundle(MessageParcel &data, MessageParcel &reply)
{
    std::string deviceId;
    if (!data.ReadString(deviceId)) {
        ANS_LOGE("[HandleSetNotificationsEnabledForBundle] fail: read deviceId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool enabled = false;
    if (!data.ReadBool(enabled)) {
        ANS_LOGE("[HandleSetNotificationsEnabledForBundle] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetNotificationsEnabledForBundle(deviceId, enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetNotificationsEnabledForBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSetNotificationsEnabledForAllBundles(MessageParcel &data, MessageParcel &reply)
{
    std::string deviceId;
    if (!data.ReadString(deviceId)) {
        ANS_LOGE("[HandleSetNotificationsEnabledForAllBundles] fail: read deviceId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool enabled = false;
    if (!data.ReadBool(enabled)) {
        ANS_LOGE("[HandleSetNotificationsEnabledForAllBundles] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetNotificationsEnabledForAllBundles(deviceId, enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetNotificationsEnabledForAllBundles] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSetNotificationsEnabledForSpecialBundle(MessageParcel &data, MessageParcel &reply)
{
    std::string deviceId;
    if (!data.ReadString(deviceId)) {
        ANS_LOGE("[HandleSetNotificationsEnabledForSpecialBundle] fail: read deviceId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<NotificationBundleOption> bundleOption = data.ReadParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleSetNotificationsEnabledForSpecialBundle] fail: read bundleOption failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool enabled = false;
    if (!data.ReadBool(enabled)) {
        ANS_LOGE("[HandleSetNotificationsEnabledForSpecialBundle] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetNotificationsEnabledForSpecialBundle(deviceId, bundleOption, enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE(
            "[HandleSetNotificationsEnabledForSpecialBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSetShowBadgeEnabledForBundle(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleSetShowBadgeEnabledForBundle] fail: read bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool enabled = false;
    if (!data.ReadBool(enabled)) {
        ANS_LOGE("[HandleSetShowBadgeEnabledForBundle] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetShowBadgeEnabledForBundle(bundleOption, enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetShowBadgeEnabledForBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetShowBadgeEnabledForBundle(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleGetShowBadgeEnabledForBundle] fail: read bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool enabled = false;
    ErrCode result = GetShowBadgeEnabledForBundle(bundleOption, enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleGetShowBadgeEnabledForBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteBool(enabled)) {
        ANS_LOGE("[HandleGetShowBadgeEnabledForBundle] fail: write enabled failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetShowBadgeEnabled(MessageParcel &data, MessageParcel &reply)
{
    bool enabled = false;
    ErrCode result = GetShowBadgeEnabled(enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleGetShowBadgeEnabled] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteBool(enabled)) {
        ANS_LOGE("[HandleGetShowBadgeEnabled] fail: write enabled failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSubscribe(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> subscriber = data.ReadRemoteObject();
    if (subscriber == nullptr) {
        ANS_LOGE("[HandleSubscribe] fail: read subscriber failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool subcribeInfo = false;
    if (!data.ReadBool(subcribeInfo)) {
        ANS_LOGE("[HandleSubscribe] fail: read isSubcribeInfo failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<NotificationSubscribeInfo> info = nullptr;
    if (subcribeInfo) {
        info = data.ReadParcelable<NotificationSubscribeInfo>();
        if (info == nullptr) {
            ANS_LOGE("[HandleSubscribe] fail: read info failed");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }

    ErrCode result = Subscribe(iface_cast<AnsSubscriberInterface>(subscriber), info);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSubscribe] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSubscribeSelf(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> subscriber = data.ReadRemoteObject();
    if (subscriber == nullptr) {
        ANS_LOGE("[HandleSubscribeSelf] fail: read subscriber failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SubscribeSelf(iface_cast<AnsSubscriberInterface>(subscriber));
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSubscribeSelf] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSubscribeLocalLiveView(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> subscriber = data.ReadRemoteObject();
    if (subscriber == nullptr) {
        ANS_LOGE("[HandleSubscribeLocalLiveView] fail: read subscriber failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool subcribeInfo = false;
    if (!data.ReadBool(subcribeInfo)) {
        ANS_LOGE("[HandleSubscribeLocalLiveView] fail: read isSubcribeInfo failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<NotificationSubscribeInfo> info = nullptr;
    if (subcribeInfo) {
        info = data.ReadParcelable<NotificationSubscribeInfo>();
        if (info == nullptr) {
            ANS_LOGE("[HandleSubscribeLocalLiveView] fail: read info failed");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }

    bool isNative = false;
    if (!data.ReadBool(isNative)) {
        ANS_LOGE("[HandleSubscribeLocalLiveView] fail: read isNative failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SubscribeLocalLiveView(
        iface_cast<AnsSubscriberLocalLiveViewInterface>(subscriber), info, isNative);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSubscribeLocalLiveView] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleUnsubscribe(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> subscriber = data.ReadRemoteObject();
    if (subscriber == nullptr) {
        ANS_LOGE("[HandleUnsubscribe] fail: read subscriber failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool subcribeInfo = false;
    if (!data.ReadBool(subcribeInfo)) {
        ANS_LOGE("[HandleUnsubscribe] fail: read isSubcribeInfo failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<NotificationSubscribeInfo> info = nullptr;
    if (subcribeInfo) {
        info = data.ReadParcelable<NotificationSubscribeInfo>();
        if (info == nullptr) {
            ANS_LOGE("[HandleUnsubscribe] fail: read info failed");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }

    ErrCode result = Unsubscribe(iface_cast<AnsSubscriberInterface>(subscriber), info);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleUnsubscribe] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleIsAllowedNotify(MessageParcel &data, MessageParcel &reply)
{
    bool allowed = false;
    ErrCode result = IsAllowedNotify(allowed);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleIsAllowedNotify] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteBool(allowed)) {
        ANS_LOGE("[HandleIsAllowedNotify] fail: write allowed failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleIsAllowedNotifySelf(MessageParcel &data, MessageParcel &reply)
{
    bool allowed = false;
    ErrCode result = IsAllowedNotifySelf(allowed);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleIsAllowedNotifySelf] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteBool(allowed)) {
        ANS_LOGE("[HandleIsAllowedNotifySelf] fail: write allowed failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleIsSpecialBundleAllowedNotify(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[IsSpecialBundleAllowedNotify] fail: read bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool allowed = false;
    ErrCode result = IsSpecialBundleAllowedNotify(bundleOption, allowed);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[IsSpecialBundleAllowedNotify] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteBool(allowed)) {
        ANS_LOGE("[IsSpecialBundleAllowedNotify] fail: write allowed failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleCancelGroup(MessageParcel &data, MessageParcel &reply)
{
    std::string groupName;
    if (!data.ReadString(groupName)) {
        ANS_LOGE("[HandleCancelGroup] fail: read groupName failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = CancelGroup(groupName);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleCancelGroup] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleRemoveGroupByBundle(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleRemoveGroupByBundle] fail: read bundleOption failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    std::string groupName;
    if (!data.ReadString(groupName)) {
        ANS_LOGE("[HandleRemoveGroupByBundle] fail: read groupName failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = RemoveGroupByBundle(bundleOption, groupName);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleRemoveGroupByBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleIsDistributedEnabled(MessageParcel &data, MessageParcel &reply)
{
    bool enabled = false;
    ErrCode result = IsDistributedEnabled(enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleIsDistributedEnabled] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteBool(enabled)) {
        ANS_LOGE("[HandleIsDistributedEnabled] fail: write enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleEnableDistributed(MessageParcel &data, MessageParcel &reply)
{
    bool enabled = false;
    if (!data.ReadBool(enabled)) {
        ANS_LOGE("[HandleEnableDistributed] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = EnableDistributed(enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleEnableDistributed] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleEnableDistributedByBundle(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleEnableDistributedByBundle] fail: read bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool enabled = false;
    if (!data.ReadBool(enabled)) {
        ANS_LOGE("[HandleEnableDistributedByBundle] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = EnableDistributedByBundle(bundleOption, enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleEnableDistributedByBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleEnableDistributedSelf(MessageParcel &data, MessageParcel &reply)
{
    bool enabled = false;
    if (!data.ReadBool(enabled)) {
        ANS_LOGE("[HandleEnableDistributedSelf] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = EnableDistributedSelf(enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleEnableDistributedSelf] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleIsDistributedEnableByBundle(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleIsDistributedEnableByBundle] fail: read bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool enabled = false;
    ErrCode result = IsDistributedEnableByBundle(bundleOption, enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleIsDistributedEnableByBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteBool(enabled)) {
        ANS_LOGE("[HandleIsDistributedEnableByBundle] fail: write enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetDeviceRemindType(MessageParcel &data, MessageParcel &reply)
{
    auto rType {NotificationConstant::RemindType::NONE};
    ErrCode result = GetDeviceRemindType(rType);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleGetDeviceRemindType] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteInt32(static_cast<int32_t>(rType))) {
        ANS_LOGE("[HandleGetDeviceRemindType] fail: write remind type failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleShellDump(MessageParcel &data, MessageParcel &reply)
{
    std::string cmd;
    if (!data.ReadString(cmd)) {
        ANS_LOGE("[HandleShellDump] fail: read cmd failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    std::string bundle;
    if (!data.ReadString(bundle)) {
        ANS_LOGE("[HandleShellDump] fail: read bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    int32_t userId;
    if (!data.ReadInt32(userId)) {
        ANS_LOGE("[HandleShellDump] fail: read userId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    int32_t recvUserId;
    if (!data.ReadInt32(recvUserId)) {
        ANS_LOGE("[HandleShellDump] fail: read recvUserId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    std::vector<std::string> notificationsInfo;
    ErrCode result = ShellDump(cmd, bundle, userId, recvUserId, notificationsInfo);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleGetRecentNotificationsInfo] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteStringVector(notificationsInfo)) {
        ANS_LOGE("[HandleGetRecentNotificationsInfo] fail: write notificationsInfo failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandlePublishReminder(MessageParcel &data, MessageParcel &reply)
{
    ANSR_LOGI("HandlePublishReminder");
    uint8_t typeInfo = static_cast<uint8_t>(ReminderRequest::ReminderType::INVALID);
    if (!data.ReadUint8(typeInfo)) {
        ANSR_LOGE("Failed to read reminder type");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    ReminderRequest::ReminderType reminderType = static_cast<ReminderRequest::ReminderType>(typeInfo);
    sptr<ReminderRequest> reminder;
    if (ReminderRequest::ReminderType::ALARM == reminderType) {
        ANSR_LOGD("Publish alarm");
        reminder = data.ReadParcelable<ReminderRequestAlarm>();
    } else if (ReminderRequest::ReminderType::TIMER == reminderType) {
        ANSR_LOGD("Publish timer");
        reminder = data.ReadParcelable<ReminderRequestTimer>();
    } else if (ReminderRequest::ReminderType::CALENDAR == reminderType) {
        ANSR_LOGD("Publish calendar");
        reminder = data.ReadParcelable<ReminderRequestCalendar>();
    } else {
        ANSR_LOGE("Reminder type invalid");
        return ERR_ANS_INVALID_PARAM;
    }
    if (!reminder) {
        ANSR_LOGE("Reminder ReadParcelable failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = PublishReminder(reminder);

    if (!reply.WriteInt32(reminder->GetReminderId())) {
        ANSR_LOGE("Write back reminderId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!reply.WriteInt32(result)) {
        ANSR_LOGE("Write back result failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerStub::HandleCancelReminder(MessageParcel &data, MessageParcel &reply)
{
    ANSR_LOGI("HandleCancelReminder");
    int32_t reminderId = -1;
    if (!data.ReadInt32(reminderId)) {
        ANSR_LOGE("Read reminder id failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = CancelReminder(reminderId);
    if (!reply.WriteInt32(result)) {
        ANSR_LOGE("Write back result failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerStub::HandleCancelAllReminders(MessageParcel &data, MessageParcel &reply)
{
    ErrCode result = CancelAllReminders();
    if (!reply.WriteInt32(result)) {
        ANSR_LOGE("Write back result failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerStub::HandleGetValidReminders(MessageParcel &data, MessageParcel &reply)
{
    ANSR_LOGI("HandleGetValidReminders");
    std::vector<sptr<ReminderRequest>> validReminders;
    ErrCode result = GetValidReminders(validReminders);

    ANSR_LOGD("Write back size=%{public}zu", validReminders.size());
    if (!reply.WriteUint8(static_cast<uint8_t>(validReminders.size()))) {
        ANSR_LOGE("Write back reminder count failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    for (auto it = validReminders.begin(); it != validReminders.end(); ++it) {
        sptr<ReminderRequest> reminder = (*it);
        uint8_t reminderType = static_cast<uint8_t>(reminder->GetReminderType());
        ANSR_LOGD("ReminderType=%{public}d", reminderType);
        if (!reply.WriteUint8(reminderType)) {
            ANSR_LOGW("Write reminder type failed");
            return ERR_ANS_PARCELABLE_FAILED;
        }
        if (!reply.WriteParcelable(reminder)) {
            ANSR_LOGW("Write reminder parcelable failed");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }
    if (!reply.WriteInt32(result)) {
        ANSR_LOGE("Write back result failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerStub::HandleAddExcludeDate(MessageParcel &data, MessageParcel &reply)
{
    ANSR_LOGI("HandleAddExcludeDate");
    int32_t reminderId = -1;
    if (!data.ReadInt32(reminderId)) {
        ANSR_LOGE("Read reminder id failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    uint64_t date = 0;
    if (!data.ReadUint64(date)) {
        ANSR_LOGE("Read exclude date failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = AddExcludeDate(reminderId, date);
    if (!reply.WriteInt32(result)) {
        ANSR_LOGE("Write back result failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerStub::HandleDelExcludeDates(MessageParcel &data, MessageParcel &reply)
{
    ANSR_LOGI("HandleDelExcludeDates");
    int32_t reminderId = -1;
    if (!data.ReadInt32(reminderId)) {
        ANSR_LOGE("Read reminder id failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = DelExcludeDates(reminderId);
    if (!reply.WriteInt32(result)) {
        ANSR_LOGE("Write back result failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerStub::HandleGetExcludeDates(MessageParcel &data, MessageParcel &reply)
{
    ANSR_LOGI("HandleGetExcludeDates");
    int32_t reminderId = -1;
    if (!data.ReadInt32(reminderId)) {
        ANSR_LOGE("Read reminder id failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    std::vector<uint64_t> dates;
    ErrCode result = GetExcludeDates(reminderId, dates);
    ANSR_LOGD("Write back size=%{public}zu", dates.size());
    if (!reply.WriteUint8(static_cast<uint8_t>(dates.size()))) {
        ANSR_LOGE("Write back exclude date count failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    for (const auto date : dates) {
        if (!reply.WriteUint64(date)) {
            ANSR_LOGW("Write exclude date failed");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }
    if (!reply.WriteInt32(result)) {
        ANSR_LOGE("Write back result failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerStub::HandleIsSupportTemplate(MessageParcel &data, MessageParcel &reply)
{
    std::string templateName;
    if (!data.ReadString(templateName)) {
        ANS_LOGE("[HandleIsSupportTemplate] fail: read template name failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    bool support = false;
    ErrCode result = IsSupportTemplate(templateName, support);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleIsSupportTemplate] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!reply.WriteBool(support)) {
        ANS_LOGE("[HandleIsSupportTemplate] fail: write support failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleIsSpecialUserAllowedNotifyByUser(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!data.ReadInt32(userId)) {
        ANS_LOGE("[HandleIsSpecialUserAllowedNotifyByUser] fail: read userId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool allowed = false;
    ErrCode result = IsSpecialUserAllowedNotify(userId, allowed);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleIsSpecialUserAllowedNotifyByUser] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteBool(allowed)) {
        ANS_LOGE("[HandleIsSpecialUserAllowedNotifyByUser] fail: write allowed failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSetNotificationsEnabledByUser(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!data.ReadInt32(userId)) {
        ANS_LOGE("[HandleSetNotificationsEnabledByUser] fail: read userId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool enabled = false;
    if (!data.ReadBool(enabled)) {
        ANS_LOGE("[HandleSetNotificationsEnabledByUser] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetNotificationsEnabledByUser(userId, enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetNotificationsEnabledByUser] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleDeleteAllByUser(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!data.ReadInt32(userId)) {
        ANS_LOGE("[HandleDeleteAllByUser] fail: read userId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = DeleteAllByUser(userId);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleDeleteAllByUser] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSetDoNotDisturbDateByUser(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!data.ReadInt32(userId)) {
        ANS_LOGE("[HandleSetDoNotDisturbDateByUser] fail: read userId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<NotificationDoNotDisturbDate> date = data.ReadParcelable<NotificationDoNotDisturbDate>();
    if (date == nullptr) {
        ANS_LOGE("[HandleSetDoNotDisturbDateByUser] fail: read date failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetDoNotDisturbDate(userId, date);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetDoNotDisturbDateByUser] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetDoNotDisturbDateByUser(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!data.ReadInt32(userId)) {
        ANS_LOGE("[HandleGetDoNotDisturbDateByUser] fail: read userId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<NotificationDoNotDisturbDate> date = nullptr;
    ErrCode result = GetDoNotDisturbDate(userId, date);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleGetDoNotDisturbDateByUser] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (result == ERR_OK) {
        if (!reply.WriteParcelable(date)) {
            ANS_LOGE("[HandleGetDoNotDisturbDateByUser] fail: write date failed.");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSetEnabledForBundleSlot(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadStrongParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleSetEnabledForBundleSlot] fail: read bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t type = 0;
    if (!data.ReadInt32(type)) {
        ANS_LOGE("[HandleSetEnabledForBundleSlot] fail: read slot type failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(type);

    bool enabled = false;
    if (!data.ReadBool(enabled)) {
        ANS_LOGE("[HandleSetEnabledForBundleSlot] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool isForceControl = false;
    if (!data.ReadBool(isForceControl)) {
        ANS_LOGE("[HandleSetEnabledForBundleSlot] fail: read isForceControl failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetEnabledForBundleSlot(bundleOption, slotType, enabled, isForceControl);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetEnabledForBundleSlot] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetEnabledForBundleSlot(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadStrongParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleGetEnabledForBundleSlot] fail: read bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t type = 0;
    if (!data.ReadInt32(type)) {
        ANS_LOGE("[HandleGetEnabledForBundleSlot] fail: read slot type failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(type);

    bool enabled = false;
    ErrCode result = GetEnabledForBundleSlot(bundleOption, slotType, enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleGetEnabledForBundleSlot] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteBool(enabled)) {
        ANS_LOGE("[HandleGetEnabledForBundleSlot] fail: write enabled failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetEnabledForBundleSlotSelf(MessageParcel &data, MessageParcel &reply)
{
    int32_t type = 0;
    if (!data.ReadInt32(type)) {
        ANS_LOGE("[HandleGetEnabledForBundleSlotSelf] fail: read slot type failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(type);

    bool enabled = false;
    ErrCode result = GetEnabledForBundleSlotSelf(slotType, enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleGetEnabledForBundleSlotSelf] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteBool(enabled)) {
        ANS_LOGE("[HandleGetEnabledForBundleSlotSelf] fail: write enabled failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleDistributedSetEnabledWithoutApp(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!data.ReadInt32(userId)) {
        ANS_LOGE("[HandleDistributedSetEnabledWithoutApp] fail: read userId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool enabled = false;
    if (!data.ReadBool(enabled)) {
        ANS_LOGE("[HandleDistributedSetEnabledWithoutApp] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetSyncNotificationEnabledWithoutApp(userId, enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleDistributedSetEnabledWithoutApp] fail: write result failed, ErrCode=%{public}d",
            result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleDistributedGetEnabledWithoutApp(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!data.ReadInt32(userId)) {
        ANS_LOGE("[HandleDistributedGetEnabledWithoutApp] fail: read userId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool enabled = false;
    ErrCode result = GetSyncNotificationEnabledWithoutApp(userId, enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleDistributedGetEnabledWithoutApp] fail: write result failed, ErrCode=%{public}d",
            result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteBool(enabled)) {
        ANS_LOGE("[HandleDistributedGetEnabledWithoutApp] fail: write enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSetBadgeNumber(MessageParcel &data, MessageParcel &reply)
{
    ANSR_LOGI("HandleSetBadgeNumber");
    int32_t badgeNumber = -1;
    if (!data.ReadInt32(badgeNumber)) {
        ANSR_LOGE("Read badge number failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetBadgeNumber(badgeNumber);
    if (!reply.WriteInt32(result)) {
        ANSR_LOGE("Write badge number failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerStub::HandleSetBadgeNumberByBundle(MessageParcel &data, MessageParcel &reply)
{
    ANS_LOGD("Called.");
    sptr<NotificationBundleOption> bundleOption = data.ReadParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("Read bundle option failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    int32_t badgeNumber = 0;
    if (!data.ReadInt32(badgeNumber)) {
        ANS_LOGE("Read badge number failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetBadgeNumberByBundle(bundleOption, badgeNumber);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("Write result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerStub::HandleGetAllNotificationEnableStatus(MessageParcel &data, MessageParcel &reply)
{
    std::vector<NotificationBundleOption> bundleOption;
    ErrCode result = GetAllNotificationEnabledBundles(bundleOption);
    int32_t vectorSize = bundleOption.size();
    if (vectorSize > MAX_STATUS_VECTOR_NUM) {
        ANS_LOGE("Bundle bundleOption vector is over size.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteInt32(result)) {
        ANS_LOGE("Write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteInt32(vectorSize)) {
        ANS_LOGE("Write bundleOption size failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    for (const auto &item : bundleOption) {
        if (!reply.WriteParcelable(&item)) {
            ANS_LOGE("Write bundleOption failed");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleRegisterPushCallback(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> pushCallBack = data.ReadRemoteObject();
    if (pushCallBack == nullptr) {
        ANS_LOGE("fail: read JSPushCallBack failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<NotificationCheckRequest> notificationCheckRequest = data.ReadParcelable<NotificationCheckRequest>();
    if (notificationCheckRequest == nullptr) {
        ANS_LOGE("fail: read notificationCheckRequest failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = RegisterPushCallback(pushCallBack, notificationCheckRequest);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerStub::HandleUnregisterPushCallback(MessageParcel &data, MessageParcel &reply)
{
    ErrCode result = UnregisterPushCallback();
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerStub::HandleAddDoNotDisturbProfiles(MessageParcel &data, MessageParcel &reply)
{
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    if (!ReadParcelableVector(profiles, data)) {
        ANS_LOGE("Read profiles failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (profiles.size() > MAX_STATUS_VECTOR_NUM) {
        ANS_LOGE("The profiles is exceeds limit.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = AddDoNotDisturbProfiles(profiles);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("Write result failed, ErrCode is %{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSetDistributedEnabledByBundle(MessageParcel &data, MessageParcel &reply)
{
    ANS_LOGD("enter");
    sptr<NotificationBundleOption> bundleOption = data.ReadParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleSetNotificationsEnabledForSpecialBundle] fail: read bundleOption failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    std::string deviceType;
    if (!data.ReadString(deviceType)) {
        ANS_LOGE("[HandleSetNotificationsEnabledForSpecialBundle] fail: read deviceId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool enabled = false;
    if (!data.ReadBool(enabled)) {
        ANS_LOGE("[HandleSetNotificationsEnabledForSpecialBundle] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetDistributedEnabledByBundle(bundleOption, deviceType, enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE(
            "[HandleSetNotificationsEnabledForSpecialBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleRemoveDoNotDisturbProfiles(MessageParcel &data, MessageParcel &reply)
{
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    if (!ReadParcelableVector(profiles, data)) {
        ANS_LOGE("Read profiles failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (profiles.size() > MAX_STATUS_VECTOR_NUM) {
        ANS_LOGE("The profiles is exceeds limit.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = RemoveDoNotDisturbProfiles(profiles);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("Write result failed, ErrCode is %{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleIsDistributedEnabledByBundle(MessageParcel &data, MessageParcel &reply)
{
    ANS_LOGD("enter");
    sptr<NotificationBundleOption> bundleOption = data.ReadParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleIsDistributedEnabledByBundle] fail: read bundleOption failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    std::string deviceType;
    if (!data.ReadString(deviceType)) {
        ANS_LOGE("[HandleIsDistributedEnabledByBundle] fail: read deviceId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    
    bool enabled = false;
    ErrCode result = IsDistributedEnabledByBundle(bundleOption, deviceType, enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE(
            "[HandleIsDistributedEnabledByBundle] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
  
    if (!reply.WriteBool(enabled)) {
        ANS_LOGE("[HandleIsDistributedEnabledByBundle] fail: write enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSetAdditionConfig(MessageParcel &data, MessageParcel &reply)
{
    std::string key;
    if (!data.ReadString(key)) {
        ANS_LOGE("Failed to read key.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    std::string value;
    if (!data.ReadString(value)) {
        ANS_LOGE("Failed to read value.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetAdditionConfig(key, value);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("Failed to write result, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerStub::HandleSetSmartReminderEnabled(MessageParcel &data, MessageParcel &reply)
{
    ANS_LOGD("enter");
    std::string deviceType;
    if (!data.ReadString(deviceType)) {
        ANS_LOGE("[HandleSetSmartReminderEnabled] fail: read deviceId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool enabled = false;
    if (!data.ReadBool(enabled)) {
        ANS_LOGE("[HandleSetSmartReminderEnabled] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetSmartReminderEnabled(deviceType, enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE(
            "[HandleSetSmartReminderEnabled] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleCancelAsBundleWithAgent(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationBundleOption> bundleOption = data.ReadParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("Read bundleOption failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t id = 0;
    if (!data.ReadInt32(id)) {
        ANS_LOGE("Read notification id failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = CancelAsBundleWithAgent(bundleOption, id);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("Write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerStub::HandleIsSmartReminderEnabled(MessageParcel &data, MessageParcel &reply)
{
    ANS_LOGD("enter");
    std::string deviceType;
    if (!data.ReadString(deviceType)) {
        ANS_LOGE("[HandleIsSmartReminderEnabled] fail: read deviceId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    
    bool enabled = false;
    ErrCode result = IsSmartReminderEnabled(deviceType, enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleIsSmartReminderEnabled] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
  
    if (!reply.WriteBool(enabled)) {
        ANS_LOGE("[HandleIsSmartReminderEnabled] fail: write enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSetTargetDeviceStatus(MessageParcel &data, MessageParcel &reply)
{
    std::string deviceType;
    if (!data.ReadString(deviceType)) {
        ANS_LOGE("[HandleSetTargetDeviceStatus] fail: read deviceType failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t status = 0;
    if (!data.ReadInt32(status)) {
        ANS_LOGE("[HandleSetTargetDeviceStatus] fail: read status failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetTargetDeviceStatus(deviceType, status);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetTargetDeviceStatus] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
ErrCode AnsManagerStub::HandleRegisterSwingCallback(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> swingCallBack = data.ReadRemoteObject();
    if (swingCallBack == nullptr) {
        ANS_LOGE("fail: read SwingCallBack failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = RegisterSwingCallback(swingCallBack);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}
#endif
}  // namespace Notification
}  // namespace OHOS
