/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
#include "disturb_manager.h"
#include "ians_subscriber_local_live_view.h"
#include "message_option.h"
#include "message_parcel.h"
#include "notification_bundle_option.h"
#include "notification_button_option.h"
#include "parcel.h"
#include "reminder_request_alarm.h"
#include "reminder_request_calendar.h"
#include "reminder_request_timer.h"
#include "slot_manager.h"

namespace OHOS {
namespace Notification {
AnsManagerStub::AnsManagerStub() {}

AnsManagerStub::~AnsManagerStub() {}

int32_t AnsManagerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &flags)
{
    std::u16string descriptor = AnsManagerStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        ANS_LOGE("[OnRemoteRequest] fail: invalid interface token!");
        return OBJECT_NULL;
    }
    ANS_LOGE("[OnRemoteRequest] called");
    ErrCode result = NO_ERROR;
    switch (code) {
        case static_cast<uint32_t>(NotificationInterfaceCode::PUBLISH_NOTIFICATION): {
            result = HandlePublish(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::PUBLISH_NOTIFICATION_INDIRECTPROXY): {
            result = HandlePublishNotificationForIndirectProxy(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::CANCEL_NOTIFICATION): {
            result = HandleCancel(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::CANCEL_ALL_NOTIFICATIONS): {
            result = HandleCancelAll(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::CANCEL_AS_BUNDLE_OPTION): {
            result = HandleCancelAsBundleOption(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::CANCEL_AS_BUNDLE_AND_USER): {
            result = HandleCancelAsBundleAndUser(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::CANCEL_AS_BUNDLE): {
            result = HandleCancelAsBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ADD_SLOT_BY_TYPE): {
            result = HandleAddSlotByType(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ADD_SLOTS):
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_ENABLED_FOR_BUNDLE_SLOT): {
            result = DelayedSingleton<SlotManager>::GetInstance()->OnRemoteRequest(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::REMOVE_SLOT_BY_TYPE): {
            result = HandleRemoveSlotByType(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::REMOVE_ALL_SLOTS): {
            result = HandleRemoveAllSlots(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_SLOT_BY_TYPE): {
            result = HandleGetSlotByType(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_SLOTS): {
            result = HandleGetSlots(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_SLOT_NUM_AS_BUNDLE): {
            result = HandleGetSlotNumAsBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_ACTIVE_NOTIFICATIONS): {
            result = HandleGetActiveNotifications(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_ACTIVE_NOTIFICATION_NUMS): {
            result = HandleGetActiveNotificationNums(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_ALL_ACTIVE_NOTIFICATIONS): {
            result = HandleGetAllActiveNotifications(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_SPECIAL_ACTIVE_NOTIFICATIONS): {
            result = HandleGetSpecialActiveNotifications(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_ACTIVE_NOTIFICATION_BY_FILTER): {
            result = HandleGetActiveNotificationByFilter(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::CAN_PUBLISH_AS_BUNDLE): {
            result = HandleCanPublishAsBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::PUBLISH_AS_BUNDLE): {
            result = HandlePublishAsBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_NOTIFICATION_BADGE_NUM): {
            result = HandleSetNotificationBadgeNum(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_BUNDLE_IMPORTANCE): {
            result = HandleGetBundleImportance(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::IS_NOTIFICATION_POLICY_ACCESS_GRANTED): {
            result = HandleIsNotificationPolicyAccessGranted(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::REMOVE_NOTIFICATION): {
            result = HandleRemoveNotification(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::REMOVE_ALL_NOTIFICATIONS): {
            result = HandleRemoveAllNotifications(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::REMOVE_NOTIFICATIONS_BY_KEYS): {
            result = HandleRemoveNotifications(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::DELETE_NOTIFICATION): {
            result = HandleDelete(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::DELETE_NOTIFICATION_BY_BUNDLE): {
            result = HandleDeleteByBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::DELETE_ALL_NOTIFICATIONS): {
            result = HandleDeleteAll(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_SLOTS_BY_BUNDLE): {
            result = HandleGetSlotsByBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::UPDATE_SLOTS): {
            result = HandleUpdateSlots(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::REQUEST_ENABLE_NOTIFICATION): {
            result = HandleRequestEnableNotification(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::REQUEST_ENABLE_NOTIFICATION_BY_BUNDLE): {
            result = HandleRequestEnableNotificationByBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_NOTIFICATION_ENABLED_FOR_BUNDLE): {
            result = HandleSetNotificationsEnabledForBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_NOTIFICATION_ENABLED_FOR_ALL_BUNDLE): {
            result = HandleSetNotificationsEnabledForAllBundles(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_NOTIFICATION_ENABLED_FOR_SPECIAL_BUNDLE): {
            result = HandleSetNotificationsEnabledForSpecialBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_SHOW_BADGE_ENABLED_FOR_BUNDLE): {
            result = HandleSetShowBadgeEnabledForBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_SHOW_BADGE_ENABLED_FOR_BUNDLE): {
            result = HandleGetShowBadgeEnabledForBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_SHOW_BADGE_ENABLED): {
            result = HandleGetShowBadgeEnabled(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SUBSCRIBE_NOTIFICATION): {
            result = HandleSubscribe(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::UNSUBSCRIBE_NOTIFICATION): {
            result = HandleUnsubscribe(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::IS_ALLOWED_NOTIFY): {
            result = HandleIsAllowedNotify(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::IS_ALLOWED_NOTIFY_SELF): {
            result = HandleIsAllowedNotifySelf(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::CAN_POP_ENABLE_NOTIFICATION_DIALOG): {
            result = HandleCanPopEnableNotificationDialog(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::REMOVE_ENABLE_NOTIFICATION_DIALOG): {
            result = HandleRemoveEnableNotificationDialog(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::IS_SPECIAL_BUNDLE_ALLOWED_NOTIFY): {
            result = HandleIsSpecialBundleAllowedNotify(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_DO_NOT_DISTURB_DATE):
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_DO_NOT_DISTURB_DATE):
        case static_cast<uint32_t>(NotificationInterfaceCode::DOES_SUPPORT_DO_NOT_DISTURB_MODE): {
            result = DelayedSingleton<DisturbManager>::GetInstance()->OnRemoteRequest(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::IS_NEED_SILENT_IN_DO_NOT_DISTURB_MODE): {
            result = HandleIsNeedSilentInDoNotDisturbMode(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::CANCEL_GROUP): {
            result = HandleCancelGroup(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::REMOVE_GROUP_BY_BUNDLE): {
            result = HandleRemoveGroupByBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::IS_DISTRIBUTED_ENABLED): {
            result = HandleIsDistributedEnabled(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ENABLE_DISTRIBUTED): {
            result = HandleEnableDistributed(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ENABLE_DISTRIBUTED_BY_BUNDLE): {
            result = HandleEnableDistributedByBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ENABLE_DISTRIBUTED_SELF): {
            result = HandleEnableDistributedSelf(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::IS_DISTRIBUTED_ENABLED_BY_BUNDLE): {
            result = HandleIsDistributedEnableByBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_DEVICE_REMIND_TYPE): {
            result = HandleGetDeviceRemindType(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SHELL_DUMP): {
            result = HandleShellDump(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::PUBLISH_CONTINUOUS_TASK_NOTIFICATION): {
            result = HandlePublishContinuousTaskNotification(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::CANCEL_CONTINUOUS_TASK_NOTIFICATION): {
            result = HandleCancelContinuousTaskNotification(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::IS_SUPPORT_TEMPLATE): {
            result = HandleIsSupportTemplate(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::IS_SPECIAL_USER_ALLOWED_NOTIFY): {
            result = HandleIsSpecialUserAllowedNotifyByUser(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_NOTIFICATION_ENABLED_BY_USER): {
            result = HandleSetNotificationsEnabledByUser(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::DELETE_ALL_NOTIFICATIONS_BY_USER): {
            result = HandleDeleteAllByUser(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_DO_NOT_DISTURB_DATE_BY_USER):
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_DO_NOT_DISTURB_DATE_BY_USER): {
            result = DelayedSingleton<DisturbManager>::GetInstance()->OnRemoteRequest(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_ENABLED_FOR_BUNDLE_SLOT): {
            result = HandleGetEnabledForBundleSlot(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_ENABLED_FOR_BUNDLE_SLOT_SELF): {
            result = HandleGetEnabledForBundleSlotSelf(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_DISTRIBUTED_ENABLED_BY_BUNDLE): {
            result = HandleSetDistributedEnabledByBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_DISTRIBUTED_ENABLED_BY_BUNDLE): {
            result = HandleIsDistributedEnabledByBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_SMART_REMINDER_ENABLED): {
            result = HandleSetSmartReminderEnabled(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_SMART_REMINDER_ENABLED): {
            result = HandleIsSmartReminderEnabled(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_DISTRIBUTED_ENABLED_BY_SLOT): {
            result = HandleSetDistributedEnabledBySlot(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_DISTRIBUTED_ENABLED_BY_SLOT): {
            result = HandleIsDistributedEnabledBySlot(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_SYNC_NOTIFICATION_ENABLED_WITHOUT_APP): {
            result = HandleDistributedSetEnabledWithoutApp(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_SYNC_NOTIFICATION_ENABLED_WITHOUT_APP): {
            result = HandleDistributedGetEnabledWithoutApp(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_BADGE_NUMBER): {
            result = HandleSetBadgeNumber(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_BADGE_NUMBER_BY_BUNDLE): {
            result = HandleSetBadgeNumberByBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_BADGE_NUMBER_FOR_DH_BY_BUNDLE): {
            result = HandleSetBadgeNumberForDhByBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_ALL_NOTIFICATION_ENABLE_STATUS): {
            result = HandleGetAllNotificationEnableStatus(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_ALL_LIVEVIEW_ENABLE_STATUS): {
            result = HandleGetAllLiveViewEnabledBundles(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_ALL_DISTRIBUTED_ENABLE_STATUS): {
            result = HandleGetAllDistributedEnabledBundles(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::REGISTER_PUSH_CALLBACK): {
            result = HandleRegisterPushCallback(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::UNREGISTER_PUSH_CALLBACK): {
            result = HandleUnregisterPushCallback(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SUBSCRIBE_LOCAL_LIVE_VIEW_NOTIFICATION): {
            result = HandleSubscribeLocalLiveView(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::TRIGGER_LOCAL_LIVE_VIEW_NOTIFICATION): {
            result = HandleTriggerLocalLiveView(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SUBSCRIBE_NOTIFICATION_SELF): {
            result = HandleSubscribeSelf(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_SLOTFLAGS_BY_BUNDLE): {
            result = HandleSetSlotFlagsAsBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_SLOTFLAGS_BY_BUNDLE): {
            result = HandleGetSlotFlagsAsBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_NOTIFICATION_AGENT_RELATIONSHIP): {
            result = HandleSetAdditionConfig(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::CANCEL_AS_BUNDLE_WITH_AGENT): {
            result = HandleCancelAsBundleWithAgent(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_SLOT_BY_BUNDLE): {
            result = HandleGetSlotByBundle(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ADD_DO_NOTDISTURB_PROFILES):
        case static_cast<uint32_t>(NotificationInterfaceCode::REMOVE_DO_NOT_DISTURB_PROFILES): {
            result = DelayedSingleton<DisturbManager>::GetInstance()->OnRemoteRequest(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_TARGET_DEVICE_STATUS): {
            result = HandleSetTargetDeviceStatus(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_TARGET_DEVICE_STATUS_WITH_FLAG): {
            result = HandleSetDeviceStatus(data, reply);
            break;
        }
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
        case static_cast<uint32_t>(NotificationInterfaceCode::REGISTER_SWING_CALLBACK): {
            result = HandleRegisterSwingCallback(data, reply);
            break;
        }
#endif
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_DONOTDISTURB_PROFILE): {
            result = DelayedSingleton<DisturbManager>::GetInstance()->OnRemoteRequest(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::UPDATE_NOTIFICATION_TIMER): {
            result = HandleUpdateNotificationTimerByUid(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ALLOW_USE_REMINDER): {
            result = HandleAllowUseReminder(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::DISABLE_NOTIFICATION_FEATURE): {
            result = HandleDisableNotificationFeature(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_TARGET_DEVICE_STATUS): {
            result = HandleGetDeviceStatus(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_NOTIFICATION_REQUEST_BY_HASHCODE): {
            result = HandleGetNotificationRequest(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::Set_HASH_CODE_RULE): {
            result = HandleSetHashCodeRule(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_ALL_NOTIFICATIONS_BY_SLOTTYPE): {
            result = HandleGetAllNotificationsBySlotType(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::REPLY_DISTRIBUTE_OPERATION): {
            result = HandleReplyDistributeOperation(data, reply);
            break;
        }
        default: {
            ANS_LOGE("[OnRemoteRequest] fail: unknown code!");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, flags);
        }
    }
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

ErrCode AnsManagerStub::HandlePublishNotificationForIndirectProxy(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationRequest> notification = data.ReadParcelable<NotificationRequest>();
    if (!notification) {
        ANS_LOGE("[HandlePublishNotificationForIndirectProxy] fail: notification ReadParcelable failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = PublishNotificationForIndirectProxy(notification);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandlePublishNotificationForIndirectProxy] fail: write result failed, ErrCode=%{public}d", result);
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

    std::string appInstanceKey;
    if (!data.ReadString(appInstanceKey)) {
        ANS_LOGE("[HandleCancel] fail: read InstanceKey failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = Cancel(notificationId, label, appInstanceKey);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleCancel] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleCancelAll(MessageParcel &data, MessageParcel &reply)
{
    std::string appInstanceKey;
    if (!data.ReadString(appInstanceKey)) {
        ANS_LOGE("[HandleCancelAll] fail: read instanceKey failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = CancelAll(appInstanceKey);
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
    std::string appInstanceKey;
    if (!data.ReadString(appInstanceKey)) {
        ANS_LOGE("[HandleGetActiveNotifications] fail: read instanceKey failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    std::vector<sptr<NotificationRequest>> notifications;
    ErrCode result = GetActiveNotifications(notifications, appInstanceKey);
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

    if (!reply.SetMaxCapacity(NotificationConstant::NOTIFICATION_MAX_LIVE_VIEW_SIZE)) {
        return ERR_ANS_PARCELABLE_FAILED;
    }
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
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetDoNotDisturbDate(MessageParcel &data, MessageParcel &reply)
{
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleDoesSupportDoNotDisturbMode(MessageParcel &data, MessageParcel &reply)
{
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleIsNeedSilentInDoNotDisturbMode(MessageParcel &data, MessageParcel &reply)
{
    std::string phoneNumber;
    if (!data.ReadString(phoneNumber)) {
        ANS_LOGE("[HandleIsNeedSilentInDoNotDisturbMode] fail: read phoneNumber failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t callerType = 0;
    if (!data.ReadInt32(callerType)) {
        ANS_LOGE("[HandleIsNeedSilentInDoNotDisturbMode] fail: read callerType failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleIsNeedSilentInDoNotDisturbMode] fail: write result failed, ErrCode=%{public}d", result);
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

    ErrCode result = RequestEnableNotification(deviceId, iface_cast<AnsDialogCallback>(callback), callerToken);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleRequestEnableNotification] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleRequestEnableNotificationByBundle(MessageParcel &data, MessageParcel &reply)
{
    ANS_LOGD("enter");
    std::string bundleName;
    if (!data.ReadString(bundleName)) {
        ANS_LOGE("[HandleRequestEnableNotificationByBundle] fail: read bundleName failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t uid = 0;
    if (!data.ReadInt32(uid)) {
        ANS_LOGE("[HandleRequestEnableNotificationByBundle] fail: read uid failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = RequestEnableNotification(bundleName, uid);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleRequestEnableNotificationByBundle] fail: write result failed, ErrCode=%{public}d", result);
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
        ANS_LOGE("[HandleSetNotificationsEnabledForSpecialBundle] fail: write result failed, ErrCode=%{public}d",
            result);
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

    ErrCode result =
        SubscribeLocalLiveView(iface_cast<IAnsSubscriberLocalLiveView>(subscriber), info, isNative);
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

ErrCode AnsManagerStub::HandleCanPopEnableNotificationDialog(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        ANS_LOGE("[HandleCanPopEnableNotificationDialog] fail: read callback failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    bool canPop = false;
    std::string bundleName;
    ErrCode result = CanPopEnableNotificationDialog(iface_cast<AnsDialogCallback>(callback), canPop, bundleName);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleCanPopEnableNotificationDialog] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteBool(canPop)) {
        ANS_LOGE("[HandleCanPopEnableNotificationDialog] fail: write canPop failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!reply.WriteString(bundleName)) {
        ANS_LOGE("[HandleCanPopEnableNotificationDialog] fail: write bundleName failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleRemoveEnableNotificationDialog(MessageParcel &data, MessageParcel &reply)
{
    ErrCode result = RemoveEnableNotificationDialog();
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleRemoveEnableNotificationDialog] fail: write result failed, ErrCode=%{public}d", result);
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

    std::string appInstanceKey;
    if (!data.ReadString(appInstanceKey)) {
        ANS_LOGE("[HandleCancelGroup] fail: read instanceKey failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = CancelGroup(groupName, appInstanceKey);
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
    auto rType{ NotificationConstant::RemindType::NONE };
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
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetDoNotDisturbDateByUser(MessageParcel &data, MessageParcel &reply)
{
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
        ANS_LOGE("[HandleDistributedSetEnabledWithoutApp] fail: write result failed, ErrCode=%{public}d", result);
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
        ANS_LOGE("[HandleDistributedGetEnabledWithoutApp] fail: write result failed, ErrCode=%{public}d", result);
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
    int32_t badgeNumber = -1;
    if (!data.ReadInt32(badgeNumber)) {
        ANSR_LOGE("Read badge number failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    std::string appInstanceKey;
    if (!data.ReadString(appInstanceKey)) {
        ANSR_LOGE("Read instance key failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetBadgeNumber(badgeNumber, appInstanceKey);
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

ErrCode AnsManagerStub::HandleSetBadgeNumberForDhByBundle(MessageParcel &data, MessageParcel &reply)
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

    ErrCode result = SetBadgeNumberForDhByBundle(bundleOption, badgeNumber);
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
ErrCode AnsManagerStub::HandleGetNotificationRequest(MessageParcel &data, MessageParcel &reply)
{
    std::string hashCode;
    if (!data.ReadString(hashCode)) {
        ANS_LOGE("read hashCode failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<NotificationRequest> request;
    ErrCode result = GetNotificationRequestByHashCode(hashCode, request);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteParcelable(request)) {
        ANS_LOGE("get request failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleAddDoNotDisturbProfiles(MessageParcel &data, MessageParcel &reply)
{
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
        ANS_LOGE("[HandleSetNotificationsEnabledForSpecialBundle] fail: write result failed, ErrCode=%{public}d",
            result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleRemoveDoNotDisturbProfiles(MessageParcel &data, MessageParcel &reply)
{
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetAllDistributedEnabledBundles(MessageParcel &data, MessageParcel &reply)
{
    std::string deviceType;
    if (!data.ReadString(deviceType)) {
        ANS_LOGE("[HandleGetAllDistributedEnabledBundles] fail: read deviceType failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    std::vector<NotificationBundleOption> bundleOption;
    ErrCode result = GetAllDistribuedEnabledBundles(deviceType, bundleOption);
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
        ANS_LOGE("[HandleIsDistributedEnabledByBundle] fail: write result failed, ErrCode=%{public}d", result);
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
        ANS_LOGE("[HandleSetSmartReminderEnabled] fail: write result failed, ErrCode=%{public}d", result);
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

ErrCode AnsManagerStub::HandleSetDistributedEnabledBySlot(MessageParcel &data, MessageParcel &reply)
{
    ANS_LOGD("enter");
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(data.ReadInt32());

    std::string deviceType;
    if (!data.ReadString(deviceType)) {
        ANS_LOGE("[HandleSetDistributedEnabledBySlot] fail: read deviceId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool enabled = false;
    if (!data.ReadBool(enabled)) {
        ANS_LOGE("[HandleSetDistributedEnabledBySlot] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetDistributedEnabledBySlot(slotType, deviceType, enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetDistributedEnabledBySlot] fail: write result failed, ErrCode=%{public}d",
            result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetAllLiveViewEnabledBundles(MessageParcel &data, MessageParcel &reply)
{
    std::vector<NotificationBundleOption> bundleOption;
    ErrCode result = GetAllLiveViewEnabledBundles(bundleOption);
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

ErrCode AnsManagerStub::HandleIsDistributedEnabledBySlot(MessageParcel &data, MessageParcel &reply)
{
    ANS_LOGD("enter");
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(data.ReadInt32());

    std::string deviceType;
    if (!data.ReadString(deviceType)) {
        ANS_LOGE("[HandleIsDistributedEnabledBySlot] fail: read deviceId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool enabled = false;
    ErrCode result = IsDistributedEnabledBySlot(slotType, deviceType, enabled);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleIsDistributedEnabledBySlot] fail: write result failed, ErrCode=%{public}d",
            result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!reply.WriteBool(enabled)) {
        ANS_LOGE("[HandleIsDistributedEnabledBySlot] fail: write enabled failed.");
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

    std::string deviceId;
    if (!data.ReadString(deviceId)) {
        ANS_LOGE("[HandleSetTargetDeviceStatus] fail: read deviceId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetTargetDeviceStatus(deviceType, status, deviceId);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetTargetDeviceStatus] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetDoNotDisturbProfile(MessageParcel &data, MessageParcel &reply)
{
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

ErrCode AnsManagerStub::HandleUpdateNotificationTimerByUid(MessageParcel &data, MessageParcel &reply)
{
    int32_t uid = data.ReadInt32();
    bool isPaused = data.ReadBool();
    ErrCode result = UpdateNotificationTimerByUid(uid, isPaused);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleUpdateNotificationTimerByUid] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleAllowUseReminder(MessageParcel &data, MessageParcel &reply)
{
    ANS_LOGD("enter");
    std::string bundleName;
    if (!data.ReadString(bundleName)) {
        ANS_LOGE("fail: read deviceId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool isAllowUseReminder = false;
    ErrCode result = AllowUseReminder(bundleName, isAllowUseReminder);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteBool(isAllowUseReminder)) {
        ANS_LOGE("fail: write enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleDisableNotificationFeature(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationDisable> notificationDisable = data.ReadParcelable<NotificationDisable>();
    ErrCode result = DisableNotificationFeature(notificationDisable);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleDisableNotificationFeature] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSetDeviceStatus(MessageParcel &data, MessageParcel &reply)
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

    int32_t controlFlag = 0;
    if (!data.ReadInt32(controlFlag)) {
        ANS_LOGE("[HandleSetTargetDeviceStatus] fail: read status failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    std::string deviceId;
    if (!data.ReadString(deviceId)) {
        ANS_LOGE("[HandleSetTargetDeviceStatus] fail: read deviceId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetTargetDeviceStatus(deviceType, status, controlFlag, deviceId);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetTargetDeviceStatus] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetDeviceStatus(MessageParcel &data, MessageParcel &reply)
{
    std::string deviceType;
    if (!data.ReadString(deviceType)) {
        ANS_LOGE("[HandleGetDeviceStatus] fail: read deviceType failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t status = 0;
    ErrCode result = GetTargetDeviceStatus(deviceType, status);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleGetDeviceStatus] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!reply.WriteInt32(status)) {
        ANS_LOGE("[HandleGetDeviceStatus] fail: write slot failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleSetHashCodeRule(MessageParcel &data, MessageParcel &reply)
{
    int32_t type = 0;
    if (!data.ReadInt32(type)) {
        ANS_LOGE("[HandleSetHashCodeRule] fail: read type failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetHashCodeRule(type);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetHashCodeRule] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleDistributeOperation(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        ANS_LOGE("remote is nullptr");
        return ERR_INVALID_DATA;
    }

    sptr<OperationCallbackInterface> callback = iface_cast<OperationCallbackInterface>(remote);
    if (callback.GetRefPtr() == nullptr) {
        ANS_LOGE("callback is null");
        return ERR_INVALID_DATA;
    }

    sptr<NotificationOperationInfo> info = nullptr;
    info = data.ReadParcelable<NotificationOperationInfo>();
    if (info == nullptr) {
        ANS_LOGE("[HandleSubscribe] fail: read info failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = DistributeOperation(info, callback);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode AnsManagerStub::HandleReplyDistributeOperation(MessageParcel &data, MessageParcel &reply)
{
    std::string hashCode;
    if (!data.ReadString(hashCode)) {
        ANS_LOGE("read hashCode failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t resultCode = 0;
    if (!data.ReadInt32(resultCode)) {
        ANS_LOGE("read hashCode failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = ReplyDistributeOperation(hashCode, resultCode);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode AnsManagerStub::HandleGetAllNotificationsBySlotType(MessageParcel &data, MessageParcel &reply)
{
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(data.ReadInt32());
    std::vector<sptr<Notification>> notifications;
    ErrCode result = GetAllNotificationsBySlotType(notifications, slotType);

    if (!reply.SetMaxCapacity(NotificationConstant::NOTIFICATION_MAX_LIVE_VIEW_SIZE)) {
        ANS_LOGE("[HandleGetAllActiveNotifications] fail:: set max capacity");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!WriteParcelableVector(notifications, reply, result)) {
        ANS_LOGE("[HandleGetAllActiveNotifications] fail: write notifications failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}
} // namespace Notification
} // namespace OHOS
