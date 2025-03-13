/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include <unistd.h>

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_subscriber_local_live_view_interface.h"
#include "distributed_notification_service_ipc_interface_code.h"
#include "message_option.h"
#include "message_parcel.h"
#include "parcel.h"
#include "ans_manager_proxy.h"

namespace OHOS {
namespace Notification {
ErrCode AnsManagerProxy::SetNotificationBadgeNum(int32_t num)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[SetNotificationBadgeNum] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(num)) {
        ANS_LOGE("[SetNotificationBadgeNum] fail: write num failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SET_NOTIFICATION_BADGE_NUM, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[SetNotificationBadgeNum] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[SetNotificationBadgeNum] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetBundleImportance(int32_t &importance)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetBundleImportance] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_BUNDLE_IMPORTANCE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetBundleImportance] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[GetBundleImportance] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadInt32(importance)) {
        ANS_LOGE("[GetBundleImportance] fail: read importance failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::HasNotificationPolicyAccessPermission(bool &granted)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[HasNotificationPolicyAccessPermission] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::IS_NOTIFICATION_POLICY_ACCESS_GRANTED,
        option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[HasNotificationPolicyAccessPermission] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[HasNotificationPolicyAccessPermission] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadBool(granted)) {
        ANS_LOGE("[HasNotificationPolicyAccessPermission] fail: read granted failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::RequestEnableNotification(const std::string &deviceId,
    const sptr<IAnsDialogCallback> &callback,
    const sptr<IRemoteObject> &callerToken)
{
    ANS_LOGD("enter");
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[RequestEnableNotification] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(deviceId)) {
        ANS_LOGE("[RequestEnableNotification] fail: write deviceId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (callback == nullptr || !data.WriteRemoteObject(callback->AsObject())) {
        ANS_LOGE("[RequestEnableNotification] fail: write callback failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteBool(callerToken != nullptr)) {
        ANS_LOGE("fail: write callerToken failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (callerToken != nullptr) {
        if (!data.WriteRemoteObject(callerToken)) {
            ANS_LOGE("fail: write callerToken failed");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::REQUEST_ENABLE_NOTIFICATION, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[RequestEnableNotification] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[RequestEnableNotification] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerProxy::RequestEnableNotification(const std::string bundleName, const int32_t uid)
{
    ANS_LOGD("enter");
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[RequestEnableNotification] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(bundleName)) {
        ANS_LOGE("[RequestEnableNotification] fail: write bundleName failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(uid)) {
        ANS_LOGE("[RequestEnableNotification] fail: write uid failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::REQUEST_ENABLE_NOTIFICATION_BY_BUNDLE,
        option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[RequestEnableNotification] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[RequestEnableNotification] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerProxy::SetNotificationsEnabledForBundle(const std::string &deviceId, bool enabled)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[SetNotificationsEnabledForBundle] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(deviceId)) {
        ANS_LOGE("[SetNotificationsEnabledForBundle] fail: write deviceId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteBool(enabled)) {
        ANS_LOGE("[SetNotificationsEnabledForBundle] fail: write enabled failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SET_NOTIFICATION_ENABLED_FOR_BUNDLE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[SetNotificationsEnabledForBundle] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[SetNotificationsEnabledForBundle] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::SetNotificationsEnabledForAllBundles(const std::string &deviceId, bool enabled)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[SetNotificationsEnabledForAllBundles] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(deviceId)) {
        ANS_LOGE("[SetNotificationsEnabledForAllBundles] fail: write deviceId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteBool(enabled)) {
        ANS_LOGE("[SetNotificationsEnabledForAllBundles] fail: write enabled failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SET_NOTIFICATION_ENABLED_FOR_ALL_BUNDLE,
        option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[SetNotificationsEnabledForAllBundles] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[SetNotificationsEnabledForAllBundles] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::SetNotificationsEnabledForSpecialBundle(
    const std::string &deviceId, const sptr<NotificationBundleOption> &bundleOption, bool enabled)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[SetNotificationsEnabledForSpecialBundle] fail: bundleOption is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[SetNotificationsEnabledForSpecialBundle] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(deviceId)) {
        ANS_LOGE("[SetNotificationsEnabledForSpecialBundle] fail: write deviceId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(bundleOption)) {
        ANS_LOGE("[SetNotificationsEnabledForSpecialBundle] fail: write bundleOption failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteBool(enabled)) {
        ANS_LOGE("[SetNotificationsEnabledForSpecialBundle] fail: write enabled failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SET_NOTIFICATION_ENABLED_FOR_SPECIAL_BUNDLE,
        option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[SetNotificationsEnabledForSpecialBundle] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[SetNotificationsEnabledForSpecialBundle] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::SetShowBadgeEnabledForBundle(const sptr<NotificationBundleOption> &bundleOption, bool enabled)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[SetShowBadgeEnabledForBundle] fail: bundle is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[SetShowBadgeEnabledForBundle] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(bundleOption)) {
        ANS_LOGE("[SetShowBadgeEnabledForBundle] fail:: write bundle failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteBool(enabled)) {
        ANS_LOGE("[SetShowBadgeEnabledForBundle] fail:: write enabled failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SET_SHOW_BADGE_ENABLED_FOR_BUNDLE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[SetShowBadgeEnabledForBundle] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[SetShowBadgeEnabledForBundle] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetShowBadgeEnabledForBundle(const sptr<NotificationBundleOption> &bundleOption, bool &enabled)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[GetShowBadgeEnabledForBundle] fail: bundle is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetShowBadgeEnabledForBundle] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(bundleOption)) {
        ANS_LOGE("[GetShowBadgeEnabledForBundle] fail:: write bundle failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_SHOW_BADGE_ENABLED_FOR_BUNDLE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetShowBadgeEnabledForBundle] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[GetShowBadgeEnabledForBundle] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadBool(enabled)) {
        ANS_LOGE("[GetShowBadgeEnabledForBundle] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetShowBadgeEnabled(bool &enabled)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetShowBadgeEnabled] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_SHOW_BADGE_ENABLED, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetShowBadgeEnabled] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[GetShowBadgeEnabled] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadBool(enabled)) {
        ANS_LOGE("[GetShowBadgeEnabled] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::IsAllowedNotify(bool &allowed)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[IsAllowedNotify] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::IS_ALLOWED_NOTIFY, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[IsAllowedNotify] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[IsAllowedNotify] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadBool(allowed)) {
        ANS_LOGE("[IsAllowedNotify] fail: read allowed failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::IsAllowedNotifySelf(bool &allowed)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[IsAllowedNotifySelf] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::IS_ALLOWED_NOTIFY_SELF, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[IsAllowedNotifySelf] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[IsAllowedNotifySelf] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadBool(allowed)) {
        ANS_LOGE("[IsAllowedNotifySelf] fail: read allowed failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::CanPopEnableNotificationDialog(const sptr<IAnsDialogCallback> &callback,
    bool &canPop, std::string &bundleName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[CanPopEnableNotificationDialog] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (callback == nullptr || !data.WriteRemoteObject(callback->AsObject())) {
        ANS_LOGE("[CanPopEnableNotificationDialog] fail: write callback failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::CAN_POP_ENABLE_NOTIFICATION_DIALOG,
        option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[CanPopEnableNotificationDialog] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[CanPopEnableNotificationDialog] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadBool(canPop)) {
        ANS_LOGE("[CanPopEnableNotificationDialog] fail: read canPop failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!reply.ReadString(bundleName)) {
        ANS_LOGE("[CanPopEnableNotificationDialog] fail: read bundleName failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::RemoveEnableNotificationDialog()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[CanPopEnableNotificationDialog] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::REMOVE_ENABLE_NOTIFICATION_DIALOG,
        option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[RemoveEnableNotificationDialog] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }
    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[CanPopEnableNotificationDialog] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerProxy::IsSpecialBundleAllowedNotify(const sptr<NotificationBundleOption> &bundleOption, bool &allowed)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[IsSpecialBundleAllowedNotify] fail: bundle is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[IsSpecialBundleAllowedNotify] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(bundleOption)) {
        ANS_LOGE("[IsSpecialBundleAllowedNotify] fail: write bundle failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::IS_SPECIAL_BUNDLE_ALLOWED_NOTIFY, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[IsSpecialBundleAllowedNotify] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[IsSpecialBundleAllowedNotify] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadBool(allowed)) {
        ANS_LOGE("[IsSpecialBundleAllowedNotify] fail: read allowed error.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::IsSpecialUserAllowedNotify(const int32_t &userId, bool &allowed)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[IsSpecialUserAllowedNotify] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(userId)) {
        ANS_LOGE("[IsSpecialUserAllowedNotify] fail: write userId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::IS_SPECIAL_USER_ALLOWED_NOTIFY, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[IsSpecialBundleAllowedNotify] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[IsSpecialBundleAllowedNotify] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadBool(allowed)) {
        ANS_LOGE("[IsSpecialBundleAllowedNotify] fail: read allowed failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::SetNotificationsEnabledByUser(const int32_t &userId, bool enabled)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[SetNotificationsEnabledByUser] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(userId)) {
        ANS_LOGE("[SetNotificationsEnabledByUser] fail: write userId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteBool(enabled)) {
        ANS_LOGE("[SetNotificationsEnabledByUser] fail: write enabled failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SET_NOTIFICATION_ENABLED_BY_USER, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[SetNotificationsEnabledByUser] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[SetNotificationsEnabledByUser] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::SetSyncNotificationEnabledWithoutApp(const int32_t userId, const bool enabled)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[SetSyncNotificationEnabledWithoutApp] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(userId)) {
        ANS_LOGE("[SetSyncNotificationEnabledWithoutApp] fail:: write userId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteBool(enabled)) {
        ANS_LOGE("[SetSyncNotificationEnabledWithoutApp] fail: write enabled failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SET_SYNC_NOTIFICATION_ENABLED_WITHOUT_APP,
        option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[SetSyncNotificationEnabledWithoutApp] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[SetSyncNotificationEnabledWithoutApp] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetSyncNotificationEnabledWithoutApp(const int32_t userId, bool &enabled)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetSyncNotificationEnabledWithoutApp] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(userId)) {
        ANS_LOGE("[GetSyncNotificationEnabledWithoutApp] fail:: write userId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_SYNC_NOTIFICATION_ENABLED_WITHOUT_APP,
        option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetSyncNotificationEnabledWithoutApp] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[GetSyncNotificationEnabledWithoutApp] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadBool(enabled)) {
        ANS_LOGE("[GetSyncNotificationEnabledWithoutApp] fail: read enable failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::SetBadgeNumber(int32_t badgeNumber, const std::string &instanceKey)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[SetBadgeNumber] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(badgeNumber)) {
        ANS_LOGE("[SetBadgeNumber] fail:: write badgeNumber failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(instanceKey)) {
        ANS_LOGE("[SetBadgeNumber] fail:: write instancekey failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SET_BADGE_NUMBER, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[SetBadgeNumber] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[SetBadgeNumber] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::SetBadgeNumberByBundle(const sptr<NotificationBundleOption> &bundleOption, int32_t badgeNumber)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("Bundle is empty.");
        return ERR_ANS_INVALID_PARAM;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("Write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!data.WriteParcelable(bundleOption)) {
        ANS_LOGE("Write bundle option failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!data.WriteInt32(badgeNumber)) {
        ANS_LOGE("Write badge number failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    ErrCode result = InnerTransact(NotificationInterfaceCode::SET_BADGE_NUMBER_BY_BUNDLE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("Transact error code is: %{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }
    if (!reply.ReadInt32(result)) {
        ANS_LOGE("Read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerProxy::GetAllNotificationEnabledBundles(std::vector<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("Called.");
    MessageParcel data;
    int32_t vectorSize = 0;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("Write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_ALL_NOTIFICATION_ENABLE_STATUS, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("Fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("Fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadInt32(vectorSize)) {
        ANS_LOGE("Fail: read vectorSize failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (vectorSize > MAX_STATUS_VECTOR_NUM) {
        ANS_LOGE("Bundle status vector is over size");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    for (auto i = 0; i < vectorSize; i++) {
        sptr<NotificationBundleOption> obj = reply.ReadParcelable<NotificationBundleOption>();
        if (obj == nullptr) {
            ANS_LOGE("The obj of Bundle status vector is nullptr.");
            return ERR_ANS_PARCELABLE_FAILED;
        }
        bundleOption.emplace_back(*obj);
    }

    return result;
}

ErrCode AnsManagerProxy::GetAllLiveViewEnabledBundles(std::vector<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("Called.");
    MessageParcel data;
    int32_t vectorSize = 0;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("Write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_ALL_LIVEVIEW_ENABLE_STATUS, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("Fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("Fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadInt32(vectorSize)) {
        ANS_LOGE("Fail: read vectorSize failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (vectorSize > MAX_STATUS_VECTOR_NUM) {
        ANS_LOGE("Bundle status vector is over size");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    for (auto i = 0; i < vectorSize; i++) {
        sptr<NotificationBundleOption> obj = reply.ReadParcelable<NotificationBundleOption>();
        if (obj == nullptr) {
            ANS_LOGE("The obj of Bundle status vector is nullptr.");
            return ERR_ANS_PARCELABLE_FAILED;
        }
        bundleOption.emplace_back(*obj);
    }

    return result;
}

ErrCode AnsManagerProxy::GetAllDistribuedEnabledBundles(const std::string& deviceType,
    std::vector<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("Called.");
    MessageParcel data;
    int32_t vectorSize = 0;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("Write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(deviceType)) {
        ANS_LOGE("[GetAllDistribuedEnabledBundles] fail: write deviceType failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_ALL_DISTRIBUTED_ENABLE_STATUS, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("Fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("Fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadInt32(vectorSize)) {
        ANS_LOGE("Fail: read vectorSize failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (vectorSize > MAX_STATUS_VECTOR_NUM) {
        ANS_LOGE("Bundle status vector is over size");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    for (auto i = 0; i < vectorSize; i++) {
        sptr<NotificationBundleOption> obj = reply.ReadParcelable<NotificationBundleOption>();
        if (obj == nullptr) {
            ANS_LOGE("The obj of Bundle status vector is nullptr.");
            return ERR_ANS_PARCELABLE_FAILED;
        }
        bundleOption.emplace_back(*obj);
    }

    return result;
}
}  // namespace Notification
}  // namespace OHOS
