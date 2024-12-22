/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "distributed_notification_service_ipc_interface_code.h"
#include "message_option.h"
#include "message_parcel.h"
#include "parcel.h"
#include "ans_manager_proxy.h"

namespace OHOS {
namespace Notification {
ErrCode AnsManagerProxy::InnerTransact(NotificationInterfaceCode code,
    MessageOption &flags, MessageParcel &data, MessageParcel &reply)
{
    auto remote = Remote();
    if (remote == nullptr) {
        ANS_LOGE("[InnerTransact] defeat: get Remote defeat code %{public}u", code);
        return ERR_DEAD_OBJECT;
    }
    int32_t err = remote->SendRequest(static_cast<uint32_t>(code), data, reply, flags);
    switch (err) {
        case NO_ERROR: {
            return ERR_OK;
        }
        case DEAD_OBJECT: {
            ANS_LOGE("[InnerTransact] defeat: ipcErr=%{public}d code %{public}d", err, code);
            return ERR_DEAD_OBJECT;
        }
        default: {
            ANS_LOGE("[InnerTransact] defeat: ipcErr=%{public}d code %{public}d", err, code);
            return ERR_ANS_TRANSACT_FAILED;
        }
    }
}

ErrCode AnsManagerProxy::RegisterPushCallback(
    const sptr<IRemoteObject> &pushCallback, const sptr<NotificationCheckRequest> &notificationCheckRequest)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteRemoteObject(pushCallback)) {
        ANS_LOGE("write pushCallback failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(notificationCheckRequest)) {
        ANS_LOGE("write notificationCheckRequest failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    ErrCode result = InnerTransact(NotificationInterfaceCode::REGISTER_PUSH_CALLBACK, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::UnregisterPushCallback()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    ErrCode result = InnerTransact(NotificationInterfaceCode::UNREGISTER_PUSH_CALLBACK, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("Set package config fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(deviceType)) {
        ANS_LOGE("Set package config fail:: write deviceType failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(status)) {
        ANS_LOGE("Set package config fail:: write status failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SET_TARGET_DEVICE_STATUS, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("Transact fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("Set package config fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status,
    const uint32_t controlFlag)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("Set package config fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(deviceType)) {
        ANS_LOGE("Set package config fail:: write deviceType failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(status)) {
        ANS_LOGE("Set package config fail:: write status failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(controlFlag)) {
        ANS_LOGE("Set package config fail:: write controlFlag failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SET_TARGET_DEVICE_STATUS_WITH_FLAG, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("Transact fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("Set package config fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::SetAdditionConfig(const std::string &key, const std::string &value)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("Set package config fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(key)) {
        ANS_LOGE("Set package config fail:: write key failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(value)) {
        ANS_LOGE("Set package config fail:: write value failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SET_NOTIFICATION_AGENT_RELATIONSHIP, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("Transact fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("Set package config fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
ErrCode AnsManagerProxy::RegisterSwingCallback(const sptr<IRemoteObject> &swingCallback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteRemoteObject(swingCallback)) {
        ANS_LOGE("write swingCallback failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    ErrCode result = InnerTransact(NotificationInterfaceCode::REGISTER_SWING_CALLBACK, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}
#endif

ErrCode AnsManagerProxy::SetSmartReminderEnabled(const std::string &deviceType, const bool enabled)
{
    ANS_LOGD("enter");
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[SetSmartReminderEnabled] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(deviceType)) {
        ANS_LOGE("[SetSmartReminderEnabled] fail: write deviceType failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteBool(enabled)) {
        ANS_LOGE("[SetSmartReminderEnabled] fail: write enabled failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SET_SMART_REMINDER_ENABLED, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[SetSmartReminderEnabled] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[SetSmartReminderEnabled] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::IsSmartReminderEnabled(const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("enter");
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[IsSmartReminderEnabled] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(deviceType)) {
        ANS_LOGE("[IsSmartReminderEnabled] fail: write deviceType failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_SMART_REMINDER_ENABLED, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[IsSmartReminderEnabled] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[IsSmartReminderEnabled] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadBool(enabled)) {
        ANS_LOGE("[IsSmartReminderEnabled] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::AllowUseReminder(const std::string& bundleName, bool& isAllowUseReminder)
{
    ANS_LOGD("enter");
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(bundleName)) {
        ANS_LOGE("fail: write bundleName failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ALLOW_USE_REMINDER, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadBool(isAllowUseReminder)) {
        ANS_LOGE("fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::ShellDump(const std::string &cmd, const std::string &bundle, int32_t userId,
    int32_t recvUserId, std::vector<std::string> &dumpInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[ShellDump] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!data.WriteString(cmd)) {
        ANS_LOGE("[ShellDump] fail: write dump cmd failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!data.WriteString(bundle)) {
        ANS_LOGE("[ShellDump] fail: write dump bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!data.WriteInt32(userId)) {
        ANS_LOGE("[ShellDump] fail: write dump userId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!data.WriteInt32(recvUserId)) {
        ANS_LOGE("[ShellDump] fail: write dump recvUserId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SHELL_DUMP, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[ShellDump] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }
    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[ShellDump] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!reply.ReadStringVector(&dumpInfo)) {
        ANS_LOGE("[ShellDump] fail: read dumpInfo failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}
}  // namespace Notification
}  // namespace OHOS
