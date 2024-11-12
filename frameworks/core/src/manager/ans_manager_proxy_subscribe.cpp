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
#include "ans_subscriber_local_live_view_interface.h"
#include "distributed_notification_service_ipc_interface_code.h"
#include "message_option.h"
#include "message_parcel.h"
#include "parcel.h"
#include "ans_manager_proxy.h"

namespace OHOS {
namespace Notification {
ErrCode AnsManagerProxy::RemoveNotification(const sptr<NotificationBundleOption> &bundleOption,
    int32_t notificationId, const std::string &label, int32_t removeReason)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[RemoveNotification] fail: bundle is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[RemoveNotification] fail:, write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteStrongParcelable(bundleOption)) {
        ANS_LOGE("[RemoveNotification] fail:: write bundle failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(notificationId)) {
        ANS_LOGE("[RemoveNotification] fail: write notificationId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(label)) {
        ANS_LOGE("[RemoveNotification] fail: write label failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(removeReason)) {
        ANS_LOGE("[RemoveNotification] fail: write removeReason failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::REMOVE_NOTIFICATION, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[RemoveNotification] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[RemoveNotification] fail: read result error.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::RemoveAllNotifications(const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[RemoveAllNotifications] fail: bundle is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[RemoveAllNotifications] fail:, write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteStrongParcelable(bundleOption)) {
        ANS_LOGE("[RemoveAllNotifications] fail:: write bundle failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::REMOVE_ALL_NOTIFICATIONS, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[RemoveNotification] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[RemoveNotification] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::RemoveNotifications(const std::vector<std::string> &keys, int32_t removeReason)
{
    if (keys.empty()) {
        ANS_LOGE("fail: keys is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("fail:, write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(keys.size())) {
        ANS_LOGE("write keys size failed");
        return false;
    }

    if (!data.WriteStringVector(keys)) {
        ANS_LOGE("fail: write keys failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(removeReason)) {
        ANS_LOGE("fail: write removeReason failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::REMOVE_NOTIFICATIONS_BY_KEYS, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::Subscribe(const sptr<AnsSubscriberInterface> &subscriber,
    const sptr<NotificationSubscribeInfo> &info)
{
    if (subscriber == nullptr) {
        ANS_LOGE("[Subscribe] fail: subscriber is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[Subscribe] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool ret = data.WriteRemoteObject(subscriber->AsObject());
    if (!ret) {
        ANS_LOGE("[Subscribe] fail: write subscriber failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteBool(info != nullptr)) {
        ANS_LOGE("[Subscribe] fail: write isSubcribeInfo failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (info != nullptr) {
        if (!data.WriteParcelable(info)) {
            ANS_LOGE("[Subscribe] fail: write subcribeInfo failed");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SUBSCRIBE_NOTIFICATION, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[Subscribe] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[Subscribe] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::SubscribeSelf(const sptr<AnsSubscriberInterface> &subscriber)
{
    if (subscriber == nullptr) {
        ANS_LOGE("[SubscribeSelf] fail: subscriber is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[SubscribeSelf] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool ret = data.WriteRemoteObject(subscriber->AsObject());
    if (!ret) {
        ANS_LOGE("[SubscribeSelf] fail: write subscriber failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SUBSCRIBE_NOTIFICATION_SELF, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[SubscribeSelf] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[SubscribeSelf] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::SubscribeLocalLiveView(const sptr<AnsSubscriberLocalLiveViewInterface> &subscriber,
    const sptr<NotificationSubscribeInfo> &info, const bool isNative)
{
    if (subscriber == nullptr) {
        ANS_LOGE("[SubscribeLocalLiveView] fail: subscriber is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[SubscribeLocalLiveView] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool ret = data.WriteRemoteObject(subscriber->AsObject());
    if (!ret) {
        ANS_LOGE("[SubscribeLocalLiveView] fail: write subscriber failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteBool(info != nullptr)) {
        ANS_LOGE("[SubscribeLocalLiveView] fail: write isSubcribeInfo failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (info != nullptr) {
        if (!data.WriteParcelable(info)) {
            ANS_LOGE("[SubscribeLocalLiveView] fail: write subcribeInfo failed");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }

    if (!data.WriteBool(isNative)) {
        ANS_LOGE("[SubscribeLocalLiveView] fail: write isNative failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SUBSCRIBE_LOCAL_LIVE_VIEW_NOTIFICATION,
        option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[Subscribe] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[Subscribe] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerProxy::Unsubscribe(
    const sptr<AnsSubscriberInterface> &subscriber, const sptr<NotificationSubscribeInfo> &info)
{
    if (subscriber == nullptr) {
        ANS_LOGE("[Unsubscribe] fail: subscriber is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[Unsubscribe] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool ret = data.WriteRemoteObject(subscriber->AsObject());
    if (!ret) {
        ANS_LOGE("[Unsubscribe] fail: write subscriber failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteBool(info != nullptr)) {
        ANS_LOGE("[Unsubscribe] fail: write isSubcribeInfo failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (info != nullptr) {
        if (!data.WriteParcelable(info)) {
            ANS_LOGE("[Unsubscribe] fail: write subcribeInfo failed");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::UNSUBSCRIBE_NOTIFICATION, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[Unsubscribe] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[Unsubscribe] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}
}  // namespace Notification
}  // namespace OHOS
