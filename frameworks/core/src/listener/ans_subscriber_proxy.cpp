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

#include "ans_subscriber_proxy.h"

#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "message_option.h"
#include "message_parcel.h"

namespace OHOS {
namespace Notification {
AnsSubscriberProxy::AnsSubscriberProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<AnsSubscriberInterface>(impl)
{}

AnsSubscriberProxy::~AnsSubscriberProxy()
{}

ErrCode AnsSubscriberProxy::InnerTransact(
    NotificationInterfaceCode code, MessageOption &flags, MessageParcel &data, MessageParcel &reply)
{
    auto remote = Remote();
    if (remote == nullptr) {
        ANS_LOGE("[InnerTransact] fail: get Remote fail code %{public}u", code);
        return ERR_DEAD_OBJECT;
    }

    int32_t err = remote->SendRequest(static_cast<uint32_t>(code), data, reply, flags);
    switch (err) {
        case NO_ERROR: {
            return ERR_OK;
        }
        case DEAD_OBJECT: {
            ANS_LOGE("[InnerTransact] fail: ipcErr=%{public}d code %{public}d", err, code);
            return ERR_DEAD_OBJECT;
        }
        default: {
            ANS_LOGE("[InnerTransact] fail: ipcErr=%{public}d code %{public}d", err, code);
            return ERR_ANS_TRANSACT_FAILED;
        }
    }
}

void AnsSubscriberProxy::OnConnected()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsSubscriberProxy::GetDescriptor())) {
        ANS_LOGE("[OnConnected] fail: write interface token failed.");
        return;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_ASYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ON_CONNECTED, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[OnConnected] fail: transact ErrCode=ERR_ANS_TRANSACT_FAILED");
        return;
    }
}

void AnsSubscriberProxy::OnDisconnected()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsSubscriberProxy::GetDescriptor())) {
        ANS_LOGE("[OnDisconnected] fail: write interface token failed.");
        return;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_ASYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ON_DISCONNECTED, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[OnDisconnected] fail: transact ErrCode=ERR_ANS_TRANSACT_FAILED");
        return;
    }
}

void AnsSubscriberProxy::OnConsumed(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap)
{
    if (notification == nullptr) {
        ANS_LOGE("[OnConsumed] fail: notification is nullptr.");
        return;
    }

    MessageParcel data;
    if (notification->GetNotificationRequestPoint()->IsCommonLiveView()) {
        if (!data.SetMaxCapacity(NotificationConstant::NOTIFICATION_MAX_LIVE_VIEW_SIZE)) {
            ANS_LOGE("[OnConsumed] fail: set max capacity failed.");
            return;
        }
    }
    if (!data.WriteInterfaceToken(AnsSubscriberProxy::GetDescriptor())) {
        ANS_LOGE("[OnConsumed] fail: write interface token failed.");
        return;
    }

    if (!data.WriteParcelable(notification)) {
        ANS_LOGE("[OnConsumed] fail: write notification failed.");
        return;
    }

    if (!data.WriteBool(notificationMap != nullptr)) {
        ANS_LOGE("[OnConsumed] fail: write existMap failed");
        return;
    }

    if (notificationMap != nullptr) {
        if (!data.WriteParcelable(notificationMap)) {
            ANS_LOGE("[OnConsumed] fail: write notificationMap failed");
            return;
        }
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_ASYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ON_CONSUMED_MAP, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[OnConsumed] fail: transact ErrCode=ERR_ANS_TRANSACT_FAILED");
        return;
    }
}

void AnsSubscriberProxy::OnConsumedList(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap)
{
    ANS_LOGD("Start consumed list in proxy.");
    if (notifications.empty() || notificationMap == nullptr) {
        ANS_LOGE("Invalid notification to consumed.");
        return;
    }

    MessageParcel data;
    if (!data.SetMaxCapacity(NotificationConstant::NOTIFICATION_MAX_LIVE_VIEW_SIZE)) {
        ANS_LOGE("[OnConsumedList] fail: set max capacity failed.");
    }
    if (!data.WriteInterfaceToken(AnsSubscriberProxy::GetDescriptor())) {
        ANS_LOGE("Write interface token failed.");
        return;
    }

    if (!WriteParcelableVector(notifications, data)) {
        ANS_LOGE("Write notifications failed");
        return;
    }

    if (!data.WriteBool(notificationMap != nullptr)) {
        ANS_LOGE("Write existMap failed");
        return;
    }

    if (notificationMap != nullptr) {
        if (!data.WriteParcelable(notificationMap)) {
            ANS_LOGE("Write notificationMap failed");
            return;
        }
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_ASYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ON_CONSUMED_LIST_MAP, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("Transact ErrCode=ERR_ANS_TRANSACT_FAILED");
        return;
    }
}

void AnsSubscriberProxy::OnCanceled(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    if (notification == nullptr) {
        ANS_LOGE("[OnCanceled] fail: notification is nullptr.");
        return;
    }

    MessageParcel data;
    if (notification->GetNotificationRequestPoint()->IsCommonLiveView()) {
        if (!data.SetMaxCapacity(NotificationConstant::NOTIFICATION_MAX_LIVE_VIEW_SIZE)) {
            ANS_LOGE("[OnCanceled] fail: set max capacity failed.");
            return;
        }
    }
    if (!data.WriteInterfaceToken(AnsSubscriberProxy::GetDescriptor())) {
        ANS_LOGE("[OnCanceled] fail: write interface token failed.");
        return;
    }

    if (!data.WriteParcelable(notification)) {
        ANS_LOGE("[OnCanceled] fail: write notification failed.");
        return;
    }

    if (!data.WriteBool(notificationMap != nullptr)) {
        ANS_LOGE("[OnCanceled] fail: write existMap failed");
        return;
    }

    if (notificationMap != nullptr) {
        if (!data.WriteParcelable(notificationMap)) {
            ANS_LOGE("[OnCanceled] fail: write notificationMap failed");
            return;
        }
    }

    if (!data.WriteInt32(deleteReason)) {
        ANS_LOGE("[OnCanceled] fail: write deleteReason failed.");
        return;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_ASYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ON_CANCELED_MAP, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[OnCanceled] fail: transact ErrCode=ERR_ANS_TRANSACT_FAILED");
        return;
    }
}

void AnsSubscriberProxy::OnCanceledList(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    if (notifications.empty()) {
        ANS_LOGE("Notifications is empty.");
        return;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsSubscriberProxy::GetDescriptor())) {
        ANS_LOGE("Write interface token failed.");
        return;
    }

    for (size_t i = 0; i < notifications.size(); i ++) {
        sptr<Notification> notification = notifications[i];
        notification->GetNotificationRequestPoint()->SetBigIcon(nullptr);
        notification->GetNotificationRequestPoint()->SetLittleIcon(nullptr);
        notification->GetNotificationRequestPoint()->SetOverlayIcon(nullptr);
    }
    if (!data.SetMaxCapacity(NotificationConstant::NOTIFICATION_MAX_LIVE_VIEW_SIZE)) {
        ANS_LOGE("[OnConsumedList] fail: set max capacity failed.");
    }
    if (!WriteParcelableVector(notifications, data)) {
        ANS_LOGE("Write notifications failed");
        return;
    }

    if (!data.WriteBool(notificationMap != nullptr)) {
        ANS_LOGE("Write existMap failed");
        return;
    }

    if (notificationMap != nullptr) {
        if (!data.WriteParcelable(notificationMap)) {
            ANS_LOGE("Write notificationMap failed");
            return;
        }
    }

    if (!data.WriteInt32(deleteReason)) {
        ANS_LOGE("Write deleteReason failed.");
        return;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_ASYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ON_CANCELED_LIST_MAP, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("Transact ErrCode=ERR_ANS_TRANSACT_FAILED");
        return;
    }
}

void AnsSubscriberProxy::OnUpdated(const sptr<NotificationSortingMap> &notificationMap)
{
    if (notificationMap == nullptr) {
        ANS_LOGE("[OnUpdated] fail: notificationMap is empty.");
        return;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsSubscriberProxy::GetDescriptor())) {
        ANS_LOGE("[OnUpdated] fail: write interface token failed.");
        return;
    }

    if (!data.WriteParcelable(notificationMap)) {
        ANS_LOGE("[OnUpdated] fail: write notificationMap failed.");
        return;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_ASYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ON_UPDATED, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[OnUpdated] fail: transact ErrCode=ERR_ANS_TRANSACT_FAILED");
        return;
    }
}

void AnsSubscriberProxy::OnDoNotDisturbDateChange(const sptr<NotificationDoNotDisturbDate> &date)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsSubscriberProxy::GetDescriptor())) {
        ANS_LOGE("[OnDoNotDisturbDateChange] fail: write interface token failed.");
        return;
    }

    if (!data.WriteParcelable(date)) {
        ANS_LOGE("[OnDoNotDisturbDateChange] fail: write date failed");
        return;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_ASYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ON_DND_DATE_CHANGED, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[OnDoNotDisturbDateChange] fail: transact ErrCode=ERR_ANS_TRANSACT_FAILED");
        return;
    }
}

void AnsSubscriberProxy::OnEnabledNotificationChanged(const sptr<EnabledNotificationCallbackData> &callbackData)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsSubscriberProxy::GetDescriptor())) {
        ANS_LOGE("[OnEnabledNotificationChanged] fail: write interface token failed.");
        return;
    }

    if (!data.WriteParcelable(callbackData)) {
        ANS_LOGE("[OnEnabledNotificationChanged] fail: write callbackData failed");
        return;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_ASYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ON_ENABLED_NOTIFICATION_CHANGED, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[OnEnabledNotificationChanged] fail: transact ErrCode=ERR_ANS_TRANSACT_FAILED");
        return;
    }
}

void AnsSubscriberProxy::OnBadgeChanged(const sptr<BadgeNumberCallbackData> &badgeData)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsSubscriberProxy::GetDescriptor())) {
        ANS_LOGE("[OnBadgeChanged] fail: write interface token failed.");
        return;
    }

    if (!data.WriteParcelable(badgeData)) {
        ANS_LOGE("[OnBadgeChanged] fail: write badgeData failed");
        return;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_ASYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ON_BADGE_CHANGED, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[OnBadgeChanged] fail: transact ErrCode=ERR_ANS_TRANSACT_FAILED");
        return;
    }
}

void AnsSubscriberProxy::OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData)
{
    if (callbackData == nullptr) {
        ANS_LOGE("Callback data is nullptr.");
        return;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsSubscriberProxy::GetDescriptor())) {
        ANS_LOGE("Write interface token failed.");
        return;
    }

    if (!data.WriteParcelable(callbackData)) {
        ANS_LOGE("Write callback data failed.");
        return;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    ErrCode result = InnerTransact(NotificationInterfaceCode::ON_BADGE_ENABLED_CHANGED, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("Transact error code is: %{public}d.", result);
        return;
    }
}

void AnsSubscriberProxy::OnApplicationInfoNeedChanged(const std::string& bundleName)
{
    MessageParcel data;
    ANS_LOGE("OnApplicationInfoNeedChanged  AnsSubscriberProxy 1.");
    if (!data.WriteInterfaceToken(AnsSubscriberProxy::GetDescriptor())) {
        ANS_LOGE("Write interface token failed.");
        return;
    }

    if (!data.WriteString(bundleName)) {
        ANS_LOGE("Write bundleName failed.");
        return;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    ErrCode result = InnerTransact(NotificationInterfaceCode::ON_APPLICATION_INFO_NEED_CHANGED, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("Transact error code is: %{public}d.", result);
        return;
    }
}

ErrCode AnsSubscriberProxy::OnOperationResponse(const sptr<NotificationOperationInfo>& operationInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsSubscriberProxy::GetDescriptor())) {
        ANS_LOGE("Write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(operationInfo)) {
        ANS_LOGE("Write operationInfo failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode result = InnerTransact(NotificationInterfaceCode::ON_RESPONSE_LISTENER, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("Transact error code is: %{public}d.", result);
        return ERR_ANS_TRANSACT_FAILED;
    }
    if (!reply.ReadInt32(result)) {
        ANS_LOGE("AnsSubscriberProxy onresponse fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}
}  // namespace Notification
}  // namespace OHOS
