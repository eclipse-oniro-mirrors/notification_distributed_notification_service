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

#include <unistd.h>

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_subscriber_local_live_view_interface.h"
#include "distributed_notification_service_ipc_interface_code.h"
#include "message_option.h"
#include "message_parcel.h"
#include "notification_bundle_option.h"
#include "parcel.h"
#include "ans_manager_proxy.h"

namespace OHOS {
namespace Notification {
AnsManagerProxy::AnsManagerProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<AnsManagerInterface>(impl)
{}

AnsManagerProxy::~AnsManagerProxy()
{}

ErrCode AnsManagerProxy::Publish(const std::string &label, const sptr<NotificationRequest> &notification)
{
    if (notification == nullptr) {
        ANS_LOGE("[Publish] fail: notification is null ptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ANS_LOGD("Publish instanceKey: %{public}s", notification->GetAppInstanceKey().c_str());
    MessageParcel data;
    if (notification->IsCommonLiveView()) {
        if (!data.SetMaxCapacity(NotificationConstant::NOTIFICATION_MAX_LIVE_VIEW_SIZE)) {
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[Publish] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(label)) {
        ANS_LOGE("[Publish] fail: write label failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(notification)) {
        ANS_LOGE("[Publish] fail: write notification parcelable failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::PUBLISH_NOTIFICATION, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[Publish] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[Publish] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::PublishNotificationForIndirectProxy(const sptr<NotificationRequest> &notification)
{
    if (notification == nullptr) {
        ANS_LOGE("[PublishNotificationForIndirectProxy] fail: notification is null ptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ANS_LOGD("PublishNotificationForIndirectProxy instanceKey: %{public}s", notification->GetAppInstanceKey().c_str());
    MessageParcel data;
    if (notification->IsCommonLiveView()) {
        if (!data.SetMaxCapacity(NotificationConstant::NOTIFICATION_MAX_LIVE_VIEW_SIZE)) {
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[PublishNotificationForIndirectProxy] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(notification)) {
        ANS_LOGE("[PublishNotificationForIndirectProxy] fail: write notification parcelable failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::PUBLISH_NOTIFICATION_INDIRECTPROXY, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[PublishNotificationForIndirectProxy] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[PublishNotificationForIndirectProxy] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::Cancel(int32_t notificationId, const std::string &label, const std::string &instanceKey)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[Cancel] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(notificationId)) {
        ANS_LOGE("[Cancel] fail: write notificationId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(label)) {
        ANS_LOGE("[Cancel] fail: write label failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(instanceKey)) {
        ANS_LOGE("[Cancel] fail: write instanceKey failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    ANS_LOGD("Cancel instanceKey: %{public}s", instanceKey.c_str());
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::CANCEL_NOTIFICATION, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[Cancel] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[Cancel] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::CancelAll(const std::string &instanceKey)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[CancelAll] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(instanceKey)) {
        ANS_LOGE("[CancelAll] fail: write instanceKey failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    ANS_LOGD("CancelAll instanceKey: %{public}s", instanceKey.c_str());
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::CANCEL_ALL_NOTIFICATIONS, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[CancelAll] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[CancelAll] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::CancelAsBundle(
    int32_t notificationId, const std::string &representativeBundle, int32_t userId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[CancelAsBundle] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(notificationId)) {
        ANS_LOGE("[CancelAsBundle] fail: write notificationId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(representativeBundle)) {
        ANS_LOGE("[CancelAsBundle] fail: write representativeBundle failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(userId)) {
        ANS_LOGE("[CancelAsBundle] fail: write userId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::CANCEL_AS_BUNDLE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[CancelAsBundle] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[CancelAsBundle] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::CancelAsBundle(
    const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[CancelAsBundle] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(bundleOption)) {
        ANS_LOGE("[CancelAsBundle] fail: write BundleOption failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(notificationId)) {
        ANS_LOGE("[CancelAsBundle] fail: write notificationId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::CANCEL_AS_BUNDLE_OPTION, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[CancelAsBundle] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[CancelAsBundle] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::CancelAsBundle(
    const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId, int32_t userId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[CancelAsBundle] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(bundleOption)) {
        ANS_LOGE("[CancelAsBundle] fail: write BundleOption failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(notificationId)) {
        ANS_LOGE("[CancelAsBundle] fail: write notificationId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!data.WriteInt32(userId)) {
        ANS_LOGE("[CancelAsBundle] fail: write notificationId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::CANCEL_AS_BUNDLE_AND_USER, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[CancelAsBundle] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[CancelAsBundle] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetActiveNotifications(
    std::vector<sptr<NotificationRequest>> &notifications, const std::string &instanceKey)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetActiveNotifications] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(instanceKey)) {
        ANS_LOGE("[GetActiveNotifications] fail: write instanceKey failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    ANS_LOGD("GetActiveNotifications instanceKey: %{public}s", instanceKey.c_str());
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_ACTIVE_NOTIFICATIONS, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetActiveNotifications] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!ReadParcelableVector(notifications, reply, result)) {
        ANS_LOGE("[GetActiveNotifications] fail: read notifications failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetActiveNotificationNums(uint64_t &num)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetActiveNotificationNums] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_ACTIVE_NOTIFICATION_NUMS, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetActiveNotificationNums] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[GetActiveNotificationNums] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadUint64(num)) {
        ANS_LOGE("[GetActiveNotificationNums] fail: read notification num failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetAllActiveNotifications(std::vector<sptr<Notification>> &notifications)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetAllActiveNotifications] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_ALL_ACTIVE_NOTIFICATIONS, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetAllActiveNotifications] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!ReadParcelableVector(notifications, reply, result)) {
        ANS_LOGE("[GetAllActiveNotifications] fail: read notifications failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetSpecialActiveNotifications(
    const std::vector<std::string> &key, std::vector<sptr<Notification>> &notifications)
{
    if (key.empty()) {
        ANS_LOGE("[GetSpecialActiveNotifications] fail: key is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetSpecialActiveNotifications] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteStringVector(key)) {
        ANS_LOGE("[GetSpecialActiveNotifications] fail:: write key failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_SPECIAL_ACTIVE_NOTIFICATIONS, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetSpecialActiveNotifications] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!ReadParcelableVector(notifications, reply, result)) {
        ANS_LOGE("[GetSpecialActiveNotifications] fail: read notifications failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetActiveNotificationByFilter(
    const sptr<NotificationBundleOption> &bundleOption, const int32_t notificationId, const std::string &label,
    const std::vector<std::string> extraInfoKeys, sptr<NotificationRequest> &request)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[GetActiveNotificationByFilter] fail: bundle is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetActiveNotificationByFilter] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(bundleOption)) {
        ANS_LOGE("[GetActiveNotificationByFilter] fail: write bundleOption failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(notificationId)) {
        ANS_LOGE("[GetActiveNotificationByFilter] fail: write notificationId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(label)) {
        ANS_LOGE("[GetActiveNotificationByFilter] fail: write label failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteStringVector(extraInfoKeys)) {
        ANS_LOGE("[GetActiveNotificationByFilter] fail:: write extraInfoKeys failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    if (!reply.SetMaxCapacity(NotificationConstant::NOTIFICATION_MAX_LIVE_VIEW_SIZE)) {
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_ACTIVE_NOTIFICATION_BY_FILTER, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetActiveNotificationByFilter] fail: transact ErrCode=%{public}d", result);
        return result;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[GetActiveNotificationByFilter] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    request = reply.ReadParcelable<NotificationRequest>();
    if (request == nullptr) {
        ANS_LOGE("[GetActiveNotificationByFilter] fail: read request is nullptr.");
    }

    return result;
}

ErrCode AnsManagerProxy::CanPublishAsBundle(const std::string &representativeBundle, bool &canPublish)
{
    if (representativeBundle.empty()) {
        ANS_LOGE("[CanPublishAsBundle] fail: representativeBundle is null.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[CanPublishAsBundle] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(representativeBundle)) {
        ANS_LOGE("[CanPublishAsBundle] fail: write representativeBundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::CAN_PUBLISH_AS_BUNDLE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[CanPublishAsBundle] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[CanPublishAsBundle] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadBool(canPublish)) {
        ANS_LOGE("[CanPublishAsBundle] fail: read canPublish failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::PublishAsBundle(
    const sptr<NotificationRequest> notification, const std::string &representativeBundle)
{
    if (notification == nullptr) {
        ANS_LOGE("[PublishAsBundle] fail: notification is null ptr.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (representativeBundle.empty()) {
        ANS_LOGE("[PublishAsBundle] fail: representativeBundle is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (notification->IsCommonLiveView()) {
        if (!data.SetMaxCapacity(NotificationConstant::NOTIFICATION_MAX_LIVE_VIEW_SIZE)) {
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[PublishAsBundle] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(notification)) {
        ANS_LOGE("[PublishAsBundle] fail: write notification failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(representativeBundle)) {
        ANS_LOGE("[PublishAsBundle] fail: write representativeBundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::PUBLISH_AS_BUNDLE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[PublishAsBundle] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[PublishAsBundle] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::TriggerLocalLiveView(const sptr<NotificationBundleOption> &bundleOption,
    const int32_t notificationId, const sptr<NotificationButtonOption> &buttonOption)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[TriggerLocalLiveView] fail: bundle is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[TriggerLocalLiveView] fail:, write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteStrongParcelable(bundleOption)) {
        ANS_LOGE("[TriggerLocalLiveView] fail:: write bundle failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(notificationId)) {
        ANS_LOGE("[TriggerLocalLiveView] fail: write notificationId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteStrongParcelable(buttonOption)) {
        ANS_LOGE("[TriggerLocalLiveView] fail: write label failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::TRIGGER_LOCAL_LIVE_VIEW_NOTIFICATION,
        option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[TriggerLocalLiveView] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[TriggerLocalLiveView] fail: read result error.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::Delete(const std::string &key, int32_t removeReason)
{
    if (key.empty()) {
        ANS_LOGE("[Delete] fail: key is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[Delete] fail:, write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(key)) {
        ANS_LOGE("[Delete] fail:: write key failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(removeReason)) {
        ANS_LOGE("[Delete] fail: write removeReason failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::DELETE_NOTIFICATION, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[Delete] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[Delete] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::DeleteByBundle(const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[DeleteByBundle] fail: bundle is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[DeleteByBundle] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteStrongParcelable(bundleOption)) {
        ANS_LOGE("[DeleteByBundle] fail: write bundle failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::DELETE_NOTIFICATION_BY_BUNDLE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[DeleteByBundle] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[DeleteByBundle] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::DeleteAll()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[DeleteAll] fail:, write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::DELETE_ALL_NOTIFICATIONS, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[DeleteAll] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[DeleteAll] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::CancelGroup(const std::string &groupName, const std::string &instanceKey)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[CancelGroup] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(groupName)) {
        ANS_LOGE("[CancelGroup] fail: write groupName failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(instanceKey)) {
        ANS_LOGE("[CancelGroup] fail: write instanceKey failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    ANS_LOGD("CancelGroup instanceKey: %{public}s", instanceKey.c_str());
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::CANCEL_GROUP, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[CancelGroup] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[CancelGroup] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::RemoveGroupByBundle(
    const sptr<NotificationBundleOption> &bundleOption, const std::string &groupName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[RemoveGroupByBundle] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(bundleOption)) {
        ANS_LOGE("[RemoveGroupByBundle] fail:: write bundleOption failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(groupName)) {
        ANS_LOGE("[RemoveGroupByBundle] fail: write groupName failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::REMOVE_GROUP_BY_BUNDLE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[RemoveGroupByBundle] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[RemoveGroupByBundle] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::PublishContinuousTaskNotification(const sptr<NotificationRequest> &request)
{
    if (request == nullptr) {
        ANS_LOGE("[PublishContinuousTaskNotification] fail: notification request is null ptr.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[PublishContinuousTaskNotification] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(request)) {
        ANS_LOGE("[PublishContinuousTaskNotification] fail: write request failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::PUBLISH_CONTINUOUS_TASK_NOTIFICATION,
        option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[PublishContinuousTaskNotification] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[PublishContinuousTaskNotification] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::CancelContinuousTaskNotification(const std::string &label, int32_t notificationId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[CancelContinuousTaskNotification] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(label)) {
        ANS_LOGE("[CancelContinuousTaskNotification] fail: write label failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(notificationId)) {
        ANS_LOGE("[CancelContinuousTaskNotification] fail: write notificationId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::CANCEL_CONTINUOUS_TASK_NOTIFICATION, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[CancelContinuousTaskNotification] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[CancelContinuousTaskNotification] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::IsSupportTemplate(const std::string &templateName, bool &support)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[IsSupportTemplate] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(templateName)) {
        ANS_LOGE("[IsSupportTemplate] fail: write template name failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::IS_SUPPORT_TEMPLATE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[IsSupportTemplate] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[IsSupportTemplate] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadBool(support)) {
        ANS_LOGE("[IsSupportTemplate] fail: read support failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::DeleteAllByUser(const int32_t &userId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[DeleteAllByUser] fail:, write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(userId)) {
        ANS_LOGE("[DeleteAllByUser] fail: write userId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::DELETE_ALL_NOTIFICATIONS_BY_USER, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[DeleteAllByUser] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[DeleteAllByUser] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::CancelAsBundleWithAgent(const sptr<NotificationBundleOption> &bundleOption, const int32_t id)
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

    if (!data.WriteStrongParcelable(bundleOption)) {
        ANS_LOGE("Write bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(id)) {
        ANS_LOGE("Write notification id failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::CANCEL_AS_BUNDLE_WITH_AGENT, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("Transact fail: ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("Read result error.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::UpdateNotificationTimerByUid(const int32_t uid, const bool isPaused)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(uid)) {
        ANS_LOGE("write uid failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteBool(isPaused)) {
        ANS_LOGE("write isPaused failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    ErrCode result = InnerTransact(NotificationInterfaceCode::UPDATE_NOTIFICATION_TIMER, option, data, reply);
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

ErrCode AnsManagerProxy::DisableNotificationFeature(const sptr<NotificationDisable> &notificationDisable)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(notificationDisable)) {
        ANS_LOGE("write notificationDisable failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    ErrCode result = InnerTransact(NotificationInterfaceCode::DISABLE_NOTIFICATION_FEATURE, option, data, reply);
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

ErrCode AnsManagerProxy::DistributeOperation(const std::string& hashCode)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(hashCode)) {
        ANS_LOGE("write hashCode failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    ErrCode result = InnerTransact(NotificationInterfaceCode::DISTRIBUTE_OPERATION, option, data, reply);
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

ErrCode AnsManagerProxy::GetNotificationRequestByHashCode(
    const std::string& hashCode, sptr<NotificationRequest>& notificationRequest)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(hashCode)) {
        ANS_LOGE("write hashCode failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    ErrCode result =
        InnerTransact(NotificationInterfaceCode::GET_NOTIFICATION_REQUEST_BY_HASHCODE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("transact ErrCode=%{public}d", result);
        return result;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    notificationRequest = reply.ReadParcelable<NotificationRequest>();
    if (notificationRequest == nullptr) {
        ANS_LOGE("read request is nullptr.");
    }
    return result;
}

ErrCode AnsManagerProxy::SetHashCodeRule(const uint32_t type)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(type)) {
        ANS_LOGE("write type failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    ErrCode result =
        InnerTransact(NotificationInterfaceCode::Set_HASH_CODE_RULE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("transact ErrCode=%{public}d", result);
        return result;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}
}  // namespace Notification
}  // namespace OHOS
