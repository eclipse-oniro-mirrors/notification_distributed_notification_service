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

ErrCode AnsManagerProxy::Cancel(int32_t notificationId, const std::string &label, int32_t instanceKey)
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

    if (!data.WriteInt32(instanceKey)) {
        ANS_LOGE("[Cancel] fail: write instanceKey failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

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

ErrCode AnsManagerProxy::CancelAll(int32_t instanceKey)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[CancelAll] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(instanceKey)) {
        ANS_LOGE("[CancelAll] fail: write instanceKey failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

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
    std::vector<sptr<NotificationRequest>> &notifications, int32_t instanceKey)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetActiveNotifications] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(instanceKey)) {
        ANS_LOGE("[GetActiveNotifications] fail: write instanceKey failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

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
    if (!reply.SetMaxCapacity(NotificationConstant::NOTIFICATION_MAX_LIVE_VIEW_SIZE)) {
        ANS_LOGE("[GetAllActiveNotifications] fail:: set max capacity");
        return ERR_ANS_PARCELABLE_FAILED;
    }
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

ErrCode AnsManagerProxy::SetNotificationAgent(const std::string &agent)
{
    if (agent.empty()) {
        ANS_LOGE("[SetNotificationAgent] fail: agent is null.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[SetNotificationAgent] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(agent)) {
        ANS_LOGE("[SetNotificationAgent] fail:: write agent failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SET_NOTIFICATION_AGENT, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[SetNotificationAgent] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[SetNotificationAgent] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetNotificationAgent(std::string &agent)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetNotificationAgent] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_NOTIFICATION_AGENT, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetNotificationAgent] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[GetNotificationAgent] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadString(agent)) {
        ANS_LOGE("[GetNotificationAgent] fail: read agent failed.");
        return ERR_ANS_PARCELABLE_FAILED;
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

ErrCode AnsManagerProxy::RequestEnableNotification(const std::string &deviceId,
    const sptr<AnsDialogCallback> &callback,
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

ErrCode AnsManagerProxy::CanPopEnableNotificationDialog(const sptr<AnsDialogCallback> &callback,
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

ErrCode AnsManagerProxy::CancelGroup(const std::string &groupName, int32_t instanceKey)
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

    if (!data.WriteInt32(instanceKey)) {
        ANS_LOGE("[CancelGroup] fail: write instanceKey failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

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

ErrCode AnsManagerProxy::IsDistributedEnabled(bool &enabled)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[IsDistributedEnabled] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::IS_DISTRIBUTED_ENABLED, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[IsDistributedEnabled] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[IsDistributedEnabled] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadBool(enabled)) {
        ANS_LOGE("[IsDistributedEnabled] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::EnableDistributed(bool enabled)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[EnableDistributed] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteBool(enabled)) {
        ANS_LOGE("[EnableDistributed] fail: write enabled failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ENABLE_DISTRIBUTED, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[EnableDistributed] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[EnableDistributed] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::EnableDistributedByBundle(const sptr<NotificationBundleOption> &bundleOption, bool enabled)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[EnableDistributedByBundle] fail: bundle is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[EnableDistributedByBundle] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(bundleOption)) {
        ANS_LOGE("[EnableDistributedByBundle] fail:: write bundle failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteBool(enabled)) {
        ANS_LOGE("[EnableDistributedByBundle] fail:: write enabled failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ENABLE_DISTRIBUTED_BY_BUNDLE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[EnableDistributedByBundle] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[EnableDistributedByBundle] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::EnableDistributedSelf(bool enabled)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[EnableDistributedSelf] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteBool(enabled)) {
        ANS_LOGE("[EnableDistributedSelf] fail: write enabled failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ENABLE_DISTRIBUTED_SELF, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[EnableDistributedSelf] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[EnableDistributedSelf] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::IsDistributedEnableByBundle(const sptr<NotificationBundleOption> &bundleOption, bool &enabled)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[IsDistributedEnableByBundle] fail: bundle is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[IsDistributedEnableByBundle] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(bundleOption)) {
        ANS_LOGE("[IsDistributedEnableByBundle] fail: write bundle failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::IS_DISTRIBUTED_ENABLED_BY_BUNDLE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[IsDistributedEnableByBundle] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[IsDistributedEnableByBundle] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadBool(enabled)) {
        ANS_LOGE("[IsDistributedEnableByBundle] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetDeviceRemindType(NotificationConstant::RemindType &remindType)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetDeviceRemindType] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_DEVICE_REMIND_TYPE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetDeviceRemindType] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[GetDeviceRemindType] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (result == ERR_OK) {
        int32_t rType {-1};
        if (!reply.ReadInt32(rType)) {
            ANS_LOGE("[GetDeviceRemindType] fail: read remind type failed.");
            return ERR_ANS_PARCELABLE_FAILED;
        }

        remindType = static_cast<NotificationConstant::RemindType>(rType);
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

ErrCode AnsManagerProxy::SetBadgeNumber(int32_t badgeNumber, int32_t instanceKey)
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

    if (!data.WriteInt32(instanceKey)) {
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
        bundleOption.emplace_back(*obj);
    }

    return result;
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
    MessageOption option = { MessageOption::TF_ASYNC };
    ErrCode result = InnerTransact(NotificationInterfaceCode::UPDATE_NOTIFICATION_TIMER, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    return result;
}
}  // namespace Notification
}  // namespace OHOS
