/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "ans_subscriber_stub.h"

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "message_option.h"
#include "message_parcel.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
AnsSubscriberStub::AnsSubscriberStub() {}

AnsSubscriberStub::~AnsSubscriberStub() {}

int32_t AnsSubscriberStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &flags)
{
    std::u16string descriptor = AnsSubscriberStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        ANS_LOGW("[OnRemoteRequest] fail: invalid interface token!");
        return OBJECT_NULL;
    }
    ErrCode result = NO_ERROR;
    switch (code) {
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_CONNECTED): {
            result = HandleOnConnected(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_DISCONNECTED): {
            result = HandleOnDisconnected(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_CONSUMED_MAP): {
            result = HandleOnConsumedMap(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_CONSUMED_LIST_MAP): {
            result = HandleOnConsumedListMap(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_CANCELED_MAP): {
            result = HandleOnCanceledMap(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_CANCELED_LIST_MAP): {
            result = HandleOnCanceledListMap(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_UPDATED): {
            result = HandleOnUpdated(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_DND_DATE_CHANGED): {
            result = HandleOnDoNotDisturbDateChange(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_ENABLED_NOTIFICATION_CHANGED): {
            result = HandleOnEnabledNotificationChanged(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_BADGE_CHANGED): {
            result = HandleOnBadgeChanged(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_BADGE_ENABLED_CHANGED): {
            result = HandleOnBadgeEnabledChanged(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_APPLICATION_INFO_NEED_CHANGED): {
            result = HandleOnApplicationInfoNeedChanged(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_RESPONSE_LISTENER): {
            result = HandleOnResponse(data, reply);
            break;
        }
        default: {
            ANS_LOGE("[OnRemoteRequest] fail: unknown code!");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, flags);
        }
    }
    return result;
}

ErrCode AnsSubscriberStub::HandleOnConnected(MessageParcel &data, MessageParcel &reply)
{
    OnConnected();
    return ERR_OK;
}

ErrCode AnsSubscriberStub::HandleOnDisconnected(MessageParcel &data, MessageParcel &reply)
{
    OnDisconnected();
    return ERR_OK;
}

ErrCode AnsSubscriberStub::HandleOnConsumedMap(MessageParcel &data, MessageParcel &reply)
{
    sptr<Notification> notification = data.ReadParcelable<Notification>();
    if (!notification) {
        ANS_LOGW("[HandleOnConsumedMap] fail: notification ReadParcelable failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool existMap = false;
    if (!data.ReadBool(existMap)) {
        ANS_LOGW("[HandleOnConsumedMap] fail: read existMap failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<NotificationSortingMap> notificationMap = nullptr;
    if (existMap) {
        notificationMap = data.ReadParcelable<NotificationSortingMap>();
        if (notificationMap == nullptr) {
            ANS_LOGW("[HandleOnConsumedMap] fail: read NotificationSortingMap failed");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }

    OnConsumed(notification, notificationMap);
    return ERR_OK;
}

ErrCode AnsSubscriberStub::HandleOnConsumedListMap(MessageParcel &data, MessageParcel &reply)
{
    ANS_LOGD("Start handle notifications in consumed list.");

    std::vector<sptr<Notification>> notifications;
    if (!ReadParcelableVector(notifications, data)) {
        ANS_LOGE("read notifications failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool existMap = false;
    if (!data.ReadBool(existMap)) {
        ANS_LOGE("read existMap failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<NotificationSortingMap> notificationMap = nullptr;
    if (existMap) {
        notificationMap = data.ReadParcelable<NotificationSortingMap>();
        if (notificationMap == nullptr) {
            ANS_LOGE("read NotificationSortingMap failed");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }

    OnConsumedList(notifications, notificationMap);
    return ERR_OK;
}

ErrCode AnsSubscriberStub::HandleOnCanceledMap(MessageParcel &data, MessageParcel &reply)
{
    sptr<Notification> notification = data.ReadParcelable<Notification>();
    if (!notification) {
        ANS_LOGW("[HandleOnCanceledMap] fail: notification ReadParcelable failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool existMap = false;
    if (!data.ReadBool(existMap)) {
        ANS_LOGW("[HandleOnCanceledMap] fail: read existMap failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<NotificationSortingMap> notificationMap = nullptr;
    if (existMap) {
        notificationMap = data.ReadParcelable<NotificationSortingMap>();
        if (notificationMap == nullptr) {
            ANS_LOGW("[HandleOnCanceledMap] fail: read NotificationSortingMap failed");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }

    int32_t reason = 0;
    if (!data.ReadInt32(reason)) {
        ANS_LOGW("[HandleOnCanceledMap] fail: read reason failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    OnCanceled(notification, notificationMap, reason);
    return ERR_OK;
}


ErrCode AnsSubscriberStub::HandleOnCanceledListMap(MessageParcel &data, MessageParcel &reply)
{
    std::vector<sptr<Notification>> notifications;
    if (!ReadParcelableVector(notifications, data)) {
        ANS_LOGE("read notifications failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool existMap = false;
    if (!data.ReadBool(existMap)) {
        ANS_LOGE("read existMap failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<NotificationSortingMap> notificationMap = nullptr;
    if (existMap) {
        notificationMap = data.ReadParcelable<NotificationSortingMap>();
        if (notificationMap == nullptr) {
            ANS_LOGE("read NotificationSortingMap failed");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }

    int32_t reason = 0;
    if (!data.ReadInt32(reason)) {
        ANS_LOGE("read reason failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    OnCanceledList(notifications, notificationMap, reason);
    return ERR_OK;
}


template<typename T>
bool AnsSubscriberStub::ReadParcelableVector(std::vector<sptr<T>> &parcelableInfos, MessageParcel &data)
{
    int32_t infoSize = 0;
    if (!data.ReadInt32(infoSize)) {
        ANS_LOGE("read Parcelable size failed.");
        return false;
    }

    parcelableInfos.clear();
    infoSize = (infoSize < MAX_PARCELABLE_VECTOR_NUM) ? infoSize : MAX_PARCELABLE_VECTOR_NUM;
    for (int32_t index = 0; index < infoSize; index++) {
        sptr<T> info = data.ReadStrongParcelable<T>();
        if (info == nullptr) {
            ANS_LOGE("read Parcelable infos failed.");
            return false;
        }
        parcelableInfos.emplace_back(info);
    }

    return true;
}

ErrCode AnsSubscriberStub::HandleOnUpdated(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationSortingMap> notificationMap = data.ReadParcelable<NotificationSortingMap>();
    if (!notificationMap) {
        ANS_LOGW("[HandleOnUpdated] fail: notificationMap ReadParcelable failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    OnUpdated(notificationMap);
    return ERR_OK;
}

ErrCode AnsSubscriberStub::HandleOnDoNotDisturbDateChange(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationDoNotDisturbDate> date = data.ReadParcelable<NotificationDoNotDisturbDate>();
    if (!date) {
        ANS_LOGW("[HandleOnDoNotDisturbDateChange] fail: date ReadParcelable failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    OnDoNotDisturbDateChange(date);
    return ERR_OK;
}

ErrCode AnsSubscriberStub::HandleOnEnabledNotificationChanged(MessageParcel &data, MessageParcel &reply)
{
    sptr<EnabledNotificationCallbackData> callbackData = data.ReadParcelable<EnabledNotificationCallbackData>();
    if (!callbackData) {
        ANS_LOGW("[HandleOnEnabledNotificationChanged] fail: callbackData ReadParcelable failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    OnEnabledNotificationChanged(callbackData);
    return ERR_OK;
}

ErrCode AnsSubscriberStub::HandleOnBadgeChanged(MessageParcel &data, MessageParcel &reply)
{
    sptr<BadgeNumberCallbackData> callbackData = data.ReadParcelable<BadgeNumberCallbackData>();
    if (!callbackData) {
        ANS_LOGW("[HandleOnBadgeChanged] fail: callbackData ReadParcelable failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    OnBadgeChanged(callbackData);
    return ERR_OK;
}

ErrCode AnsSubscriberStub::HandleOnBadgeEnabledChanged(MessageParcel &data, MessageParcel &reply)
{
    sptr<EnabledNotificationCallbackData> callbackData = data.ReadParcelable<EnabledNotificationCallbackData>();
    if (callbackData == nullptr) {
        ANS_LOGE("Read callback data failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    OnBadgeEnabledChanged(callbackData);
    return ERR_OK;
}

ErrCode AnsSubscriberStub::HandleOnApplicationInfoNeedChanged(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName;
    if (!data.ReadString(bundleName)) {
        ANS_LOGE("[HandleGetAllDistribuedEnabledBundles] fail: read deviceType failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    OnApplicationInfoNeedChanged(bundleName);
    return ERR_OK;
}

ErrCode AnsSubscriberStub::HandleOnResponse(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationOperationInfo> operationInfo = data.ReadParcelable<NotificationOperationInfo>();
    if (!operationInfo) {
        ANS_LOGW("notification ReadParcelable failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    ErrCode result = OnOperationResponse(operationInfo);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

void AnsSubscriberStub::OnConnected() {}

void AnsSubscriberStub::OnDisconnected() {}

void AnsSubscriberStub::OnConsumed(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap)
{}

void AnsSubscriberStub::OnConsumedList(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap)
{}

void AnsSubscriberStub::OnCanceled(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{}

void AnsSubscriberStub::OnCanceledList(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{}

void AnsSubscriberStub::OnUpdated(const sptr<NotificationSortingMap> &notificationMap) {}

void AnsSubscriberStub::OnDoNotDisturbDateChange(const sptr<NotificationDoNotDisturbDate> &date) {}

void AnsSubscriberStub::OnEnabledNotificationChanged(const sptr<EnabledNotificationCallbackData> &callbackData) {}

void AnsSubscriberStub::OnBadgeChanged(const sptr<BadgeNumberCallbackData> &badgeData) {}

void AnsSubscriberStub::OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) {}

void AnsSubscriberStub::OnApplicationInfoNeedChanged(const std::string& bundleName) {}

ErrCode AnsSubscriberStub::OnOperationResponse(const sptr<NotificationOperationInfo>& operationInfo) { return 0; }
} // namespace Notification
} // namespace OHOS
