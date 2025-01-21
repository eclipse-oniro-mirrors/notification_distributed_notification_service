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

#ifndef BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_SUBSCRIBER_STUB_H
#define BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_SUBSCRIBER_STUB_H

#include "ans_subscriber_interface.h"
#include "distributed_notification_service_ipc_interface_code.h"
#include "iremote_stub.h"

namespace OHOS {
namespace Notification {
class AnsSubscriberStub : public IRemoteStub<AnsSubscriberInterface> {
public:
    AnsSubscriberStub();
    ~AnsSubscriberStub() override;
    DISALLOW_COPY_AND_MOVE(AnsSubscriberStub);

    /**
     * @brief Handle remote request.
     *
     * @param data Indicates the input parcel.
     * @param reply Indicates the output parcel.
     * @param option Indicates the message option.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    /**
     * @brief The callback function for the subscriber to establish a connection.
     */
    void OnConnected() override;

    /**
     * @brief The callback function for subscriber disconnected.
     */
    void OnDisconnected() override;

    /**
     * @brief The callback function on a notification published.
     *
     * @param notification Indicates the consumed notification.
     * @param notificationMap Indicates the NotificationSortingMap object.
     */
    void OnConsumed(
        const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap) override;

    void OnConsumedList(const std::vector<sptr<Notification>> &notifications,
        const sptr<NotificationSortingMap> &notificationMap) override;

    /**
     * @brief The callback function on a notification canceled.
     *
     * @param notification Indicates the canceled notification.
     * @param notificationMap Indicates the NotificationSortingMap object.
     * @param deleteReason Indicates the delete reason.
     */
    void OnCanceled(const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap,
        int32_t deleteReason) override;

    void OnCanceledList(const std::vector<sptr<Notification>> &notifications,
        const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason) override;

    /**
     * @brief The callback function on the notifications updated.
     *
     * @param notificationMap Indicates the NotificationSortingMap object.
     */
    void OnUpdated(const sptr<NotificationSortingMap> &notificationMap) override;

    /**
     * @brief The callback function on the do not disturb date changed.
     *
     * @param date Indicates the NotificationDoNotDisturbDate object.
     */
    void OnDoNotDisturbDateChange(const sptr<NotificationDoNotDisturbDate> &date) override;

    /**
     * @brief The callback function on the notification enabled flag changed.
     *
     * @param callbackData Indicates the EnabledNotificationCallbackData object.
     */
    void OnEnabledNotificationChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override;

    /**
     * @brief The callback function on the badge number changed.
     *
     * @param badgeData Indicates the BadgeNumberCallbackData object.
     */
    void OnBadgeChanged(const sptr<BadgeNumberCallbackData> &badgeData) override;

    /**
     * @brief The callback function on the badge enabled state changed.
     *
     * @param callbackData Indicates the EnabledNotificationCallbackData object.
     */
    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override;

    void OnApplicationInfoNeedChanged(const std::string& bundleName) override;

    /**
     * @brief The callback function on the response.
     *
     * @param notification Indicates the received Notification object.
     */
    ErrCode OnResponse(const sptr<Notification> &notification) override;

private:

    ErrCode HandleOnConnected(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleOnDisconnected(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleOnConsumedMap(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleOnConsumedListMap(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleOnCanceledMap(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleOnCanceledListMap(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleOnUpdated(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleOnDoNotDisturbDateChange(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleOnEnabledNotificationChanged(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleOnBadgeChanged(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleOnBadgeEnabledChanged(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleOnApplicationInfoNeedChanged(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleOnResponse(MessageParcel &data, MessageParcel &reply);

    template<typename T>
    bool ReadParcelableVector(std::vector<sptr<T>> &parcelableInfos, MessageParcel &data);
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_SUBSCRIBER_STUB_H
