/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_SUBSCRIBER_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_SUBSCRIBER_INFO_H

#include "parcel.h"
#include "notification_constant.h"

namespace OHOS {
namespace Notification {
class NotificationSubscribeInfo final : public Parcelable {
public:
    NotificationSubscribeInfo();

    ~NotificationSubscribeInfo();

    /**
     * @brief A constructor used to create a NotificationSubscribeInfo instance by copying parameters from an existing
     * one.
     *
     * @param subscribeInfo Indicates the NotificationSubscribeInfo object.
     */
    NotificationSubscribeInfo(const NotificationSubscribeInfo &subscribeInfo);

    /**
     * @brief Sets a single application name as the filter criterion,
     * which means to subscribe to notifications of this application.
     *
     * @param appName Indicates the application name.
     **/
    void AddAppName(const std::string appName);

    /**
     * @brief Sets multiple application names as the filter criteria,
     * which means to subscribe to notifications of these applications.
     *
     * @param appNames Indicates the set of application names.
     **/
    void AddAppNames(const std::vector<std::string> &appNames);

    /**
     * @brief Obtains the application names in the current NotificationSubscribeInfo object.
     * The application names can be set by calling AddAppNames.
     *
     * @return Returns the set of application names.
     **/
    std::vector<std::string> GetAppNames() const;

    /**
     * @brief Adds application userid.
     *
     * @param appNames Indicates the userid of application.
     **/
    void AddAppUserId(const int32_t userId);

    /**
     * @brief Obtains the userid of application.
     *
     * @return Returns the userid of application.
     **/
    int32_t GetAppUserId() const;

    /**
     * @brief Adds application deviceType.
     *
     * @param appNames Indicates the deviceType of application.
     **/
    void AddDeviceType(const std::string deviceType);

    /**
     * @brief Obtains the deviceType of application.
     *
     * @return Returns the deviceType of application.
     **/
    std::string GetDeviceType() const;

    /**
     * @brief Marshals a NotificationSubscribeInfo object into a Parcel.
     *
     * @param parcel Indicates the Parcel object for marshalling.
     * @return Returns true if the marshalling is successful; returns false otherwise.
     */
    bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshals a NotificationSubscribeInfo object from a Parcel.
     *
     * @param parcel Indicates the Parcel object for unmarshalling.
     * @return Returns the NotificationSubscribeInfo object.
     */
    static NotificationSubscribeInfo *Unmarshalling(Parcel &parcel);

    /**
     * @brief Dumps subscribe info.
     *
     * @return Returns subscribe info.
     */
    std::string Dump();

    /**
     * @brief Adds subscriber uid.
     *
     * @param appNames Indicates the uid of subscriber.
     **/
    void SetSubscriberUid(const int32_t uid);

    /**
     * @brief Obtains the uid of subscriber.
     *
     * @return Returns the uid of subscriber.
     **/
    int32_t GetSubscriberUid() const;

    /**
     * @brief Sets a single slot type as the filter criterion,
     * which means to subscribe to notifications of this slot.
     *
     * @param slotType Indicates the slot type.
     **/
    void AddSlotType(const NotificationConstant::SlotType slotType);

    /**
     * @brief Sets multiple slot type as the filter criteria,
     * which means to subscribe to notifications of these slotType.
     *
     * @param slotTypes Indicates the set of slot types.
     **/
    void AddSlotTypes(const std::vector<NotificationConstant::SlotType> &slotTypes);

    /**
     * @brief Obtains the slot types in the current NotificationSubscribeInfo object.
     * The slot types can be set by calling AddSlotTypes.
     *
     * @return Returns the set of slot types.
     **/
    std::vector<NotificationConstant::SlotType> GetSlotTypes() const;

    /**
     * @brief Adds filter type.
     *
     * @param filterType Indicates the filter type of subscriber.
     **/
    void SetFilterType(const int32_t filterType);

    /**
     * @brief Obtains the filter type.
     *
     * @return Returns the filter type of subscriber.
     **/
    int32_t GetFilterType() const;

private:
    bool ReadFromParcel(Parcel &parcel);

private:
    std::vector<std::string> appNames_ {};
    int32_t userId_ {-1};
    std::string deviceType_;
    int32_t subscriberUid_ {-1};
    std::vector<NotificationConstant::SlotType> slotTypes_;
    int32_t filterType_;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_SUBSCRIBER_INFO_H
