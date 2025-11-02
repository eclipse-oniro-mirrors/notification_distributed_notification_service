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
     * @brief Adds subscriber slotTypes.
     *
     * @param slotTypes Indicates the slotTypes of subscriber.
     **/
    void SetSlotTypes(const std::vector<NotificationConstant::SlotType> slotTypes);

    /**
     * @brief Obtains the slotTypes of subscriber.
     *
     * @return Returns the slotTypes of subscriber.
     **/
    std::vector<NotificationConstant::SlotType> GetSlotTypes() const;

    /**
     * @brief Adds filter type.
     *
     * @param filterType Indicates the filter type of subscriber.
     **/
    void SetFilterType(const uint32_t filterType);

    /**
     * @brief Obtains the filter type.
     *
     * @return Returns the filter type of subscriber.
     **/
    uint32_t GetFilterType() const;

    /**
     * @brief Obtains notify application change.
     *
     * @return Returns the result.
     **/
    bool GetNeedNotifyApplication() const;

    /**
     * @brief Obtains notify application change.
     *
     * @return Returns the result.
     **/
    void SetNeedNotifyApplication(bool isNeed);

    /**
     * @brief Obtains notify repsponse.
     *
     * @return Returns the result.
     **/
    bool GetNeedNotifyResponse() const;

    /**
     * @brief Obtains notify repsponse.
     *
     * @return Returns the result.
     **/
    void SetNeedNotifyResponse(bool isNeed);

    /**
     * @brief Set isSubscribeSelf.
     *
     * @return Void.
     **/
    void SetIsSubscribeSelf(bool isSubscribeSelf);

    /**
     * @brief Obtains the value of isSubscribeSelf.
     *
     * @return Returns the value of isSubscribeSelf.
     **/
    bool GetIsSubscribeSelf() const;

private:
    bool ReadFromParcel(Parcel &parcel);
    void SetSubscriberBundleName(const std::string &bundleName);
    std::string GetSubscriberBundleName() const;
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

    void SetSubscribedFlags(uint32_t subscribedFlags);

    uint32_t GetSubscribedFlags() const;

private:
    std::vector<std::string> appNames_ {};
    int32_t userId_ {-1};
    std::string deviceType_;
    int32_t subscriberUid_ {-1};
    std::string subscriberBundleName_;
    uint32_t filterType_ {0};
    uint32_t subscribedFlags_ {0};
    std::vector<NotificationConstant::SlotType> slotTypes_ {};
    bool needNotifyApplicationChanged_ = false;
    bool needNotifyResponse_ = false;
    bool isSubscribeSelf_ = false;
    friend class NotificationSubscriberManager;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_SUBSCRIBER_INFO_H
