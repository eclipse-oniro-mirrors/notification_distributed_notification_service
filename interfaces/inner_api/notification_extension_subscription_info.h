/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_EXTENSION_SUBSCRIPTION_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_EXTENSION_SUBSCRIPTION_INFO_H

#include "notification_constant.h"
#include "notification_json_convert.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
class NotificationExtensionSubscriptionInfo : public Parcelable, public NotificationJsonConvertionBase {
public:
    NotificationExtensionSubscriptionInfo() = default;

    /**
     * @brief A constructor used to create a NotificationExtensionSubscriptionInfo instance based on the address and
     * type.
     *
     * @param addr Indicates the address.
     * @param type Indicates the type.
     */
    NotificationExtensionSubscriptionInfo(const std::string& addr, const NotificationConstant::SubscribeType type);

    /**
     * @brief Copy constructor.
     *
     * @param info Another NotificationExtensionSubscriptionInfo instance to copy from.
     */
    NotificationExtensionSubscriptionInfo(const NotificationExtensionSubscriptionInfo& info);

    virtual ~NotificationExtensionSubscriptionInfo();

    /**
     * @brief Get addr.
     *
     * @return Returns addr.
     */
    std::string GetAddr() const;

    /**
     * @brief Sets addr.
     *
     * @param addr addr info.
     */
    void SetAddr(const std::string& addr);

    /**
     * @brief Get hfp.
     *
     * @return Returns hfp value.
     */
    bool IsHfp() const;

    /**
     * @brief Sets hfp.
     *
     * @param hfp hfp status.
     */
    void SetHfp(const bool& hfp);

    /**
     * @brief Get type.
     *
     * @return Returns type value.
     */
    NotificationConstant::SubscribeType GetType() const;

    /**
     * @brief Sets type.
     *
     * @param type type value.
     */
    void SetType(const NotificationConstant::SubscribeType type);

    /**
     * @brief Returns a string representation of the object.
     *
     * @return Returns a string representation of the object.
     */
    std::string Dump();

    /**
     * @brief Marshal a object into a Parcel.
     *
     * @param parcel Indicates the object into the parcel
     * @return Returns true if succeed; returns false otherwise.
     */
    virtual bool Marshalling(Parcel& parcel) const override;

    /**
     * @brief Unmarshal object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns the NotificationExtensionSubscriptionInfo
     */
    static NotificationExtensionSubscriptionInfo *Unmarshalling(Parcel& parcel);

    /**
     * @brief Converts a notification extension subscription info object into a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ToJson(nlohmann::json& jsonObject) const override;

    /**
     * @brief Creates a notification extension subscription info object from a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns the NotificationExtensionSubscriptionInfo.
     */
    static NotificationExtensionSubscriptionInfo *FromJson(const nlohmann::json& jsonObject);

private:
    /**
     * @brief Read data from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if read success; returns false otherwise.
     */
    bool ReadFromParcel(Parcel& parcel);

private:
    std::string addr_ {};
    bool isHfp_ = false;
    NotificationConstant::SubscribeType type_ = NotificationConstant::SubscribeType::BLUETOOTH;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_EXTENSION_SUBSCRIPTION_INFO_H