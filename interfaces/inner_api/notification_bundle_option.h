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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_BUNDLE_OPTION_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_BUNDLE_OPTION_H

#include "notification_json_convert.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
class NotificationBundleOption : public Parcelable, public NotificationJsonConvertionBase {
public:
    NotificationBundleOption() = default;

    /**
     * @brief A constructor used to create a NotificationBundleOption instance based on the creator bundle name and uid.
     *
     * @param bundleName Indicates the creator bundle name.
     * @param uid Indicates the creator uid.
     */
    NotificationBundleOption(const std::string &bundleName, const int32_t uid);

    virtual ~NotificationBundleOption();

    /**
     * @brief Sets the creator bundle name.
     *
     * @param bundleName Indicates the creator bundle name.
     */
    void SetBundleName(const std::string &bundleName);

    /**
     * @brief Obtains the creator bundle name.
     *
     * @return Returns the creator bundle name.
     */
    std::string GetBundleName() const;

    void SetAppName(const std::string &appName);

    std::string GetAppName() const;

    /**
     * @brief Sets the creator uid.
     *
     * @param uid Indicates the creator uid.
     */
    void SetUid(const int32_t uid);

    /**
     * @brief Obtains the creator uid.
     *
     * @return Returns the creator uid.
     */
    int32_t GetUid() const;

    /**
     * @brief Sets the application instance key.
     *
     * @param uid Indicates the application instance key.
     */
    void SetInstanceKey(const int32_t key);

    /**
     * @brief Obtains the application instance key.
     *
     * @return Returns the application instance key.
     */
    int32_t GetInstanceKey() const;

    /**
     * @brief Sets the application instance key.
     *
     * @param key Indicates the application instance key.
     */
    void SetAppInstanceKey(const std::string &key);

    /**
     * @brief Obtains the application instance key.
     *
     * @return Returns the application instance key.
     */
    std::string GetAppInstanceKey() const;

    /**
     * @brief Sets the application index.
     *
     * @param uid Indicates the application index.
     */
    void SetAppIndex(const int32_t appIndex);

    /**
     * @brief Obtains the application index.
     *
     * @return Returns the application index.
     */
    int32_t GetAppIndex() const;

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
    virtual bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshal object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns the NotificationBundleOption
     */
    static NotificationBundleOption *Unmarshalling(Parcel &parcel);

    /**
     * @brief Converts a notification bundle option object into a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ToJson(nlohmann::json &jsonObject) const override;

    /**
     * @brief Creates a bundle option object from a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns the NotificationBundleOption.
     */
    static NotificationBundleOption *FromJson(const nlohmann::json &jsonObject);

private:
    /**
     * @brief Read data from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if read success; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel);

private:
    std::string bundleName_ {};
    std::string appInstanceKey_ {};
    int32_t uid_ {};
    int32_t instanceKey_ {};
    int32_t appIndex_ = -1;
    bool badgeEnabled_ = false;
    std::string appName_ {};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_BUNDLE_OPTION_H
