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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_DISTRIBUTED_BUNDLE_OPTION_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_DISTRIBUTED_BUNDLE_OPTION_H

#include "notification_json_convert.h"
#include "notification_bundle_option.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
class DistributedBundleOption : public Parcelable, public NotificationJsonConvertionBase {
public:
    DistributedBundleOption() = default;

    /**
     * @brief A constructor used to create a DistributedBundleOption instance based on the creator bundles and enable.
     *
     * @param bundles Indicates the bundles.
     * @param enable Indicates the status.
     */
    DistributedBundleOption(std::shared_ptr<NotificationBundleOption> &bundle, const bool enable);

    virtual ~DistributedBundleOption();

    /**
     * @brief Get bundle.
     *
     * @return Returns bundle info.
     */
    std::shared_ptr<NotificationBundleOption> GetBundle() const;

    /**
     * @brief Sets bundle.
     *
     * @param bundle bundle info.
     */
    void SetBundle(std::shared_ptr<NotificationBundleOption> bundle);

    /**
     * @brief Get enable.
     *
     * @return Returns enable value.
     */
    bool isEnable() const;

    /**
     * @brief Sets enable.
     *
     * @param enable enable status.
     */
    void SetEnable(const bool& enable);

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
     * @return Returns the DistributedBundleOption
     */
    static DistributedBundleOption *Unmarshalling(Parcel &parcel);

    /**
     * @brief Converts a distributed bundle option object into a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ToJson(nlohmann::json &jsonObject) const override;

    /**
     * @brief Creates a distributed bundle option object from a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns the DistributedBundleOption.
     */
    static DistributedBundleOption *FromJson(const nlohmann::json &jsonObject);

private:
    /**
     * @brief Read data from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if read success; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel);

private:
    std::shared_ptr<NotificationBundleOption> bundle_ {};
    bool enable_ = false;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_DISTRIBUTED_BUNDLE_OPTION_H