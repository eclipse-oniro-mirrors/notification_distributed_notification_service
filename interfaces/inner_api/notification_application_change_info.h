/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_APPLICATION_CHANGE_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_APPLICATION_CHANGE_INFO_H

#include "parcel.h"
#include <cstdint>

#include "distributed_data_define.h"
#include "notification_bundle_option.h"

namespace OHOS {
namespace Notification {
class NotificationApplicationChangeInfo : public Parcelable {
public:
    NotificationApplicationChangeInfo() = default;

    ~NotificationApplicationChangeInfo() = default;

    /**
     * @brief Set the change type.
     */
    void SetChangeType(const DistributedBundleChangeType type);

    /**
     * @brief Get the change type.
     */
    DistributedBundleChangeType GetChangeType() const;

    /**
     * @brief Set the bundle option.
     */
    void SetBundle(const std::shared_ptr<NotificationBundleOption> bundle);

    /**
     * @brief Obtains the bundle option.
     */
    std::shared_ptr<NotificationBundleOption> GetBundle() const;

    /**
     * @brief Set the bundle switch enable.
     */
    void SetEnable(const bool enable);

    /**
     * @brief Get the bundle switch enable.
     */
    bool GetEnable() const;

    std::string Dump();

    /**
     * @brief Marshal a object into a Parcel.
     *
     * @param parcel Indicates the object into the parcel.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshal object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     */
    static NotificationApplicationChangeInfo *Unmarshalling(Parcel &parcel);

private:

    bool ReadFromParcel(Parcel &parcel);
    bool switchEnable_ = false;
    std::shared_ptr<NotificationBundleOption> bundleOption_;
    DistributedBundleChangeType changeType_;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_APPLICATION_CHANGE_INFO_H
