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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_DISTRIBUTED_NOTIFICATION_BUNDLE_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_DISTRIBUTED_NOTIFICATION_BUNDLE_INFO_H

#include "notification_bundle_option.h"
#include "parcel.h"
#include "pixel_map.h"
#include "want_params.h"

namespace OHOS {
namespace Notification {
class DistributedNotificationBundleInfo : public Parcelable {
public:
    DistributedNotificationBundleInfo() = default;

    /**
     * @brief A constructor used to create a DistributedBundleOption instance based on the creator bundles and enable.
     *
     * @param bundles Indicates the bundles.
     * @param enable Indicates the status.
     */
    DistributedNotificationBundleInfo(const std::string& bundleName, const int32_t& uid);

    virtual ~DistributedNotificationBundleInfo();

    /**
     * @brief Get bundle name.
     */
    std::string GetBundleName() const;

    /**
     * @brief Sets bundle name.
     */
    void SetBundleName(const std::string& bundleName);

    /**
     * @brief Get bundle uid.
     */
    int32_t GetBundleUid() const;

    /**
     * @brief Sets bundle uid.
     */
    void SetBundleUid(const int32_t uid);

    /**
     * @brief Get extend info.
     */
    const std::shared_ptr<AAFwk::WantParams> GetExtendInfo() const;

    /**
     * @brief Get extend info.
     */
    void SetExtendInfo(const std::shared_ptr<AAFwk::WantParams> &extendInfo);

    /**
     * @brief Get bundle icon.
     */
    const std::shared_ptr<Media::PixelMap> GetBundleIcon() const;

    /**
     * @brief Set bundle icon.
     */
    void SetBundleIcon(const std::shared_ptr<Media::PixelMap> &icon);

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
     * @return Returns the DistributedNotificationBundleInfo
     */
    static DistributedNotificationBundleInfo *Unmarshalling(Parcel &parcel);

private:
    /**
     * @brief Read data from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if read success; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel);

private:
    int32_t uid_;
    std::string bundleName_;
    std::shared_ptr<Media::PixelMap> icon_ {};
    std::shared_ptr<AAFwk::WantParams> extendInfo_ {};
};
}  // namespace Notification
}  // namespace OHOS

#endif
