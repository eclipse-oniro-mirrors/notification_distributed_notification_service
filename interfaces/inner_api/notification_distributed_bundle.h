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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_DISTRIBUTED_BUNDLE_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_DISTRIBUTED_BUNDLE_INFO_H

#include "parcel.h"
#include "pixel_map.h"
#include "notification_constant.h"

#include "notification_json_convert.h"

namespace OHOS {
namespace Notification {

class NotificationDistributedBundle : public Parcelable {
public:
    NotificationDistributedBundle() = default;

    /**
     * @brief A constructor used to create a NotificationDistributedBundle instance.
     *
     * @param bundleName Indicates the bundle name.
     * @param uid Indicates the uid.
     */
    NotificationDistributedBundle(std::string bundleName, int32_t uid);

    ~NotificationDistributedBundle() = default;

    /**
     * @brief Get bundle uid.
     */
    int32_t GetBundleUid() const;

    /**
     * @brief Set bundle uid.
     */
    void SetBundleUid(int32_t uid);

    /**
     * @brief Set notification name.
     */
    std::string GetBundleName() const;

    /**
     * @brief Set notification name.
     */
    void SetBundleName(const std::string& name);

    /**
     * @brief Set notification label.
     */
    std::string GetBundleLabel() const;

    /**
     * @brief Set notification label.
     */
    void SetBundleLabel(const std::string& label);

    /**
     * @brief Set notification icon.
     */
    std::shared_ptr<Media::PixelMap> GetBundleIcon() const;

    /**
     * @brief Set notification icon.
     */
    void SetBundleIcon(const std::shared_ptr<Media::PixelMap> icon);

    /**
     * @brief Get anco flag.
     */
    bool IsAncoBundle() const;

    /**
     * @brief Set anco flag.
     */
    void SetAncoBundle(bool isAnco);

    /**
     * @brief Set installed same bundle.
     */
    void SetInstalledbundle(const std::string& bundleName, const std::string& label);

    /**
     * @brief Check installed bundle.
     */
    bool CheckInstalledBundle(const std::string bundleName, const std::string label) const;

    /**
     * @brief Get live view enable.
     */
    NotificationConstant::SWITCH_STATE GetLiveViewEnable() const;

    /**
     * @brief Set live view enable.
     */
    void SetLiveViewEnable(NotificationConstant::SWITCH_STATE enable);

    /**
     * @brief Get notification enable.
     */
    NotificationConstant::SWITCH_STATE GetNotificationEnable() const;

    /**
     * @brief Set notification enable.
     */
    void SetNotificationEnable(NotificationConstant::SWITCH_STATE enable);

    /**
     * @brief Returns a string representation of the object.
     *
     * @return Returns a string representation of the object.
     */
    std::string Dump() const;

    /**
     * @brief Marshal a object into a Parcel.
     *
     * @param parcel Indicates the object into the parcel
     * @return Returns true if succeed; returns false otherwise.
     */
    bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshal object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns the NotificationDistributedBundle
     */
    static NotificationDistributedBundle *Unmarshalling(Parcel &parcel);

private:
    /**
     * @brief Read data from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if read success; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel);

private:
    bool existSame_ = false;
    bool isAnco_ = false;
    NotificationConstant::SWITCH_STATE liveView_ = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
    NotificationConstant::SWITCH_STATE notification_ = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
    int32_t uid_ = 0;
    std::string installedAppLabel_;
    std::string installedBundleName_;
    std::string appLabel_;
    std::string bundleName_;
    std::shared_ptr<Media::PixelMap> icon_ = nullptr;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_DISTRIBUTED_BUNDLE_INFO_H
