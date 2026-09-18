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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_BUNDLE_ICON_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_BUNDLE_ICON_INFO_H

#include <string>

#include "parcel.h"
#include "pixel_map.h"

namespace OHOS {
namespace Notification {
class NotificationBundleIconInfo : public Parcelable {
public:
    NotificationBundleIconInfo() = default;

    /**
     * @brief A constructor used to create a NotificationBundleIconInfo instance based on the
     * bundle name, uid, app index and icon.
     *
     * @param bundleName Indicates the bundle name of the granted application.
     * @param uid Indicates the uid of the granted application.
     * @param appIndex Indicates the app index of the granted application.
     * @param icon Indicates the current icon of the granted application.
     */
    NotificationBundleIconInfo(
        const std::string &bundleName, const int32_t uid, const int32_t appIndex,
        const std::shared_ptr<Media::PixelMap> &icon);

    virtual ~NotificationBundleIconInfo();

    /**
     * @brief Sets the bundle name.
     *
     * @param bundleName Indicates the bundle name.
     */
    void SetBundleName(const std::string &bundleName);

    /**
     * @brief Obtains the bundle name.
     *
     * @return Returns the bundle name.
     */
    std::string GetBundleName() const;

    /**
     * @brief Sets the uid.
     *
     * @param uid Indicates the uid.
     */
    void SetUid(const int32_t uid);

    /**
     * @brief Obtains the uid.
     *
     * @return Returns the uid.
     */
    int32_t GetUid() const;

    /**
     * @brief Sets the app index.
     *
     * @param appIndex Indicates the app index.
     */
    void SetAppIndex(const int32_t appIndex);

    /**
     * @brief Obtains the app index.
     *
     * @return Returns the app index.
     */
    int32_t GetAppIndex() const;

    /**
     * @brief Sets the icon.
     *
     * @param icon Indicates the icon of the application.
     */
    void SetIcon(const std::shared_ptr<Media::PixelMap> &icon);

    /**
     * @brief Obtains the icon.
     *
     * @return Returns the icon of the application, which may be null when the icon is unavailable.
     */
    std::shared_ptr<Media::PixelMap> GetIcon() const;

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
     * @return Returns the NotificationBundleIconInfo
     */
    static NotificationBundleIconInfo *Unmarshalling(Parcel &parcel);

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
    int32_t uid_ {};
    int32_t appIndex_ = -1;
    std::shared_ptr<Media::PixelMap> icon_ {};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_BUNDLE_ICON_INFO_H
