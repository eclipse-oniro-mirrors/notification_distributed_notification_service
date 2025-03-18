/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_DO_NOT_DISTURB_PROFILE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_DO_NOT_DISTURB_PROFILE_H

#include "notification_bundle_option.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
class NotificationDoNotDisturbProfile : public Parcelable {
public:
    /**
     * Default constructor used to create a NotificationDoNotDisturbProfile instance.
     */
    NotificationDoNotDisturbProfile() = default;

    /**
     * A constructor used to create a NotificationDoNotDisturbProfile instance with the input parameters passed.
     *
     * @param id Indicates the profile id to add.
     * @param name Indicates the profile name to add.
     * @param trustlist Indicates the profile trustlist to add.
     */
    NotificationDoNotDisturbProfile(
        int64_t id, const std::string &name, const std::vector<NotificationBundleOption> &trustList);

    /**
     * Default deconstructor used to deconstruct.
     */
    ~NotificationDoNotDisturbProfile() = default;

    /**
     * Sets profile id for this NotificationDoNotDisturbProfile.
     *
     * @param profileId Indicates the profile id to add.
     */
    void SetProfileId(int64_t id);

    /**
     * Sets profile name for this NotificationDoNotDisturbProfile.
     *
     * @param profileName Indicates the profile name to add.
     */
    void SetProfileName(const std::string &name);

    /**
     * Sets profile trustlist for this NotificationDoNotDisturbProfile.
     *
     * @param profileTrustlist Indicates the profile trustlist to add.
     * For available values, see NotificationBundleOption.
     */
    void SetProfileTrustList(const std::vector<NotificationBundleOption> &trustList);

    /**
     * Obtains the profile id of this NotificationDoNotDisturbProfile.
     *
     *  @return the profile id of this NotificationDoNotDisturbProfile.
     */
    int64_t GetProfileId() const;

    /**
     * Obtains the profile name of this NotificationDoNotDisturbProfile.
     *
     * @return the profile name of this NotificationDoNotDisturbProfile.
     */
    std::string GetProfileName() const;

    /**
     * Obtains the profile trustlist of this NotificationDoNotDisturbProfile.
     *
     * @return the profile trustlist of this NotificationDoNotDisturbProfile,
     * For available values, see NotificationBundleOption.
     */
    std::vector<NotificationBundleOption> GetProfileTrustList() const;

    /**
     * Marshal a object into a Parcel.
     *
     * @param parcel the object into the parcel
     */
    bool Marshalling(Parcel &parcel) const override;

    /**
     * Read a NotificationDoNotDisturbProfile object from a Parcel.
     *
     * @param parcel the parcel
     */
    bool ReadFromParcel(Parcel &parcel);

    static NotificationDoNotDisturbProfile *Unmarshalling(Parcel &parcel);
    std::string ToJson();
    void FromJson(const std::string &value);
    void GetProfileJson(nlohmann::json &jsonObject) const;

private:
    int64_t id_;
    std::string name_;
    std::vector<NotificationBundleOption> trustList_;
};
} // namespace Notification
} // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_DO_NOT_DISTURB_PROFILE_H
