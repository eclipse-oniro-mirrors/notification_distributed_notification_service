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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_RINGTONE_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_RINGTONE_INFO_H

#include "notification_constant.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
class NotificationRingtoneInfo : public Parcelable {
public:
    /**
     * Default constructor used to create a NotificationRingtoneInfo instance.
     */
    NotificationRingtoneInfo() = default;

    /**
     * A constructor used to create a NotificationRingtoneInfo instance with the input parameters passed.
     * @param ringtoneType Indicates the ringtone type to add.
     * @param ringtoneTitle Indicates the ringtone title to add.
     * @param ringtoneFileName Indicates the ringtone file name to add.
     * @param ringtoneUri Indicates the ringtone uri to add.
     */
    NotificationRingtoneInfo(NotificationConstant::RingtoneType ringtoneType, const std::string &ringtoneTitle,
        const std::string &ringtoneFileName, const std::string &ringtoneUri);

    /**
     * Default deconstructor used to deconstruct.
     */
    ~NotificationRingtoneInfo() = default;

    /**
     * Sets ringtone type for this NotificationRingtoneInfo.
     * @param ringtoneType Indicates the ringtone type to add.
     * For available values, see NotificationConstant::RingtoneType.
     */
    void SetRingtoneType(NotificationConstant::RingtoneType ringtoneType);

    /**
     * Obtains the ringtone type of this NotificationRingtoneInfo.
     * @return the ringtone type of this NotificationRingtoneInfo,
     * as enumerated in NotificationConstant::RingtoneType.
     */
    NotificationConstant::RingtoneType GetRingtoneType() const;

    /**
     * Sets ringtone title for this NotificationRingtoneInfo.
     * @param ringtoneTitle Indicates the ringtone title to add.
     */
    void SetRingtoneTitle(const std::string &ringtoneTitle);

    /**
     * Obtains the ringtone title of this NotificationRingtoneInfo.
     * @return the ringtone title of this NotificationRingtoneInfo.
     */
    std::string GetRingtoneTitle() const;

    /**
     * Sets ringtone file name for this NotificationRingtoneInfo.
     * @param ringtoneFileName Indicates the ringtone file name to add.
     */
    void SetRingtoneFileName(const std::string &ringtoneFileName);

    /**
     * Obtains the ringtone file name of this NotificationRingtoneInfo.
     * @return the ringtone file name of this NotificationRingtoneInfo.
     */
    std::string GetRingtoneFileName() const;

    /**
     * Sets ringtone uri for this NotificationRingtoneInfo.
     * @param ringtoneUri Indicates the ringtone uri to add.
     */
    void SetRingtoneUri(const std::string &ringtoneUri);

    /**
     * Obtains the ringtone uri of this NotificationRingtoneInfo.
     * @return the ringtone uri of this NotificationRingtoneInfo.
     */
    std::string GetRingtoneUri() const;

    void ResetRingtone();

    /**
     * Marshals a NotificationRingtoneInfo object into a Parcel object.
     *
     * @param parcel Indicates the Parcel object into which the NotificationRingtoneInfo object is marshaled.
     * @return true if the operation is successful; false otherwise.
     */
    bool Marshalling(Parcel &parcel) const override;

    /**
     * Unmarshals a NotificationRingtoneInfo object from a Parcel object.
     *
     * @param parcel Indicates the Parcel object from which the NotificationRingtoneInfo object is unmarshaled.
     * @return true if the operation is successful; false otherwise.
     */
    static NotificationRingtoneInfo *Unmarshalling(Parcel &parcel);

    /**
     * Converts the NotificationRingtoneInfo object to a JSON string.
     *
     * @return the JSON string representation of this NotificationRingtoneInfo object.
     */
    std::string ToJson();

    /**
     * Parses a JSON string and updates this NotificationRingtoneInfo object with the parsed values.
     *
     * @param jsonObj Indicates the JSON string to parse.
     */
    void FromJson(const std::string &jsonObj);

private:
    /**
     * Read a NotificationRingtoneInfo object from a Parcel.
     * @param parcel the parcel
     */
    bool ReadFromParcel(Parcel &parcel);

private:
    NotificationConstant::RingtoneType ringtoneType_ { NotificationConstant::RingtoneType::RINGTONE_CUSTOM_BUTT };
    std::string ringtoneTitle_ {""};
    std::string ringtoneFileName_ {""};
    std::string ringtoneUri_ {""};
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_RINGTONE_INFO_H