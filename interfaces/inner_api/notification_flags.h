/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_FLAGS_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_FLAGS_H

#include <memory>
#include "parcel.h"

#include "notification_constant.h"
#include "notification_json_convert.h"

namespace OHOS {
namespace Notification {
class NotificationFlags : public Parcelable, public NotificationJsonConvertionBase {
public:
    /**
     * Default constructor used to create an empty NotificationFlags instance.
     */
    NotificationFlags() = default;

    /**
     * constructor by reminderFlags
     */
    NotificationFlags(uint32_t reminderFlags);

    /**
     * Default deconstructor used to deconstruct.
     */
    ~NotificationFlags() = default;

    /**
     * Sets the notification whether enable sound.
     * @param soundEnabled whether enable sound.
     */
    void SetSoundEnabled(NotificationConstant::FlagStatus soundEnabled);

    /**
     * Checks whether enable sound.
     * @return sound enable.
     */
    NotificationConstant::FlagStatus IsSoundEnabled() const;

    /**
     * Sets the notification whether enable vibration.
     * @param vibrationEnabled whether enable vibration.
     */
    void SetVibrationEnabled(NotificationConstant::FlagStatus vibrationEnabled);

    /**
     * Checks whether enable vibration.
     * @return vibration enable.
     */
    NotificationConstant::FlagStatus IsVibrationEnabled() const;

    /**
     * Get reminder flags.
     * @return reminder flags.
     */
    uint32_t GetReminderFlags();

    /**
     * Set reminder flags.
     */
    void SetReminderFlags(const uint32_t reminderFlag);

    /**
     * Sets the notification whether enable lock screen.
     * @param visblenessEnabled whether enable lock screen.
     */
    void SetLockScreenVisblenessEnabled(bool visblenessEnabled);

    /**
     * Checks whether enable lock screen.
     * @return lock screen enable.
     */
    bool IsLockScreenVisblenessEnabled();

    /**
     * Sets the notification whether enable banner.
     * @param bannerEnabled whether enable banner.
     */
    void SetBannerEnabled(bool bannerEnabled);

    /**
     * Checks whether enable banner.
     * @return banner enable.
     */
    bool IsBannerEnabled();

    /**
     * Sets the notification whether light screen.
     * @param lightScreenEnabled whether light screen.
     */
    void SetLightScreenEnabled(bool lightScreenEnabled);

    /**
     * Checks whether enable light screen.
     * @return light screen enable.
     */
    bool IsLightScreenEnabled();

    /**
     * Sets the notification whether status icon.
     * @param statusIconEnabled whether status icon.
     */
    void SetStatusIconEnabled(bool statusIconEnabled);

    /**
     * Checks whether enable status icon.
     * @return status icon enable.
     */
    bool IsStatusIconEnabled();

    /**
     * Returns a string representation of the object.
     * @return a string representation of the object.
     */
    std::string Dump();

    /**
     * Converts a NotificationFlags object into a Json.
     * @param jsonObject Indicates the Json object.
     */
    bool ToJson(nlohmann::json &jsonObject) const override;

    /**
     * Creates a NotificationFlags object from a Json.
     * @param jsonObject Indicates the Json object.
     * @return the NotificationFlags.
     */
    static NotificationFlags *FromJson(const nlohmann::json &jsonObject);

    /**
     * Marshal a object into a Parcel.
     * @param parcel the object into the parcel
     */
    virtual bool Marshalling(Parcel &parcel) const override;

    /**
     * Unmarshal object from a Parcel.
     * @return the NotificationFlags
     */
    static NotificationFlags *Unmarshalling(Parcel &parcel);

    static bool GetReminderFlagsByString(
        const std::string &strReminderFlags, std::shared_ptr<NotificationFlags> &reminderFlags);

    static bool ValidCharReminderFlag(const char &charReminderFlag, const int32_t &seq);

private:
    /**
     * Read a NotificationFlags object from a Parcel.
     * @param parcel the parcel
     */
    bool ReadFromParcel(Parcel &parcel);

private:
    NotificationConstant::FlagStatus soundEnabled_ {NotificationConstant::FlagStatus::NONE};
    NotificationConstant::FlagStatus vibrationEnabled_ {NotificationConstant::FlagStatus::NONE};
    uint32_t reminderFlags_ = 0;

    static constexpr char CHAR_REMIND_DISABLE = '0';
    static constexpr char CHAR_REMIND_ENABLE = '1';
    static constexpr char CHAR_FLAG_STATUS_CLOSE = '2';
    static constexpr int32_t REMINDER_FLAG_SIZE = 6;
    static constexpr int32_t SOUND_ENABLED_SEQ = 5;
    static constexpr int32_t LOCK_SCREEN_VISIBLENESS_ENABLED_SEQ = 4;
    static constexpr int32_t BANNER_ENABLED_SEQ = 3;
    static constexpr int32_t LIGHT_SCREEN_ENABLED_SEQ = 2;
    static constexpr int32_t VIBRATION_ENABLED_SEQ = 1;
    static constexpr int32_t ICON_ENABLED_SEQ = 0;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_FLAGS_H

