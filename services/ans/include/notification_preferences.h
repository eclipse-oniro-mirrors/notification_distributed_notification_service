/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_NOTIFICATION_PREFERENCES_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_NOTIFICATION_PREFERENCES_H

#include "refbase.h"
#include "singleton.h"

#include "notification_do_not_disturb_date.h"
#include "notification_preferences_database.h"
#include <mutex>

namespace OHOS {
namespace Notification {
class NotificationPreferences final {
public:
    DISALLOW_COPY_AND_MOVE(NotificationPreferences);

    /**
     * @brief Get NotificationPreferences instance object.
     */
    static NotificationPreferences &GetInstance();

    /**
     * @brief Add notification slots into DB.
     *
     * @param bundleOption Indicates bunlde info label.
     * @param slots Indicates add notification slots.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode AddNotificationSlots(
        const sptr<NotificationBundleOption> &bundleOption, const std::vector<sptr<NotificationSlot>> &slots);

    /**
     * @brief Add notification bunle info into DB.
     *
     * @param bundleOption Indicates bunlde info.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode AddNotificationBundleProperty(const sptr<NotificationBundleOption> &bundleOption);

    /**
     * @brief Remove notification a slot in the of bundle from DB.
     *
     * @param bundleOption Indicates bunlde info label.
     * @param slotType Indicates slot type.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode RemoveNotificationSlot(
        const sptr<NotificationBundleOption> &bundleOption, const NotificationConstant::SlotType &slotType);

    /**
     * @brief Remove notification all slot in the of bundle from DB.
     *
     * @param bundleOption Indicates bunlde info label.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode RemoveNotificationAllSlots(const sptr<NotificationBundleOption> &bundleOption);

    /**
     * @brief Remove notification bundle from DB.
     *
     * @param bundleOption Indicates bunlde info label.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode RemoveNotificationForBundle(const sptr<NotificationBundleOption> &bundleOption);

    /**
     * @brief Update notification slot into DB.
     *
     * @param bundleOption Indicates bunlde info label.
     * @param slot Indicates need to upadte slot.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode UpdateNotificationSlots(
        const sptr<NotificationBundleOption> &bundleOption, const std::vector<sptr<NotificationSlot>> &slot);

    /**
     * @brief Get notification slot from DB.
     *
     * @param bundleOption Indicates bunlde info label.
     * @param type Indicates to get slot type.
     * @param slot Indicates to get slot.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode GetNotificationSlot(const sptr<NotificationBundleOption> &bundleOption,
        const NotificationConstant::SlotType &type, sptr<NotificationSlot> &slot);

    /**
     * @brief Get notification all slots in a bundle from DB.
     *
     * @param bundleOption Indicates bunlde info label.
     * @param slots Indicates to get slots.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode GetNotificationAllSlots(
        const sptr<NotificationBundleOption> &bundleOption, std::vector<sptr<NotificationSlot>> &slots);

    /**
     * @brief Get notification slot num in a bundle from DB.
     *
     * @param bundleOption Indicates bunlde info label.
     * @param num Indicates to get slot num.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode GetNotificationSlotsNumForBundle(const sptr<NotificationBundleOption> &bundleOption, uint64_t &num);

    /**
     * @brief Get show badge in the of bunlde from DB.
     *
     * @param bundleOption Indicates bunlde info label.
     * @param enable Indicates to whether to show badge
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode IsShowBadge(const sptr<NotificationBundleOption> &bundleOption, bool &enable);

    /**
     * @brief Set show badge in the of bunlde from DB.
     *
     * @param bundleOption Indicates bunlde info label.
     * @param enable Indicates to set show badge
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode SetShowBadge(const sptr<NotificationBundleOption> &bundleOption, const bool enable);

    /**
    * @brief Get importance in the of bunlde from DB.
    *
    * @param bundleOption Indicates bunlde info label.
    * @param importance Indicates to importance label which can be LEVEL_NONE,
               LEVEL_MIN, LEVEL_LOW, LEVEL_DEFAULT, LEVEL_HIGH, or LEVEL_UNDEFINED.
    * @return Return ERR_OK on success, others on failure.
    */
    ErrCode GetImportance(const sptr<NotificationBundleOption> &bundleOption, int32_t &importance);

    /**
    * @brief Set importance in the of bunlde from DB.
    *
    * @param bundleOption Indicates bunlde info label.
    * @param importance Indicates to set a importance label which can be LEVEL_NONE,
               LEVEL_MIN, LEVEL_LOW, LEVEL_DEFAULT, LEVEL_HIGH, or LEVEL_UNDEFINED.
    * @return Return ERR_OK on success, others on failure.
    */
    ErrCode SetImportance(const sptr<NotificationBundleOption> &bundleOption, const int32_t &importance);

    /**
     * @brief Get total badge nums in the of bunlde from DB.
     *
     * @param bundleOption Indicates bunlde info label.
     * @param totalBadgeNum Indicates to get badge num.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode GetTotalBadgeNums(const sptr<NotificationBundleOption> &bundleOption, int32_t &totalBadgeNum);

    /**
     * @brief Set total badge nums in the of bunlde from DB.
     *
     * @param bundleOption Indicates bunlde info label.
     * @param totalBadgeNum Indicates to set badge num.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode SetTotalBadgeNums(const sptr<NotificationBundleOption> &bundleOption, const int32_t num);

    /**
     * @brief Get slotFlags in the of bunlde from DB.
     *
     * @param bundleOption Indicates bunlde info label.
     * @param slotFlags Indicates to set soltFlags.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode GetNotificationSlotFlagsForBundle(const sptr<NotificationBundleOption> &bundleOption, uint32_t &slotFlags);

    /**
     * @brief Get slotFlags in the of bunlde from DB.
     *
     * @param bundleOption Indicates bunlde info label.
     * @param slotFlags Indicates to get slotFlags.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode SetNotificationSlotFlagsForBundle(const sptr<NotificationBundleOption> &bundleOption, uint32_t slotFlags);

    /**
     * @brief Get private notification enable in the of bunlde from DB.
     *
     * @param bundleOption Indicates bunlde info label.
     * @param enabled Indicates to whether to enable.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode GetNotificationsEnabledForBundle(const sptr<NotificationBundleOption> &bundleOption, bool &enabled);

    /**
     * @brief Set private notification enable in the of bunlde from DB.
     *
     * @param bundleOption Indicates bunlde info label.
     * @param enabled Indicates to set enable.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode SetNotificationsEnabledForBundle(const sptr<NotificationBundleOption> &bundleOption, const bool enabled);

    /**
     * @brief Get notification enable from DB.
     *
     * @param userId Indicates user.
     * @param enabled Indicates to whether to enable.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode GetNotificationsEnabled(const int32_t &userId, bool &enabled);

    /**
     * @brief Set notification enable from DB.
     *
     * @param userId Indicates user.
     * @param enabled Indicates to set enable.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode SetNotificationsEnabled(const int32_t &userId, const bool &enabled);
    ErrCode GetHasPoppedDialog(const sptr<NotificationBundleOption> &bundleOption, bool &hasPopped);
    ErrCode SetHasPoppedDialog(const sptr<NotificationBundleOption> &bundleOption, bool hasPopped);

    /**
     * @brief Get do not disturb date from DB.
     *
     * @param userId Indicates user.
     * @param date Indicates to get do not disturb date.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode GetDoNotDisturbDate(const int32_t &userId, sptr<NotificationDoNotDisturbDate> &date);

    /**
     * @brief Set do not disturb date from DB.
     *
     * @param userId Indicates user.
     * @param date Indicates to set do not disturb date.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode SetDoNotDisturbDate(const int32_t &userId, const sptr<NotificationDoNotDisturbDate> date);
    ErrCode GetTemplateSupported(const std::string &templateName, bool &support);

    /**
     * @brief Add do not disturb profiles from DB.
     *
     * @param userId Indicates user.
     * @param profiles Indicates to add do not disturb profiles.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode AddDoNotDisturbProfiles(int32_t userId, const std::vector<sptr<NotificationDoNotDisturbProfile>> profiles);

    /**
     * @brief Remove do not disturb profiles from DB.
     *
     * @param userId Indicates user.
     * @param profiles Indicates to remove do not disturb profiles.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode RemoveDoNotDisturbProfiles(
        int32_t userId, const std::vector<sptr<NotificationDoNotDisturbProfile>> profiles);

    /**
     * @brief Obtains allow notification application list.
     *
     * @param bundleOption Indicates the bundle bundleOption.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetAllNotificationEnabledBundles(std::vector<NotificationBundleOption> &bundleOption);

    /**
     * @brief Remove all proferences info from DB.
     *
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode ClearNotificationInRestoreFactorySettings();

    /**
     * @brief Query whether there is a agent relationship between the two apps.
     *
     * @param agentBundleName The bundleName of the agent app.
     * @param sourceBundleName The bundleName of the source app.
     * @return Returns true if There is an agent relationship; returns false otherwise.
     */
    bool IsAgentRelationship(const std::string &agentBundleName, const std::string &sourceBundleName);

    /**
     * @brief Querying Aggregation Configuration Values
     *
     * @return Configured value
     */
    std::string GetAdditionalConfig();

    /**
     * @brief Sets whether to allow a specified application to publish notifications cross
     * device collaboration. The caller must have system permissions to call this method.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Specifies whether to allow the given application to publish notifications. The value
     *                true indicates that notifications are allowed, and the value false indicates that
     *                notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    ErrCode SetDistributedEnabledByBundle(const sptr<NotificationBundleOption> &bundleOption,
        const std::string &deviceType, const bool enabled);
    
    /**
     * @brief Get Enable smartphone to collaborate with other devices for intelligent reminders
     *
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Specifies whether to allow the given device to publish notifications.
     *                The value true indicates that notifications are allowed, and the value
     *                false indicates that notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    ErrCode IsSmartReminderEnabled(const std::string &deviceType, bool &enabled);

    /**
     * @brief Set Enable smartphone to collaborate with other devices for intelligent reminders
     *
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Specifies whether to allow the given device to publish notifications.
     *                The value true indicates that notifications are allowed, and the value
     *                false indicates that notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    ErrCode SetSmartReminderEnabled(const std::string &deviceType, const bool enabled);

    /**
     * @brief Get whether to allow a specified application to publish notifications cross
     * device collaboration. The caller must have system permissions to call this method.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Specifies whether to allow the given application to publish notifications. The value
     *                true indicates that notifications are allowed, and the value false indicates that
     *                notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    ErrCode IsDistributedEnabledByBundle(const sptr<NotificationBundleOption> &bundleOption,
        const std::string &deviceType, bool &enabled);

    /**
     * @brief Get the bundle name set for send the sound.
     *
     * @param allPackage Specifies whether to allow all bundle to publish notification with sound.
     * @param bundleNames Indicates bundle name set, allow to publish notification with sound.
     * @return true if get the permission; returns false otherwise.
     */
    bool GetBundleSoundPermission(bool &allPackage, std::set<std::string> &bundleNames);

    void InitSettingFromDisturbDB();
    void RemoveSettings(int32_t userId);
    void RemoveAnsBundleDbInfo(const sptr<NotificationBundleOption> &bundleOption);
    void RemoveEnabledDbByBundle(const sptr<NotificationBundleOption> &bundleOption);
    int32_t SetKvToDb(const std::string &key, const std::string &value, const int32_t &userId);
    int32_t SetByteToDb(const std::string &key, const std::vector<uint8_t> &value, const int32_t &userId);
    int32_t GetKvFromDb(const std::string &key, std::string &value, const int32_t &userId);
    int32_t GetByteFromDb(const std::string &key, std::vector<uint8_t> &value, const int32_t &userId);
    int32_t GetBatchKvsFromDb(
        const std::string &key, std::unordered_map<std::string, std::string>  &values, const int32_t &userId);
    int32_t DeleteKvFromDb(const std::string &key, const int &userId);
    ErrCode GetDoNotDisturbProfile(int32_t profileId, int32_t userId, sptr<NotificationDoNotDisturbProfile> &profile);
    bool CheckDoNotDisturbProfileID(int32_t profileId);
    void RemoveDoNotDisturbProfileTrustList(int32_t userId, const sptr<NotificationBundleOption> &bundleOption);

private:
    ErrCode CheckSlotForCreateSlot(const sptr<NotificationBundleOption> &bundleOption,
        const sptr<NotificationSlot> &slot, NotificationPreferencesInfo &preferencesInfo) const;
    ErrCode CheckSlotForRemoveSlot(const sptr<NotificationBundleOption> &bundleOption,
        const NotificationConstant::SlotType &slotType, NotificationPreferencesInfo &preferencesInfo) const;
    ErrCode CheckSlotForUpdateSlot(const sptr<NotificationBundleOption> &bundleOption,
        const sptr<NotificationSlot> &slot, NotificationPreferencesInfo &preferencesInfo) const;
    template <typename T>
    ErrCode SetBundleProperty(NotificationPreferencesInfo &preferencesInfo,
        const sptr<NotificationBundleOption> &bundleOption, const BundleType &type, const T &value);
    template <typename T>
    ErrCode SaveBundleProperty(NotificationPreferencesInfo::BundleInfo &bundleInfo,
        const sptr<NotificationBundleOption> &bundleOption, const BundleType &type, const T &value);
    template <typename T>
    ErrCode GetBundleProperty(
        const sptr<NotificationBundleOption> &bundleOption, const BundleType &type, T &value);
    std::string GenerateBundleKey(const sptr<NotificationBundleOption> &bundleOption) const;
    bool CheckApiCompatibility(const sptr<NotificationBundleOption> &bundleOption) const;

private:
    NotificationPreferencesInfo preferencesInfo_ {};
    std::mutex preferenceMutex_;
    std::unique_ptr<NotificationPreferencesDatabase> preferncesDB_ = nullptr;
    DECLARE_DELAYED_REF_SINGLETON(NotificationPreferences);
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_NOTIFICATION_PREFERENCES_H
