/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include <memory>
#include <mutex>
#include "notification_clone_bundle_info.h"
#include "notification_constant.h"

namespace OHOS {
namespace Notification {
class NotificationPreferences final {
public:
    NotificationPreferences();
    ~NotificationPreferences() = default;
    /**
     * @brief Get NotificationPreferences instance object.
     */
    static std::shared_ptr<NotificationPreferences> GetInstance();

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
     * @param state Indicates to whether to enable.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode GetNotificationsEnabledForBundle(const sptr<NotificationBundleOption> &bundleOption,
        NotificationConstant::SWITCH_STATE &state);

    /**
     * @brief Set private notification enable in the of bunlde from DB.
     *
     * @param bundleOption Indicates bunlde info label.
     * @param state Indicates to set switch state.
     * @return Return ERR_OK on success, others on failure.
     */
    ErrCode SetNotificationsEnabledForBundle(const sptr<NotificationBundleOption> &bundleOption,
        const NotificationConstant::SWITCH_STATE state);

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

    ErrCode GetAllLiveViewEnabledBundles(const int32_t userId, std::vector<NotificationBundleOption> &bundleOption);

    ErrCode GetAllDistribuedEnabledBundles(int32_t userId,
        const std::string &deviceType, std::vector<NotificationBundleOption> &bundleOption);

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
    std::string GetAdditionalConfig(const std::string &key);

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
     * @brief Sets whether to allow a specified application to publish notifications cross
     * device collaboration. The caller must have system permissions to call this method.
     *
     * @param bundles Indicates the bundles.
     * @param deviceType Indicates the type of the device running the application.
     * @return Returns set distributed enabled for specified bundle result.
     */
    ErrCode SetDistributedBundleOption(
        const std::vector<sptr<DistributedBundleOption>> &bundles,
        const std::string &deviceType);

    /**
     * @brief Sets whether to allow a specified application to publish notifications cross
     * device collaboration. The caller must have system permissions to call this method.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param enabled Specifies whether to allow the given application to publish notifications. The value
     *                true indicates that notifications are allowed, and the value false indicates that
     *                notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    ErrCode SetSilentReminderEnabled(const sptr<NotificationBundleOption> &bundleOption, const bool enabled);
 
    /**
     * @brief Get whether to allow a specified application to publish notifications cross
     * device collaboration. The caller must have system permissions to call this method.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param enabled Specifies whether to allow the given application to publish notifications. The value
     *                true indicates that notifications are allowed, and the value false indicates that
     *                notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    ErrCode IsSilentReminderEnabled(
        const sptr<NotificationBundleOption> &bundleOption, NotificationConstant::SWITCH_STATE &enableStatus);

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
     * @brief Configuring Whether to Synchronize Common Notifications to Target Devices.
     *
     * @param deviceType Target device type.
     * @param enabled Whether to Synchronize Common Notifications to Target Devices.
     * @return Returns configuring Whether to Synchronize Common Notifications to Target Devices result.
     */
    ErrCode SetDistributedEnabled(
        const std::string &deviceType, const NotificationConstant::SWITCH_STATE &enableStatus);

    /**
     * @brief Querying Whether to Synchronize Common Devices to Target Devices.
     *
     * @param deviceType Target device type.
     * @param enabled Whether to Synchronize Common Notifications to Target Devices.
     * @return Returns Whether to Synchronize Common Notifications to Target Devices result.
     */
    ErrCode IsDistributedEnabled(
        const std::string &deviceType, NotificationConstant::SWITCH_STATE &enableStatus);

    /**
     * @brief Get the target device's authorization status.
     *
     * @param deviceType Type of the target device whose status you want to set.
     * @param deviceId The id of the target device.
     * @param targetUserId The userid of the target device.
     * @param isAuth Return The authorization status.
     * @return Returns get result.
     */
    ErrCode GetDistributedAuthStatus(
        const std::string &deviceType, const std::string &deviceId, int32_t targetUserId, bool &isAuth);

    /**
     * @brief Set the target device's authorization status.
     *
     * @param deviceType Type of the target device whose status you want to set.
     * @param deviceId The id of the target device.
     * @param targetUserId The userid of the target device.
     * @param isAuth The authorization status.
     * @return Returns set result.
     */
    ErrCode SetDistributedAuthStatus(
        const std::string &deviceType, const std::string &deviceId, int32_t targetUserId, bool isAuth);

    /**
     * @brief Set the channel switch for collaborative reminders.
       The caller must have system permissions to call this method.
     *
     * @param slotType Indicates the slot type of the application.
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Indicates slot switch status.
     * @return Returns set channel switch result.
     */
    ErrCode SetDistributedEnabledBySlot(
        const NotificationConstant::SlotType &slotType, const std::string &deviceType, const bool enabled);

    /**
     * @brief Query the channel switch for collaborative reminders.
       The caller must have system permissions to call this method.
     *
     * @param slotType Indicates the slot type of the application.
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Indicates slot switch status.
     * @return Returns channel switch result.
     */
    ErrCode IsDistributedEnabledBySlot(
        const NotificationConstant::SlotType &slotType, const std::string &deviceType, bool &enabled);

    /**
     * @brief Get the bundle name set for send the sound.
     *
     * @param allPackage Specifies whether to allow all bundle to publish notification with sound.
     * @param bundleNames Indicates bundle name set, allow to publish notification with sound.
     * @return true if get the permission; returns false otherwise.
     */
    bool GetBundleSoundPermission(bool &allPackage, std::set<std::string> &bundleNames);

    ErrCode UpdateDoNotDisturbProfiles(int32_t userId, int64_t profileId,
        const std::string& name, const std::vector<NotificationBundleOption>& bundleList);

    void UpdateProfilesUtil(std::vector<NotificationBundleOption>& trustList,
        const std::vector<NotificationBundleOption> bundleList);

    void InitSettingFromDisturbDB(int32_t userId = -1);
    void RemoveSettings(int32_t userId);
    void RemoveAnsBundleDbInfo(const sptr<NotificationBundleOption> &bundleOption);
    void RemoveEnabledDbByBundle(const sptr<NotificationBundleOption> &bundleOption);
    void RemoveSilentEnabledDbByBundle(const sptr<NotificationBundleOption> &bundleOption);
    int32_t SetKvToDb(const std::string &key, const std::string &value, const int32_t &userId);
    int32_t SetByteToDb(const std::string &key, const std::vector<uint8_t> &value, const int32_t &userId);
    int32_t GetKvFromDb(const std::string &key, std::string &value, const int32_t &userId);
    int32_t GetBatchKvsFromDbContainsKey(
        const std::string &key, std::unordered_map<std::string, std::string>  &values, const int32_t &userId);
#ifdef ENABLE_ANS_PRIVILEGED_MESSAGE_EXT_WRAPPER
    int32_t GetKvFromDb(const std::string &key, std::string &value, const int32_t &userId, int32_t &retCode);
#endif
    int32_t GetByteFromDb(const std::string &key, std::vector<uint8_t> &value, const int32_t &userId);
    int32_t GetBatchKvsFromDb(
        const std::string &key, std::unordered_map<std::string, std::string>  &values, const int32_t &userId);
    int32_t DeleteKvFromDb(const std::string &key, const int &userId);
    int32_t DeleteBatchKvFromDb(const std::vector<std::string> &keys, const int &userId);
    ErrCode GetDoNotDisturbProfile(int64_t profileId, int32_t userId, sptr<NotificationDoNotDisturbProfile> &profile);
    void RemoveDoNotDisturbProfileTrustList(int32_t userId, const sptr<NotificationBundleOption> &bundleOption);
    void GetDoNotDisturbProfileListByUserId(int32_t userId,
        std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles);
    void GetAllCLoneBundlesInfo(int32_t userId, std::vector<NotificationCloneBundleInfo> &cloneBundles);
    void UpdateCloneBundleInfo(int32_t userId, const NotificationCloneBundleInfo& cloneBundleInfo);
    bool IsNotificationSlotFlagsExists(const sptr<NotificationBundleOption> &bundleOption);
    bool DelCloneProfileInfo(const int32_t &userId, const sptr<NotificationDoNotDisturbProfile>& info);
    bool UpdateBatchCloneProfileInfo(const int32_t &userId,
        const std::vector<sptr<NotificationDoNotDisturbProfile>>& profileInfo);
    void GetAllCloneProfileInfo(const int32_t &userId,
        std::vector<sptr<NotificationDoNotDisturbProfile>>& profilesInfo);
    void GetAllCloneBundleInfo(const int32_t &userId, std::vector<NotificationCloneBundleInfo>& cloneBundleInfo);
    bool UpdateBatchCloneBundleInfo(const int32_t &userId,
        const std::vector<NotificationCloneBundleInfo>& cloneBundleInfo);
    bool DelCloneBundleInfo(const int32_t &userId, const NotificationCloneBundleInfo& cloneBundleInfo);
    bool DelBatchCloneBundleInfo(const int32_t &userId,
        const std::vector<NotificationCloneBundleInfo>& cloneBundleInfo);
    bool DelBatchCloneProfileInfo(const int32_t &userId,
        const std::vector<sptr<NotificationDoNotDisturbProfile>>& profileInfo);
    ErrCode SetDisableNotificationInfo(const sptr<NotificationDisable> &notificationDisable);
    bool GetDisableNotificationInfo(NotificationDisable &notificationDisable);
    bool GetUserDisableNotificationInfo(int32_t userId, NotificationDisable &notificationDisable);
    ErrCode SetSubscriberExistFlag(const std::string& deviceType, bool existFlag);
    ErrCode GetSubscriberExistFlag(const std::string& deviceType, bool& existFlag);
    /**
     * @brief set rule of generate hashCode.
     *
     * @param uid uid.
     * @param type generate hashCode.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SetHashCodeRule(const int32_t uid, const uint32_t type);

    /**
     * @brief get rule of generate hashCode.
     *
     * @param uid uid.
     * @return  generate hashCode type.
     */
    uint32_t GetHashCodeRule(const int32_t uid);

    bool GetBundleRemoveFlag(const sptr<NotificationBundleOption> &bundleOption,
        const NotificationConstant::SlotType &slotType, int32_t sourceType);

    bool SetBundleRemoveFlag(const sptr<NotificationBundleOption> &bundleOption,
        const NotificationConstant::SlotType &slotType, int32_t sourceType);

    void SetKioskModeStatus(bool isKioskMode);

    bool IsKioskMode();

    bool GetkioskAppTrustList(std::vector<std::string> &kioskAppTrustList);

    /**
     * @brief Set distributed device list.
     *
     * @param deviceTypes Indicates device types.
     * @param userId Indicates userId
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SetDistributedDevicelist(std::vector<std::string> &deviceTypes, const int32_t &userId);

    /**
     * @brief Get distributed device list.
     *
     * @param deviceTypes Indicates device types.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetDistributedDevicelist(std::vector<std::string> &deviceTypes);

    ErrCode GetLiveViewConfigVersion(int32_t &version);
    bool SetLiveViewConfigVersion(const int32_t& version);
    ErrCode GetLiveViewRebuildFlag(std::string& flag, int32_t userId);
    bool SetLiveViewRebuildFlag(int32_t userId);
    ErrCode InitBundlesInfo(int32_t userId, std::unordered_map<std::string, std::string>& bundlesMap);
    void GetAllLiveViewBundles(std::vector<sptr<NotificationBundleOption>>& bundleOption);
private:
    bool GetBundleInfo(NotificationPreferencesInfo &preferencesInfo,
        const sptr<NotificationBundleOption> &bundleOption, NotificationPreferencesInfo::BundleInfo &info) const;
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
    void SetDistributedEnabledForBundle(const NotificationPreferencesInfo::BundleInfo& bundleInfo);

private:
    static ffrt::mutex instanceMutex_;
    static std::shared_ptr<NotificationPreferences> instance_;
    NotificationPreferencesInfo preferencesInfo_ {};
    ffrt::mutex preferenceMutex_;
    std::shared_ptr<NotificationPreferencesDatabase> preferncesDB_ = nullptr;
    bool isCachedMirrorNotificationEnabledStatus_ = false;
    std::vector<std::string> mirrorNotificationEnabledStatus_ = {};
    bool isKioskMode_ = false;
    bool isKioskTrustListUpdate_ = false;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_NOTIFICATION_PREFERENCES_H
