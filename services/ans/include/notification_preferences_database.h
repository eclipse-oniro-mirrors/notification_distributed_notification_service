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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_NOTIFICATION_PREFERENCES_DATABASE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_NOTIFICATION_PREFERENCES_DATABASE_H

#include <functional>
#include <memory>
#include <sstream>
#include <string>

#include "notification_rdb_data_mgr.h"
#include "notification_preferences_info.h"

namespace OHOS {
namespace Notification {
class NotificationPreferencesDatabase final {
public:
    NotificationPreferencesDatabase();
    ~NotificationPreferencesDatabase();

    /**
     * @brief Put notification slots into disturbe DB.
     *
     * @param bundleName Indicates bundle name.
     * @param bundleUid Indicates bundle uid.
     * @param slots Indicates notification slots.
     * @return Return true on success, false on failure.
     */
    bool PutSlotsToDisturbeDB(
        const std::string &bundleName, const int32_t &bundleUid, const std::vector<sptr<NotificationSlot>> &slots);

    /**
     * @brief Put notification bundle into disturbe DB.
     *
     * @param bundleInfo Indicates bundle info.
     * @return Return true on success, false on failure.
     */
    bool PutBundlePropertyToDisturbeDB(const NotificationPreferencesInfo::BundleInfo &bundleInfo);

    /**
     * @brief Put show badge in the of bundle into disturbe DB.
     *
     * @param bundleInfo Indicates bundle info.
     * @param enable Indicates to whether show badge.
     * @return Return true on success, false on failure.
     */
    bool PutShowBadge(const NotificationPreferencesInfo::BundleInfo &bundleInfo, const bool &enable);

    /**
     * @brief Put importance in the of bundle into disturbe DB.
     *
     * @param bundleInfo Indicates bundle info.
     * @param importance Indicates to importance level  which can be LEVEL_NONE,
               LEVEL_MIN, LEVEL_LOW, LEVEL_DEFAULT, LEVEL_HIGH, or LEVEL_UNDEFINED.
     * @return Return true on success, false on failure.
     */
    bool PutImportance(const NotificationPreferencesInfo::BundleInfo &bundleInfo, const int32_t &importance);

    /**
     * @brief Put badge total nums in the of  bundle into disturbe DB.
     *
     * @param bundleInfo Indicates bundle info.
     * @param totalBadgeNum Indicates to total badge num.
     * @return Return true on success, false on failure.
     */
    bool PutTotalBadgeNums(const NotificationPreferencesInfo::BundleInfo &bundleInfo, const int32_t &totalBadgeNum);

    /**
     * @brief Put enable notification in the of  bundle into disturbe DB.
     *
     * @param bundleInfo Indicates bundle info.
     * @param enabled Indicates to whether to enabled
     * @return Return true on success, false on failure.
     */
    bool PutNotificationsEnabledForBundle(
        const NotificationPreferencesInfo::BundleInfo &bundleInfo, const bool &enabled);

    /**
     * @brief Put distributed enable notification in the of  bundle into disturbe DB.
     *
     * @param deviceType Indicates device type.
     * @param bundleInfo Indicates bundle info.
     * @param enabled Indicates to whether to enabled
     * @return Return true on success, false on failure.
     */
    bool PutDistributedEnabledForBundle(const std::string deviceType,
        const NotificationPreferencesInfo::BundleInfo &bundleInfo, const bool &enabled);

    /**
     * @brief Get distributed enable notification in the of  bundle into disturbe DB.
     *
     * @param deviceType Indicates device type.
     * @param bundleInfo Indicates bundle info.
     * @param enabled Indicates to whether to enabled
     * @return Return true on success, false on failure.
     */
    bool GetDistributedEnabledForBundle(const std::string deviceType,
        const NotificationPreferencesInfo::BundleInfo &bundleInfo, bool &enabled);

    /**
     * @brief Put smart reminder enable notification in the of  bundle into disturbe DB.
     *
     * @param deviceType Indicates device type.
     * @param enabled Indicates to whether to enabled
     * @return Return true on success, false on failure.
     */
    bool SetSmartReminderEnabled(const std::string deviceType, const bool &enabled);

    /**
     * @brief Get smart reminder enable notification in the of  bundle into disturbe DB.
     *
     * @param deviceType Indicates device type.
     * @param enabled Indicates to whether to enabled
     * @return Return true on success, false on failure.
     */
    bool IsSmartReminderEnabled(const std::string deviceType, bool &enabled);

    /**
     * @brief Querying Aggregation Configuration Values
     *
     * @return Configured value
     */
    std::string GetAdditionalConfig(const std::string &key);

    /**
     * @brief Put enable notification into disturbe DB.
     *
     * @param userId Indicates user.
     * @param enabled Indicates to whether to enabled
     * @return Return true on success, false on failure.
     */
    bool PutNotificationsEnabled(const int32_t &userId, const bool &enabled);
    bool PutSlotFlags(NotificationPreferencesInfo::BundleInfo &bundleInfo, const int32_t &slotFlags);
    bool PutHasPoppedDialog(const NotificationPreferencesInfo::BundleInfo &bundleInfo, const bool &hasPopped);

    /**
     * @brief Put do not disturbe date into disturbe DB.
     *
     * @param userId Indicates user.
     * @param date Indicates to do not disturbe date.
     * @return Return true on success, false on failure.
     */
    bool PutDoNotDisturbDate(const int32_t &userId, const sptr<NotificationDoNotDisturbDate> &date);

    /**
     * @brief Parse notification info from disturbe DB.
     *
     * @param info Indicates notification info.
     * @return Return true on success, false on failure.
     */
    bool ParseFromDisturbeDB(NotificationPreferencesInfo &info, int32_t userId = -1);

    /**
     * @brief Delete all data from disturbe DB.
     *
     * @return Return true on success, false on failure.
     */
    bool RemoveAllDataFromDisturbeDB();

    /**
     * @brief Delete bundle data from disturbe DB.
     *
     * @param bundleKey Indicates the bundle key.
     * @param bundleId Indicates to bundle uid.
     * @return Return true on success, false on failure.
     */
    bool RemoveBundleFromDisturbeDB(const std::string &bundleKey, const int32_t &bundleUid);

    /**
     * @brief Delete slot from disturbe DB.
     *
     * @param bundleKey Indicates to which a bundle.
     * @param type Indicates to slot type.
     * @param bundleId Indicates to bundle uid.
     * @return Return true on success, false on failure.
     */
    bool RemoveSlotFromDisturbeDB(const std::string &bundleKey, const NotificationConstant::SlotType &type,
        const int32_t &bundleUid);

    /**
     * @brief Obtains allow notification application list.
     *
     * @param bundleOption Indicates the bundle bundleOption.
     * @return Returns ERR_OK on success, others on failure.
     */
    bool GetAllNotificationEnabledBundles(std::vector<NotificationBundleOption> &bundleOption);

    /**
     * @brief Delete all slots in the of bundle from disturbe DB.
     *
     * @param bundleKey Indicates to which a bundle.
     * @param bundleUid Indicates to the bundle uid.
     * @return Return true on success, false on failure.
     */
    bool RemoveAllSlotsFromDisturbeDB(const std::string &bundleKey, const int32_t &bundleUid);

     /**
     * @brief Get bundleInfo from DB.
     *
     * @param bundleOption Indicates the bundle bundleOption.
     * @param bundleInfo Indicates bundle info.
     * @return Return true on success, false on failure.
     */
    bool GetBundleInfo(const sptr<NotificationBundleOption> &bundleOption,
        NotificationPreferencesInfo::BundleInfo &bundleInfo);

    /**
     * @brief Query whether there is a agent relationship between the two apps.
     *
     * @param agentBundleName The bundleName of the agent app.
     * @param sourceBundleName The bundleName of the source app.
     * @return Returns true if There is an agent relationship; returns false otherwise.
     */
    bool IsAgentRelationship(const std::string &agentBundleName, const std::string &sourceBundleName);
    bool RemoveNotificationEnable(const int32_t userId);
    bool RemoveDoNotDisturbDate(const int32_t userId);
    bool RemoveAnsBundleDbInfo(std::string bundleName, int32_t uid);
    bool AddDoNotDisturbProfiles(int32_t userId, const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles);
    bool RemoveDoNotDisturbProfiles(
        int32_t userId, const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles);
    bool GetDoNotDisturbProfiles(
        const std::string &key, sptr<NotificationDoNotDisturbProfile> &profile, const int32_t &userId);
    bool RemoveEnabledDbByBundleName(std::string bundleName, const int32_t &bundleUid);
    int32_t SetKvToDb(const std::string &key, const std::string &value, const int32_t &userId);
    int32_t SetByteToDb(const std::string &key, const std::vector<uint8_t> &value, const int32_t &userId);
    int32_t GetKvFromDb(const std::string &key, std::string &value, const int32_t &userId);
    int32_t GetByteFromDb(const std::string &key, std::vector<uint8_t> &value, const int32_t &userId);
    int32_t GetBatchKvsFromDb(
        const std::string &key, std::unordered_map<std::string, std::string> &values, const int32_t &userId);
    int32_t DeleteKvFromDb(const std::string &key, const int32_t &userId);
    int32_t DeleteBatchKvFromDb(const std::vector<std::string> &keys, const int &userId);
    int32_t DropUserTable(const int32_t userId);
    bool UpdateBundlePropertyToDisturbeDB(int32_t userId, const NotificationPreferencesInfo::BundleInfo &bundleInfo);
    bool UpdateBundleSlotToDisturbeDB(int32_t userId, const std::string &bundleName,
        const int32_t &bundleUid, const std::vector<sptr<NotificationSlot>> &slots);
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
    bool DelBatchCloneProfileInfo(const int32_t &userId,
        const std::vector<sptr<NotificationDoNotDisturbProfile>>& profileInfo);
    bool DelBatchCloneBundleInfo(const int32_t &userId,
        const std::vector<NotificationCloneBundleInfo>& cloneBundleInfo);

    /**
     * @brief set rule of generate hashCode.
     *
     * @param uid uid.
     * @param type generate hashCode.
     * @return result true:success.
     */
    bool SetHashCodeRule(const int32_t uid, const uint32_t type);

    /**
     * @brief set rule of generate hashCode.
     *
     * @param uid uid.
     * @return type generate hashCode.
     */
    uint32_t GetHashCodeRule(const int32_t uid);

    bool SetBundleRemoveFlag(const sptr<NotificationBundleOption> &bundleOption,
        const NotificationConstant::SlotType &slotType);

    bool GetBundleRemoveFlag(const sptr<NotificationBundleOption> &bundleOption,
        const NotificationConstant::SlotType &slotType);

private:
    bool CheckRdbStore();

    bool CheckBundle(const std::string &bundleName, const int32_t &bundleUid);
    bool PutBundlePropertyValueToDisturbeDB(const NotificationPreferencesInfo::BundleInfo &bundleInfo);
    template <typename T>
    int32_t PutBundlePropertyToDisturbeDB(
        const std::string &bundleKey, const BundleType &type, const T &t, const int32_t &bundleUid);
    template <typename T>
    int32_t PutDataToDB(const std::string &key, const T &t, const int32_t &userId);
    bool PutBundleToDisturbeDB(
        const std::string &bundleKey, const NotificationPreferencesInfo::BundleInfo &bundleInfo);
    bool HandleDataBaseMap(
        const std::unordered_map<std::string, std::string> &datas, std::vector<NotificationBundleOption> &bundleOption);

    void GetValueFromDisturbeDB(const std::string &key, const int &userId,
        std::function<void(std::string &)> function);
    void GetValueFromDisturbeDB(const std::string &key, const int &userId,
        std::function<void(int32_t &, std::string &)> function);

    bool SlotToEntry(const std::string &bundleName, const int32_t &bundleUid, const sptr<NotificationSlot> &slot,
        std::unordered_map<std::string, std::string> &values);
    void GenerateSlotEntry(const std::string &bundleKey, const sptr<NotificationSlot> &slot,
        std::unordered_map<std::string, std::string> &values) const;
    void GenerateEntry(
        const std::string &key, const std::string &value, std::unordered_map<std::string, std::string> &values) const;

    std::string FindLastString(const std::string &findString, const std::string &inputString) const;
    std::string SubUniqueIdentifyFromString(const std::string &findString, const std::string &keyStr) const;
    std::string VectorToString(const std::vector<int64_t> &data) const;
    void StringToVector(const std::string &str, std::vector<int64_t> &data) const;
    int32_t StringToInt(const std::string &str) const;
    int64_t StringToInt64(const std::string &str) const;
    bool IsSlotKey(const std::string &bundleKey, const std::string &key) const;
    std::string GenerateSlotKey(
        const std::string &bundleKey, const std::string &type = "", const std::string &subType = "") const;
    std::string GenerateBundleKey(const std::string &bundleKey, const std::string &type = "") const;

    void ParseBundleFromDistureDB(NotificationPreferencesInfo &info,
        const std::unordered_map<std::string, std::string> &entries, const int32_t &userId);
    void ParseSlotFromDisturbeDB(NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &bundleKey,
        const std::pair<std::string, std::string> &entry, const int32_t &userId);
    void ParseBundlePropertyFromDisturbeDB(NotificationPreferencesInfo::BundleInfo &bundleInfo,
        const std::string &bundleKey, const std::pair<std::string, std::string> &entry);
    void ParseBundleName(NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &value) const;
    void ParseBundleImportance(NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &value) const;
    void ParseBundleSlotFlags(NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &value) const;
    void ParseBundleShowBadgeEnable(NotificationPreferencesInfo::BundleInfo &bundleInfo,
        const std::string &value) const;
    void ParseBundleBadgeNum(NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &value) const;
    void ParseBundleEnableNotification(
        NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &value) const;
    void ParseBundlePoppedDialog(
        NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &value) const;
    void ParseBundleUid(NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &value) const;
    void ParseSlot(const std::string &findString, sptr<NotificationSlot> &slot,
        const std::pair<std::string, std::string> &entry, const int32_t &userId);
    void ParseSlotDescription(sptr<NotificationSlot> &slot, const std::string &value) const;
    void ParseSlotLevel(sptr<NotificationSlot> &slot, const std::string &value) const;
    void ParseSlotShowBadge(sptr<NotificationSlot> &slot, const std::string &value) const;
    void ParseSlotEnableLight(sptr<NotificationSlot> &slot, const std::string &value) const;
    void ParseSlotEnableVrbration(sptr<NotificationSlot> &slot, const std::string &value) const;
    void ParseSlotLedLightColor(sptr<NotificationSlot> &slot, const std::string &value) const;
    void ParseSlotLockscreenVisibleness(sptr<NotificationSlot> &slot, const std::string &value) const;
    void ParseSlotSound(sptr<NotificationSlot> &slot, const std::string &value) const;
    void ParseSlotVibrationSytle(sptr<NotificationSlot> &slot, const std::string &value) const;
    void ParseSlotEnableBypassDnd(sptr<NotificationSlot> &slot, const std::string &value) const;
    void ParseSlotEnabled(sptr<NotificationSlot> &slot, const std::string &value) const;
    void ParseSlotFlags(sptr<NotificationSlot> &slot, const std::string &value) const;
    void ParseSlotAuthorizedStatus(sptr<NotificationSlot> &slot, const std::string &value) const;
    void ParseSlotAuthHitnCnt(sptr<NotificationSlot> &slot, const std::string &value) const;
    void ParseSlotReminderMode(sptr<NotificationSlot> &slot, const std::string &value) const;
    bool UpdateCloneToDisturbeDB(const int32_t &userId,
        const std::unordered_map<std::string, std::string> values);

    std::string GenerateBundleLablel(const NotificationPreferencesInfo::BundleInfo &bundleInfo) const;
    std::string GenerateBundleLablel(const NotificationPreferencesInfo::BundleInfo &bundleInfo,
        const std::string &deviceType) const;
    std::string GenerateBundleLablel(const std::string &deviceType, const int32_t userId) const;
    void GetDoNotDisturbType(NotificationPreferencesInfo &info, int32_t userId);
    void GetDoNotDisturbBeginDate(NotificationPreferencesInfo &info, int32_t userId);
    void GetDoNotDisturbEndDate(NotificationPreferencesInfo &info, int32_t userId);
    void GetEnableAllNotification(NotificationPreferencesInfo &info, int32_t userId);
    void GetDoNotDisturbProfile(NotificationPreferencesInfo &info, int32_t userId);
    void SetSoltProperty(sptr<NotificationSlot> &slot, std::string &typeStr, std::string &valueStr,
        const std::string &findString, const int32_t &userId);
    void ExecuteDisturbeDB(sptr<NotificationSlot> &slot, std::string &typeStr, std::string &valueStr,
        const std::string &findString, const int32_t &userId);
    bool CheckApiCompatibility(const std::string &bundleName, const int32_t &uid);
    std::shared_ptr<NotificationDataMgr> rdbDataManager_;
    std::string GenerateHashCodeGenerate(int32_t uid);
};
} // namespace Notification
} // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_NOTIFICATION_PREFERENCES_DATABASE_H
