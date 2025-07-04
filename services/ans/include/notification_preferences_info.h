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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_NOTIFICATION_PREFERENCES_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_NOTIFICATION_PREFERENCES_INFO_H

#include <map>
#include <string>
#include <vector>

#include "notification_bundle_option.h"
#include "notification_do_not_disturb_date.h"
#include "notification_slot.h"
#include "preferences_constant.h"
#include "advanced_notification_service.h"
#include "notification_clone_bundle_info.h"
#include "notification_disable.h"
#include "notification_constant.h"

namespace OHOS {
namespace Notification {
class NotificationPreferencesInfo final {
public:

    struct SilentReminderInfo {
        std::string bundleName;
        int32_t uid;
        NotificationConstant::SWITCH_STATE enableStatus {NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF};
    };
    class BundleInfo final {
    public:
        BundleInfo();
        ~BundleInfo();
        /**
         * @brief Set bundle name.
         *
         * @param name Indicates the bundle name.
         */
        void SetBundleName(const std::string &name);

        /**
         * @brief Get bundle name.
         *
         * @return Return bundle name.
         */
        std::string GetBundleName() const;

        /**
         * @brief Set bundle importance.
         *
         * @param name Indicates the bundle importance.
         */
        void SetImportance(const int32_t &level);

        /**
         * @brief Get bundle importance.
         *
         * @return Return importance.
         */
        int32_t GetImportance() const;

        /**
         * @brief Set bundle Whether to show badge.
         *
         * @param name Indicates the set bundle Whether to show badge.
         */
        void SetIsShowBadge(const bool &isShowBadge);

        /**
         * @brief Get bundle Whether to show badge.
         *
         * @return Return true on success, false on failure.
         */
        bool GetIsShowBadge() const;

        /**
         * @brief Set bundle total badge num.
         *
         * @param name Indicates the set bundle total badge num.
         */
        void SetBadgeTotalNum(const int32_t &num);

        /**
         * @brief Get bundle total badge num.
         *
         * @return Return badge total num.
         */
        int32_t GetBadgeTotalNum() const;

        /**
         * @brief Set bundle enable notification.
         *
         * @param enable Indicates the set enable notification.
         */
        void SetEnableNotification(const bool &enable);

        /**
         * @brief Set bundle enable notification.
         *
         * @return Return true on success, false on failure.
         */
        bool GetEnableNotification() const;

        void SetHasPoppedDialog(const bool &hasPopped);
        bool GetHasPoppedDialog() const;

        /**
         * @brief Set bundle slot.
         *
         * @param slot Indicates the set slot.
         */
        void SetSlot(const sptr<NotificationSlot> &slot);

        /**
         * @brief Get bundle slot by type.
         *
         * @param type Indicates the slot type.
         * @param slot Indicates the slot object.
         * @return Return true on success, false on failure.
         */
        bool GetSlot(const NotificationConstant::SlotType &type, sptr<NotificationSlot> &slot) const;

        /**
         * @brief Get slots from bundle.
         *
         * @param slots Indicates the get slots.
         * @return Return true on success, false on failure.
         */
        bool GetAllSlots(std::vector<sptr<NotificationSlot>> &slots);

        /**
         * @brief Get slot num from bundle.
         *
         * @return Return true on success, false on failure.
         */
        uint32_t GetAllSlotsSize();

        /**
         * @brief Get slotflags from bundle.
         *
         * @return Return slotFlags of bundle.
         */
        uint32_t GetSlotFlags();

        /**
         * @brief Set slotflags to bundle.
         *
         * @param slotFlags Indicates slotFlags of bundle.
         */
        void SetSlotFlags(uint32_t slotFlags);

        /**
         * get slot type name string from slottype enum type.
         * @param type  slot type enum value.
         * @return slot type name string.
         */
        const char *GetSlotFlagsKeyFromType(const NotificationConstant::SlotType &type) const;

        /**
         * set for specified slottype slotfalgs.
         * @param type Indicates slot type.
         */
        void SetSlotFlagsForSlot(const NotificationConstant::SlotType &type);

        /**
         * get for specified slottype slotfalgs.
         * @param type  Indicates slot type.
         * @return specified slottype's slotfalgs.
         */
        uint32_t GetSlotFlagsForSlot(const NotificationConstant::SlotType &type) const;

        /**
         * @brief Get all slot from group in bundle.
         *
         * @param groupId Indicates a groupId from bundle.
         * @param slots Indicates get slots from group.
         * @return Return true on success, false on failure.
         */
        bool GetAllSlotsInGroup(const std::string &groupId, std::vector<sptr<NotificationSlot>> &slots);

        /**
         * @brief Get all slot from group in bundle.
         *
         * @param groupId Indicates a groupId from bundle.
         * @param slots Indicates get slots from group.
         * @return Return true on success, false on failure.
         */
        bool GetAllSlotsInGroup(const std::string &groupId, std::vector<NotificationSlot> &slots);

        /**
         * @brief Check whether to exsist slot in the of bundle.
         *
         * @param type Indicates the slot type.
         * @return Return true on success, false on failure.
         */
        bool IsExsitSlot(const NotificationConstant::SlotType &type) const;

        /**
         * @brief Rremove a slot from bundle.
         *
         * @param type Indicates the slot type.
         * @return Return true on success, false on failure.
         */
        bool RemoveSlot(const NotificationConstant::SlotType &type);

        /**
         * @brief Remove all slots from bundle.
         *
         * @return Return true on success, false on failure.
         */
        void RemoveAllSlots();

        void SetBundleUid(const int32_t &uid);
        int32_t GetBundleUid() const;
        void SetSlotEnabled(NotificationConstant::SlotType slotType, bool enabled);
        bool GetSlotEnabled(NotificationConstant::SlotType slotType, bool &enabled) const;

    private:
        std::string bundleName_;
        int32_t uid_ = 0;
        uint32_t slotFlags_ = 59; // 0b111011
        int32_t importance_ = BUNDLE_IMPORTANCE;
        bool isShowBadge_ = BUNDLE_SHOW_BADGE;
        int32_t badgeTotalNum_ = BUNDLE_BADGE_TOTAL_NUM;
        bool isEnabledNotification_ = BUNDLE_ENABLE_NOTIFICATION;
        bool hasPoppedDialog_ = BUNDLE_POPPED_DIALOG;
        std::map<NotificationConstant::SlotType, sptr<NotificationSlot>> slots_;
        std::map<std::string, uint32_t> slotFlagsMap_;
    };

    /*
     * @brief Constructor used to create an NotificationPreferencesInfo object.
     */
    NotificationPreferencesInfo()
    {}

    /**
     * @brief Default destructor.
     */
    ~NotificationPreferencesInfo()
    {}

    /**
     * set bundle info into preferences info.
     * @param info Indicates the bundle.
     */
    void SetBundleInfo(BundleInfo &info);

    /**
     * get bundle info from preferences info.
     * @param bundleOption Indicates the bundle info label.
     * @param info Indicates the bundle info.
     * @return Whether to get bundle info success.
     */
    bool GetBundleInfo(const sptr<NotificationBundleOption> &bundleOption, BundleInfo &info) const;

    /**
     * set silent reminder info into preferences info.
     * @param info Indicates the bundle.
     */
    void SetSilentReminderInfo(SilentReminderInfo &info);

    /**
     * get silent reminder info from preferences info.
     * @param bundleOption Indicates the bundle info label.
     * @param info Indicates the silent reminder info.
     * @return Whether to get silent reminder info success.
     */
    bool GetSilentReminderInfo(const sptr<NotificationBundleOption> &bundleOption, SilentReminderInfo &info) const;

    /**
     * remove silent reminder info from preferences info.
     * @param bundleOption Indicates the silent reminder info label.
     * @return Whether to remove silent reminder info success.
     */
    bool RemoveSilentReminderInfo(const sptr<NotificationBundleOption> &bundleOption);

    /**
     * remove bundle info from preferences info.
     * @param bundleOption Indicates the bundle info label.
     * @return Whether to remove bundle info success.
     */
    bool RemoveBundleInfo(const sptr<NotificationBundleOption> &bundleOption);

    /**
     * whether to exsist bundle info in the of preferences info.
     * @param bundleOption Indicates the bundle info label.
     * @return Whether to exsist bundle info.
     */
    bool IsExsitBundleInfo(const sptr<NotificationBundleOption> &bundleOption) const;

    /**
     * clear bundle info in the of preferences info.
     */
    void ClearBundleInfo();

    /**
     * set do not disturb date into preferences info.
     * @param userId Indicates userId.
     * @param doNotDisturbDate Indicates do not disturb date.
     * @return Whether to set do not disturb success.
     */
    void SetDoNotDisturbDate(const int32_t &userId,
        const sptr<NotificationDoNotDisturbDate> &doNotDisturbDate);

    /**
     * get do not disturb date from preferences info.
     * @param userId Indicates userId.
     * @param doNotDisturbDate Indicates do not disturb date.
     * @return Whether to get do not disturb success.
     */
    bool GetDoNotDisturbDate(const int32_t &userId,
        sptr<NotificationDoNotDisturbDate> &doNotDisturbDate) const;

    /**
     * set enable all notification into preferences info.
     * @param userId Indicates userId.
     * @param enable Indicates whether to enable all notification.
     */
    void SetEnabledAllNotification(const int32_t &userId, const bool &enable);

    /**
     * get enable all notification from preferences info.
     * @param userId Indicates userId.
     * @param enable Indicates whether to enable all notification.
     * @return Whether to enable all notification success.
     */
    bool GetEnabledAllNotification(const int32_t &userId, bool &enable) const;
    void RemoveNotificationEnable(const int32_t userId);
    void RemoveDoNotDisturbDate(const int32_t userId);
    void SetBundleInfoFromDb(BundleInfo &info, std::string bundleKey);
    void SetSilentReminderInfoFromDb(SilentReminderInfo &silentReminderInfo, std::string bundleKey);
    std::string MakeDoNotDisturbProfileKey(int32_t userId, int64_t profileId);
    void AddDoNotDisturbProfiles(int32_t userId, const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles);
    void RemoveDoNotDisturbProfiles(int32_t userId, const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles);
    bool GetDoNotDisturbProfiles(int64_t profileId, int32_t userId, sptr<NotificationDoNotDisturbProfile> &profiles);
    void GetAllDoNotDisturbProfiles(int32_t userId, std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles);
    void GetAllCLoneBundlesInfo(const int32_t &userId, const std::unordered_map<std::string, std::string> &bunlesMap,
        std::vector<NotificationCloneBundleInfo> &cloneBundles);
    void SetDisableNotificationInfo(const sptr<NotificationDisable> &notificationDisable);
    bool GetDisableNotificationInfo(NotificationDisable &notificationDisable);
    void AddDisableNotificationInfo(const std::string &value);
    ErrCode GetAllLiveViewEnabledBundles(const int32_t userId, std::vector<NotificationBundleOption> &bundleOption);
    void SetkioskAppTrustList(const std::vector<std::string> &kioskAppTrustList);
    bool GetkioskAppTrustList(std::vector<std::string> &kioskAppTrustList) const;

private:
    std::map<int32_t, bool> isEnabledAllNotification_;
    std::map<int32_t, sptr<NotificationDoNotDisturbDate>> doNotDisturbDate_;
    std::map<std::string, sptr<NotificationDoNotDisturbProfile>> doNotDisturbProfiles_;
    std::map<std::string, BundleInfo> infos_;
    std::vector<std::string> kioskAppTrustList_;
    std::unordered_map<std::string, SilentReminderInfo> silentReminderInfos_;

    struct DisableNotificationInfo {
        int32_t disabled = -1;
        std::vector<std::string> bundleList;
    };
    DisableNotificationInfo disableNotificationInfo_;
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_NOTIFICATION_PREFERENCES_INFO_H
