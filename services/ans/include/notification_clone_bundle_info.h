/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_BUNDLE_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_BUNDLE_INFO_H

#include "notification_clone_template.h"

#include "ffrt.h"
#include "notification_constant.h"
#include "notification_bundle_option.h"
#include "notification_do_not_disturb_profile.h"
#include "notification_extension_subscription_info.h"
#include "notification_constant.h"
#include "notification_ringtone_info.h"

namespace OHOS {
namespace Notification {
class NotificationCloneBundleInfo {
public:
    class SlotInfo {
    public:
        std::string Dump() const;
        int32_t GetAuthStaus() const;
        NotificationConstant::SlotType slotType_;
        bool enable_;
        bool isForceControl_;
        bool authorizedStatus_ = true;
    };
    NotificationCloneBundleInfo() = default;
    ~NotificationCloneBundleInfo() = default;

    void SetBundleName(const std::string &name);
    std::string GetBundleName() const;

    void SetAppIndex(const int32_t &appIndex);
    int32_t GetAppIndex() const;

    void SetSlotFlags(const uint32_t &slotFlags);
    uint32_t GetSlotFlags() const;

    void SetUid(const int32_t &uid);
    int32_t GetUid() const;

    void SetIsShowBadge(const bool &isShowBadge);
    bool GetIsShowBadge() const;

    void SetHasPoppedDialog(const bool &hasPoppedDialog);
    bool GetHasPoppedDialog() const;

    void SetEnableNotification(const NotificationConstant::SWITCH_STATE &state);
    NotificationConstant::SWITCH_STATE GetEnableNotification() const;

    void SetSilentReminderEnabled(const NotificationConstant::SWITCH_STATE &silentReminderEnabled);
    NotificationConstant::SWITCH_STATE GetSilentReminderEnabled() const;

    void SetEnabledExtensionSubscription(const NotificationConstant::SWITCH_STATE &state);
    NotificationConstant::SWITCH_STATE GetEnabledExtensionSubscription() const;

    void AddSlotInfo(const SlotInfo &slotInfo);
    std::vector<SlotInfo> GetSlotInfo() const;

    void SetExtensionSubscriptionInfos(const std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos);
    const std::vector<sptr<NotificationExtensionSubscriptionInfo>>& GetExtensionSubscriptionInfos() const;

    void SetExtensionSubscriptionBundles(const std::vector<sptr<NotificationBundleOption>>& bundles);
    const std::vector<sptr<NotificationBundleOption>>& GetExtensionSubscriptionBundles() const;

    void AddRingtoneInfo(sptr<NotificationRingtoneInfo> ringtoneInfo);
    sptr<NotificationRingtoneInfo> GetRingtoneInfo() const;

    void ToJson(nlohmann::json &jsonObject) const;
    void FromJson(const nlohmann::json &root);
    void SlotsFromJson(const nlohmann::json &jsonObject);
    void RingtoneFromJson(const nlohmann::json &jsonObject);
    void SubscriptionInfosFromJson(const nlohmann::json &jsonObject);
    void ExtensionSubscriptionFromJson(const nlohmann::json &jsonObject);
    void SubscriptionBundlesFromJson(const nlohmann::json &jsonObject);
    std::string Dump() const;

private:
    std::string bundleName_;
    int32_t appIndex_ = -1;
    int32_t uid_ = -1;
    uint32_t slotFlags_ = 0;
    bool isShowBadge_ = false;
    bool hasPoppedDialog_ = false;
    NotificationConstant::SWITCH_STATE isEnabledNotification_ = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    std::vector<SlotInfo> slotsInfo_;
    sptr<NotificationRingtoneInfo> ringtoneInfo_ = nullptr;
    NotificationConstant::SWITCH_STATE silentReminderEnabled_;
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> extensionSubscriptionInfos_;
    NotificationConstant::SWITCH_STATE enabledExtensionSubscription_ =
        NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    std::vector<sptr<NotificationBundleOption>> extensionSubscriptionBundles_;
};
} // namespace Notification
} // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_BUNDLE_INFO_H
