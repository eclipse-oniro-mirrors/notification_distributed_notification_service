/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#include "notification_constant.h"

namespace OHOS {
namespace Notification {
class NotificationCloneBundleInfo {
public:
    class SlotInfo {
    public:
        std::string Dump() const;
        NotificationConstant::SlotType slotType_;
        bool enable_;
        bool isForceControl_;
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

    void SetEnableNotification(const NotificationConstant::SWITCH_STATE &state);
    NotificationConstant::SWITCH_STATE GetEnableNotification() const;

    void SetSilentReminderEnabled(const NotificationConstant::SWITCH_STATE &silentReminderEnabled);
    NotificationConstant::SWITCH_STATE GetSilentReminderEnabled() const;

    void AddSlotInfo(const SlotInfo &slotInfo);
    std::vector<SlotInfo> GetSlotInfo() const;

    void ToJson(nlohmann::json &jsonObject) const;
    void FromJson(const nlohmann::json &root);
    void SlotsFromJson(const nlohmann::json &jsonObject);
    std::string Dump() const;

private:
    std::string bundleName_;
    int32_t appIndex_ = -1;
    int32_t uid_ = -1;
    uint32_t slotFlags_ = 0;
    bool isShowBadge_ = false;
    NotificationConstant::SWITCH_STATE isEnabledNotification_ = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    std::vector<SlotInfo> slotsInfo_;
    NotificationConstant::SWITCH_STATE silentReminderEnabled_;
};
} // namespace Notification
} // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_BUNDLE_INFO_H
