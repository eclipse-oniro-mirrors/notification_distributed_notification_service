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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CONFIG_FILE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CONFIG_FILE_H

#include <map>
#include <string>
#include <set>
#include <vector>
#include <singleton.h>
#include <unordered_set>
#include <mutex>

#ifdef CONFIG_POLICY_ENABLE
#include "config_policy_utils.h"
#endif
#include "nlohmann/json.hpp"
#include "notification_app_privileges.h"
#include "notification_bundle_option.h"
#include "notification_constant.h"
#include "notification_flags.h"
#include "advanced_notification_flow_control_service.h"

namespace OHOS {
namespace Notification {
class NotificationConfigParse : public DelayedSingleton<NotificationConfigParse> {
public:
    NotificationConfigParse();
    ~NotificationConfigParse() = default;

    bool GetConfigJson(const std::string &keyCheck, nlohmann::json &configJson) const;
    bool GetCurrentSlotReminder(
        std::map<NotificationConstant::SlotType, std::shared_ptr<NotificationFlags>> &currentSlotReminder) const;
    void GetReportTrustListConfig();
    bool IsReportTrustList(const std::string& bundleName) const;
    bool IsReportTrustBundles(const std::string& bundleName) const;
    uint32_t GetConfigSlotReminderModeByType(NotificationConstant::SlotType slotType);
    std::shared_ptr<NotificationAppPrivileges> GetAppPrivileges(const std::string &bundleName) const;
    bool IsLiveViewEnabled(const std::string bundleName) const;
    bool IsBannerEnabled(const std::string bundleName) const;
    bool IsReminderEnabled(const std::string& bundleName) const;
    bool IsDistributedReplyEnabled(const std::string& bundleName) const;
    void GetFlowCtrlConfigFromCCM(FlowControlThreshold &threshold);
    bool GetSmartReminderEnableList(std::vector<std::string>& deviceTypes);
    bool GetMirrorNotificationEnabledStatus(std::vector<std::string>& deviceTypes);
    bool GetAppAndDeviceRelationMap(std::map<std::string, std::string>& relationMap);
    std::unordered_set<std::string> GetCollaborativeDeleteType() const;
    bool GetCollaborativeDeleteTypeByDevice(std::map<std::string, std::map<std::string,
        std::unordered_set<std::string>>>& map) const;
    bool GetFilterUidAndBundleName(const std::string &key);
    void GetCollaborationFilter();
    bool IsInCollaborationFilter(const std::string &bundleName, int32_t uid) const;
    uint32_t GetStartAbilityTimeout();
    bool CheckAppLiveViewCcm();
    bool IsNotificationExtensionSubscribeSupportHfp(bool &outSupportHfp) const;
    bool IsNotificationExtensionLifecycleDestroyTimeConfigured(uint32_t &outDestroyTime) const;
    bool GetNotificationExtensionEnabledBundlesWriteList(std::vector<std::string>& bundles) const;

private:
    bool ParseCollaborativeDeleteTypesDevices(std::map<std::string, std::map<std::string,
        std::unordered_set<std::string>>>& map, nlohmann::json& collaborativeDeleteTypes) const;
    bool ParseDeviceSlotType(const nlohmann::json& device,
        std::map<std::string, std::unordered_set<std::string>>& peerDeviceTypeMap) const;
    std::map<NotificationConstant::SlotType, uint32_t> defaultCurrentSlotReminder_;
    std::vector<nlohmann::json> notificationConfigJsons_;
    ffrt::mutex mutex_;
    ffrt::mutex slotReminderMutex_;
    std::vector<int32_t> uidList_;
    std::vector<std::string> bundleNameList_;
    std::set<std::string> reporteTrustSet_ {};
    std::set<std::string> keyTrustBundles_ {};

public:
    constexpr static const char* CFG_KEY_NOTIFICATION_SERVICE = "notificationService";
    constexpr static const char* CFG_KEY_SLOT_TYPE_REMINDER = "slotTypeReminder";
    constexpr static const char* APP_LIVEVIEW_PERMISSIONS = "appLiveViewPermissions";
    constexpr static const char* CFG_KEY_NAME = "name";
    constexpr static const char* CFG_KEY_REMINDER_FLAGS = "reminderFlags";
    constexpr static const char* APP_PRIVILEGES = "appPrivileges";
    constexpr static const char* COLLABORATION_FILTER = "collaborationFilter";
    constexpr static const char* COLLABORATION_FILTER_KEY_NAME = "bundleName";
    constexpr static const char* COLLABORATION_FILTER_KEY_UID = "uid";
    constexpr static const char* CFG_KEY_MAX_CREATE_NUM_PERSECOND = "MaxCreateNumPerSecond";
    constexpr static const char* CFG_KEY_MAX_UPDATE_NUM_PERSECOND = "MaxUpdateNumPerSecond";
    constexpr static const char* CFG_KEY_MAX_CREATE_NUM_PERSECOND_PERAPP = "MaxCreateNumPerSecondPerApp";
    constexpr static const char* CFG_KEY_MAX_UPDATE_NUM_PERSECOND_PERAPP = "MaxUpdateNumPerSecondPerApp";
    constexpr static const char* CFG_KEY_SMART_REMINDER_ENABLE_LIST = "smartReminderEnableList";
    constexpr static const char* CFG_KEY_MIRROR_NOTIFICAITON_ENABLED_STATUS = "mirrorNotificationEnabledStatus";
    constexpr static const char* CFG_KEY_APP_AND_DEVICE_RELATION_MAP = "appAndDeviceRelationMap";
    constexpr static const char* CFG_KEY_DFX_NORMAL_EVENT = "dfxNormalEvent";
    constexpr static const char* CFG_KEY_BUNDLE_NAME = "dfxKeyBundle";
    constexpr static const char* CFG_KEY_NOTIFICATION_EXTENSION = "notificationExtension";
    constexpr static const char* CFG_KEY_SUPPORT_HFP = "supportHfp";
    constexpr static const char* CFG_KEY_NOTIFICATION_EXTENSION_LIFECYCLE_DESTROY_TIME = "lifecycleDestroyTime";
    constexpr static const char* CFG_KEY_ENABLED_BUNDLES_WRITE_LIST = "enabledBundlesWriteList";
    #ifdef CONFIG_POLICY_ENABLE
        constexpr static const char* NOTIFICAITON_CONFIG_FILE = "etc/notification/notification_config.json";
    # else
        constexpr static const char* NOTIFICAITON_CONFIG_FILE = "system/etc/notification/notification_config.json";
    #endif
    constexpr static const char* CFG_KEY_COLLABORATIVE_DELETE_TYPES = "collaborativeDeleteTypes";
    constexpr static const char* CFG_KEY_START_ABILITY_TIMEOUT = "startAbilityTimeout";
    constexpr static const char* CFG_KEY_COLLABORATIVE_DELETE_TYPES_DEVICES = "collaborativeDeleteTypesDevices";
    constexpr static const char* LOCAL_DEVICE_TYPE = "localDeviceType";
    constexpr static const char* PEER_DELETE_FILTER_DEVICE = "peerDeleteFilterDevice";
    constexpr static const char* PEER_DEVICE_TYPE = "peerDeviceType";
    constexpr static const char* DELETE_SLOT_TYPE = "deleteSlotTypes";
};
} // namespace Notification
} // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CONFIG_FILE_H
