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

#include <memory>

#include "notification_config_parse.h"

#include "ans_log_wrapper.h"
#ifdef ENABLE_ANS_ADDITIONAL_CONTROL
#include "notification_extension_wrapper.h"
#endif
#include "notification_slot.h"
#include "file_utils.h"
#include "mock_device_manager_impl.h"

namespace OHOS {
namespace Notification {
static int32_t g_configScene = -1;
constexpr int32_t CONFIG_SCENE_0 = 0;
constexpr int32_t CONFIG_SCENE_1 = 1;
constexpr int32_t CONFIG_SCENE_2 = 2;
constexpr int32_t CONFIG_SCENE_3 = 3;
constexpr int32_t CONFIG_SCENE_4 = 4;
constexpr int32_t DEFAULT_TITLE_LENGTH = 200;
constexpr int32_t DEFAULT_CONTENT_LENGTH = 400;
constexpr int32_t MOCK_DEFAULT_REPLY_TIMEOUT = 3;

void DeviceTrigger::MockConfigScene(int32_t scene)
{
    g_configScene = scene;
}

NotificationConfigParse::NotificationConfigParse()
{
}

std::shared_ptr<NotificationAppPrivileges> NotificationConfigParse::GetAppPrivileges(
    const std::string &bundleName) const
{
    return nullptr;
}

bool NotificationConfigParse::GetConfigJson(const std::string &keyCheck, nlohmann::json &configJson) const
{
    if (g_configScene == CONFIG_SCENE_0) {
        return false;
    }
    if (g_configScene == CONFIG_SCENE_1) {
        return true;
    }
    if (g_configScene == CONFIG_SCENE_2) {
        nlohmann::json distribuedConfig;
        nlohmann::json notificationService;
        notificationService["distribuedConfig"] = distribuedConfig;
        configJson["notificationService"] = notificationService;
        return true;
    }
    if (g_configScene == CONFIG_SCENE_3) {
        nlohmann::json distribuedConfig;
        distribuedConfig["maxContentLength"] = std::string();
        nlohmann::json notificationService;
        notificationService["distribuedConfig"] = distribuedConfig;
        configJson["notificationService"] = notificationService;
        return true;
    }
    if (g_configScene == CONFIG_SCENE_4) {
        nlohmann::json distribuedConfig;
        nlohmann::json supportPeerDevice = nlohmann::json::array();
        supportPeerDevice.emplace_back("Watch");
        distribuedConfig["supportPeerDevice"] = supportPeerDevice;
        nlohmann::json notificationService;
        notificationService["distribuedConfig"] = distribuedConfig;
        configJson["notificationService"] = notificationService;
        return true;
    }
    nlohmann::json distribuedConfig;
    nlohmann::json supportPeerDevice = nlohmann::json::array();
    supportPeerDevice.emplace_back("Watch");
    distribuedConfig["localType"] = "Phone";
    distribuedConfig["supportPeerDevice"] = supportPeerDevice;
    distribuedConfig["maxTitleLength"] = DEFAULT_TITLE_LENGTH;
    distribuedConfig["maxContentLength"] = DEFAULT_CONTENT_LENGTH;
    nlohmann::json notificationService;
    notificationService["distribuedConfig"] = distribuedConfig;
    configJson["notificationService"] = notificationService;
    return true;
}

bool NotificationConfigParse::GetCurrentSlotReminder(
    std::map<NotificationConstant::SlotType, std::shared_ptr<NotificationFlags>> &currentSlotReminder) const
{
    return true;
}

uint32_t NotificationConfigParse::GetConfigSlotReminderModeByType(NotificationConstant::SlotType slotType)
{
    return 0;
}

bool NotificationConfigParse::IsLiveViewEnabled(const std::string bundleName) const
{
    return true;
}

bool NotificationConfigParse::IsReminderEnabled(const std::string& bundleName) const
{
    return true;
}

bool NotificationConfigParse::IsDistributedReplyEnabled(const std::string& bundleName) const
{
    return true;
}

bool NotificationConfigParse::IsBannerEnabled(const std::string bundleName) const
{
    return false;
}

void NotificationConfigParse::GetFlowCtrlConfigFromCCM(FlowControlThreshold &threshold)
{
}

bool NotificationConfigParse::GetSmartReminderEnableList(std::vector<std::string>& deviceTypes)
{
    return true;
}

bool NotificationConfigParse::GetMirrorNotificationEnabledStatus(std::vector<std::string>& deviceTypes)
{
    return true;
}

bool NotificationConfigParse::GetAppAndDeviceRelationMap(std::map<std::string, std::string>& relationMap)
{
    return true;
}

std::unordered_set<std::string> NotificationConfigParse::GetCollaborativeDeleteType() const
{
    std::unordered_set<std::string> collaborativeDeleteTypeSet;
    collaborativeDeleteTypeSet.insert("LIVE_VIEW");
    collaborativeDeleteTypeSet.insert("SOCIAL_COMMUNICATION");
    return collaborativeDeleteTypeSet;
}

bool NotificationConfigParse::GetFilterUidAndBundleName(const std::string &key)
{
    return false;
}

void NotificationConfigParse::GetCollaborationFilter()
{
}

bool NotificationConfigParse::IsInCollaborationFilter(const std::string& bundleName, int32_t uid) const
{
    return false;
}

uint32_t NotificationConfigParse::GetStartAbilityTimeout()
{
    return MOCK_DEFAULT_REPLY_TIMEOUT;
}

void NotificationConfigParse::GetReportTrustListConfig()
{
    return;
}

bool NotificationConfigParse::IsReportTrustList(const std::string& bundleName) const
{
    return true;
}
} // namespace Notification
} // namespace OHOS

