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

namespace OHOS {
namespace Notification {
NotificationConfigParse::NotificationConfigParse()
{
    if (!FileUtils::GetJsonByFilePath(NOTIFICAITON_CONFIG_FILE, notificationConfigJsons_)) {
        ANS_LOGE("Failed to get notification config file, fileName: %{public}s.", NOTIFICAITON_CONFIG_FILE);
    }
    defaultCurrentSlotReminder_ = {
        {NotificationConstant::SlotType::SOCIAL_COMMUNICATION, 0b111111},
        {NotificationConstant::SlotType::SERVICE_REMINDER, 0b111111},
        {NotificationConstant::SlotType::CONTENT_INFORMATION, 0b000000},
        {NotificationConstant::SlotType::OTHER, 0b000000},
        {NotificationConstant::SlotType::LIVE_VIEW, 0b111011},
        {NotificationConstant::SlotType::CUSTOMER_SERVICE, 0b110001},
        {NotificationConstant::SlotType::EMERGENCY_INFORMATION, 0b111111}
    };
}

std::shared_ptr<NotificationAppPrivileges> NotificationConfigParse::GetAppPrivileges(
    const std::string &bundleName) const
{
    nlohmann::json root;
    std::string JsonPoint = "/";
    JsonPoint.append(APP_PRIVILEGES);
    if (!GetConfigJson(JsonPoint, root)) {
        ANS_LOGE("Failed to get JsonPoint CCM config file.");
        return nullptr;
    }
    if (!root.contains(APP_PRIVILEGES)) {
        ANS_LOGW("not found jsonKey appPrivileges");
        return nullptr;
    }
    nlohmann::json affects = root[APP_PRIVILEGES];
    if (affects.is_null() || affects.empty()) {
        ANS_LOGE("GetCcmPrivileges failed as invalid ccmPrivileges json.");
        return nullptr;
    }
    for (auto &affect : affects.items()) {
        if (affect.key() == bundleName) {
            return std::make_shared<NotificationAppPrivileges>(affect.value());
        }
    }
    return nullptr;
}

bool NotificationConfigParse::GetConfigJson(const std::string &keyCheck, nlohmann::json &configJson) const
{
    if (notificationConfigJsons_.size() <= 0) {
        ANS_LOGE("Failed to get config json cause empty notificationConfigJsons.");
        return false;
    }
    bool ret = false;
    std::for_each(notificationConfigJsons_.rbegin(), notificationConfigJsons_.rend(),
        [&keyCheck, &configJson, &ret](const nlohmann::json &json) {
        if (keyCheck.find("/") == std::string::npos && json.contains(keyCheck)) {
            configJson = json;
            ret = true;
        }

        if (keyCheck.find("/") != std::string::npos) {
            nlohmann::json::json_pointer keyCheckPoint(keyCheck);
            if (json.contains(keyCheckPoint)) {
                configJson = json;
                ret = true;
            }
        }
    });
    if (!ret) {
        ANS_LOGE("Cannot find keyCheck: %{public}s in notificationConfigJsons.", keyCheck.c_str());
    }
    return ret;
}

bool NotificationConfigParse::GetCurrentSlotReminder(
    std::map<NotificationConstant::SlotType, std::shared_ptr<NotificationFlags>> &currentSlotReminder) const
{
    nlohmann::json root;
    std::string slotJsonPoint = "/";
    slotJsonPoint.append(CFG_KEY_NOTIFICATION_SERVICE);
    slotJsonPoint.append("/");
    slotJsonPoint.append(CFG_KEY_SLOT_TYPE_REMINDER);
    if (!GetConfigJson(slotJsonPoint, root)) {
        return false;
    }

    if (root.find(CFG_KEY_NOTIFICATION_SERVICE) == root.end()) {
        ANS_LOGE("GetCurrentSlotReminder failed as can not find notificationService.");
        return false;
    }
    nlohmann::json currentDeviceRemindJson = root[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_SLOT_TYPE_REMINDER];
    if (currentDeviceRemindJson.is_null() || !currentDeviceRemindJson.is_array() || currentDeviceRemindJson.empty()) {
        ANS_LOGE("GetCurrentSlotReminder failed as invalid currentDeviceReminder json.");
        return false;
    }
    for (auto &reminderFilterSlot : currentDeviceRemindJson) {
        NotificationConstant::SlotType slotType;
        if (reminderFilterSlot.find(CFG_KEY_NAME) == reminderFilterSlot.end() ||
            reminderFilterSlot[CFG_KEY_NAME].is_null() ||
            !reminderFilterSlot[CFG_KEY_NAME].is_string() ||
            !NotificationSlot::GetSlotTypeByString(reminderFilterSlot[CFG_KEY_NAME].get<std::string>(), slotType)) {
            continue;
        }

        std::shared_ptr<NotificationFlags> reminderFlags;
        if (reminderFilterSlot.find(CFG_KEY_REMINDER_FLAGS) == reminderFilterSlot.end() ||
            reminderFilterSlot[CFG_KEY_REMINDER_FLAGS].is_null() ||
            !reminderFilterSlot[CFG_KEY_REMINDER_FLAGS].is_string() ||
            !NotificationFlags::GetReminderFlagsByString(
                reminderFilterSlot[CFG_KEY_REMINDER_FLAGS].get<std::string>(), reminderFlags)) {
            continue;
        }
        currentSlotReminder[slotType] = reminderFlags;
    }
    if (currentSlotReminder.size() <= 0) {
        ANS_LOGE("GetCurrentSlotReminder failed as invalid currentSlotReminder size.");
        return false;
    }
    return true;
}

uint32_t NotificationConfigParse::GetConfigSlotReminderModeByType(NotificationConstant::SlotType slotType)
{
    static std::map<NotificationConstant::SlotType, std::shared_ptr<NotificationFlags>> configSlotsReminder;
    {
        std::lock_guard<std::mutex> lock(slotReminderMutex_);
        if (configSlotsReminder.empty()) {
            GetCurrentSlotReminder(configSlotsReminder);
        }
    }
    auto iter = configSlotsReminder.find(slotType);
    if (iter != configSlotsReminder.end()) {
        return iter->second->GetReminderFlags();
    }

    auto defaultIter = defaultCurrentSlotReminder_.find(slotType);
    if (defaultIter != defaultCurrentSlotReminder_.end()) {
        return defaultIter->second;
    }

    return 0;
}

bool NotificationConfigParse::IsLiveViewEnabled(const std::string bundleName) const
{
    std::shared_ptr<NotificationAppPrivileges> appPrivileges = GetAppPrivileges(bundleName);
    if (appPrivileges == nullptr) {
        return false;
    }
    return appPrivileges->IsLiveViewEnabled();
}

bool NotificationConfigParse::IsReminderEnabled(const std::string& bundleName) const
{
    std::shared_ptr<NotificationAppPrivileges> appPrivileges = GetAppPrivileges(bundleName);
    if (appPrivileges == nullptr) {
        return false;
    }
    return appPrivileges->IsReminderEnabled();
}

bool NotificationConfigParse::IsBannerEnabled(const std::string bundleName) const
{
    std::shared_ptr<NotificationAppPrivileges> appPrivileges = GetAppPrivileges(bundleName);
    if (appPrivileges != nullptr && appPrivileges->IsBannerEnabled()) {
        return true;
    }
#ifdef ENABLE_ANS_ADDITIONAL_CONTROL
    int32_t ctrlResult = EXTENTION_WRAPPER->BannerControl(bundleName);
    return (ctrlResult == ERR_OK) ? true : false;
#else
    return false;
#endif
}

void NotificationConfigParse::GetFlowCtrlConfigFromCCM(FlowControlThreshold &threshold)
{
    nlohmann::json root;
    std::string JsonPoint = "/";
    JsonPoint.append(CFG_KEY_NOTIFICATION_SERVICE);
    if (!GetConfigJson(JsonPoint, root)) {
        ANS_LOGE("Failed to get JsonPoint CCM config file");
        return;
    }
    if (!root.contains(CFG_KEY_NOTIFICATION_SERVICE)) {
        ANS_LOGW("GetFlowCtrlConfigFromCCM not found jsonKey");
        return;
    }
    nlohmann::json affects = root[CFG_KEY_NOTIFICATION_SERVICE];
    if (affects.is_null() || affects.empty()) {
        ANS_LOGE("GetFlowCtrlConfigFromCCM failed as invalid ccmFlowCtrlConfig json");
        return;
    }
    if (affects.contains(CFG_KEY_MAX_CREATE_NUM_PERSECOND)) {
        threshold.maxCreateNumPerSecond = affects[CFG_KEY_MAX_CREATE_NUM_PERSECOND];
    }

    if (affects.contains(CFG_KEY_MAX_UPDATE_NUM_PERSECOND)) {
        threshold.maxUpdateNumPerSecond = affects[CFG_KEY_MAX_UPDATE_NUM_PERSECOND];
    }

    if (affects.contains(CFG_KEY_MAX_CREATE_NUM_PERSECOND_PERAPP)) {
        threshold.maxCreateNumPerSecondPerApp = affects[CFG_KEY_MAX_CREATE_NUM_PERSECOND_PERAPP];
    }

    if (affects.contains(CFG_KEY_MAX_UPDATE_NUM_PERSECOND_PERAPP)) {
        threshold.maxUpdateNumPerSecondPerApp = affects[CFG_KEY_MAX_UPDATE_NUM_PERSECOND_PERAPP];
    }

    ANS_LOGI("GetFlowCtrlConfigFromCCM success");
}

bool NotificationConfigParse::GetSmartReminderEnableList(std::vector<std::string>& deviceTypes)
{
    nlohmann::json root;
    std::string jsonPoint = "/";
    jsonPoint.append(CFG_KEY_NOTIFICATION_SERVICE);
    jsonPoint.append("/");
    jsonPoint.append(CFG_KEY_SMART_REMINDER_ENABLE_LIST);
    if (!GetConfigJson(jsonPoint, root)) {
        ANS_LOGE("get configJson fail");
        return false;
    }

    if (root.find(CFG_KEY_NOTIFICATION_SERVICE) == root.end()) {
        ANS_LOGE("find notificationService fail");
        return false;
    }

    nlohmann::json smartReminderEnableList = root[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_SMART_REMINDER_ENABLE_LIST];
    if (smartReminderEnableList.is_null() || !smartReminderEnableList.is_array() || smartReminderEnableList.empty()) {
        ANS_LOGE("smartReminderEnableList is invalid");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    deviceTypes = smartReminderEnableList.get<std::vector<std::string>>();
    return true;
}

bool NotificationConfigParse::GetMirrorNotificationEnabledStatus(std::vector<std::string>& deviceTypes)
{
    nlohmann::json root;
    std::string jsonPoint = "/";
    jsonPoint.append(CFG_KEY_NOTIFICATION_SERVICE);
    jsonPoint.append("/");
    jsonPoint.append(CFG_KEY_MIRROR_NOTIFICAITON_ENABLED_STATUS);
    if (!GetConfigJson(jsonPoint, root)) {
        ANS_LOGE("get configJson fail");
        return false;
    }

    if (root.find(CFG_KEY_NOTIFICATION_SERVICE) == root.end()) {
        ANS_LOGE("find notificationService fail");
        return false;
    }

    nlohmann::json mirrorNotificationEnabledStatus =
        root[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_MIRROR_NOTIFICAITON_ENABLED_STATUS];
    if (mirrorNotificationEnabledStatus.is_null() || !mirrorNotificationEnabledStatus.is_array() ||
        mirrorNotificationEnabledStatus.empty()) {
        ANS_LOGE("mirrorNotificationEnabledStatus is invalid");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    deviceTypes = mirrorNotificationEnabledStatus.get<std::vector<std::string>>();
    return true;
}

bool NotificationConfigParse::GetAppAndDeviceRelationMap(std::map<std::string, std::string>& relationMap)
{
    nlohmann::json root;
    std::string jsonPoint = "/";
    jsonPoint.append(CFG_KEY_NOTIFICATION_SERVICE);
    jsonPoint.append("/");
    jsonPoint.append(CFG_KEY_APP_AND_DEVICE_RELATION_MAP);
    if (!GetConfigJson(jsonPoint, root)) {
        ANS_LOGE("get configJson fail");
        return false;
    }

    if (root.find(CFG_KEY_NOTIFICATION_SERVICE) == root.end()) {
        ANS_LOGE("find notificationService fail");
        return false;
    }

    nlohmann::json appAndDeviceRelationMap = root[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_APP_AND_DEVICE_RELATION_MAP];
    if (appAndDeviceRelationMap.is_null() || appAndDeviceRelationMap.empty()) {
        ANS_LOGE("appAndDeviceRelationMap is invalid");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& appAndDeviceRelation : appAndDeviceRelationMap.items()) {
        relationMap[appAndDeviceRelation.key()] = appAndDeviceRelation.value();
    }
    return true;
}

std::unordered_set<std::string> NotificationConfigParse::GetCollaborativeDeleteType() const
{
    nlohmann::json root;
    std::string JsonPoint = "/";
    JsonPoint.append(CFG_KEY_NOTIFICATION_SERVICE);
    JsonPoint.append("/");
    JsonPoint.append(CFG_KEY_COLLABORATIVE_DELETE_TYPES);
    if (!GetConfigJson(JsonPoint, root)) {
        ANS_LOGE("GetConfigJson faild");
        return std::unordered_set<std::string>();
    }
    if (root.find(CFG_KEY_NOTIFICATION_SERVICE) == root.end()) {
        ANS_LOGE("appPrivileges null");
        return std::unordered_set<std::string>();
    }

    nlohmann::json collaborativeDeleteTypes = root[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_COLLABORATIVE_DELETE_TYPES];
    if (collaborativeDeleteTypes.empty() && !collaborativeDeleteTypes.is_array()) {
        ANS_LOGE("collaborativeDeleteTypes null or no array");
        return std::unordered_set<std::string>();
    }
    std::unordered_set<std::string> collaborativeDeleteTypeSet;
    for (const auto &item : collaborativeDeleteTypes) {
        if (item.is_string()) {
            collaborativeDeleteTypeSet.insert(item.get<std::string>());
        }
    }

    return collaborativeDeleteTypeSet;
}

bool NotificationConfigParse::GetFilterUidAndBundleName(const std::string &key)
{
    nlohmann::json root;
    std::string jsonPoint = "/";
    jsonPoint.append(CFG_KEY_NOTIFICATION_SERVICE).append("/").append(COLLABORATION_FILTER).append("/").append(key);
    if (!GetConfigJson(jsonPoint, root)) {
        ANS_LOGE("Failed to get jsonPoint CCM config file.");
        return false;
    }

    if (!root.contains(CFG_KEY_NOTIFICATION_SERVICE) ||
        !root[CFG_KEY_NOTIFICATION_SERVICE].contains(COLLABORATION_FILTER)) {
        ANS_LOGE("Not found jsonKey collaborationFilter.");
        return false;
    }

    nlohmann::json collaborationFilter = root[CFG_KEY_NOTIFICATION_SERVICE][COLLABORATION_FILTER];
    if (collaborationFilter.is_null() || collaborationFilter.empty()) {
        ANS_LOGE("GetCollaborationFilter failed as invalid ccmCollaborationFilter json.");
        return false;
    }
    if (collaborationFilter.contains(key) && collaborationFilter[key].is_array()) {
        for (const auto& item : collaborationFilter[key]) {
            if (item.is_number_integer()) {
                uidList_.push_back(item.get<int32_t>());
            }
            if (item.is_string()) {
                bundleNameList_.push_back(item.get<std::string>());
            }
        }
        return true;
    }
    return false;
}

void NotificationConfigParse::GetCollaborationFilter()
{
    if (!GetFilterUidAndBundleName(COLLABORATION_FILTER_KEY_UID)) {
        ANS_LOGW("Failed to get filterUid.");
    }
    if (!GetFilterUidAndBundleName(COLLABORATION_FILTER_KEY_NAME)) {
        ANS_LOGW("Failed to get filterBundleName.");
    }
}

bool NotificationConfigParse::IsInCollaborationFilter(const std::string& bundleName, int32_t uid) const
{
    if (uidList_.empty() && bundleNameList_.empty()) {
        ANS_LOGW("UidList and bundleNameList empty.");
        return false;
    }

    if (std::find(uidList_.begin(), uidList_.end(), uid) != uidList_.end()) {
        ANS_LOGI("Uid <%{public}d> in CollaborationFilter.", uid);
        return true;
    }

    if (std::find(bundleNameList_.begin(), bundleNameList_.end(), bundleName) != bundleNameList_.end()) {
        ANS_LOGI("BundleName <%{public}s> in CollaborationFilter.", bundleName.c_str());
        return true;
    }

    ANS_LOGI("Uid <%{public}d> and BundleName <%{public}s> not in CollaborationFilter.", uid, bundleName.c_str());
    return false;
}

uint32_t NotificationConfigParse::GetStartAbilityTimeout()
{
    nlohmann::json root;
    std::string JsonPoint = "/";
    JsonPoint.append(CFG_KEY_NOTIFICATION_SERVICE);
    if (!GetConfigJson(JsonPoint, root)) {
        ANS_LOGE("Failed to get JsonPoint CCM config file");
        return 0;
    }
    if (!root.contains(CFG_KEY_NOTIFICATION_SERVICE)) {
        ANS_LOGW("GetStartAbilityTimeout not found jsonKey");
        return 0;
    }
    nlohmann::json affects = root[CFG_KEY_NOTIFICATION_SERVICE];
    if (affects.is_null() || affects.empty()) {
        ANS_LOGE("GetStartAbilityTimeout failed as invalid ccmFlowCtrlConfig json");
        return 0;
    }
    if (affects.contains(CFG_KEY_START_ABILITY_TIMEOUT)) {
        return affects[CFG_KEY_START_ABILITY_TIMEOUT];
    }

    return 0;
}

void NotificationConfigParse::GetReportTrustListConfig()
{
    nlohmann::json root;
    std::string reportJsonPoint = "/";
    reportJsonPoint.append(CFG_KEY_NOTIFICATION_SERVICE);
    reportJsonPoint.append("/");
    reportJsonPoint.append(CFG_KEY_DFX_NORMAL_EVENT);
    if (!GetConfigJson(reportJsonPoint, root)) {
        return;
    }
    if (root.find(CFG_KEY_NOTIFICATION_SERVICE) == root.end()) {
        ANS_LOGE("Failed to get JsonPoint CCM config file");
        return;
    }

    nlohmann::json reportTrustList = root[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_DFX_NORMAL_EVENT];
    if (reportTrustList.is_null() || reportTrustList.empty() || !reportTrustList.is_array()) {
        ANS_LOGE("GetReportTrustListConfig failed as invalid dfx_normal_events json.");
        return;
    }
    for (auto &reportTrust : reportTrustList) {
        reporteTrustSet_.emplace(reportTrust);
    }
    return;
}


bool NotificationConfigParse::IsReportTrustList(const std::string& bundleName) const
{
    return reporteTrustSet_.count(bundleName);
}

} // namespace Notification
} // namespace OHOS
