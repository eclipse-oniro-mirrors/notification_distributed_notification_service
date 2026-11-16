/*
* Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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
#include "notification_extension_wrapper.h"
#include "os_account_manager_helper.h"
#include "notification_analytics_util.h"

namespace OHOS {
namespace Notification {
namespace {
std::string JsonPoint(const char *key)
{
    return std::string("/") + key;
}

std::string JsonPoint(const char *first, const char *second)
{
    return std::string("/") + first + "/" + second;
}

std::string JsonPoint(const char *first, const char *second, const char *third)
{
    return std::string("/") + first + "/" + second + "/" + third;
}
} // namespace

NotificationConfigParse::NotificationConfigParse()
{
    defaultCurrentSlotReminder_ = {
        {NotificationConstant::SlotType::SOCIAL_COMMUNICATION, 0b111111},
        {NotificationConstant::SlotType::SERVICE_REMINDER, 0b111111},
        {NotificationConstant::SlotType::CONTENT_INFORMATION, 0b000000},
        {NotificationConstant::SlotType::OTHER, 0b000000},
        {NotificationConstant::SlotType::LIVE_VIEW, 0b111011},
        {NotificationConstant::SlotType::CUSTOMER_SERVICE, 0b110001},
        {NotificationConstant::SlotType::EMERGENCY_INFORMATION, 0b111111}
    };

    std::vector<nlohmann::json> docs;
    if (!LoadConfigJsons(docs)) {
        ANS_LOGE("Failed to get notification config file, fileName: %{public}s.", NOTIFICAITON_CONFIG_FILE);
        return;
    }
    ParseConfigs(docs);
}

bool NotificationConfigParse::LoadConfigJsons(std::vector<nlohmann::json> &docs) const
{
    return FileUtils::GetJsonByFilePath(NOTIFICAITON_CONFIG_FILE, docs);
}

const nlohmann::json *NotificationConfigParse::FindConfigDoc(const std::vector<nlohmann::json> &docs,
    const std::string &jsonPoint) const
{
    // Documents are ordered from the highest to the lowest priority, the first match wins.
    for (const auto &doc : docs) {
        if (jsonPoint.find('/') == std::string::npos) {
            if (doc.contains(jsonPoint)) {
                return &doc;
            }
            continue;
        }
        nlohmann::json::json_pointer pointer(jsonPoint);
        if (doc.contains(pointer)) {
            return &doc;
        }
    }
    return nullptr;
}

bool __attribute__((weak)) NotificationConfigParse::GetConfigJson(
    const std::string &keyCheck, nlohmann::json &configJson) const
{
    std::vector<nlohmann::json> docs;
    if (!LoadConfigJsons(docs) || docs.empty()) {
        ANS_LOGE("Failed to get config json cause empty notificationConfigJsons.");
        return false;
    }
    const nlohmann::json *doc = FindConfigDoc(docs, keyCheck);
    if (doc == nullptr) {
        ANS_LOGE("Cannot find keyCheck: %{public}s in notificationConfigJsons.", keyCheck.c_str());
        return false;
    }
    configJson = *doc;
    return true;
}

void NotificationConfigParse::ParseConfigs(const std::vector<nlohmann::json> &docs)
{
    appPrivileges_.clear();
    currentSlotReminder_.clear();
    hasSlotReminder_ = false;
    flowCtrlConfig_ = FlowCtrlConfig();
    smartReminderEnableList_.clear();
    hasSmartReminderEnableList_ = false;
    mirrorNotificationEnabledStatus_.clear();
    hasMirrorNotificationEnabledStatus_ = false;
    appAndDeviceRelationMap_.clear();
    hasAppAndDeviceRelationMap_ = false;
    collaborativeDeleteTypes_.clear();
    collaborativeDeleteTypesByDevice_.clear();
    hasCollaborativeDeleteTypesByDevice_ = false;
    hasAppLiveViewCcm_ = false;
    startAbilityTimeout_ = 0;
    hasStartAbilityTimeout_ = false;
    cloneExpiredTimeDays_ = 0;
    hasCloneExpiredTime_ = false;
    dataCloneBundleName_.clear();
    extensionLifecycleDestroyTime_ = 0;
    hasExtensionLifecycleDestroyTime_ = false;
    extensionEnabledBundlesWriteList_.clear();
    hasExtensionEnabledBundlesWriteList_ = false;
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        uidList_.clear();
        bundleNameList_.clear();
    }
    reporteTrustSet_.clear();
    keyTrustBundles_.clear();

    ParseAppPrivileges(docs);
    ParseSlotTypeReminder(docs);
    ParseFlowCtrlConfig(docs);
    ParseSmartReminderEnableList(docs);
    ParseMirrorNotificationEnabledStatus(docs);
    ParseAppAndDeviceRelationMap(docs);
    ParseCollaborativeDeleteTypes(docs);
    ParseCollaborativeDeleteTypesByDevice(docs);
    ParseCollaborationFilter(docs);
    ParseStartAbilityTimeout(docs);
    ParseAppLiveViewCcm(docs);
    ParseReportTrustList(docs);
    ParseCloneExpiredTime(docs);
    ParseDataCloneBundleName(docs);
    ParseNotificationExtension(docs);
}

void NotificationConfigParse::ParseAppPrivileges(const std::vector<nlohmann::json> &docs)
{
    const nlohmann::json *root = FindConfigDoc(docs, JsonPoint(APP_PRIVILEGES));
    if (root == nullptr) {
        ANS_LOGE("not found jsonKey appPrivileges");
        return;
    }
    const nlohmann::json &affects = (*root)[APP_PRIVILEGES];
    if (affects.is_null() || affects.empty() || !affects.is_object()) {
        ANS_LOGE("GetCcmPrivileges failed as invalid ccmPrivileges json.");
        return;
    }
    for (const auto &affect : affects.items()) {
        if (affect.value().is_string()) {
            appPrivileges_[affect.key()] =
                std::make_shared<NotificationAppPrivileges>(affect.value().get<std::string>());
        }
    }
}

void NotificationConfigParse::ParseSlotTypeReminder(const std::vector<nlohmann::json> &docs)
{
    const nlohmann::json *root = FindConfigDoc(docs, JsonPoint(CFG_KEY_NOTIFICATION_SERVICE,
        CFG_KEY_SLOT_TYPE_REMINDER));
    if (root == nullptr) {
        return;
    }
    const nlohmann::json &currentDeviceRemindJson =
        (*root)[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_SLOT_TYPE_REMINDER];
    if (currentDeviceRemindJson.is_null() || !currentDeviceRemindJson.is_array() || currentDeviceRemindJson.empty()) {
        ANS_LOGE("GetCurrentSlotReminder failed as invalid currentDeviceReminder json.");
        return;
    }
    for (const auto &reminderFilterSlot : currentDeviceRemindJson) {
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
        currentSlotReminder_[slotType] = reminderFlags;
    }
    hasSlotReminder_ = !currentSlotReminder_.empty();
    if (!hasSlotReminder_) {
        ANS_LOGE("GetCurrentSlotReminder failed as invalid currentSlotReminder size.");
    }
}

void NotificationConfigParse::ParseFlowCtrlConfig(const std::vector<nlohmann::json> &docs)
{
    const nlohmann::json *root = FindConfigDoc(docs, JsonPoint(CFG_KEY_NOTIFICATION_SERVICE));
    if (root == nullptr) {
        ANS_LOGE("GetFlowCtrlConfigFromCCM not found jsonKey");
        return;
    }
    const nlohmann::json &affects = (*root)[CFG_KEY_NOTIFICATION_SERVICE];
    if (affects.is_null() || affects.empty()) {
        ANS_LOGE("GetFlowCtrlConfigFromCCM failed as invalid ccmFlowCtrlConfig json");
        return;
    }
    if (affects.contains(CFG_KEY_MAX_CREATE_NUM_PERSECOND) &&
        affects[CFG_KEY_MAX_CREATE_NUM_PERSECOND].is_number_integer()) {
        flowCtrlConfig_.maxCreateNumPerSecond = affects[CFG_KEY_MAX_CREATE_NUM_PERSECOND].get<uint32_t>();
        flowCtrlConfig_.hasMaxCreateNumPerSecond = true;
    }
    if (affects.contains(CFG_KEY_MAX_UPDATE_NUM_PERSECOND) &&
        affects[CFG_KEY_MAX_UPDATE_NUM_PERSECOND].is_number_integer()) {
        flowCtrlConfig_.maxUpdateNumPerSecond = affects[CFG_KEY_MAX_UPDATE_NUM_PERSECOND].get<uint32_t>();
        flowCtrlConfig_.hasMaxUpdateNumPerSecond = true;
    }
    if (affects.contains(CFG_KEY_MAX_CREATE_NUM_PERSECOND_PERAPP) &&
        affects[CFG_KEY_MAX_CREATE_NUM_PERSECOND_PERAPP].is_number_integer()) {
        flowCtrlConfig_.maxCreateNumPerSecondPerApp =
            affects[CFG_KEY_MAX_CREATE_NUM_PERSECOND_PERAPP].get<uint32_t>();
        flowCtrlConfig_.hasMaxCreateNumPerSecondPerApp = true;
    }
    if (affects.contains(CFG_KEY_MAX_UPDATE_NUM_PERSECOND_PERAPP) &&
        affects[CFG_KEY_MAX_UPDATE_NUM_PERSECOND_PERAPP].is_number_integer()) {
        flowCtrlConfig_.maxUpdateNumPerSecondPerApp =
            affects[CFG_KEY_MAX_UPDATE_NUM_PERSECOND_PERAPP].get<uint32_t>();
        flowCtrlConfig_.hasMaxUpdateNumPerSecondPerApp = true;
    }
    ANS_LOGI("GetFlowCtrlConfigFromCCM success");
}

void NotificationConfigParse::ParseSmartReminderEnableList(const std::vector<nlohmann::json> &docs)
{
    const nlohmann::json *root = FindConfigDoc(docs, JsonPoint(CFG_KEY_NOTIFICATION_SERVICE,
        CFG_KEY_SMART_REMINDER_ENABLE_LIST));
    if (root == nullptr) {
        ANS_LOGE("get configJson fail");
        return;
    }
    const nlohmann::json &smartReminderEnableList =
        (*root)[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_SMART_REMINDER_ENABLE_LIST];
    if (smartReminderEnableList.is_null() || !smartReminderEnableList.is_array() || smartReminderEnableList.empty()) {
        ANS_LOGE("smartReminderEnableList is invalid");
        return;
    }
    hasSmartReminderEnableList_ = true;
    for (const auto &deviceType : smartReminderEnableList) {
        if (deviceType.is_string()) {
            smartReminderEnableList_.push_back(deviceType.get<std::string>());
        }
    }
}

void NotificationConfigParse::ParseMirrorNotificationEnabledStatus(const std::vector<nlohmann::json> &docs)
{
    const nlohmann::json *root = FindConfigDoc(docs, JsonPoint(CFG_KEY_NOTIFICATION_SERVICE,
        CFG_KEY_MIRROR_NOTIFICAITON_ENABLED_STATUS));
    if (root == nullptr) {
        ANS_LOGE("get configJson fail");
        return;
    }
    const nlohmann::json &mirrorNotificationEnabledStatus =
        (*root)[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_MIRROR_NOTIFICAITON_ENABLED_STATUS];
    if (mirrorNotificationEnabledStatus.is_null() || !mirrorNotificationEnabledStatus.is_array() ||
        mirrorNotificationEnabledStatus.empty()) {
        ANS_LOGE("Invalid mirror Status");
        return;
    }
    hasMirrorNotificationEnabledStatus_ = true;
    for (const auto &deviceType : mirrorNotificationEnabledStatus) {
        if (deviceType.is_string()) {
            mirrorNotificationEnabledStatus_.push_back(deviceType.get<std::string>());
        }
    }
}

void NotificationConfigParse::ParseAppAndDeviceRelationMap(const std::vector<nlohmann::json> &docs)
{
    const nlohmann::json *root = FindConfigDoc(docs, JsonPoint(CFG_KEY_NOTIFICATION_SERVICE,
        CFG_KEY_APP_AND_DEVICE_RELATION_MAP));
    if (root == nullptr) {
        ANS_LOGE("get configJson fail");
        return;
    }
    const nlohmann::json &appAndDeviceRelationMap =
        (*root)[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_APP_AND_DEVICE_RELATION_MAP];
    if (appAndDeviceRelationMap.is_null() || appAndDeviceRelationMap.empty()) {
        ANS_LOGE("appAndDeviceRelationMap is invalid");
        return;
    }
    hasAppAndDeviceRelationMap_ = true;
    for (const auto &relation : appAndDeviceRelationMap.items()) {
        if (relation.value().is_string()) {
            appAndDeviceRelationMap_[relation.key()] = relation.value().get<std::string>();
        }
    }
}

void NotificationConfigParse::ParseCollaborativeDeleteTypes(const std::vector<nlohmann::json> &docs)
{
    const nlohmann::json *root = FindConfigDoc(docs, JsonPoint(CFG_KEY_NOTIFICATION_SERVICE,
        CFG_KEY_COLLABORATIVE_DELETE_TYPES));
    if (root == nullptr) {
        ANS_LOGE("GetConfigJson faild");
        return;
    }
    const nlohmann::json &collaborativeDeleteTypes =
        (*root)[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_COLLABORATIVE_DELETE_TYPES];
    if (collaborativeDeleteTypes.empty() && !collaborativeDeleteTypes.is_array()) {
        ANS_LOGE("collaborativeDeleteTypes null or no array");
        return;
    }
    for (const auto &item : collaborativeDeleteTypes) {
        if (item.is_string()) {
            collaborativeDeleteTypes_.insert(item.get<std::string>());
        }
    }
}

void NotificationConfigParse::ParseCollaborativeDeleteTypesByDevice(const std::vector<nlohmann::json> &docs)
{
    const nlohmann::json *root = FindConfigDoc(docs, JsonPoint(CFG_KEY_NOTIFICATION_SERVICE,
        CFG_KEY_COLLABORATIVE_DELETE_TYPES_DEVICES));
    if (root == nullptr) {
        ANS_LOGE("GetConfigJson faild");
        return;
    }
    const nlohmann::json &collaborativeDeleteTypes =
        (*root)[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_COLLABORATIVE_DELETE_TYPES_DEVICES];
    if (collaborativeDeleteTypes.is_null() || collaborativeDeleteTypes.empty() ||
        !collaborativeDeleteTypes.is_array()) {
        ANS_LOGE("get collaborativeDeleteTypes failed.");
        return;
    }
    std::map<std::string, std::map<std::string, std::unordered_set<std::string>>> tempMap;
    if (!ParseCollaborativeDeleteTypesDevices(tempMap, collaborativeDeleteTypes)) {
        return;
    }
    collaborativeDeleteTypesByDevice_ = std::move(tempMap);
    hasCollaborativeDeleteTypesByDevice_ = !collaborativeDeleteTypesByDevice_.empty();
}

void NotificationConfigParse::ParseCollaborationFilter(const std::vector<nlohmann::json> &docs)
{
    const nlohmann::json *root = FindConfigDoc(docs, JsonPoint(CFG_KEY_NOTIFICATION_SERVICE, COLLABORATION_FILTER));
    if (root == nullptr) {
        ANS_LOGE("Failed to get jsonPoint CCM config file.");
        return;
    }
    const nlohmann::json &collaborationFilter =
        (*root)[CFG_KEY_NOTIFICATION_SERVICE][COLLABORATION_FILTER];
    if (collaborationFilter.is_null() || collaborationFilter.empty()) {
        ANS_LOGE("GetCollaborationFilter failed as invalid ccmCollaborationFilter json.");
        return;
    }
    const char *keys[] = {COLLABORATION_FILTER_KEY_UID, COLLABORATION_FILTER_KEY_NAME};
    for (const char *key : keys) {
        if (!collaborationFilter.contains(key) || !collaborationFilter[key].is_array()) {
            continue;
        }
        for (const auto &item : collaborationFilter[key]) {
            if (item.is_number_integer()) {
                uidList_.push_back(item.get<int32_t>());
            }
            if (item.is_string()) {
                bundleNameList_.push_back(item.get<std::string>());
            }
        }
    }
}

void NotificationConfigParse::ParseStartAbilityTimeout(const std::vector<nlohmann::json> &docs)
{
    const nlohmann::json *root = FindConfigDoc(docs, JsonPoint(CFG_KEY_NOTIFICATION_SERVICE));
    if (root == nullptr) {
        ANS_LOGE("GetStartAbilityTimeout not found jsonKey");
        return;
    }
    const nlohmann::json &affects = (*root)[CFG_KEY_NOTIFICATION_SERVICE];
    if (affects.is_null() || affects.empty()) {
        ANS_LOGE("GetStartAbilityTimeout failed as invalid ccmFlowCtrlConfig json");
        return;
    }
    if (affects.contains(CFG_KEY_START_ABILITY_TIMEOUT) &&
        affects[CFG_KEY_START_ABILITY_TIMEOUT].is_number_integer()) {
        startAbilityTimeout_ = affects[CFG_KEY_START_ABILITY_TIMEOUT].get<uint32_t>();
        hasStartAbilityTimeout_ = true;
    }
}

void NotificationConfigParse::ParseAppLiveViewCcm(const std::vector<nlohmann::json> &docs)
{
    hasAppLiveViewCcm_ = FindConfigDoc(docs, JsonPoint(APP_LIVEVIEW_PERMISSIONS)) != nullptr;
}

void NotificationConfigParse::ParseReportTrustList(const std::vector<nlohmann::json> &docs)
{
    const nlohmann::json *root = FindConfigDoc(docs, JsonPoint(CFG_KEY_NOTIFICATION_SERVICE,
        CFG_KEY_DFX_NORMAL_EVENT));
    if (root == nullptr) {
        return;
    }
    const nlohmann::json &reportTrustList =
        (*root)[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_DFX_NORMAL_EVENT];
    if (reportTrustList.is_null() || reportTrustList.empty() || !reportTrustList.is_array()) {
        ANS_LOGE("GetReportTrustListConfig failed as invalid dfx_normal_events json.");
        return;
    }
    for (const auto &reportTrust : reportTrustList) {
        if (reportTrust.is_string()) {
            reporteTrustSet_.emplace(reportTrust.get<std::string>());
        }
    }

    if (!(*root)[CFG_KEY_NOTIFICATION_SERVICE].contains(CFG_KEY_BUNDLE_NAME)) {
        ANS_LOGE("Key bundles failed json.");
        return;
    }
    const nlohmann::json &keyBundles = (*root)[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_BUNDLE_NAME];
    if (keyBundles.is_null() || keyBundles.empty() || !keyBundles.is_array()) {
        ANS_LOGE("Key bundles failed json.");
        return;
    }
    for (const auto &bundle : keyBundles) {
        if (bundle.is_string()) {
            keyTrustBundles_.emplace(bundle.get<std::string>());
        }
    }
}

void NotificationConfigParse::ParseCloneExpiredTime(const std::vector<nlohmann::json> &docs)
{
    const nlohmann::json *root = FindConfigDoc(docs, JsonPoint(CFG_KEY_NOTIFICATION_SERVICE,
        CFG_KEY_CLONE_EXPIRED_TIME));
    if (root == nullptr) {
        return;
    }
    const nlohmann::json &jsonItem = (*root)[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_CLONE_EXPIRED_TIME];
    if (jsonItem.is_null() || !jsonItem.is_number_integer()) {
        ANS_LOGE("cloneExpiredTime failed json.");
        return;
    }
    cloneExpiredTimeDays_ = jsonItem.get<int32_t>();
    hasCloneExpiredTime_ = true;
}

void NotificationConfigParse::ParseDataCloneBundleName(const std::vector<nlohmann::json> &docs)
{
    const nlohmann::json *root = FindConfigDoc(docs, JsonPoint(CFG_KEY_NOTIFICATION_SERVICE,
        CFG_KEY_DATACLONE_BUNDLE_NAME));
    if (root == nullptr) {
        ANS_LOGE("Failed to get JsonPoint CCM config file.");
        return;
    }
    const nlohmann::json &jsonItem = (*root)[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_DATACLONE_BUNDLE_NAME];
    if (jsonItem.is_null() || !jsonItem.is_string()) {
        ANS_LOGE("datacloneBundleName is missing or not a string in CCM config.");
        return;
    }
    dataCloneBundleName_ = jsonItem.get<std::string>();
    if (dataCloneBundleName_.empty()) {
        ANS_LOGE("datacloneBundleName is empty in CCM config.");
        return;
    }
    ANS_LOGI("Got datacloneBundleName from CCM: %{public}s.", dataCloneBundleName_.c_str());
}

void NotificationConfigParse::ParseNotificationExtension(const std::vector<nlohmann::json> &docs)
{
    const nlohmann::json *root = FindConfigDoc(docs, JsonPoint(CFG_KEY_NOTIFICATION_SERVICE,
        CFG_KEY_NOTIFICATION_EXTENSION));
    if (root == nullptr) {
        ANS_LOGE("Failed to get notification extension config.");
        return;
    }
    const nlohmann::json &extension =
        (*root)[CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_NOTIFICATION_EXTENSION];
    if (extension.is_null() || extension.empty()) {
        ANS_LOGE("notification extension config is invalid");
        return;
    }
    if (extension.contains(CFG_KEY_NOTIFICATION_EXTENSION_LIFECYCLE_DESTORY_TIME) &&
        extension[CFG_KEY_NOTIFICATION_EXTENSION_LIFECYCLE_DESTORY_TIME].is_number_integer()) {
        extensionLifecycleDestroyTime_ =
            extension[CFG_KEY_NOTIFICATION_EXTENSION_LIFECYCLE_DESTORY_TIME].get<uint32_t>();
        hasExtensionLifecycleDestroyTime_ = true;
    }
    if (!extension.contains(CFG_KEY_ENABLED_BUNDLES_WRITE_LIST)) {
        return;
    }
    const nlohmann::json &list = extension[CFG_KEY_ENABLED_BUNDLES_WRITE_LIST];
    if (!list.is_array() || list.empty()) {
        return;
    }
    hasExtensionEnabledBundlesWriteList_ = true;
    for (const auto &bundle : list) {
        if (!bundle.is_string()) {
            continue;
        }
        extensionEnabledBundlesWriteList_.push_back(bundle.get<std::string>());
    }
}

bool __attribute__((weak)) NotificationConfigParse::GetCurrentSlotReminder(
    std::map<NotificationConstant::SlotType, std::shared_ptr<NotificationFlags>> &currentSlotReminder) const
{
    if (!hasSlotReminder_) {
        return false;
    }
    for (const auto &slot : currentSlotReminder_) {
        currentSlotReminder[slot.first] = slot.second;
    }
    return true;
}

uint32_t __attribute__((weak)) NotificationConfigParse::GetConfigSlotReminderModeByType(
    NotificationConstant::SlotType slotType)
{
    auto iter = currentSlotReminder_.find(slotType);
    if (iter != currentSlotReminder_.end() && iter->second != nullptr) {
        return iter->second->GetReminderFlags();
    }

    auto defaultIter = defaultCurrentSlotReminder_.find(slotType);
    if (defaultIter != defaultCurrentSlotReminder_.end()) {
        return defaultIter->second;
    }
    return 0;
}

std::shared_ptr<NotificationAppPrivileges> __attribute__((weak)) NotificationConfigParse::GetAppPrivileges(
    const std::string &bundleName) const
{
    auto iter = appPrivileges_.find(bundleName);
    if (iter == appPrivileges_.end()) {
        return nullptr;
    }
    return iter->second;
}

bool __attribute__((weak)) NotificationConfigParse::IsLiveViewEnabled(const std::string bundleName) const
{
    std::shared_ptr<NotificationAppPrivileges> appPrivileges = GetAppPrivileges(bundleName);
    if (appPrivileges == nullptr) {
        return false;
    }
    return appPrivileges->IsLiveViewEnabled();
}

bool __attribute__((weak)) NotificationConfigParse::IsReminderEnabled(const std::string& bundleName) const
{
    std::shared_ptr<NotificationAppPrivileges> appPrivileges = GetAppPrivileges(bundleName);
    if (appPrivileges == nullptr) {
        return false;
    }
    return appPrivileges->IsReminderEnabled();
}

bool __attribute__((weak)) NotificationConfigParse::IsDistributedReplyEnabled(const std::string& bundleName) const
{
    std::shared_ptr<NotificationAppPrivileges> appPrivileges = GetAppPrivileges(bundleName);
    if (appPrivileges == nullptr) {
        return false;
    }
    return appPrivileges->IsDistributedReplyEnabled();
}

bool __attribute__((weak)) NotificationConfigParse::IsBannerEnabled(const std::string bundleName) const
{
    int32_t userId = SUBSCRIBE_USER_INIT;
    ErrCode errCode = OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    bool profileEnabled = false;
    bool report = false;
    if (errCode == ERR_OK) {
        int32_t ret = EXTENTION_WRAPPER->BannerControlFromProfile(bundleName, userId, profileEnabled);
        ANS_LOGW("BannerControlFromProfile enable: %{public}d, ret: %{public}d", profileEnabled, ret);
        if (ret == ERR_OK && profileEnabled == true) {
            return true;
        }
        report = ret == ERR_OK ? true : false;
    }

    std::string errMessage = "not in profile,  bundleName :";
    errMessage.append(bundleName);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_34, EventBranchId::BRANCH_0);
    std::shared_ptr<NotificationAppPrivileges> appPrivileges = GetAppPrivileges(bundleName);
    if (appPrivileges != nullptr && appPrivileges->IsBannerEnabled()) {
        if (report) {
            errMessage.append(" IsBannerEnabled");
            NotificationAnalyticsUtil::ReportModifyEvent(message.Message(errMessage));
        }
        return true;
    }
#ifdef ENABLE_ANS_ADDITIONAL_CONTROL
    int32_t ctrlResult = EXTENTION_WRAPPER->BannerControl(bundleName);
    if (ctrlResult == ERR_OK) {
        if (report) {
            errMessage.append(" BannerControl");
            NotificationAnalyticsUtil::ReportModifyEvent(message.Message(errMessage));
        }
        return true;
    } else {
        return false;
    }
#else
    return false;
#endif
}

void __attribute__((weak)) NotificationConfigParse::GetFlowCtrlConfigFromCCM(FlowControlThreshold &threshold)
{
    if (flowCtrlConfig_.hasMaxCreateNumPerSecond) {
        threshold.maxCreateNumPerSecond = flowCtrlConfig_.maxCreateNumPerSecond;
    }
    if (flowCtrlConfig_.hasMaxUpdateNumPerSecond) {
        threshold.maxUpdateNumPerSecond = flowCtrlConfig_.maxUpdateNumPerSecond;
    }
    if (flowCtrlConfig_.hasMaxCreateNumPerSecondPerApp) {
        threshold.maxCreateNumPerSecondPerApp = flowCtrlConfig_.maxCreateNumPerSecondPerApp;
    }
    if (flowCtrlConfig_.hasMaxUpdateNumPerSecondPerApp) {
        threshold.maxUpdateNumPerSecondPerApp = flowCtrlConfig_.maxUpdateNumPerSecondPerApp;
    }
}

bool __attribute__((weak)) NotificationConfigParse::GetSmartReminderEnableList(std::vector<std::string>& deviceTypes)
{
    if (!hasSmartReminderEnableList_) {
        ANS_LOGE("smartReminderEnableList is invalid");
        return false;
    }
    deviceTypes.insert(deviceTypes.end(), smartReminderEnableList_.begin(), smartReminderEnableList_.end());
    return true;
}

bool __attribute__((weak)) NotificationConfigParse::GetMirrorNotificationEnabledStatus(
    std::vector<std::string>& deviceTypes)
{
    if (!hasMirrorNotificationEnabledStatus_) {
        ANS_LOGE("Invalid mirror Status");
        return false;
    }
    deviceTypes.insert(deviceTypes.end(), mirrorNotificationEnabledStatus_.begin(),
        mirrorNotificationEnabledStatus_.end());
    return true;
}

bool __attribute__((weak)) NotificationConfigParse::GetAppAndDeviceRelationMap(
    std::map<std::string, std::string>& relationMap)
{
    if (!hasAppAndDeviceRelationMap_) {
        ANS_LOGE("appAndDeviceRelationMap is invalid");
        return false;
    }
    for (const auto &relation : appAndDeviceRelationMap_) {
        relationMap[relation.first] = relation.second;
    }
    return true;
}

std::unordered_set<std::string> __attribute__((weak)) NotificationConfigParse::GetCollaborativeDeleteType() const
{
    return collaborativeDeleteTypes_;
}

bool __attribute__((weak)) NotificationConfigParse::GetFilterUidAndBundleName(const std::string &key)
{
    std::vector<nlohmann::json> docs;
    if (!LoadConfigJsons(docs) || docs.empty()) {
        ANS_LOGE("Failed to get jsonPoint CCM config file.");
        return false;
    }
    const nlohmann::json *root = FindConfigDoc(docs,
        JsonPoint(CFG_KEY_NOTIFICATION_SERVICE, COLLABORATION_FILTER, key.c_str()));
    if (root == nullptr) {
        ANS_LOGE("Failed to get jsonPoint CCM config file.");
        return false;
    }
    const nlohmann::json &collaborationFilter =
        (*root)[CFG_KEY_NOTIFICATION_SERVICE][COLLABORATION_FILTER];
    if (collaborationFilter.is_null() || collaborationFilter.empty()) {
        ANS_LOGE("GetCollaborationFilter failed as invalid ccmCollaborationFilter json.");
        return false;
    }
    if (!collaborationFilter.contains(key) || !collaborationFilter[key].is_array()) {
        return false;
    }
    std::lock_guard<ffrt::mutex> lock(mutex_);
    for (const auto &item : collaborationFilter[key]) {
        if (item.is_number_integer()) {
            uidList_.push_back(item.get<int32_t>());
        }
        if (item.is_string()) {
            bundleNameList_.push_back(item.get<std::string>());
        }
    }
    return true;
}

void __attribute__((weak)) NotificationConfigParse::GetCollaborationFilter()
{
    std::vector<int32_t> uidList;
    std::vector<std::string> bundleNameList;
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        uidList.swap(uidList_);
        bundleNameList.swap(bundleNameList_);
    }
    if (!GetFilterUidAndBundleName(COLLABORATION_FILTER_KEY_UID)) {
        ANS_LOGW("Failed to get filterUid.");
    }
    if (!GetFilterUidAndBundleName(COLLABORATION_FILTER_KEY_NAME)) {
        ANS_LOGW("Failed to get filterBundleName.");
    }
}

bool __attribute__((weak)) NotificationConfigParse::IsInCollaborationFilter(
    const std::string& bundleName, int32_t uid) const
{
    if (uidList_.empty() && bundleNameList_.empty()) {
        ANS_LOGD("empty uidList or bundleNameList");
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

    ANS_LOGE("Uid <%{public}d> and BundleName <%{public}s> not in CollaborationFilter.", uid, bundleName.c_str());
    return false;
}

uint32_t __attribute__((weak)) NotificationConfigParse::GetStartAbilityTimeout()
{
    if (!hasStartAbilityTimeout_) {
        ANS_LOGE("GetStartAbilityTimeout not found jsonKey");
        return 0;
    }
    return startAbilityTimeout_;
}

bool __attribute__((weak)) NotificationConfigParse::CheckAppLiveViewCcm()
{
    return hasAppLiveViewCcm_;
}

void __attribute__((weak)) NotificationConfigParse::GetReportTrustListConfig()
{
    std::vector<nlohmann::json> docs;
    if (!LoadConfigJsons(docs) || docs.empty()) {
        return;
    }
    reporteTrustSet_.clear();
    keyTrustBundles_.clear();
    ParseReportTrustList(docs);
}

bool __attribute__((weak)) NotificationConfigParse::IsReportTrustList(const std::string& bundleName) const
{
    return reporteTrustSet_.count(bundleName);
}

bool __attribute__((weak)) NotificationConfigParse::IsReportTrustBundles(const std::string& bundleName) const
{
    return keyTrustBundles_.count(bundleName);
}

bool __attribute__((weak)) NotificationConfigParse::GetCloneExpiredTime(int32_t& days)
{
    if (!hasCloneExpiredTime_) {
        ANS_LOGE("cloneExpiredTime failed json.");
        return false;
    }
    days = cloneExpiredTimeDays_;
    return true;
}

bool __attribute__((weak)) NotificationConfigParse::GetDataCloneBundleName(std::string &bundleName)
{
    if (dataCloneBundleName_.empty()) {
        ANS_LOGE("datacloneBundleName is missing or empty in CCM config.");
        return false;
    }
    bundleName = dataCloneBundleName_;
    return true;
}

bool __attribute__((weak)) NotificationConfigParse::GetCollaborativeDeleteTypeByDevice(std::map<std::string,
    std::map<std::string, std::unordered_set<std::string>>>& resultMap) const
{
    if (!hasCollaborativeDeleteTypesByDevice_) {
        ANS_LOGE("get collaborativeDeleteTypes failed.");
        return false;
    }
    resultMap = collaborativeDeleteTypesByDevice_;
    return true;
}

bool __attribute__((weak)) NotificationConfigParse::ParseCollaborativeDeleteTypesDevices(std::map<std::string,
    std::map<std::string, std::unordered_set<std::string>>>& resultMap,
    const nlohmann::json& collaborativeDeleteTypes) const
{
    for (const auto& device : collaborativeDeleteTypes) {
        if (!device.contains(LOCAL_DEVICE_TYPE) || !device[LOCAL_DEVICE_TYPE].is_string()) {
            continue;
        }
        std::string localDeviceType = device[LOCAL_DEVICE_TYPE];

        if (!device.contains(PEER_DELETE_FILTER_DEVICE) || !device[PEER_DELETE_FILTER_DEVICE].is_array()) {
            continue;
        }

        std::map<std::string, std::unordered_set<std::string>> peerDeviceTypeMap;
        ParseDeviceSlotType(device, peerDeviceTypeMap);
        resultMap[localDeviceType] = peerDeviceTypeMap;
    }
    return true;
}

bool __attribute__((weak)) NotificationConfigParse::ParseDeviceSlotType(const nlohmann::json& device,
    std::map<std::string, std::unordered_set<std::string>>& peerDeviceTypeMap) const
{
    for (const auto& peerDevice : device[PEER_DELETE_FILTER_DEVICE]) {
        if (!peerDevice.contains(PEER_DEVICE_TYPE) || !peerDevice[PEER_DEVICE_TYPE].is_string()) {
            continue;
        }
        std::string peerDeviceType = peerDevice[PEER_DEVICE_TYPE];

        if (!peerDevice.contains(DELETE_SLOT_TYPE) || !peerDevice[DELETE_SLOT_TYPE].is_array()) {
            continue;
        }

        std::unordered_set<std::string> deleteSlotTypes;
        for (const auto& slotType : peerDevice[DELETE_SLOT_TYPE]) {
            if (slotType.is_string()) {
                deleteSlotTypes.insert(slotType);
            }
        }

        peerDeviceTypeMap[peerDeviceType] = std::move(deleteSlotTypes);
    }
    return true;
}

bool __attribute__((weak)) NotificationConfigParse::IsNotificationExtensionLifecycleDestroyTimeConfigured(
    uint32_t &outDestroyTime) const
{
    if (!hasExtensionLifecycleDestroyTime_) {
        ANS_LOGI("Notification extension lifecycle destroy time config not found");
        return false;
    }
    outDestroyTime = extensionLifecycleDestroyTime_;
    ANS_LOGI("Notification extension lifecycle destroy time config found and valid");
    return true;
}

bool __attribute__((weak)) NotificationConfigParse::GetNotificationExtensionEnabledBundlesWriteList(
    std::vector<std::string>& bundles) const
{
    if (!hasExtensionEnabledBundlesWriteList_) {
        ANS_LOGE("enabledBundlesWriteList is invalid or empty");
        return false;
    }
    bundles.insert(bundles.end(), extensionEnabledBundlesWriteList_.begin(),
        extensionEnabledBundlesWriteList_.end());
    return true;
}
} // namespace Notification
} // namespace OHOS
