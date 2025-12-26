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

#include "notification_clone_manager.h"

#include <fcntl.h>
#include <unistd.h>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sendfile.h>

#include "ans_log_wrapper.h"
#include "nlohmann/json.hpp"
#include "notification_clone_disturb_service.h"
#include "notification_clone_bundle_service.h"
#include "notification_clone_geofence_switch.h"
#include "notification_clone_priority_service.h"
#include "notification_clone_util.h"
#include "dh_notification_clone_bundle_service.h"
#include "common_event_manager.h"
#include "notification_analytics_util.h"
#include "notification_liveview_utils.h"
#include "common_event_support.h"
#include "notification_preferences.h"

namespace OHOS {
namespace Notification {

const int ANS_CLONE_ERROR = -1;
const int32_t DEFAULT_APP_INDEX = -1;
constexpr int32_t DEFAULT_ANCO_APP_INDEX = 0;
constexpr uint64_t NOTIFICATION_FDSAN_TAG = 0xD001203;
constexpr uint64_t COMMON_FDSAN_TAG = 0;
constexpr const char* CLONE_ITEM_BUNDLE_INFO = "notificationBundle";
constexpr const char* DH_CLONE_ITEM_BUNDLE_INFO = "dhNotificationBundle";
constexpr const char* CLONE_ITEM_DISTURB = "notificationDisturb";
constexpr const char* CLONE_GEOFENCE = "notificationGeofence";
constexpr const char* CLONE_ITEM_PRIORITY_INFO = "notificationPriority";
constexpr const char* BACKUP_CONFIG_FILE_PATH = "/data/service/el1/public/notification/backup_config.conf";
constexpr const char* EVENT_NAME = "usual.event.ANCO_RESTORE_START";
constexpr const char* EVENT_PUBLISHER_PERMISSION = "ohos.permission.RECEIVE_BMS_BROKER_MESSAGES";

std::shared_ptr<AncoRestoreStartEventSubscriber> AncoRestoreStartEventSubscriber::create()
{
    ANS_LOGD("start");
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT_NAME);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetPermission(EVENT_PUBLISHER_PERMISSION);
    return std::make_shared<AncoRestoreStartEventSubscriber>(subscriberInfo);
    ANS_LOGD("end");
}

AncoRestoreStartEventSubscriber::AncoRestoreStartEventSubscriber(
    const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo)
{
}

AncoRestoreStartEventSubscriber::~AncoRestoreStartEventSubscriber()
{
    ANS_LOGD("called");
}

void AncoRestoreStartEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData& data)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_22, EventBranchId::BRANCH_4);
    std::string bundleName = data.GetWant().GetStringParam("bundleName");
    int32_t uid = data.GetWant().GetIntParam("uid", 0);
    ANS_LOGI("AncoRestoreStartEventSubscriber Get Data %{public}s %{public}d",
        bundleName.c_str(), uid);
    if (uid <= 0) {
        message.Message("dh restoreStart uid error" + bundleName);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("AncoRestoreStartEventSubscriber uid error");
        return;
    }
    NotificationCloneManager::GetInstance().OnDhRestoreStart(bundleName, uid);
}

NotificationCloneManager& NotificationCloneManager::GetInstance()
{
    static NotificationCloneManager notificationCloneManager;
    return notificationCloneManager;
}

static std::string SetBackUpReply()
{
    nlohmann::json reply;
    nlohmann::json resultInfo = nlohmann::json::array();
    nlohmann::json errorInfo;

    errorInfo["type"] = "ErrorInfo";
    errorInfo["errorCode"] = std::to_string(ERR_OK);
    errorInfo["errorInfo"] = "";

    resultInfo.emplace_back(errorInfo);
    reply["resultInfo"] = resultInfo;

    return reply.dump();
}

int32_t NotificationCloneManager::OnBackup(MessageParcel& data, MessageParcel& reply)
{
    ANS_LOGD("called");
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_22, EventBranchId::BRANCH_1);
    if (cloneTemplates.empty()) {
        ANS_LOGI("Notification no need Backup.");
        return ERR_OK;
    }

    nlohmann::json jsonObject;
    for (auto iter = cloneTemplates.begin(); iter != cloneTemplates.end(); ++iter) {
        nlohmann::json jsonItem;
        auto cloneTemplate = iter->second;
        if (cloneTemplate == nullptr) {
            ANS_LOGW("null cloneTemplate %{public}s", iter->first.c_str());
            continue;
        }
        if (iter->second->OnBackup(jsonItem) != ERR_OK) {
            ANS_LOGW("Notification OnBackup %{public}s failed.", iter->first.c_str());
            continue;
        }
        jsonObject[iter->first] = jsonItem;
    }

    if (SaveConfig(jsonObject.dump()) != ERR_OK) {
        message.Message("SaveConfig failed.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ANS_CLONE_ERROR;
    }

    FILE *fdfile = fopen(BACKUP_CONFIG_FILE_PATH, "r");
    if (fdfile == nullptr) {
        ANS_LOGE("null fdfile");
        message.Message("Notification open file failed.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ANS_CLONE_ERROR;
    }
    auto fd = fileno(fdfile);
    if (reply.WriteFileDescriptor(fd) == false) {
        (void)fclose(fdfile);
        ANS_LOGE("Notification write file descriptor failed!");
        message.Message("Notification write file descriptor failed!");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ANS_CLONE_ERROR;
    }

    ANS_LOGI("Notification OnBackup end fd: %{public}d.", fd);
    (void)fclose(fdfile);
    return ERR_OK;
}

void NotificationCloneManager::GetRestoreSystemApp(const std::string& extralInfo, std::set<std::string>& bundles)
{
    if (extralInfo.empty()) {
        return;
    }

    nlohmann::json jsonObject = nlohmann::json::parse(extralInfo, nullptr, false);
    if (jsonObject.is_null() || !jsonObject.is_array()) {
        ANS_LOGE("Invalid extralInfo array");
        return;
    }

    for (auto& item : jsonObject) {
        const auto &jsonEnd = item.cend();
        if (item.find("type") == jsonEnd || !item.at("type").is_string()) {
            continue;
        }
        if (item.at("type").get<std::string>() != "systemAppInfo") {
            continue;
        }
        if (item.find("detail") == jsonEnd || !item.at("detail").is_array() || item.at("detail").empty()) {
            continue;
        }
        auto bundlesJson = item.at("detail");
        for (auto& bundle : bundlesJson) {
            if (!bundle.is_string()) {
                continue;
            }
            bundles.emplace(bundle.get<std::string>());
            ANS_LOGI("Restore extralInfo application %{public}s", bundle.get<std::string>().c_str());
        }
        break;
    }
    ANS_LOGI("Restore extralInfo %{public}zu", bundles.size());
}

int32_t NotificationCloneManager::OnRestore(MessageParcel& data, MessageParcel& reply)
{
    ANS_LOGD("start");
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_22, EventBranchId::BRANCH_2);
    reply.WriteString(SetBackUpReply());
    std::string storeMessage;
    UniqueFd fd(data.ReadFileDescriptor());
    if (LoadConfig(fd, storeMessage) != ERR_OK) {
        close(fd.Release());
        RemoveBackUpFile();
        message.Message("LoadConfig failed!");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ANS_CLONE_ERROR;
    }

    RemoveBackUpFile();
    if (storeMessage.empty() || !nlohmann::json::accept(storeMessage)) {
        ANS_LOGE("Invalid JSON");
        message.Message("Invalid JSON");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ANS_CLONE_ERROR;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(storeMessage, nullptr, false);
    if (jsonObject.is_null() || !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        message.Message("Invalid JSON object");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ANS_CLONE_ERROR;
    }

    std::set<std::string> systemApps;
    std::string extralInfo = data.ReadString();
    GetRestoreSystemApp(extralInfo, systemApps);
    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    NotificationPreferences::GetInstance()->SetCloneTimeStamp(userId, NotificationAnalyticsUtil::GetCurrentTime());
    for (auto iter = cloneTemplates.begin(); iter != cloneTemplates.end(); ++iter) {
        if (jsonObject.contains(iter->first) && iter->second != nullptr) {
            iter->second->OnRestore(jsonObject.at(iter->first), systemApps);
        }
    }
    ANS_LOGD("end");
    return ERR_OK;
}

void NotificationCloneManager::OnRestoreEnd()
{
    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    ANS_LOGW("Clone start transfer %{public}d.", userId);
    for (auto iter = cloneTemplates.begin(); iter != cloneTemplates.end(); ++iter) {
        if (iter->second != nullptr) {
            iter->second->OnRestoreEnd(userId);
        }
    }
}

NotificationCloneManager::NotificationCloneManager()
{
    ANS_LOGD("start");
    // not change push sequence, ensure [clone item] before [dh clone item]
    cloneTemplates.push_back(std::make_pair(CLONE_ITEM_BUNDLE_INFO, NotificationCloneBundle::GetInstance()));
    cloneTemplates.push_back(std::make_pair(DH_CLONE_ITEM_BUNDLE_INFO, DhNotificationCloneBundle::GetInstance()));
    cloneTemplates.push_back(std::make_pair(CLONE_ITEM_DISTURB, NotificationCloneDisturb::GetInstance()));
    cloneTemplates.push_back(std::make_pair(CLONE_ITEM_PRIORITY_INFO, NotificationClonePriority::GetInstance()));
    cloneTemplates.push_back(std::make_pair(CLONE_GEOFENCE, NotificationCloneGeofenceSwitch::GetInstance()));

    restoreStartEventSubscriber_ = AncoRestoreStartEventSubscriber::create();
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(restoreStartEventSubscriber_)) {
        ANS_LOGE("Subscribe AncoRestoreStartEventSubscriber Failed.");
        restoreStartEventSubscriber_ = nullptr;
    }
    ANS_LOGD("end");
}

NotificationCloneManager::~NotificationCloneManager()
{
    ANS_LOGD("called");
}

ErrCode NotificationCloneManager::LoadConfig(UniqueFd &fd, std::string& config)
{
    ANS_LOGD("called");
    struct stat statBuf;
    if (fstat(fd.Get(), &statBuf) < 0) {
        ANS_LOGE("LoadConfig fstat fd fail %{public}d.", fd.Get());
        return ANS_CLONE_ERROR;
    }
    int destFd = open(BACKUP_CONFIG_FILE_PATH, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (destFd < 0) {
        ANS_LOGE("LoadConfig open file fail.");
        return ANS_CLONE_ERROR;
    }
    fdsan_exchange_owner_tag(destFd, COMMON_FDSAN_TAG, NOTIFICATION_FDSAN_TAG);
    if (sendfile(destFd, fd.Get(), nullptr, statBuf.st_size) < 0) {
        ANS_LOGE("LoadConfig fd sendfile(size: %{public}d) to destFd fail.", static_cast<int>(statBuf.st_size));
        fdsan_close_with_tag(destFd, NOTIFICATION_FDSAN_TAG);
        return ANS_CLONE_ERROR;
    }
    fdsan_close_with_tag(destFd, NOTIFICATION_FDSAN_TAG);
    std::ifstream fs(BACKUP_CONFIG_FILE_PATH);
    if (!fs.is_open()) {
        ANS_LOGE("Loading config file is_open() failed!");
        return ANS_CLONE_ERROR;
    }
    config.clear();
    std::string line;
    while (std::getline(fs, line)) {
        config.append(line);
    }
    fs.close();
    return ERR_OK;
}

ErrCode NotificationCloneManager::SaveConfig(const std::string& config)
{
    ANS_LOGD("Save config file %{public}s", config.c_str());
    RemoveBackUpFile();
    FILE* fp = fopen(BACKUP_CONFIG_FILE_PATH, "w");
    if (!fp) {
        ANS_LOGE("Save config file fopen() failed!");
        return ANS_CLONE_ERROR;
    }

    int ret = static_cast<int>(fwrite(config.c_str(), 1, config.length(), fp));
    if (ret != (int)config.length()) {
        ANS_LOGE("Save config file, fwrite %{public}d failed!", ret);
    }
    (void)fflush(fp);
    (void)fsync(fileno(fp));
    (void)fclose(fp);
    ANS_LOGI("Save config file %{public}zu", config.size());
    return ERR_OK;
}

void NotificationCloneManager::RemoveBackUpFile()
{
    remove(BACKUP_CONFIG_FILE_PATH);
}

void NotificationCloneManager::OnUserSwitch(int32_t userId)
{
    for (auto iter = cloneTemplates.begin(); iter != cloneTemplates.end(); ++iter) {
        if (iter->second != nullptr) {
            iter->second->OnUserSwitch(userId);
        }
    }
}

void NotificationCloneManager::OnRestoreStart(EventFwk::Want want)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_22, EventBranchId::BRANCH_3);
    int32_t appIndex = want.GetIntParam("index", -1);
    std::string bundleName = want.GetStringParam("bundleName");
    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    if (appIndex == -1 || bundleName.empty()) {
        ANS_LOGW("Invalid restore data %{public}d %{public}d %{public}s",
            appIndex, userId, bundleName.c_str());
        message.Message("Invalid restore data");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return;
    }
    int32_t uid = NotificationCloneUtil::GetBundleUid(bundleName, userId, appIndex);
    for (auto iter = cloneTemplates.begin(); iter != cloneTemplates.end(); ++iter) {
        if (iter->second != nullptr && !iter->second->isDhSource()) {
            iter->second->OnRestoreStart(bundleName, appIndex, userId, uid);
        }
    }

    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundleName, uid);
    if (bundleOption != nullptr) {
        NotificationLiveViewUtils::GetInstance().NotifyLiveViewEvent(
            EventFwk::CommonEventSupport::COMMON_EVENT_RESTORE_START, bundleOption);
    }
}

void NotificationCloneManager::OnDhRestoreStart(const std::string bundleName, const int32_t uid)
{
    for (auto iter = cloneTemplates.begin(); iter != cloneTemplates.end(); ++iter) {
        if (iter->second != nullptr && iter->second->isDhSource()) {
            iter->second->OnRestoreStart(bundleName, DEFAULT_APP_INDEX, ZERO_USERID, uid);
        }
        if (iter->first == CLONE_ITEM_DISTURB && iter->second != nullptr) {
            iter->second->OnRestoreStart(bundleName, DEFAULT_ANCO_APP_INDEX, DEFAULT_USER_ID, uid);
        }
    }
}
}
}
