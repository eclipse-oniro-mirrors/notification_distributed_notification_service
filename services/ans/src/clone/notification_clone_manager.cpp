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
#include "notification_clone_util.h"
#include "dh_notification_clone_bundle_service.h"
#include "common_event_manager.h"
#include "notification_analytics_util.h"

namespace OHOS {
namespace Notification {

const int ANS_CLONE_ERROR = -1;
const int32_t DEFAULT_APP_INDEX = -1;
constexpr int32_t DEFAULT_ANCO_APP_INDEX = 0;
constexpr uint64_t NOTIFICATION_FDSAN_TAG = 0xD001203;
constexpr uint64_t COMMON_FDSAN_TAG = 0;
constexpr const char *CLONE_ITEM_BUNDLE_INFO = "notificationBundle";
constexpr const char *DH_CLONE_ITEM_BUNDLE_INFO = "dhNotificationBundle";
constexpr const char *CLONE_ITEM_DISTURB = "notificationDisturb";
constexpr const char *BACKUP_CONFIG_FILE_PATH = "/data/service/el1/public/notification/backup_config.conf";

std::shared_ptr<AncoRestoreStartEventSubscriber> AncoRestoreStartEventSubscriber::create()
{
    ANS_LOGI("AncoRestoreStartEventSubscriber create");
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(AncoRestoreStartEventSubscriber::EVENT_NAME);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetPermission(AncoRestoreStartEventSubscriber::EVENT_PUBLISHER_PERMISSION);
    return std::make_shared<AncoRestoreStartEventSubscriber>(subscriberInfo);
    ANS_LOGI("AncoRestoreStartEventSubscriber create end");
}

AncoRestoreStartEventSubscriber::AncoRestoreStartEventSubscriber(
    const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo)
{
}

AncoRestoreStartEventSubscriber::~AncoRestoreStartEventSubscriber()
{
    ANS_LOGI("AncoRestoreStartEventSubscriber release");
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
    ANS_LOGI("OnBackup start");
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
            ANS_LOGW("Notification OnBackup %{public}s funtion is null.", iter->first.c_str());
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
        ANS_LOGE("Notification open file failed.");
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

int32_t NotificationCloneManager::OnRestore(MessageParcel& data, MessageParcel& reply)
{
    ANS_LOGI("OnRestore start");
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
    for (auto iter = cloneTemplates.begin(); iter != cloneTemplates.end(); ++iter) {
        if (jsonObject.contains(iter->first) && iter->second != nullptr) {
            iter->second->OnRestore(jsonObject.at(iter->first));
        }
    }
    ANS_LOGI("OnRestore end");
    return ERR_OK;
}

NotificationCloneManager::NotificationCloneManager()
{
    ANS_LOGI("Notification clone manager init.");
    // not change push sequence, ensure [clone item] before [dh clone item]
    cloneTemplates.push_back(std::make_pair(CLONE_ITEM_BUNDLE_INFO, NotificationCloneBundle::GetInstance()));
    cloneTemplates.push_back(std::make_pair(DH_CLONE_ITEM_BUNDLE_INFO, DhNotificationCloneBundle::GetInstance()));
    cloneTemplates.push_back(std::make_pair(CLONE_ITEM_DISTURB, NotificationCloneDisturb::GetInstance()));

    restoreStartEventSubscriber_ = AncoRestoreStartEventSubscriber::create();
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(restoreStartEventSubscriber_)) {
        ANS_LOGE("Subscribe AncoRestoreStartEventSubscriber Failed.");
        restoreStartEventSubscriber_ = nullptr;
    }
    ANS_LOGI("Subscribe AncoRestoreStartEventSubscriber success.");
}

NotificationCloneManager::~NotificationCloneManager()
{
    ANS_LOGI("Notification clone manager destory.");
}

ErrCode NotificationCloneManager::LoadConfig(UniqueFd &fd, std::string& config)
{
    ANS_LOGI("Load notification config.");
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
