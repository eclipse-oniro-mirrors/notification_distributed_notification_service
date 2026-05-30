/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "notification_clone_notification_switch.h"

#include "ans_log_wrapper.h"
#include "notification_clone_util.h"
#include "notification_constant.h"
#include "notification_preferences.h"
#include "notification_subscriber_manager.h"

namespace OHOS {
namespace Notification {
std::shared_ptr<NotificationCloneNotificationSwitch> NotificationCloneNotificationSwitch::GetInstance()
{
    static std::shared_ptr<NotificationCloneNotificationSwitch> instance =
        std::make_shared<NotificationCloneNotificationSwitch>();
    return instance;
}

ErrCode NotificationCloneNotificationSwitch::OnBackup(nlohmann::json &jsonObject)
{
    ANS_LOGI("NotificationCloneNotificationSwitch OnBackup start");

    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    if (userId < 0) {
        ANS_LOGE("GetActiveUserId failed, userId: %{public}d", userId);
        return ERR_ANS_INVALID_PARAM;
    }

    std::vector<NotificationCloneNotificationSwitchInfo> notificationSwitchInfos;
    NotificationPreferences::GetInstance()->GetAllNotificationSwitchInfo(userId, notificationSwitchInfos);

    if (notificationSwitchInfos.empty()) {
        ANS_LOGI("No switch data to backup for userId: %{public}d", userId);
        jsonObject[CLONE_ITEM_NOTIFICATION_SWITCH] = nlohmann::json::array();
        return ERR_OK;
    }

    nlohmann::json jsonArray = nlohmann::json::array();
    for (const auto &info : notificationSwitchInfos) {
        nlohmann::json infoJson;
        info.ToJson(infoJson);
        jsonArray.push_back(infoJson);
        ANS_LOGD("Backup switch info type: %{public}s, state: %{public}d",
            info.GetSwitchName().c_str(), static_cast<int32_t>(info.GetSwitchState()));
    }

    jsonObject[CLONE_ITEM_NOTIFICATION_SWITCH] = jsonArray;
    ANS_LOGI("NotificationCloneNotificationSwitch OnBackup end, backup %{public}zu items",
        notificationSwitchInfos.size());
    return ERR_OK;
}

void NotificationCloneNotificationSwitch::OnRestore(const nlohmann::json &jsonObject, std::set<std::string> systemApps)
{
    ANS_LOGI("NotificationCloneNotificationSwitch OnRestore start");

    if (jsonObject.is_null()) {
        ANS_LOGI("jsonObject is null, skip restore");
        return;
    }

    if (!jsonObject.contains(CLONE_ITEM_NOTIFICATION_SWITCH)) {
        ANS_LOGI("jsonObject does not contain %{public}s, skip restore", CLONE_ITEM_NOTIFICATION_SWITCH);
        return;
    }

    const nlohmann::json &notificationSwitchJson = jsonObject[CLONE_ITEM_NOTIFICATION_SWITCH];
    if (!notificationSwitchJson.is_array()) {
        ANS_LOGE("jsonObject[%{public}s] is not array, skip restore", CLONE_ITEM_NOTIFICATION_SWITCH);
        return;
    }

    std::vector<NotificationCloneNotificationSwitchInfo> tempInfos;

    for (const auto &item : notificationSwitchJson) {
        if (item.is_null()) {
            ANS_LOGW("Skip null item in aggregation array");
            continue;
        }

        NotificationCloneNotificationSwitchInfo info;
        if (!info.FromJson(item)) {
            ANS_LOGW("Failed to parse aggregation info from JSON, skip this item");
            continue;
        }

        tempInfos.push_back(info);
    }

    // Restore each aggregation switch
    for (const auto &info : tempInfos) {
        RestoreNotificationSwitch(info);
    }

    ANS_LOGI("NotificationCloneNotificationSwitch OnRestore end, restored %{public}zu items", tempInfos.size());
}

void NotificationCloneNotificationSwitch::OnRestoreStart(const std::string bundleName, int32_t appIndex,
    int32_t userId, int32_t uid)
{
    ANS_LOGD("OnRestoreStart: bundleName=%{public}s, appIndex=%{public}d, userId=%{public}d, uid=%{public}d",
        bundleName.c_str(), appIndex, userId, uid);
    // Empty implementation: aggregation switches are user-level settings, not application-level
}

void NotificationCloneNotificationSwitch::OnRestoreEnd(int32_t userId)
{
    ANS_LOGI("NotificationCloneNotificationSwitch OnRestoreEnd start, userId: %{public}d", userId);
}

void NotificationCloneNotificationSwitch::OnUserSwitch(int32_t userId)
{
    ANS_LOGD("NotificationCloneNotificationSwitch OnUserSwitch, userId: %{public}d", userId);
}

void NotificationCloneNotificationSwitch::RestoreNotificationSwitch(const NotificationCloneNotificationSwitchInfo &info)
{
    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    if (userId < 0) {
        ANS_LOGE("GetActiveUserId failed, userId: %{public}d", userId);
        return;
    }
    const std::string &switchName = info.GetSwitchName();
    NotificationConstant::SWITCH_STATE state = info.GetSwitchState();

    ANS_LOGI("Restore notification switch: switchName=%{public}s, userId=%{public}d, state=%{public}d",
        switchName.c_str(), userId, static_cast<int32_t>(state));
    NotificationConstant::SWITCH_STATE oldState = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
    NotificationPreferences::GetInstance()->GetNotificationSwitch(switchName, userId, oldState);
    ErrCode err = NotificationPreferences::GetInstance()->SetNotificationSwitch(switchName, state, userId);
    if (err != ERR_OK) {
        ANS_LOGE("Failed to set notification switch: switchName=%{public}s, userId=%{public}d, err=%{public}d",
            switchName.c_str(), userId, err);
        return;
    }

    // Notify subscribers about the switch state change
    if (oldState != state) {
        NotifySwitchChanged(switchName, userId, state);
    }
}

void NotificationCloneNotificationSwitch::NotifySwitchChanged(const std::string &switchName, int32_t userId,
    NotificationConstant::SWITCH_STATE state)
{
    ANS_LOGI("Notify notification switch changed: switchName=%{public}s, userId=%{public}d, state=%{public}d",
        switchName.c_str(), userId, static_cast<int32_t>(state));

    sptr<NotificationSwitchChangedCallbackData> callbackData =
        new NotificationSwitchChangedCallbackData(switchName, userId, state);
    if (callbackData == nullptr) {
        ANS_LOGE("Failed to create NotificationSwitchChangedCallbackData");
        return;
    }

    NotificationSubscriberManager::GetInstance()->NotifyNotificationSwitchChanged(callbackData);
}
}  // namespace Notification
}  // namespace OHOS