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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_AGGREGATION_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_AGGREGATION_H

#include "notification_clone_template.h"

#include "ffrt.h"
#include "notification_clone_notification_switch_info.h"

namespace OHOS {
namespace Notification {
/**
 * @brief Aggregation switch clone service for backup and restore operations.
 *
 * This class is responsible for cloning aggregation switch state information
 * during backup, restore, and user switch operations. It handles two types of
 * aggregation switches: DEAL (transaction alerts) and LOGISTICS (logistics notifications).
 *
 */
class NotificationCloneNotificationSwitch final : public NotificationCloneTemplate {
public:
    /**
     * @brief Gets the singleton instance of NotificationCloneNotificationSwitch.
     *
     * @return Returns the singleton instance.
     */
    static std::shared_ptr<NotificationCloneNotificationSwitch> GetInstance();

    /**
     * @brief Backs up aggregation switch state information to JSON.
     *
     * This method retrieves the current aggregation switch states (DEAL and LOGISTICS)
     * for the active user and serializes them into a JSON object for backup.
     *
     * @param jsonObject Indicates the JSON object to write backup data to.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode OnBackup(nlohmann::json &jsonObject) override;

    /**
     * @brief Restores aggregation switch state information from JSON.
     *
     * This method deserializes aggregation switch state information from a JSON object
     * and restores the switch states to the database. It also notifies subscribers
     * about the switch state changes.
     *
     * @param jsonObject Indicates the JSON object to read restore data from.
     * @param systemApps Indicates the set of system application bundle names.
     */
    void OnRestore(const nlohmann::json &jsonObject, std::set<std::string> systemApps) override;

    /**
     * @brief Handles the start of restore for a single application.
     *
     * This method is called when restore starts for a single application.
     * For aggregation switches, this method has an empty implementation as
     * aggregation switches are user-level settings, not application-level.
     *
     * @param bundleName Indicates the bundle name of the application.
     * @param appIndex Indicates the application index.
     * @param userId Indicates the user ID.
     * @param uid Indicates the UID of the application.
     */
    void OnRestoreStart(const std::string bundleName, int32_t appIndex, int32_t userId, int32_t uid) override;

    /**
     * @brief Cleans up temporary data after restore completes.
     *
     * This method is called after all restore operations complete.
     * It cleans up any temporary cache data used during the restore process.
     *
     * @param userId Indicates the user ID.
     */
    void OnRestoreEnd(int32_t userId) override;

    /**
     * @brief Handles user switch event.
     *
     * This method is called when the active user changes.
     * For aggregation switches, this method has an empty implementation as
     * the switch states are already persisted per user.
     *
     * @param userId Indicates the new user ID.
     */
    void OnUserSwitch(int32_t userId) override;

private:
    /**
     * @brief Restores a single aggregation switch from clone info.
     *
     * @param info Indicates the clone aggregation info to restore.
     */
    void RestoreNotificationSwitch(const NotificationCloneNotificationSwitchInfo &info);

    /**
     * @brief Notifies subscribers about aggregation switch state change.
     *
     * @param type Indicates the aggregation type (DEAL or LOGISTICS).
     * @param userId Indicates the user ID.
     * @param state Indicates the switch state.
     */
    void NotifySwitchChanged(const std::string &type, int32_t userId, NotificationConstant::SWITCH_STATE state);

private:
    // JSON key constant for aggregation switch data
    static constexpr const char *CLONE_ITEM_NOTIFICATION_SWITCH = "notificationSwitch";
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLONE_AGGREGATION_H