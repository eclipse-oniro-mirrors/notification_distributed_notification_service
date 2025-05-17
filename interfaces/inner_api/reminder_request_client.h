/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_REQUEST_CLIENT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_REQUEST_CLIENT_H
#include <list>
#include <memory>

#include "reminder_request.h"
#include "reminder_request_adaptation.h"
#include "notification_slot.h"
#include "notification_constant.h"
#include "ians_manager.h"
#include "ireminder_agent_service.h"
#include "ffrt.h"

namespace OHOS {
namespace Notification {
class ReminderRequestClient {
public:
    /**
     * @brief Publishes a scheduled reminder.
     *
     * @param reminder Indicates a reminder.
     * @return Returns publish result.
     */
    ErrCode PublishReminder(const ReminderRequest& reminder, int32_t& reminderId);

    /**
     * @brief Updates a scheduled reminder.
     *
     * @param reminderId Indicates reminder Id.
     * @param reminder Indicates a reminder.
     * @return Returns publish result.
     */
    ErrCode UpdateReminder(const int32_t reminderId, const ReminderRequest& reminder);

    /**
     * @brief Cancels a specified reminder.
     *
     * @param reminderId Indicates reminder Id.
     * @return Returns cancel result.
     */
    ErrCode CancelReminder(const int32_t reminderId);

    /**
     * @brief Cancels all reminders of current third part application.
     *
     * @return Returns cancel result.
     */
    ErrCode CancelAllReminders();

    /**
     * @brief Obtains all valid reminder notifications set by the current application.
     *
     * @param[out] validReminders Indicates the vector to store the result.
     * @return Returns get valid reminders result.
     */
    ErrCode GetValidReminders(std::vector<ReminderRequestAdaptation> &validReminders);

    /**
     * @brief Add exclude date for reminder
     *
     * @param reminderId Identifies the reminders id.
     * @param date exclude date
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode AddExcludeDate(const int32_t reminderId, const int64_t date);

    /**
     * @brief Clear exclude date for reminder
     *
     * @param reminderId Identifies the reminders id.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DelExcludeDates(const int32_t reminderId);

    /**
     * @brief Get exclude date for reminder
     *
     * @param reminderId Identifies the reminders id.
     * @param dates exclude dates
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetExcludeDates(const int32_t reminderId, std::vector<int64_t>& dates);

    /**
     * @brief Creates a notification slot.
     * @note You can call the NotificationRequest::SetSlotType(NotificationConstant::SlotType) method to bind the slot
     * for publishing. A NotificationSlot instance cannot be used directly after being initialized. Instead, you have to
     * call this method to create a notification slot and bind the slot ID to a NotificationRequest object so that the
     * notification published can have all the characteristics set in the NotificationSlot. After a notification slot is
     * created by using this method, only the name and description of the notification slot can be changed. Changes to
     * the other attributes, such as the vibration status and notification tone, will no longer take effect.
     *
     * @param slot Indicates the notification slot to be created, which is set by NotificationSlot.
     *             This parameter must be specified.
     * @return Returns add notification slot result.
     */
    ErrCode AddNotificationSlot(const NotificationSlot &slot);

    /**
     * @brief Deletes a created notification slot based on the slot ID.
     *
     * @param slotType Indicates the ID of the slot, which is created by AddNotificationSlot
     *                This parameter must be specified.
     * @return Returns remove notification slot result.
     */
    ErrCode RemoveNotificationSlot(const NotificationConstant::SlotType &slotType);

    void LoadSystemAbilitySuccess(const sptr<IRemoteObject> &remoteObject);

    void LoadSystemAbilityFail();

    void StartReminderAgentService();

private:

    /**
     * @brief Adds a notification slot by type.
     *
     * @param slotType Indicates the notification slot type to be added.
     * @return Returns add notification slot result.
     */
    ErrCode AddSlotByType(const NotificationConstant::SlotType &slotType);

    sptr<IAnsManager> GetAnsManagerProxy();

    sptr<IReminderAgentService> GetReminderServiceProxy();

    bool LoadReminderService();

    ffrt::mutex serviceLock_;

    ffrt::condition_variable proxyConVar_;

    sptr<IReminderAgentService> proxy_;
};
}  // namespace Notification
}  // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_REQUEST_CLIENT_H

