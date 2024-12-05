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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_SERVICE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_SERVICE_H

#include <ctime>
#include <set>
#include <list>
#include <memory>
#include <mutex>

#include "event_handler.h"
#include "event_runner.h"
#include "ffrt.h"
#include "refbase.h"

#include "ans_const_define.h"
#include "reminder_service_stub.h"
#include "reminder_request_adaptation.h"

namespace OHOS {
namespace Notification {

static const uint32_t DEFAULT_SLOT_FLAGS = 59; // 0b111011
class ReminderService final : public ReminderServiceStub,
    public std::enable_shared_from_this<ReminderService> {
public:

    ~ReminderService() override = default;

    DISALLOW_COPY_AND_MOVE(ReminderService);

    /**
     * @brief Get the instance of service.
     *
     * @return Returns the instance.
     */
    static sptr<ReminderService> GetInstance();

    /**
     * @brief Check reminder permission
     */
    bool CheckReminderPermission();

    /**
     * @brief Publishes a reminder notification.
     *
     * @param reminder Identifies the reminder notification request that needs to be published.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode PublishReminder(const ReminderRequest &reminder, int32_t& reminderId) override;

    /**
     * @brief Cancel a reminder notifications.
     *
     * @param reminderId Identifies the reminders id that needs to be canceled.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode CancelReminder(const int32_t reminderId) override;

    /**
     * @brief Get all valid reminder notifications.
     *
     * @param reminders Identifies the list of all valid notifications.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetValidReminders(std::vector<ReminderRequestAdaptation> &reminders) override;

    /**
     * @brief Cancel all reminder notifications.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode CancelAllReminders() override;

    /**
     * @brief Add exclude date for reminder
     *
     * @param reminderId Identifies the reminders id.
     * @param date exclude date
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode AddExcludeDate(const int32_t reminderId, const int64_t date) override;

    /**
     * @brief Clear exclude date for reminder
     *
     * @param reminderId Identifies the reminders id.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DelExcludeDates(const int32_t reminderId) override;

    /**
     * @brief Get exclude date for reminder
     *
     * @param reminderId Identifies the reminders id.
     * @param dates exclude dates
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetExcludeDates(const int32_t reminderId, std::vector<int64_t>& dates) override;

    void TryPostDelayUnloadTask(int64_t delayTime);
private:
    ReminderService() = default;

    void PostDelayUnloadTask();

    void TryInit();

    sptr<ReminderRequest> CreateTarReminderRequest(const ReminderRequest &reminder);

    ErrCode InitReminderRequest(sptr<ReminderRequest>& tarReminder, const std::string& bundle,
        const int32_t callingUid);
private:
    ffrt::task_handle tryUnloadTask_ = nullptr;
    static sptr<ReminderService> instance_;
    static std::mutex instanceMutex_;

    static std::mutex unloadMutex_;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_SERVICE_H
