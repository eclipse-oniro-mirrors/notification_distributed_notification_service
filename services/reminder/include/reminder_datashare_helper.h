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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_REMINDER_INCLUDE_REMINDER_DATASHARE_HELPER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_REMINDER_INCLUDE_REMINDER_DATASHARE_HELPER_H

#include "ffrt.h"
#include "reminder_request.h"
#include "datashare_helper.h"
#include "data_ability_observer_stub.h"

#include <vector>
#include <string>

namespace OHOS::Notification {
class ReminderDataShareHelper {
public:
    static ReminderDataShareHelper& GetInstance();

    /**
     * @brief Register datashare observer.
     */
    bool RegisterObserver();

    /**
     * @brief UnRegister datashare observer.
     */
    bool UnRegisterObserver();

public:
    /**
     * @brief Search for reminders from the current time to X minutes.
     */
    bool Query(std::map<std::string, sptr<ReminderRequest>>& reminders);

    /**
     * @brief Search value from uri.
     */
    bool Query(Uri& uri, const std::string& key, std::string& value);

    /**
     * @brief Update the reminder state.
     * state is ReminderCalendarShareTable::STATE_*
     */
    bool Update(const std::string& identifier, const int32_t state);

    /**
     * @brief Start calendar data extension.
     * reason is ReminderCalendarShareTable::START_*
     */
    void StartDataExtension(const int32_t reason);

public:
    /**
     * @brief Set current user id.
     */
    void SetUserId(const int32_t userId)
    {
        curUserId_ = userId;
    }

    /**
     * @brief Update calendar uid and calendar data uid.
     */
    void UpdateCalendarUid();

    /**
     * @brief Get cache update reminders.
     */
    std::map<std::string, sptr<ReminderRequest>> GetCacheReminders();

    /**
     * @brief Save update reminders to cache.
     */
    void InsertCacheReminders(const std::map<std::string, sptr<ReminderRequest>>& reminders);

public:
    /**
     * @brief When datashare notify OnChange, the change type is insert or delete.
     */
    void OnDataInsertOrDelete();

    /**
     * @brief When datashare notify OnChange, the change type is update.
     */
    void OnDataUpdate(const DataShare::DataShareObserver::ChangeInfo& info);

private:
    /**
     * @brief Build datasharehelper, need to release it after use,
     * call ReleaseDataShareHelper.
     */
    std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(const std::string& uriStr);
    bool ReleaseDataShareHelper(const std::shared_ptr<DataShare::DataShareHelper>& helper);

    /**
     * @brief Get share table columns.
     */
    std::vector<std::string> GetColumns() const;

private:
    /**
     * @brief Build ReminderRequest from DataShareResultSet.
     */
    sptr<ReminderRequest> CreateReminder(const std::shared_ptr<DataShare::DataShareResultSet>& result);

    /**
     * @brief Build ReminderRequest from ChangeInfo.
     */
    std::map<std::string, sptr<ReminderRequest>> CreateReminder(
        const DataShare::DataShareObserver::ChangeInfo& info);

    /**
     * @brief Init reminder base info.
     */
    void InitNormalInfo(sptr<ReminderRequest>& reminder);
    void InitBaseInfo(const DataShare::DataShareObserver::ChangeInfo::VBucket& info,
        sptr<ReminderRequest>& reminder);

    /**
     * @brief Calendar database version1
     */
    void BuildReminderV1(const std::shared_ptr<DataShare::DataShareResultSet>& result,
        sptr<ReminderRequest>& reminder);
    void BuildReminderV1(const DataShare::DataShareObserver::ChangeInfo::VBucket& info,
        sptr<ReminderRequest>& reminder);
private:
    // Singleton
    ReminderDataShareHelper();
    ~ReminderDataShareHelper() = default;

    ReminderDataShareHelper(const ReminderDataShareHelper&) = delete;
    ReminderDataShareHelper& operator=(const ReminderDataShareHelper&) = delete;
    ReminderDataShareHelper(ReminderDataShareHelper&&) = delete;
    ReminderDataShareHelper& operator=(ReminderDataShareHelper&&) = delete;

private:
    int32_t curUserId_ {0};
    int32_t uid_ {0};  // calendar
    int32_t dataUid_ {0};  // calendardata
    bool isNewRdbVer_ = false;  // is new calendar rdb version
    std::atomic<bool> insertTask_ {false};
    std::atomic<bool> updateTask_ {false};
    std::atomic<int64_t> insertTime_ {0};
    std::atomic<int64_t> updateTime_ {0};

    std::mutex mutex_;  // for observer_
    std::shared_ptr<DataShare::DataShareObserver> observer_;

    std::mutex cacheMutex_;  // for cache
    std::map<std::string, sptr<ReminderRequest>> cache_;  // reminder cache

    std::shared_ptr<ffrt::queue> queue_;  // for OnChange

private:
class ReminderDataObserver : public DataShare::DataShareObserver {
public:
    ReminderDataObserver() = default;
    ~ReminderDataObserver() = default;

    /**
     * @brief Notification of data changes.
     */
    void OnChange(const ChangeInfo& info) override;
};
};
}  // namespace OHOS::Notification
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_REMINDER_INCLUDE_REMINDER_DATASHARE_HELPER_H