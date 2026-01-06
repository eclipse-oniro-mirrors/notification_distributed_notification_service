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
     * @brief Register a DataShare observer to listen for calendar reminder changes.
     *
     * The observer will receive OnChange callbacks from the DataShare framework.
     * This method creates and registers an internal observer and stores it in `observer_`.
     *
     * @return true if the observer was successfully registered; false otherwise.
     */
    bool RegisterObserver();

    /**
     * @brief Unregister the DataShare observer previously registered by RegisterObserver.
     *
     * This will stop receiving DataShare OnChange notifications and release observer resources.
     *
     * @return true if the observer was successfully unregistered or no observer was registered;
     *         false on failure.
     */
    bool UnRegisterObserver();

public:
    /**
     * @brief Query reminders within a configured time window (relative to current time).
     *
     * The implementation typically queries the DataShare provider for reminders within a
     * time range (e.g., from now to now + X minutes) and returns them as a map keyed by
     * reminder identifier.
     *
     * @param[out] reminders A map to be filled with identifier -> ReminderRequest mappings.
     * @return true on successful query (even if the result set is empty), false on error.
     */
    bool Query(std::map<std::string, sptr<ReminderRequest>>& reminders);

    /**
     * @brief Query a single string value from the specified DataShare URI by key/column name.
     *
     * Typical usage includes fetching metadata values such as provider uid or version strings.
     *
     * @param[in] uri DataShare Uri to query.
     * @param[in] key Column name to retrieve.
     * @param[out] value Retrieved string value when returns true.
     * @return true if the value was found and assigned to `value`, false otherwise.
     */
    bool Query(Uri& uri, const std::string& key, std::string& value);

    /**
     * @brief Update the state field of a reminder identified by `identifier`.
     *
     * The `state` parameter must be one of ReminderCalendarShareTable::STATE_* constants.
     *
     * @param[in] identifier The unique identifier of the reminder to update.
     * @param[in] state New state value to set.
     * @return true if the update succeeded, false otherwise.
     */
    bool Update(const std::string& identifier, const int32_t state);

    /**
     * @brief Start calendar data extension actions such as sync or background processing.
     *
     * The `reason` parameter should use codes defined in ReminderCalendarShareTable::START_*.
     *
     * @param[in] reason Reason code that indicates why the data extension is started.
     */
    void StartDataExtension(const int32_t reason);

public:
    /**
     * @brief Set the current user id used to build URIs and access contexts.
     * @param[in] userId User id to set for subsequent operations.
     */
    void SetUserId(const int32_t userId)
    {
        userId_ = userId;
    }

    /**
     * @brief Reset ReminderCalendarShareTable::NAME uid. because app uninstall.
     */
    void ResetUid()
    {
        uid_ = -1;
    }

    /**
     * @brief Update cached calendar provider UIDs (calendar and calendardata).
     *
     * This method refreshes `uid_` and `dataUid_` based on system/provider discovery.
     * Call when user context or provider configuration changes.
     */
    void UpdateCalendarUid();

    /**
     * @brief Get a snapshot copy of cached reminders pending processing.
     *
     * Returns a thread-safe copy of the internal cache so callers can safely iterate
     * without holding internal locks.
     *
     * @return Move of the internal reminder cache map.
     */
    std::map<std::string, sptr<ReminderRequest>> GetCacheReminders();

    /**
     * @brief Insert or merge provided reminders into the internal cache.
     *
     * The method is thread-safe and protected by `cacheMutex_`. The cache is used to
     * coalesce frequent updates before delivering them to upper layers.
     *
     * @param[in] reminders Map of identifier -> ReminderRequest to insert into cache.
     */
    void InsertCacheReminders(const std::map<std::string, sptr<ReminderRequest>>& reminders);

public:
    /**
     * @brief Handle DataShare OnChange events that are insert or delete type.
     *
     * Implementation may throttle or coalesce rapid insert/delete events to reduce
     * query frequency. This method is intended to be lightweight and signal work
     * to an asynchronous queue (`queue_`) if needed.
     */
    void OnDataInsertOrDelete();

    /**
     * @brief Handle DataShare OnChange events that contain update details.
     *
     * Parses `info` to construct ReminderRequest objects and inserts them into the cache
     * or dispatches them to listeners as required.
     *
     * @param[in] info ChangeInfo structure containing column/value buckets describing updates.
     */
    void OnDataUpdate(const DataShare::DataShareObserver::ChangeInfo& info);

    /**
     * @brief Reset insertTask_ or updateTask_ value.
     *
     * @param[in] isInsertTask true: set insertTask_ value, false: set updateTask_ value.
     */
    void ResetTaskFlag(const bool isInsertTask);

private:
    /**
     * @brief Create a DataShareHelper for the given URI string.
     *
     * The returned helper should be released by calling DataShareHelper::Release when no
     * longer needed.
     *
     * @param[in] uriStr String representation of the DataShare URI.
     * @return Shared pointer to a DataShareHelper instance, or nullptr on failure.
     */
    std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(const std::string& uriStr);

private:
    /**
     * @brief Build a ReminderRequest from a DataShare result row.
     *
     * Parses the DataShare::DataShareResultSet row according to the detected RDB
     * schema version and fills a ReminderRequest instance.
     *
     * @param[in] result Result set row to parse.
     * @return Smart pointer to a constructed ReminderRequest; nullptr on parse failure.
     */
    sptr<ReminderRequest> CreateReminder(const std::shared_ptr<DataShare::DataShareResultSet>& result);

    /**
     * @brief Build ReminderRequest objects from ChangeInfo update buckets.
     *
     * Iterates over ChangeInfo VBucket entries and constructs a map of identifier ->
     * ReminderRequest representing updated rows.
     *
     * @param[in] info ChangeInfo carrying VBucket entries with column/value mappings.
     * @return Map of identifier to constructed ReminderRequest objects.
     */
    std::map<std::string, sptr<ReminderRequest>> CreateReminder(
        const DataShare::DataShareObserver::ChangeInfo& info);

    /**
     * @brief Initialize common reminder fields after construction/parsing.
     *
     * Normalizes values, sets defaults and computes derived fields required for
     * ReminderRequest to be consumable by notification logic.
     *
     * @param[in,out] reminder ReminderRequest instance to initialize.
     */
    void InitNormalInfo(sptr<ReminderRequest>& reminder);

    /**
     * @brief Populate base fields of a ReminderRequest from a single VBucket entry.
     *
     * Reads standard columns from the provided VBucket and maps them to ReminderRequest
     * members. Used by CreateReminder(ChangeInfo).
     *
     * @param[in] info Single change bucket with column/value pairs.
     * @param[in,out] reminder Target ReminderRequest to fill.
     */
    void InitBaseInfo(const DataShare::DataShareObserver::ChangeInfo::VBucket& info,
        sptr<ReminderRequest>& reminder);

    /**
     * @brief Parsing helpers for calendar RDB schema version 1.
     *
     * These overloads parse version-1-formatted rows or VBucket entries into a
     * ReminderRequest.
     */
    void BuildReminderV1(const std::shared_ptr<DataShare::DataShareResultSet>& result,
        sptr<ReminderRequest>& reminder);
    void BuildReminderV1(const DataShare::DataShareObserver::ChangeInfo::VBucket& info,
        sptr<ReminderRequest>& reminder);

    /**
     * @brief Build query predicates conditions.
     *
     * Create predicates for querying valid alerts.
     */
    DataShare::DataSharePredicates BuildQueryPredicates(int64_t timestamp, int64_t targetTimestamp);

private:
    // Singleton
    ReminderDataShareHelper();
    ~ReminderDataShareHelper() = default;

    ReminderDataShareHelper(const ReminderDataShareHelper&) = delete;
    ReminderDataShareHelper& operator=(const ReminderDataShareHelper&) = delete;
    ReminderDataShareHelper(ReminderDataShareHelper&&) = delete;
    ReminderDataShareHelper& operator=(ReminderDataShareHelper&&) = delete;

private:
    int8_t rdbVersion_ {0};  // calendar rdb version
    int32_t userId_ {0};
    int32_t uid_ {-1};  // calendar
    int32_t dataUid_ {0};  // calendardata
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
     * @brief DataShare change notification entry point.
     *
     * Implementations should forward the `info` to the owning ReminderDataShareHelper
     * in a thread-safe and non-blocking manner (e.g., by posting a task to `queue_`).
     *
     * @param[in] info Structure describing the data change.
     */
    void OnChange(const ChangeInfo& info) override;
};
};
}  // namespace OHOS::Notification
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_REMINDER_INCLUDE_REMINDER_DATASHARE_HELPER_H