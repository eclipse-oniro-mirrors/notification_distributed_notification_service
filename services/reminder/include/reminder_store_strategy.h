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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_STORE_STRATEGY_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_STORE_STRATEGY_H

#include <vector>
#include <unordered_map>

#include "reminder_request.h"
#include "rdb_store.h"

namespace OHOS {
namespace Notification {
class ReminderStrategy {
public:
    /**
     * @brief Gets the value from rdb result.
     *
     * @param resultSet the rdb result.
     * @param name the column name in rdb.
     * @param value the column value in rdb.
     */
    template<typename T>
    static void GetRdbValue(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
        const std::string& name, T& value);

public:
    /**
     * @brief Persist the reminder to the database.
     */
    static void AppendValuesBucket(const sptr<ReminderRequest>& reminder,
        NativeRdb::ValuesBucket &values, const bool oldVersion = false);

    /**
     * @brief Restore the reminder from the database(old version rdb).
     */
    static void RecoverFromOldVersion(sptr<ReminderRequest>& reminder,
        const std::shared_ptr<NativeRdb::ResultSet>& resultSet);

    /**
     * @brief Restore the reminder from the database.
     */
    static void RecoverFromDb(sptr<ReminderRequest>& reminder, const std::shared_ptr<NativeRdb::ResultSet>& resultSet);

private:
    /**
     * @brief Recovery time related fields from the database(old version rdb).
     */
    static void RecoverTimeFromOldVersion(sptr<ReminderRequest>& reminder,
        const std::shared_ptr<NativeRdb::ResultSet>& resultSet);
    /**
     * @brief Recovery id related fields from the database(old version rdb).
     */
    static void RecoverIdFromOldVersion(sptr<ReminderRequest>& reminder,
        const std::shared_ptr<NativeRdb::ResultSet>& resultSet);
    /**
     * @brief Recovery context related from the database(old version rdb).
     */
    static void RecoverContextFromOldVersion(sptr<ReminderRequest>& reminder,
        const std::shared_ptr<NativeRdb::ResultSet>& resultSet);

    /**
     * @brief Recovery time related fields from the database.
     */
    static void RecoverTimeFromDb(sptr<ReminderRequest>& reminder,
        const std::shared_ptr<NativeRdb::ResultSet>& resultSet);
    /**
     * @brief Recovery id related fields from the database.
     */
    static void RecoverIdFromDb(sptr<ReminderRequest>& reminder,
        const std::shared_ptr<NativeRdb::ResultSet>& resultSet);
    /**
     * @brief Recovery context related from the database.
     */
    static void RecoverContextFromDb(sptr<ReminderRequest>& reminder,
        const std::shared_ptr<NativeRdb::ResultSet>& resultSet);
};

class ReminderTimerStrategy {
public:
    /**
     * @brief Persist the reminder to the database.
     */
    static void AppendValuesBucket(const sptr<ReminderRequest>& reminder,
        NativeRdb::ValuesBucket& values);

    /**
     * @brief Restore the reminder from the database(old version rdb).
     */
    static void RecoverFromOldVersion(sptr<ReminderRequest>& reminder,
        const std::shared_ptr<NativeRdb::ResultSet>& resultSet);

    /**
     * @brief Restore the reminder from the database.
     */
    static void RecoverFromDb(sptr<ReminderRequest>& reminder, const std::shared_ptr<NativeRdb::ResultSet>& baseResult,
        const std::shared_ptr<NativeRdb::ResultSet>& resultSet);
};

class ReminderAlarmStrategy {
public:
    /**
     * @brief Persist the reminder to the database.
     */
    static void AppendValuesBucket(const sptr<ReminderRequest> &reminder, NativeRdb::ValuesBucket &values);

    /**
     * @brief Restore the reminder from the database(old version rdb).
     */
    static void RecoverFromOldVersion(sptr<ReminderRequest>& reminder,
        const std::shared_ptr<NativeRdb::ResultSet>& resultSet);

    /**
     * @brief Restore the reminder from the database.
     */
    static void RecoverFromDb(sptr<ReminderRequest>& reminder, const std::shared_ptr<NativeRdb::ResultSet>& baseResult,
        const std::shared_ptr<NativeRdb::ResultSet>& resultSet);
};

class ReminderCalendarStrategy {
public:
    /**
     * @brief Persist the reminder to the database.
     */
    static void AppendValuesBucket(const sptr<ReminderRequest> &reminder, NativeRdb::ValuesBucket &values);

    /**
     * @brief Restore the reminder from the database(old version rdb).
     */
    static void RecoverFromOldVersion(sptr<ReminderRequest>& reminder,
        const std::shared_ptr<NativeRdb::ResultSet>& resultSet);

    /**
     * @brief Restore the reminder from the database.
     */
    static void RecoverFromDb(sptr<ReminderRequest>& reminder, const std::shared_ptr<NativeRdb::ResultSet>& baseResult,
        const std::shared_ptr<NativeRdb::ResultSet>& resultSet);

private:
    static void RecoverTime(sptr<ReminderRequest>& reminder, const std::shared_ptr<NativeRdb::ResultSet>& resultSet);
};

template<typename T>
void ReminderStrategy::GetRdbValue(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
    const std::string& name, T& value)
{
    value = T();
    int32_t columnIndex = -1;
    resultSet->GetColumnIndex(name, columnIndex);
    if (columnIndex == -1) {
        ANSR_LOGE("the column %{public}s does not exsit.", name.c_str());
        return;
    }

    if constexpr (std::is_same_v<T, std::string>) {
        resultSet->GetString(columnIndex, value);
    } else if constexpr (std::is_same_v<T, int64_t>) {
        resultSet->GetLong(columnIndex, value);
    } else if constexpr (std::is_same_v<T, uint64_t>) {
        int64_t t = 0;
        resultSet->GetLong(columnIndex, t);
        value = static_cast<uint64_t>(t);
    } else if constexpr (std::is_same_v<T, int32_t>) {
        resultSet->GetInt(columnIndex, value);
    } else if constexpr (std::is_same_v<T, uint32_t>) {
        int32_t t = 0;
        resultSet->GetInt(columnIndex, t);
        value = static_cast<uint32_t>(t);
    } else if constexpr (std::is_same_v<T, uint16_t>) {
        int32_t t = 0;
        resultSet->GetInt(columnIndex, t);
        value = static_cast<uint16_t>(t);
    } else if constexpr (std::is_same_v<T, uint8_t>) {
        int32_t t = 0;
        resultSet->GetInt(columnIndex, t);
        value = static_cast<uint8_t>(t);
    }
}
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_STORE_STRATEGY_H