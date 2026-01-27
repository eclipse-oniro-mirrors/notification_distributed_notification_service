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

#ifndef ANS_NOTIFICATION_RDB_MGR_H
#define ANS_NOTIFICATION_RDB_MGR_H

#include <cstdint>
#include <memory>
#include <string>
#include <set>
#include <unordered_map>
#include <vector>
#include "ffrt.h"
#include "notification_rdb_config.h"
#include "notification_rdb_hook.h"
#include "notification_rdb_event_handler_type.h"

namespace OHOS::Notification::Infra {

class NtfRdbStoreWrapper;

/**
 * @class NotificationRdbMgr
 * @brief Public façade for notification key-value persistence on top of NativeRdb.
 *
 * This class mainly delegates to an internal NtfRdbStoreWrapper instance, which owns the
 * NativeRdb store and handles table management, error reporting, and recovery.
 */
class NotificationRdbMgr {
public:
    /**
     * @brief Construct a manager with configuration, hooks, and enabled event handlers.
     *
     * @param config Database configuration (path/name/table/version/journal/sync).
     * @param hooks Callback hooks used for upgrade migration, error reporting, and metrics.
     * @param eventHandlerTypes Enabled RDB open/upgrade handlers.
     */
    NotificationRdbMgr(NotificationRdbConfig& config, const NtfRdbHook &hooks,
        const std::set<RdbEventHandlerType> &eventHandlerTypes);

    ~NotificationRdbMgr() = default;

    /** @brief Create/open the underlying RDB store and initialize internal state. */
    int32_t Init();

    /** @brief Close and delete the underlying RDB store. */
    int32_t Destroy();

    /**
     * @brief Insert or replace a string value by key.
     *
     * @param key Record key.
     * @param value String value.
     * @param userId User id used for per-user tables (implementation defines the valid range).
     */
    int32_t InsertData(const std::string &key, const std::string &value, const int32_t &userId = -1);

    /**
     * @brief Insert or replace a blob value by key.
     *
     * @param key Record key.
     * @param value Blob value.
     * @param userId User id used for per-user tables (implementation defines the valid range).
     */
    int32_t InsertData(const std::string &key, const std::vector<uint8_t> &value, const int32_t &userId = -1);

    /**
     * @brief Batch insert string key-value pairs.
     *
     * Empty input is treated as success.
     */
    int32_t InsertBatchData(const std::unordered_map<std::string, std::string> &values,
        const int32_t &userId = -1);

    /** @brief Delete a record by key (may search/delete in multiple tables depending on userId). */
    int32_t DeleteData(const std::string &key, const int32_t &userId = -1);

    /** @brief Batch delete keys (may search/delete in multiple tables depending on userId). */
    int32_t DeleteBatchData(const std::vector<std::string> &keys, const int32_t userId = -1);

    /**
     * @brief Query a string value by key.
     *
     * If multiple tables are involved, the implementation may search a user table first and
     * then fall back to the default table.
     */
    int32_t QueryData(const std::string &key, std::string &value, const int32_t &userId = -1);

    /** @brief Query a blob value by key; see the string overload for lookup behavior. */
    int32_t QueryData(const std::string &key, std::vector<uint8_t> &value, const int32_t &userId = -1);

    /** @brief Query all records whose key begins with the given prefix. */
    int32_t QueryDataBeginWithKey(const std::string &key,
        std::unordered_map<std::string, std::string> &values, const int32_t &userId = -1);

    /** @brief Query all records whose key contains the given substring. */
    int32_t QueryDataContainsWithKey(const std::string &key,
        std::unordered_map<std::string, std::string> &values, const int32_t &userId = -1);

    /** @brief Query all key-value records. */
    int32_t QueryAllData(std::unordered_map<std::string, std::string> &values, const int32_t &userId = -1);

    /** @brief Drop the per-user table for the given userId, if it exists. */
    int32_t DropUserTable(const int32_t userId);

private:
    /** Underlying store wrapper that implements the actual RDB operations. */
    std::shared_ptr<NtfRdbStoreWrapper> rdbStoreWrapper_;
};
} // namespace OHOS::Notification::Infra
#endif // ANS_NOTIFICATION_RDB_MGR_H