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

#ifndef ANS_NOTIFICATION_RDB_STORE_WRAPPER_H
#define ANS_NOTIFICATION_RDB_STORE_WRAPPER_H

#include <cstdint>
#include <memory>
#include <string>
#include <set>
#include <unordered_map>
#include <vector>
#include "ffrt.h"
#include "notification_rdb_config.h"
#include "notification_rdb_event_handler_type.h"
#include "notification_rdb_hook.h"
#include "notification_rdb_hook_mgr.h"

namespace OHOS {
namespace NativeRdb {
class RdbStore;
class AbsSharedResultSet;
class AbsRdbPredicates;
} // namespace NativeRdb
namespace Notification::Infra {
/**
 * @class NtfRdbStoreWrapper
 * @brief Notification RDB adapter that provides key-value style operations on top of NativeRdb.
 *
 * The wrapper maintains a default table and may create per-user tables for specific user ids.
 * Reads and deletes may operate on multiple tables depending on the user id.
 */
class NtfRdbStoreWrapper {
public:
    /**
     * @brief Construct the wrapper.
     * @param config Database configuration.
     * @param hooks Callback hooks for upgrade migration, error reporting, and metrics.
     * @param eventHandlerTypes Enabled RDB open/upgrade handlers.
     */
    NtfRdbStoreWrapper(const NotificationRdbConfig& config, const NtfRdbHook &hooks,
        const std::set<RdbEventHandlerType> &eventHandlerTypes);

    ~NtfRdbStoreWrapper() = default;

    /** @brief Create/open the RDB store and cache existing table names. */
    int32_t Init();

    /** @brief Close and delete the underlying database file. */
    int32_t Destroy();

    /** @brief Insert or replace a string value by key. */
    int32_t InsertData(const std::string &key, const std::string &value, const int32_t &userId = -1);

    /** @brief Insert or replace a blob value by key. */
    int32_t InsertData(const std::string &key, const std::vector<uint8_t> &value, const int32_t &userId = -1);

    /** @brief Batch insert key-value pairs (empty input is treated as success). */
    int32_t InsertBatchData(const std::unordered_map<std::string, std::string> &values,
        const int32_t &userId = -1);

    /** @brief Delete a record by key (may try more than one table depending on userId). */
    int32_t DeleteData(const std::string &key, const int32_t &userId = -1);

    /** @brief Batch delete keys (may try more than one table depending on userId). */
    int32_t DeleteBatchData(const std::vector<std::string> &keys, const int32_t userId = -1);

    /** @brief Query a string value by key (may fall back across tables depending on userId). */
    int32_t QueryData(const std::string &key, std::string &value, const int32_t &userId = -1);

    /** @brief Query a blob value by key (may fall back across tables depending on userId). */
    int32_t QueryData(const std::string &key, std::vector<uint8_t> &value, const int32_t &userId = -1);

    /** @brief Query all records whose key begins with the given prefix. */
    int32_t QueryDataBeginWithKey(const std::string &key,
        std::unordered_map<std::string, std::string> &values, const int32_t &userId = -1);

    /** @brief Query all records whose key contains the given substring. */
    int32_t QueryDataContainsWithKey(const std::string &key,
        std::unordered_map<std::string, std::string> &values, const int32_t &userId = -1);

    /** @brief Query all key-value records. */
    int32_t QueryAllData(std::unordered_map<std::string, std::string> &values, const int32_t &userId = -1);

    /** @brief Drop a per-user table and update the internal created-table cache. */
    int32_t DropUserTable(const int32_t userId);
private:
    /** @brief Create the NativeRdb store instance if not already created. */
    int32_t InitRdbStore();

    /** @brief Populate createdTables_ from sqlite_master. */
    int32_t InitCreatedTables();

    /** @brief Build the list of tables that should be operated for the given user id. */
    std::vector<std::string> GenerateOperatedTables(const int32_t &userId);

    /** @brief Resolve the actual table name for a user (create it if needed). */
    int32_t GetUserTableName(const int32_t &userId, std::string &tableName);

    /** @brief Try to restore the store when corruption is detected. */
    int32_t RestoreForMasterSlaver();

    /** @brief Full recovery by destroying and reinitializing the store (guarded by isRecovering_). */
    void RecoverDatabase();

    /** @brief Delete one key from a specific table. */
    int32_t DeleteData(const std::string &tableName, const std::string &key, int32_t rowId);

    /** @brief Query a string value from a specific table. */
    int32_t QueryData(const std::string tableName, const std::string key, std::string &value);

    /** @brief Query a blob value from a specific table. */
    int32_t QueryData(const std::string tableName, const std::string key, std::vector<uint8_t> &value);

    /** @brief Query key-value pairs whose key begins with the given prefix from a specific table. */
    int32_t QueryDataBeginWithKey(const std::string tableName, const std::string key,
        std::unordered_map<std::string, std::string> &values);

    /** @brief Query key-value pairs whose key contains the given substring from a specific table. */
    int32_t QueryDataContainsWithKey(const std::string tableName, const std::string key,
        std::unordered_map<std::string, std::string> &values);

    /** @brief Query all key-value pairs from a specific table. */
    int32_t QueryAllData(const std::string tableName, std::unordered_map<std::string, std::string> &datas);

    /** @brief Split a key list into fixed-size batches for IN(...) predicates. */
    std::vector<std::vector<std::string>> SplitKeysIntoBatches(
        const std::vector<std::string>& keys, size_t batchSize) const;

    /** @brief Delete batched keys from a specific table. */
    int32_t DeleteFromTable(
        const std::vector<std::vector<std::string>>& batchKeys,
        const std::string& tableName) const;

    template<typename Func>
    /** @brief Execute an insert function with corruption detection and error reporting. */
    int32_t InsertDataWithErrorHandling(const int32_t userId, Func insertFunc, bool isBatchMode,
        const int32_t sceneId, const int32_t branchId);

    template<typename Func>
    /** @brief Execute a query function across multiple tables with corruption detection. */
    int32_t QueryMultiTablesWithErrorHandling(const int32_t userId, Func queryFunc, bool isSingleValueMode);

    /** @brief Execute a query and return status. */
    int32_t ExecuteQuery(const std::string& tableName, NativeRdb::AbsRdbPredicates& predicates,
        std::shared_ptr<NativeRdb::AbsSharedResultSet>& resultSet);

    /** @brief Validate the first row exists and report errors consistently. */
    int32_t CheckFirstRow(std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet, const std::string& tableName,
        const std::string& key, int32_t sceneId, int32_t branchId);

    /** @brief Extract a string value from the current row and close the result set. */
    int32_t ExtractStringValue(std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet, const std::string& tableName,
        std::string& value, int32_t sceneId, int32_t branchId);

    /** @brief Extract a blob value from the current row and close the result set. */
    int32_t ExtractBlobValue(std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet, const std::string& tableName,
        std::vector<uint8_t>& value, int32_t sceneId, int32_t branchId);

    /** @brief Extract all key-value pairs from the result set into a map and close it. */
    int32_t ExtractMapValues(std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet, const std::string& tableName,
        std::unordered_map<std::string, std::string>& values, int32_t sceneId, int32_t branchId);

    template<typename Func>
    /** @brief Execute a delete function with corruption detection and error reporting. */
    int32_t DeleteDataWithErrorHandling(const int32_t userId, Func deleteFunc, bool isBatchMode,
        const int32_t sceneId, const int32_t branchId);

private:
    /** Database configuration used to open and manage the store. */
    NotificationRdbConfig notificationRdbConfig_;

    /** Hook manager for upgrade migration, failure reporting, and size metrics. */
    std::shared_ptr<NtfRdbHookMgr> hookMgr_{nullptr};

    /** Enabled handler types used when opening the RdbStore. */
    std::set<RdbEventHandlerType> eventHandlerTypes_;

    /** Protects rdbStore_ creation and all direct store operations. */
    mutable ffrt::mutex rdbStorePtrMutex_;

    /** NativeRdb store instance (lazily created). */
    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;

    /** Protects createdTables_. */
    mutable ffrt::mutex createdTableMutex_;

    /** Cache of created table names to avoid redundant CREATE TABLE operations. */
    std::set<std::string> createdTables_;

    /** Guard flag indicating that a recovery flow is in progress. */
    std::atomic<bool> isRecovering_{false};
};
} // namespace Notification::Infra
} // namespace OHOS
#endif // ANS_NOTIFICATION_RDB_STORE_WRAPPER_H