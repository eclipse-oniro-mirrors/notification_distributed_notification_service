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

#ifndef ANS_NOTIFICATION_LIVE_VIEW_MIGRATION_HANDLER_H
#define ANS_NOTIFICATION_LIVE_VIEW_MIGRATION_HANDLER_H

#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include "i_rdb_event_handler.h"
#include "notification_rdb_hook_mgr.h"

namespace OHOS {
namespace NativeRdb {
class RdbStore;
class AbsSharedResultSet;
} // namespace NativeRdb
namespace Notification::Infra {
/**
 * @class LiveViewMigrationHandler
 * @brief Migrates live view records during schema upgrade.
 *
 * Current implementation:
 * - Runs only when upgrading from version 1.
 * - Enumerates all tables via sqlite_master.
 * - For each table, queries keys beginning with "secure_live_view".
 * - For each matching row, invokes hookMgr_->OnRdbUpgradeLiveviewMigrate(old, outNew).
 * - Replaces the row value with the migrated data.
 */
class LiveViewMigrationHandler : public IRdbEventHandler {
public:
    /**
     * @brief Constructor for LiveViewMigrationHandler.
     *
     * Initializes the handler with no configuration required.
     * All parameters for migration are embedded in the database schema.
     */
    /**
     * @brief Construct the handler.
     * @param hookMgr Hook manager used to perform per-record value migration.
     */
    LiveViewMigrationHandler(std::shared_ptr<NtfRdbHookMgr> hookMgr) : hookMgr_(hookMgr) {};

    /**
     * @brief Destructor.
     */
    virtual ~LiveViewMigrationHandler() = default;

    /**
     * @brief Execute migration logic during database upgrade.
     * @return NativeRdb::E_OK on success.
     */
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion) override;

    /** @brief Return the fixed handler name used for registration. */
    std::string GetHandlerName() const override;

private:
    /** @brief Query sqlite_master and return all table names. */
    std::set<std::string> GetTableNames(NativeRdb::RdbStore &rdbStore);

    /** @brief Process a single table and migrate all matching rows. */
    bool ProcessTable(NativeRdb::RdbStore &rdbStore, const std::string &tableName);

    /** @brief Query rows whose key begins with LIVE_VIEW_KEY. */
    std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryTable(
        NativeRdb::RdbStore &rdbStore, const std::string &tableName);

    /** @brief Iterate a result set and migrate each row. */
    bool ProcessResultSet(
        std::shared_ptr<NativeRdb::AbsSharedResultSet> absSharedResultSet,
        NativeRdb::RdbStore &rdbStore, const std::string &tableName);

    /** @brief Migrate the current row and update it via INSERT OR REPLACE semantics. */
    bool ProcessRow(
        std::shared_ptr<NativeRdb::AbsSharedResultSet> absSharedResultSet,
        NativeRdb::RdbStore &rdbStore, const std::string &tableName);

    /** @brief Read a string from the current row and column index. */
    bool GetStringFromResultSet(
        std::shared_ptr<NativeRdb::AbsSharedResultSet> absSharedResultSet,
        int columnIndex, std::string &result);

private:
    /** Column name for the key field. */
    static const std::string NOTIFICATION_KEY;

    /** Column name for the value field. */
    static const std::string NOTIFICATION_VALUE;

    /** Result column index for the key field. */
    static const int32_t NOTIFICATION_KEY_INDEX;

    /** Result column index for the value field. */
    static const int32_t NOTIFICATION_VALUE_INDEX;

    /** Key prefix that identifies live view records. */
    static const std::string LIVE_VIEW_KEY;

    /** Hook manager used to perform value migration. */
    std::shared_ptr<NtfRdbHookMgr> hookMgr_;
};
} // namespace Notification::Infra
} // namespace OHOS

#endif // ANS_NOTIFICATION_LIVE_VIEW_MIGRATION_HANDLER_H
