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

#ifndef ANS_NOTIFICATION_PRIORITY_INFO_MIGRATION_HANDLER_H
#define ANS_NOTIFICATION_PRIORITY_INFO_MIGRATION_HANDLER_H

#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include "i_rdb_event_handler.h"

namespace OHOS {
namespace NativeRdb {
class RdbStore;
class AbsSharedResultSet;
} // namespace NativeRdb
namespace Notification::Infra {
/**
 * @class PriorityInfoMigrationHandler
 * @brief Migrates priority records during database upgrade.
 *
 * Current implementation:
 * - Runs only when upgrading from version 2.
 * - Replaces the row value with the migrated data.
 */
class PriorityInfoMigrationHandler : public IRdbEventHandler {
public:
    /**
     * @brief Constructor for PriorityInfoMigrationHandlerr.
     *
     * Initializes the handler with no configuration required.
     */
    /**
     * @brief Construct the handler.
     */
    PriorityInfoMigrationHandler() = default;

    /**
     * @brief Destructor.
     */
    virtual ~PriorityInfoMigrationHandler() = default;

    /**
     * @brief Execute migration logic during database upgrade.
     * @return NativeRdb::E_OK on success.
     */
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion) override;

    void OnUpgradeFailure(NativeRdb::RdbStore &rdbStore) override;

    std::string GetMigrationMarkKey() const override;

    /** @brief Return the fixed handler name used for registration. */
    std::string GetHandlerName() const override;

private:
    /** @brief Query sqlite_master and return all table names. */
    std::set<std::string> GetTableNames(NativeRdb::RdbStore &rdbStore);

    /** @brief Process a single table and migrate all matching rows. */
    bool ProcessTable(NativeRdb::RdbStore &rdbStore, const std::string &tableName);

    /** @brief Query rows whose key likes priority. */
    std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryTable(
        NativeRdb::RdbStore &rdbStore, const std::string &tableName);

    /** @brief Iterate a result set and migrate each row. */
    bool ProcessResultSet(
        std::shared_ptr<NativeRdb::AbsSharedResultSet> absSharedResultSet,
        NativeRdb::RdbStore &rdbStore, const std::string &tableName);

    /** @brief Process a single row from the result set. */
    bool ProcessRow(
        std::shared_ptr<NativeRdb::AbsSharedResultSet> absSharedResultSet,
        NativeRdb::RdbStore &rdbStore, const std::string &tableName);

    /** @brief Read a string from the current row and column index. */
    bool GetStringFromResultSet(
        std::shared_ptr<NativeRdb::AbsSharedResultSet> absSharedResultSet,
        int columnIndex, std::string &result);

    /** @brief Migrate the current row and update it via INSERT OR REPLACE semantics. */
    bool onRdbUpgradePriorityMigrate(
        NativeRdb::RdbStore &rdbStore, const std::string &key, const std::string &val, const std::string &tableName);

    /** @brief Insert or replace a key-value pair into the specified table. */
    bool InsertToDatabase(NativeRdb::RdbStore &rdbStore,
        const std::string& key, const std::string& value, const std::string& tableName);
private:
    /** Column name for the key field. */
    static const std::string NOTIFICATION_KEY;

    /** Column name for the value field. */
    static const std::string NOTIFICATION_VALUE;

    /** Result column index for the key field. */
    static const int32_t NOTIFICATION_KEY_INDEX;

    /** Result column index for the value field. */
    static const int32_t NOTIFICATION_VALUE_INDEX;

    /** Key suffix for priority notification switch. */
    static const std::string PRIORITY_SWITCH_KEY;

    /** Key suffix for per-bundle priority notification switch. */
    static const std::string PRIORITY_SWITCH_FOR_BUNDLE_KEY;

    /** Key suffix for intelligent priority notification switch. */
    static const std::string PRIORITY_INTELLIGENT_SWITCH_KEY;

    /** Key suffix for per-bundle priority notification switch V2. */
    static const std::string PRIORITY_SWITCH_FOR_BUNDLE_V2_KEY;

    /** Key suffix for per-bundle priority strategy configuration. */
    static const std::string PRIORITY_STRATEGY_FOR_BUNDLE_KEY;

    /** Value representing disabled state (0). */
    static const std::string PRIORITY_SWITCH_DISABLED;

    /** Value representing enabled for intelligent state (1). */
    static const std::string PRIORITY_SWITCH_ENABLED;

    /** Value representing enabled for all state (2). */
    static const std::string PRIORITY_SWITCH_ENABLED_ALL;

    /** Value representing intelligent strategy state (30). */
    static const std::string PRIORITY_SWITCH_STRATEGY_INTELLIGENT;

    /** Value representing all messages strategy state (32). */
    static const std::string PRIORITY_SWITCH_STRATEGY_ALL;

    /** Value representing legacy priority database version (2). */
    static const int32_t PRIORITY_LEGACY_VERSION;
};
} // namespace Notification::Infra
} // namespace OHOS

#endif // ANS_NOTIFICATION_PRIORITY_INFO_MIGRATION_HANDLER_H
