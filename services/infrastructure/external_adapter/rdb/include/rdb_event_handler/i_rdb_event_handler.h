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

#ifndef ANS_NOTIFICATION_I_RDB_EVENT_HANDLER_H
#define ANS_NOTIFICATION_I_RDB_EVENT_HANDLER_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace NativeRdb {
class RdbStore;
} // namespace NativeRdb
namespace Notification::Infra {
/**
 * @class IRdbEventHandler
 * @brief Base class for handling NativeRdb open callback events.
 *
 * Subclasses override the event methods they care about. The default implementations return
 * NativeRdb::E_OK and perform no action.
 */
class IRdbEventHandler {
public:
    /** @brief Virtual destructor. */
    virtual ~IRdbEventHandler() = default;

    /**
     * @brief Called when the database is created for the first time.
     * @return NativeRdb::E_OK on success; non-zero to abort the open.
     */
    virtual int32_t OnCreate(NativeRdb::RdbStore &rdbStore);

    /**
     * @brief Called when the database schema is being upgraded.
     * @return NativeRdb::E_OK on success; non-zero to abort the upgrade.
     */
    virtual int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion);

    /**
     * @brief Called when the database schema is being downgraded.
     * @return NativeRdb::E_OK on success; non-zero to abort the downgrade.
     */
    virtual int32_t OnDowngrade(NativeRdb::RdbStore &rdbStore, int32_t currentVersion, int32_t targetVersion);

    /**
     * @brief Called when the database is opened.
     * @return NativeRdb::E_OK on success; non-zero to abort the open.
     */
    virtual int32_t OnOpen(NativeRdb::RdbStore &rdbStore);

    /**
     * @brief Called when database corruption is detected.
     * @return NativeRdb::E_OK on success; non-zero to indicate handling failure.
     */
    virtual int32_t OnCorruption(const std::string &databaseFile);

    /**
     * @brief Called when upgrade has failed repeatedly and data cleanup is needed.
     *
     * Each handler should delete only the data it manages (e.g., specific key prefixes)
     * to preserve unrelated data in the database.
     */
    virtual void OnUpgradeFailure(NativeRdb::RdbStore &rdbStore);

    /**
     * @brief Per-business migration-in-progress mark key for crash recovery.
     *
     * The mark is written before the handler's migration starts and cleared after it
     * returns normally. A residual mark on the next open means the last migration was
     * interrupted by a crash, so the handler's data may be half-migrated and its
     * OnUpgradeFailure cleanup must run. An empty string opts out of crash recovery.
     */
    virtual std::string GetMigrationMarkKey() const;

    /** @brief Unique handler name used for registration and logging. */
    virtual std::string GetHandlerName() const = 0;

    /** @brief Whether this handler is enabled and should be executed. */
    virtual bool IsEnabled() const;

    /** @brief Enable or disable this handler. */
    virtual void SetEnabled(bool enabled);

protected:
    /** Whether the handler should be executed by a manager. */
    bool enabled_ = true;
};
} // namespace Notification::Infra
} // namespace OHOS

#endif // ANS_NOTIFICATION_I_RDB_EVENT_HANDLER_H