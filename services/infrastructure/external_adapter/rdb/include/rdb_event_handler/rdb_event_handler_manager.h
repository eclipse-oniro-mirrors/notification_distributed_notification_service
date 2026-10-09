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

#ifndef ANS_NOTIFICATION_RDB_EVENT_HANDLER_MANAGER_H
#define ANS_NOTIFICATION_RDB_EVENT_HANDLER_MANAGER_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include "i_rdb_event_handler.h"
#include "ffrt.h"


namespace OHOS {
namespace NativeRdb {
class RdbStore;
} // namespace NativeRdb
namespace Notification::Infra {
/**
 * @class RdbEventHandlerManager
 * @brief Thread-safe registry and dispatcher for IRdbEventHandler instances.
 *
 * Handlers are grouped by event type. Registration requires unique handler names across all
 * event lists.
 */
class RdbEventHandlerManager {
public:
    /** @brief Supported database lifecycle events. */
    enum class EventType {
        /** Database created. */
        ON_CREATE = 0,
        /** Schema upgrade. */
        ON_UPGRADE = 1,
        /** Schema downgrade. */
        ON_DOWNGRADE = 2,
        /** Database opened. */
        ON_OPEN = 3,
        /** Database corruption detected. */
        ON_CORRUPTION = 4,
    };

    RdbEventHandlerManager() = default;

    ~RdbEventHandlerManager() = default;

    /**
     * @brief Register a handler for an event type.
     * @return true if registered; false if handler is null or a duplicate name exists.
     */
    bool RegisterHandler(EventType eventType, std::shared_ptr<IRdbEventHandler> handler);

    /**
     * @brief Unregister a handler by name.
     * @return true if found and removed; otherwise false.
     */
    bool UnregisterHandler(const std::string &handlerName);

    /** @brief Execute all enabled handlers registered for ON_CREATE. */
    int32_t ExecuteOnCreate(NativeRdb::RdbStore &rdbStore);

    /**
     * @brief Execute ON_UPGRADE handlers via each handler's crash-recovery lifecycle,
     *         short-circuiting on the first handler failure.
     */
    int32_t ExecuteOnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion);

    /**
     * @brief Execute ON_UPGRADE handlers via each handler's crash-recovery lifecycle
     *         (IRdbEventHandler::ExecuteUpgradeWithCrashRecovery) without short-circuiting.
     *
     * Per-handler crash recovery (migration mark counting, OnUpgradeFailure cleanup on
     * repeated crash interruption, and migration skip with old-format data when the
     * cleanup itself fails) is owned by IRdbEventHandler. This method only iterates
     * the registered handlers and aggregates the first business failure, so one
     * handler's failure never blocks the remaining handlers.
     */
    int32_t ExecuteOnUpgradeWithCrashRecovery(NativeRdb::RdbStore &rdbStore,
        int32_t oldVersion, int32_t newVersion);

    /** @brief Execute all enabled handlers registered for ON_DOWNGRADE. */
    int32_t ExecuteOnDowngrade(NativeRdb::RdbStore &rdbStore, int32_t currentVersion, int32_t targetVersion);

    /** @brief Execute all enabled handlers registered for ON_OPEN. */
    int32_t ExecuteOnOpen(NativeRdb::RdbStore &rdbStore);

    /** @brief Execute all enabled handlers registered for ON_CORRUPTION. */
    int32_t ExecuteOnCorruption(const std::string &databaseFile);

private:
    bool IsHandlerRegistered(const std::string &handlerName) const;

    int32_t ExecuteHandlerList(
        EventType eventType,
        const std::string &eventName,
        std::function<int32_t(std::shared_ptr<IRdbEventHandler>)> executeFunc) const;

private:

    /** Handler lists indexed by event type. */
    std::map<EventType, std::vector<std::shared_ptr<IRdbEventHandler>>> eventHandlers_;

    /** Protects eventHandlers_ and handler execution. */
    mutable ffrt::mutex managersLock_;
};
} // namespace Notification::Infra
} // namespace OHOS

#endif // ANS_NOTIFICATION_RDB_EVENT_HANDLER_MANAGER_H