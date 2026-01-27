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

#ifndef ANS_NOTIFICATION_RDB_STORE_CALLBACK_H
#define ANS_NOTIFICATION_RDB_STORE_CALLBACK_H

#include <string>
#include <memory>

#include "notification_rdb_config.h"
#include "notification_rdb_hook_mgr.h"
#include "notification_rdb_event_handler_type.h"
#include "rdb_event_handler_manager.h"
#include "rdb_open_callback.h"


namespace OHOS {
namespace NativeRdb {
class RdbStore;
} // namespace NativeRdb
namespace Notification::Infra {

/**
 * @class RdbStoreCallback
 * @brief NativeRdb open callback that dispatches events to registered IRdbEventHandler objects.
 *
 * The constructor registers handlers based on the provided RdbEventHandlerType set.
 */
class RdbStoreCallback : public NativeRdb::RdbOpenCallback {
public:
    /**
     * @brief Construct the callback dispatcher.
     * @param config Database configuration used by some handlers.
     * @param hookMgr Hook manager used by some handlers (e.g., upgrade migration).
     * @param eventHandlerTypes Enabled handler types.
     */
    explicit RdbStoreCallback(const NotificationRdbConfig& config, std::shared_ptr<NtfRdbHookMgr> hookMgr,
        const std::set<RdbEventHandlerType> &eventHandlerTypes);

    virtual ~RdbStoreCallback();

    /** @brief Dispatch the create event to registered handlers. */
    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;

    /** @brief Dispatch the upgrade event to registered handlers. */
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion) override;

    /** @brief Dispatch the downgrade event to registered handlers. */
    int32_t OnDowngrade(NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion) override;

    /** @brief Dispatch the open event to registered handlers. */
    int32_t OnOpen(NativeRdb::RdbStore &rdbStore) override;

    /** @brief Dispatch the corruption event to registered handlers. */
    int32_t onCorruption(std::string databaseFile) override;

    /**
     * @brief Register built-in handlers according to eventHandlerTypes.
     *
     * This method can be called again to reinitialize the manager with a new handler set.
     */
    void InitializeHandlers(const NotificationRdbConfig& config, std::shared_ptr<NtfRdbHookMgr> hookMgr,
        const std::set<RdbEventHandlerType> &eventHandlerTypes);

private:
    /** Manages and executes handler lists for each event. */
    RdbEventHandlerManager handlerManager_;
};
} // namespace Notification::Infra
} // namespace OHOS

#endif // ANS_NOTIFICATION_RDB_STORE_CALLBACK_H