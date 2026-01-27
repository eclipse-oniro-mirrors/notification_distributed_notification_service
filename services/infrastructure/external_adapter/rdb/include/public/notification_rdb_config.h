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

#ifndef ANS_NOTIFICATION_RDB_CONFIG_H
#define ANS_NOTIFICATION_RDB_CONFIG_H

#include <string>
#include "notification_rdb_constant.h"

namespace OHOS::Notification::Infra {
/**
 * @struct NotificationRdbConfig
 * @brief Configuration parameters for the notification RDB (Relational Database).
 *
 * This structure encapsulates all configuration settings required to initialize and manage
 * the notification relational database. It provides default values from NtfRdbConstant
 * and allows customization of database behavior.
 */
struct NotificationRdbConfig {
    /** Database file storage path. */
    std::string dbPath { NtfRdbConstant::NOTIFICATION_RDB_PATH };

    /** Database name used for RDB creation. */
    std::string dbName { NtfRdbConstant::NOTIFICATION_RDB_NAME };

    /** Default table name for notification storage. */
    std::string tableName { NtfRdbConstant::NOTIFICATION_RDB_TABLE_NAME };

    /** Journal mode for transaction handling (e.g., "DELETE", "WAL"). */
    std::string journalMode { NtfRdbConstant::NOTIFICATION_JOURNAL_MODE };

    /** Synchronization mode (e.g., "FULL", "NORMAL", "OFF"). */
    std::string syncMode { NtfRdbConstant::NOTIFICATION_SYNC_MODE };

    /** Database schema version number. Used for upgrade/downgrade management. */
    int32_t version { NtfRdbConstant::NOTIFICATION_RDB_VERSION };
};
} // namespace OHOS::Notification::Infra

#endif // ANS_NOTIFICATION_RDB_CONFIG_H