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

#ifndef ANS_DOMAIN_SETTINGS_NOTIFICATION_RDB_HOOKS_H
#define ANS_DOMAIN_SETTINGS_NOTIFICATION_RDB_HOOKS_H

#include <cstdint>
#include <string>

namespace OHOS::Notification::Domain {
/**
 * @brief Callback for handling RDB live view data migration during upgrade.
 *
 * Invoked during database upgrade to allow data migration/transformation.
 * The callback should implement the migration logic and return the migrated value.
 *
 * @param oldValue The original value from the database before upgrade.
 * @param newValue Output parameter containing the migrated/transformed value.
 * @return true if migration succeeded and newValue is valid,
 *         false if migration failed or should be skipped.
 */
bool OnRdbUpgradeLiveviewMigrate(const std::string &oldValue, std::string &newValue);

/**
 * @brief Callback for reporting RDB operation failures for logging/metrics.
 *
 * Invoked when database operations fail to allow error reporting and diagnostics.
 * Typically used to log errors to system event services (report system).
 *
 * @param sceneId Application context/scenario identifier (for categorizing errors).
 * @param branchId Sub-scenario identifier within the scene (for granular tracking).
 * @param errCode The error code returned by the failed database operation.
 * @param errMsg Human-readable error message describing what failed.
 */
void OnRdbOperationFailReport(const int32_t sceneId, const int32_t branchId,
    const int32_t errCode, const std::string &errMsg);

/**
 * @brief Callback for sending user data size statistics event.
 *
 * Invoked periodically or on-demand to report user notification data size
 * metrics to the system event service for monitoring and analytics.
 *
 * Implementation should calculate and report statistics like:
 * - Total database size
 * - Average record size
 * - Number of active users
 * - Data by user breakdown
 *
 * @note This is typically called for metrics collection and system health monitoring.
 */
void OnSendUserDataSizeHisysevent();
} // namespace OHOS::Notification::Domain

#endif // #define ANS_DOMAIN_SETTINGS_NOTIFICATION_RDB_HOOKS_H