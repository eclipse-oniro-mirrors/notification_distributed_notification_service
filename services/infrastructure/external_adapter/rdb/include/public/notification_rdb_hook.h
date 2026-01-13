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

#ifndef ANS_NOTIFICATION_RDB_HOOK_H
#define ANS_NOTIFICATION_RDB_HOOK_H

#include <functional>
#include <string>

namespace OHOS::Notification::Infra {
/**
 * @struct NtfRdbHook
 * @brief Callback set used by the notification RDB adapter.
 *
 * All callbacks are optional (may be nullptr). Implementations should be fast and avoid
 * blocking, because they are invoked from database paths.
 */
struct NtfRdbHook {
    /**
    * @brief Transform a live view record value during database upgrade.
     *
     * @param oldValue The original value from the database before upgrade.
     * @param newValue Output parameter containing the migrated/transformed value.
    * @return true if migration succeeded and newValue is valid; otherwise false.
     */
    std::function<bool(const std::string &, std::string &)> OnRdbUpgradeLiveviewMigrate {nullptr};

    /**
     * @brief Report an RDB operation failure for logging/metrics.
     *
     * @param sceneId Application context/scenario identifier (for categorizing errors).
     * @param branchId Sub-scenario identifier within the scene (for granular tracking).
     * @param errCode The error code returned by the failed database operation.
     * @param errMsg Human-readable error message describing what failed.
     */
    std::function<void(const int32_t, const int32_t,
        const int32_t, const std::string &)> OnRdbOperationFailReport {nullptr};

    /**
     * @brief Report user data size statistics to HiSysEvent.
     *
     * The adapter calls this after successful insert operations to keep size metrics updated.
     */
    std::function<void()> OnSendUserDataSizeHisysevent {nullptr};
};
} // namespace OHOS::Notification::Infra

#endif // #define ANS_NOTIFICATION_RDB_HOOK_H