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

#ifndef ANS_NOTIFICATION_RDB_EVENT_CALLBACK_MGR_H
#define ANS_NOTIFICATION_RDB_EVENT_CALLBACK_MGR_H

#include <cstdint>
#include <string>
#include "notification_rdb_hook.h"

namespace OHOS::Notification::Infra {
/**
 * @class NtfRdbHookMgr
 * @brief Thin wrapper around NtfRdbHook callbacks.
 *
 * Owns a copy of the hook set and provides null-checking wrappers so callers can invoke hooks
 * without repeating boilerplate.
 *
 * Note: This class does not serialize access to the callbacks. Thread-safety depends on the
 * provided hook implementations.
 */
class NtfRdbHookMgr {
public:
    /**
     * @brief Create a hook manager from a hook set.
     *
     * @param hooks Hook callbacks (each member may be nullptr).
     */
    NtfRdbHookMgr(const NtfRdbHook &hooks) : hooks_(hooks) {};

    ~NtfRdbHookMgr() = default;

    /**
     * @brief Invoke OnRdbUpgradeLiveviewMigrate callback for data migration.
     *
     * Calls the registered live view migration callback if available.
     *
     * @param oldValue The original value before upgrade.
     * @param newValue Output parameter for the migrated value.
     * @return true if callback executed successfully, false if not registered or failed.
     */
    bool OnRdbUpgradeLiveviewMigrate(const std::string &oldValue, std::string &newValue);

    /**
     * @brief Invoke OnRdbOperationFailReport callback for error reporting.
     *
     * Calls the registered operation failure report callback if available.
     *
     * @param sceneId Application scenario identifier.
     * @param branchId Branch/sub-scenario identifier.
     * @param errCode The error code from the failed operation.
     * @param errMsg Human-readable error message.
     * @return true if callback executed successfully.
     */
    bool OnRdbOperationFailReport(const int32_t sceneId, const int32_t branchId,
        const int32_t errCode, const std::string &errMsg);

    /**
     * @brief Invoke OnSendUserDataSizeHisysevent callback for metrics reporting.
     *
     * Calls the registered data size statistics callback if available.
     *
     * @return true if callback executed successfully.
     */
    bool OnSendUserDataSizeHisysevent();
private:
    /** Container for all registered callbacks. */
    NtfRdbHook hooks_;
};
} // namespace OHOS::Notification::Infra

#endif // ANS_NOTIFICATION_RDB_EVENT_CALLBACK_MGR_H