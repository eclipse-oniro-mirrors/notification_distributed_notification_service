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

#include "rdb_event_handler_manager.h"
#include <algorithm>
#include <cstdlib>
#include "ans_log_wrapper.h"
#include "notification_rdb_constant.h"
#include "rdb_predicates.h"
#include "rdb_store.h"

namespace OHOS::Notification::Infra {
namespace {
const std::string NOTIFICATION_KEY_COLUMN = "KEY";
const std::string NOTIFICATION_VALUE_COLUMN = "VALUE";

int32_t ReadCrashInterruptCount(NativeRdb::RdbStore &rdbStore, const std::string &markKey)
{
    NativeRdb::AbsRdbPredicates predicates(NtfRdbConstant::NOTIFICATION_RDB_TABLE_NAME);
    predicates.EqualTo(NOTIFICATION_KEY_COLUMN, markKey);
    auto resultSet = rdbStore.Query(predicates, std::vector<std::string>());
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        if (resultSet != nullptr) {
            resultSet->Close();
        }
        return 0;
    }
    std::string value;
    int32_t ret = resultSet->GetString(1, value);
    resultSet->Close();
    if (ret != NativeRdb::E_OK || value.empty()) {
        return 0;
    }
    int32_t count = static_cast<int32_t>(std::strtol(value.c_str(), nullptr, 10));
    return count < 0 ? 0 : count;
}

void WriteCrashInterruptCount(NativeRdb::RdbStore &rdbStore, const std::string &markKey, int32_t count)
{
    if (count <= 0) {
        NativeRdb::RdbPredicates predicates(NtfRdbConstant::NOTIFICATION_RDB_TABLE_NAME);
        predicates.EqualTo(NOTIFICATION_KEY_COLUMN, markKey);
        int32_t deletedRows = 0;
        int32_t deleteRet = rdbStore.Delete(deletedRows, predicates);
        if (deleteRet != NativeRdb::E_OK) {
            ANS_LOGE("Failed to clear migration mark, ret=%{public}d", deleteRet);
        }
        return;
    }

    int64_t rowId = -1;
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(NOTIFICATION_KEY_COLUMN, markKey);
    valuesBucket.PutString(NOTIFICATION_VALUE_COLUMN, std::to_string(count));
    int32_t insertRet = rdbStore.InsertWithConflictResolution(rowId,
        NtfRdbConstant::NOTIFICATION_RDB_TABLE_NAME, valuesBucket,
        NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    if (insertRet != NativeRdb::E_OK) {
        ANS_LOGE("Failed to set migration mark, ret=%{public}d", insertRet);
    }
}
} // namespace

bool RdbEventHandlerManager::RegisterHandler(EventType eventType, std::shared_ptr<IRdbEventHandler> handler)
{
    if (!handler) {
        ANS_LOGE("Handler is null");
        return false;
    }
    std::string handlerName = handler->GetHandlerName();
    std::lock_guard<ffrt::mutex> lock(managersLock_);
    // Check if handler already exists in any list
    if (IsHandlerRegistered(handlerName)) {
        ANS_LOGW("Handler %{public}s already registered", handlerName.c_str());
        return false;
    }
    // Add to the specific event list
    eventHandlers_[eventType].push_back(handler);
    return true;
}

bool RdbEventHandlerManager::UnregisterHandler(const std::string &handlerName)
{
    std::lock_guard<ffrt::mutex> lock(managersLock_);

    bool found = false;

    // Remove from all event lists
    for (auto& pair : eventHandlers_) {
        auto& handlers = pair.second;
        auto it = std::find_if(handlers.begin(), handlers.end(),
            [&handlerName](const std::shared_ptr<IRdbEventHandler> &handler) {
                return handler->GetHandlerName() == handlerName;
            });
        if (it != handlers.end()) {
            handlers.erase(it);
            found = true;
            break;
        }
    }

    if (found) {
        ANS_LOGD("Handler %{public}s unregistered", handlerName.c_str());
    } else {
        ANS_LOGW("Handler %{public}s not found", handlerName.c_str());
    }

    return found;
}

int32_t RdbEventHandlerManager::ExecuteOnCreate(NativeRdb::RdbStore &rdbStore)
{
    return ExecuteHandlerList(EventType::ON_CREATE, "OnCreate",
        [&rdbStore](std::shared_ptr<IRdbEventHandler> handler) {
            return handler->OnCreate(rdbStore);
        });
}

int32_t RdbEventHandlerManager::ExecuteOnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion)
{
    return ExecuteHandlerList(EventType::ON_UPGRADE, "OnUpgrade",
        [&rdbStore, oldVersion, newVersion](std::shared_ptr<IRdbEventHandler> handler) {
            return handler->OnUpgrade(rdbStore, oldVersion, newVersion);
        });
}

int32_t RdbEventHandlerManager::ExecuteOnUpgradeWithCrashRecovery(NativeRdb::RdbStore &rdbStore,
    int32_t oldVersion, int32_t newVersion)
{
    int32_t firstFailure = NativeRdb::E_OK;
    ExecuteHandlerList(EventType::ON_UPGRADE, "OnUpgradeWithCrashRecovery",
        [&rdbStore, oldVersion, newVersion, &firstFailure](std::shared_ptr<IRdbEventHandler> handler) {
            std::string markKey = handler->GetMigrationMarkKey();
            if (markKey.empty()) {
                int32_t ret = handler->OnUpgrade(rdbStore, oldVersion, newVersion);
                if (ret != NativeRdb::E_OK && firstFailure == NativeRdb::E_OK) {
                    firstFailure = ret;
                }
                return NativeRdb::E_OK;
            }

            int32_t crashCount = ReadCrashInterruptCount(rdbStore, markKey);
            if (crashCount > 0 && crashCount < NtfRdbConstant::NOTIFICATION_RDB_CRASH_CLEANUP_THRESHOLD) {
                ANS_LOGW("Handler %{public}s migration was crash-interrupted %{public}d time(s), retrying",
                    handler->GetHandlerName().c_str(), crashCount);
            } else if (crashCount >= NtfRdbConstant::NOTIFICATION_RDB_CRASH_CLEANUP_THRESHOLD) {
                ANS_LOGE("Handler %{public}s migration crash-interrupted %{public}d times, cleaning its data",
                    handler->GetHandlerName().c_str(), crashCount);
                handler->OnUpgradeFailure(rdbStore);
                crashCount = 0;
            }

            // Mark before migration: if the process crashes mid-migration, the residual
            // count on next boot is crashCount+1. Business failures never clean data;
            // only repeated crash interruption does.
            WriteCrashInterruptCount(rdbStore, markKey, crashCount + 1);
            int32_t ret = handler->OnUpgrade(rdbStore, oldVersion, newVersion);
            WriteCrashInterruptCount(rdbStore, markKey, 0);
            if (ret != NativeRdb::E_OK && firstFailure == NativeRdb::E_OK) {
                firstFailure = ret;
            }
            return NativeRdb::E_OK;
        });
    return firstFailure;
}

int32_t RdbEventHandlerManager::ExecuteOnDowngrade(
    NativeRdb::RdbStore &rdbStore, int32_t currentVersion, int32_t targetVersion)
{
    return ExecuteHandlerList(EventType::ON_DOWNGRADE, "OnDowngrade",
        [&rdbStore, currentVersion, targetVersion](std::shared_ptr<IRdbEventHandler> handler) {
            return handler->OnDowngrade(rdbStore, currentVersion, targetVersion);
        });
}

int32_t RdbEventHandlerManager::ExecuteOnOpen(NativeRdb::RdbStore &rdbStore)
{
    return ExecuteHandlerList(EventType::ON_OPEN, "OnOpen",
        [&rdbStore](std::shared_ptr<IRdbEventHandler> handler) {
            return handler->OnOpen(rdbStore);
        });
}

int32_t RdbEventHandlerManager::ExecuteOnCorruption(const std::string &databaseFile)
{
    return ExecuteHandlerList(EventType::ON_CORRUPTION, "OnCorruption",
        [&databaseFile](std::shared_ptr<IRdbEventHandler> handler) {
            return handler->OnCorruption(databaseFile);
        });
}

bool RdbEventHandlerManager::IsHandlerRegistered(const std::string &handlerName) const
{
    for (const auto& pair : eventHandlers_) {
        const auto& handlers = pair.second;
        auto it = std::find_if(handlers.begin(), handlers.end(),
            [&handlerName](const std::shared_ptr<IRdbEventHandler> &handler) {
                return handler->GetHandlerName() == handlerName;
            });
        if (it != handlers.end()) {
            return true;
        }
    }
    return false;
}

int32_t RdbEventHandlerManager::ExecuteHandlerList(EventType eventType,
    const std::string &eventName, std::function<int32_t(std::shared_ptr<IRdbEventHandler>)> executeFunc) const
{
    std::lock_guard<ffrt::mutex> lock(managersLock_);

    auto it = eventHandlers_.find(eventType);
    if (it == eventHandlers_.end()) {
        return NativeRdb::E_OK;
    }
    const auto &eventList = it->second;

    ANS_LOGD("Executing %{public}zu handlers for event %{public}s", eventList.size(), eventName.c_str());

    for (const auto &handler : eventList) {
        if (!handler->IsEnabled()) {
            ANS_LOGD("Handler %{public}s is disabled for %{public}s event",
                     handler->GetHandlerName().c_str(), eventName.c_str());
            continue;
        }

        int32_t ret = executeFunc(handler);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("Handler %{public}s failed for %{public}s event with ret: %{public}d",
                     handler->GetHandlerName().c_str(), eventName.c_str(), ret);
            return ret;
        }

        ANS_LOGD("Handler %{public}s executed successfully for %{public}s event",
                 handler->GetHandlerName().c_str(), eventName.c_str());
    }

    return NativeRdb::E_OK;
}
} // namespace OHOS::Notification::Infra