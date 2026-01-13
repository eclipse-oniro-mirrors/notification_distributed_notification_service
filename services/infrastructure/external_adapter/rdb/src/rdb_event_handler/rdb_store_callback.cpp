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

#include "rdb_store_callback.h"
#include "ans_log_wrapper.h"
#include "init_default_table_handler.h"
#include "live_view_migration_handler.h"
#include "rdb_store.h"

namespace OHOS::Notification::Infra {
RdbStoreCallback::RdbStoreCallback(const NotificationRdbConfig& config, std::shared_ptr<NtfRdbHookMgr> hookMgr,
    const std::set<RdbEventHandlerType> &eventHandlerTypes)
{
    ANS_LOGD("Create rdb store callback instance");
    InitializeHandlers(config, hookMgr, eventHandlerTypes);
}

RdbStoreCallback::~RdbStoreCallback()
{
    ANS_LOGD("Destroy rdb store callback instance");
}

int32_t RdbStoreCallback::OnCreate(NativeRdb::RdbStore &rdbStore)
{
    ANS_LOGD("RdbStoreCallback::OnCreate");
    return handlerManager_.ExecuteOnCreate(rdbStore);
}

int32_t RdbStoreCallback::OnUpgrade(
    NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion)
{
    ANS_LOGD("RdbStoreCallback::OnUpgrade oldVersion: %{public}d, newVersion: %{public}d",
        oldVersion, newVersion);
    return handlerManager_.ExecuteOnUpgrade(rdbStore, oldVersion, newVersion);
}

int32_t RdbStoreCallback::OnDowngrade(
    NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion)
{
    ANS_LOGD("RdbStoreCallback::OnDowngrade currentVersion: %{public}d, targetVersion: %{public}d",
        currentVersion, targetVersion);
    return handlerManager_.ExecuteOnDowngrade(rdbStore, currentVersion, targetVersion);
}

int32_t RdbStoreCallback::OnOpen(NativeRdb::RdbStore &rdbStore)
{
    ANS_LOGD("RdbStoreCallback::OnOpen");
    return handlerManager_.ExecuteOnOpen(rdbStore);
}

int32_t RdbStoreCallback::onCorruption(std::string databaseFile)
{
    ANS_LOGD("RdbStoreCallback::onCorruption databaseFile: %{public}s", databaseFile.c_str());
    return handlerManager_.ExecuteOnCorruption(databaseFile);
}

void RdbStoreCallback::InitializeHandlers(const NotificationRdbConfig& config, std::shared_ptr<NtfRdbHookMgr> hookMgr,
    const std::set<RdbEventHandlerType> &eventHandlerTypes)
{
    for (const auto& type : eventHandlerTypes) {
        switch (type) {
            case RdbEventHandlerType::ON_CREATE_INIT_DEFAULT_TABLE: {
                auto initDefaultTableHandler = std::make_shared<InitDefaultTableHandler>(config);
                handlerManager_.RegisterHandler(RdbEventHandlerManager::EventType::ON_CREATE, initDefaultTableHandler);
                break;
            }
            case RdbEventHandlerType::ON_UPGRADE_LIVE_VIEW_MIGRATION: {
                auto liveViewMigrationHandler = std::make_shared<LiveViewMigrationHandler>(hookMgr);
                handlerManager_.RegisterHandler(
                    RdbEventHandlerManager::EventType::ON_UPGRADE, liveViewMigrationHandler);
                break;
            }
            default: {
                ANS_LOGW("RdbStoreCallback::InitializeDefaultHandlers unknown handler type");
                break;
            }
        }
    }
}
} // namespace OHOS::Notification::Infra