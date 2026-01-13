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
#include "ans_log_wrapper.h"
#include "rdb_store.h"

namespace OHOS::Notification::Infra {
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
    const auto& handlers = GetEventHandlers(EventType::ON_CREATE);
    return ExecuteHandlerList(handlers, "OnCreate", [&rdbStore](std::shared_ptr<IRdbEventHandler> handler) {
            return handler->OnCreate(rdbStore);
        });
}

int32_t RdbEventHandlerManager::ExecuteOnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion)
{
    const auto& handlers = GetEventHandlers(EventType::ON_UPGRADE);
    return ExecuteHandlerList(handlers, "OnUpgrade",
        [&rdbStore, oldVersion, newVersion](std::shared_ptr<IRdbEventHandler> handler) {
            return handler->OnUpgrade(rdbStore, oldVersion, newVersion);
        });
}

int32_t RdbEventHandlerManager::ExecuteOnDowngrade(
    NativeRdb::RdbStore &rdbStore, int32_t currentVersion, int32_t targetVersion)
{
    const auto& handlers = GetEventHandlers(EventType::ON_DOWNGRADE);
    return ExecuteHandlerList(handlers, "OnDowngrade",
        [&rdbStore, currentVersion, targetVersion](std::shared_ptr<IRdbEventHandler> handler) {
            return handler->OnDowngrade(rdbStore, currentVersion, targetVersion);
        });
}

int32_t RdbEventHandlerManager::ExecuteOnOpen(NativeRdb::RdbStore &rdbStore)
{
    const auto& handlers = GetEventHandlers(EventType::ON_OPEN);
    return ExecuteHandlerList(handlers, "OnOpen",
        [&rdbStore](std::shared_ptr<IRdbEventHandler> handler) {
            return handler->OnOpen(rdbStore);
        });
}

int32_t RdbEventHandlerManager::ExecuteOnCorruption(const std::string &databaseFile)
{
    const auto& handlers = GetEventHandlers(EventType::ON_CORRUPTION);
    return ExecuteHandlerList(handlers, "OnCorruption",
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

int32_t RdbEventHandlerManager::ExecuteHandlerList(const std::vector<std::shared_ptr<IRdbEventHandler>> &eventList,
    const std::string &eventName, std::function<int32_t(std::shared_ptr<IRdbEventHandler>)> executeFunc) const
{
    std::lock_guard<ffrt::mutex> lock(managersLock_);

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

const std::vector<std::shared_ptr<IRdbEventHandler>> RdbEventHandlerManager::GetEventHandlers(
    EventType eventType) const
{
    auto it = eventHandlers_.find(eventType);
    if (it != eventHandlers_.end()) {
        return it->second;
    }
    return {};
}
} // namespace OHOS::Notification::Infra