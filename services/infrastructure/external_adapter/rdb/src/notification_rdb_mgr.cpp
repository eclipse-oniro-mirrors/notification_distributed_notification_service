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
#include "notification_rdb_mgr.h"

#include <sstream>
#include "ans_log_wrapper.h"
#include "rdb_store_wrapper.h"

namespace OHOS::Notification::Infra {
NotificationRdbMgr::NotificationRdbMgr(NotificationRdbConfig& config, const NtfRdbHook &hooks,
    const std::set<RdbEventHandlerType> &eventHandlerTypes)
{
    rdbStoreWrapper_ = std::make_shared<NtfRdbStoreWrapper>(config, hooks, eventHandlerTypes);
}

int32_t NotificationRdbMgr::Init()
{
    return rdbStoreWrapper_->Init();
}

int32_t NotificationRdbMgr::Destroy()
{
    return rdbStoreWrapper_->Destroy();
}

int32_t NotificationRdbMgr::InsertData(const std::string &key, const std::string &value, const int32_t &userId)
{
    return rdbStoreWrapper_->InsertData(key, value, userId);
}

int32_t NotificationRdbMgr::InsertData(const std::string &key, const std::vector<uint8_t> &value,
    const int32_t &userId)
{
    return rdbStoreWrapper_->InsertData(key, value, userId);
}

int32_t NotificationRdbMgr::InsertBatchData(const std::unordered_map<std::string, std::string> &values,
    const int32_t &userId)
{
    return rdbStoreWrapper_->InsertBatchData(values, userId);
}

int32_t NotificationRdbMgr::DeleteData(const std::string &key, const int32_t &userId)
{
    return rdbStoreWrapper_->DeleteData(key, userId);
}

int32_t NotificationRdbMgr::DeleteBatchData(const std::vector<std::string> &keys, const int32_t userId)
{
    return rdbStoreWrapper_->DeleteBatchData(keys, userId);
}

int32_t NotificationRdbMgr::QueryData(const std::string &key, std::string &value, const int32_t &userId)
{
    return rdbStoreWrapper_->QueryData(key, value, userId);
}

int32_t NotificationRdbMgr::QueryData(const std::string &key, std::vector<uint8_t> &value, const int32_t &userId)
{
    return rdbStoreWrapper_->QueryData(key, value, userId);
}

int32_t NotificationRdbMgr::QueryDataBeginWithKey(const std::string &key,
    std::unordered_map<std::string, std::string> &values, const int32_t &userId)
{
    return rdbStoreWrapper_->QueryDataBeginWithKey(key, values, userId);
}

int32_t NotificationRdbMgr::QueryDataContainsWithKey(const std::string &key,
    std::unordered_map<std::string, std::string> &values, const int32_t &userId)
{
    return rdbStoreWrapper_->QueryDataContainsWithKey(key, values, userId);
}

int32_t NotificationRdbMgr::QueryAllData(std::unordered_map<std::string, std::string> &values, const int32_t &userId)
{
    return rdbStoreWrapper_->QueryAllData(values, userId);
}

int32_t NotificationRdbMgr::DropUserTable(const int32_t userId)
{
    return rdbStoreWrapper_->DropUserTable(userId);
}
} // namespace OHOS::Notification::Infra