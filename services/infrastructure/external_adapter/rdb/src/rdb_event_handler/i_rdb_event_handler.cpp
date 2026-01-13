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

#include "i_rdb_event_handler.h"
#include "rdb_errno.h"

namespace OHOS::Notification::Infra {
int32_t IRdbEventHandler::OnCreate(NativeRdb::RdbStore &rdbStore)
{
    return NativeRdb::E_OK;
}

int32_t IRdbEventHandler::OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion)
{
    return NativeRdb::E_OK;
}

int32_t IRdbEventHandler::OnDowngrade(NativeRdb::RdbStore &rdbStore, int32_t currentVersion, int32_t targetVersion)
{
    return NativeRdb::E_OK;
}

int32_t IRdbEventHandler::OnOpen(NativeRdb::RdbStore &rdbStore)
{
    return NativeRdb::E_OK;
}

int32_t IRdbEventHandler::OnCorruption(const std::string &databaseFile)
{
    return NativeRdb::E_OK;
}

bool IRdbEventHandler::IsEnabled() const
{
    return enabled_;
}

void IRdbEventHandler::SetEnabled(bool enabled)
{
    enabled_ = enabled;
}
} // namespace OHOS::Notification::Infra