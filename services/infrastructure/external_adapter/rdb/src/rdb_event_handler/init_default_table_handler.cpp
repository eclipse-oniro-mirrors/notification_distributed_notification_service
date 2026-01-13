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

#include "init_default_table_handler.h"
#include "ans_log_wrapper.h"
#include "rdb_errno.h"
#include "rdb_store.h"

namespace OHOS::Notification::Infra {
InitDefaultTableHandler::InitDefaultTableHandler(const NotificationRdbConfig &config)
    : config_(config)
{
    ANS_LOGD("InitDefaultTableHandler created");
}

int32_t InitDefaultTableHandler::OnCreate(NativeRdb::RdbStore &rdbStore)
{
    ANS_LOGD("InitDefaultTableHandler::OnCreate");

    int32_t ret = NativeRdb::E_OK;
    if (tableInitialized_) {
        return ret;
    }

    std::string createTableSql = "CREATE TABLE IF NOT EXISTS " + config_.tableName
        + " (KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL);";

    ret = rdbStore.ExecuteSql(createTableSql);
    if (ret == NativeRdb::E_OK) {
        tableInitialized_ = true;
        ANS_LOGD("Create table %{public}s succeed", config_.tableName.c_str());
    } else {
        ANS_LOGE("Create table %{public}s failed with ret: %{public}d",
            config_.tableName.c_str(), ret);
    }

    return ret;
}

std::string InitDefaultTableHandler::GetHandlerName() const
{
    return "InitDefaultTableHandler";
}
} // namespace OHOS::Notification::Infra