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

#include "live_view_migration_handler.h"

#include "ans_log_wrapper.h"
#include "rdb_errno.h"
#include "rdb_store.h"
#include "rdb_predicates.h"

namespace OHOS::Notification::Infra {
const std::string LiveViewMigrationHandler::NOTIFICATION_KEY = "KEY";
const std::string LiveViewMigrationHandler::NOTIFICATION_VALUE = "VALUE";
const int32_t LiveViewMigrationHandler::NOTIFICATION_KEY_INDEX = 0;
const int32_t LiveViewMigrationHandler::NOTIFICATION_VALUE_INDEX = 1;
const std::string LiveViewMigrationHandler::LIVE_VIEW_KEY = "secure_live_view";

int32_t LiveViewMigrationHandler::OnUpgrade(
    NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion)
{
    ANS_LOGD("LiveViewMigrationHandler::OnUpgrade oldVersion: %{public}d, newVersion: %{public}d",
        oldVersion, newVersion);

    if (oldVersion == 1) {
        std::set<std::string> tables = GetTableNames(rdbStore);
        if (tables.empty()) {
            ANS_LOGE("Query tableName failed");
            return NativeRdb::E_OK;
        }

        for (const std::string &tableName : tables) {
            if (!ProcessTable(rdbStore, tableName)) {
                ANS_LOGW("No liveview in %{public}s", tableName.c_str());
            }
        }
    }

    return NativeRdb::E_OK;
}

std::string LiveViewMigrationHandler::GetHandlerName() const
{
    return "LiveViewMigrationHandler";
}

std::set<std::string> LiveViewMigrationHandler::GetTableNames(NativeRdb::RdbStore &rdbStore)
{
    std::set<std::string> tables;
    std::string queryTableSql = "SELECT name FROM sqlite_master WHERE type='table'";
    auto absSharedResultSet = rdbStore.QuerySql(queryTableSql);
    if (absSharedResultSet == nullptr) {
        ANS_LOGE("QuerySql failed");
        return tables;
    }

    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("GoToFirstRow failed with ret: %{public}d", ret);
        return tables;
    }

    do {
        std::string tableName;
        ret = absSharedResultSet->GetString(0, tableName);
        if (ret == NativeRdb::E_OK) {
            tables.insert(tableName);
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);

    return tables;
}

bool LiveViewMigrationHandler::ProcessTable(
    NativeRdb::RdbStore &rdbStore, const std::string &tableName)
{
    ANS_LOGD("LiveViewMigrationHandler::ProcessTable tableName: %{public}s", tableName.c_str());

    auto absSharedResultSet = QueryTable(rdbStore, tableName);
    if (!absSharedResultSet) {
        return false;
    }

    bool result = ProcessResultSet(absSharedResultSet, rdbStore, tableName);
    absSharedResultSet->Close();
    return result;
}

std::shared_ptr<NativeRdb::AbsSharedResultSet> LiveViewMigrationHandler::QueryTable(
    NativeRdb::RdbStore &rdbStore, const std::string &tableName)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    absRdbPredicates.BeginsWith(NOTIFICATION_KEY, LIVE_VIEW_KEY);
    auto absSharedResultSet = rdbStore.Query(absRdbPredicates, std::vector<std::string>());
    if (!absSharedResultSet) {
        ANS_LOGE("QueryTable from %{public}s returned null (expected if no liveview data)", tableName.c_str());
    }
    return absSharedResultSet;
}

bool LiveViewMigrationHandler::ProcessResultSet(
    std::shared_ptr<NativeRdb::AbsSharedResultSet> absSharedResultSet,
    NativeRdb::RdbStore &rdbStore, const std::string &tableName)
{
    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        ANS_LOGD("No rows to process in %{public}s", tableName.c_str());
        return false;
    }

    do {
        if (!ProcessRow(absSharedResultSet, rdbStore, tableName)) {
            return false;
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);

    return true;
}

bool LiveViewMigrationHandler::ProcessRow(
    std::shared_ptr<NativeRdb::AbsSharedResultSet> absSharedResultSet,
    NativeRdb::RdbStore &rdbStore, const std::string &tableName)
{
    ANS_LOGD("LiveViewMigrationHandler::ProcessRow");

    std::string resultKey;
    if (!GetStringFromResultSet(absSharedResultSet, NOTIFICATION_KEY_INDEX, resultKey)) {
        ANS_LOGE("Failed to get KEY from result set");
        return false;
    }

    std::string resultValue;
    if (!GetStringFromResultSet(absSharedResultSet, NOTIFICATION_VALUE_INDEX, resultValue)) {
        ANS_LOGE("Failed to get VALUE from result set");
        return false;
    }

    std::string encryptValue;
    bool ret = hookMgr_->OnRdbUpgradeLiveviewMigrate(resultValue, encryptValue);
    if (ret) {
        int64_t rowId = -1;
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(NOTIFICATION_KEY, resultKey);
        valuesBucket.PutString(NOTIFICATION_VALUE, encryptValue);
        int32_t insertRet = rdbStore.InsertWithConflictResolution(rowId, tableName, valuesBucket,
            NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
        if (insertRet != NativeRdb::E_OK) {
            ANS_LOGE("Insert failed with ret: %{public}d", insertRet);
            return false;
        }

        ANS_LOGD("Updated liveview row with key: %{public}s", resultKey.c_str());
    } else {
        ANS_LOGE("UpdateRequestJsonObject failed.");
    }
    return ret;
}

bool LiveViewMigrationHandler::GetStringFromResultSet(
    std::shared_ptr<NativeRdb::AbsSharedResultSet> absSharedResultSet,
    int columnIndex, std::string &result)
{
    int32_t ret = absSharedResultSet->GetString(columnIndex, result);
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("GetString failed with ret: %{public}d", ret);
        return false;
    }
    return true;
}
} // namespace OHOS::Notification::Infra