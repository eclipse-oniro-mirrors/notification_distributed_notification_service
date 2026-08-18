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

#include "priorityinfo_migration_handler.h"

#include "ans_log_wrapper.h"
#include "rdb_errno.h"
#include "rdb_store.h"
#include "rdb_predicates.h"

namespace OHOS::Notification::Infra {
const std::string PriorityInfoMigrationHandler::NOTIFICATION_KEY = "KEY";
const std::string PriorityInfoMigrationHandler::NOTIFICATION_VALUE = "VALUE";
const int32_t PriorityInfoMigrationHandler::NOTIFICATION_KEY_INDEX = 0;
const int32_t PriorityInfoMigrationHandler::NOTIFICATION_VALUE_INDEX = 1;
const std::string PriorityInfoMigrationHandler::PRIORITY_SWITCH_KEY = "priorityNotificationSwitch";
const std::string PriorityInfoMigrationHandler::PRIORITY_SWITCH_FOR_BUNDLE_KEY = "priorityNotificationSwitchForBundle";
const std::string PriorityInfoMigrationHandler::PRIORITY_INTELLIGENT_SWITCH_KEY = "priorityIntelligentSwitch";
const std::string
    PriorityInfoMigrationHandler::PRIORITY_SWITCH_FOR_BUNDLE_V2_KEY = "priorityNotificationSwitchForBundleV2";
const std::string PriorityInfoMigrationHandler::PRIORITY_STRATEGY_FOR_BUNDLE_KEY = "priorityStrategyForBundle";
const std::string PriorityInfoMigrationHandler::PRIORITY_SWITCH_DISABLED = "0";
const std::string PriorityInfoMigrationHandler::PRIORITY_SWITCH_ENABLED = "1";
const std::string PriorityInfoMigrationHandler::PRIORITY_SWITCH_ENABLED_ALL = "2";
const std::string PriorityInfoMigrationHandler::PRIORITY_SWITCH_STRATEGY_INTELLIGENT = "30";
const std::string PriorityInfoMigrationHandler::PRIORITY_SWITCH_STRATEGY_ALL = "32";
const int32_t PriorityInfoMigrationHandler::PRIORITY_LEGACY_VERSION = 2;

int32_t PriorityInfoMigrationHandler::OnUpgrade(
    NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion)
{
    ANS_LOGI("PriorityInfoMigrationHandler::OnUpgrade oldVersion: %{public}d, newVersion: %{public}d",
        oldVersion, newVersion);
    if (oldVersion == PRIORITY_LEGACY_VERSION) {
        std::set<std::string> tables = GetTableNames(rdbStore);
        if (tables.empty()) {
            ANS_LOGE("Query tableName failed.");
            return NativeRdb::E_OK;
        }

        for (const std::string &table : tables) {
            if (!ProcessTable(rdbStore, table)) {
                ANS_LOGW("No priority records in %{public}s", table.c_str());
            }
        }
    }
    return NativeRdb::E_OK;
}

void PriorityInfoMigrationHandler::OnUpgradeFailure(NativeRdb::RdbStore &rdbStore)
{
    ANS_LOGI("Cleaning up priority info data due to upgrade failure");
    std::set<std::string> tables = GetTableNames(rdbStore);
    if (tables.empty()) {
        return;
    }
    int32_t ret = rdbStore.BeginTransaction();
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("BeginTransaction failed, ret=%{public}d", ret);
        return;
    }
    for (const auto &tableName : tables) {
        NativeRdb::RdbPredicates predicates(tableName);
        predicates.BeginsWith(NOTIFICATION_KEY, PRIORITY_SWITCH_KEY)->Or()
            ->BeginsWith(NOTIFICATION_KEY, PRIORITY_INTELLIGENT_SWITCH_KEY)->Or()
            ->BeginsWith(NOTIFICATION_KEY, PRIORITY_STRATEGY_FOR_BUNDLE_KEY);
        int32_t deletedRows = 0;
        ret = rdbStore.Delete(deletedRows, predicates);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("Failed to delete priority data from %{public}s: %{public}d", tableName.c_str(), ret);
            rdbStore.RollBack();
            return;
        }
    }
    ret = rdbStore.Commit();
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("Commit failed, ret=%{public}d", ret);
        rdbStore.RollBack();
    }
}

std::string PriorityInfoMigrationHandler::GetHandlerName() const
{
    return "PriorityInfoMigrationHandler";
}

std::string PriorityInfoMigrationHandler::GetMigrationMarkKey() const
{
    return "upgrade_migration_mark_priority_info";
}

std::set<std::string> PriorityInfoMigrationHandler::GetTableNames(NativeRdb::RdbStore &rdbStore)
{
    std::set<std::string> tables;
    std::string queryTableSql = "SELECT name FROM sqlite_master WHERE type = 'table'";
    auto absSharedResultSet = rdbStore.QuerySql(queryTableSql);
    if (absSharedResultSet == nullptr) {
        ANS_LOGE("QuerySql failed.");
        return tables;
    }

    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("GoToFirstRow failed with ret: %{public}d.", ret);
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

bool PriorityInfoMigrationHandler::ProcessTable(
    NativeRdb::RdbStore &rdbStore, const std::string &tableName)
{
    ANS_LOGI("PriorityInfoMigrationHandler::ProcessTable tableName: %{public}s", tableName.c_str());
    auto absSharedResultSet = QueryTable(rdbStore, tableName);
    if (!absSharedResultSet) {
        return false;
    }

    bool result = ProcessResultSet(absSharedResultSet, rdbStore, tableName);
    if (!result) {
        ANS_LOGE("PriorityInfoMigrationHandler::ProcessTable tableName: %{public}s failed.", tableName.c_str());
    }
    absSharedResultSet->Close();
    return result;
}

std::shared_ptr<NativeRdb::AbsSharedResultSet> PriorityInfoMigrationHandler::QueryTable(
    NativeRdb::RdbStore &rdbStore, const std::string &tableName)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    absRdbPredicates.BeginsWith(NOTIFICATION_KEY, PRIORITY_SWITCH_KEY)->Or()
        ->EndsWith(NOTIFICATION_KEY, PRIORITY_SWITCH_FOR_BUNDLE_KEY);

    auto absSharedResultSet = rdbStore.Query(absRdbPredicates, std::vector<std::string>());
    if (!absSharedResultSet) {
        ANS_LOGE("QueryTable from %{public}s returned null (expected if no priority data)", tableName.c_str());
    }
    return absSharedResultSet;
}

bool PriorityInfoMigrationHandler::ProcessResultSet(
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

bool PriorityInfoMigrationHandler::ProcessRow(
    std::shared_ptr<NativeRdb::AbsSharedResultSet> absSharedResultSet,
    NativeRdb::RdbStore &rdbStore, const std::string &tableName)
{
    std::string resultKey;
    if (!GetStringFromResultSet(absSharedResultSet, NOTIFICATION_KEY_INDEX, resultKey)) {
        ANS_LOGE("Failed to get KEY from result set.");
        return false;
    }

    std::string resultValue;
    if (!GetStringFromResultSet(absSharedResultSet, NOTIFICATION_VALUE_INDEX, resultValue)) {
        ANS_LOGE("Failed to get VALUE from result set.");
        return false;
    }

    return onRdbUpgradePriorityMigrate(rdbStore, resultKey, resultValue, tableName);
}

bool PriorityInfoMigrationHandler::GetStringFromResultSet(
    std::shared_ptr<NativeRdb::AbsSharedResultSet> absSharedResultSet,
    int columnIndex, std::string &result)
{
    int32_t ret = absSharedResultSet->GetString(columnIndex, result);
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("GetString failed with ret: %{public}d.", ret);
        return false;
    }
    return true;
}

bool PriorityInfoMigrationHandler::onRdbUpgradePriorityMigrate(NativeRdb::RdbStore &rdbStore,
    const std::string &key, const std::string &val, const std::string &tableName)
{
    size_t suffixLen = PRIORITY_SWITCH_FOR_BUNDLE_KEY.length();
    if (key.length() >= suffixLen &&
        key.compare(key.length() - suffixLen, suffixLen, PRIORITY_SWITCH_FOR_BUNDLE_KEY) == 0) {
        std::string keyPrefix = key.substr(0, key.length() - suffixLen);
        std::string keyV2 = keyPrefix + PRIORITY_SWITCH_FOR_BUNDLE_V2_KEY;
        std::string keyStrategy = keyPrefix + PRIORITY_STRATEGY_FOR_BUNDLE_KEY;
        std::string valV2 = (val == PRIORITY_SWITCH_DISABLED) ? PRIORITY_SWITCH_DISABLED : PRIORITY_SWITCH_ENABLED;
        std::string valStrategy = (val == PRIORITY_SWITCH_ENABLED_ALL) ?
            PRIORITY_SWITCH_STRATEGY_ALL : PRIORITY_SWITCH_STRATEGY_INTELLIGENT;
        if (InsertToDatabase(rdbStore, keyV2, valV2, tableName) &&
            InsertToDatabase(rdbStore, keyStrategy, valStrategy, tableName)) {
            return true;
        }
        return false;
    }

    size_t prefixLen = PRIORITY_SWITCH_KEY.length();
    if (key.length() >= prefixLen &&
        key.compare(0, prefixLen, PRIORITY_SWITCH_KEY) == 0) {
        std::string keySuffix = key.substr(prefixLen);
        std::string intelligentKey = PRIORITY_INTELLIGENT_SWITCH_KEY + keySuffix;
        if (!InsertToDatabase(rdbStore, intelligentKey, val, tableName)) {
            return false;
        }
    }

    return true;
}

bool PriorityInfoMigrationHandler::InsertToDatabase(NativeRdb::RdbStore &rdbStore,
    const std::string& key, const std::string& val, const std::string& tableName)
{
    int64_t rowId = -1;
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(NOTIFICATION_KEY, key);
    valuesBucket.PutString(NOTIFICATION_VALUE, val);
    
    int32_t insertRet = rdbStore.InsertWithConflictResolution(rowId, tableName, valuesBucket,
        NativeRdb::ConflictResolution::ON_CONFLICT_IGNORE);
    if (insertRet != NativeRdb::E_OK) {
        ANS_LOGE("Insert failed with ret: %{public}d, key: %{public}s",  insertRet, key.c_str());
        return false;
    }
    
    ANS_LOGI("Inserted row with key: %{public}s, val:%{public}s table:%{public}s, rowId: %{public}" PRId64,
        key.c_str(), val.c_str(), tableName.c_str(), rowId);
    return true;
}
} // namespace OHOS::Notification::Infra
