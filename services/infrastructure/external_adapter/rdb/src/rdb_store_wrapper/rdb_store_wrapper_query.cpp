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
#include "rdb_store_wrapper.h"

#include "ans_log_wrapper.h"
#include "rdb_errno.h"
#include "rdb_store.h"

namespace OHOS::Notification::Infra {
namespace {
const std::string NOTIFICATION_KEY = "KEY";
const int32_t NOTIFICATION_KEY_INDEX = 0;
const int32_t NOTIFICATION_VALUE_INDEX = 1;
const int64_t LAST_DAY_MS = 7 * 24 * 60 * 60 * 1000;
}

template<typename Func>
int32_t NtfRdbStoreWrapper::QueryMultiTablesWithErrorHandling(
    const int32_t userId,
    Func queryFunc,
    bool isSingleValueMode)
{
    if (isRecovering_.load()) {
        ANS_LOGD("The db is being repaired.");
        return NativeRdb::E_ERROR;
    }

    auto operatedTables = GenerateOperatedTables(userId);
    int32_t ret = NativeRdb::E_OK;

    for (auto tableName : operatedTables) {
        ret = queryFunc(tableName);
        if (ret == NativeRdb::E_SQLITE_CORRUPT) {
            int32_t restoreRet = RestoreForMasterSlaver();
            if (restoreRet == NativeRdb::E_SQLITE_CORRUPT) {
                RecoverDatabase();
            }
            return NativeRdb::E_ERROR;
        }

        if (isSingleValueMode) {
            if (ret != NativeRdb::E_EMPTY_VALUES_BUCKET) {
                return ret;
            }
        } else {
            if (ret == NativeRdb::E_ERROR) {
                return ret;
            }
        }
    }
    return ret;
}

int32_t NtfRdbStoreWrapper::GetStatisticsInfos(const int64_t lastTimeMs,
    const int32_t bundleUid, const std::string &tableName, int32_t &totalCount, int64_t &lastTime)
{
    std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
    std::string querySql =
        "SELECT COUNT(*) as total_count, MAX(notificationTime) as max_timestamp "
        "FROM " + tableName + " "
        "WHERE "
        "uid = " + std::to_string(bundleUid) + " "
        "AND notificationTime >= " +  std::to_string(lastTimeMs) + ";";
    std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = nullptr;
    resultSet = rdbStore_->QuerySql(querySql);
    if (resultSet == nullptr) {
        ANS_LOGE("SELECT * fail resultSet is nullptr");
        return NativeRdb::E_ERROR;
    }

    if (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t columnIndex;
        if (resultSet->GetColumnIndex("total_count", columnIndex) == NativeRdb::E_OK) {
            if (resultSet->GetInt(columnIndex, totalCount) != NativeRdb::E_OK) {
                ANS_LOGW("failed to get total_count value");
            }
        }
        if (resultSet->GetColumnIndex("max_timestamp", columnIndex) == NativeRdb::E_OK) {
            if (resultSet->GetLong(columnIndex, lastTime) != NativeRdb::E_OK) {
                ANS_LOGW("failed to get max_timestamp value");
            }
        }
    }
    resultSet->Close();
    ANS_LOGD("NtfRdbStoreWrapper::GetStatisticsInfos: %{public}s", tableName.c_str());
    return NativeRdb::E_OK;
}

int32_t NtfRdbStoreWrapper::QueryStatisticsInfosByBundle(const int32_t bundleUid, const int32_t userId,
    const int64_t beginTime, int32_t &totalCount, int64_t &lastTime)
{
    if (rdbStore_ == nullptr) {
        ANS_LOGE("NtfRdbStoreWrapper rdbStore_ is null");
        return NativeRdb::E_ERROR;
    }

    std::string tableName = NOTIFICATION_STATISTICS_TABLENAME + "_" + std::to_string(userId);
    int32_t reuslt = GetStatisticsInfos(beginTime, bundleUid, tableName, totalCount, lastTime);

    ANS_LOGD("QueryStatisticsInfosByBundle reuslt: %{public}d", reuslt);
    return reuslt;
}

int32_t NtfRdbStoreWrapper::UpdateStatisticsTimeStamp(const int32_t userId, int64_t offsetMs)
{
    if (rdbStore_ == nullptr) {
        ANS_LOGE("NtfRdbStoreWrapper rdbStore_ is null");
        return NativeRdb::E_ERROR;
    }

    int updatedRows = -1;
    std::string tableName = NOTIFICATION_STATISTICS_TABLENAME + "_" + std::to_string(userId);
    std::string updateSqlStr = "UPDATE " + tableName + " SET notificationTime = notificationTime + ?";
    std::vector<NativeRdb::ValueObject> bindArgs;
    NativeRdb::ValueObject value(offsetMs);
    bindArgs.push_back(value);

    int ret = rdbStore_->ExecuteSql(updateSqlStr, bindArgs);
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("rdbStore_ ExecuteSql update notificationTime fail: %{public}d", ret);
        return NativeRdb::E_ERROR;
    }

    return NativeRdb::E_OK;
}

int32_t NtfRdbStoreWrapper::QueryData(const std::string &key, std::string &value, const int32_t &userId)
{
    ANS_LOGD("QueryData start");
    auto queryFunc = [this, &key, &value](const std::string& tableName) {
        return this->QueryData(tableName, key, value);
    };
    return QueryMultiTablesWithErrorHandling(userId, queryFunc, true);
}

int32_t NtfRdbStoreWrapper::QueryData(const std::string &key, std::vector<uint8_t> &values, const int32_t &userId)
{
    ANS_LOGD("QueryData start");
    auto queryFunc = [this, &key, &values](const std::string& tableName) {
        return this->QueryData(tableName, key, values);
    };
    return QueryMultiTablesWithErrorHandling(userId, queryFunc, true);
}

int32_t NtfRdbStoreWrapper::QueryDataBeginWithKey(
    const std::string &key, std::unordered_map<std::string, std::string> &values, const int32_t &userId)
{
    ANS_LOGD("QueryData BeginWithKey start");
    auto queryFunc = [this, &key, &values](const std::string& tableName) {
        return this->QueryDataBeginWithKey(tableName, key, values);
    };
    int32_t ret = QueryMultiTablesWithErrorHandling(userId, queryFunc, false);
    if (ret == NativeRdb::E_EMPTY_VALUES_BUCKET && values.empty()) {
        return NativeRdb::E_EMPTY_VALUES_BUCKET;
    }
    return ret == NativeRdb::E_ERROR ? ret : NativeRdb::E_OK;
}

int32_t NtfRdbStoreWrapper::QueryDataContainsWithKey(
    const std::string &key, std::unordered_map<std::string, std::string> &values, const int32_t &userId)
{
    ANS_LOGD("QueryDataContainsWithKey start");
    auto queryFunc = [this, &key, &values](const std::string& tableName) {
        return this->QueryDataContainsWithKey(tableName, key, values);
    };
    int32_t ret = QueryMultiTablesWithErrorHandling(userId, queryFunc, false);
    if (ret == NativeRdb::E_EMPTY_VALUES_BUCKET && values.empty()) {
        return NativeRdb::E_EMPTY_VALUES_BUCKET;
    }
    return ret == NativeRdb::E_ERROR ? ret : NativeRdb::E_OK;
}


int32_t NtfRdbStoreWrapper::QueryAllData(std::unordered_map<std::string, std::string> &datas, const int32_t &userId)
{
    ANS_LOGD("QueryAllData start");
    auto queryFunc = [this, &datas](const std::string& tableName) {
        return this->QueryAllData(tableName, datas);
    };
    int32_t ret = QueryMultiTablesWithErrorHandling(userId, queryFunc, false);
    if (ret == NativeRdb::E_EMPTY_VALUES_BUCKET && datas.empty()) {
        return NativeRdb::E_EMPTY_VALUES_BUCKET;
    }
    return ret == NativeRdb::E_OK ? NativeRdb::E_OK : ret;
}

int32_t NtfRdbStoreWrapper::ExecuteQuery(const std::string& tableName, NativeRdb::AbsRdbPredicates& predicates,
    std::shared_ptr<NativeRdb::AbsSharedResultSet>& resultSet)
{
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }
        resultSet = rdbStore_->Query(predicates, std::vector<std::string>());
    }

    if (resultSet == nullptr) {
        ANS_LOGE("absSharedResultSet failed from %{public}s table.", tableName.c_str());
        return NativeRdb::E_ERROR;
    }

    return NativeRdb::E_OK;
}

int32_t NtfRdbStoreWrapper::CheckFirstRow(std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet,
    const std::string& tableName, const std::string& key, int32_t sceneId, int32_t branchId)
{
    int32_t ret = resultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        ANS_LOGD("GoToFirstRow failed from %{public}s table. It is empty!, key=%{public}s",
            tableName.c_str(), key.c_str());
        if (ret != NativeRdb::E_ROW_OUT_RANGE) {
            ANS_LOGD("GoToFirstRow failed, rdb error is %{public}d.", ret);
            hookMgr_->OnRdbOperationFailReport(sceneId, branchId, ret, "GoToFirstRow failed");
        }
        resultSet->Close();
        return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_EMPTY_VALUES_BUCKET;
    }

    return NativeRdb::E_OK;
}

int32_t NtfRdbStoreWrapper::ExtractStringValue(std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet,
    const std::string& tableName, std::string& value, int32_t sceneId, int32_t branchId)
{
    int32_t ret = resultSet->GetString(NOTIFICATION_VALUE_INDEX, value);
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("GetString value failed from %{public}s table.", tableName.c_str());
        hookMgr_->OnRdbOperationFailReport(sceneId, branchId, ret, "GetString value failed");
        resultSet->Close();
        return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_ERROR;
    }

    resultSet->Close();
    return NativeRdb::E_OK;
}

int32_t NtfRdbStoreWrapper::ExtractBlobValue(std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet,
    const std::string& tableName, std::vector<uint8_t>& value, int32_t sceneId, int32_t branchId)
{
    int32_t ret = resultSet->GetBlob(NOTIFICATION_VALUE_INDEX, value);
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("GetString value failed from %{public}s table.", tableName.c_str());
        hookMgr_->OnRdbOperationFailReport(sceneId, branchId, ret, "GetString value failed");
        resultSet->Close();
        return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_ERROR;
    }

    resultSet->Close();
    return NativeRdb::E_OK;
}

int32_t NtfRdbStoreWrapper::ExtractMapValues(std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet,
    const std::string& tableName, std::unordered_map<std::string, std::string>& values,
    int32_t sceneId, int32_t branchId)
{
    do {
        std::string resultKey;
        int32_t ret = resultSet->GetString(NOTIFICATION_KEY_INDEX, resultKey);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("Failed to GetString key from %{public}s table.", tableName.c_str());
            hookMgr_->OnRdbOperationFailReport(sceneId, branchId, ret, "GetString key failed");
            resultSet->Close();
            return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_ERROR;
        }

        std::string resultValue;
        ret = resultSet->GetString(NOTIFICATION_VALUE_INDEX, resultValue);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("GetString value failed from %{public}s table.", tableName.c_str());
            hookMgr_->OnRdbOperationFailReport(sceneId, branchId, ret, "GetString value failed");
            resultSet->Close();
            return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_ERROR;
        }

        values.emplace(resultKey, resultValue);
    } while (resultSet->GoToNextRow() == NativeRdb::E_OK);

    resultSet->Close();
    return NativeRdb::E_OK;
}

int32_t NtfRdbStoreWrapper::QueryData(const std::string tableName, const std::string key, std::string &value)
{
    NativeRdb::AbsRdbPredicates predicates(tableName);
    predicates.EqualTo(NOTIFICATION_KEY, key);

    std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = nullptr;
    int32_t ret = ExecuteQuery(tableName, predicates, resultSet);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }

    const int32_t sceneId = 10;
    const int32_t branchId = 2; // EventSceneId::SCENE_10, EventBranchId::BRANCH_2
    ret = CheckFirstRow(resultSet, tableName, key, sceneId, branchId);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }
    return ExtractStringValue(resultSet, tableName, value, sceneId, branchId);
}

int32_t NtfRdbStoreWrapper::QueryData(const std::string tableName, const std::string key, std::vector<uint8_t> &value)
{
    NativeRdb::AbsRdbPredicates predicates(tableName);
    predicates.EqualTo(NOTIFICATION_KEY, key);

    std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = nullptr;
    int32_t ret = ExecuteQuery(tableName, predicates, resultSet);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }
    const int32_t sceneId = 10;
    const int32_t branchId = 3; // EventSceneId::SCENE_10, EventBranchId::BRANCH_3
    ret = CheckFirstRow(resultSet, tableName, key, sceneId, branchId);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }
    return ExtractBlobValue(resultSet, tableName, value, sceneId, branchId);
}

int32_t NtfRdbStoreWrapper::QueryDataBeginWithKey(
    const std::string tableName, const std::string key, std::unordered_map<std::string, std::string> &values)
{
    NativeRdb::AbsRdbPredicates predicates(tableName);
    predicates.BeginsWith(NOTIFICATION_KEY, key);

    std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = nullptr;
    int32_t ret = ExecuteQuery(tableName, predicates, resultSet);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }
    const int32_t sceneId = 10;
    const int32_t branchId = 5; // EventSceneId::SCENE_10, EventBranchId::BRANCH_5
    ret = CheckFirstRow(resultSet, tableName, key, sceneId, branchId);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }

    return ExtractMapValues(resultSet, tableName, values, sceneId, branchId);
}

int32_t NtfRdbStoreWrapper::QueryDataContainsWithKey(
    const std::string tableName, const std::string key, std::unordered_map<std::string, std::string> &values)
{
    NativeRdb::AbsRdbPredicates predicates(tableName);
    predicates.Contains(NOTIFICATION_KEY, key);

    std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = nullptr;
    int32_t ret = ExecuteQuery(tableName, predicates, resultSet);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }
    const int32_t sceneId = 10;
    const int32_t branchId = 7; // EventSceneId::SCENE_10, EventBranchId::BRANCH_7
    ret = CheckFirstRow(resultSet, tableName, key, sceneId, branchId);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }

    return ExtractMapValues(resultSet, tableName, values, sceneId, branchId);
}

int32_t NtfRdbStoreWrapper::QueryAllData(
    const std::string tableName, std::unordered_map<std::string, std::string> &datas)
{
    NativeRdb::AbsRdbPredicates predicates(tableName);

    std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = nullptr;
    int32_t ret = ExecuteQuery(tableName, predicates, resultSet);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }
    const int32_t sceneId = 10;
    const int32_t branchId = 4; // EventSceneId::SCENE_10, EventBranchId::BRANCH_4
    ret = CheckFirstRow(resultSet, tableName, "", sceneId, branchId);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }

    return ExtractMapValues(resultSet, tableName, datas, sceneId, branchId);
}
} // namespace OHOS::Notification::Infra