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

#include <sstream>
#include "ans_log_wrapper.h"
#include "rdb_errno.h"
#include "rdb_store.h"

namespace OHOS::Notification::Infra {
namespace {
const std::string NOTIFICATION_KEY = "KEY";
const std::ptrdiff_t MAX_SIZE_PER_BATCH = 100;
}

template<typename Func>
int32_t NtfRdbStoreWrapper::DeleteDataWithErrorHandling(const int32_t userId, Func deleteFunc, bool isBatchMode,
    const int32_t sceneId, const int32_t branchId)
{
    if (isRecovering_.load()) {
        ANS_LOGD("The db is being repaired.");
        return NativeRdb::E_ERROR;
    }

    auto operatedTables = GenerateOperatedTables(userId);
    int32_t deleteRet = NativeRdb::E_OK;
    bool needRecover = false;

    for (auto it = operatedTables.rbegin(); it != operatedTables.rend(); ++it) {
        const std::string &tableName = *it;
        deleteRet = deleteFunc(tableName);
        if (deleteRet == NativeRdb::E_SQLITE_CORRUPT) {
            ANS_LOGW("Delete detected SQLITE_CORRUPT for table=%{public}s", tableName.c_str());
            hookMgr_->OnRdbOperationFailReport(sceneId, branchId, deleteRet,
                isBatchMode ? "Delete batch operation failed" : "Delete operation failed");
            needRecover = true;
            break;
        }
        if (deleteRet != NativeRdb::E_OK) {
            ANS_LOGW("Delete operation failed from %{public}s, result: %{public}d.",
                tableName.c_str(), deleteRet);
            hookMgr_->OnRdbOperationFailReport(sceneId, branchId, deleteRet,
                isBatchMode ? "Delete batch operation failed" : "Delete operation failed");
            return NativeRdb::E_ERROR;
        }
    }

    // Handle corruption / recovery outside the DB lock to avoid deadlocks.
    if (needRecover) {
        int32_t restoreRet = RestoreForMasterSlaver();
        if (restoreRet == NativeRdb::E_SQLITE_CORRUPT) {
            RecoverDatabase();
        }
        return NativeRdb::E_ERROR;
    }

    return NativeRdb::E_OK;
}

int32_t NtfRdbStoreWrapper::DeleteData(const std::string &key, const int32_t &userId)
{
    ANS_LOGD("DeleteData start");
    auto deleteFunc = [this, &key](const std::string& tableName) {
        int32_t rowId = -1;
        return this->DeleteData(tableName, key, rowId);
    };

    constexpr int32_t sceneId = 10;
    constexpr int32_t branchId = 6; // EventSceneId::SCENE_10, EventBranchId::BRANCH_6
    return DeleteDataWithErrorHandling(userId, deleteFunc, false, sceneId, branchId);
}

int32_t NtfRdbStoreWrapper::DeleteData(const std::string &tableName, const std::string &key, int32_t rowId)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    absRdbPredicates.EqualTo(NOTIFICATION_KEY, key);

    int32_t ret = NativeRdb::E_OK;
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }
        ret = rdbStore_->Delete(rowId, absRdbPredicates);
    }

    if (ret != NativeRdb::E_OK) {
        ANS_LOGD("Delete operation result: %{public}d, table=%{public}s, key=%{public}s.",
            ret, tableName.c_str(), key.c_str());
        return ret;
    }

    return NativeRdb::E_OK;
}

int32_t NtfRdbStoreWrapper::DeleteBatchData(const std::vector<std::string>& keys, const int32_t userId)
{
    ANS_LOGD("DeleteBatchData start");
    if (keys.empty()) {
        ANS_LOGD("No keys to delete for user: %d", userId);
        return NativeRdb::E_OK;
    }

    const auto batchKeys = SplitKeysIntoBatches(keys, MAX_SIZE_PER_BATCH);

    auto deleteFunc = [this, &batchKeys](const std::string& tableName) {
        return this->DeleteFromTable(batchKeys, tableName);
    };

    constexpr int32_t sceneId = 10;
    constexpr int32_t branchId = 9; // EventSceneId::SCENE_10, EventBranchId::BRANCH_9
    return DeleteDataWithErrorHandling(userId, deleteFunc, true, sceneId, branchId);
}

std::vector<std::vector<std::string>> NtfRdbStoreWrapper::SplitKeysIntoBatches(
    const std::vector<std::string>& keys, size_t batchSize) const
{
    std::vector<std::vector<std::string>> batches;

    if (keys.empty() || batchSize == 0) {
        return batches;
    }

    const size_t totalKeys = keys.size();
    const size_t numBatches = (totalKeys + batchSize - 1) / batchSize;
    batches.reserve(numBatches);

    auto start = keys.begin();
    while (start != keys.end()) {
        auto end = std::distance(start, keys.end()) > static_cast<std::ptrdiff_t>(batchSize) ?
            start + batchSize : keys.end();
        batches.emplace_back(start, end);
        start = end;
    }

    return batches;
}

int32_t NtfRdbStoreWrapper::DeleteFromTable(
    const std::vector<std::vector<std::string>>& batchKeys,
    const std::string& tableName) const
{
    std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
    if (rdbStore_ == nullptr) {
        ANS_LOGE("notification rdb is null");
        return NativeRdb::E_ERROR;
    }

    for (const auto& batch : batchKeys) {
        if (batch.empty()) {
            continue;
        }

        NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
        absRdbPredicates.In(NOTIFICATION_KEY, batch);

        int32_t rowId = -1;
        int32_t result = rdbStore_->Delete(rowId, absRdbPredicates);
        if (result != NativeRdb::E_OK) {
            ANS_LOGE("Batch delete failed from %{public}s, batch size: %zu, result: %{public}d",
                tableName.c_str(), batch.size(), result);
            return result;
        }
    }

    return NativeRdb::E_OK;
}

int32_t NtfRdbStoreWrapper::DropUserTable(const int32_t userId)
{
    constexpr const char* TABLE_SEPARATOR = "_";
    std::stringstream stream;
    stream << notificationRdbConfig_.tableName << TABLE_SEPARATOR << userId;
    const std::string tableName = stream.str();

    int32_t ret = NativeRdb::E_OK;
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }
        std::string dropTableSql = "DROP TABLE IF EXISTS " + tableName;
        ret = rdbStore_->ExecuteSql(dropTableSql);
    }

    if (ret == NativeRdb::E_OK) {
        std::lock_guard<ffrt::mutex> lock(createdTableMutex_);
        createdTables_.erase(tableName);
        ANS_LOGD("Drop table %{public}s succeed", tableName.c_str());
    } else {
        ANS_LOGW("Drop table %{public}s failed, result: %{public}d", tableName.c_str(), ret);
    }

    return ret;
}
} // namespace OHOS::Notification::Infra