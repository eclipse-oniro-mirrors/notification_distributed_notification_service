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
const std::string NOTIFICATION_VALUE = "VALUE";
}

template<typename Func>
int32_t NtfRdbStoreWrapper::InsertDataWithErrorHandling(const int32_t userId, Func insertFunc, bool isBatchMode,
    const int32_t sceneId, const int32_t branchId)
{
    if (isRecovering_.load()) {
        ANS_LOGD("The db is being repaired.");
        return NativeRdb::E_ERROR;
    }

    std::string tableName;
    int32_t ret = GetUserTableName(userId, tableName);
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("Get user table name failed.");
        return NativeRdb::E_ERROR;
    }

    int32_t insertRet = NativeRdb::E_OK;
    bool needRecover = false;

    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }

        insertRet = insertFunc(tableName);
        if (insertRet == NativeRdb::E_SQLITE_CORRUPT) {
            ANS_LOGW("Insert detected SQLITE_CORRUPT for table=%{public}s", tableName.c_str());
            needRecover = true;
        }
    }

    // Handle corruption / recovery outside the DB lock to avoid deadlocks and long-held locks.
    if (needRecover) {
        int32_t restoreRet = RestoreForMasterSlaver();
        if (restoreRet == NativeRdb::E_SQLITE_CORRUPT) {
            // Full recovery may be time-consuming; call RecoverDatabase() (it guards against concurrent runs).
            RecoverDatabase();
        }
    }

    if (insertRet != NativeRdb::E_OK) {
        ANS_LOGE("Insert operation failed, result: %{public}d, table=%{public}s.", insertRet, tableName.c_str());
        // EventSceneId and EventBranchId depend on mode
        hookMgr_->OnRdbOperationFailReport(sceneId, branchId, insertRet,
            isBatchMode ? "Insert batch operation failed" : "Insert operation failed");
        return NativeRdb::E_ERROR;
    }

    hookMgr_->OnSendUserDataSizeHisysevent();
    return NativeRdb::E_OK;
}

int32_t NtfRdbStoreWrapper::InsertData(const std::string &key, const std::string &value, const int32_t &userId)
{
    // Prepare values outside the DB lock to minimize lock duration.
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(NOTIFICATION_KEY, key);
    valuesBucket.PutString(NOTIFICATION_VALUE, value);

    auto insertFunc = [this, &valuesBucket](const std::string& tableName) {
        int64_t rowId = -1;
        return this->rdbStore_->InsertWithConflictResolution(rowId, tableName, valuesBucket,
            NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    };

    constexpr int32_t sceneId = 11;
    constexpr int32_t branchId = 0; // EventSceneId::SCENE_11, EventBranchId::BRANCH_0
    return InsertDataWithErrorHandling(userId, insertFunc, false, sceneId, branchId);
}

int32_t NtfRdbStoreWrapper::InsertData(const std::string &key, const std::vector<uint8_t> &value,
    const int32_t &userId)
{
    // Prepare values outside DB lock to minimize lock duration.
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(NOTIFICATION_KEY, key);
    valuesBucket.PutBlob(NOTIFICATION_VALUE, value);

    auto insertFunc = [this, &valuesBucket](const std::string& tableName) {
        int64_t rowId = -1;
        return this->rdbStore_->InsertWithConflictResolution(rowId, tableName, valuesBucket,
            NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    };

    constexpr int32_t sceneId = 10;
    constexpr int32_t branchId = 8; // EventSceneId::SCENE_10, EventBranchId::BRANCH_8
    return InsertDataWithErrorHandling(userId, insertFunc, false, sceneId, branchId);
}

int32_t NtfRdbStoreWrapper::InsertBatchData(const std::unordered_map<std::string, std::string> &values,
    const int32_t &userId)
{
    if (values.empty()) {
        ANS_LOGD("No values to insert (empty batch).");
        return NativeRdb::E_OK;
    }

    // Prepare buckets outside of DB lock to minimize lock hold time.
    std::vector<NativeRdb::ValuesBucket> buckets;
    buckets.reserve(values.size());
    for (const auto &entry : values) {
        NativeRdb::ValuesBucket vb;
        vb.PutString(NOTIFICATION_KEY, entry.first);
        vb.PutString(NOTIFICATION_VALUE, entry.second);
        buckets.emplace_back(std::move(vb));
    }
    auto insertFunc = [this, &buckets](const std::string& tableName) {
        int64_t rowId = -1;
        return this->rdbStore_->BatchInsert(rowId, tableName, buckets);
    };
    constexpr int32_t sceneId = 10;
    constexpr int32_t branchId = 7; // EventSceneId::SCENE_10, EventBranchId::BRANCH_7
    return InsertDataWithErrorHandling(userId, insertFunc, true, sceneId, branchId);
}
} // namespace OHOS::Notification::Infra