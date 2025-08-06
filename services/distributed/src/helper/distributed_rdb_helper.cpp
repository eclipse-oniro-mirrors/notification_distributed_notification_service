/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "distributed_rdb_helper.h"

#include "ans_log_wrapper.h"
namespace OHOS {
namespace Notification {

namespace {
const std::string NOTIFICATION_KEY = "KEY";
const std::string NOTIFICATION_VALUE = "VALUE";
const int32_t NOTIFICATION_KEY_INDEX = 0;
const int32_t NOTIFICATION_VALUE_INDEX = 1;
} // namespace

RdbCallBack::RdbCallBack(const DistributedRdbConfig &notificationRdbConfig)
    : notificationRdbConfig_(notificationRdbConfig)
{
    ANS_LOGD("create rdb store callback instance");
}

RdbCallBack::~RdbCallBack()
{
    ANS_LOGD("destroy rdb store callback instance");
}

int32_t RdbCallBack::OnCreate(NativeRdb::RdbStore &rdbStore)
{
    ANS_LOGD("OnCreate");
    int ret = NativeRdb::E_OK;
    if (hasTableInit_) {
        return ret;
    }
    std::string createTableSql = "CREATE TABLE IF NOT EXISTS " + notificationRdbConfig_.tableName
        + " (KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL);";
    ret = rdbStore.ExecuteSql(createTableSql);
    if (ret == NativeRdb::E_OK) {
        hasTableInit_ = true;
        ANS_LOGD("createTable succeed");
    }
    return ret;
}

int32_t RdbCallBack::OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion)
{
    ANS_LOGD("OnUpgrade currentVersion: %{public}d, targetVersion: %{public}d",
        oldVersion, newVersion);
    return NativeRdb::E_OK;
}

int32_t RdbCallBack::OnDowngrade(NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion)
{
    ANS_LOGD("OnDowngrade  currentVersion: %{public}d, targetVersion: %{public}d",
        currentVersion, targetVersion);
    return NativeRdb::E_OK;
}

int32_t RdbCallBack::OnOpen(NativeRdb::RdbStore &rdbStore)
{
    ANS_LOGD("OnOpen");
    return NativeRdb::E_OK;
}

int32_t RdbCallBack::onCorruption(std::string databaseFile)
{
    return NativeRdb::E_OK;
}

DistributedRdbHelper::DistributedRdbHelper(const DistributedRdbConfig &notificationRdbConfig)
    : notificationRdbConfig_(notificationRdbConfig)
{
    ANS_LOGD("create notification rdb data manager");
}

int32_t DistributedRdbHelper::Init()
{
    ANS_LOGD("Create rdbStore");
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ != nullptr) {
            ANS_LOGD("notification rdb has existed");
            return NativeRdb::E_OK;
        }
    }
    NativeRdb::RdbStoreConfig config(
            notificationRdbConfig_.dbPath + notificationRdbConfig_.dbName,
            NativeRdb::StorageMode::MODE_DISK,
            false,
            std::vector<uint8_t>(),
            notificationRdbConfig_.journalMode,
            notificationRdbConfig_.syncMode);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    config.SetHaMode(NativeRdb::HAMode::MAIN_REPLICA);
    RdbCallBack rdbDataCallBack_(notificationRdbConfig_);
    std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
    int32_t ret = NativeRdb::E_OK;
    rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(config, notificationRdbConfig_.version,
        rdbDataCallBack_, ret);
    if (ret == NativeRdb::E_SQLITE_CORRUPT) {
        ANS_LOGE("notification rdb init corrupt, need rebuild.");
        NativeRdb::RdbHelper::DeleteRdbStore(notificationRdbConfig_.dbPath + notificationRdbConfig_.dbName);
        rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(config, notificationRdbConfig_.version,
            rdbDataCallBack_, ret);
    }
    if (rdbStore_ == nullptr) {
        ANS_LOGE("notification rdb init fail, result = %{public}d.", ret);
        return NativeRdb::E_ERROR;
    }
    ANS_LOGI("Create rdbStore successfully");
    return NativeRdb::E_OK;
}

int32_t DistributedRdbHelper::Destroy()
{
    ANS_LOGD("Destory rdbStore");

    std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
    if (rdbStore_ == nullptr) {
        ANS_LOGE("notification rdb is null");
        return NativeRdb::E_ERROR;
    }
    rdbStore_ = nullptr;
    int32_t ret = NativeRdb::RdbHelper::DeleteRdbStore(notificationRdbConfig_.dbPath + notificationRdbConfig_.dbName);
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("failed to destroy db store");
        return NativeRdb::E_ERROR;
    }
    ANS_LOGI("destroy db store successfully");
    return NativeRdb::E_OK;
}

int32_t DistributedRdbHelper::InsertData(const std::string &key, const std::string &value)
{
    if (isRecovering_.load()) {
        ANS_LOGD("The db is being repaired.");
        return NativeRdb::E_ERROR;
    }
    int32_t ret = NativeRdb::E_OK;
    int32_t restoreRet = NativeRdb::E_OK;
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }
        int64_t rowId = -1;
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(NOTIFICATION_KEY, key);
        valuesBucket.PutString(NOTIFICATION_VALUE, value);
        ret = rdbStore_->InsertWithConflictResolution(rowId, notificationRdbConfig_.tableName,
            valuesBucket, NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
        if (ret == NativeRdb::E_SQLITE_CORRUPT) {
            restoreRet = RestoreForMasterSlaver();
        }
    }
    {
        if (restoreRet == NativeRdb::E_SQLITE_CORRUPT) {
            RecoverDatabase();
        }
    }
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("Insert operation failed, result: %{public}d, key=%{public}s.", ret, key.c_str());
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t DistributedRdbHelper::InsertBatchData(const std::unordered_map<std::string, std::string> &values)
{
    if (isRecovering_.load()) {
        ANS_LOGD("The db is being repaired.");
        return NativeRdb::E_ERROR;
    }
    int32_t ret = NativeRdb::E_OK;
    int32_t restoreRet = NativeRdb::E_OK;
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }
        int64_t rowId = -1;
        std::vector<NativeRdb::ValuesBucket> buckets;
        for (auto &value : values) {
            NativeRdb::ValuesBucket valuesBucket;
            valuesBucket.PutString(NOTIFICATION_KEY, value.first);
            valuesBucket.PutString(NOTIFICATION_VALUE, value.second);
            buckets.emplace_back(valuesBucket);
        }
        ret = rdbStore_->BatchInsert(rowId, notificationRdbConfig_.tableName, buckets);
        if (ret == NativeRdb::E_SQLITE_CORRUPT) {
            restoreRet = RestoreForMasterSlaver();
        }
    }
    {
        if (restoreRet == NativeRdb::E_SQLITE_CORRUPT) {
            RecoverDatabase();
        }
    }
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("Insert batch operation failed, result: %{public}d.", ret);
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t DistributedRdbHelper::DeleteData(const std::string &key)
{
    if (isRecovering_.load()) {
        ANS_LOGD("The db is being repaired.");
        return NativeRdb::E_ERROR;
    }
    int32_t ret = NativeRdb::E_OK;
    int32_t restoreRet = NativeRdb::E_OK;
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }
        int32_t rowId = -1;
        ret = DeleteData(notificationRdbConfig_.tableName, key, rowId);
        if (ret == NativeRdb::E_SQLITE_CORRUPT) {
            restoreRet = RestoreForMasterSlaver();
        }
    }
    {
        if (restoreRet == NativeRdb::E_SQLITE_CORRUPT) {
            RecoverDatabase();
        }
    }
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("Delete operation failed, result: %{public}d.", ret);
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t DistributedRdbHelper::DeleteData(const std::string tableName, const std::string key, int32_t &rowId)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    absRdbPredicates.EqualTo(NOTIFICATION_KEY, key);
    int32_t ret = rdbStore_->Delete(rowId, absRdbPredicates);
    if (ret != NativeRdb::E_OK) {
        ANS_LOGW("Delete operation failed from %{public}s, result: %{public}d, key=%{public}s.",
            tableName.c_str(), ret, key.c_str());
        return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t DistributedRdbHelper::QueryData(const std::string &key, std::string &value)
{
    ANS_LOGD("QueryData start");
    if (isRecovering_.load()) {
        ANS_LOGD("The db is being repaired.");
        return NativeRdb::E_ERROR;
    }
    int32_t ret = NativeRdb::E_OK;
    int32_t restoreRet = NativeRdb::E_OK;
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }
        ret = QueryData(notificationRdbConfig_.tableName, key, value);
        if (ret == NativeRdb::E_SQLITE_CORRUPT) {
            restoreRet = RestoreForMasterSlaver();
        }
    }
    {
        if (restoreRet == NativeRdb::E_SQLITE_CORRUPT) {
            RecoverDatabase();
        }
    }
    if (ret == NativeRdb::E_EMPTY_VALUES_BUCKET && value.empty()) {
        return NativeRdb::E_EMPTY_VALUES_BUCKET;
    }

    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("Delete operation failed, result: %{public}d.", ret);
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t DistributedRdbHelper::QueryData(const std::string tableName, const std::string key, std::string &value)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    absRdbPredicates.EqualTo(NOTIFICATION_KEY, key);
    auto absSharedResultSet = rdbStore_->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr) {
        ANS_LOGE("absSharedResultSet failed from %{public}s table.", tableName.c_str());
        return NativeRdb::E_ERROR;
    }

    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        ANS_LOGW("GoToFirstRow failed from %{public}s table. It is empty!, key=%{public}s",
            tableName.c_str(), key.c_str());
        absSharedResultSet->Close();
        return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_EMPTY_VALUES_BUCKET;
    }
    ret = absSharedResultSet->GetString(NOTIFICATION_VALUE_INDEX, value);
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("GetString value failed from %{public}s table.", tableName.c_str());
        absSharedResultSet->Close();
        return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_ERROR;
    }
    absSharedResultSet->Close();
    return NativeRdb::E_OK;
}

int32_t DistributedRdbHelper::QueryDataBeginWithKey(
    const std::string &key, std::unordered_map<std::string, std::string> &values)
{
    ANS_LOGD("QueryData BeginWithKey start");
    if (isRecovering_.load()) {
        ANS_LOGD("The db is being repaired.");
        return NativeRdb::E_ERROR;
    }
    int32_t ret = NativeRdb::E_OK;
    int32_t restoreRet = NativeRdb::E_OK;
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }
        int32_t ret = QueryDataBeginWithKey(notificationRdbConfig_.tableName, key, values);
        if (ret == NativeRdb::E_SQLITE_CORRUPT) {
            restoreRet = RestoreForMasterSlaver();
        }
        if (ret == NativeRdb::E_ERROR) {
            return ret;
        }
    }
    {
        if (restoreRet == NativeRdb::E_SQLITE_CORRUPT) {
            RecoverDatabase();
        }
    }
    if (ret == NativeRdb::E_SQLITE_CORRUPT) {
        return NativeRdb::E_ERROR;
    }

    if (ret == NativeRdb::E_EMPTY_VALUES_BUCKET && values.empty()) {
        ANS_LOGI("notification rdb is empty.");
        return NativeRdb::E_EMPTY_VALUES_BUCKET;
    }
    return NativeRdb::E_OK;
}

int32_t DistributedRdbHelper::QueryDataBeginWithKey(
    const std::string tableName, const std::string key, std::unordered_map<std::string, std::string> &values)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    absRdbPredicates.BeginsWith(NOTIFICATION_KEY, key);
    auto absSharedResultSet = rdbStore_->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr) {
        ANS_LOGE("absSharedResultSet failed from %{public}s table.", tableName.c_str());
        return NativeRdb::E_ERROR;
    }

    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        ANS_LOGD("GoToFirstRow failed from %{public}s table.It is empty!, key=%{public}s",
            tableName.c_str(), key.c_str());
        absSharedResultSet->Close();
        return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_EMPTY_VALUES_BUCKET;
    }

    do {
        std::string resultKey;
        ret = absSharedResultSet->GetString(NOTIFICATION_KEY_INDEX, resultKey);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("Failed to GetString key from %{public}s table.", tableName.c_str());
            absSharedResultSet->Close();
            return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_ERROR;
        }

        std::string resultValue;
        ret = absSharedResultSet->GetString(NOTIFICATION_VALUE_INDEX, resultValue);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("GetString value failed from %{public}s table", tableName.c_str());
            absSharedResultSet->Close();
            return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_ERROR;
        }
        values.emplace(resultKey, resultValue);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    absSharedResultSet->Close();
    return NativeRdb::E_OK;
}

int32_t DistributedRdbHelper::RestoreForMasterSlaver()
{
    ANS_LOGI("RestoreForMasterSlaver start");
    int32_t result = rdbStore_->Restore("");
    ANS_LOGI("RestoreForMasterSlaver result = %{public}d", result);
    return result;
}

void DistributedRdbHelper::RecoverDatabase()
{
    if (!recoveryMutex_.try_lock()) {
        ANS_LOGI("Recovery already in progress");
        return;
    }
    std::lock_guard<ffrt::mutex> recoveryLock(recoveryMutex_, std::adopt_lock);
    isRecovering_.store(true);
    ANS_LOGI("Performing full database recovery");

    int32_t ret = Destroy();
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("Database destruction failed: %d", ret);
        isRecovering_.store(false);
        return;
    }
    ANS_LOGD("Database destroyed, starting reinitialization");
    ret = Init();
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("Database reinitialization failed: %d", ret);
    } else {
        ANS_LOGI("Database reinitialization success");
    }
    isRecovering_.store(false);
    return;
}
}
}