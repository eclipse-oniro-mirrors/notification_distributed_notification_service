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
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "rdb_store_callback.h"

namespace OHOS::Notification::Infra {
namespace {
const int32_t NOTIFICATION_RDB_MAX_MEMORY_SIZE = 1;
}

NtfRdbStoreWrapper::NtfRdbStoreWrapper(const NotificationRdbConfig& config, const NtfRdbHook &hooks,
    const std::set<RdbEventHandlerType> &eventHandlerTypes) : notificationRdbConfig_(config),
    hookMgr_(std::make_shared<NtfRdbHookMgr>(hooks)),
    eventHandlerTypes_(eventHandlerTypes)
{
    ANS_LOGD("create notification rdb data manager");
}

int32_t NtfRdbStoreWrapper::Init()
{
    std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
    if (rdbStore_ != nullptr) {
        ANS_LOGD("notification rdb has existed");
        return NativeRdb::E_OK;
    }
    int32_t ret = InitRdbStore();
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("InitRdbStore failed, ret=%{public}d", ret);
        return ret;
    }
    ret = InitCreatedTables();
    return ret;
}

int32_t NtfRdbStoreWrapper::InitRdbStore()
{
    ANS_LOGD("Create rdbStore");
    NativeRdb::RdbStoreConfig rdbStoreConfig(
        notificationRdbConfig_.dbPath + notificationRdbConfig_.dbName,
        NativeRdb::StorageMode::MODE_DISK,
        false,
        std::vector<uint8_t>(),
        notificationRdbConfig_.journalMode,
        notificationRdbConfig_.syncMode);
    rdbStoreConfig.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    rdbStoreConfig.SetHaMode(NativeRdb::HAMode::MAIN_REPLICA);
    rdbStoreConfig.SetClearMemorySize(NOTIFICATION_RDB_MAX_MEMORY_SIZE);
    RdbStoreCallback rdbDataCallBack_(notificationRdbConfig_, hookMgr_, eventHandlerTypes_);
    int32_t ret = NativeRdb::E_OK;
    rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(rdbStoreConfig, notificationRdbConfig_.version,
        rdbDataCallBack_, ret);
    if (ret == NativeRdb::E_SQLITE_CORRUPT) {
        ANS_LOGE("notification rdb init corrupt, need rebuild.");
        NativeRdb::RdbHelper::DeleteRdbStore(notificationRdbConfig_.dbPath + notificationRdbConfig_.dbName);
        rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(rdbStoreConfig, notificationRdbConfig_.version,
            rdbDataCallBack_, ret);
    }
    if (rdbStore_ == nullptr) {
        ANS_LOGE("notification rdb init fail, ret %{public}d", ret);
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NtfRdbStoreWrapper::InitCreatedTables()
{
    std::string queryTableSql = "SELECT name FROM sqlite_master WHERE type='table'";
    std::shared_ptr<NativeRdb::AbsSharedResultSet> absSharedResultSet = nullptr;
    absSharedResultSet = rdbStore_->QuerySql(queryTableSql);
    if (absSharedResultSet == nullptr) {
        ANS_LOGE("Query tableName failed");
        return NativeRdb::E_ERROR;
    }
    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("Query tableName failed. It's empty!");
        return NativeRdb::E_EMPTY_VALUES_BUCKET;
    }
    std::set<std::string> tableNames;
    do {
        std::string tableName;
        ret = absSharedResultSet->GetString(0, tableName);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("GetString string failed from sqlite_master table.");
            return NativeRdb::E_ERROR;
        }
        tableNames.insert(tableName);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    absSharedResultSet->Close();
    {
        std::lock_guard<ffrt::mutex> lock(createdTableMutex_);
        createdTables_ = tableNames;
    }
    ANS_LOGI("create tables successfully");
    return NativeRdb::E_OK;
}

int32_t NtfRdbStoreWrapper::Destroy()
{
    ANS_LOGD("Destory rdbStore");
    {
        std::lock_guard<ffrt::mutex> lock(createdTableMutex_);
        createdTables_.clear();
    }
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }
        rdbStore_ = nullptr;
    }
    int32_t ret = NativeRdb::RdbHelper::DeleteRdbStore(notificationRdbConfig_.dbPath + notificationRdbConfig_.dbName);
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("failed to destroy db store");
        return NativeRdb::E_ERROR;
    }
    ANS_LOGI("destroy db store successfully");
    return NativeRdb::E_OK;
}

static bool IsSystemAccount(const int32_t userId)
{
    const int32_t START_USER_ID = 100;
    const int32_t MAX_USER_ID = 10736;
    return userId >= START_USER_ID && userId <= MAX_USER_ID;
}

std::vector<std::string> NtfRdbStoreWrapper::GenerateOperatedTables(const int32_t &userId)
{
    std::vector<std::string> operatedTables;
    if (IsSystemAccount(userId)) {
        const char *keySpliter = "_";
        std::stringstream stream;
        stream << notificationRdbConfig_.tableName << keySpliter << userId;
        std::string tableName = stream.str();
        std::lock_guard<ffrt::mutex> lock(createdTableMutex_);
        if (createdTables_.find(tableName) != createdTables_.end()) {
            operatedTables.emplace_back(tableName);
        }
    }
    operatedTables.emplace_back(notificationRdbConfig_.tableName);
    return operatedTables;
}

int32_t NtfRdbStoreWrapper::GetUserTableName(const int32_t &userId, std::string &tableName)
{
    if (!IsSystemAccount(userId)) {
        tableName = notificationRdbConfig_.tableName;
        return NativeRdb::E_OK;
    }

    const char *keySpliter = "_";
    std::stringstream stream;
    stream << notificationRdbConfig_.tableName << keySpliter << userId;
    tableName = stream.str();
    // If table already exists, no need to create it.
    {
        std::lock_guard<ffrt::mutex> lock(createdTableMutex_);
        if (createdTables_.find(tableName) != createdTables_.end()) {
            return NativeRdb::E_OK;
        }
    }

    // Create table if it does not exist in the database.
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }

        std::string createTableSql = "CREATE TABLE IF NOT EXISTS " + tableName +
            " (KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL);";
        int32_t ret = rdbStore_->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGW("createTable %{public}s failed, code: %{public}d", tableName.c_str(), ret);
            // EventSceneId::SCENE_11, EventBranchId::BRANCH_1
            int32_t sceneId = 11;
            int32_t branchId = 1;
            hookMgr_->OnRdbOperationFailReport(sceneId, branchId, ret, "create table failed");
            return ret;
        }
    }

    // Record the created table name to avoid future creations.
    {
        std::lock_guard<ffrt::mutex> lock(createdTableMutex_);
        createdTables_.insert(tableName);
    }
    ANS_LOGD("createTable %{public}s succeed", tableName.c_str());
    return NativeRdb::E_OK;
}

int32_t NtfRdbStoreWrapper::RestoreForMasterSlaver()
{
    // EventSceneId::SCENE_10, EventBranchId::BRANCH_1
    int32_t sceneId = 10;
    int32_t branchId = 1;
    hookMgr_->OnRdbOperationFailReport(sceneId, branchId, NativeRdb::E_SQLITE_CORRUPT, "Rdb is corrupted");
    ANS_LOGI("RestoreForMasterSlaver start");
    int32_t result = NativeRdb::E_OK;
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        result = rdbStore_->Restore("");
    }
    ANS_LOGI("RestoreForMasterSlaver result = %{public}d", result);
    return result;
}

void NtfRdbStoreWrapper::RecoverDatabase()
{
    bool expected = false;
    if (!isRecovering_.compare_exchange_strong(expected, true)) {
        ANS_LOGI("Recovery already in progress");
        return;
    }

    // RAII guard to ensure isRecovering_ is reset on all exits
    struct RecoverGuard {
        std::atomic<bool> &flag;
        RecoverGuard(std::atomic<bool> &f) : flag(f) {}
        ~RecoverGuard() { flag.store(false); }
    } guard(isRecovering_);

    ANS_LOGI("Performing full database recovery");

    // EventSceneId::SCENE_10, EventBranchId::BRANCH_10
    int32_t sceneId = 10;
    int32_t branchId = 10;
    hookMgr_->OnRdbOperationFailReport(
        sceneId, branchId, NativeRdb::E_SQLITE_CORRUPT, "Rdb restore corrupted, need recover");
    int32_t ret = Destroy();
    if (ret != NativeRdb::E_OK) {
        // EventSceneId::SCENE_10, EventBranchId::BRANCH_11
        branchId = 11;
        hookMgr_->OnRdbOperationFailReport(sceneId, branchId, ret, "Rdb destroy failed");
        ANS_LOGE("Database destruction failed: %{public}d", ret);
        return;
    }

    ANS_LOGD("Database destroyed, starting reinitialization");
    ret = Init();
    if (ret != NativeRdb::E_OK) {
        // EventSceneId::SCENE_10, EventBranchId::BRANCH_12
        branchId = 12;
        hookMgr_->OnRdbOperationFailReport(sceneId, branchId, ret, "Rdb init failed");
        ANS_LOGE("Database reinitialization failed: %{public}d", ret);
    } else {
        // EventSceneId::SCENE_10, EventBranchId::BRANCH_13
        branchId = 13;
        hookMgr_->OnRdbOperationFailReport(sceneId, branchId, ret, "Rdb reinitialization success");
        ANS_LOGI("Database reinitialization success");
    }
    return;
}
} // namespace OHOS::Notification::Infra