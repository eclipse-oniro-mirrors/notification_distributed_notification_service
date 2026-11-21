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

#include <chrono>
#include <sstream>
#include "ffrt_inner.h"
#include "ans_common_utils.h"
#include "ans_const_define.h"
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
constexpr int64_t MICROSECONDS_PER_MILLISECOND = 1000;

bool IsLegacyStatisticsTable(const std::string &name)
{
    static const std::string prefix = NOTIFICATION_STATISTICS_TABLENAME + "_";
    if (name.size() <= prefix.size() || name.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    int32_t userId = AnsCommonUtils::StringToInt(name.substr(prefix.size()));
    return userId > ZERO_USERID && userId < DEFAULT_USER_ID;
}
}

NtfRdbStoreWrapper::NtfRdbStoreWrapper(const NotificationRdbConfig& config, const NtfRdbHook &hooks,
    const std::set<RdbEventHandlerType> &eventHandlerTypes) : notificationRdbConfig_(config),
    hookMgr_(std::make_shared<NtfRdbHookMgr>(hooks)),
    eventHandlerTypes_(eventHandlerTypes)
{
    ANS_LOGD("create notification rdb data manager");
}

NtfRdbStoreWrapper::~NtfRdbStoreWrapper()
{
    CancelIdleRelease();
}

int64_t NtfRdbStoreWrapper::NowMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void NtfRdbStoreWrapper::TouchStoreLocked()
{
    lastUsedTimeMs_ = NowMs();
}

bool NtfRdbStoreWrapper::EnsureRdbStoreLocked()
{
    if (rdbStore_ == nullptr) {
        int32_t ret = InitRdbStore();
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("Failed to reopen notification rdb, ret=%{public}d", ret);
            return false;
        }
        int32_t tableRet = InitCreatedTables();
        if (tableRet != NativeRdb::E_OK && tableRet != NativeRdb::E_EMPTY_VALUES_BUCKET) {
            ANS_LOGE("Failed to reload notification rdb tables, ret=%{public}d", tableRet);
            rdbStore_ = nullptr;
            return false;
        }
        ANS_LOGI("Notification rdb reopened after idle release");
        ScheduleIdleRelease();
    }
    TouchStoreLocked();
    return true;
}

void NtfRdbStoreWrapper::ScheduleIdleRelease()
{
    const int64_t timeoutMs = notificationRdbConfig_.idleReleaseTimeoutMs;
    if (timeoutMs <= 0) {
        return;
    }
    std::lock_guard<ffrt::mutex> lock(idleReleaseMutex_);
    if (idleReleaseHandle_ != nullptr) {
        return;
    }
    idleReleaseHandle_ = ffrt::submit_h([this, timeoutMs]() {
        this->HandleIdleRelease(timeoutMs);
    }, {}, {}, ffrt::task_attr().delay(timeoutMs * MICROSECONDS_PER_MILLISECOND)
        .name("AnsRdbIdleRelease"));
    if (idleReleaseHandle_ == nullptr) {
        ANS_LOGW("Failed to arm notification rdb idle release timer");
        return;
    }
    ANS_LOGI("Notification rdb idle release timer armed, timeout=%{public}lld ms",
        static_cast<long long>(timeoutMs));
}

void NtfRdbStoreWrapper::CancelIdleRelease()
{
    std::lock_guard<ffrt::mutex> lock(idleReleaseMutex_);
    if (idleReleaseHandle_ != nullptr) {
        ffrt::skip(idleReleaseHandle_);
        idleReleaseHandle_ = nullptr;
    }
}

void NtfRdbStoreWrapper::HandleIdleRelease(int64_t idleMs)
{
    {
        std::lock_guard<ffrt::mutex> lock(idleReleaseMutex_);
        idleReleaseHandle_ = nullptr;
    }
    if (ReleaseIfIdle(idleMs) != NativeRdb::E_OK) {
        // The store is still in use, check again later.
        ScheduleIdleRelease();
    }
}

int32_t NtfRdbStoreWrapper::ReleaseIfIdle(int64_t idleMs)
{
    std::unique_lock<ffrt::mutex> storeLock(rdbStorePtrMutex_, std::try_to_lock);
    if (!storeLock.owns_lock()) {
        ANS_LOGD("Notification rdb is busy, skip idle release");
        return NativeRdb::E_ERROR;
    }
    if (rdbStore_ == nullptr) {
        ANS_LOGI("Notification rdb is already released");
        return NativeRdb::E_OK;
    }
    if (isRecovering_.load()) {
        ANS_LOGD("Notification rdb is recovering, skip idle release");
        return NativeRdb::E_ERROR;
    }
    const int64_t lastUsed = lastUsedTimeMs_;
    const int64_t now = NowMs();
    if (lastUsed > 0 && now - lastUsed < idleMs) {
        return NativeRdb::E_ERROR;
    }
    rdbStore_ = nullptr;
    {
        std::lock_guard<ffrt::mutex> tableLock(createdTableMutex_);
        createdTables_.clear();
    }
    lastUsedTimeMs_ = 0;
    ANS_LOGI("Notification rdb released after idle %{public}lld ms, file kept",
        static_cast<long long>(now - lastUsed));
    return NativeRdb::E_OK;
}

bool NtfRdbStoreWrapper::IsStoreOpen() const
{
    std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
    return rdbStore_ != nullptr;
}

int32_t NtfRdbStoreWrapper::Init()
{
    std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
    if (rdbStore_ != nullptr) {
        ANS_LOGD("notification rdb has existed");
        TouchStoreLocked();
        ScheduleIdleRelease();
        return NativeRdb::E_OK;
    }
    int32_t ret = InitRdbStore();
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("InitRdbStore failed, ret=%{public}d", ret);
        return ret;
    }
    ret = InitCreatedTables();
    if (ret == NativeRdb::E_OK || ret == NativeRdb::E_EMPTY_VALUES_BUCKET) {
        TouchStoreLocked();
        ScheduleIdleRelease();
    }
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
    CleanLegacyStatisticsTables(tableNames);
    {
        std::lock_guard<ffrt::mutex> lock(createdTableMutex_);
        createdTables_ = tableNames;
    }
    ANS_LOGI("create tables successfully");
    return NativeRdb::E_OK;
}

void NtfRdbStoreWrapper::CleanLegacyStatisticsTables(std::set<std::string> &tableNames)
{
    for (auto it = tableNames.begin(); it != tableNames.end();) {
        const std::string &name = *it;
        if (!IsLegacyStatisticsTable(name)) {
            ++it;
            continue;
        }
        std::string dropSql = "DROP TABLE IF EXISTS " + name;
        int32_t ret = rdbStore_->ExecuteSql(dropSql);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGW("Drop legacy table %{public}s failed: %{public}d", name.c_str(), ret);
            ++it;
            continue;
        }
        ANS_LOGI("Dropped legacy statistics table %{public}s", name.c_str());
        it = tableNames.erase(it);
    }
}

int32_t NtfRdbStoreWrapper::Destroy()
{
    ANS_LOGD("Destory rdbStore");
    CancelIdleRelease();
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
        lastUsedTimeMs_ = 0;
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
        if (!EnsureRdbStoreLocked()) {
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

int32_t NtfRdbStoreWrapper::GetUserStatisticTableName(const int32_t &userId, std::string &tableName)
{
    const char *keySpliter = "_";
    std::stringstream stream;
    stream << NOTIFICATION_STATISTICS_TABLENAME << keySpliter << userId;
    tableName = stream.str();

    // If statistics table already exists, no need to create it.
    {
        std::lock_guard<ffrt::mutex> lock(createdTableMutex_);
        if (createdTables_.find(tableName) != createdTables_.end()) {
            return NativeRdb::E_OK;
        }
    }

    // Create table if it does not exist in the database.
    do {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (!EnsureRdbStoreLocked()) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }

        std::string createTableSql = "CREATE TABLE IF NOT EXISTS " + tableName
            + " (notificationTime BIGINT NOT NULL, bundleName TEXT NOT NULL,"
            + " uid INTEGER NOT NULL, type TEXT NOT NULL,"
            + " id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL);";
        int32_t ret = rdbStore_->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGW("createTable %{public}s failed, code: %{public}d", tableName.c_str(), ret);
            // EventSceneId::SCENE_11, EventBranchId::BRANCH_1
            hookMgr_->OnRdbOperationFailReport(11, 1, ret, "create table failed");
            return ret;
        }
    } while (0);

    // Record the created table name to avoid future creations.
    {
        std::lock_guard<ffrt::mutex> lock(createdTableMutex_);
        createdTables_.insert(tableName);
    }

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
        if (rdbStore_ == nullptr) {
            ANS_LOGE("NtfRdbStoreWrapper rdbStore_ is null");
            return NativeRdb::E_ERROR;
        }
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

