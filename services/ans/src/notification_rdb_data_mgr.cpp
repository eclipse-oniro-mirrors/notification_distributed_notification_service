/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "notification_rdb_data_mgr.h"

#include "ans_log_wrapper.h"
#include "os_account_manager_helper.h"
#include "rdb_errno.h"
#include <algorithm>
#include <cstddef>
#include <sstream>
#include <string>
#include <vector>
#include "notification_analytics_util.h"

namespace OHOS {
namespace Notification {
namespace {
const std::string NOTIFICATION_KEY = "KEY";
const std::string NOTIFICATION_VALUE = "VALUE";
const int32_t NOTIFICATION_KEY_INDEX = 0;
const int32_t NOTIFICATION_VALUE_INDEX = 1;
const std::ptrdiff_t MAX_SIZE_PER_BATCH = 100;
const int32_t NOTIFICATION_RDB_MAX_MEMORY_SIZE = 1;
} // namespace
RdbStoreDataCallBackNotificationStorage::RdbStoreDataCallBackNotificationStorage(
    const NotificationRdbConfig &notificationRdbConfig): notificationRdbConfig_(notificationRdbConfig)
{
    ANS_LOGD("create rdb store callback instance");
}

RdbStoreDataCallBackNotificationStorage::~RdbStoreDataCallBackNotificationStorage()
{
    ANS_LOGD("destroy rdb store callback instance");
}

int32_t RdbStoreDataCallBackNotificationStorage::OnCreate(NativeRdb::RdbStore &rdbStore)
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

int32_t RdbStoreDataCallBackNotificationStorage::OnUpgrade(
    NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion)
{
    ANS_LOGD("OnUpgrade currentVersion: %{public}d, targetVersion: %{public}d",
        oldVersion, newVersion);
    return NativeRdb::E_OK;
}

int32_t RdbStoreDataCallBackNotificationStorage::OnDowngrade(
    NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion)
{
    ANS_LOGD("OnDowngrade  currentVersion: %{public}d, targetVersion: %{public}d",
        currentVersion, targetVersion);
    return NativeRdb::E_OK;
}

int32_t RdbStoreDataCallBackNotificationStorage::OnOpen(NativeRdb::RdbStore &rdbStore)
{
    ANS_LOGD("OnOpen");
    return NativeRdb::E_OK;
}

int32_t RdbStoreDataCallBackNotificationStorage::onCorruption(std::string databaseFile)
{
    return NativeRdb::E_OK;
}

NotificationDataMgr::NotificationDataMgr(const NotificationRdbConfig &notificationRdbConfig)
    : notificationRdbConfig_(notificationRdbConfig)
{
    ANS_LOGD("create notification rdb data manager");
}

int32_t NotificationDataMgr::Init()
{
    ANS_LOGD("Create rdbStore");
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ != nullptr) {
            ANS_LOGD("notification rdb has existed");
            return NativeRdb::E_OK;
        }
    }
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
    RdbStoreDataCallBackNotificationStorage rdbDataCallBack_(notificationRdbConfig_);
    std::lock_guard<ffrt::mutex> lock(createdTableMutex_);
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
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
        return InitCreatedTables();
    }
}

int32_t NotificationDataMgr::InitCreatedTables()
{
    std::string queryTableSql = "SELECT name FROM sqlite_master WHERE type='table'";
    auto absSharedResultSet = rdbStore_->QuerySql(queryTableSql);
    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("Query tableName failed. It's empty!");
        return NativeRdb::E_EMPTY_VALUES_BUCKET;
    }
    do {
        std::string tableName;
        ret = absSharedResultSet->GetString(0, tableName);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("GetString string failed from sqlite_master table.");
            return NativeRdb::E_ERROR;
        }
        createdTables_.insert(tableName);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    absSharedResultSet->Close();
    ANS_LOGI("create tables successfully");
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::Destroy()
{
    ANS_LOGD("Destory rdbStore");
    std::lock_guard<ffrt::mutex> lock(createdTableMutex_);
    createdTables_.clear();
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

int32_t NotificationDataMgr::InsertData(const std::string &key, const std::string &value, const int32_t &userId)
{
    ANS_LOGD("InsertData start");
    if (isRecovering_.load()) {
        ANS_LOGD("The db is being repaired.");
        return NativeRdb::E_ERROR;
    }
    int32_t ret = NativeRdb::E_OK;
    int32_t restoreRet = NativeRdb::E_OK;
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_11, EventBranchId::BRANCH_0);
    std::string tableName;
    ret = GetUserTableName(userId, tableName);
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("Get user table name failed.");
        return NativeRdb::E_ERROR;
    }
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
        ret = rdbStore_->InsertWithConflictResolution(rowId, tableName, valuesBucket,
            NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
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
        message.ErrorCode(ret).Message("Insert operation failed.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return NativeRdb::E_ERROR;
    }
    SendUserDataSizeHisysevent();
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::InsertData(const std::string &key, const std::vector<uint8_t> &value,
    const int32_t &userId)
{
    if (isRecovering_.load()) {
        ANS_LOGD("The db is being repaired.");
        return NativeRdb::E_ERROR;
    }
    int32_t ret = NativeRdb::E_OK;
    int32_t restoreRet = NativeRdb::E_OK;
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_10, EventBranchId::BRANCH_8);
    std::string tableName;
    ret = GetUserTableName(userId, tableName);
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("Get user table name failed.");
        return NativeRdb::E_ERROR;
    }
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }
        int64_t rowId = -1;
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(NOTIFICATION_KEY, key);
        valuesBucket.PutBlob(NOTIFICATION_VALUE, value);
        ret = rdbStore_->InsertWithConflictResolution(rowId, tableName, valuesBucket,
            NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
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
        message.ErrorCode(ret).Message("Insert operation failed.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return NativeRdb::E_ERROR;
    }
    SendUserDataSizeHisysevent();
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::InsertBatchData(const std::unordered_map<std::string, std::string> &values,
    const int32_t &userId)
{
    ANS_LOGD("InsertBatchData start");
    if (isRecovering_.load()) {
        ANS_LOGD("The db is being repaired.");
        return NativeRdb::E_ERROR;
    }
    int32_t ret = NativeRdb::E_OK;
    int32_t restoreRet = NativeRdb::E_OK;
    std::string tableName;
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_10, EventBranchId::BRANCH_7);
    ret = GetUserTableName(userId, tableName);
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("Get user table name failed.");
        return NativeRdb::E_ERROR;
    }
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
        ret = rdbStore_->BatchInsert(rowId, tableName, buckets);
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
        message.ErrorCode(ret).Message("Insert batch operation failed.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return NativeRdb::E_ERROR;
    }
    SendUserDataSizeHisysevent();
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::DeleteData(const std::string &key, const int32_t &userId)
{
    ANS_LOGD("DeleteData start");
    if (isRecovering_.load()) {
        ANS_LOGD("The db is being repaired.");
        return NativeRdb::E_ERROR;
    }
    int32_t ret = NativeRdb::E_OK;
    int32_t restoreRet = NativeRdb::E_OK;
    std::vector<std::string> operatedTables = GenerateOperatedTables(userId);
    std::reverse(operatedTables.begin(), operatedTables.end());
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }
        int32_t rowId = -1;
        for (auto tableName : operatedTables) {
            ret = DeleteData(tableName, key, rowId);
            if (ret == NativeRdb::E_SQLITE_CORRUPT) {
                restoreRet = RestoreForMasterSlaver();
                break;
            }
            if (ret != NativeRdb::E_OK) {
                return ret;
            }
        }
    }
    {
        if (restoreRet == NativeRdb::E_SQLITE_CORRUPT) {
            RecoverDatabase();
        }
    }
    return ret == NativeRdb::E_OK ? NativeRdb::E_OK : NativeRdb::E_ERROR;
}

int32_t NotificationDataMgr::DeleteData(const std::string tableName, const std::string key, int32_t &rowId)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_10, EventBranchId::BRANCH_6);
    absRdbPredicates.EqualTo(NOTIFICATION_KEY, key);
    int32_t ret = rdbStore_->Delete(rowId, absRdbPredicates);
    if (ret != NativeRdb::E_OK) {
        ANS_LOGW("Delete operation failed from %{public}s, result: %{public}d, key=%{public}s.",
            tableName.c_str(), ret, key.c_str());
        message.ErrorCode(ret).Message("Delete operation failed.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::DeleteBatchData(const std::vector<std::string> &keys, const int32_t &userId)
{
    if (isRecovering_.load()) {
        ANS_LOGD("The db is being repaired.");
        return NativeRdb::E_ERROR;
    }
    int32_t ret = NativeRdb::E_OK;
    int32_t restoreRet = NativeRdb::E_OK;
    std::vector<std::string> operatedTables = GenerateOperatedTables(userId);
    std::reverse(operatedTables.begin(), operatedTables.end());
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }
        std::vector<std::vector<std::string>> batchKeys;
        auto start = keys.cbegin(), next = keys.cbegin(), end = keys.cend();
        while (next != end) {
            next = end - next < MAX_SIZE_PER_BATCH ? end : next + MAX_SIZE_PER_BATCH;
            batchKeys.push_back(std::vector<std::string>(start, next));
            start = next;
        }

        int32_t rowId = -1;
        for (auto tableName : operatedTables) {
            NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
            for (const auto &batchKey : batchKeys) {
                absRdbPredicates.In(NOTIFICATION_KEY, batchKey);
                ret = rdbStore_->Delete(rowId, absRdbPredicates);
                if (ret == NativeRdb::E_SQLITE_CORRUPT) {
                    restoreRet = RestoreForMasterSlaver();
                    break;
                }
                if (ret != NativeRdb::E_OK) {
                    ANS_LOGW("Delete operation failed from %{public}s, result: %{public}d.",
                        tableName.c_str(), ret);
                    return NativeRdb::E_ERROR;
                }
            }
            if (ret == NativeRdb::E_SQLITE_CORRUPT) {
                break;
            }
        }
    }
    {
        if (restoreRet == NativeRdb::E_SQLITE_CORRUPT) {
            RecoverDatabase();
        }
    }
    return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_ERROR : NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryData(const std::string &key, std::string &value, const int32_t &userId)
{
    ANS_LOGD("QueryData start");
    if (isRecovering_.load()) {
        ANS_LOGD("The db is being repaired.");
        return NativeRdb::E_ERROR;
    }
    int32_t ret = NativeRdb::E_OK;
    int32_t restoreRet = NativeRdb::E_OK;
    std::vector<std::string> operatedTables = GenerateOperatedTables(userId);
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }
        for (auto tableName : operatedTables) {
            ret = QueryData(tableName, key, value);
            if (ret == NativeRdb::E_SQLITE_CORRUPT) {
                restoreRet = RestoreForMasterSlaver();
                break;
            }
            if (ret != NativeRdb::E_EMPTY_VALUES_BUCKET) {
                return ret;
            }
        }
    }
    {
        if (restoreRet == NativeRdb::E_SQLITE_CORRUPT) {
            RecoverDatabase();
        }
    }
    return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_ERROR : ret;
}

int32_t NotificationDataMgr::QueryData(const std::string tableName, const std::string key, std::string &value)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_10, EventBranchId::BRANCH_2);
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
            if (ret != NativeRdb::E_ROW_OUT_RANGE) {
                ANS_LOGW("GoToFirstRow failed, rdb error is %{public}d.", ret);
                message.ErrorCode(ret).Message("GoToFirstRow failed.");
                NotificationAnalyticsUtil::ReportModifyEvent(message);
            }
        absSharedResultSet->Close();
        return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_EMPTY_VALUES_BUCKET;
    }
    ret = absSharedResultSet->GetString(NOTIFICATION_VALUE_INDEX, value);
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("GetString value failed from %{public}s table.", tableName.c_str());
        message.ErrorCode(ret).Message("GetString value failed.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        absSharedResultSet->Close();
        return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_ERROR;
    }
    absSharedResultSet->Close();
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryData(const std::string &key, std::vector<uint8_t> &values, const int32_t &userId)
{
    if (isRecovering_.load()) {
        ANS_LOGD("The db is being repaired.");
        return NativeRdb::E_ERROR;
    }
    int32_t ret = NativeRdb::E_OK;
    int32_t restoreRet = NativeRdb::E_OK;
    std::vector<std::string> operatedTables = GenerateOperatedTables(userId);
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }
        for (auto tableName : operatedTables) {
            ret = QueryData(tableName, key, values);
            if (ret == NativeRdb::E_SQLITE_CORRUPT) {
                restoreRet = RestoreForMasterSlaver();
                break;
            }
            if (ret != NativeRdb::E_EMPTY_VALUES_BUCKET) {
                return ret;
            }
        }
    }
    {
        if (restoreRet == NativeRdb::E_SQLITE_CORRUPT) {
            RecoverDatabase();
        }
    }
    return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_ERROR : ret;
}

int32_t NotificationDataMgr::QueryData(const std::string tableName, const std::string key, std::vector<uint8_t> &value)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_10, EventBranchId::BRANCH_3);
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
        if (ret != NativeRdb::E_ROW_OUT_RANGE) {
            ANS_LOGW("GoToFirstRow failed, rdb error is %{public}d.", ret);
            message.ErrorCode(ret).Message("GoToFirstRow failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
        }
        absSharedResultSet->Close();
        return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_EMPTY_VALUES_BUCKET;
    }
    ret = absSharedResultSet->GetBlob(NOTIFICATION_VALUE_INDEX, value);
    if (ret != NativeRdb::E_OK) {
        message.ErrorCode(ret).Message("GetString value failed.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("GetString value failed from %{public}s table.", tableName.c_str());
        absSharedResultSet->Close();
        return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_ERROR;
    }
    absSharedResultSet->Close();

    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryDataBeginWithKey(
    const std::string &key, std::unordered_map<std::string, std::string> &values, const int32_t &userId)
{
    ANS_LOGD("QueryData BeginWithKey start");
    if (isRecovering_.load()) {
        ANS_LOGD("The db is being repaired.");
        return NativeRdb::E_ERROR;
    }
    int32_t ret = NativeRdb::E_OK;
    int32_t restoreRet = NativeRdb::E_OK;
    std::vector<std::string> operatedTables = GenerateOperatedTables(userId);
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }
        for (auto tableName : operatedTables) {
            ret = QueryDataBeginWithKey(tableName, key, values);
            if (ret == NativeRdb::E_SQLITE_CORRUPT) {
                restoreRet = RestoreForMasterSlaver();
                break;
            }
            if (ret == NativeRdb::E_ERROR) {
                return ret;
            }
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
        return NativeRdb::E_EMPTY_VALUES_BUCKET;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryDataBeginWithKey(
    const std::string tableName, const std::string key, std::unordered_map<std::string, std::string> &values)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_10, EventBranchId::BRANCH_5);
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
        if (ret != NativeRdb::E_ROW_OUT_RANGE) {
            ANS_LOGW("GoToFirstRow failed, rdb error is %{public}d.", ret);
            message.ErrorCode(ret).Message("GoToFirstRow failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
        }
        absSharedResultSet->Close();
        return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_EMPTY_VALUES_BUCKET;
    }

    do {
        std::string resultKey;
        ret = absSharedResultSet->GetString(NOTIFICATION_KEY_INDEX, resultKey);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("Failed to GetString key from %{public}s table.", tableName.c_str());
            message.ErrorCode(ret).Message("GetString key failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            absSharedResultSet->Close();
            return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_ERROR;
        }

        std::string resultValue;
        ret = absSharedResultSet->GetString(NOTIFICATION_VALUE_INDEX, resultValue);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("GetString value failed from %{public}s table", tableName.c_str());
            message.ErrorCode(ret).Message("GetString value failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            absSharedResultSet->Close();
            return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_ERROR;
        }

        values.emplace(resultKey, resultValue);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    absSharedResultSet->Close();

    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryDataContainsWithKey(
    const std::string &key, std::unordered_map<std::string, std::string> &values, const int32_t &userId)
{
    ANS_LOGD("QueryDataContainsWithKey start");
    if (isRecovering_.load()) {
        ANS_LOGD("The db is being repaired.");
        return NativeRdb::E_ERROR;
    }
    int32_t ret = NativeRdb::E_OK;
    int32_t restoreRet = NativeRdb::E_OK;
    std::vector<std::string> operatedTables = GenerateOperatedTables(userId);
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }
        for (auto tableName : operatedTables) {
            ret = QueryDataContainsWithKey(tableName, key, values);
            if (ret == NativeRdb::E_SQLITE_CORRUPT) {
                restoreRet = RestoreForMasterSlaver();
                break;
            }
            if (ret == NativeRdb::E_ERROR) {
                return ret;
            }
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
        return NativeRdb::E_EMPTY_VALUES_BUCKET;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryDataContainsWithKey(
    const std::string tableName, const std::string key, std::unordered_map<std::string, std::string> &values)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_10, EventBranchId::BRANCH_9);
    absRdbPredicates.Contains(NOTIFICATION_KEY, key);
    auto absSharedResultSet = rdbStore_->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr) {
        ANS_LOGE("absSharedResultSet failed from %{public}s table.", tableName.c_str());
        return NativeRdb::E_ERROR;
    }
    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        ANS_LOGD("GoToFirstRow failed from %{public}s table.It is empty!, key=%{public}s",
            tableName.c_str(), key.c_str());
        if (ret != NativeRdb::E_ROW_OUT_RANGE) {
            ANS_LOGW("GoToFirstRow failed, rdb error is %{public}d.", ret);
            message.ErrorCode(ret).Message("GoToFirstRow failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
        }
        absSharedResultSet->Close();
        return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_EMPTY_VALUES_BUCKET;
    }
    do {
        std::string resultKey;
        ret = absSharedResultSet->GetString(NOTIFICATION_KEY_INDEX, resultKey);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("Failed to GetString key from %{public}s table.", tableName.c_str());
            message.ErrorCode(ret).Message("GetString key failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            absSharedResultSet->Close();
            return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_ERROR;
        }
        std::string resultValue;
        ret = absSharedResultSet->GetString(NOTIFICATION_VALUE_INDEX, resultValue);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("GetString value failed from %{public}s table", tableName.c_str());
            message.ErrorCode(ret).Message("GetString value failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            absSharedResultSet->Close();
            return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_ERROR;
        }
        values.emplace(resultKey, resultValue);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    absSharedResultSet->Close();
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryAllData(std::unordered_map<std::string, std::string> &datas, const int32_t &userId)
{
    ANS_LOGD("QueryAllData start");
    if (isRecovering_.load()) {
        ANS_LOGD("The db is being repaired.");
        return NativeRdb::E_ERROR;
    }
    int32_t ret = NativeRdb::E_OK;
    int32_t restoreRet = NativeRdb::E_OK;
    std::vector<std::string> operatedTables = GenerateOperatedTables(userId);
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }
        for (auto tableName : operatedTables) {
            ret = QueryAllData(tableName,  datas);
            if (ret == NativeRdb::E_SQLITE_CORRUPT) {
                restoreRet = RestoreForMasterSlaver();
                break;
            }
            if (ret == NativeRdb::E_ERROR) {
                return ret;
            }
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

    if (ret == NativeRdb::E_EMPTY_VALUES_BUCKET && datas.empty()) {
        return NativeRdb::E_EMPTY_VALUES_BUCKET;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryAllData(
    const std::string tableName, std::unordered_map<std::string, std::string> &datas)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_10, EventBranchId::BRANCH_4);
    auto absSharedResultSet = rdbStore_->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr) {
        ANS_LOGE("absSharedResultSet failed from %{public}s table.", tableName.c_str());
        return NativeRdb::E_ERROR;
    }

    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        ANS_LOGD("GoToFirstRow failed from %{public}s table. It is empty!", tableName.c_str());
        if (ret != NativeRdb::E_ROW_OUT_RANGE) {
            ANS_LOGW("GoToFirstRow failed, rdb error is %{public}d.", ret);
            message.ErrorCode(ret).Message("GoToFirstRow failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
        }
        absSharedResultSet->Close();
        return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_EMPTY_VALUES_BUCKET;
    }

    do {
        std::string resultKey;
        ret = absSharedResultSet->GetString(NOTIFICATION_KEY_INDEX, resultKey);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("GetString key failed from %{public}s table.", tableName.c_str());
            message.ErrorCode(ret).Message("GetString key failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            absSharedResultSet->Close();
            return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_ERROR;
        }

        std::string resultValue;
        ret = absSharedResultSet->GetString(NOTIFICATION_VALUE_INDEX, resultValue);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("GetString value failed from %{public}s table.", tableName.c_str());
            message.ErrorCode(ret).Message("GetString value failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            absSharedResultSet->Close();
            return ret == NativeRdb::E_SQLITE_CORRUPT ? NativeRdb::E_SQLITE_CORRUPT : NativeRdb::E_ERROR;
        }

        datas.emplace(resultKey, resultValue);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    absSharedResultSet->Close();

    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::DropUserTable(const int32_t userId)
{
    const char *keySpliter = "_";
    std::stringstream stream;
    stream << notificationRdbConfig_.tableName << keySpliter << userId;
    std::string tableName = stream.str();
    std::lock_guard<ffrt::mutex> lock(createdTableMutex_);
    int32_t ret = NativeRdb::E_OK;
    {
        std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
        if (rdbStore_ == nullptr) {
            return NativeRdb::E_ERROR;
        }
        std::string dropTableSql = "DROP TABLE IF EXISTS " + tableName;
        ret = rdbStore_->ExecuteSql(dropTableSql);
    }
    if (ret == NativeRdb::E_OK) {
        createdTables_.erase(tableName);
        ANS_LOGD("drop Table %{public}s succeed", tableName.c_str());
        return ret;
    }
    return ret;
}

int32_t NotificationDataMgr::GetUserTableName(const int32_t &userId, std::string &tableName)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_11, EventBranchId::BRANCH_1);
    if (!OsAccountManagerHelper::IsSystemAccount(userId)) {
        tableName = notificationRdbConfig_.tableName;
        return NativeRdb::E_OK;
    }

    const char *keySpliter = "_";
    std::stringstream stream;
    stream << notificationRdbConfig_.tableName << keySpliter << userId;
    tableName = stream.str();
    if (createdTables_.find(tableName) == createdTables_.end()) {
        std::lock_guard<ffrt::mutex> lock(createdTableMutex_);
        if (createdTables_.find(tableName) == createdTables_.end()) {
            std::lock_guard<ffrt::mutex> lock(rdbStorePtrMutex_);
            if (rdbStore_ == nullptr) {
                return NativeRdb::E_ERROR;
            }
            std::string createTableSql = "CREATE TABLE IF NOT EXISTS " + tableName
                + " (KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL);";
            int32_t ret = rdbStore_->ExecuteSql(createTableSql);
            if (ret != NativeRdb::E_OK) {
                ANS_LOGW("createTable %{public}s failed, code: %{public}d", tableName.c_str(), ret);
                message.ErrorCode(ret).Message("create table failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
                return ret;
            }
            createdTables_.insert(tableName);
            ANS_LOGD("createTable %{public}s succeed", tableName.c_str());
            return NativeRdb::E_OK;
        }
    }
    return NativeRdb::E_OK;
}

std::vector<std::string> NotificationDataMgr::GenerateOperatedTables(const int32_t &userId)
{
    std::vector<std::string> operatedTables;
    if (OsAccountManagerHelper::IsSystemAccount(userId)) {
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

int32_t NotificationDataMgr::RestoreForMasterSlaver()
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_10, EventBranchId::BRANCH_1)
        .ErrorCode(NativeRdb::E_SQLITE_CORRUPT).Message("Rdb is corrupted.");
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    ANS_LOGI("RestoreForMasterSlaver start");
    int32_t result = rdbStore_->Restore("");
    ANS_LOGI("RestoreForMasterSlaver result = %{public}d", result);
    return result;
}

void NotificationDataMgr::RecoverDatabase()
{
    if (!recoveryMutex_.try_lock()) {
        ANS_LOGI("Recovery already in progress");
        return;
    }
    std::lock_guard<ffrt::mutex> recoveryLock(recoveryMutex_, std::adopt_lock);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_10, EventBranchId::BRANCH_10)
        .ErrorCode(NativeRdb::E_SQLITE_CORRUPT).Message("Rdb restore corrupted, need recover.");
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    isRecovering_.store(true);
    ANS_LOGI("Performing full database recovery");

    int32_t ret = Destroy();
    if (ret != NativeRdb::E_OK) {
        message.Message("Rdb destroy failed.").BranchId(BRANCH_11);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("Database destruction failed: %{public}d", ret);
        isRecovering_.store(false);
        return;
    }
    ANS_LOGD("Database destroyed, starting reinitialization");
    ret = Init();
    if (ret != NativeRdb::E_OK) {
        message.Message("Rdb init failed.").BranchId(BRANCH_12);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("Database reinitialization failed: %{public}d", ret);
    } else {
        message.Message("Rdb reinitialization success.").BranchId(BRANCH_13);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGI("Database reinitialization success");
    }
    isRecovering_.store(false);
    return;
}
}
}