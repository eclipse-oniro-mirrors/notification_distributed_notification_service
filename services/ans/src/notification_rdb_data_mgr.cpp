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
    std::shared_ptr<NativeRdb::RdbStore> rdbConnection = GetConnection();
    if (rdbConnection == nullptr) {
        ANS_LOGE("notification rdb is null");
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

std::shared_ptr<NativeRdb::RdbStore> NotificationDataMgr::GetConnection()
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
    RdbStoreDataCallBackNotificationStorage rdbDataCallBack_(notificationRdbConfig_);

    int32_t ret = NativeRdb::E_OK;
    std::shared_ptr<NativeRdb::RdbStore> rdbStore = NativeRdb::RdbHelper::GetRdbStore(rdbStoreConfig,
        notificationRdbConfig_.version, rdbDataCallBack_, ret);
    if (rdbStore == nullptr) {
        ANS_LOGE("notification rdb init fail");
        return nullptr;
    }
    InitCreatedTables(rdbStore);
    return rdbStore;
}

int32_t NotificationDataMgr::InitCreatedTables(std::shared_ptr<NativeRdb::RdbStore> rdbConnection)
{
    {
        std::lock_guard<std::mutex> lock(createdTableMutex_);
        if (!createdTables_.empty()) {
            return NativeRdb::E_OK;
        }
    }
    std::string queryTableSql = "SELECT name FROM sqlite_master WHERE type='table'";
    auto absSharedResultSet = rdbConnection->QuerySql(queryTableSql);
    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("Query tableName failed. It's empty!");
        return NativeRdb::E_EMPTY_VALUES_BUCKET;
    }
    {
        std::lock_guard<std::mutex> lock(createdTableMutex_);
        do {
            std::string tableName;
            ret = absSharedResultSet->GetString(0, tableName);
            if (ret != NativeRdb::E_OK) {
                ANS_LOGE("GetString string failed from sqlite_master table.");
                return NativeRdb::E_ERROR;
            }
            createdTables_.insert(tableName);
        } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    }
    absSharedResultSet->Close();
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::Destroy()
{
    ANS_LOGD("Destory rdbStore");
    std::lock_guard<std::mutex> lock(createdTableMutex_);
    createdTables_.clear();
    int32_t ret = NativeRdb::RdbHelper::DeleteRdbStore(notificationRdbConfig_.dbPath + notificationRdbConfig_.dbName);
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("failed to destroy db store");
        return NativeRdb::E_ERROR;
    }
    ANS_LOGD("destroy db store successfully");
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::InsertData(const std::string &key, const std::string &value, const int32_t &userId)
{
    ANS_LOGD("InsertData start");
    {
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_11, EventBranchId::BRANCH_0);
        std::string tableName;
        int32_t ret = GetUserTableName(userId, tableName);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("Get user table name failed.");
            return NativeRdb::E_ERROR;
        }
        std::shared_ptr<NativeRdb::RdbStore> rdbConnection = GetConnection();
        if (rdbConnection == nullptr) {
            ANS_LOGE("notification rdb is null");
            return NativeRdb::E_ERROR;
        }
        int64_t rowId = -1;
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(NOTIFICATION_KEY, key);
        valuesBucket.PutString(NOTIFICATION_VALUE, value);
        ret = rdbConnection->InsertWithConflictResolution(rowId, tableName, valuesBucket,
            NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
        if (ret == NativeRdb::E_SQLITE_CORRUPT) {
            RestoreForMasterSlaver();
        }
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("Insert operation failed, result: %{public}d, key=%{public}s.", ret, key.c_str());
            message.ErrorCode(ret).Message("Insert operation failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            return NativeRdb::E_ERROR;
        }
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::InsertData(const std::string &key, const std::vector<uint8_t> &value,
    const int32_t &userId)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_10, EventBranchId::BRANCH_8);
    std::string tableName;
    int32_t ret = GetUserTableName(userId, tableName);
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("Get user table name failed.");
        return NativeRdb::E_ERROR;
    }
    std::shared_ptr<NativeRdb::RdbStore> rdbConnection = GetConnection();
    if (rdbConnection == nullptr) {
        ANS_LOGE("notification rdb is null");
        return NativeRdb::E_ERROR;
    }
    int64_t rowId = -1;
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(NOTIFICATION_KEY, key);
    valuesBucket.PutBlob(NOTIFICATION_VALUE, value);
    ret = rdbConnection->InsertWithConflictResolution(rowId, tableName, valuesBucket,
        NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    if (ret == NativeRdb::E_SQLITE_CORRUPT) {
            RestoreForMasterSlaver();
        }
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("Insert operation failed, result: %{public}d, key=%{public}s.", ret, key.c_str());
        message.ErrorCode(ret).Message("Insert operation failed.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::InsertBatchData(const std::unordered_map<std::string, std::string> &values,
    const int32_t &userId)
{
    ANS_LOGD("InsertBatchData start");
    {
        std::string tableName;
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_10, EventBranchId::BRANCH_7);
        int32_t ret = GetUserTableName(userId, tableName);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("Get user table name failed.");
            return NativeRdb::E_ERROR;
        }
        std::shared_ptr<NativeRdb::RdbStore> rdbConnection = GetConnection();
        if (rdbConnection == nullptr) {
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
        ret = rdbConnection->BatchInsert(rowId, tableName, buckets);
        if (ret == NativeRdb::E_SQLITE_CORRUPT) {
            RestoreForMasterSlaver();
        }
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("Insert batch operation failed, result: %{public}d.", ret);
            message.ErrorCode(ret).Message("Insert batch operation failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            return NativeRdb::E_ERROR;
        }
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::DeleteData(const std::string &key, const int32_t &userId)
{
    ANS_LOGD("DeleteData start");
    std::vector<std::string> operatedTables = GenerateOperatedTables(userId);
    std::reverse(operatedTables.begin(), operatedTables.end());

    int32_t ret = NativeRdb::E_OK;
    int32_t rowId = -1;
    for (auto tableName : operatedTables) {
        ret = DeleteData(tableName, key, rowId);
        if (ret != NativeRdb::E_OK) {
            return ret;
        }
    }
    return ret;
}

int32_t NotificationDataMgr::DeleteData(const std::string tableName, const std::string key, int32_t &rowId)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_10, EventBranchId::BRANCH_6);
    absRdbPredicates.EqualTo(NOTIFICATION_KEY, key);
    std::shared_ptr<NativeRdb::RdbStore> rdbConnection = GetConnection();
    if (rdbConnection == nullptr) {
        ANS_LOGE("notification rdb is null");
        return NativeRdb::E_ERROR;
    }
    int32_t ret = rdbConnection->Delete(rowId, absRdbPredicates);
    if (ret == NativeRdb::E_SQLITE_CORRUPT) {
        RestoreForMasterSlaver();
    }
    if (ret != NativeRdb::E_OK) {
        ANS_LOGW("Delete operation failed from %{public}s, result: %{public}d, key=%{public}s.",
            tableName.c_str(), ret, key.c_str());
        message.ErrorCode(ret).Message("Delete operation failed.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::DeleteBatchData(const std::vector<std::string> &keys, const int32_t &userId)
{
    ANS_LOGD("Delete Bathch Data start");
    {
        std::vector<std::string> operatedTables = GenerateOperatedTables(userId);
        std::reverse(operatedTables.begin(), operatedTables.end());
        std::shared_ptr<NativeRdb::RdbStore> rdbConnection = GetConnection();
        if (rdbConnection == nullptr) {
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
                int32_t ret = rdbConnection->Delete(rowId, absRdbPredicates);
                if (ret == NativeRdb::E_SQLITE_CORRUPT) {
                    RestoreForMasterSlaver();
                }
                if (ret != NativeRdb::E_OK) {
                    ANS_LOGW("Delete operation failed from %{public}s, result: %{public}d.",
                        tableName.c_str(), ret);
                    return NativeRdb::E_ERROR;
                }
            }
        }
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryData(const std::string &key, std::string &value, const int32_t &userId)
{
    ANS_LOGD("QueryData start");
    std::vector<std::string> operatedTables = GenerateOperatedTables(userId);
    int32_t ret = NativeRdb::E_OK;
    for (auto tableName : operatedTables) {
        ret = QueryData(tableName, key, value);
        if (ret != NativeRdb::E_EMPTY_VALUES_BUCKET) {
            return ret;
        }
    }
    return ret;
}

int32_t NotificationDataMgr::QueryData(const std::string tableName, const std::string key, std::string &value)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_10, EventBranchId::BRANCH_2);
    absRdbPredicates.EqualTo(NOTIFICATION_KEY, key);
    std::shared_ptr<NativeRdb::RdbStore> rdbConnection = GetConnection();
    if (rdbConnection == nullptr) {
        ANS_LOGE("notification rdb is null");
        return NativeRdb::E_ERROR;
    }
    auto absSharedResultSet = rdbConnection->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr) {
        ANS_LOGE("absSharedResultSet failed from %{public}s table.", tableName.c_str());
        return NativeRdb::E_ERROR;
    }

    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret == NativeRdb::E_SQLITE_CORRUPT) {
        RestoreForMasterSlaver();
    }
    if (ret != NativeRdb::E_OK) {
        ANS_LOGW("GoToFirstRow failed from %{public}s table. It is empty!, key=%{public}s",
            tableName.c_str(), key.c_str());
            if (ret != NativeRdb::E_ROW_OUT_RANGE) {
                ANS_LOGW("GoToFirstRow failed, rdb error is %{public}d.", ret);
                message.ErrorCode(ret).Message("GoToFirstRow failed.");
                NotificationAnalyticsUtil::ReportModifyEvent(message);
            }
        return NativeRdb::E_EMPTY_VALUES_BUCKET;
    }
    ret = absSharedResultSet->GetString(NOTIFICATION_VALUE_INDEX, value);
    if (ret == NativeRdb::E_SQLITE_CORRUPT) {
        RestoreForMasterSlaver();
    }
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("GetString value failed from %{public}s table.", tableName.c_str());
        message.ErrorCode(ret).Message("GetString value failed.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return NativeRdb::E_ERROR;
    }
    absSharedResultSet->Close();
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryData(const std::string &key, std::vector<uint8_t> &values, const int32_t &userId)
{
    std::vector<std::string> operatedTables = GenerateOperatedTables(userId);
    int32_t ret = NativeRdb::E_OK;
    for (auto tableName : operatedTables) {
        ret = QueryData(tableName, key, values);
        if (ret != NativeRdb::E_EMPTY_VALUES_BUCKET) {
            return ret;
        }
    }
    return ret;
}

int32_t NotificationDataMgr::QueryData(const std::string tableName, const std::string key, std::vector<uint8_t> &value)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_10, EventBranchId::BRANCH_3);
    absRdbPredicates.EqualTo(NOTIFICATION_KEY, key);
    std::shared_ptr<NativeRdb::RdbStore> rdbConnection = GetConnection();
    if (rdbConnection == nullptr) {
        ANS_LOGE("notification rdb is null");
        return NativeRdb::E_ERROR;
    }
    auto absSharedResultSet = rdbConnection->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr) {
        ANS_LOGE("absSharedResultSet failed from %{public}s table.", tableName.c_str());
        return NativeRdb::E_ERROR;
    }

    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret == NativeRdb::E_SQLITE_CORRUPT) {
        RestoreForMasterSlaver();
    }
    if (ret != NativeRdb::E_OK) {
        ANS_LOGW("GoToFirstRow failed from %{public}s table. It is empty!, key=%{public}s",
            tableName.c_str(), key.c_str());
        if (ret != NativeRdb::E_ROW_OUT_RANGE) {
            ANS_LOGW("GoToFirstRow failed, rdb error is %{public}d.", ret);
            message.ErrorCode(ret).Message("GoToFirstRow failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
        }
        return NativeRdb::E_EMPTY_VALUES_BUCKET;
    }
    ret = absSharedResultSet->GetBlob(NOTIFICATION_VALUE_INDEX, value);
    if (ret != NativeRdb::E_OK) {
        message.ErrorCode(ret).Message("GetString value failed.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("GetString value failed from %{public}s table.", tableName.c_str());
        return NativeRdb::E_ERROR;
    }
    absSharedResultSet->Close();

    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryDataBeginWithKey(
    const std::string &key, std::unordered_map<std::string, std::string> &values, const int32_t &userId)
{
    ANS_LOGD("QueryData BeginWithKey start");
    std::vector<std::string> operatedTables = GenerateOperatedTables(userId);
   
    int32_t ret = NativeRdb::E_OK;
    for (auto tableName : operatedTables) {
        ret = QueryDataBeginWithKey(tableName, key, values);
        if (ret == NativeRdb::E_ERROR) {
            return ret;
        }
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
    std::shared_ptr<NativeRdb::RdbStore> rdbConnection = GetConnection();
    if (rdbConnection == nullptr) {
        ANS_LOGE("notification rdb is null");
        return NativeRdb::E_ERROR;
    }
    auto absSharedResultSet = rdbConnection->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr) {
        ANS_LOGE("absSharedResultSet failed from %{public}s table.", tableName.c_str());
        return NativeRdb::E_ERROR;
    }

    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret == NativeRdb::E_SQLITE_CORRUPT) {
        RestoreForMasterSlaver();
    }
    if (ret != NativeRdb::E_OK) {
        ANS_LOGD("GoToFirstRow failed from %{public}s table.It is empty!, key=%{public}s",
            tableName.c_str(), key.c_str());
        if (ret != NativeRdb::E_ROW_OUT_RANGE) {
            ANS_LOGW("GoToFirstRow failed, rdb error is %{public}d.", ret);
            message.ErrorCode(ret).Message("GoToFirstRow failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
        }
        return NativeRdb::E_EMPTY_VALUES_BUCKET;
    }

    do {
        std::string resultKey;
        ret = absSharedResultSet->GetString(NOTIFICATION_KEY_INDEX, resultKey);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("Failed to GetString key from %{public}s table.", tableName.c_str());
            message.ErrorCode(ret).Message("GetString key failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            return NativeRdb::E_ERROR;
        }

        std::string resultValue;
        ret = absSharedResultSet->GetString(NOTIFICATION_VALUE_INDEX, resultValue);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("GetString value failed from %{public}s table", tableName.c_str());
            message.ErrorCode(ret).Message("GetString value failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            return NativeRdb::E_ERROR;
        }

        values.emplace(resultKey, resultValue);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    absSharedResultSet->Close();

    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryAllData(std::unordered_map<std::string, std::string> &datas, const int32_t &userId)
{
    ANS_LOGD("QueryAllData start");
    std::vector<std::string> operatedTables = GenerateOperatedTables(userId);
    int32_t ret = NativeRdb::E_OK;
    for (auto tableName : operatedTables) {
        ret = QueryAllData(tableName,  datas);
        if (ret == NativeRdb::E_ERROR) {
            return ret;
        }
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
    std::shared_ptr<NativeRdb::RdbStore> rdbConnection = GetConnection();
    if (rdbConnection == nullptr) {
        ANS_LOGE("notification rdb is null");
        return NativeRdb::E_ERROR;
    }
    auto absSharedResultSet = rdbConnection->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr) {
        ANS_LOGE("absSharedResultSet failed from %{public}s table.", tableName.c_str());
        return NativeRdb::E_ERROR;
    }

    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret == NativeRdb::E_SQLITE_CORRUPT) {
        RestoreForMasterSlaver();
    }
    if (ret != NativeRdb::E_OK) {
        ANS_LOGD("GoToFirstRow failed from %{public}s table. It is empty!", tableName.c_str());
        if (ret != NativeRdb::E_ROW_OUT_RANGE) {
            ANS_LOGW("GoToFirstRow failed, rdb error is %{public}d.", ret);
            message.ErrorCode(ret).Message("GoToFirstRow failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
        }
        return NativeRdb::E_EMPTY_VALUES_BUCKET;
    }

    do {
        std::string resultKey;
        ret = absSharedResultSet->GetString(NOTIFICATION_KEY_INDEX, resultKey);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("GetString key failed from %{public}s table.", tableName.c_str());
            message.ErrorCode(ret).Message("GetString key failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            return NativeRdb::E_ERROR;
        }

        std::string resultValue;
        ret = absSharedResultSet->GetString(NOTIFICATION_VALUE_INDEX, resultValue);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("GetString value failed from %{public}s table.", tableName.c_str());
            message.ErrorCode(ret).Message("GetString value failed.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            return NativeRdb::E_ERROR;
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
    std::lock_guard<std::mutex> lock(createdTableMutex_);
    int32_t ret = NativeRdb::E_OK;
    {
        std::shared_ptr<NativeRdb::RdbStore> rdbConnection = GetConnection();
        if (rdbConnection == nullptr) {
            return NativeRdb::E_ERROR;
        }
        std::string dropTableSql = "DROP TABLE IF EXISTS " + tableName;
        ret = rdbConnection->ExecuteSql(dropTableSql);
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
    std::shared_ptr<NativeRdb::RdbStore> rdbConnection = GetConnection();
    if (rdbConnection == nullptr) {
        return NativeRdb::E_ERROR;
    }

    const char *keySpliter = "_";
    std::stringstream stream;
    stream << notificationRdbConfig_.tableName << keySpliter << userId;
    tableName = stream.str();
    if (createdTables_.find(tableName) == createdTables_.end()) {
        std::lock_guard<std::mutex> lock(createdTableMutex_);
        if (createdTables_.find(tableName) == createdTables_.end()) {
            std::string createTableSql = "CREATE TABLE IF NOT EXISTS " + tableName
                + " (KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL);";
            int32_t ret = rdbConnection->ExecuteSql(createTableSql);
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
        std::lock_guard<std::mutex> lock(createdTableMutex_);
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
        .ErrorCode(NativeRdb::E_SQLITE_CORRUPT).Message("Rdb is corruped.");
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    ANS_LOGI("RestoreForMasterSlaver start");
    std::shared_ptr<NativeRdb::RdbStore> rdbConnection = GetConnection();
    int32_t result =  rdbConnection->Restore("");
    ANS_LOGI("RestoreForMasterSlaver result = %{public}d", result);
    return result;
}
}
}