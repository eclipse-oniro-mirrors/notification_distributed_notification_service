/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

namespace OHOS {
namespace Notification {
namespace {
const std::string NOTIFICATION_KEY = "KEY";
const std::string NOTIFICATION_VALUE = "VALUE";
const int32_t NOTIFICATION_KEY_INDEX = 0;
const int32_t NOTIFICATION_VALUE_INDEX = 1;
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
    ANS_LOGD("OnUpgrade currentVersion: %{plubic}d, targetVersion: %{plubic}d",
        oldVersion, newVersion);
    return NativeRdb::E_OK;
}

int32_t RdbStoreDataCallBackNotificationStorage::OnDowngrade(
    NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion)
{
    ANS_LOGD("OnDowngrade  currentVersion: %{plubic}d, targetVersion: %{plubic}d",
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

    int32_t ret = NativeRdb::E_OK;
    if (rdbStore_ != nullptr) {
        ANS_LOGD("notification rdb has existed");
        return NativeRdb::E_OK;
    }

    NativeRdb::RdbStoreConfig rdbStoreConfig(
            notificationRdbConfig_.dbPath + notificationRdbConfig_.dbName,
            NativeRdb::StorageMode::MODE_DISK,
            false,
            std::vector<uint8_t>(),
            notificationRdbConfig_.journalMode,
            notificationRdbConfig_.syncMode);
    RdbStoreDataCallBackNotificationStorage rdbDataCallBack_(notificationRdbConfig_);
    rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(
        rdbStoreConfig, notificationRdbConfig_.version, rdbDataCallBack_, ret);
    if (rdbStore_ == nullptr) {
        ANS_LOGE("notification rdb init fail");
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::Destroy()
{
    ANS_LOGD("Destory rdbStore");

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
    ANS_LOGD("destroy db store successfully");
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::InsertData(const std::string &key, const std::string &value)
{
    ANS_LOGD("InsertData start");
    if (rdbStore_ == nullptr) {
        ANS_LOGE("notification rdb is null");
        return NativeRdb::E_ERROR;
    }
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        int64_t rowId = -1;
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(NOTIFICATION_KEY, key);
        valuesBucket.PutString(NOTIFICATION_VALUE, value);
        int32_t ret = rdbStore_->InsertWithConflictResolution(
            rowId, notificationRdbConfig_.tableName, valuesBucket,
            NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("Insert operation failed, result: %{public}d, key=%{public}s.", ret, key.c_str());
            return NativeRdb::E_ERROR;
        }
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::InsertBatchData(const std::unordered_map<std::string, std::string> &values)
{
    ANS_LOGD("InsertBatchData start");
    if (rdbStore_ == nullptr) {
        ANS_LOGE("notification rdb is null");
        return NativeRdb::E_ERROR;
    }
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        int64_t rowId = -1;
        for (auto &value : values) {
            NativeRdb::ValuesBucket valuesBucket;
            valuesBucket.PutString(NOTIFICATION_KEY, value.first);
            valuesBucket.PutString(NOTIFICATION_VALUE, value.second);
            int32_t ret = rdbStore_->InsertWithConflictResolution(
                rowId, notificationRdbConfig_.tableName, valuesBucket,
                NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
            if (ret != NativeRdb::E_OK) {
                ANS_LOGE("Insert batch operation failed, result: %{public}d.", ret);
                return NativeRdb::E_ERROR;
            }
        }
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::DeleteData(const std::string &key)
{
    ANS_LOGD("DeleteData start");
    if (rdbStore_ == nullptr) {
        ANS_LOGE("notification rdb is null");
        return NativeRdb::E_ERROR;
    }
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        int32_t rowId = -1;
        NativeRdb::AbsRdbPredicates absRdbPredicates(notificationRdbConfig_.tableName);
        absRdbPredicates.EqualTo(NOTIFICATION_KEY, key);
        int32_t ret = rdbStore_->Delete(rowId, absRdbPredicates);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("Delete operation failed, result: %{public}d, key=%{public}s.",
                ret, key.c_str());
            return NativeRdb::E_ERROR;
        }
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::DeleteBathchData(const std::vector<std::string> &keys)
{
    ANS_LOGD("Delete Bathch Data start");
    if (rdbStore_ == nullptr) {
        ANS_LOGE("notification rdb is null");
        return NativeRdb::E_ERROR;
    }
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        for (auto key : keys) {
            NativeRdb::AbsRdbPredicates absRdbPredicates(notificationRdbConfig_.tableName);
            int32_t rowId = -1;
            absRdbPredicates.EqualTo(NOTIFICATION_KEY, key);
            int32_t ret = rdbStore_->Delete(rowId, absRdbPredicates);
            if (ret != NativeRdb::E_OK) {
                ANS_LOGE("Delete Batch operation failed, result: %{public}d, key=%{public}s.",
                    ret, key.c_str());
                return NativeRdb::E_ERROR;
            }
        }
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryData(const std::string &key, std::string &value)
{
    ANS_LOGD("QueryData start");
    if (rdbStore_ == nullptr) {
        ANS_LOGE("notification rdb is null");
        return NativeRdb::E_ERROR;
    }
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        NativeRdb::AbsRdbPredicates absRdbPredicates(notificationRdbConfig_.tableName);
        absRdbPredicates.EqualTo(NOTIFICATION_KEY, key);
        auto absSharedResultSet = rdbStore_->Query(absRdbPredicates, std::vector<std::string>());
        if (absSharedResultSet == nullptr || !absSharedResultSet->HasBlock()) {
            ANS_LOGD("absSharedResultSet failed");
            return NativeRdb::E_ERROR;
        }

        int32_t ret = absSharedResultSet->GoToFirstRow();
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("GoToFirstRow failed.It is empty!, key=%{public}s", key.c_str());
            return NativeRdb::E_EMPTY_VALUES_BUCKET;
        }
        ret = absSharedResultSet->GetString(NOTIFICATION_VALUE_INDEX, value);
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("GetString value failed");
            return NativeRdb::E_ERROR;
        }
        absSharedResultSet->Close();
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryDataBeginWithKey(
    const std::string &key, std::unordered_map<std::string, std::string> &values)
{
    ANS_LOGD("QueryData BeginWithKey start");
    if (rdbStore_ == nullptr) {
        ANS_LOGE("notification rdb is null");
        return NativeRdb::E_ERROR;
    }
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        NativeRdb::AbsRdbPredicates absRdbPredicates(notificationRdbConfig_.tableName);
        absRdbPredicates.BeginsWith(NOTIFICATION_KEY, key);
        auto absSharedResultSet = rdbStore_->Query(absRdbPredicates, std::vector<std::string>());
        if (absSharedResultSet == nullptr || !absSharedResultSet->HasBlock()) {
            ANS_LOGE("absSharedResultSet failed");
            return NativeRdb::E_ERROR;
        }

        int32_t ret = absSharedResultSet->GoToFirstRow();
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("GoToFirstRow failed.It is empty!, key=%{public}s", key.c_str());
            return NativeRdb::E_EMPTY_VALUES_BUCKET;
        }

        do {
            std::string resultKey;
            ret = absSharedResultSet->GetString(NOTIFICATION_KEY_INDEX, resultKey);
            if (ret != NativeRdb::E_OK) {
                ANS_LOGE("GetString key failed");
                return NativeRdb::E_ERROR;
            }

            std::string resultValue;
            ret = absSharedResultSet->GetString(NOTIFICATION_VALUE_INDEX, resultValue);
            if (ret != NativeRdb::E_OK) {
                ANS_LOGE("GetString value failed");
                return NativeRdb::E_ERROR;
            }

            values.emplace(resultKey, resultValue);
        } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
        absSharedResultSet->Close();
    }

    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryAllData(std::unordered_map<std::string, std::string> &datas)
{
    ANS_LOGD("QueryAllData start");
    if (rdbStore_ == nullptr) {
        ANS_LOGE("notification rdb is null");
        return NativeRdb::E_ERROR;
    }
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        NativeRdb::AbsRdbPredicates absRdbPredicates(notificationRdbConfig_.tableName);
        auto absSharedResultSet = rdbStore_->Query(absRdbPredicates, std::vector<std::string>());
        if (absSharedResultSet == nullptr || !absSharedResultSet->HasBlock()) {
            ANS_LOGE("absSharedResultSet failed");
            return NativeRdb::E_ERROR;
        }

        int32_t ret = absSharedResultSet->GoToFirstRow();
        if (ret != NativeRdb::E_OK) {
            ANS_LOGE("GoToFirstRow failed. It is empty!");
            return NativeRdb::E_EMPTY_VALUES_BUCKET;
        }

        do {
            std::string resultKey;
            ret = absSharedResultSet->GetString(NOTIFICATION_KEY_INDEX, resultKey);
            if (ret != NativeRdb::E_OK) {
                ANS_LOGE("GetString key failed");
                return NativeRdb::E_ERROR;
            }

            std::string resultValue;
            ret = absSharedResultSet->GetString(NOTIFICATION_VALUE_INDEX, resultValue);
            if (ret != NativeRdb::E_OK) {
                ANS_LOGE("GetString value failed");
                return NativeRdb::E_ERROR;
            }

            datas.emplace(resultKey, resultValue);
        } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
        absSharedResultSet->Close();
    }
    return NativeRdb::E_OK;
}
}
}