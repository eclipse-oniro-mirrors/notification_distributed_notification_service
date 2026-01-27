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

#include "mock_rdb_store.h"

namespace OHOS::Notification::Infra {
namespace {

int g_mockQuerySqlExecuteTimes = 0;
std::vector<MockRdbStore::AbsSharedResultSetPtr> g_mockQuerySqlResults = {nullptr};

int g_mockExecuteSqlExecuteTimes = 0;
std::vector<int> g_mockExecuteSqlErrCodes = {NativeRdb::E_OK};

int g_mockInsertWithConflictResolutionExecuteTimes = 0;
std::vector<int32_t> g_mockInsertWithConflictResolutionErrCodes = {NativeRdb::E_OK};

int g_mockBatchInsertExecuteTimes = 0;
std::vector<int32_t> g_mockBatchInsertErrCodes = {NativeRdb::E_OK};

int g_mockReStoreExecuteTimes = 0;
std::vector<int> g_mockReStoreErrCodes = {NativeRdb::E_OK};

int g_mockDeleteExecuteTimes = 0;
std::vector<int> g_mockDeleteErrCodes = {NativeRdb::E_OK};

int g_mockQueryExecuteTimes = 0;
std::vector<MockRdbStore::AbsSharedResultSetPtr> g_mockQueryResults = {nullptr};
}

MockRdbStore::AbsSharedResultSetPtr MockRdbStore::QuerySql(
    const std::string &querySql, const Values &args)
{
    (void)querySql;
    (void)args;
    if (g_mockQuerySqlResults.empty()) {
        return nullptr;
    }
    if (g_mockQuerySqlExecuteTimes < static_cast<int>(g_mockQuerySqlResults.size())) {
        return g_mockQuerySqlResults[g_mockQuerySqlExecuteTimes++];
    }
    return g_mockQuerySqlResults.back();
}

void SetMockQuerySqlResults(const std::vector<MockRdbStore::AbsSharedResultSetPtr> &results)
{
    g_mockQuerySqlResults = results;
    g_mockQuerySqlExecuteTimes = 0;
}

int MockRdbStore::ExecuteSql(const std::string &sql, const Values &args)
{
    (void)sql;
    if (g_mockExecuteSqlErrCodes.empty()) {
        return NativeRdb::E_ERROR;
    }
    if (g_mockExecuteSqlExecuteTimes < static_cast<int>(g_mockExecuteSqlErrCodes.size())) {
        return g_mockExecuteSqlErrCodes[g_mockExecuteSqlExecuteTimes++];
    }
    return g_mockExecuteSqlErrCodes.back();
}

void SetMockExecuteSqlErrCodes(const std::vector<int> &errCodes)
{
    g_mockExecuteSqlErrCodes = errCodes;
    g_mockExecuteSqlExecuteTimes = 0;
}


int32_t MockRdbStore::InsertWithConflictResolution(
    int64_t &rowId,
    const std::string &tableName,
    const NativeRdb::ValuesBucket &values,
    NativeRdb::ConflictResolution conflictResolution)
{
    (void)rowId;
    (void)tableName;
    (void)values;
    (void)conflictResolution;
    if (g_mockInsertWithConflictResolutionErrCodes.empty()) {
        return NativeRdb::E_ERROR;
    }
    if (g_mockInsertWithConflictResolutionExecuteTimes <
        static_cast<int>(g_mockInsertWithConflictResolutionErrCodes.size())) {
        return g_mockInsertWithConflictResolutionErrCodes[g_mockInsertWithConflictResolutionExecuteTimes++];
    }
    return g_mockInsertWithConflictResolutionErrCodes.back();
}

void SetMockInsertWithConflictResolutionErrCodes(const std::vector<int32_t> &errCodes)
{
    g_mockInsertWithConflictResolutionErrCodes = errCodes;
    g_mockInsertWithConflictResolutionExecuteTimes = 0;
}

int MockRdbStore::BatchInsert(int64_t &rowId, const std::string &tableName, const Rows &rows)
{
    (void)rowId;
    (void)tableName;
    (void)rows;
    if (g_mockBatchInsertErrCodes.empty()) {
        return NativeRdb::E_ERROR;
    }
    if (g_mockBatchInsertExecuteTimes < static_cast<int>(g_mockBatchInsertErrCodes.size())) {
        return g_mockBatchInsertErrCodes[g_mockInsertWithConflictResolutionExecuteTimes++];
    }
    return g_mockBatchInsertErrCodes.back();
}

void SetMockBatchInsertErrCodes(const std::vector<int32_t> &errCodes)
{
    g_mockBatchInsertErrCodes = errCodes;
    g_mockBatchInsertExecuteTimes = 0;
}

int MockRdbStore::Restore(const std::string &backupPath, const std::vector<uint8_t> &newKey)
{
    (void)backupPath;
    (void)newKey;
    if (g_mockReStoreErrCodes.empty()) {
        return NativeRdb::E_ERROR;
    }
    if (g_mockReStoreExecuteTimes < static_cast<int>(g_mockReStoreErrCodes.size())) {
        return g_mockReStoreErrCodes[g_mockReStoreExecuteTimes++];
    }
    return g_mockReStoreErrCodes.back();
}

void SetMockReStoreErrCodes(const std::vector<int> &errCodes)
{
    g_mockReStoreErrCodes = errCodes;
    g_mockReStoreExecuteTimes = 0;
}


int MockRdbStore::Delete(int &rowId, const NativeRdb::AbsRdbPredicates &predicates)
{
    (void)rowId;
    (void)predicates;
    if (g_mockDeleteErrCodes.empty()) {
        return NativeRdb::E_ERROR;
    }
    if (g_mockDeleteExecuteTimes < static_cast<int>(g_mockDeleteErrCodes.size())) {
        return g_mockDeleteErrCodes[g_mockDeleteExecuteTimes++];
    }
    return g_mockDeleteErrCodes.back();
}

void SetMockDeleteErrCodes(const std::vector<int> &errCodes)
{
    g_mockDeleteErrCodes = errCodes;
    g_mockDeleteExecuteTimes = 0;
}


MockRdbStore::AbsSharedResultSetPtr MockRdbStore::Query(
    const NativeRdb::AbsRdbPredicates &predicates, const Fields &columns)
{
    (void)predicates;
    (void)columns;
    if (g_mockQueryResults.empty()) {
        return nullptr;
    }
    if (g_mockQueryExecuteTimes < static_cast<int>(g_mockQueryResults.size())) {
        return g_mockQueryResults[g_mockQueryExecuteTimes++];
    }
    return g_mockQueryResults.back();
}

void SetMockQueryResults(const std::vector<MockRdbStore::AbsSharedResultSetPtr> &results)
{
    g_mockQueryResults = results;
    g_mockQueryExecuteTimes = 0;
}

void ResetMockRdbStore()
{
    g_mockQuerySqlResults = {nullptr};
    g_mockQuerySqlExecuteTimes = 0;

    g_mockExecuteSqlErrCodes = {NativeRdb::E_OK};
    g_mockExecuteSqlExecuteTimes = 0;

    g_mockInsertWithConflictResolutionErrCodes = {NativeRdb::E_OK};
    g_mockInsertWithConflictResolutionExecuteTimes = 0;

    g_mockBatchInsertErrCodes = {NativeRdb::E_OK};
    g_mockBatchInsertExecuteTimes = 0;

    g_mockReStoreErrCodes = {NativeRdb::E_OK};
    g_mockReStoreExecuteTimes = 0;

    g_mockDeleteErrCodes = {NativeRdb::E_OK};
    g_mockDeleteExecuteTimes = 0;

    g_mockQueryResults = {nullptr};
    g_mockQueryExecuteTimes = 0;
}
} // namespace OHOS::Notification::Infra