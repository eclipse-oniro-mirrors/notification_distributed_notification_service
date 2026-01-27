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

#ifndef ANS_NOTIFICATION_MOCK_RDB_STORE_H
#define ANS_NOTIFICATION_MOCK_RDB_STORE_H
#include "rdb_store.h"
namespace OHOS::Notification::Infra {
class MockRdbStore : public NativeRdb::RdbStore {
public:
    using AbsSharedResultSetPtr = std::shared_ptr<NativeRdb::AbsSharedResultSet>;

    AbsSharedResultSetPtr QuerySql(const std::string &querySql, const Values &args = {}) override;
    int ExecuteSql(const std::string &sql, const Values &args = {}) override;
    int32_t InsertWithConflictResolution(
        int64_t &rowId,
        const std::string &tableName,
        const NativeRdb::ValuesBucket &values,
        NativeRdb::ConflictResolution conflictResolution) override;
    int BatchInsert(int64_t &rowId, const std::string &tableName, const Rows &rows) override;
    int Restore(const std::string &backupPath, const std::vector<uint8_t> &newKey = {}) override;
    int Delete(int &rowId, const NativeRdb::AbsRdbPredicates &predicates) override;
    AbsSharedResultSetPtr Query(
        const NativeRdb::AbsRdbPredicates &predicates, const Fields &columns) override;

    int GetVersion(int &version) override
    {
        return 0;
    }

    int SetVersion(int version) override
    {
        (void)version;
        return 0;
    }
};

void SetMockQuerySqlResults(const std::vector<MockRdbStore::AbsSharedResultSetPtr> &results);
void SetMockExecuteSqlErrCodes(const std::vector<int> &errCodes);
void SetMockInsertWithConflictResolutionErrCodes(const std::vector<int32_t> &errCodes);
void SetMockBatchInsertErrCodes(const std::vector<int32_t> &errCodes);
void SetMockReStoreErrCodes(const std::vector<int> &errCodes);
void SetMockDeleteErrCodes(const std::vector<int> &errCodes);
void SetMockQueryResults(const std::vector<MockRdbStore::AbsSharedResultSetPtr> &results);
void ResetMockRdbStore();
} // namespace OHOS::Notification::Infra
#endif // ANS_NOTIFICATION_MOCK_RDB_STORE_H