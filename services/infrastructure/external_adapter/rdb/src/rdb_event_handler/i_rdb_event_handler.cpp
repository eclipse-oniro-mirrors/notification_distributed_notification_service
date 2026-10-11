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

#include "i_rdb_event_handler.h"
#include <cstdlib>
#include "ans_log_wrapper.h"
#include "notification_rdb_constant.h"
#include "rdb_errno.h"
#include "rdb_predicates.h"
#include "rdb_store.h"

namespace OHOS::Notification::Infra {
namespace {
const std::string NOTIFICATION_KEY_COLUMN = "KEY";
const std::string NOTIFICATION_VALUE_COLUMN = "VALUE";

int32_t ReadCrashInterruptCount(NativeRdb::RdbStore &rdbStore, const std::string &markKey)
{
    NativeRdb::AbsRdbPredicates predicates(NtfRdbConstant::NOTIFICATION_RDB_TABLE_NAME);
    predicates.EqualTo(NOTIFICATION_KEY_COLUMN, markKey);
    auto resultSet = rdbStore.Query(predicates, std::vector<std::string>());
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        if (resultSet != nullptr) {
            resultSet->Close();
        }
        return 0;
    }
    std::string value;
    int32_t ret = resultSet->GetString(1, value);
    resultSet->Close();
    if (ret != NativeRdb::E_OK || value.empty()) {
        return 0;
    }
    int32_t count = static_cast<int32_t>(std::strtol(value.c_str(), nullptr, 10));
    return count < 0 ? 0 : count;
}

void WriteCrashInterruptCount(NativeRdb::RdbStore &rdbStore, const std::string &markKey, int32_t count)
{
    if (count <= 0) {
        NativeRdb::RdbPredicates predicates(NtfRdbConstant::NOTIFICATION_RDB_TABLE_NAME);
        predicates.EqualTo(NOTIFICATION_KEY_COLUMN, markKey);
        int32_t deletedRows = 0;
        int32_t deleteRet = rdbStore.Delete(deletedRows, predicates);
        if (deleteRet != NativeRdb::E_OK) {
            ANS_LOGE("Failed to clear migration mark, ret=%{public}d", deleteRet);
        }
        return;
    }

    int64_t rowId = -1;
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(NOTIFICATION_KEY_COLUMN, markKey);
    valuesBucket.PutString(NOTIFICATION_VALUE_COLUMN, std::to_string(count));
    int32_t insertRet = rdbStore.InsertWithConflictResolution(rowId,
        NtfRdbConstant::NOTIFICATION_RDB_TABLE_NAME, valuesBucket,
        NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    if (insertRet != NativeRdb::E_OK) {
        ANS_LOGE("Failed to set migration mark, ret=%{public}d", insertRet);
    }
}
} // namespace

int32_t IRdbEventHandler::OnCreate(NativeRdb::RdbStore &rdbStore)
{
    return NativeRdb::E_OK;
}

int32_t IRdbEventHandler::OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion)
{
    return NativeRdb::E_OK;
}

int32_t IRdbEventHandler::OnDowngrade(NativeRdb::RdbStore &rdbStore, int32_t currentVersion, int32_t targetVersion)
{
    return NativeRdb::E_OK;
}

int32_t IRdbEventHandler::OnOpen(NativeRdb::RdbStore &rdbStore)
{
    return NativeRdb::E_OK;
}

int32_t IRdbEventHandler::OnCorruption(const std::string &databaseFile)
{
    return NativeRdb::E_OK;
}

int32_t IRdbEventHandler::OnUpgradeFailure(NativeRdb::RdbStore &rdbStore)
{
    (void)rdbStore;
    return NativeRdb::E_OK;
}

std::string IRdbEventHandler::GetMigrationMarkKey() const
{
    return "";
}

int32_t IRdbEventHandler::ExecuteUpgradeWithCrashRecovery(NativeRdb::RdbStore &rdbStore,
    int32_t oldVersion, int32_t newVersion)
{
    std::string markKey = GetMigrationMarkKey();
    if (markKey.empty()) {
        return OnUpgrade(rdbStore, oldVersion, newVersion);
    }

    int32_t crashCount = ReadCrashInterruptCount(rdbStore, markKey);
    if (crashCount > 0 && crashCount < NtfRdbConstant::NOTIFICATION_RDB_CRASH_CLEANUP_THRESHOLD) {
        ANS_LOGW("Handler %{public}s migration was crash-interrupted %{public}d time(s), retrying",
            GetHandlerName().c_str(), crashCount);
    } else if (crashCount >= NtfRdbConstant::NOTIFICATION_RDB_CRASH_CLEANUP_THRESHOLD) {
        ANS_LOGE("Handler %{public}s migration crash-interrupted %{public}d times, cleaning its data",
            GetHandlerName().c_str(), crashCount);
        int32_t cleanupRet = OnUpgradeFailure(rdbStore);
        if (cleanupRet != NativeRdb::E_OK) {
            ANS_LOGE("Handler %{public}s cleanup failed, ret=%{public}d, skip its migration to avoid "
                     "crash-restart loop and keep its data in the old format",
                GetHandlerName().c_str(), cleanupRet);
            WriteCrashInterruptCount(rdbStore, markKey, 0);
            return NativeRdb::E_OK;
        }
        crashCount = 0;
    }

    WriteCrashInterruptCount(rdbStore, markKey, crashCount + 1);
    int32_t ret = OnUpgrade(rdbStore, oldVersion, newVersion);
    WriteCrashInterruptCount(rdbStore, markKey, 0);
    return ret;
}

bool IRdbEventHandler::IsEnabled() const
{
    return enabled_;
}

void IRdbEventHandler::SetEnabled(bool enabled)
{
    enabled_ = enabled;
}
} // namespace OHOS::Notification::Infra