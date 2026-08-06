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

#include "mock_notification_rdb_data_mgr.h"

#include <map>
#include <utility>

#include "notification_rdb_data_mgr.h"
#include "notification_rdb_mgr.h"
#include "rdb_errno.h"
#include "rdb_store_wrapper.h"

namespace OHOS {
namespace Notification {
namespace {
    bool g_mockInitRet = true;
    int32_t g_mockQueryDataRet = 0;
    bool g_mockInsertDataRet = true;
    bool g_mockInsertBatchDataRet = true;
    bool g_mockQueryDataBeginWithKeyRet = true;
    bool g_mockDeleteBatchDataRet = true;
    bool g_mockDeleteDataRet = true;
    bool g_mockQueryAllData = true;
    bool g_mockDropTable = true;
    bool g_mockInsertStatisticsDataRet = true;
    bool g_mockQueryStatisticsByBundleRet = true;
    bool g_mockUpdateStatisticsTimeRet = true;
    bool g_mockDropStatisticsTableRet = true;
    bool g_mockCleanStatisticsExperDataRet = true;
    bool g_mockDeleteStatisticsByBundleRet = true;
    std::string g_mockDataValue;
    std::unordered_map<std::string, std::string> g_mockDataValues;

    struct StatisticsState {
        int32_t count {0};
        int64_t lastTime {0};
    };
    std::map<std::pair<int32_t, int32_t>, StatisticsState> g_statisticsState;
}

void MockInit(bool mockRet)
{
    g_mockInitRet = mockRet;
}

void MockQueryData(int32_t mockRet)
{
    g_mockQueryDataRet = mockRet;
}

void MockSetDataValue(std::string value)
{
    g_mockDataValue = value;
}

void MockSetDataValues(std::unordered_map<std::string, std::string> &values)
{
    g_mockDataValues = values;
}

void MockInsertData(bool mockRet)
{
    g_mockInsertDataRet = mockRet;
}

void MockInsertBatchData(bool mockRet)
{
    g_mockInsertBatchDataRet = mockRet;
}

void MockQueryDataBeginWithKey(bool mockRet)
{
    g_mockQueryDataBeginWithKeyRet = mockRet;
}

void MockDeleteBatchData(bool mockRet)
{
    g_mockDeleteBatchDataRet = mockRet;
}

void MockDeleteData(bool mockRet)
{
    g_mockDeleteDataRet = mockRet;
}

void MockQueryAllData(bool mockRet)
{
    g_mockQueryAllData = mockRet;
}

void MockDropTable(bool mockRet)
{
    g_mockDropTable = mockRet;
}

void MockInsertStatisticsData(bool mockRet)
{
    g_mockInsertStatisticsDataRet = mockRet;
}

void MockQueryStatisticsByBundle(bool mockRet)
{
    g_mockQueryStatisticsByBundleRet = mockRet;
}

void MockUpdateStatisticsTime(bool mockRet)
{
    g_mockUpdateStatisticsTimeRet = mockRet;
}

void MockDropStatisticsTable(bool mockRet)
{
    g_mockDropStatisticsTableRet = mockRet;
}

void MockCleanStatisticsExperData(bool mockRet)
{
    g_mockCleanStatisticsExperDataRet = mockRet;
}

void MockDeleteStatisticsByBundle(bool mockRet)
{
    g_mockDeleteStatisticsByBundleRet = mockRet;
}

void MockClearStatisticsState()
{
    g_statisticsState.clear();
}

int32_t NotificationDataMgr::Init()
{
    if (g_mockInitRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::Destroy()
{
    if (g_mockInitRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryData(const std::string &key, std::string &value, const int32_t &userId)
{
    value = g_mockDataValue;
    return g_mockQueryDataRet;
}

int32_t NotificationDataMgr::InsertData(const std::string &key, const std::string &value, const int32_t &userId)
{
    if (g_mockInsertDataRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::InsertBatchData(const std::unordered_map<std::string, std::string> &values,
    const int32_t &userId)
{
    if (g_mockInsertBatchDataRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryDataBeginWithKey(
    const std::string &key, std::unordered_map<std::string, std::string> &values, const int32_t &userId)
{
    if (g_mockQueryDataBeginWithKeyRet == false) {
        return NativeRdb::E_ERROR;
    }
    values = g_mockDataValues;
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::DeleteBatchData(const std::vector<std::string> &keys, const int32_t &userId)
{
    if (g_mockDeleteBatchDataRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::DeleteData(const std::string &key, const int32_t &userId)
{
    if (g_mockDeleteDataRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryAllData(std::unordered_map<std::string, std::string> &values, const int32_t &userId)
{
    if (g_mockQueryAllData == false) {
        return NativeRdb::E_ERROR;
    }
    values = g_mockDataValues;
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::DropUserTable(const int32_t userId)
{
    if (g_mockDropTable == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

namespace Infra {
int32_t NotificationRdbMgr::Init()
{
    if (g_mockInitRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationRdbMgr::Destroy()
{
    if (g_mockInitRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationRdbMgr::QueryData(const std::string &key, std::string &value, const int32_t &userId)
{
    value = g_mockDataValue;
    return g_mockQueryDataRet;
}

int32_t NotificationRdbMgr::InsertData(const std::string &key, const std::string &value, const int32_t &userId)
{
    if (g_mockInsertDataRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationRdbMgr::InsertBatchData(const std::unordered_map<std::string, std::string> &values,
    const int32_t &userId)
{
    if (g_mockInsertBatchDataRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationRdbMgr::QueryDataBeginWithKey(
    const std::string &key, std::unordered_map<std::string, std::string> &values, const int32_t &userId)
{
    if (g_mockQueryDataBeginWithKeyRet == false) {
        return NativeRdb::E_ERROR;
    }
    values = g_mockDataValues;
    return NativeRdb::E_OK;
}

int32_t NotificationRdbMgr::DeleteBatchData(const std::vector<std::string> &keys, const int32_t userId)
{
    if (g_mockDeleteBatchDataRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationRdbMgr::DeleteData(const std::string &key, const int32_t &userId)
{
    if (g_mockDeleteDataRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationRdbMgr::QueryAllData(std::unordered_map<std::string, std::string> &values, const int32_t &userId)
{
    if (g_mockQueryAllData == false) {
        return NativeRdb::E_ERROR;
    }
    values = g_mockDataValues;
    return NativeRdb::E_OK;
}

int32_t NotificationRdbMgr::DropUserTable(const int32_t userId)
{
    if (g_mockDropTable == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationRdbMgr::InsertStatisticsData(const int32_t userId, const struct StatisticsWrapperInfo &info)
{
    if (g_mockInsertStatisticsDataRet == false) {
        return NativeRdb::E_ERROR;
    }
    auto key = std::make_pair(userId, info.uid);
    auto &state = g_statisticsState[key];
    state.count += 1;
    state.lastTime = info.notificationTime;
    return NativeRdb::E_OK;
}

int32_t NotificationRdbMgr::QueryStatisticsByBundle(const int32_t bundleUid,
    const int32_t uid, const int64_t beginTime, int32_t &totalCount, int64_t &lastTime)
{
    totalCount = 0;
    lastTime = 0;
    if (g_mockQueryStatisticsByBundleRet == false) {
        return NativeRdb::E_ERROR;
    }
    auto it = g_statisticsState.find(std::make_pair(uid, bundleUid));
    if (it != g_statisticsState.end()) {
        totalCount = it->second.count;
        lastTime = it->second.lastTime;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationRdbMgr::UpdateStatisticsTime(const int32_t userId, int64_t offsetMs)
{
    if (g_mockUpdateStatisticsTimeRet == false) {
        return NativeRdb::E_ERROR;
    }
    for (auto &entry : g_statisticsState) {
        if (entry.first.first == userId) {
            entry.second.lastTime += offsetMs;
        }
    }
    return NativeRdb::E_OK;
}

int32_t NotificationRdbMgr::DropStatisticsTable(const int32_t userId)
{
    if (g_mockDropStatisticsTableRet == false) {
        return NativeRdb::E_ERROR;
    }
    for (auto it = g_statisticsState.begin(); it != g_statisticsState.end();) {
        if (it->first.first == userId) {
            it = g_statisticsState.erase(it);
        } else {
            ++it;
        }
    }
    return NativeRdb::E_OK;
}

int32_t NotificationRdbMgr::CleanStatisticsExperData(const int32_t userId)
{
    if (g_mockCleanStatisticsExperDataRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationRdbMgr::CleanStatisticsExperDataTimer(const std::vector<int32_t> &userIds)
{
    if (g_mockCleanStatisticsExperDataRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationRdbMgr::DeleteStatisticsByBundle(const int32_t userId,
    const std::string &bundleName, int32_t packageId)
{
    if (g_mockDeleteStatisticsByBundleRet == false) {
        return NativeRdb::E_ERROR;
    }
    auto it = g_statisticsState.find(std::make_pair(userId, packageId));
    if (it != g_statisticsState.end()) {
        g_statisticsState.erase(it);
    }
    return NativeRdb::E_OK;
}
}
}
}
