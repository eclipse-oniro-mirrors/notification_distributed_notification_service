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
#include "notification_rdb_mgr.h"
#include "rdb_errno.h"

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
    std::string g_mockDataValue;
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
namespace OHOS {
namespace Notification {
NotificationDataMgr::NotificationDataMgr(const NotificationRdbConfig &notificationRdbConfig)
    : notificationRdbConfig_(notificationRdbConfig)
{
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
    return NativeRdb::E_OK;
}

int32_t NotificationRdbMgr::DropUserTable(const int32_t userId)
{
    if (g_mockDropTable == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}
}
}
}
