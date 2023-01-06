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

namespace {
    bool g_mockInitRet = true;
    bool g_mockQueryDataRet = true;
    bool g_mockInsertDataRet = true;
    bool g_mockInsertBatchDataRet = true;
    bool g_mockQueryDataBeginWithKeyRet = true;
    bool g_mockDeleteBathchDataRet = true;
    bool g_mockDeleteDataRet = true;
}

void MockInit(bool mockRet)
{
    g_mockInitRet = mockRet;
}

void MockQueryData(bool mockRet)
{
    g_mockQueryDataRet = mockRet;
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

void MockDeleteBathchData(bool mockRet)
{
    g_mockDeleteBathchDataRet = mockRet;
}

void MockDeleteData(bool mockRet)
{
    g_mockDeleteDataRet = mockRet;
}

namespace OHOS {
namespace Notification {
int32_t NotificationDataMgr::Init()
{
    if (g_mockInitRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryData(const std::string &key, std::string &value)
{
    if (g_mockQueryDataRet == false) {
        return NativeRdb::E_EMPTY_VALUES_BUCKET;
    }
    return NativeRdb::E_ERROR;
}

int32_t NotificationDataMgr::InsertData(const std::string &key, const std::string &value)
{
    if (g_mockInsertDataRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::InsertBatchData(const std::unordered_map<std::string, std::string> &values)
{
    if (g_mockInsertBatchDataRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::QueryDataBeginWithKey(
    const std::string &key, std::unordered_map<std::string, std::string> &values)
{
    if (g_mockQueryDataBeginWithKeyRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::DeleteBathchData(const std::vector<std::string> &keys)
{
    if (g_mockDeleteBathchDataRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

int32_t NotificationDataMgr::DeleteData(const std::string &key)
{
    if (g_mockDeleteDataRet == false) {
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}
}
}