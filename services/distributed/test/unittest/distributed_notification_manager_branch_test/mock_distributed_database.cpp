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

#include "distributed_database.h"

#include "ans_log_wrapper.h"

namespace {
    bool g_mockOnDeviceConnectedRet = true;
    bool g_mockGetEntriesFromDistributedDBRet = true;
    bool g_mockGetDeviceInfoListRet = true;
    bool g_mockGetLocalDeviceIdRet = true;
}

void MockOnDeviceConnected(bool mockRet)
{
    g_mockOnDeviceConnectedRet = mockRet;
}

void MockGetEntriesFromDistributedDB(bool mockRet)
{
    g_mockGetEntriesFromDistributedDBRet = mockRet;
}

void MockGetDeviceInfoList(bool mockRet)
{
    g_mockGetDeviceInfoListRet = mockRet;
}

void MockGetLocalDeviceId(bool mockRet)
{
    g_mockGetLocalDeviceIdRet = mockRet;
}

namespace OHOS {
namespace Notification {
bool DistributedDatabase::OnDeviceConnected()
{
    return g_mockOnDeviceConnectedRet;
}

bool DistributedDatabase::GetEntriesFromDistributedDB(const std::string &prefixKey, std::vector<Entry> &entries)
{
    Entry entry;
    entry.key = "GetEntriesFromDistributedDB";
    entries.emplace_back(entry);
    return g_mockGetEntriesFromDistributedDBRet;
}

bool DistributedDatabase::GetDeviceInfoList(std::vector<DeviceInfo> &deviceList)
{
    return g_mockGetDeviceInfoListRet;
}

bool DistributedDatabase::GetLocalDeviceId(std::string &deviceId)
{
    return g_mockGetLocalDeviceIdRet;
}

bool DistributedDatabase::PutToDistributedDB(const std::string &key, const std::string &value)
{
    return false;
}

bool DistributedDatabase::GetLocalDeviceInfo(DeviceInfo &localInfo)
{
    return false;
}

bool DistributedDatabase::RecreateDistributedDB()
{
    return false;
}
}  // namespace Notification
}  // namespace OHOS