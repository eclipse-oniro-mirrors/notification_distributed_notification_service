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

#include "distributed_preferences_database.h"

namespace {
    bool g_mockGetEntriesFromDistributedDBRet = true;
    bool g_mockPutToDistributedDBRet = true;
    bool g_mockDeleteToDistributedDBRet = true;
    bool g_mockClearDatabaseRet = true;
}

void MockGetEntriesFromDistributedDB(bool mockRet)
{
    g_mockGetEntriesFromDistributedDBRet = mockRet;
}

void MockPutToDistributedDB(bool mockRet)
{
    g_mockPutToDistributedDBRet = mockRet;
}

void MockDeleteToDistributedDB(bool mockRet)
{
    g_mockDeleteToDistributedDBRet = mockRet;
}

void MockClearDatabase(bool mockRet)
{
    g_mockClearDatabaseRet = mockRet;
}

namespace OHOS {
namespace Notification {

DistributedPreferencesDatabase::DistributedPreferencesDatabase() : DistributedFlowControl()
{
    GetKvDataManager();
}

DistributedPreferencesDatabase::~DistributedPreferencesDatabase()
{}

bool DistributedPreferencesDatabase::GetEntriesFromDistributedDB(
    const std::string &prefixKey, std::vector<Entry> &entries)
{
    Entry entry;
    entry.key = "GetEntriesFromDistributedDB";
    entries.emplace_back(entry);
    return g_mockGetEntriesFromDistributedDBRet;
}

bool DistributedPreferencesDatabase::PutToDistributedDB(const std::string &key, const std::string &value)
{
    return g_mockPutToDistributedDBRet;
}

bool DistributedPreferencesDatabase::DeleteToDistributedDB(const std::string &key)
{
    return g_mockDeleteToDistributedDBRet;
}

bool DistributedPreferencesDatabase::ClearDatabase()
{
    return g_mockClearDatabaseRet;
}
}  // namespace Notification
}  // namespace OHOS