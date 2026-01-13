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

#include "mock_rdb_helper.h"

#include "rdb_helper.h"
#include "mock_rdb_store.h"

namespace OHOS {
namespace {
int g_mockGetRdbHelperExecuteTimes = 0;
std::vector<int> g_mockGetRdbHelperErrCodes = {NativeRdb::E_OK};
std::vector<std::shared_ptr<Notification::Infra::MockRdbStore>> g_mockRdbStoreResults = {nullptr};

int g_mockDeleteRdbStoreExecuteTimes = 0;
std::vector<int> g_mockDeleteRdbStoreErrCodes = {NativeRdb::E_OK};
}

namespace NativeRdb {

std::shared_ptr<RdbStore> RdbHelper::GetRdbStore(
    const RdbStoreConfig &config, int version, RdbOpenCallback &callback, int &errCode)
{
    (void)config;
    (void)version;
    (void)callback;
    if (g_mockGetRdbHelperErrCodes.empty() || g_mockRdbStoreResults.empty()) {
        errCode = NativeRdb::E_ERROR;
        return nullptr;
    }

    if (g_mockGetRdbHelperErrCodes.size() != g_mockRdbStoreResults.size()) {
        errCode = NativeRdb::E_ERROR;
        return nullptr;
    }
    if (g_mockGetRdbHelperExecuteTimes < static_cast<int>(g_mockGetRdbHelperErrCodes.size())) {
        errCode = g_mockGetRdbHelperErrCodes[g_mockGetRdbHelperExecuteTimes];
        return g_mockRdbStoreResults[g_mockGetRdbHelperExecuteTimes++];
    }
    errCode = g_mockGetRdbHelperErrCodes.back();
    return g_mockRdbStoreResults.back();
}


int RdbHelper::DeleteRdbStore(const std::string &dbFileName, bool shouldClose)
{
    (void)dbFileName;
    (void)shouldClose;
    if (g_mockDeleteRdbStoreErrCodes.empty()) {
        return NativeRdb::E_ERROR;
    }

    if (g_mockDeleteRdbStoreExecuteTimes < static_cast<int>(g_mockDeleteRdbStoreErrCodes.size())) {
        return g_mockDeleteRdbStoreErrCodes[g_mockDeleteRdbStoreExecuteTimes++];
    }
    return g_mockDeleteRdbStoreErrCodes.back();
}
} // namespace NativeRdb

namespace Notification::Infra {

void SetMockGetRdbHelperErrCodes(const std::vector<int> &errCodes)
{
    g_mockGetRdbHelperErrCodes = errCodes;
    g_mockGetRdbHelperExecuteTimes = 0;
}

void SetMockRdbStoreResults(const std::vector<std::shared_ptr<MockRdbStore>> &results)
{
    g_mockRdbStoreResults = results;
    g_mockGetRdbHelperExecuteTimes = 0;
}

void SetMockDeleteRdbStoreErrCodes(const std::vector<int> &errCodes)
{
    g_mockDeleteRdbStoreErrCodes = errCodes;
    g_mockDeleteRdbStoreExecuteTimes = 0;
}

void ResetMockRdbHelper()
{
    g_mockGetRdbHelperErrCodes = {NativeRdb::E_OK};
    g_mockRdbStoreResults = {nullptr};
    g_mockGetRdbHelperExecuteTimes = 0;
    g_mockDeleteRdbStoreErrCodes = {NativeRdb::E_OK};
    g_mockDeleteRdbStoreExecuteTimes = 0;
}
} // namespace Notification::Infra
} // namespace OHOS