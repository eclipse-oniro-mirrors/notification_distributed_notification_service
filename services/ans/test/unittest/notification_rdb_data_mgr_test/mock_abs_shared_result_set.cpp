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

#include "abs_shared_result_set.h"
#include "rdb_errno.h"

namespace {
    bool g_mockHasBlockRet = true;
    bool g_mockGetStringRet = true;
    bool g_mockGetUserTableName = true;
}

void MockHasBlock(bool mockRet)
{
    g_mockHasBlockRet = mockRet;
}

void MockGetString(bool mockRet)
{
    g_mockGetStringRet = mockRet;
}

void MockGetUserTableName(bool mockRet)
{
    g_mockGetUserTableName = mockRet;
}

namespace OHOS {
namespace NativeRdb {
bool AbsSharedResultSet::HasBlock()
{
    return g_mockHasBlockRet;
}

int AbsSharedResultSet::GetString(int columnIndex, std::string &value)
{
    if (g_mockGetStringRet == false) {
        return E_ERROR;
    }
    return E_OK;
}
} // namespace NativeRdb
} // namespace OHOS
