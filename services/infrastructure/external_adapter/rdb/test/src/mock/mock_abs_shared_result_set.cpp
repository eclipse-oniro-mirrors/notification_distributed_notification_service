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

#include "mock_abs_shared_result_set.h"

namespace OHOS::Notification::Infra {
namespace {
int g_mockGoToFirstRowExecuteTimes = 0;
std::vector<int> g_mockGoToFirstRowErrCodes = {NativeRdb::E_OK};

int g_mockGetStringExecuteTimes = 0;
std::vector<std::string> g_mockGetStringValues = {"testValue"};
std::vector<int> g_mockGetStringErrCodes  = {NativeRdb::E_OK};

int g_mockGetBlobExecuteTimes = 0;
std::vector<std::vector<uint8_t>> g_mockGetBlobValues = {{'b', 'l', 'o', 'b'}};
std::vector<int> g_mockGetBlobErrCodes  = {NativeRdb::E_OK};

int g_mockGoToNextRowExecuteTimes = 0;
std::vector<int> g_mockGoToNextRowErrCodes = {NativeRdb::E_OK};
}

int MockAbsSharedResultSet::GoToFirstRow()
{
    if (g_mockGoToFirstRowErrCodes.empty()) {
        return NativeRdb::E_ERROR;
    }
    if (g_mockGoToFirstRowExecuteTimes < static_cast<int>(g_mockGoToFirstRowErrCodes.size())) {
        return g_mockGoToFirstRowErrCodes[g_mockGoToFirstRowExecuteTimes++];
    }

    return g_mockGoToFirstRowErrCodes.back();
}

void SetMockGoToFirstRowErrCodes(const std::vector<int> &errCodes)
{
    g_mockGoToFirstRowErrCodes = errCodes;
    g_mockGoToFirstRowExecuteTimes = 0;
}

int MockAbsSharedResultSet::GetString(int columnIndex, std::string &value)
{
    (void)columnIndex;
    if (g_mockGetStringErrCodes.empty()) {
        return NativeRdb::E_ERROR;
    }
    if (g_mockGetStringExecuteTimes >= static_cast<int>(g_mockGetStringErrCodes.size())) {
        value = g_mockGetStringValues.back();
        return g_mockGetStringErrCodes.back();
    }
    value = g_mockGetStringValues[g_mockGetStringExecuteTimes];
    return g_mockGetStringErrCodes[g_mockGetStringExecuteTimes++];
}

void SetMockGetStringValuesAndErrCodes(const std::vector<std::string> &values, const std::vector<int> &errCodes)
{
    g_mockGetStringValues = values;
    g_mockGetStringErrCodes = errCodes;
    g_mockGetStringExecuteTimes = 0;
}

int MockAbsSharedResultSet::GetBlob(int columnIndex, std::vector<uint8_t>& blob)
{
    (void)columnIndex;
    (void)blob;
    if (g_mockGetBlobErrCodes.empty()) {
        return NativeRdb::E_ERROR;
    }
    if (g_mockGetBlobExecuteTimes >= static_cast<int>(g_mockGetStringErrCodes.size())) {
        blob = g_mockGetBlobValues.back();
        return g_mockGetBlobErrCodes.back();
    }
    blob = g_mockGetBlobValues[g_mockGetBlobExecuteTimes];
    return g_mockGetBlobErrCodes[g_mockGetBlobExecuteTimes++];
}

void SetMockGetBlobValuesAndErrCodes(const std::vector<std::vector<uint8_t>> blobs, const std::vector<int> &errCodes)
{
    g_mockGetBlobValues = blobs;
    g_mockGetBlobErrCodes = errCodes;
    g_mockGetBlobExecuteTimes = 0;
}

int MockAbsSharedResultSet::GoToNextRow()
{
    if (g_mockGoToNextRowErrCodes.empty()) {
        return NativeRdb::E_ERROR;
    }
    if (g_mockGoToNextRowExecuteTimes < static_cast<int>(g_mockGoToNextRowErrCodes.size())) {
        return g_mockGoToNextRowErrCodes[g_mockGoToNextRowExecuteTimes++];
    }

    return g_mockGoToNextRowErrCodes.back();
}

void SetMockGoToNextRowErrCodes(const std::vector<int> &errCodes)
{
    g_mockGoToNextRowErrCodes = errCodes;
    g_mockGoToNextRowExecuteTimes = 0;
}

void ResetMockAbsSharedResultSet()
{
    g_mockGoToFirstRowErrCodes = {NativeRdb::E_OK};
    g_mockGoToFirstRowExecuteTimes = 0;

    g_mockGetStringValues = {"testValue"};
    g_mockGetStringErrCodes = {NativeRdb::E_OK};
    g_mockGetStringExecuteTimes = 0;

    g_mockGetBlobValues = {{'b', 'l', 'o', 'b'}};
    g_mockGetBlobErrCodes = {NativeRdb::E_OK};
    g_mockGetBlobExecuteTimes = 0;

    g_mockGoToNextRowErrCodes = {NativeRdb::E_OK};
    g_mockGoToNextRowExecuteTimes = 0;
}

int MockAbsSharedResultSet::Close()
{
    return NativeRdb::E_OK;
}
} // namespace OHOS::Notification::Infra