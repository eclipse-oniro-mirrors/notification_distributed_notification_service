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

#include "mock_resource_manager.h"

namespace {
const int DEFAULT_FILE_FD = 10;
const long DEFAULT_FILE_LENGTH = 1024;
bool g_mockGetRawFileDescriptorFail = false;
int g_mockRawFileDescriptorFd = DEFAULT_FILE_FD;
long g_mockRawFileDescriptorOffset = 0;
long g_mockRawFileDescriptorLength = DEFAULT_FILE_LENGTH;
bool g_mockCloseRawFileDescriptorFail = false;
}

namespace OHOS {
namespace Global {
namespace Resource {
namespace Mock {

bool g_mockGetResourceManagerReturnNull = false;

void MockGetRawFileDescriptorFail(bool fail)
{
    g_mockGetRawFileDescriptorFail = fail;
}

void MockGetRawFileDescriptorReturn(int fd, long offset, long length)
{
    g_mockRawFileDescriptorFd = fd;
    g_mockRawFileDescriptorOffset = offset;
    g_mockRawFileDescriptorLength = length;
}

void MockCloseRawFileDescriptorFail(bool fail)
{
    g_mockCloseRawFileDescriptorFail = fail;
}

void MockGetResourceManagerReturnNull(bool isNull)
{
    g_mockGetResourceManagerReturnNull = isNull;
}

void MockResetGetResourceManagerState()
{
    g_mockGetResourceManagerReturnNull = false;
}

void MockResetResourceManagerState()
{
    g_mockGetRawFileDescriptorFail = false;
    g_mockRawFileDescriptorFd = DEFAULT_FILE_FD;
    g_mockRawFileDescriptorOffset = 0;
    g_mockRawFileDescriptorLength = DEFAULT_FILE_LENGTH;
    g_mockCloseRawFileDescriptorFail = false;
    g_mockGetResourceManagerReturnNull = false;
}

MockResourceManager::MockResourceManager()
{}

MockResourceManager::~MockResourceManager()
{}

RState MockResourceManager::GetRawFileDescriptor(
    const std::string &path, RawFileDescriptor &descriptor)
{
    if (g_mockGetRawFileDescriptorFail) {
        return NOT_FOUND;
    }
    descriptor.fd = g_mockRawFileDescriptorFd;
    descriptor.offset = g_mockRawFileDescriptorOffset;
    descriptor.length = g_mockRawFileDescriptorLength;
    return SUCCESS;
}

RState MockResourceManager::CloseRawFileDescriptor(const std::string &path)
{
    if (g_mockCloseRawFileDescriptorFail) {
        return NOT_FOUND;
    }
    return SUCCESS;
}

}  // namespace Mock
}  // namespace Resource
}  // namespace Global
}  // namespace OHOS