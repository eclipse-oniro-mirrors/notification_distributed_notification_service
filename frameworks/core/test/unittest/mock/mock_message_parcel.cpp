/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "message_parcel.h"
#include "iremote_object.h"

namespace {
    bool g_mockWriteInterfaceTokenRet = true;
}

void MockWriteInterfaceToken(bool mockRet)
{
    g_mockWriteInterfaceTokenRet = mockRet;
}

namespace OHOS {

MessageParcel::MessageParcel()
{}

MessageParcel::MessageParcel(Allocator *allocator)
    : Parcel(allocator)
{
    writeRawDataFd_ = -1;
    readRawDataFd_ = -1;
    kernelMappedWrite_ = nullptr;
    kernelMappedRead_ = nullptr;
    rawData_ = nullptr;
    rawDataSize_ = 0;
}

MessageParcel::~MessageParcel()
{}


#ifndef CONFIG_IPC_SINGLE
bool MessageParcel::WriteDBinderProxy(const sptr<IRemoteObject> &object, uint32_t handle, uint64_t stubIndex)
{
    return true;
}
#endif

bool MessageParcel::WriteRemoteObject(const sptr<IRemoteObject> &object)
{
    return true;
}

sptr<IRemoteObject> MessageParcel::ReadRemoteObject()
{
    sptr<IRemoteObject> temp = ReadObject<IRemoteObject>();
    return temp;
}

bool MessageParcel::WriteFileDescriptor(int fd)
{
    return true;
}

int MessageParcel::ReadFileDescriptor()
{
    return 0;
}

void MessageParcel::ClearFileDescriptor()
{}

bool MessageParcel::ContainFileDescriptors() const
{
    return true;
}

bool MessageParcel::WriteInterfaceToken(std::u16string name)
{
    return g_mockWriteInterfaceTokenRet;
}

std::u16string MessageParcel::ReadInterfaceToken()
{
    return ReadString16();
}

bool MessageParcel::WriteRawData(const void *data, size_t size)
{
    return true;
}

bool MessageParcel::RestoreRawData(std::shared_ptr<char> rawData, size_t size)
{
    return true;
}

const void *MessageParcel::ReadRawData(size_t size)
{
    return nullptr;
}

const void *MessageParcel::GetRawData() const
{
    return nullptr;
}

size_t MessageParcel::GetRawDataSize() const
{
    return 0;
}

size_t MessageParcel::GetRawDataCapacity() const
{
    return 0;
}

void MessageParcel::WriteNoException()
{
    WriteInt32(0);
}

int32_t MessageParcel::ReadException()
{
    return 0;
}

bool MessageParcel::WriteAshmem(sptr<Ashmem> ashmem)
{
    return true;
}

sptr<Ashmem> MessageParcel::ReadAshmem()
{
    return nullptr;
}

bool MessageParcel::Append(MessageParcel &data)
{
    return true;
}
} // namespace OHOS
