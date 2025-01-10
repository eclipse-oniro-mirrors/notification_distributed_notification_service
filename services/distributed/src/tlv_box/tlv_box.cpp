/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "tlv_box.h"

#include <securec.h>
#include <arpa/inet.h>
#include "ans_log_wrapper.h"
#include "zlib.h"

namespace OHOS {
namespace Notification {

namespace {
constexpr int32_t MAX_BUFFER_LENGTH = 1024 * 4 * 1024;
}

int32_t TlvItem::GetType() const
{
    return type_;
}

int32_t TlvItem::GetLength() const
{
    return length_;
}

unsigned char* TlvItem::GetValue() const
{
    return value_;
}

void TlvItem::Initialize(const void* data, int32_t length)
{
    if (length > MAX_BUFFER_LENGTH) {
        ANS_LOGW("Initialize data invalid %{public}d %{public}d %{public}d", type_, length, length_);
        return;
    }
    length_ = length;
    value_ = new unsigned char[length];
    errno_t err = memcpy_s(value_, length, data, length);
    if (err != EOK) {
        ANS_LOGW("tlv item copy failed.");
    }
}

TlvItem::~TlvItem()
{
    if (value_ != nullptr) {
        delete[] value_;
        value_ = nullptr;
    }
}

TlvItem::TlvItem(int32_t type, bool value) : type_(type)
{
    Initialize(&value, sizeof(bool));
}

TlvItem::TlvItem(int32_t type, int32_t value) : type_(type)
{
    int32_t newValue = htonl(value);
    Initialize(&newValue, sizeof(int32_t));
}

TlvItem::TlvItem(int32_t type, std::string value) : type_(type)
{
    Initialize(value.c_str(), value.size() + 1);
}

TlvItem::TlvItem(int32_t type, const TlvItem& value) : type_(type)
{
    Initialize(value.GetValue(), value.GetLength());
}

TlvItem::TlvItem(int32_t type, const unsigned char* value, int32_t length) : type_(type)
{
    Initialize(value, length);
}

TlvBox::~TlvBox()
{
    if (byteBuffer_ != NULL) {
        delete[] byteBuffer_;
        byteBuffer_ = NULL;
    }
}

bool TlvBox::PutValue(std::shared_ptr<TlvItem> value)
{
    auto iter = TlvMap_.find(value->GetType());
    if (iter != TlvMap_.end()) {
        std::shared_ptr<TlvItem> item = iter->second;
        bytesLength_ = bytesLength_ - (sizeof(int32_t) + sizeof(int32_t) + item->GetLength());
        iter->second = value;
    } else {
        TlvMap_.insert(std::pair<int32_t, std::shared_ptr<TlvItem>>(value->GetType(), value));
    }

    bytesLength_ += (sizeof(int32_t) + sizeof(int32_t) + value->GetLength());
    return true;
}

bool TlvBox::GetMessageType(int32_t& messageType)
{
    return GetInt32Value(MESSAGE_TYPE_ID, messageType);
}

bool TlvBox::GetBoolValue(int32_t type, bool& value)
{
    auto iter = TlvMap_.find(type);
    if (iter != TlvMap_.end()) {
        value = (*(bool*)(iter->second->GetValue()));
        return true;
    }
    return false;
}

bool TlvBox::GetBytes(int32_t type, std::vector<uint8_t>& value)
{
    auto iter = TlvMap_.find(type);
    if (iter != TlvMap_.end()) {
        auto begin = iter->second->GetValue();
        value.assign(begin, begin + iter->second->GetLength());
        return true;
    }
    return false;
}

bool TlvBox::GetStringValue(int32_t type, std::string& value)
{
    auto iter = TlvMap_.find(type);
    if (iter != TlvMap_.end()) {
        value = reinterpret_cast<char*>(iter->second->GetValue());
        return true;
    }
    return false;
}

bool TlvBox::GetInt32Value(int32_t type, int32_t& value)
{
    auto iter = TlvMap_.find(type);
    if (iter != TlvMap_.end()) {
        value = ntohl((*(int32_t*)(iter->second->GetValue())));
        return true;
    }
    return false;
}

bool TlvBox::GetObjectValue(int32_t type, TlvBox& value)
{
    auto iter = TlvMap_.find(type);
    if (iter == TlvMap_.end()) {
        return false;
    }
    return value.Parse(iter->second->GetValue(), iter->second->GetLength());
}

bool TlvBox::Parse(const unsigned char* buffer, int32_t buffersize)
{
    if (buffer == NULL) {
        return false;
    }

    if (buffersize > MAX_BUFFER_LENGTH) {
        ANS_LOGW("Parse data length invalid %{public}d", buffersize);
        return false;
    }
    unsigned char* cached = new unsigned char[buffersize];
    errno_t err = memcpy_s(cached, buffersize, buffer, buffersize);
    if (err != EOK) {
        return false;
    }

    int offset = 0;
    while (offset < buffersize) {
        int32_t type = ntohl((*(int32_t*)(cached + offset)));
        offset += sizeof(int32_t);
        int32_t length = ntohl((*(int32_t*)(cached + offset)));
        offset += sizeof(int32_t);
        PutValue(std::make_shared<TlvItem>(type, cached + offset, length));
        offset += length;
    }

    bytesLength_ = buffersize;
    return true;
}

bool TlvBox::Serialize(bool addCheck)
{
    int offset = 0;
    int32_t bytesLeft = bytesLength_;
    if (addCheck) {
        bytesLength_ = bytesLength_ + sizeof(uint32_t);
    }
    if (bytesLength_ > MAX_BUFFER_LENGTH) {
        ANS_LOGW("Serialize data length invalid %{public}d", bytesLength_);
        return false;
    }
    byteBuffer_ = new unsigned char[bytesLength_];
    for (auto iter = TlvMap_.begin(); iter != TlvMap_.end(); iter++) {
        int32_t type = htonl(iter->second->GetType());
        errno_t err = memcpy_s(byteBuffer_ + offset, bytesLeft, &type, sizeof(int32_t));
        if (err != EOK) {
            delete[] byteBuffer_;
            byteBuffer_ = nullptr;
            return false;
        }
        offset += sizeof(int32_t);
        bytesLeft -= sizeof(int32_t);
        int32_t length = iter->second->GetLength();
        int32_t lengthValue = htonl(length);
        err = memcpy_s(byteBuffer_ + offset, bytesLeft, &lengthValue, sizeof(int32_t));
        if (err != EOK) {
            delete[] byteBuffer_;
            byteBuffer_ = nullptr;
            return false;
        }
        offset += sizeof(int32_t);
        bytesLeft -= sizeof(int32_t);
        err = memcpy_s(byteBuffer_ + offset, bytesLeft, iter->second->GetValue(), length);
        if (err != EOK) {
            delete[] byteBuffer_;
            byteBuffer_ = nullptr;
            return false;
        }
        offset += length;
        bytesLeft -= length;
    }
    if (addCheck) {
        uint32_t calCrc = crc32(crc32(0L, Z_NULL, 0), (const Bytef*)byteBuffer_, offset);
        uint32_t calValue = htonl(calCrc);
        (void)memcpy_s(byteBuffer_ + offset, sizeof(uint32_t), &calValue, sizeof(uint32_t));
        ANS_LOGI("Box Serialize crc32 %{public}u %{public}u.", offset + sizeof(uint32_t), calCrc);
    } else {
        ANS_LOGI("Box Serialize crc32 %{public}d.", offset);
    }
    return true;
}

bool TlvBox::SetMessageType(int32_t messageType)
{
    return PutValue(std::make_shared<TlvItem>(MESSAGE_TYPE_ID, messageType));
}

bool TlvBox::CheckMessageCRC(const unsigned char*data, uint32_t dataLen)
{
    uint32_t calcSize = sizeof(uint32_t);
    if (dataLen <= calcSize) {
        return false;
    }
    uint32_t recv = ntohl((*(uint32_t*)(data + dataLen - calcSize)));
    uint32_t calc = crc32(crc32(0L, Z_NULL, 0), (const Bytef*)data, dataLen - calcSize);
    if (calc != recv) {
        ANS_LOGW("Box check crc32 failed %{public}d %{public}d.", recv, calc);
        return false;
    }
    return true;
}

}
}
