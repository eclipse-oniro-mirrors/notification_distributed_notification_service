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

#include "match_box.h"

namespace OHOS {
namespace Notification {

NotifticationMatchBox::NotifticationMatchBox()
{
    if (box_ == nullptr) {
        return;
    }
    box_->SetMessageType(NOTIFICATION_MATCH_SYNC);
}

NotifticationMatchBox::NotifticationMatchBox(std::shared_ptr<TlvBox> box) : BoxBase(box)
{
}

bool NotifticationMatchBox::SetPeerDeviceType(const int32_t& deviceType)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(PEER_DEVICE_TYPE, deviceType));
}

bool NotifticationMatchBox::SetPeerDeviceId(const std::string& deviceId)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(PEER_DEVICE_ID, deviceId));
}

bool NotifticationMatchBox::SetLocalDeviceType(const int32_t& deviceType)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(LOCAL_DEVICE_TYPE, deviceType));
}

bool NotifticationMatchBox::SetLocalDeviceId(const std::string& deviceId)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(LOCAL_DEVICE_ID, deviceId));
}

bool NotifticationMatchBox::SetVersion(int32_t version)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(LOCAL_VERSION, version));
}

bool NotifticationMatchBox::SetMatchType(int32_t type)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(MATCH_TYPE, type));
}

bool NotifticationMatchBox::SetDeviceUserId(const int32_t& userId)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(LOCAL_DEVICE_USERID, userId));
}

bool NotifticationMatchBox::GetPeerDeviceType(int32_t& deviceType)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(PEER_DEVICE_TYPE, deviceType);
}

bool NotifticationMatchBox::GetPeerDeviceId(std::string& deviceId)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(PEER_DEVICE_ID, deviceId);
}

bool NotifticationMatchBox::GetLocalDeviceType(int32_t& deviceType)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(LOCAL_DEVICE_TYPE, deviceType);
}

bool NotifticationMatchBox::GetLocalDeviceId(std::string& deviceId)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(LOCAL_DEVICE_ID, deviceId);
}

bool NotifticationMatchBox::GetVersion(int32_t& version)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(LOCAL_VERSION, version);
}

bool NotifticationMatchBox::GetMatchType(int32_t& type)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(MATCH_TYPE, type);
}

bool NotifticationMatchBox::GetDeviceUserId(int32_t& userId)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(LOCAL_DEVICE_USERID, userId);
}
}
}
