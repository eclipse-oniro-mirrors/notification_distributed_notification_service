/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_TLV_BOX_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_TLV_BOX_H

#include <vector>
#include <string>
#include <map>

namespace OHOS {
namespace Notification {

enum NotificationEventType : int32_t {
    PUBLISH_NOTIFICATION = 0,
    UPDATE_NOTIFICATION = 1,
    REMOVE_NOTIFICATION = 2,
    CLICK_TO_JUMP = 3,
    NOTIFICATION_QUICK_REPLY = 4,
    NOTIFICATION_STATE_SYNC = 5,
    NOTIFICATION_MATCH_SYNC = 6,
};

enum TlvType : int32_t {
    MESSAGE_TYPE_ID = 0,
    NOTIFICATION_HASHCODE,
    NOTIFICATION_SLOT_TYPE,
    NOTIFICATION_REMINDERFLAG,
    BUNDLE_NAME,
    NOTIFICATION_TITLE,
    NOTIFICATION_CONTENT,
    BUNDLE_ICON,
    NOTIFICATION_BIG_ICON = 8,
    NOTIFICATION_OVERLAY_ICON = 9,
    MATCH_TYPE = 993,
    PEER_DEVICE_ID = 994,
    PEER_DEVICE_TYPE = 995,
    LOCAL_DEVICE_STATUE = 996,
    LOCAL_DEVICE_ID = 997,
    LOCAL_DEVICE_TYPE = 998,
    LOCAL_VERSION = 999,
    CHECK_SUM = 1000,
};

class TlvItem {
public:
    TlvItem(int32_t type, bool value);
    TlvItem(int32_t type, int32_t value);
    TlvItem(int32_t type, std::string value);
    TlvItem(int32_t type, unsigned char* value, int32_t length);
    TlvItem(int32_t type, const TlvItem& value);
    ~TlvItem();

    int32_t GetType() const;
    int32_t GetLength() const;
    unsigned char* GetValue() const;

private:
    void Initialize(const void* value, int32_t length);

    int32_t type_;
    int32_t length_;
    unsigned char* value_;
};

class TlvBox {
public:
    ~TlvBox();
    bool Serialize();
    bool Parse(const unsigned char* buffer, int32_t buffersize);
    bool PutValue(std::shared_ptr<TlvItem> value);
    bool SetMessageType(int32_t messageType);
    void AddMessageCRC(std::string& content);
    static bool CheckMessageCRC(const unsigned char* data, uint32_t dataLen);

    bool GetMessageType(int32_t& messageType);
    bool GetBoolValue(int32_t type, bool& value);
    bool GetStringValue(int32_t type, std::string& value);
    bool GetInt32Value(int32_t type, int32_t& value);
    bool GetObjectValue(int32_t type, TlvBox& value);

    int32_t bytesLength_ = 0;
    unsigned char* byteBuffer_ = nullptr;
    std::map<int32_t, std::shared_ptr<TlvItem>> TlvMap_;
};
}  // namespace Notification
}  // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_TLV_BOX_H

