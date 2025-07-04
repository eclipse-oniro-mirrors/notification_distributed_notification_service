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
    BUNDLE_ICON_SYNC = 7,
    REMOVE_ALL_NOTIFICATIONS = 8,
    NOTIFICATION_RESPONSE_SYNC = 9,
    SYNC_NOTIFICATION = 10,
    NOTIFICATION_RESPONSE_REPLY_SYNC = 11,
    INSTALLED_BUNDLE_SYNC = 12,
    REMOVE_ALL_DISTRIBUTED_NOTIFICATIONS = 13,
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
    NOTIFICATION_CONTENT_TYPE = 10,
    NOTIFICATION_COMMON_LIVEVIEW = 11,
    BATCH_REMOVE_SLOT_TYPE = 14,
    AUTO_DELETE_TIME = 15,
    FINISH_DEADLINE_TIME = 16,
    ACTION_BUTTON_NAME = 17,
    ACTION_USER_INPUT = 18,
    NOTIFICATION_ADDITIONAL_TEXT = 19,
    NOTIFICATION_BRIEF_TEXT = 20,
    NOTIFICATION_EXPANDED_TITLE = 21,
    NOTIFICATION_LONG_TITLE = 22,
    ALL_LINES_LENGTH = 23,
    NOTIFICATION_APP_MESSAGE_ID = 24,
    NOTIFICATION_EXTENDINFO = 25,
    NOTIFICATION_RECEIVE_USERID = 26,
    LOCAL_DEVICE_USERID = 986,
    LIVEVIEW_SYNC_ENABLE = 987,
    NOTIFICATION_SYNC_ENABLE = 988,
    RESULT_CODE = 989,
    OPERATION_TYPE = 990,
    OPERATION_EVENT_ID = 991,
    BUNDLE_ICON_SYNC_TYPE = 992,
    MATCH_TYPE = 993,
    PEER_DEVICE_ID = 994,
    PEER_DEVICE_TYPE = 995,
    LOCAL_DEVICE_STATUS = 996,
    LOCAL_DEVICE_ID = 997,
    LOCAL_DEVICE_TYPE = 998,
    LOCAL_VERSION = 999,
    CHECK_SUM = 1000,
    OPERATION_BTN_INDEX = 1001,
    ACTION_BUTTONS_TITILE_INDEX = 1002,
    ACTION_BUTTONS_LENGTH = 1005,
    OPERATION_JUMP_TYPE = 1006,
    NOTIFICATION_ALL_LINES_START_INDEX = 2000,
};

class TlvItem {
public:
    TlvItem(int32_t type, bool value);
    TlvItem(int32_t type, int32_t value);
    TlvItem(int32_t type, int64_t value);
    TlvItem(int32_t type, std::string value);
    TlvItem(int32_t type, const unsigned char* value, int32_t length);
    TlvItem(int32_t type, const TlvItem& value);
    ~TlvItem();

    int32_t GetType() const;
    int32_t GetLength() const;
    unsigned char* GetValue() const;

private:
    void Initialize(const void* value, int32_t length);

    int32_t type_;
    int32_t length_ = 0;
    unsigned char* value_ = nullptr;
};

class TlvBox {
public:
    ~TlvBox();
    bool Serialize(bool addCheck = true);
    bool Parse(const unsigned char* buffer, int32_t buffersize);
    bool PutValue(std::shared_ptr<TlvItem> value);
    bool SetMessageType(int32_t messageType);
    void AddMessageCRC(std::string& content);
    static bool CheckMessageCRC(const unsigned char* data, uint32_t dataLen);

    bool GetMessageType(int32_t& messageType);
    bool GetBoolValue(int32_t type, bool& value);
    bool GetBytes(int32_t type, std::vector<uint8_t>& value);
    bool GetStringValue(int32_t type, std::string& value);
    bool GetInt32Value(int32_t type, int32_t& value);
    bool GetInt64Value(int32_t type, int64_t& value);
    bool GetObjectValue(int32_t type, TlvBox& value);

    int32_t bytesLength_ = 0;
    unsigned char* byteBuffer_ = nullptr;
    std::map<int32_t, std::shared_ptr<TlvItem>> TlvMap_;
};
}  // namespace Notification
}  // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_TLV_BOX_H

