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

#ifndef OHOS_NOTIFICATION_UTILS_H
#define OHOS_NOTIFICATION_UTILS_H

#include "cj_ffi/cj_common_ffi.h"

namespace OHOS {
namespace CJSystemapi {

constexpr int32_t STR_MAX_SIZE = 204;
constexpr int32_t LONG_STR_MAX_SIZE = 1028;
constexpr int32_t EOK = 0;

struct CNotificationBasicContent {
    char* title;
    char* text;
    char* additionalText;
};

struct CNotificationLongTextContent {
    char* title;
    char* text;
    char* additionalText;
    char* longText;
    char* briefText;
    char* expandedTitle;
};

struct CNotificationMultiLineContent {
    char* title;
    char* text;
    char* additionalText;
    char* briefText;
    char* longTitle;
    CArrString lines;
};

struct CNotificationPictureContent {
    char* title;
    char* text;
    char* additionalText;
    char* briefText;
    char* expandedTitle;
    int64_t picture;
};

struct CNotificationContent {
    int32_t notificationContentType;
    CNotificationBasicContent* normal;
    CNotificationLongTextContent* longText;
    CNotificationMultiLineContent* multiLine;
    CNotificationPictureContent* picture;
};

struct CDistributedOptions {
    bool isDistributed;
    CArrString supportDisplayDevices;
    CArrString supportOperateDevices;
};

enum class ContentType {
    NOTIFICATION_CONTENT_BASIC_TEXT,
    NOTIFICATION_CONTENT_LONG_TEXT,
    NOTIFICATION_CONTENT_PICTURE,
    NOTIFICATION_CONTENT_CONVERSATION,
    NOTIFICATION_CONTENT_MULTILINE,
    NOTIFICATION_CONTENT_LOCAL_LIVE_VIEW,
    NOTIFICATION_CONTENT_LIVE_VIEW
};

enum class SlotType {
    UNKNOWN_TYPE = 0,
    SOCIAL_COMMUNICATION = 1,
    SERVICE_INFORMATION = 2,
    CONTENT_INFORMATION = 3,
    LIVE_VIEW = 4,
    CUSTOMER_SERVICE = 5,
    OTHER_TYPES = 0xFFFF,
};

struct CNotificationRequest {
    CNotificationContent notificationContent;
    int32_t id;
    int32_t notificationSlotType;
    bool isOngoing;
    bool isUnremovable;
    int64_t deliveryTime;
    bool tapDismissed;
    int64_t autoDeletedTime;
    uint32_t color;
    bool colorEnabled;
    bool isAlertOnce;
    bool isStopwatch;
    bool isCountDown;
    char* label;
    int32_t badgeIconStyle;
    bool showDeliveryTime;
    int64_t smallIcon;
    int64_t largeIcon;
    char* creatorBundleName;
    char* groupName;
    CDistributedOptions* distributedOption;
    int32_t badgeNumber;
};
} // namespace CJSystemapi
} // namespace OHOS

#endif // OHOS_NOTIFICATION_UTILS_H