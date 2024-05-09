/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_ANS_STANDARD_INNERKITS_BASE_INCLUDE_ANS_CONST_DEFINE_H
#define BASE_NOTIFICATION_ANS_STANDARD_INNERKITS_BASE_INCLUDE_ANS_CONST_DEFINE_H

#include <vector>

#include "uri.h"

#include "notification_constant.h"

namespace OHOS {
namespace Notification {
// Max active notification number
constexpr size_t MAX_ACTIVE_NUM = 1000;
constexpr uint32_t MAX_ACTIVE_NUM_PERAPP = 100;
constexpr uint32_t MAX_ACTIVE_NUM_PERSECOND = 10;
constexpr uint32_t MAX_UPDATE_NUM_PERSECOND = 20;
constexpr size_t MAX_SLOT_NUM = 5;
constexpr uint32_t MAX_ICON_SIZE = 100 * 1024;
constexpr uint32_t MAX_PICTURE_SIZE = 2 * 1024 * 1024;
constexpr uint32_t MAX_LIVE_VIEW_ICON_NUM = 6;
constexpr bool SUPPORT_DO_NOT_DISTRUB = true;
constexpr uint32_t SYSTEM_SERVICE_UID = 1000;
constexpr uint32_t MAX_CONVERSATIONAL_NUM = 10000;
constexpr uint32_t MAX_PERMIT_MIME_TYPE_NUM = 10000;
constexpr uint32_t MAX_ACTION_BUTTON_NUM = 3;
constexpr int32_t MAX_PARCELABLE_VECTOR_NUM = 10000;
constexpr int32_t MAX_STATUS_VECTOR_NUM = 1000;
constexpr uint32_t MAX_CANCELED_PARCELABLE_VECTOR_NUM = 200;

constexpr int32_t DEFAULT_UID = 0;
constexpr int32_t SUBSCRIBE_USER_INIT = -1;
constexpr int32_t SUBSCRIBE_USER_ALL = -2;
constexpr int32_t DEFAULT_USER_ID = 100;
constexpr int32_t SUBSCRIBE_USER_SYSTEM_BEGIN = 0;
constexpr int32_t SUBSCRIBE_USER_SYSTEM_END = 99;
constexpr int32_t NOTIFICATION_MIN_COUNT = 0;
constexpr int32_t NOTIFICATION_MAX_COUNT = 1024;
constexpr int32_t DO_NOT_DISTURB_PROFILE_MIN_ID = 1;
constexpr int32_t DO_NOT_DISTURB_PROFILE_MAX_ID = 10;

// Default sound for notification
const static Uri DEFAULT_NOTIFICATION_SOUND("file://system/etc/Light.ogg");
const static std::vector<int64_t> DEFAULT_NOTIFICATION_VIBRATION = {200};

// Default path for template
const static std::string DEFAULT_TEMPLATE_PATH("/system/etc/notification_template/external.json");
const std::string CURRENT_DEVICE_TYPE = "current";
const std::string RING_TRUST_PKG_KEY = "RING_TRUSTLIST_PKG";
const std::string DOWNLOAD_TEMPLATE_NAME = "downloadTemplate";

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
constexpr NotificationConstant::DistributedReminderPolicy DEFAULT_DISTRIBUTED_REMINDER_POLICY =
    NotificationConstant::DistributedReminderPolicy::DEFAULT;
constexpr bool DEFAULT_DISTRIBUTED_ENABLE_IN_APPLICATION_INFO = false;
#endif
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_STANDARD_INNERKITS_BASE_INCLUDE_ANS_CONST_DEFINE_H
