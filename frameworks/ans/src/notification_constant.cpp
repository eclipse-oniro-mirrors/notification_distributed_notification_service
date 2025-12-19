/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "notification_constant.h"

namespace OHOS {
namespace Notification {
const std::string NotificationConstant::EXTRA_INPUTS_SOURCE {"notification_user_input_source"};
const char* NotificationConstant::NOTIFICATION_RDB_NAME = "/notificationdb.db";
const char* NotificationConstant::NOTIFICATION_RDB_TABLE_NAME = "notification_table";
const char* NotificationConstant::NOTIFICATION_RDB_PATH = "/data/service/el1/public/database/notification_service";
const char* NotificationConstant::NOTIFICATION_JOURNAL_MODE = "WAL";
const char* NotificationConstant::NOTIFICATION_SYNC_MODE = "FULL";
const char* NotificationConstant::SLOTTYPECCMNAMES[] = {"Social_communication", "Service_reminder",
    "Content_information", "Other", "Custom", "Live_view", "Custom_service", "Emergency_information"};
const char* NotificationConstant::CURRENT_DEVICE_TYPE = "current";
const char* NotificationConstant::HEADSET_DEVICE_TYPE = "headset";
const char* NotificationConstant::LITEWEARABLE_DEVICE_TYPE = "liteWearable";
const char* NotificationConstant::WEARABLE_DEVICE_TYPE = "wearable";
const char* NotificationConstant::PAD_DEVICE_TYPE = "tablet";
const char* NotificationConstant::PC_DEVICE_TYPE = "2in1";
const char* NotificationConstant::SLAVE_DEVICE_TYPE = "slave";
const char* NotificationConstant::THIRD_PARTY_WEARABLE_DEVICE_TYPE = "thirdPartyWearable";
const char* NotificationConstant::DEVICESTYPES[] = { "headset", "liteWearable", "wearable", "2in1", "tablet",
    "thirdPartyWearable" };
const char* NotificationConstant::ANS_VOIP = "ANS_VOIP";
const char* NotificationConstant::PC_PAD_VOIP_FLAG = "110101";
const char* NotificationConstant::HEALTH_BUNDLE_WHITE_LIST  = "HEALTH_BUNDLE_WHITE_LIST";

const char* NotificationConstant::PriorityNotificationType::OTHER = "OTHER";
const char* NotificationConstant::PriorityNotificationType::PRIMARY_CONTACT = "PRIMARY_CONTACT";
const char* NotificationConstant::PriorityNotificationType::AT_ME = "AT_ME";
const char* NotificationConstant::PriorityNotificationType::URGENT_MESSAGE = "URGENT_MESSAGE";
const char* NotificationConstant::PriorityNotificationType::SCHEDULE_REMINDER = "SCHEDULE_REMINDER";
const char* NotificationConstant::PriorityNotificationType::PAYMENT_DUE = "PAYMENT_DUE";
const char* NotificationConstant::PriorityNotificationType::TRANSACTION_ALERT = "TRANSACTION_ALERT";
const char* NotificationConstant::PriorityNotificationType::EXPRESS_PROGRESS = "EXPRESS_PROGRESS";
const char* NotificationConstant::PriorityNotificationType::MISS_CALL = "MISS_CALL";
const char* NotificationConstant::PriorityNotificationType::TRAVEL_ALERT = "TRAVEL_ALERT";
const char* NotificationConstant::PriorityNotificationType::ACCOUNT_ALERT = "ACCOUNT_ALERT";
const char* NotificationConstant::PriorityNotificationType::APPOINTMENT_REMINDER = "APPOINTMENT_REMINDER";
const char* NotificationConstant::PriorityNotificationType::TRAFFIC_NOTICE = "TRAFFIC_NOTICE";
const char* NotificationConstant::PriorityNotificationType::KEY_PROGRESS = "KEY_PROGRESS";
const char* NotificationConstant::PriorityNotificationType::PUBLIC_EVENT = "PUBLIC_EVENT";
const char* NotificationConstant::PriorityNotificationType::IOT_WARNING = "IOT_WARNING";
const char* NotificationConstant::PriorityNotificationType::CUSTOM_KEYWORD = "CUSTOM_KEYWORD";
}  // namespace Notification
}  // namespace OHOS