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

#ifndef BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_CONVER_ENUM_H
#define BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_CONVER_ENUM_H

#include "notification_constant.h"
#include "notification_content.h"
#include "notification_slot.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

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
    EMERGENCY_INFORMATION = 10,
    OTHER_TYPES = 0xFFFF,
};

enum class SlotLevel {
    LEVEL_NONE = 0,
    LEVEL_MIN = 1,
    LEVEL_LOW = 2,
    LEVEL_DEFAULT = 3,
    LEVEL_HIGH = 4,
};

enum class RemoveReason {
    DEFAULT_REASON_DELETE = 0,
    CLICK_REASON_REMOVE = 1,
    CANCEL_REASON_REMOVE = 2,
    CANCEL_ALL_REASON_REMOVE = 3,
    ERROR_REASON_REMOVE = 4,
    PACKAGE_CHANGED_REASON_REMOVE = 5,
    USER_STOPPED_REASON_REMOVE = 6,
    PACKAGE_BANNED_REASON_REMOVE = 7,
    APP_CANCEL_REASON_REMOVE = 8,
    APP_CANCEL_ALL_REASON_REMOVE = 9,
    USER_REMOVED_REASON_DELETE = 10,
    FLOW_CONTROL_REASON_DELETE = 11,
    DISABLE_SLOT_REASON_DELETE = 12,
    DISABLE_NOTIFICATION_REASON_DELETE = 13,
    APP_CANCEL_AS_BUNELE_REASON_DELETE = 14,
    APP_CANCEL_AS_BUNELE_WITH_AGENT_REASON_DELETE = 15,
    APP_CANCEL_REMINDER_REASON_DELETE = 16,
    APP_CANCEL_GROPU_REASON_DELETE = 17,
    APP_REMOVE_GROUP_REASON_DELETE = 18,
    APP_REMOVE_ALL_REASON_DELETE = 19,
    APP_REMOVE_ALL_USER_REASON_DELETE = 20,
    TRIGGER_EIGHT_HOUR_REASON_DELETE = 21,
    TRIGGER_FOUR_HOUR_REASON_DELETE = 22,
    TRIGGER_TEN_MINUTES_REASON_DELETE = 23,
    TRIGGER_FIFTEEN_MINUTES_REASON_DELETE = 24,
    TRIGGER_THIRTY_MINUTES_REASON_DELETE = 25,
    TRIGGER_START_ARCHIVE_REASON_DELETE = 26,
    TRIGGER_AUTO_DELETE_REASON_DELETE = 27,
    PACKAGE_REMOVE_REASON_DELETE = 28,
    SLOT_ENABLED_REASON_DELETE = 29,
    RECOVER_LIVE_VIEW_DELETE = 30,
    DISABLE_NOTIFICATION_FEATURE_REASON_DELETE = 31,
    DISTRIBUTED_COLLABORATIVE_DELETE = 32,
    USER_LOGOUT_REASON_DELETE = 33,
    DISTRIBUTED_ENABLE_CLOSE_DELETE = 34,
    DISTRIBUTED_RELEASE_DELETE = 35,
    APP_CANCEL_REASON_OTHER = 100,
};

enum class DoNotDisturbType {
    TYPE_NONE, TYPE_ONCE,
    TYPE_DAILY, TYPE_CLEARLY
};

enum class SourceType {
    TYPE_NORMAL = 0x00000000,
    TYPE_CONTINUOUS = 0x00000001,
    TYPE_TIMER = 0x00000002
};

enum class NotificationControlFlagStatus {
    NOTIFICATION_STATUS_CLOSE_SOUND = 1 << 0,
    NOTIFICATION_STATUS_CLOSE_LOCKSCREEN = 1 << 1,
    NOTIFICATION_STATUS_CLOSE_BANNER = 1 << 2,
    NOTIFICATION_STATUS_CLOSE_LIGHT_SCREEN = 1 << 3,
    NOTIFICATION_STATUS_CLOSE_VIBRATION = 1 << 4,
    NOTIFICATION_STATUS_CLOSE_STATUSBAR_ICON = 1 << 5
};

enum class DeviceRemindType {
    IDLE_DONOT_REMIND,
    IDLE_REMIND,
    ACTIVE_DONOT_REMIND,
    ACTIVE_REMIND
};

enum class LiveViewStatus {
    LIVE_VIEW_CREATE,
    LIVE_VIEW_INCREMENTAL_UPDATE,
    LIVE_VIEW_END,
    LIVE_VIEW_FULL_UPDATE,
    LIVE_VIEW_BUTT
};

enum class LiveViewTypes {
    LIVE_VIEW_ACTIVITY,
    LIVE_VIEW_INSTANT,
    LIVE_VIEW_LONG_TERM,
    LIVE_VIEW_INSTANT_BANNER
};

enum class EnabledStatus {
    DEFAULT_FALSE,
    DEFAULT_TRUE,
    ENABLED_TRUE,
    ENABLED_FALSE
};

class AnsEnumUtil {
public:
    /**
     * @brief Converts content type from js to native
     *
     * @param inType Indicates a js ContentType object
     * @param outType Indicates a NotificationContent object
     * @return Returns true if success, returns false otherwise
     */
    static bool ContentTypeJSToC(const ContentType &inType, NotificationContent::Type &outType);

    /**
     * @brief Converts content type from native to js
     *
     * @param inType Indicates a NotificationContent object
     * @param outType Indicates a js ContentType object
     * @return Returns true if success, returns false otherwise
     */
    static bool ContentTypeCToJS(const NotificationContent::Type &inType, ContentType &outType);

    /**
     * @brief Converts slot type from js to native
     *
     * @param inType Indicates a native SlotType object
     * @param outType Indicates a js SlotType object
     * @return Returns true if success, returns false otherwise
     */
    static bool SlotTypeJSToC(const SlotType &inType, NotificationConstant::SlotType &outType);

    /**
     * @brief Converts slot type from native to js
     *
     * @param inType Indicates a js SlotType object
     * @param outType Indicates a native SlotType object
     * @return Returns true if success, returns false otherwise
     */
    static bool SlotTypeCToJS(const NotificationConstant::SlotType &inType, SlotType &outType);

    /**
     * @brief Converts slot level from js to native
     *
     * @param inType Indicates a native SlotLevel object
     * @param outType Indicates a js NotificationLevel object
     * @return Returns true if success, returns false otherwise
     */
    static bool SlotLevelJSToC(const SlotLevel &inLevel, NotificationSlot::NotificationLevel &outLevel);

    /**
     * @brief Converts liveview status from js to native
     *
     * @param inType Indicates a js liveview status object
     * @param outType Indicates a liveview status object
     * @return Returns true if success, returns false otherwise
     */
    static bool LiveViewStatusJSToC(const LiveViewStatus &inType, NotificationLiveViewContent::LiveViewStatus &outType);

    /**
     * @brief Converts liveview types from js to native
     *
     * @param in Indicates a js liveview type object
     * @param out Indicates a liveview type object
     * @return Returns true if success, returns false otherwise
     */
    static bool LiveViewTypesJSToC(const LiveViewTypes &in, NotificationLocalLiveViewContent::LiveViewTypes &out);

    /**
     * @brief Converts slot level from native to js
     *
     * @param inType Indicates a js NotificationLevel object
     * @param outType Indicates a native SlotLevel object
     * @return Returns true if success, returns false otherwise
     */
    static bool SlotLevelCToJS(const NotificationSlot::NotificationLevel &inLevel, SlotLevel &outLevel);

    /**
     * @brief Converts reason type from native to js
     *
     * @param inType Indicates a native reason type
     * @param outType Indicates a js reason type
     * @return Returns true if success, returns false otherwise
     */
    static bool ReasonCToJS(const int32_t &inType, int32_t &outType);

    /**
     * @brief Converts reason type from native to js
     *
     * @param inType Indicates a native reason type
     * @param outType Indicates a js reason type
     * @return Returns true if success, returns false otherwise
     */
    static void ReasonCToJSExt(const int32_t &inType, int32_t &outType);

    /**
     * @brief Converts reason type from native to js
     *
     * @param inType Indicates a native reason type
     * @param outType Indicates a js reason type
     * @return Returns true if success, returns false otherwise
     */
    static void ReasonCToJSSecondExt(const int32_t &inType, int32_t &outType);

    /**
     * @brief Converts do-not-disturb type from js to native
     *
     * @param inType Indicates a js DoNotDisturbType object
     * @param outType Indicates a native DoNotDisturbType object
     * @return Returns true if success, returns false otherwise
     */
    static bool DoNotDisturbTypeJSToC(const DoNotDisturbType &inType, NotificationConstant::DoNotDisturbType &outType);

    /**
     * @brief Converts do-not-disturb type from native to js
     *
     * @param inType Indicates a native DoNotDisturbType object
     * @param outType Indicates a js DoNotDisturbType object
     * @return Returns true if success, returns false otherwise
     */
    static bool DoNotDisturbTypeCToJS(const NotificationConstant::DoNotDisturbType &inType, DoNotDisturbType &outType);

    /**
     * @brief Converts remind type from native to js
     *
     * @param inType Indicates a native RemindType object
     * @param outType Indicates a js DeviceRemindType object
     * @return Returns true if success, returns false otherwise
     */
    static bool DeviceRemindTypeCToJS(const NotificationConstant::RemindType &inType, DeviceRemindType &outType);

    /**
     * @brief Converts source type from native to js
     *
     * @param inType Indicates a native SourceType object
     * @param outType Indicates a js SourceType object
     * @return Returns true if success, returns false otherwise
     */
    static bool SourceTypeCToJS(const NotificationConstant::SourceType &inType, SourceType &outType);

    /**
     * @brief Converts liveview status type from native to js
     *
     * @param inType Indicates a native liveview status object
     * @param outType Indicates a js liveview status object
     * @return Returns true if success, returns false otherwise
     */
    static bool LiveViewStatusCToJS(const NotificationLiveViewContent::LiveViewStatus &inType, LiveViewStatus &outType);

    /**
     * @brief Converts liveview type from native to js
     *
     * @param in Indicates a native liveview type object
     * @param out Indicates a js liveview type object
     * @return Returns true if success, returns false otherwise
     */
    static bool LiveViewTypesCToJS(const NotificationLocalLiveViewContent::LiveViewTypes &in, LiveViewTypes &out);
};
}
}

#endif
