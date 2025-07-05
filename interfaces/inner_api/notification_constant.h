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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_CONSTANT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_CONSTANT_H

#include <string>

namespace OHOS {
namespace Notification {
class NotificationConstant {
public:
    enum InputEditType {
        EDIT_AUTO,      // Indicates that the system determines whether to allow the user to edit the options before
                        // they are sent to the application.
        EDIT_DISABLED,  // Indicates that the user is not allowed to edit an option before the option is sent to the
                        // application.
        EDIT_ENABLED,   // Indicates that the user is allowed to edit an option before the option is sent to the
                        // application.
    };

    enum InputsSource {
        FREE_FORM_INPUT,  // Indicates that the user manually input the content.
        OPTION,           // Indicates that the user selected one of the provided options.
    };

    enum SemanticActionButton {
        NONE_ACTION_BUTTON,         // Indicates that no WantAgent is associated.
        REPLY_ACTION_BUTTON,        // Indicates the action of replying to a conversation.
        READ_ACTION_BUTTON,         // Indicates the action of marking the content as read.
        UNREAD_ACTION_BUTTON,       // Indicates the action of marking the content as unread.
        DELETE_ACTION_BUTTON,       // Indicates the action of deleting the content associated with the notification.
        ARCHIVE_ACTION_BUTTON,      // Indicates the action of archiving the content associated with the notification.
        MUTE_ACTION_BUTTON,         // Indicates the action of muting the content associated with the notification.
        UNMUTE_ACTION_BUTTON,       // Indicates the action of unmuting the content associated with the notification.
        THUMBS_UP_ACTION_BUTTON,    // Indicates the action of marking the content with a thumbs-up.
        THUMBS_DOWN_ACTION_BUTTON,  // Indicates the action of marking the content with a thumbs-down.
        CALL_ACTION_BUTTON,         // Indicates the action of making a call.
    };

    enum SubscribeResult : uint32_t {
        SUCCESS,
        PREMISSION_FAIL,
        RESOURCES_FAIL,
    };

    enum SlotType {
        SOCIAL_COMMUNICATION,   // the notification type is social communication
        SERVICE_REMINDER,       // the notification type is service reminder
        CONTENT_INFORMATION,    // the notificatin type is content information
        OTHER,                  // the notificatin type is other
        CUSTOM,                 // the notification type is custom
        LIVE_VIEW,              // the notification type is live view
        CUSTOMER_SERVICE,       // the notification type is customer service
        EMERGENCY_INFORMATION,  // the notification type is emergency information
        ILLEGAL_TYPE,           // invalid type,it is used as the upper limit of the enumerated value
    };

    enum ReminderFlag {
        SOUND_FLAG = 1 << 0,
        LOCKSCREEN_FLAG = 1 << 1,
        BANNER_FLAG = 1 << 2,
        LIGHTSCREEN_FLAG = 1 << 3,
        VIBRATION_FLAG = 1 << 4,
        STATUSBAR_ICON_FLAG = 1 << 5,
        SA_SELF_BANNER_FLAG = 1 << 9,
    };

    enum DistributedDeleteType {
        ALL,
        SLOT,
        EXCLUDE_ONE_SLOT,
        HASHCODES,
        DEVICE_ID,
    };

    enum class VisiblenessType {
        /**
         * the notification display effect has not been set by NotificationRequest::setVisibleness().
         * This method is usually not used.
         */
        NO_OVERRIDE,
        /**
         * only the basic information, such as application icon and application name is displayed on the lock screen.
         */
        PRIVATE,
        /**
         * contents of a notification are displayed on the lock screen.
         */
        PUBLIC,
        /**
         * notifications are not displayed on the lock screen.
         */
        SECRET,
        /**
         * invalid type
         * It is used as the upper limit of the enumerated value.
         */
        ILLEGAL_TYPE
    };

    enum class DoNotDisturbType {
        NONE    = 0,
        ONCE    = 1,    // only once
        DAILY   = 2,    // every day
        CLEARLY = 3,    // time period
    };

    enum class RemindType {
        NONE                       = -1,
        DEVICE_IDLE_DONOT_REMIND   = 0, // The device is not in use, no reminder
        DEVICE_IDLE_REMIND         = 1, // The device is not in use, remind
        DEVICE_ACTIVE_DONOT_REMIND = 2, // The device is in use, no reminder
        DEVICE_ACTIVE_REMIND       = 3, // The device is in use, reminder
    };

    enum class DistributedReminderPolicy {
        DEFAULT,
        ALWAYS_REMIND,
        DO_NOT_REMIND,
    };

    enum class SourceType {
        /**
         * general notification.
         */
        TYPE_NORMAL = 0x00000000,
        /**
         * long-term task notification.
         */
        TYPE_CONTINUOUS = 0x00000001,
        /**
         * timed notification.
         */
        TYPE_TIMER = 0x00000002
    };

    enum class FlagStatus {
        NONE,
        OPEN,
        CLOSE
    };

    enum class SWITCH_STATE {
        /**
         * Represents an off state that was explicitly set bt the user.
         */
        SYSTEM_DEFAULT_OFF,

        /**
         * Represents an on state that was explicitly set bt the user.
         */
        SYSTEM_DEFAULT_ON,

        /**
         * Represents an initial off state before any user modification.
         */
        USER_MODIFIED_OFF,

        /**
         * Represents an initial on state before any user modification.
         */
        USER_MODIFIED_ON
    };

    enum class DANS_SUPPORT_STATUS {
        /**
         * unsupport the set of distributed abilities.
         */
        UNSUPPORT = -1,

        /**
         * support the set of distributed abilities.
         */
        SUPPORT
    };

    static const int32_t DEFAULT_REASON_DELETE = 0;

    /**
     * Indicates that a notification is deleted because it is clicked.
     */
    static const int32_t CLICK_REASON_DELETE = 1;

    /**
     * Indicates that a notification is deleted because the user clears it.
     */
    static const int32_t CANCEL_REASON_DELETE = 2;

    /**
     * Indicates that a notification is deleted because the user clears all notifications.
     */
    static const int32_t CANCEL_ALL_REASON_DELETE = 3;

    /**
     * Indicates that a notification is deleted because of a UI error.
     */
    static const int32_t ERROR_REASON_DELETE = 4;

    /**
     * Indicates that a notification is deleted because a change has been made to the application.
     */
    static const int32_t PACKAGE_CHANGED_REASON_DELETE = 5;

    /**
     * Indicates that a notification is deleted because the application context is stopped.
     */
    static const int32_t USER_STOPPED_REASON_DELETE = 6;

    /**
     * Indicates that a notification is deleted because the application is banned from sending notifications.
     */
    static const int32_t PACKAGE_BANNED_REASON_DELETE = 7;

    /**
     * Indicates that a notification is deleted because the application cancels it.
     */
    static const int32_t APP_CANCEL_REASON_DELETE = 8;

    /**
     * Indicates that a notification is deleted because the application cancels all notifications.
     */
    static const int32_t APP_CANCEL_ALL_REASON_DELETE = 9;
    
    /**
     * Indicates that a notification is deleted because this user is removed.
     */
    static const int32_t USER_REMOVED_REASON_DELETE = 10;

    /**
     * Indicates that a notification is deleted because of flow control.
     */
    static const int32_t FLOW_CONTROL_REASON_DELETE = 11;

    /**
     * Indicates that a notification is deleted because enable state is changed.
     */
    static const int32_t DISABLE_SLOT_REASON_DELETE = 12;

    /**
     * Indicates that a notification is deleted because enable state is changed.
     */
    static const int32_t DISABLE_NOTIFICATION_REASON_DELETE = 13;

    /**
     * Indicates that a notification is deleted by bundle because the application cancel it.
     */
    static const int32_t APP_CANCEL_AS_BUNELE_REASON_DELETE = 14;

    /**
     * Indicates that a notification is deleted by agent because the application cancel it.
     */
    static const int32_t APP_CANCEL_AS_BUNELE_WITH_AGENT_REASON_DELETE = 15;

    /**
     * Indicates that a notification is deleted because the reminder cancel it.
     */
    static const int32_t APP_CANCEL_REMINDER_REASON_DELETE = 16;

    /**
     * Indicates that a notification is deleted because the application cancel it by group.
     */
    static const int32_t APP_CANCEL_GROPU_REASON_DELETE = 17;
    
    /**
     * Indicates that a notification is deleted by group because the system cancel it.
     */
    static const int32_t APP_REMOVE_GROUP_REASON_DELETE = 18;

    /**
     * Indicates that aLL notification is deleted because the system cancel it.
     */
    static const int32_t APP_REMOVE_ALL_REASON_DELETE = 19;

    /**
     * Indicates that aLL notification is deleted by userId because the system cancel it.
     */
    static const int32_t APP_REMOVE_ALL_USER_REASON_DELETE = 20;

    /**
     * Indicates that notification is deleted because eight-hour timer cancel it.
     */
    static const int32_t TRIGGER_EIGHT_HOUR_REASON_DELETE = 21;

    /**
     * Indicates that notification is deleted because four-hour timer cancel it.
     */
    static const int32_t TRIGGER_FOUR_HOUR_REASON_DELETE = 22;

    /**
     * Indicates that notification is deleted because ten-minutes timer cancel it.
     */
    static const int32_t TRIGGER_TEN_MINUTES_REASON_DELETE = 23;
    
    /**
     * Indicates that notification is deleted because fifteen-minutes timer cancel it.
     */
    static const int32_t TRIGGER_FIFTEEN_MINUTES_REASON_DELETE = 24;

    /**
     * Indicates that notification is deleted because thirty-minutes timer cancel it.
     */
    static const int32_t TRIGGER_THIRTY_MINUTES_REASON_DELETE = 25;

    /**
     * Indicates that notification is deleted because startArchive timer cancel it.
     */
    static const int32_t TRIGGER_START_ARCHIVE_REASON_DELETE = 26;

    /**
     * Indicates that notification is deleted because auto delete timer cancel it.
     */
    static const int32_t TRIGGER_AUTO_DELETE_REASON_DELETE = 27;

    /**
     * Indicates that notification is deleted because auto packge remove cancel it.
     */
    static const int32_t PACKAGE_REMOVE_REASON_DELETE = 28;

    /**
     * Indicates that notification is deleted because slot enabled close remove cancel it.
     */
    static const int32_t SLOT_ENABLED_REASON_DELETE = 29;

    /**
     * Indicates that a notification is deleted because recover live live validated need delete.
     */
    static const int32_t RECOVER_LIVE_VIEW_DELETE = 30;

    /**
     * Indicates that a notification is deleted because disable.
     */
    static const int32_t DISABLE_NOTIFICATION_FEATURE_REASON_DELETE = 31;

    /**
     * Indicates that a notification is deleted because collaborative delete.
     */
    static const int32_t DISTRIBUTED_COLLABORATIVE_DELETE = 32;

    /**
     * Indicates that a notification is deleted because this user is removed.
     */
    static const int32_t USER_LOGOUT_REASON_DELETE = 33;

    /**
     * Indicates that a notification is deleted because collaboration click.
     */
    static const int32_t DISTRIBUTED_COLLABORATIVE_CLICK_DELETE = 34;
    
    /**
     * Indicates that a notification is deleted because distributed enable close removed.
     */
    static const int32_t DISTRIBUTED_ENABLE_CLOSE_DELETE = 35;

    /**
     * Indicates that a notification is deleted because distributed release removed.
     */
    static const int32_t DISTRIBUTED_RELEASE_DELETE = 36;

    /**
     * Indicates that a notification is deleted for other reasons.
     */
    static const int32_t APP_CANCEL_REASON_OTHER = 100;

    /**
     * The key indicates input source.
     */
    static const std::string EXTRA_INPUTS_SOURCE;

    static const int64_t HOUR_TO_MS = 3600000;

    static const int64_t SECOND_TO_MS = 1000;
    
    static const int64_t TEN_MINUTES = 600000;
    
    static const int64_t FIFTEEN_MINUTES = 900000;
    
    static const int64_t THIRTY_MINUTES = 1800000;
    
    static const int64_t FINISH_PER = 100;
    
    static const int64_t DEFAULT_FINISH_STATUS = -1;

    static const int64_t MAX_FINISH_TIME = 8 * HOUR_TO_MS;

    static const int64_t MAX_UPDATE_TIME = 4 * HOUR_TO_MS;

    static const int64_t INVALID_AUTO_DELETE_TIME = -1;

    /* one hour */
    static const int64_t DEFAULT_AUTO_DELETE_TIME = 3600;

    static const int64_t NO_DELAY_DELETE_TIME = 0;

    static constexpr uint64_t INVALID_TIMER_ID = 0ULL;

    static constexpr int32_t ANS_UID = 5523;

    static const int32_t MAX_BTN_NUM = 3;
 
    static const int32_t DISTRIBUTE_JUMP_INVALID = -1;
 
    static const int32_t DISTRIBUTE_JUMP_BY_NTF = 0;
 
    static const int32_t DISTRIBUTE_JUMP_BY_BTN = 1;
 
    static const int32_t DISTRIBUTE_JUMP_BY_LIVE_VIEW = 32;

    // live view max size is 512KB(extra size) + 8KB(base size) = 520KB
    static constexpr uint64_t NOTIFICATION_MAX_LIVE_VIEW_SIZE = 520ULL * 1024ULL;

    // rdb
    constexpr static const char* NOTIFICATION_RDB_NAME = "/notificationdb.db";
    constexpr static const char* NOTIFICATION_RDB_TABLE_NAME = "notification_table";
    constexpr static const char* NOTIFICATION_RDB_PATH = "/data/service/el1/public/database/notification_service";
    constexpr static const char* NOTIFICATION_JOURNAL_MODE = "WAL";
    constexpr static const char* NOTIFICATION_SYNC_MODE = "FULL";
    constexpr static int32_t NOTIFICATION_RDB_VERSION = 1;
    constexpr static const char* SLOTTYPECCMNAMES[] = {"Social_communication", "Service_reminder",
        "Content_information", "Other", "Custom", "Live_view", "Custom_service", "Emergency_information"};
    constexpr static const char* CURRENT_DEVICE_TYPE = "current";
    constexpr static const char* HEADSET_DEVICE_TYPE = "headset";
    constexpr static const char* LITEWEARABLE_DEVICE_TYPE = "liteWearable";
    constexpr static const char* WEARABLE_DEVICE_TYPE = "wearable";
    constexpr static const char* PAD_DEVICE_TYPE = "pad";
    constexpr static const char* PC_DEVICE_TYPE = "pc";
    constexpr static const char* DEVICESTYPES[] = {"headset", "liteWearable", "wearable", "pc", "pad"};
    constexpr static const char* ANS_VOIP = "ANS_VOIP";
    constexpr static const char* PC_PAD_VOIP_FLAG = "110101";
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_CONSTANT_H
