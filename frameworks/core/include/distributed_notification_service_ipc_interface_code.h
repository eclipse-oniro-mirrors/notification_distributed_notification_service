/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_DISTRIBUTED_NOTIFICATION_SERVICE_IPC_INTERFACE_CODE_H
#define BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_DISTRIBUTED_NOTIFICATION_SERVICE_IPC_INTERFACE_CODE_H

#include "iremote_broker.h"

/* SAID: 3203 */
namespace OHOS {
namespace Notification {
    enum class NotificationInterfaceCode {
        // ans_manager_interface
        PUBLISH_NOTIFICATION = FIRST_CALL_TRANSACTION,
        PUBLISH_NOTIFICATION_TO_DEVICE, // Obsolete
        CANCEL_NOTIFICATION,
        CANCEL_ALL_NOTIFICATIONS,
        CANCEL_AS_BUNDLE,
        ADD_SLOT_BY_TYPE,
        ADD_SLOTS,
        REMOVE_SLOT_BY_TYPE,
        REMOVE_ALL_SLOTS,
        ADD_SLOT_GROUPS,
        GET_SLOT_BY_TYPE,
        GET_SLOTS,
        GET_SLOT_GROUP,
        GET_SLOT_GROUPS,
        GET_SLOT_NUM_AS_BUNDLE,
        REMOVE_SLOT_GROUPS,
        GET_ACTIVE_NOTIFICATIONS,
        GET_ACTIVE_NOTIFICATION_NUMS,
        GET_ALL_ACTIVE_NOTIFICATIONS,
        GET_SPECIAL_ACTIVE_NOTIFICATIONS,
        SET_NOTIFICATION_AGENT,
        GET_NOTIFICATION_AGENT,
        CAN_PUBLISH_AS_BUNDLE,
        PUBLISH_AS_BUNDLE,
        SET_NOTIFICATION_BADGE_NUM,
        GET_BUNDLE_IMPORTANCE,
        IS_NOTIFICATION_POLICY_ACCESS_GRANTED,
        REMOVE_NOTIFICATION,
        REMOVE_ALL_NOTIFICATIONS,
        REMOVE_NOTIFICATIONS_BY_KEYS,
        DELETE_NOTIFICATION,
        DELETE_NOTIFICATION_BY_BUNDLE,
        DELETE_ALL_NOTIFICATIONS,
        GET_SLOTS_BY_BUNDLE,
        UPDATE_SLOTS,
        UPDATE_SLOT_GROUPS,
        REQUEST_ENABLE_NOTIFICATION,
        SET_NOTIFICATION_ENABLED_FOR_BUNDLE,
        SET_NOTIFICATION_ENABLED_FOR_ALL_BUNDLE,
        SET_NOTIFICATION_ENABLED_FOR_SPECIAL_BUNDLE,
        SET_SHOW_BADGE_ENABLED_FOR_BUNDLE,
        GET_SHOW_BADGE_ENABLED_FOR_BUNDLE,
        GET_SHOW_BADGE_ENABLED,
        SUBSCRIBE_NOTIFICATION,
        UNSUBSCRIBE_NOTIFICATION,
        ARE_NOTIFICATION_SUSPENDED, // Obsolete
        GET_CURRENT_APP_SORTING,    // Obsolete
        IS_ALLOWED_NOTIFY,
        IS_ALLOWED_NOTIFY_SELF,
        IS_SPECIAL_BUNDLE_ALLOWED_NOTIFY,
        SET_DO_NOT_DISTURB_DATE,
        GET_DO_NOT_DISTURB_DATE,
        DOES_SUPPORT_DO_NOT_DISTURB_MODE,
        CANCEL_GROUP,
        REMOVE_GROUP_BY_BUNDLE,
        IS_DISTRIBUTED_ENABLED,
        ENABLE_DISTRIBUTED,
        ENABLE_DISTRIBUTED_BY_BUNDLE,
        ENABLE_DISTRIBUTED_SELF,
        IS_DISTRIBUTED_ENABLED_BY_BUNDLE,
        GET_DEVICE_REMIND_TYPE,
        SHELL_DUMP,
        PUBLISH_CONTINUOUS_TASK_NOTIFICATION,
        CANCEL_CONTINUOUS_TASK_NOTIFICATION,
        PUBLISH_REMINDER,
        CANCEL_REMINDER,
        CANCEL_ALL_REMINDERS,
        GET_ALL_VALID_REMINDERS,
        IS_SUPPORT_TEMPLATE,
        IS_SPECIAL_USER_ALLOWED_NOTIFY,
        SET_NOTIFICATION_ENABLED_BY_USER,
        DELETE_ALL_NOTIFICATIONS_BY_USER,
        SET_DO_NOT_DISTURB_DATE_BY_USER,
        GET_DO_NOT_DISTURB_DATE_BY_USER,
        SET_ENABLED_FOR_BUNDLE_SLOT,
        GET_ENABLED_FOR_BUNDLE_SLOT,
        SET_SYNC_NOTIFICATION_ENABLED_WITHOUT_APP,
        GET_SYNC_NOTIFICATION_ENABLED_WITHOUT_APP,
        SET_BADGE_NUMBER,
        REGISTER_PUSH_CALLBACK,
        UNREGISTER_PUSH_CALLBACK,
        // ans_subscriber_interface
        ON_CONNECTED,
        ON_DISCONNECTED,
        ON_CONSUMED, // Obsolete
        ON_CONSUMED_MAP,
        ON_CANCELED_MAP,
        ON_CANCELED_LIST_MAP,
        ON_UPDATED,
        ON_DND_DATE_CHANGED,
        ON_ENABLED_NOTIFICATION_CHANGED,
        ON_BADGE_CHANGED,
        // push_callback_interface
        ON_CHECK_NOTIFICATION,
        ON_RESPONSE,
        SUBSCRIBE_LOCAL_LIVE_VIEW_NOTIFICATION,
        TRIGGER_LOCAL_LIVE_VIEW_NOTIFICATION,
    };
}
}

#endif