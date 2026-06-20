/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_ANS_SERVICE_ERRORS_H
#define BASE_NOTIFICATION_ANS_SERVICE_ERRORS_H

#include <cstdint>
#include <string>
#include "errors.h"

namespace OHOS {
namespace Notification {
/**
 * Service-layer error code group base values.
 * Groups are spaced 10,000 apart to allow for future expansion.
 */
constexpr int32_t ERR_ANS_INNER_BASE_INFRA          = 100000;
constexpr int32_t ERR_ANS_INNER_BASE_PERMISSION     = 110000;
constexpr int32_t ERR_ANS_INNER_BASE_PARAM          = 120000;
constexpr int32_t ERR_ANS_INNER_BASE_NOTIFICATION   = 130000;
constexpr int32_t ERR_ANS_INNER_BASE_SLOT           = 140000;
constexpr int32_t ERR_ANS_INNER_BASE_SUBSCRIBE      = 150000;
constexpr int32_t ERR_ANS_INNER_BASE_DISTRIBUTED    = 160000;
constexpr int32_t ERR_ANS_INNER_BASE_GEOFENCE       = 170000;
constexpr int32_t ERR_ANS_INNER_BASE_PUSH           = 180000;
constexpr int32_t ERR_ANS_INNER_BASE_DIALOG         = 190000;
constexpr int32_t ERR_ANS_INNER_BASE_ENCRYPT        = 200000;
constexpr int32_t ERR_ANS_INNER_BASE_AGENT_EXT      = 210000;

/**
 * Service-layer error code enumeration.
 * Unified error codes used by AnsNotification, IPC, and the Service layer.
 */
enum InnerErrorCode : int32_t {
    // ===== Group 0: Infrastructure (100000+) =====
    ERR_ANS_INNER_OK                              = 0,
    ERR_ANS_INNER_SERVICE_NOT_READY               = ERR_ANS_INNER_BASE_INFRA + 1,
    ERR_ANS_INNER_SERVICE_NOT_CONNECTED           = ERR_ANS_INNER_BASE_INFRA + 2,
    ERR_ANS_INNER_PARCELABLE_FAILED               = ERR_ANS_INNER_BASE_INFRA + 3,
    ERR_ANS_INNER_TRANSACT_FAILED                 = ERR_ANS_INNER_BASE_INFRA + 4,
    ERR_ANS_INNER_REMOTE_DEAD                     = ERR_ANS_INNER_BASE_INFRA + 5,
    ERR_ANS_INNER_NO_MEMORY                       = ERR_ANS_INNER_BASE_INFRA + 6,
    ERR_ANS_INNER_TASK_ERR                        = ERR_ANS_INNER_BASE_INFRA + 7,
    ERR_ANS_INNER_INVALID_OPERATION               = ERR_ANS_INNER_BASE_INFRA + 8,

    // ===== Group 1: Permission (110000+) =====
    ERR_ANS_INNER_PERMISSION_DENIED               = ERR_ANS_INNER_BASE_PERMISSION + 1,
    ERR_ANS_INNER_NON_SYSTEM_APP                  = ERR_ANS_INNER_BASE_PERMISSION + 2,
    ERR_ANS_INNER_NOT_SYSTEM_SERVICE              = ERR_ANS_INNER_BASE_PERMISSION + 3,
    ERR_ANS_INNER_NOT_ALLOWED                     = ERR_ANS_INNER_BASE_PERMISSION + 4,

    // ===== Group 2: Parameter validation (120000+) =====
    ERR_ANS_INNER_INVALID_PARAM                   = ERR_ANS_INNER_BASE_PARAM + 1,
    ERR_ANS_INNER_INVALID_UID                     = ERR_ANS_INNER_BASE_PARAM + 2,
    ERR_ANS_INNER_INVALID_PID                     = ERR_ANS_INNER_BASE_PARAM + 3,
    ERR_ANS_INNER_INVALID_BUNDLE                  = ERR_ANS_INNER_BASE_PARAM + 4,
    ERR_ANS_INNER_INVALID_BUNDLE_OPTION           = ERR_ANS_INNER_BASE_PARAM + 5,
    ERR_ANS_INNER_ICON_OVER_SIZE                  = ERR_ANS_INNER_BASE_PARAM + 6,
    ERR_ANS_INNER_PICTURE_OVER_SIZE               = ERR_ANS_INNER_BASE_PARAM + 7,
    ERR_ANS_INNER_PUSH_CHECK_EXTRAINFO_INVALID    = ERR_ANS_INNER_BASE_PARAM + 8,

    // ===== Group 3: Notification management (130000+) =====
    ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS         = ERR_ANS_INNER_BASE_NOTIFICATION + 1,
    ERR_ANS_INNER_NOTIFICATION_IS_UNREMOVABLE     = ERR_ANS_INNER_BASE_NOTIFICATION + 2,
    ERR_ANS_INNER_NOTIFICATION_IS_UNALLOWED_REMOVEALLOWED = ERR_ANS_INNER_BASE_NOTIFICATION + 3,
    ERR_ANS_INNER_OVER_MAX_ACTIVE_PERSECOND       = ERR_ANS_INNER_BASE_NOTIFICATION + 4,
    ERR_ANS_INNER_OVER_MAX_UPDATE_PERSECOND       = ERR_ANS_INNER_BASE_NOTIFICATION + 5,
    ERR_ANS_INNER_DUPLICATE_MSG                   = ERR_ANS_INNER_BASE_NOTIFICATION + 6,
    ERR_ANS_INNER_EXPIRED_NOTIFICATION            = ERR_ANS_INNER_BASE_NOTIFICATION + 7,
    ERR_ANS_INNER_REPEAT_CREATE                   = ERR_ANS_INNER_BASE_NOTIFICATION + 8,
    ERR_ANS_INNER_END_NOTIFICATION                = ERR_ANS_INNER_BASE_NOTIFICATION + 9,
    ERR_ANS_INNER_DIALOG_POP_SUCCEEDED            = ERR_ANS_INNER_BASE_NOTIFICATION + 10,

    // ===== Group 4: Slot/channel (140000+) =====
    ERR_ANS_INNER_PREFERENCES_NOTIFICATION_SLOT_NOT_EXIST       = ERR_ANS_INNER_BASE_SLOT + 1,
    ERR_ANS_INNER_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST     = ERR_ANS_INNER_BASE_SLOT + 2,
    ERR_ANS_INNER_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST  = ERR_ANS_INNER_BASE_SLOT + 3,
    ERR_ANS_INNER_PREFERENCES_NOTIFICATION_SLOTGROUP_NOT_EXIST  = ERR_ANS_INNER_BASE_SLOT + 4,
    ERR_ANS_INNER_PREFERENCES_NOTIFICATION_SLOTGROUP_ID_INVALID = ERR_ANS_INNER_BASE_SLOT + 5,
    ERR_ANS_INNER_PREFERENCES_NOTIFICATION_SLOTGROUP_EXCEED_MAX_NUM = ERR_ANS_INNER_BASE_SLOT + 6,
    ERR_ANS_INNER_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED  = ERR_ANS_INNER_BASE_SLOT + 7,
    ERR_ANS_INNER_PREFERENCES_NOTIFICATION_READ_TEMPLATE_CONFIG_FAILED = ERR_ANS_INNER_BASE_SLOT + 8,
    ERR_ANS_INNER_PREFERENCES_NOTIFICATION_SLOT_ENABLED         = ERR_ANS_INNER_BASE_SLOT + 9,

    // ===== Group 5: Subscription (150000+) =====
    ERR_ANS_INNER_SUBSCRIBER_IS_DELETING          = ERR_ANS_INNER_BASE_SUBSCRIBE + 1,
    ERR_ANS_INNER_LOCAL_SUBSCRIBE_CHECK_FAILED    = ERR_ANS_INNER_BASE_SUBSCRIBE + 2,
    ERR_ANS_INNER_GET_ACTIVE_USER_FAILED          = ERR_ANS_INNER_BASE_SUBSCRIBE + 3,
    ERR_ANS_INNER_USER_NOT_EXIST                  = ERR_ANS_INNER_BASE_SUBSCRIBE + 4,

    // ===== Group 6: Distributed (160000+) =====
    ERR_ANS_INNER_DISTRIBUTED_OPERATION_FAILED    = ERR_ANS_INNER_BASE_DISTRIBUTED + 1,
    ERR_ANS_INNER_DISTRIBUTED_GET_INFO_FAILED     = ERR_ANS_INNER_BASE_DISTRIBUTED + 2,
    ERR_ANS_INNER_OPERATION_TIMEOUT               = ERR_ANS_INNER_BASE_DISTRIBUTED + 3,

    // ===== Group 7: Geofence (170000+) =====
    ERR_ANS_INNER_GEOFENCE_ENABLED                = ERR_ANS_INNER_BASE_GEOFENCE + 1,
    ERR_ANS_INNER_GEOFENCE_EXCEEDED               = ERR_ANS_INNER_BASE_GEOFENCE + 2,
    ERR_ANS_INNER_GEOFENCING_OPERATION_TIMEOUT    = ERR_ANS_INNER_BASE_GEOFENCE + 3,
    ERR_ANS_INNER_ERROR_LOCATION_CLOSED           = ERR_ANS_INNER_BASE_GEOFENCE + 4,
    ERR_ANS_INNER_AWARNESS_SUGGESTIONS_CLOSED     = ERR_ANS_INNER_BASE_GEOFENCE + 5,
    ERR_ANS_INNER_CHECK_WEAK_NETWORK              = ERR_ANS_INNER_BASE_GEOFENCE + 6,

    // ===== Group 8: Push (180000+) =====
    ERR_ANS_INNER_PUSH_CHECK_FAILED               = ERR_ANS_INNER_BASE_PUSH + 1,
    ERR_ANS_INNER_PUSH_CHECK_UNREGISTERED         = ERR_ANS_INNER_BASE_PUSH + 2,
    ERR_ANS_INNER_PUSH_CHECK_NETWORK_UNREACHABLE  = ERR_ANS_INNER_BASE_PUSH + 3,

    // ===== Group 9: Dialog (190000+) =====
    ERR_ANS_INNER_DIALOG_IS_POPPING               = ERR_ANS_INNER_BASE_DIALOG + 1,
    ERR_ANS_INNER_SETTING_WINDOW_EXIST            = ERR_ANS_INNER_BASE_DIALOG + 2,

    // ===== Group 10: Encryption (200000+) =====
    ERR_ANS_INNER_ENCRYPT_FAIL                    = ERR_ANS_INNER_BASE_ENCRYPT + 1,
    ERR_ANS_INNER_DECRYPT_FAIL                    = ERR_ANS_INNER_BASE_ENCRYPT + 2,

    // ===== Group 11: Agent/Extension (210000+) =====
    ERR_ANS_INNER_NO_AGENT_SETTING                = ERR_ANS_INNER_BASE_AGENT_EXT + 1,
    ERR_ANS_INNER_NO_PROFILE_TEMPLATE             = ERR_ANS_INNER_BASE_AGENT_EXT + 2,
    ERR_ANS_INNER_REJECTED_WITH_DISABLE_NOTIFICATION = ERR_ANS_INNER_BASE_AGENT_EXT + 3,
    ERR_ANS_INNER_NO_CUSTOM_RINGTONE_INFO         = ERR_ANS_INNER_BASE_AGENT_EXT + 4,
    ERR_ANS_INNER_VOICE_SUMMARY_COUNT_EXCEEDED    = ERR_ANS_INNER_BASE_AGENT_EXT + 5,
    ERR_ANS_INNER_DEVICE_NOT_SUPPORT              = ERR_ANS_INNER_BASE_AGENT_EXT + 6,
    ERR_ANS_INNER_NOT_IMPL_EXTENSIONABILITY       = ERR_ANS_INNER_BASE_AGENT_EXT + 7,
    ERR_ANS_INNER_DLP_HAP                         = ERR_ANS_INNER_BASE_AGENT_EXT + 8,
    ERR_ANS_INNER_NOTIFICATION_SNOOZE_NOTALLOWED  = ERR_ANS_INNER_BASE_AGENT_EXT + 9,
    ERR_ANS_INNER_CUSTOM_EXTENSION_EXISTS_CHECK_FAILED = ERR_ANS_INNER_BASE_AGENT_EXT + 10,
    ERR_ANS_INNER_CUSTOM_EXTENSION_RIGHTS_CHECK_FAILED = ERR_ANS_INNER_BASE_AGENT_EXT + 11,
};

/**
 * Convert a Service-layer error code to an external error code.
 *
 * Single-pass lookup: checks SERVICE_ERROR_CONVERT_TABLE once,
 * matching both innerCode and nativeCode in the same loop.
 * Falls back to idempotency pass-through for already-converted
 * external codes; otherwise returns ERROR_INTERNAL_ERROR.
 *
 * @param innerErrCode A InnerErrorCode value or a legacy Inner API error code.
 * @return The corresponding external error code, or ERROR_INTERNAL_ERROR if unknown.
 */
int32_t InnerErrorToExternal(int32_t innerErrCode);

/**
 * Convert a Service-layer error code to an Inner API error code (ERR_ANS_*).
 * @param innerErrCode A InnerErrorCode value.
 * @return The corresponding Inner API error code, or ERR_ANS_TASK_ERR if unknown.
 */
ErrCode InnerErrorToNative(int32_t innerErrCode);

/**
 * Convert native error code (returned by NotificationHelper) to external error code.
 *
 * NotificationHelper returns InnerErrorCode via ServiceErrorToInner conversion.
 * This function converts that InnerErrorCode to the corresponding ExternalCode
 * for display to users in legacy (deprecated) API layers.
 *
 * @param nativeErrCode Native error code (InnerErrorCode returned by NotificationHelper).
 * @return The corresponding external error code (e.g. 1600001, 401), or ERROR_INTERNAL_ERROR if unknown.
 */
int32_t NativeErrorToExternal(int32_t nativeErrCode);

// ===== Error message queries =====

/**
 * Get a human-readable message for an external error code.
 *
 * Looks up the message in the unified conversion table by external code.
 *
 * @param externalErrCode An external error code (e.g. 1600001).
 * @param defaultMsg Fallback message for unknown codes.
 * @return The error message string.
 */
std::string GetExternalErrMessage(int32_t externalErrCode, std::string defaultMsg = "");

/**
 * @brief Get error message by inner error code
 *
 * @param innerErrCode Inner error code (ERR_ANS_INNER_*)
 * @param defaultMsg Default message if error code not found
 * @return std::string Error message
 */
std::string GetInnerErrMessage(int32_t innerErrCode, std::string defaultMsg = "");

}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_SERVICE_ERRORS_H
