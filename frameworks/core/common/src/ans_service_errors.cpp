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

#include "ans_service_errors.h"

#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ipc_types.h"

namespace OHOS {
namespace Notification {
struct ServiceErrorConvertEntry {
    int32_t innerCode;
    ErrCode nativeCode;
    int32_t externalCode;
    std::string message;
};

/**
 * Unified conversion table: each row maps InnerErrorCode → nativeCode →
 * ExternalCode → Message.
 *
 * The `message` field is kept identical with the corresponding entry in the
 * legacy ANS_ERROR_CODE_MESSAGE_MAP so that the same error produces the same
 * user-facing text regardless of which path is taken.
 */
static const std::vector<ServiceErrorConvertEntry> SERVICE_ERROR_CONVERT_TABLE = {
    // ===== Infrastructure =====
    {ERR_ANS_INNER_SERVICE_NOT_READY,       ERR_ANS_SERVICE_NOT_READY,       ERROR_SERVICE_CONNECT_ERROR,
        "Failed to connect to the service"},
    {ERR_ANS_INNER_SERVICE_NOT_CONNECTED,   ERR_ANS_SERVICE_NOT_CONNECTED,   ERROR_SERVICE_CONNECT_ERROR,
        "Failed to connect to the service"},
    {ERR_ANS_INNER_PARCELABLE_FAILED,       ERR_ANS_PARCELABLE_FAILED,       ERROR_IPC_ERROR,
        "Marshalling or unmarshalling error"},
    {ERR_ANS_INNER_TRANSACT_FAILED,         ERR_ANS_TRANSACT_FAILED,         ERROR_IPC_ERROR,
        "Marshalling or unmarshalling error"},
    {ERR_ANS_INNER_REMOTE_DEAD,             ERR_ANS_REMOTE_DEAD,             ERROR_IPC_ERROR,
        "Marshalling or unmarshalling error"},
    {ERR_INVALID_VALUE,                     ERR_INVALID_VALUE,               ERROR_IPC_ERROR,
        "Marshalling or unmarshalling error"},
    {ERR_INVALID_DATA,                      ERR_INVALID_DATA,                ERROR_IPC_ERROR,
        "Marshalling or unmarshalling error"},
    {DEAD_OBJECT,                           DEAD_OBJECT,                     ERROR_IPC_ERROR,
        "Marshalling or unmarshalling error"},
    {ERR_ANS_INNER_NO_MEMORY,              ERR_ANS_NO_MEMORY,               ERROR_NO_MEMORY,
        "Memory operation failed"},
    {ERR_ANS_INNER_TASK_ERR,               ERR_ANS_TASK_ERR,                ERROR_INTERNAL_ERROR,
        "Internal error. Possible cause: 1.IPC communication failed. 2.Memory operation error"},
    {ERR_ANS_INNER_INVALID_OPERATION,      ERR_INVALID_OPERATION,           ERROR_INTERNAL_ERROR,
        "Invalid operation"},

    // ===== Permission =====
    {ERR_ANS_INNER_PERMISSION_DENIED,      ERR_ANS_PERMISSION_DENIED,       ERROR_PERMISSION_DENIED,
        "Permission denied"},
    {ERR_ANS_INNER_NON_SYSTEM_APP,         ERR_ANS_NON_SYSTEM_APP,          ERROR_NOT_SYSTEM_APP,
        "Not system application to call the interface"},
    {ERR_ANS_INNER_NOT_SYSTEM_SERVICE,     ERR_ANS_NOT_SYSTEM_SERVICE,      ERROR_NOT_SYSTEM_APP,
        "Not system application to call the interface"},
    {ERR_ANS_INNER_NOT_ALLOWED,            ERR_ANS_NOT_ALLOWED,             ERROR_NOTIFICATION_CLOSED,
        "Notification disabled"},

    // ===== Parameter validation =====
    {ERR_ANS_INNER_INVALID_PARAM,          ERR_ANS_INVALID_PARAM,           ERROR_PARAM_INVALID,
        "Invalid parameter"},
    {ERR_ANS_INNER_INVALID_UID,            ERR_ANS_INVALID_UID,             ERROR_PARAM_INVALID,
        "Invalid parameter"},
    {ERR_ANS_INNER_INVALID_PID,            ERR_ANS_INVALID_PID,             ERROR_BUNDLE_NOT_FOUND,
        "The specified bundle name was not found"},
    {ERR_ANS_INNER_INVALID_BUNDLE,         ERR_ANS_INVALID_BUNDLE,          ERROR_BUNDLE_NOT_FOUND,
        "The specified bundle name was not found"},
    {ERR_ANS_INNER_INVALID_BUNDLE_OPTION,  ERR_ANS_INVALID_BUNDLE_OPTION,   ERROR_BUNDLE_INVALID,
        "The specified bundle is invalid"},
    {ERR_ANS_INNER_ICON_OVER_SIZE,         ERR_ANS_ICON_OVER_SIZE,          ERROR_PARAM_INVALID,
        "Invalid parameter"},
    {ERR_ANS_INNER_PICTURE_OVER_SIZE,      ERR_ANS_PICTURE_OVER_SIZE,       ERROR_PARAM_INVALID,
        "Invalid parameter"},
    {ERR_ANS_INNER_PUSH_CHECK_EXTRAINFO_INVALID, ERR_ANS_PUSH_CHECK_EXTRAINFO_INVALID, ERROR_PARAM_INVALID,
        "Invalid parameter"},

    // ===== Notification management =====
    {ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS, ERR_ANS_NOTIFICATION_NOT_EXISTS, ERROR_NOTIFICATION_NOT_EXIST,
        "The notification does not exist"},
    {ERR_ANS_INNER_NOTIFICATION_IS_UNREMOVABLE, ERR_ANS_NOTIFICATION_IS_UNREMOVABLE, ERROR_NOTIFICATION_UNREMOVABLE,
        "Notification deletion disabled"},
    {ERR_ANS_INNER_OVER_MAX_ACTIVE_PERSECOND, ERR_ANS_OVER_MAX_ACTIVE_PERSECOND, ERROR_OVER_MAX_NUM_PER_SECOND,
        "The notification sending frequency reaches the upper limit"},
    {ERR_ANS_INNER_OVER_MAX_UPDATE_PERSECOND, ERR_ANS_OVER_MAX_UPDATE_PERSECOND, ERROR_OVER_MAX_NUM_PER_SECOND,
        "The notification sending frequency reaches the upper limit"},
    {ERR_ANS_INNER_DUPLICATE_MSG,          ERR_ANS_DUPLICATE_MSG,           ERROR_INTERNAL_ERROR,
        "Internal error. Possible cause: 1.IPC communication failed. 2.Memory operation error"},
    {ERR_ANS_INNER_EXPIRED_NOTIFICATION,   ERR_ANS_EXPIRED_NOTIFICATION,    ERROR_EXPIRED_NOTIFICATION,
        "The notification version for this update is too low"},
    {ERR_ANS_INNER_REPEAT_CREATE,          ERR_ANS_REPEAT_CREATE,           ERROR_REPEAT_SET,
        "Repeat create or end"},
    {ERR_ANS_INNER_END_NOTIFICATION,       ERR_ANS_END_NOTIFICATION,        ERROR_REPEAT_SET,
        "Repeat create or end"},
    {ERR_ANS_INNER_DIALOG_POP_SUCCEEDED,   ERR_ANS_DIALOG_POP_SUCCEEDED,    ERROR_INTERNAL_ERROR,
        "Internal error. Possible cause: 1.IPC communication failed. 2.Memory operation error"},

    // ===== Slot/channel =====
    {ERR_ANS_INNER_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED,
        ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED, ERROR_INTERNAL_ERROR,
        "Internal error. Database operation failed."},
    {ERR_ANS_INNER_PREFERENCES_NOTIFICATION_SLOT_NOT_EXIST,
        ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_NOT_EXIST, ERROR_INTERNAL_ERROR,
        "Internal error. Possible cause: 1.IPC communication failed. 2.Memory operation error"},
    {ERR_ANS_INNER_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST,
        ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST, ERROR_INTERNAL_ERROR,
        "Internal error. Possible cause: 1.IPC communication failed. 2.Memory operation error"},
    {ERR_ANS_INNER_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST,
        ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST, ERROR_INTERNAL_ERROR,
        "Internal error. Possible cause: 1.IPC communication failed. 2.Memory operation error"},
    {ERR_ANS_INNER_PREFERENCES_NOTIFICATION_SLOTGROUP_NOT_EXIST,
        ERR_ANS_PREFERENCES_NOTIFICATION_SLOTGROUP_NOT_EXIST, ERROR_INTERNAL_ERROR,
        "Internal error. Possible cause: 1.IPC communication failed. 2.Memory operation error"},
    {ERR_ANS_INNER_PREFERENCES_NOTIFICATION_SLOTGROUP_ID_INVALID,
        ERR_ANS_PREFERENCES_NOTIFICATION_SLOTGROUP_ID_INVALID, ERROR_INTERNAL_ERROR,
        "Internal error. Possible cause: 1.IPC communication failed. 2.Memory operation error"},
    {ERR_ANS_INNER_PREFERENCES_NOTIFICATION_SLOTGROUP_EXCEED_MAX_NUM,
        ERR_ANS_PREFERENCES_NOTIFICATION_SLOTGROUP_EXCEED_MAX_NUM, ERROR_INTERNAL_ERROR,
        "Internal error. Possible cause: 1.IPC communication failed. 2.Memory operation error"},
    {ERR_ANS_INNER_PREFERENCES_NOTIFICATION_READ_TEMPLATE_CONFIG_FAILED,
        ERR_ANS_PREFERENCES_NOTIFICATION_READ_TEMPLATE_CONFIG_FAILED, ERROR_READ_TEMPLATE_CONFIG_FAILED,
        "Failed to read the template configuration"},
    {ERR_ANS_INNER_PREFERENCES_NOTIFICATION_SLOT_ENABLED,
        ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_ENABLED, ERROR_SLOT_CLOSED,
        "Notification slot disabled"},

    // ===== Subscription =====
    {ERR_ANS_INNER_SUBSCRIBER_IS_DELETING,     ERR_ANS_SUBSCRIBER_IS_DELETING,     ERROR_INTERNAL_ERROR,
        "Internal error. Possible cause: 1.IPC communication failed. 2.Memory operation error"},
    {ERR_ANS_INNER_LOCAL_SUBSCRIBE_CHECK_FAILED, ERR_ANS_LOCAL_SUBSCRIBE_CHECK_FAILED, ERROR_NO_RIGHT,
        "No permission"},
    {ERR_ANS_INNER_GET_ACTIVE_USER_FAILED,     ERR_ANS_GET_ACTIVE_USER_FAILED,     ERROR_USER_NOT_EXIST,
        "The user does not exist"},
    {ERR_ANS_INNER_USER_NOT_EXIST,             ERR_ANS_USER_NOT_EXIST,              ERROR_USER_NOT_EXIST,
        "The user does not exist"},

    // ===== Distributed =====
    {ERR_ANS_INNER_DISTRIBUTED_OPERATION_FAILED, ERR_ANS_DISTRIBUTED_OPERATION_FAILED,
        ERROR_DISTRIBUTED_OPERATION_FAILED,
        "Distributed operation failed"},
    {ERR_ANS_INNER_DISTRIBUTED_GET_INFO_FAILED, ERR_ANS_DISTRIBUTED_GET_INFO_FAILED, ERROR_DISTRIBUTED_OPERATION_FAILED,
        "Distributed operation failed"},
    {ERR_ANS_INNER_OPERATION_TIMEOUT,           ERR_ANS_OPERATION_TIMEOUT, ERROR_DISTRIBUTED_OPERATION_TIMEOUT,
        "Distributed operation timeout"},

    // ===== Geofence =====
    {ERR_ANS_INNER_GEOFENCE_ENABLED,              ERR_ANS_GEOFENCE_ENABLED,              ERROR_GEOFENCE_ENABLED,
        "Geofencing disabled"},
    {ERR_ANS_INNER_GEOFENCE_EXCEEDED,             ERR_ANS_GEOFENCE_EXCEEDED,             ERROR_PARAM_INVALID,
        "Invalid parameter"},
    {ERR_ANS_INNER_GEOFENCING_OPERATION_TIMEOUT,  ERR_ANS_GEOFENCING_OPERATION_TIMEOUT,  ERROR_SERVICE_CONNECT_ERROR,
        "Failed to connect to the service"},
    {ERR_ANS_INNER_ERROR_LOCATION_CLOSED,         ERR_ANS_ERROR_LOCATION_CLOSED,         ERROR_LOCATION_CLOSED,
        "The location switch is off"},
    {ERR_ANS_INNER_AWARNESS_SUGGESTIONS_CLOSED, ERR_ANS_AWARNESS_SUGGESTIONS_CLOSED,
        ERROR_AWARNESS_SUGGESTIONS_CLOSED,
        "The \"Awareness & suggestions\" switch of the location-based service is off"},
    {ERR_ANS_INNER_CHECK_WEAK_NETWORK,            ERR_ANS_CHECK_WEAK_NETWORK,            ERROR_NETWORK_UNREACHABLE,
        "Network unreachable"},

    // ===== Push =====
    {ERR_ANS_INNER_PUSH_CHECK_FAILED,             ERR_ANS_PUSH_CHECK_FAILED,             ERROR_NO_RIGHT,
        "No permission"},
    {ERR_ANS_INNER_PUSH_CHECK_UNREGISTERED,       ERR_ANS_PUSH_CHECK_UNREGISTERED,       ERROR_NO_RIGHT,
        "No permission"},
    {ERR_ANS_INNER_PUSH_CHECK_NETWORK_UNREACHABLE, ERR_ANS_PUSH_CHECK_NETWORK_UNREACHABLE, ERROR_NETWORK_UNREACHABLE,
        "Network unreachable"},

    // ===== Dialog =====
    {ERR_ANS_INNER_DIALOG_IS_POPPING,             ERR_ANS_DIALOG_IS_POPPING,             ERROR_DIALOG_IS_POPPING,
        "Dialog is popping"},
    {ERR_ANS_INNER_SETTING_WINDOW_EXIST,          ERR_ANS_DIALOG_POP_SUCCEEDED,          ERROR_SETTING_WINDOW_EXIST,
        "The notification settings window is already displayed"},

    // ===== Encryption =====
    {ERR_ANS_INNER_ENCRYPT_FAIL,                  ERR_ANS_ENCRYPT_FAIL,                  ERROR_INTERNAL_ERROR,
        "Internal error. Possible cause: 1.IPC communication failed. 2.Memory operation error"},
    {ERR_ANS_INNER_DECRYPT_FAIL,                  ERR_ANS_DECRYPT_FAIL,                  ERROR_INTERNAL_ERROR,
        "Internal error. Possible cause: 1.IPC communication failed. 2.Memory operation error"},

    // ===== Agent/Extension =====
    {ERR_ANS_INNER_NO_AGENT_SETTING,              ERR_ANS_NO_AGENT_SETTING,              ERROR_NO_AGENT_SETTING,
        "There is no corresponding agent relationship configuration"},
    {ERR_ANS_INNER_NO_PROFILE_TEMPLATE,           ERR_ANS_NO_PROFILE_TEMPLATE,           ERROR_NO_PROFILE_TEMPLATE,
        "The do-not-disturb profile does not exist"},
    {ERR_ANS_INNER_REJECTED_WITH_DISABLE_NOTIFICATION,
        ERR_ANS_REJECTED_WITH_DISABLE_NOTIFICATION, ERROR_REJECTED_WITH_DISABLE_NOTIFICATION,
        "The application is not allowed to send notifications due to permission settings"},
    {ERR_ANS_INNER_NO_CUSTOM_RINGTONE_INFO,       ERR_ANS_NO_CUSTOM_RINGTONE_INFO,       ERROR_NO_CUSTOM_RINGTONE_INFO,
        "The specified bundle has no custom ringtone information"},
    {ERR_ANS_INNER_VOICE_SUMMARY_COUNT_EXCEEDED,  ERR_ANS_VOICE_SUMMARY_COUNT_EXCEEDED,  ERROR_INTERNAL_ERROR,
        "Internal error. Possible cause: 1.IPC communication failed. 2.Memory operation error"},
    {ERR_ANS_INNER_DEVICE_NOT_SUPPORT,            ERR_ANS_DEVICE_NOT_SUPPORT,            ERROR_SYSTEM_CAP_ERROR,
        "SystemCapability not found"},
    {ERR_ANS_INNER_NOT_IMPL_EXTENSIONABILITY, ERR_ANS_NOT_IMPL_EXTENSIONABILITY,
        ERROR_NOT_IMPL_EXTENSIONABILITY,
        "The application does not implement the NotificationSubscriberExtensionAbility"},
    {ERR_ANS_INNER_DLP_HAP,                       ERR_ANS_DLP_HAP,                       ERROR_INTERNAL_ERROR,
        "Internal error. Possible cause: 1.IPC communication failed. 2.Memory operation error"},
    {ERR_ANS_INNER_NOTIFICATION_SNOOZE_NOTALLOWED, ERR_ANS_NOTIFICATION_SNOOZE_NOTALLOWED, ERR_NOTIFICATION_NOT_SUPPORT,
        "This notification is not supported"},
    {ERR_ANS_INNER_CUSTOM_EXTENSION_EXISTS_CHECK_FAILED,
        ERR_ANS_CUSTOM_EXTENSION_EXISTS_CHECK_FAILED, ERROR_NO_RIGHT,
        "No permission"},
    {ERR_ANS_INNER_CUSTOM_EXTENSION_RIGHTS_CHECK_FAILED,
        ERR_ANS_CUSTOM_EXTENSION_RIGHTS_CHECK_FAILED, ERROR_NO_RIGHT,
        "No permission"},
};

// ===== Conversion functions (all use single-pass table lookup) =====

int32_t InnerErrorToExternal(int32_t innerErrCode)
{
    // Handle success case (both ERR_OK and ERR_ANS_INNER_OK)
    if (innerErrCode == ERR_OK || innerErrCode == ERR_ANS_INNER_OK) {
        return ERR_OK;
    }
    // Single pass: check both innerCode and nativeCode
    for (const auto &entry : SERVICE_ERROR_CONVERT_TABLE) {
        if (innerErrCode == entry.innerCode || innerErrCode == entry.nativeCode) {
            return entry.externalCode;
        }
    }
    ANS_LOGW("Unknown error code: %{public}d, passthrough", innerErrCode);
    return innerErrCode;
}

ErrCode InnerErrorToNative(int32_t innerErrCode)
{
    if (innerErrCode == ERR_ANS_INNER_OK || innerErrCode == ERR_OK) {
        return ERR_OK;
    }
    for (const auto &entry : SERVICE_ERROR_CONVERT_TABLE) {
        if (innerErrCode == entry.innerCode || innerErrCode == entry.nativeCode) {
            return entry.nativeCode;
        }
    }
    ANS_LOGW("Unknown service error code: %{public}d, fallback to ERR_ANS_TASK_ERR", innerErrCode);
    return ERR_ANS_TASK_ERR;
}

int32_t NativeErrorToExternal(int32_t nativeErrCode)
{
    return InnerErrorToExternal(nativeErrCode);
}

std::string GetExternalErrMessage(int32_t externalErrCode, std::string defaultMsg)
{
    for (const auto &entry : SERVICE_ERROR_CONVERT_TABLE) {
        if (externalErrCode == entry.externalCode) {
            return entry.message;
        }
    }
    ANS_LOGW("Unknown external error code: %{public}d, return default message", externalErrCode);
    return defaultMsg;
}

std::string GetInnerErrMessage(int32_t innerErrCode, std::string defaultMsg)
{
    for (const auto &entry : SERVICE_ERROR_CONVERT_TABLE) {
        if (entry.innerCode == innerErrCode || innerErrCode == entry.nativeCode) {
            return entry.message;
        }
    }
    ANS_LOGW("Unknown inner error code: %{public}d, return default message", innerErrCode);
    return defaultMsg;
}

}  // namespace Notification
}  // namespace OHOS
