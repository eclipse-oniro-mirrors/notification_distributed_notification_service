/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_CONTENT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_CONTENT_H
#include "ani.h"
#include <string>
#include <vector>
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ets_error_utils.h"

namespace OHOS {
namespace NotificationSts {
using namespace OHOS::Notification;
static const std::unordered_map<int32_t, std::string> ERROR_CODE_TO_MESSAGE {
    {ERROR_PERMISSION_DENIED, "Permission denied"},
    {ERROR_NOT_SYSTEM_APP, "The application isn't system application"},
    {ERROR_PARAM_INVALID, "Invalid parameter"},
    {ERROR_SYSTEM_CAP_ERROR, "SystemCapability not found"},
    {ERROR_INTERNAL_ERROR, "Internal error"},
    {ERROR_IPC_ERROR, "Marshalling or unmarshalling error"},
    {ERROR_SERVICE_CONNECT_ERROR, "Failed to connect to the service"},
    {ERROR_NOTIFICATION_CLOSED, "Notification disabled"},
    {ERROR_SLOT_CLOSED, "Notification slot disabled"},
    {ERROR_NOTIFICATION_UNREMOVABLE, "Notification deletion disabled"},
    {ERROR_NOTIFICATION_NOT_EXIST, "The notification does not exist"},
    {ERROR_USER_NOT_EXIST, "The user does not exist"},
    {ERROR_OVER_MAX_NUM_PER_SECOND, "The notification sending frequency reaches the upper limit"},
    {ERROR_DISTRIBUTED_OPERATION_FAILED, "Distributed operation failed"},
    {ERROR_READ_TEMPLATE_CONFIG_FAILED, "Failed to read the template configuration"},
    {ERROR_NO_MEMORY, "No memory space"},
    {ERROR_BUNDLE_NOT_FOUND, "The specified bundle name was not found"},
    {ERROR_NO_AGENT_SETTING, "There is no corresponding agent relationship configuration"},
    {ERROR_DIALOG_IS_POPPING, "Dialog is popping"},
    {ERROR_SETTING_WINDOW_EXIST, "The notification settings window is already displayed"},
    {ERROR_NO_PROFILE_TEMPLATE, "The do-not-disturb profile does not exist"},
    {ERROR_REPEAT_SET, "Repeat create or end"},
    {ERROR_NO_RIGHT, "No permission"},
    {ERROR_EXPIRED_NOTIFICATION, "Low update version"},
    {ERROR_NETWORK_UNREACHABLE, "Network unreachable"},
    {ERROR_REJECTED_WITH_DISABLE_NOTIFICATION,
        "The application is not allowed to send notifications due to permission settings"},
    {ERROR_DISTRIBUTED_OPERATION_TIMEOUT, "Distributed operation timeout"},
};

static const std::vector<std::pair<uint32_t, int32_t>> ERRORS_CONVERT = {
    {ERR_ANS_PERMISSION_DENIED, ERROR_PERMISSION_DENIED},
    {ERR_ANS_NON_SYSTEM_APP, ERROR_NOT_SYSTEM_APP},
    {ERR_ANS_NOT_SYSTEM_SERVICE, ERROR_NOT_SYSTEM_APP},
    {ERR_ANS_INVALID_PARAM, ERROR_PARAM_INVALID},
    {ERR_ANS_INVALID_UID, ERROR_PARAM_INVALID},
    {ERR_ANS_ICON_OVER_SIZE, ERROR_PARAM_INVALID},
    {ERR_ANS_PICTURE_OVER_SIZE, ERROR_PARAM_INVALID},
    {ERR_ANS_PUSH_CHECK_EXTRAINFO_INVALID, ERROR_PARAM_INVALID},
    {ERR_ANS_NO_MEMORY, ERROR_NO_MEMORY},
    {ERR_ANS_TASK_ERR, ERROR_INTERNAL_ERROR},
    {ERR_ANS_PARCELABLE_FAILED, ERROR_IPC_ERROR},
    {ERR_ANS_TRANSACT_FAILED, ERROR_IPC_ERROR},
    {ERR_ANS_REMOTE_DEAD, ERROR_IPC_ERROR},
    {ERR_ANS_SERVICE_NOT_READY, ERROR_SERVICE_CONNECT_ERROR},
    {ERR_ANS_SERVICE_NOT_CONNECTED, ERROR_SERVICE_CONNECT_ERROR},
    {ERR_ANS_NOT_ALLOWED, ERROR_NOTIFICATION_CLOSED},
    {ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_ENABLED, ERROR_SLOT_CLOSED},
    {ERR_ANS_NOTIFICATION_IS_UNREMOVABLE, ERROR_NOTIFICATION_UNREMOVABLE},
    {ERR_ANS_NOTIFICATION_NOT_EXISTS, ERROR_NOTIFICATION_NOT_EXIST},
    {ERR_ANS_GET_ACTIVE_USER_FAILED, ERROR_USER_NOT_EXIST},
    {ERR_ANS_INVALID_PID, ERROR_BUNDLE_NOT_FOUND},
    {ERR_ANS_INVALID_BUNDLE, ERROR_BUNDLE_NOT_FOUND},
    {ERR_ANS_OVER_MAX_ACTIVE_PERSECOND, ERROR_OVER_MAX_NUM_PER_SECOND},
    {ERR_ANS_OVER_MAX_UPDATE_PERSECOND, ERROR_OVER_MAX_NUM_PER_SECOND},
    {ERR_ANS_DISTRIBUTED_OPERATION_FAILED, ERROR_DISTRIBUTED_OPERATION_FAILED},
    {ERR_ANS_DISTRIBUTED_GET_INFO_FAILED, ERROR_DISTRIBUTED_OPERATION_FAILED},
    {ERR_ANS_PREFERENCES_NOTIFICATION_READ_TEMPLATE_CONFIG_FAILED, ERROR_READ_TEMPLATE_CONFIG_FAILED},
    {ERR_ANS_REPEAT_CREATE, ERROR_REPEAT_SET},
    {ERR_ANS_END_NOTIFICATION, ERROR_REPEAT_SET},
    {ERR_ANS_EXPIRED_NOTIFICATION, ERROR_EXPIRED_NOTIFICATION},
    {ERR_ANS_PUSH_CHECK_FAILED, ERROR_NO_RIGHT},
    {ERR_ANS_PUSH_CHECK_UNREGISTERED, ERROR_NO_RIGHT},
    {ERR_ANS_LOCAL_SUBSCRIBE_CHECK_FAILED, ERROR_NO_RIGHT},
    {ERR_ANS_PUSH_CHECK_NETWORK_UNREACHABLE, ERROR_NETWORK_UNREACHABLE},
    {ERR_ANS_NO_AGENT_SETTING, ERROR_NO_AGENT_SETTING},
    {ERR_ANS_DIALOG_IS_POPPING, ERROR_DIALOG_IS_POPPING},
    {ERR_ANS_NO_PROFILE_TEMPLATE, ERROR_NO_PROFILE_TEMPLATE},
    {ERR_ANS_REJECTED_WITH_DISABLE_NOTIFICATION, ERROR_REJECTED_WITH_DISABLE_NOTIFICATION},
    {ERR_ANS_OPERATION_TIMEOUT, ERROR_DISTRIBUTED_OPERATION_TIMEOUT},
};


int32_t GetExternalCode(uint32_t errCode);

std::string FindAnsErrMsg(const int32_t errCode);

void ThrowError(ani_env *env, int32_t errCode, const std::string &errorMsg);

ani_object CreateError(ani_env *env, int32_t code, const std::string &msg);

inline void ThrowErrorWithMsg(ani_env *env, std::string logMsg)
{
    ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
        FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
}

inline void ThrowErrorWithCode(ani_env *env, const int32_t errCode, std::string msg = "")
{
    if (env == nullptr) return;
    ThrowError(env, errCode, msg.empty() ? FindAnsErrMsg(errCode) : msg);
}

inline void ThrowErrorWithInvalidParam(ani_env *env)
{
    ThrowErrorWithCode(env, ERROR_PARAM_INVALID);
}

} // namespace NotificationSts
} // OHOS
#endif

