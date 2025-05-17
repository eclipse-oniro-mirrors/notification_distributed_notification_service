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
#include "sts_error_utils.h"

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
    {ERROR_NO_PROFILE_TEMPLATE, "Not exit noNotDisturb profile template"},
    {ERROR_REPEAT_SET, "Repeat create or end"},
    {ERROR_NO_RIGHT, "No permission"},
    {ERROR_EXPIRED_NOTIFICATION, "Low update version"},
    {ERROR_NETWORK_UNREACHABLE, "Network unreachable"},
    {ERROR_REJECTED_WITH_DISABLE_NOTIFICATION,
        "The application is not allowed to publish notifications due to permission control settings"},
    {ERROR_DISTRIBUTED_OPERATION_TIMEOUT, "Distributed operation timeout"},
};

inline std::string FindAnsErrMsg(const int32_t errCode)
{
    auto findMsg = ERROR_CODE_TO_MESSAGE.find(errCode);
    if (findMsg == ERROR_CODE_TO_MESSAGE.end()) {
        ANSR_LOGE("FindAnsErrMsg Inner error.");
        return "Inner error.";
    }
    return findMsg->second;
}

inline void ThrowStsErroWithLog(ani_env *env, std::string logMsg) {
    OHOS::AbilityRuntime::ThrowStsError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
        FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
}
} // namespace NotificationSts
} // OHOS
#endif

