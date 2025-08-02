/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "inner_errors.h"
#include "notification_manager_log.h"

namespace OHOS {
namespace CJSystemapi {
namespace Notification {
    int32_t ErrorToExternal(uint32_t errCode)
    {
    static std::vector<std::pair<uint32_t, int32_t>> errorsConvert = {
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
        {ERR_ANS_DISTRIBUTED_OPERATION_FAILED, ERROR_DISTRIBUTED_OPERATION_FAILED},
        {ERR_ANS_DISTRIBUTED_GET_INFO_FAILED, ERROR_DISTRIBUTED_OPERATION_FAILED},
        {ERR_ANS_PREFERENCES_NOTIFICATION_READ_TEMPLATE_CONFIG_FAILED, ERROR_READ_TEMPLATE_CONFIG_FAILED},
        {ERR_ANS_REPEAT_CREATE, ERROR_REPEAT_SET},
        {ERR_ANS_END_NOTIFICATION, ERROR_REPEAT_SET},
        {ERR_ANS_EXPIRED_NOTIFICATION, ERROR_EXPIRED_NOTIFICATION},
        {ERR_ANS_PUSH_CHECK_FAILED, ERROR_NO_RIGHT},
        {ERR_ANS_PUSH_CHECK_UNREGISTERED, ERROR_NO_RIGHT},
        {ERR_ANS_LOCAL_SUBSCRIBE_CHECK_FAILED, ERROR_NO_RIGHT},
        {ERR_ANS_PUSH_CHECK_NETWORK_UNREACHABLE, ERROR_NETWORK_UNREACHABLE}
    };

    int32_t externalCode = SUCCESS_CODE;
    for (const auto &errorConvert : errorsConvert) {
        if (errCode == errorConvert.first) {
            externalCode = errorConvert.second;
            break;
        }
    }

    LOGI("internal errorCode[%{public}u] to external errorCode[%{public}d]", errCode, externalCode);
    return externalCode;
}
    
} // namespace Notification
} // namespace CJSystemapi
} // namespace OHOS
