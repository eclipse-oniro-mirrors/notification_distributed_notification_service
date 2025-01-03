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

#include "disturb_manager.h"
#include <functional>
#include <iomanip>
#include <sstream>

#include "access_token_helper.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_permission_def.h"
#include "errors.h"
#include "os_account_manager_helper.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace Notification {
int32_t DisturbManager::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    ErrCode result = CheckInterfacePermission(code);
    if (result != ERR_OK) {
        if (!reply.WriteInt32(result)) {
            return ERR_ANS_PARCELABLE_FAILED;
        }
        return ERR_OK;
    }
    switch (code) {
        case static_cast<uint32_t>(NotificationInterfaceCode::REMOVE_DO_NOT_DISTURB_PROFILES): {
            result = RemoveDoNotDisturbProfiles(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_DO_NOT_DISTURB_DATE): {
            result = SetDoNotDisturbDate(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_DO_NOT_DISTURB_DATE): {
            result = GetDoNotDisturbDate(data, reply);
            break;
        }
        default: {
            ANS_LOGE("[OnRemoteRequest] fail: unknown code!");
            return ERR_ANS_INVALID_PARAM;
        }
    }
    if (SUCCEEDED(result)) {
        return NO_ERROR;
    }

    return result;
}

int32_t DisturbManager::CheckInterfacePermission(uint32_t code)
{
    switch (code) {
        case static_cast<uint32_t>(NotificationInterfaceCode::REMOVE_DO_NOT_DISTURB_PROFILES):
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_DO_NOT_DISTURB_DATE):
        case static_cast<uint32_t>(NotificationInterfaceCode::GET_DO_NOT_DISTURB_DATE): {
            bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
            if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
                return ERR_ANS_NON_SYSTEM_APP;
            }

            if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
                return ERR_ANS_PERMISSION_DENIED;
            }
            return ERR_OK;
        }
        default: {
            ANS_LOGE("[OnRemoteRequest] fail: unknown code!");
            return ERR_ANS_INVALID_PARAM;
        }
    }
}
}  // namespace Notification
}  // namespace OHOS
