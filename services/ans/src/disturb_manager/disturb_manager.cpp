/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include <type_traits>

#include "access_token_helper.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_permission_def.h"
#include "errors.h"
#include "os_account_manager_helper.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace Notification {
DisturbManager::DisturbManager()
{
    codeAndExecuteFuncMap_ = {
        {static_cast<uint32_t>(NotificationInterfaceCode::REMOVE_DO_NOT_DISTURB_PROFILES),
            std::bind(&DisturbManager::HandleRemoveDoNotDisturbProfiles, this, std::placeholders::_1,
                std::placeholders::_2)},
        {static_cast<uint32_t>(NotificationInterfaceCode::SET_DO_NOT_DISTURB_DATE),
            std::bind(&DisturbManager::HandleSetDoNotDisturbDate, this, std::placeholders::_1,
                std::placeholders::_2)},
        {static_cast<uint32_t>(NotificationInterfaceCode::GET_DO_NOT_DISTURB_DATE),
            std::bind(&DisturbManager::HandleGetDoNotDisturbDate, this, std::placeholders::_1,
                std::placeholders::_2)},
        {static_cast<uint32_t>(NotificationInterfaceCode::SET_DO_NOT_DISTURB_DATE_BY_USER),
            std::bind(&DisturbManager::HandleSetDoNotDisturbDateByUser, this, std::placeholders::_1,
                std::placeholders::_2)},
        {static_cast<uint32_t>(NotificationInterfaceCode::GET_DO_NOT_DISTURB_DATE_BY_USER),
            std::bind(&DisturbManager::HandleGetDoNotDisturbDateByUser, this, std::placeholders::_1,
                std::placeholders::_2)},
        {static_cast<uint32_t>(NotificationInterfaceCode::ADD_DO_NOTDISTURB_PROFILES),
            std::bind(&DisturbManager::HandleAddDoNotDisturbProfiles, this, std::placeholders::_1,
                std::placeholders::_2)},
        {static_cast<uint32_t>(NotificationInterfaceCode::GET_DONOTDISTURB_PROFILE),
            std::bind(&DisturbManager::HandleGetDoNotDisturbProfile, this, std::placeholders::_1,
                std::placeholders::_2)},
        {static_cast<uint32_t>(NotificationInterfaceCode::DOES_SUPPORT_DO_NOT_DISTURB_MODE),
            std::bind(&DisturbManager::HandleDoesSupportDoNotDisturbMode, this, std::placeholders::_1,
                std::placeholders::_2)},
    };
    codeAndPermissionFuncMap_ = {
        {static_cast<uint32_t>(NotificationInterfaceCode::REMOVE_DO_NOT_DISTURB_PROFILES),
            std::bind(&DisturbManager::CheckSystemAndControllerPermission, this)},
        {static_cast<uint32_t>(NotificationInterfaceCode::SET_DO_NOT_DISTURB_DATE),
            std::bind(&DisturbManager::CheckSystemAndControllerPermission, this)},
        {static_cast<uint32_t>(NotificationInterfaceCode::GET_DO_NOT_DISTURB_DATE),
            std::bind(&DisturbManager::CheckSystemAndControllerPermission, this)},
        {static_cast<uint32_t>(NotificationInterfaceCode::SET_DO_NOT_DISTURB_DATE_BY_USER),
            std::bind(&DisturbManager::CheckSystemAndControllerPermission, this)},
        {static_cast<uint32_t>(NotificationInterfaceCode::GET_DO_NOT_DISTURB_DATE_BY_USER),
            std::bind(&DisturbManager::CheckSystemAndControllerPermission, this)},
        {static_cast<uint32_t>(NotificationInterfaceCode::ADD_DO_NOTDISTURB_PROFILES),
            std::bind(&DisturbManager::CheckSystemAndControllerPermission, this)},
        {static_cast<uint32_t>(NotificationInterfaceCode::GET_DONOTDISTURB_PROFILE),
            std::bind(&DisturbManager::CheckSystemAndControllerPermission, this)},
    };
}

int32_t DisturbManager::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    ANS_LOGD("[DisturbManager] called.");
    auto permissionChecker = codeAndPermissionFuncMap_.find(code);
    if (permissionChecker != codeAndPermissionFuncMap_.end()) {
        ErrCode result = permissionChecker->second();
        if (result != ERR_OK) {
            if (!reply.WriteInt32(result)) {
                return ERR_ANS_PARCELABLE_FAILED;
            }
            return ERR_OK;
        }
    }
    auto execution = codeAndExecuteFuncMap_.find(code);
    if (execution == codeAndExecuteFuncMap_.end()) {
        ANS_LOGE("[OnRemoteRequest] fail: unknown code!");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = execution->second(data, reply);
    if (SUCCEEDED(result)) {
        return NO_ERROR;
    }
    return result;
}

int32_t DisturbManager::CheckSystemAndControllerPermission()
{
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }
    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS
