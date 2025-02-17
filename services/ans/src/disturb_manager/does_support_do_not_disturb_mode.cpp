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

#include "access_token_helper.h"
#include "ans_inner_errors.h"
#include "ans_permission_def.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace Notification {
ErrCode DisturbManager::HandleDoesSupportDoNotDisturbMode(MessageParcel &data, MessageParcel &reply)
{
    bool support = false;

    ErrCode result = DoesSupportDoNotDisturbModeInner(support);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleDoesSupportDoNotDisturbMode] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.WriteBool(support)) {
        ANS_LOGE("[HandleDoesSupportDoNotDisturbMode] fail: write doesSupport failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode DisturbManager::DoesSupportDoNotDisturbModeInner(bool &doesSupport)
{
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }
    doesSupport = SUPPORT_DO_NOT_DISTRUB;
    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS
