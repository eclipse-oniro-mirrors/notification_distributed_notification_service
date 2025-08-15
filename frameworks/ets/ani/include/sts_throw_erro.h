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

int32_t GetExternalCode(const uint32_t errCode);

inline std::string FindAnsErrMsg(const int32_t errCode)
{
    return GetAnsErrMessage(errCode);
}

void ThrowError(ani_env *env, int32_t errCode, const std::string &errorMsg);

ani_object CreateError(ani_env *env, ani_int code, const std::string &msg);

inline void ThrowStsErroWithMsg(ani_env *env, std::string logMsg)
{
    ANS_LOGE("%{public}s", logMsg.c_str());
    ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
        FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
}

inline void ThrowStsErrorWithCode(ani_env *env, const int32_t errCode, std::string msg = "")
{
    if (env == nullptr) return;
    ThrowError(env, errCode, msg.empty() ? FindAnsErrMsg(errCode) : msg);
}

inline void ThrowStsErrorWithInvalidParam(ani_env *env)
{
    ThrowStsErrorWithCode(env, ERROR_PARAM_INVALID);
}

} // namespace NotificationSts
} // OHOS
#endif

