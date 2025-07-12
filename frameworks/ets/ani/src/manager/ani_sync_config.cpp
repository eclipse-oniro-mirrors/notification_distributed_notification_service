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
#include "ani_sync_config.h"

#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "sts_bundle_option.h"
#include "sts_notification_manager.h"

namespace OHOS {
namespace NotificationManagerSts {
const double RESULT_OK = 0.0;
const double RESULT_FAILED = 1.0;

ani_double AniSetAdditionalConfig(ani_env *env, ani_string key, ani_string value)
{
    ANS_LOGD("sts setAdditionalConfig call");
    if (env == nullptr || key == nullptr) {
        ANS_LOGE("Invalid env or key is null");
        return RESULT_FAILED;
    }
    std::string keyStr;
    if (NotificationSts::GetStringByAniString(env, key, keyStr) != ANI_OK) {
        std::string msg = "Parameter verification failed";
        ANS_LOGE("GetStringByAniString failed. msg: %{public}s", msg.c_str());
        OHOS::NotificationSts::ThrowError(env, Notification::ERROR_PARAM_INVALID, msg);
        return RESULT_FAILED;
    }
    std::string valueStr;
    if (NotificationSts::GetStringByAniString(env, value, valueStr) != ANI_OK) {
        std::string msg = "Parameter verification failed";
        ANS_LOGE("GetStringByAniString failed. msg: %{public}s", msg.c_str());
        OHOS::NotificationSts::ThrowError(env, Notification::ERROR_PARAM_INVALID, msg);
        return RESULT_FAILED;
    }
    int returncode = Notification::NotificationHelper::SetAdditionConfig(keyStr, valueStr);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("setAdditionalConfig -> error, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return RESULT_FAILED;
    }
    return RESULT_OK;
}
} // namespace NotificationManagerSts
} // namespace OHOS