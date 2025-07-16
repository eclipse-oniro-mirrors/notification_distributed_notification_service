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

#include "ani_remove_group.h"

#include "ans_log_wrapper.h"
#include "sts_error_utils.h"
#include "notification_helper.h"
#include "sts_common.h"
#include "sts_throw_erro.h"
#include "sts_bundle_option.h"
#include "notification_helper.h"

namespace OHOS {
namespace NotificationManagerSts {

void AniRemoveGroupByBundle(ani_env *env, ani_object bundleOption, ani_string groupName)
{
    ANS_LOGD("AniRemoveGroupByBundle call");
    OHOS::Notification::NotificationBundleOption option;
    if (!OHOS::NotificationSts::UnwrapBundleOption(env, bundleOption, option)) {
        NotificationSts::ThrowStsErroWithMsg(env, "sts AniRemoveGroupByBundle ERROR_INTERNAL_ERROR");
        return ;
    }
    std::string tempStr = "";
    ani_status status = NotificationSts::GetStringByAniString(env, groupName, tempStr);
    if (status !=  ANI_OK) {
        NotificationSts::ThrowStsErroWithMsg(env, "sts AniRemoveGroupByBundle ERROR_INTERNAL_ERROR");
        return ;
    }
    std::string groupNameStr = NotificationSts::GetResizeStr(tempStr, NotificationSts::STR_MAX_SIZE);
    int returncode = OHOS::Notification::NotificationHelper::RemoveGroupByBundle(option, groupNameStr);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniRemoveGroupByBundle -> error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniRemoveGroupByBundle end");
}
}
}