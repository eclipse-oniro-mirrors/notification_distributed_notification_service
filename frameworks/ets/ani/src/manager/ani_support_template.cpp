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
#include "ani_support_template.h"

#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "sts_bundle_option.h"
#include "sts_notification_manager.h"

namespace OHOS {
namespace NotificationManagerSts {
ani_boolean AniIsSupportTemplate(ani_env* env, ani_string templateName)
{
    ANS_LOGD("AniIsSupportTemplate call");
    std::string tempStr;
    if (NotificationSts::GetStringByAniString(env, templateName, tempStr) != ANI_OK) {
        NotificationSts::ThrowStsErroWithMsg(env, "templateName parse failed!");
        return NotificationSts::BoolToAniBoolean(false);
    }
    std::string templateNameStr = NotificationSts::GetResizeStr(tempStr, NotificationSts::STR_MAX_SIZE);
    ANS_LOGD("AniIsSupportTemplate by templateName:%{public}s", templateNameStr.c_str());
    bool support = false;
    int returncode = Notification::NotificationHelper::IsSupportTemplate(templateNameStr, support);
    int externalCode = NotificationSts::GetExternalCode(returncode);
    if (externalCode != ERR_OK) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniIsSupportTemplate -> error, errorCode: %{public}d", externalCode);
        return NotificationSts::BoolToAniBoolean(false);
    }
    ANS_LOGD("AniIsSupportTemplate end, support: %{public}d, returncode: %{public}d", support, externalCode);
    return NotificationSts::BoolToAniBoolean(support);
}

ani_object AniGetDeviceRemindType(ani_env *env)
{
    ANS_LOGD("AniGetDeviceRemindType enter");

    Notification::NotificationConstant::RemindType remindType =
        Notification::NotificationConstant::RemindType::DEVICE_IDLE_REMIND;
    int returncode = Notification::NotificationHelper::GetDeviceRemindType(remindType);

    int externalCode = NotificationSts::GetExternalCode(returncode);
    if (externalCode != ERR_OK) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniGetDeviceRemindType error, errorCode: %{public}d", externalCode);
        return nullptr;
    }
    ani_enum_item remindTypeItem {};
    if (!NotificationSts::DeviceRemindTypeCToEts(env, remindType, remindTypeItem)) {
        NotificationSts::ThrowStsErroWithMsg(env, "AniGetDeviceRemindType:failed to WrapNotificationSlotArray");
        return nullptr;
    }
    ANS_LOGD("AniGetDeviceRemindType end, ret: %{public}d", externalCode);
    return remindTypeItem;
}
}
}