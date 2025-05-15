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
#include "sts_user_input.h"

#include "sts_common.h"

namespace OHOS {
namespace NotificationSts {
ani_status UnwrapNotificationUserInput(ani_env *env, ani_object param,
    std::shared_ptr<Notification::NotificationUserInput> &userInput)
{
    ani_status status = ANI_ERROR;
    std::string inputKey;
    ani_boolean isUndefined = ANI_TRUE;
    if((status = GetPropertyString(env, param, "inputKey", isUndefined, inputKey)) != ANI_OK
        || isUndefined == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    userInput = Notification::NotificationUserInput::Create(inputKey);
    return status;
}

ani_object WarpUserInput(ani_env *env, std::shared_ptr<Notification::NotificationUserInput> userInput)
{
    ani_class userInputCls = nullptr;
    ani_object userInputObject = nullptr;
    RETURN_NULL_IF_FALSE(CreateClassObjByClassName(env,
        "Lnotification/notificationUserInput/NotificationUserInputInner;", userInputCls, userInputObject));
    ani_string stringValue;
    RETURN_NULL_IF_FALSE(GetAniStringByString(env, userInput->GetInputKey(), stringValue));
    RETURN_NULL_IF_FALSE(CallSetter(env, userInputCls, userInputObject, "inputKey", stringValue));
    return userInputObject;
}
}
}
