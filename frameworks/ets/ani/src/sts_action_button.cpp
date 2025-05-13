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
#include "sts_action_button.h"

#include "sts_common.h"
#include "sts_convert_other.h"
#include "ani_common_want.h"
#include "sts_user_input.h"


namespace OHOS {
namespace NotificationSts {
ani_status UnwrapNotificationActionButton(ani_env *env, ani_object param,
    StsActionButton &actionButton)
{
    ani_status status = ANI_ERROR;
    ani_boolean isUndefind = ANI_TRUE;
    std::string title;
    if((status = GetPropertyString(env, param, "title", isUndefind, title)) != ANI_OK || isUndefind == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    ani_ref wantAgentRef;
    WantAgent* pWantAgent = nullptr;
    if(ANI_OK == GetPropertyRef(env, param, "wantAgent", isUndefind, wantAgentRef) && isUndefind == ANI_FALSE) {
        UnwrapWantAgent(env, static_cast<ani_object>(wantAgentRef), reinterpret_cast<void **>(&pWantAgent));
    } else {
        return ANI_INVALID_ARGS;
    }
    if (pWantAgent == nullptr) {
       return ANI_INVALID_ARGS;
    }
    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);

    isUndefind = ANI_TRUE;
    WantParams wantParams = {};
    ani_ref extrasRef;
    if(ANI_OK == GetPropertyRef(env, param, "extras", isUndefind, extrasRef) && isUndefind == ANI_FALSE) {
        UnwrapWantParams(env, extrasRef, wantParams);
    } else {
        return ANI_INVALID_ARGS;
    }
    std::shared_ptr<WantParams> extras = std::make_shared<WantParams>(wantParams);

    std::shared_ptr<Notification::NotificationUserInput> userInput = nullptr;
    ani_ref userInputRef;
    if(ANI_OK == GetPropertyRef(env, param, "userInput", isUndefind, userInputRef) && isUndefind == ANI_FALSE) {
        UnwrapNotificationUserInput(env, static_cast<ani_object>(userInputRef), userInput);
    }
    if (userInput == nullptr) {
        userInput = {};
    }
    actionButton.icon = nullptr;
    actionButton.title = title;
    actionButton.wantAgent = wantAgent;
    actionButton.extras = extras;
    actionButton.semanticActionButton = SemanticActionButton::NONE_ACTION_BUTTON;
    actionButton.autoCreatedReplies = true;
    actionButton.mimeTypeOnlyInputs = {};
    actionButton.userInput = userInput;
    actionButton.isContextual = false;
    return status;
}

ani_object WrapNotificationActionButton(ani_env* env,
    const std::shared_ptr<NotificationActionButton> &actionButton)
{
    if (actionButton == nullptr) {
        ANS_LOGE("actionButton is null");
        return nullptr;
    }
    ani_object iconButtonObject = nullptr;
    ani_class iconButtonCls = nullptr;
    RETURN_NULL_IF_FALSE(CreateClassObjByClassName(env,
        "Lnotification/notificationActionButton/NotificationActionButtonInner;", iconButtonCls, iconButtonObject));
    // title: string;
    ani_string stringValue = nullptr;
    RETURN_NULL_IF_FALSE(GetAniStringByString(env, actionButton->GetTitle(), stringValue));
    RETURN_NULL_IF_FALSE(CallSetterOptional(env, iconButtonCls, iconButtonObject, "title", stringValue));
    // wantAgent: WantAgent;
    //napi处理过程
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> agent = actionButton->GetWantAgent();
    if (agent == nullptr) {
        ANS_LOGI("agent is null");
        return nullptr;
    } else {
        ani_object wantAgent = AppExecFwk::WrapWantAgent(env, agent.get());
        RETURN_NULL_IF_FALSE(CallSetterOptional(env, iconButtonCls, iconButtonObject, "wantAgent", wantAgent));
    }

    // need to do
    // extras?: Record<string, Object>; napi中没有处理它的过程？
    //napi位置：notification_distributed_notification_service-OpenHarmony_feature_20250328\frameworks\js\napi\src\common_convert_request.cpp  419行
    // // icon?: image.PixelMap 未找到ETS属性

    // userInput?: NotificationUserInput -> inputKey: string;
    ani_object userInputObject = WarpUserInput(env, actionButton->GetUserInput());
    RETURN_NULL_IF_FALSE(CallSetter(env, iconButtonCls, iconButtonObject, "userInput", userInputObject));

    return iconButtonObject;
}

ani_status GetNotificationActionButtonArray(ani_env *env, ani_object param,
    const char *name, std::vector<std::shared_ptr<NotificationActionButton>> &res)
{
    ani_ref arrayObj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status;
    ani_double length;
    StsActionButton actionButton;

    if ((status = GetPropertyRef(env, param, name, isUndefined, arrayObj)) != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGI("status : %{public}d , %{public}s :  may be undefined", status, name);
        return ANI_INVALID_ARGS;
    }
    status = GetPropertyDouble(env, static_cast<ani_object>(arrayObj), "length", isUndefined, length);
    if (status != ANI_OK) {
        ANS_LOGI("status : %{public}d", status);
        return status;
    }

    for (int i = 0; i < static_cast<int>(length); i++) {
        ani_ref buttonRef;
        status = env->Object_CallMethodByName_Ref(static_cast<ani_object>(arrayObj),
            "$_get", "I:Lstd/core/Object;", &buttonRef, (ani_int)i);
        if (status != ANI_OK) {
            ANS_LOGI("status : %{public}d, index: %{public}d", status, i);
            return status;
        }
        status = UnwrapNotificationActionButton(env, static_cast<ani_object>(buttonRef), actionButton);
        if (status != ANI_OK) {
            ANS_LOGI("ActionButton failed, index: %{public}d", i);
            return status;
        }
        std::shared_ptr<NotificationActionButton> button
            = NotificationActionButton::Create(actionButton.icon,
            actionButton.title, actionButton.wantAgent, actionButton.extras, 
            actionButton.semanticActionButton, actionButton.autoCreatedReplies, actionButton.mimeTypeOnlyInputs,
            actionButton.userInput, actionButton.isContextual);
        res.push_back(button);
    }
    return status;
}

ani_object GetAniArrayNotificationActionButton(ani_env* env,
    const std::vector<std::shared_ptr<NotificationActionButton>> &actionButtons)
{
    if (actionButtons.empty()) {
        ANS_LOGE("actionButtons is empty");
        return nullptr;
    }
    ani_object arrayObj = newArrayClass(env, actionButtons.size());
    if (arrayObj == nullptr) {
        ANS_LOGE("arrayObj is empty");
        return nullptr;
    }
    ani_size index = 0;
    for (auto &button : actionButtons) {
        ani_object item = WrapNotificationActionButton(env, button);
        RETURN_NULL_IF_NULL(item);
        if(ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", index, item)){
            std::cerr << "Object_CallMethodByName_Void  $_set Faild " << std::endl;
            return nullptr;
        }   
        index ++;
    }
    return arrayObj;
}
}
}