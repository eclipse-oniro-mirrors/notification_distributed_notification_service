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
void GetStsActionButtonByOther(StsActionButton &actionButton)
{
    actionButton.icon = nullptr;
    actionButton.semanticActionButton = SemanticActionButton::NONE_ACTION_BUTTON;
    actionButton.autoCreatedReplies = true;
    actionButton.mimeTypeOnlyInputs = {};
    actionButton.isContextual = false;
}
ani_status GetStsActionButtonByWantAgent(ani_env *env, ani_object param,
    StsActionButton &actionButton)
{
    ani_boolean isUndefind = ANI_TRUE;
    ani_ref wantAgentRef;
    if (ANI_OK != GetPropertyRef(env, param, "wantAgent", isUndefind, wantAgentRef) || isUndefind == ANI_TRUE) {
        deletePoint(wantAgentRef);
        return ANI_INVALID_ARGS;
    }
    std::shared_ptr<WantAgent> wantAgent = UnwrapWantAgent(env, static_cast<ani_object>(wantAgentRef));
    deletePoint(wantAgentRef);
    if (wantAgent == nullptr) {
        return ANI_INVALID_ARGS;
    }
    actionButton.wantAgent = wantAgent;
    return ANI_OK;
}

ani_status GetStsActionButtonByWantParams(ani_env *env, ani_object param,
    StsActionButton &actionButton)
{
    ani_boolean isUndefind = ANI_TRUE;
    WantParams wantParams = {};
    ani_ref extrasRef;
    if (ANI_OK == GetPropertyRef(env, param, "extras", isUndefind, extrasRef) && isUndefind == ANI_FALSE) {
        UnwrapWantParams(env, extrasRef, wantParams);
    } else {
        deletePoint(extrasRef);
        return ANI_INVALID_ARGS;
    }
    std::shared_ptr<WantParams> extras = std::make_shared<WantParams>(wantParams);
    actionButton.extras = extras;
    return ANI_OK;
}
ani_status GetStsActionButtonByUserInput(ani_env *env, ani_object param,
    StsActionButton &actionButton)
{
    ani_boolean isUndefind = ANI_TRUE;
    std::shared_ptr<Notification::NotificationUserInput> userInput = nullptr;
    ani_ref userInputRef;
    if(ANI_OK == GetPropertyRef(env, param, "userInput", isUndefind, userInputRef) && isUndefind == ANI_FALSE) {
        UnwrapNotificationUserInput(env, static_cast<ani_object>(userInputRef), userInput);
    }
    if (userInput == nullptr) {
        userInput = {};
    }
    actionButton.userInput = userInput;
    return ANI_OK;
}

ani_status UnwrapNotificationActionButton(ani_env *env, ani_object param,
    StsActionButton &actionButton)
{
    ani_status status = ANI_ERROR;
    ani_boolean isUndefind = ANI_TRUE;
    std::string title;
    if ((status = GetPropertyString(env, param, "title", isUndefind, title)) != ANI_OK || isUndefind == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    actionButton.title = title;
    if (ANI_OK != GetStsActionButtonByWantAgent(env, param, actionButton)) {
        return ANI_INVALID_ARGS;
    }
    if (ANI_OK != GetStsActionButtonByWantParams(env, param, actionButton)) {
        return ANI_INVALID_ARGS;
    }
    GetStsActionButtonByOther(actionButton);
    return status;
}

bool SetNotificationActionButtonByRequiredParameter(
    ani_env *env,
    ani_class iconButtonCls,
    ani_object &iconButtonObject,
    const std::shared_ptr<NotificationActionButton> &actionButton)
{
    ani_string stringValue;
    // title: string;
    if (!GetAniStringByString(env, actionButton->GetTitle(), stringValue)) {
        deletePoint(stringValue);
        return false;
    }
    if (!CallSetter(env, iconButtonCls, iconButtonObject, "title", stringValue)) {
        deletePoint(stringValue);
        return false;
    }
    // wantAgent: WantAgent;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> agent = actionButton->GetWantAgent();
    if (agent == nullptr) {
        ANS_LOGI("agent is null");
        deletePoint(stringValue);
        return false;
    } else {
        ani_object wantAgent = AppExecFwk::WrapWantAgent(env, agent.get());
        if (!CallSetter(env, iconButtonCls, iconButtonObject, "wantAgent", wantAgent)) {
            deletePoint(stringValue);
            return false;
        }
    }
    return true;
}

void SetNotificationActionButtonByOptionalParameter(
    ani_env *env,
    ani_class iconButtonCls,
    ani_object &iconButtonObject,
    const std::shared_ptr<NotificationActionButton> &actionButton)
{
    // extras?: Record<string, Object>
    ani_ref extras = WrapWantParams(env, *(actionButton->GetAdditionalData().get()));
    if (!CallSetter(env, iconButtonCls, iconButtonObject, "extras", extras)) {
        deletePoint(extras);
    }
    // userInput?: NotificationUserInput
    ani_object userInputObject = WarpUserInput(env, actionButton->GetUserInput());
    if (!CallSetter(env, iconButtonCls, iconButtonObject, "userInput", userInputObject)) {
        deletePoint(userInputObject);
    }
}

void deletePointOfWrapNotificationActionButton(
    ani_object iconButtonObject, ani_class iconButtonCls, ani_string stringValue) {
    deletePoint(iconButtonObject);
    deletePoint(iconButtonCls);
    deletePoint(stringValue);
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
    ani_string stringValue = nullptr;
    if (!CreateClassObjByClassName(env,
        "Lnotification/notificationActionButton/NotificationActionButtonInner;", iconButtonCls, iconButtonObject)) {
        deletePointOfWrapNotificationActionButton(iconButtonObject, iconButtonCls, stringValue);
        return nullptr;
    }
    if (!SetNotificationActionButtonByRequiredParameter(env, iconButtonCls, iconButtonObject, actionButton)) {
        deletePointOfWrapNotificationActionButton(iconButtonObject, iconButtonCls, stringValue);
        return nullptr;
    }
    SetNotificationActionButtonByOptionalParameter(env, iconButtonCls, iconButtonObject, actionButton);
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
        deletePoint(arrayObj);
        return ANI_INVALID_ARGS;
    }
    status = GetPropertyDouble(env, static_cast<ani_object>(arrayObj), "length", isUndefined, length);
    if (status != ANI_OK) {
        ANS_LOGI("status : %{public}d", status);
        deletePoint(arrayObj);
        return status;
    }

    for (int i = 0; i < static_cast<int>(length); i++) {
        ani_ref buttonRef;
        status = env->Object_CallMethodByName_Ref(static_cast<ani_object>(arrayObj),
            "$_get", "I:Lstd/core/Object;", &buttonRef, (ani_int)i);
        if (status != ANI_OK) {
            deletePoint(arrayObj);
            deletePoint(buttonRef);
            ANS_LOGI("status : %{public}d, index: %{public}d", status, i);
            return status;
        }
        status = UnwrapNotificationActionButton(env, static_cast<ani_object>(buttonRef), actionButton);
        if (status != ANI_OK) {
            ANS_LOGI("ActionButton failed, index: %{public}d", i);
            deletePoint(arrayObj);
            deletePoint(buttonRef);
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
        deletePoint(arrayObj);
        return nullptr;
    }
    ani_size index = 0;
    for (auto &button : actionButtons) {
        ani_object item = WrapNotificationActionButton(env, button);
        if (item == nullptr) {
            deletePoint(arrayObj);
            deletePoint(item);
            return nullptr;
        }
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", index, item)) {
            deletePoint(arrayObj);
            deletePoint(item);
            return nullptr;
        }   
        index ++;
    }
    return arrayObj;
}
}
}