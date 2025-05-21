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
#include "ans_log_wrapper.h"
#include "sts_user_input.h"


namespace OHOS {
namespace NotificationSts {
void GetStsActionButtonByOther(StsActionButton &actionButton)
{
    ANS_LOGD("GetStsActionButtonByOther call");
    actionButton.icon = nullptr;
    actionButton.semanticActionButton = SemanticActionButton::NONE_ACTION_BUTTON;
    actionButton.autoCreatedReplies = true;
    actionButton.mimeTypeOnlyInputs = {};
    actionButton.isContextual = false;
    ANS_LOGD("GetStsActionButtonByOther end");
}
ani_status GetStsActionButtonByWantAgent(ani_env *env, ani_object param,
    StsActionButton &actionButton)
{
    ANS_LOGD("GetStsActionButtonByWantAgent call");
    if (env == nullptr || param == nullptr) {
        ANS_LOGE("GetStsActionButtonByWantAgent fail, has nullptr");
        return ANI_ERROR;
    }
    ani_boolean isUndefind = ANI_TRUE;
    ani_ref wantAgentRef;
    if (ANI_OK != GetPropertyRef(env, param, "wantAgent", isUndefind, wantAgentRef) || isUndefind == ANI_TRUE) {
        ANS_LOGE("GetStsActionButtonByWantAgent: GetPropertyRef wantAgent failed");
        return ANI_INVALID_ARGS;
    }
    std::shared_ptr<WantAgent> wantAgent = UnwrapWantAgent(env, static_cast<ani_object>(wantAgentRef));
    if (wantAgent == nullptr) {
        ANS_LOGE("GetStsActionButtonByWantAgent: wantAgent is nullptr");
        return ANI_INVALID_ARGS;
    }
    actionButton.wantAgent = wantAgent;
    ANS_LOGD("GetStsActionButtonByWantAgent end");
    return ANI_OK;
}

ani_status GetStsActionButtonByWantParams(ani_env *env, ani_object param,
    StsActionButton &actionButton)
{
    ANS_LOGD("GetStsActionButtonByWantParams call");
    if (env == nullptr || param == nullptr) {
        ANS_LOGE("GetStsActionButtonByWantParams fail, has nullptr");
        return ANI_ERROR;
    }
    ani_boolean isUndefind = ANI_TRUE;
    WantParams wantParams = {};
    ani_ref extrasRef;
    if (ANI_OK == GetPropertyRef(env, param, "extras", isUndefind, extrasRef) && isUndefind == ANI_FALSE) {
        UnwrapWantParams(env, extrasRef, wantParams);
    } else {
        ANS_LOGE("GetStsActionButtonByWantParams: GetPropertyRef extras failed");
        return ANI_INVALID_ARGS;
    }
    std::shared_ptr<WantParams> extras = std::make_shared<WantParams>(wantParams);
    actionButton.extras = extras;
    ANS_LOGD("GetStsActionButtonByWantParams end");
    return ANI_OK;
}
ani_status GetStsActionButtonByUserInput(ani_env *env, ani_object param,
    StsActionButton &actionButton)
{
    ANS_LOGD("GetStsActionButtonByUserInput call");
    if (env == nullptr || param == nullptr) {
        ANS_LOGE("GetStsActionButtonByUserInput fail, has nullptr");
        return ANI_ERROR;
    }
    ani_boolean isUndefind = ANI_TRUE;
    std::shared_ptr<Notification::NotificationUserInput> userInput = nullptr;
    ani_ref userInputRef;
    if(ANI_OK == GetPropertyRef(env, param, "userInput", isUndefind, userInputRef) && isUndefind == ANI_FALSE) {
        UnwrapNotificationUserInput(env, static_cast<ani_object>(userInputRef), userInput);
    } else {
        ANS_LOGD("GetStsActionButtonByUserInput : GetPropertyRef userInput failed");
    }
    if (userInput == nullptr) {
        ANS_LOGD("GetStsActionButtonByUserInput : userInput is nullptr");
        userInput = {};
    }
    actionButton.userInput = userInput;
    ANS_LOGD("GetStsActionButtonByUserInput end");
    return ANI_OK;
}

ani_status UnwrapNotificationActionButton(ani_env *env, ani_object param,
    StsActionButton &actionButton)
{
    ANS_LOGD("UnwrapNotificationActionButton call");
    if (env == nullptr || param == nullptr) {
        ANS_LOGE("UnwrapNotificationActionButton fail, has nullptr");
        return ANI_ERROR;
    }
    ani_status status = ANI_ERROR;
    ani_boolean isUndefind = ANI_TRUE;
    std::string title;
    if ((status = GetPropertyString(env, param, "title", isUndefind, title)) != ANI_OK || isUndefind == ANI_TRUE) {
        ANS_LOGE("UnwrapNotificationActionButton : Get title failed");
        return ANI_INVALID_ARGS;
    }
    actionButton.title = title;
    if (ANI_OK != GetStsActionButtonByWantAgent(env, param, actionButton)) {
        ANS_LOGE("UnwrapNotificationActionButton : GetStsActionButtonByWantAgent failed");
        return ANI_INVALID_ARGS;
    }
    if (ANI_OK != GetStsActionButtonByWantParams(env, param, actionButton)) {
        ANS_LOGE("UnwrapNotificationActionButton : GetStsActionButtonByWantParams failed");
        return ANI_INVALID_ARGS;
    }
    GetStsActionButtonByOther(actionButton);
    ANS_LOGD("UnwrapNotificationActionButton end");
    return status;
}

bool SetNotificationActionButtonByRequiredParameter(
    ani_env *env,
    ani_class iconButtonCls,
    ani_object &iconButtonObject,
    const std::shared_ptr<NotificationActionButton> &actionButton)
{
    ANS_LOGD("SetActionButtonByRequiredParameter call");
    if (env == nullptr || iconButtonCls == nullptr || iconButtonObject == nullptr || actionButton == nullptr) {
        ANS_LOGE("SetActionButtonByRequiredParameter fail, has nullptr");
        return ANI_ERROR;
    }
    ani_string stringValue;
    // title: string;
    if (!GetAniStringByString(env, actionButton->GetTitle(), stringValue)) {
        ANS_LOGE("SetActionButtonByRequiredParameter: Get title failed");
        return false;
    }
    if (!CallSetter(env, iconButtonCls, iconButtonObject, "title", stringValue)) {
        ANS_LOGE("SetActionButtonByRequiredParameter: Set title failed");
        return false;
    }
    // wantAgent: WantAgent;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> agent = actionButton->GetWantAgent();
    if (agent == nullptr) {
        ANS_LOGE("SetActionButtonByRequiredParameter:agent is null");
        return false;
    } else {
        ani_object wantAgent = AppExecFwk::WrapWantAgent(env, agent.get());
        if (wantAgent == nullptr) {
            ANS_LOGE("SetActionButtonByRequiredParameter: wantAgent is nullptr");
            return false;
        }
        if (!CallSetter(env, iconButtonCls, iconButtonObject, "wantAgent", wantAgent)) {
            ANS_LOGE("SetActionButtonByRequiredParameter: Set wantAgent failed");
            return false;
        }
    }
    ANS_LOGD("SetActionButtonByRequiredParameter end");
    return true;
}

void SetNotificationActionButtonByOptionalParameter(
    ani_env *env,
    ani_class iconButtonCls,
    ani_object &iconButtonObject,
    const std::shared_ptr<NotificationActionButton> &actionButton)
{
    ANS_LOGD("SetActionButtonByOptionalParameter call");
    if (env == nullptr || iconButtonCls == nullptr || iconButtonObject == nullptr || actionButton == nullptr) {
        ANS_LOGE("SetActionButtonByOptionalParameter fail, has nullptr");
        return;
    }
    // extras?: Record<string, Object>
    ani_ref extras = WrapWantParams(env, *(actionButton->GetAdditionalData().get()));
    if (!CallSetter(env, iconButtonCls, iconButtonObject, "extras", extras)) {
        ANS_LOGD("SetActionButtonByOptionalParameter : Set extras failed");
    }
    // userInput?: NotificationUserInput
    ani_object userInputObject = WarpUserInput(env, actionButton->GetUserInput());
    if (!CallSetter(env, iconButtonCls, iconButtonObject, "userInput", userInputObject)) {
        ANS_LOGD("SetActionButtonByOptionalParameter : Set userInput failed");
    }
    ANS_LOGD("SetActionButtonByOptionalParameter end");
}

ani_object WrapNotificationActionButton(ani_env* env,
    const std::shared_ptr<NotificationActionButton> &actionButton)
{
    ANS_LOGD("WrapNotificationActionButton call");
    if (env == nullptr || actionButton == nullptr) {
        ANS_LOGE("WrapNotificationActionButton failed, has nullptr");
        return nullptr;
    }
    ani_object iconButtonObject = nullptr;
    ani_class iconButtonCls = nullptr;
    if (!CreateClassObjByClassName(env,
        "Lnotification/notificationActionButton/NotificationActionButtonInner;", iconButtonCls, iconButtonObject)) {
        ANS_LOGE("WrapNotificationActionButton : CreateClassObjByClassName failed");
        return nullptr;
    }
    if (!SetNotificationActionButtonByRequiredParameter(env, iconButtonCls, iconButtonObject, actionButton)) {
        ANS_LOGE("WrapNotificationActionButton : SetRequiredParameter failed");
        return nullptr;
    }
    SetNotificationActionButtonByOptionalParameter(env, iconButtonCls, iconButtonObject, actionButton);
    ANS_LOGE("WrapNotificationActionButton end");
    return iconButtonObject;
}

ani_status GetNotificationActionButtonArray(ani_env *env, ani_object param,
    const char *name, std::vector<std::shared_ptr<NotificationActionButton>> &res)
{
    ANS_LOGD("GetActionButtonArray call");
    if (env == nullptr || param == nullptr || name == nullptr) {
        ANS_LOGE("GetActionButtonArray failed, has nullptr");
        return ANI_ERROR;
    }
    ani_ref arrayObj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status;
    ani_double length;
    StsActionButton actionButton;
    if ((status = GetPropertyRef(env, param, name, isUndefined, arrayObj)) != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGE("GetActionButtonArray: GetPropertyRef name = %{public}s, status = %{public}d", name, status);
        return ANI_INVALID_ARGS;
    }
    if (ANI_OK!= (status = GetPropertyDouble(env, static_cast<ani_object>(arrayObj), "length", isUndefined, length))) {
        ANS_LOGE("GetActionButtonArray: GetPropertyDouble name = %{public}s, status = %{public}d", name, status);
        return status;
    }
    for (int dex = 0; dex < static_cast<int>(length); dex++) {
        ani_ref buttonRef;
        if (ANI_OK != (status = env->Object_CallMethodByName_Ref(static_cast<ani_object>(arrayObj),
            "$_get", "I:Lstd/core/Object;", &buttonRef, (ani_int)dex))) {
            ANS_LOGE("GetActionButtonArray: get ref failed, status = %{public}d, index = %{public}d", status, dex);
            return status;
        }
        if (ANI_OK
            != (status = UnwrapNotificationActionButton(env, static_cast<ani_object>(buttonRef), actionButton))) {
            ANS_LOGE("GetActionButtonArray: UnwrapActionButton failed, status = %{public}d, index = %{public}d",
                status, dex);
            return status;
        }
        std::shared_ptr<NotificationActionButton> button
            = NotificationActionButton::Create(actionButton.icon,
            actionButton.title, actionButton.wantAgent, actionButton.extras, 
            actionButton.semanticActionButton, actionButton.autoCreatedReplies, actionButton.mimeTypeOnlyInputs,
            actionButton.userInput, actionButton.isContextual);
        res.push_back(button);
    }
    ANS_LOGD("GetActionButtonArray end");
    return status;
}

ani_object GetAniArrayNotificationActionButton(ani_env* env,
    const std::vector<std::shared_ptr<NotificationActionButton>> &actionButtons)
{
    ANS_LOGD("GetAniArrayActionButton call");
    if (env == nullptr || actionButtons.empty()) {
        ANS_LOGE("GetAniArrayActionButton failed, has nullptr");
        return nullptr;
    }
    ani_object arrayObj = newArrayClass(env, actionButtons.size());
    if (arrayObj == nullptr) {
        ANS_LOGE("GetAniArrayActionButton: arrayObj is nullptr");
        return nullptr;
    }
    ani_size index = 0;
    for (auto &button : actionButtons) {
        ani_object item = WrapNotificationActionButton(env, button);
        if (item == nullptr) {
            ANS_LOGE("GetAniArrayActionButton: item is nullptr");
            return nullptr;
        }
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", index, item)) {
            ANS_LOGE("GetAniArrayActionButton: Object_CallMethodByName_Void failed");
            return nullptr;
        }   
        index ++;
    }
    ANS_LOGD("GetAniArrayActionButton end");
    return arrayObj;
}
}
}