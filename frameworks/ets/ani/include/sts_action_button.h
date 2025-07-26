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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_ACTION_BUTTON_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_ACTION_BUTTON_H
#include "ani.h"
#include "pixel_map.h"
#include "want_params.h"
#include "want_agent.h"
#include "notification_constant.h"
#include "notification_user_input.h"
#include "notification_action_button.h"

namespace OHOS {
namespace NotificationSts {
using namespace OHOS::AppExecFwk;
using namespace OHOS::AAFwk;
using SemanticActionButton = OHOS::Notification::NotificationConstant::SemanticActionButton;
using WantAgent = OHOS::AbilityRuntime::WantAgent::WantAgent;
using NotificationUserInput = OHOS::Notification::NotificationUserInput;
using NotificationActionButton = OHOS::Notification::NotificationActionButton;

struct StsActionButton {
    std::shared_ptr<Media::PixelMap> icon;
    std::string title;
    std::shared_ptr<WantAgent> wantAgent;
    std::shared_ptr<WantParams> extras = {};
    SemanticActionButton semanticActionButton = SemanticActionButton::NONE_ACTION_BUTTON;
    bool autoCreatedReplies = true;
    std::vector<std::shared_ptr<NotificationUserInput>> mimeTypeOnlyInputs = {};
    std::shared_ptr<NotificationUserInput> userInput = {};
    bool isContextual = false;
};

ani_status UnwrapNotificationActionButton(ani_env *env, ani_object param,
    StsActionButton &actionButton);
ani_object WrapNotificationActionButton(ani_env* env,
    const std::shared_ptr<NotificationActionButton> &actionButton);

ani_status GetNotificationActionButtonArray(ani_env *env, ani_object param,
    const char *name, std::vector<std::shared_ptr<NotificationActionButton>> &res);
ani_object GetAniArrayNotificationActionButton(ani_env* env,
    const std::vector<std::shared_ptr<NotificationActionButton>> &actionButtons);
}
}
#endif