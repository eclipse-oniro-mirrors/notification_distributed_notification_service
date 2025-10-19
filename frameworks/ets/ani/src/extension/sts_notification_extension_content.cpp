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
#include "sts_notification_extension_content.h"

#include "sts_common.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace NotificationSts {
ani_status UnwrapNotificationExtensionContent(ani_env *env, ani_object param,
    NotificationExtensionContent &extensionContent)
{
    ANS_LOGD("UnwrapNotificationExtensionContent call");
    if (env == nullptr || param == nullptr) {
        ANS_LOGE("UnwrapNotificationExtensionContent fail, has nullptr");
        return ANI_ERROR;
    }
    ani_status status = ANI_ERROR;
    ani_boolean isUndefind = ANI_TRUE;
    std::string title;
    if ((status = GetPropertyString(env, param, "title", isUndefind, title)) != ANI_OK) {
        ANS_LOGE("UnwrapNotificationExtensionContent : Get title failed");
        return ANI_INVALID_ARGS;
    }
    extensionContent.SetTitle(title);

    std::string text;
    if ((status = GetPropertyString(env, param, "text", isUndefind, text)) != ANI_OK) {
        ANS_LOGE("UnwrapNotificationExtensionContent : Get text failed");
        return ANI_INVALID_ARGS;
    }
    extensionContent.SetText(text);

    ANS_LOGD("UnwrapNotificationExtensionContent end");
    return status;
}

bool SetNotificationExtensionContentByRequiredParameter(
    ani_env *env, ani_class contentCls, ani_object &contentObject,
    const std::shared_ptr<NotificationExtensionContent> &extensionContent)
{
    ANS_LOGD("SetExtensionContentParameter call");
    if (env == nullptr || contentCls == nullptr || contentObject == nullptr || extensionContent == nullptr) {
        ANS_LOGE("SetExtensionContentParameter fail, has nullptr");
        return false;
    }
    // title: string;
    if (!SetPropertyOptionalByString(env, contentObject, "title", extensionContent->GetTitle())) {
        ANS_LOGE("SetExtensionContentParameter: Set title failed");
        return false;
    }

    // text: string;
    if (!SetPropertyOptionalByString(env, contentObject, "text", extensionContent->GetText())) {
        ANS_LOGE("SetExtensionContentParameter: Set text failed");
        return false;
    }

    ANS_LOGD("SetExtensionContentParameter end");
    return true;
}

ani_object WrapNotificationExtensionContent(ani_env* env,
    const std::shared_ptr<NotificationExtensionContent> &extensionContent)
{
    ANS_LOGD("WrapNotificationExtensionContent call");
    if (env == nullptr || extensionContent == nullptr) {
        ANS_LOGE("WrapNotificationExtensionContent failed, has nullptr");
        return nullptr;
    }
    ani_object contentObject = nullptr;
    ani_class contentCls = nullptr;
    if (!CreateClassObjByClassName(env,
        "notification.NotificationExtensionContent.NotificationExtensionContentInner", contentCls, contentObject)) {
        ANS_LOGE("WrapNotificationExtensionContent : CreateClassObjByClassName failed");
        return nullptr;
    }
    if (!SetNotificationExtensionContentByRequiredParameter(env, contentCls, contentObject, extensionContent)) {
        ANS_LOGE("WrapNotificationExtensionContent : SetExtensionContentParameter failed");
        return nullptr;
    }

    return contentObject;
}
}
}