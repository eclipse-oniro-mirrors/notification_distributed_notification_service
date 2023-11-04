/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_JS_ANS_DIALOG_CALLBACK_H
#define BASE_NOTIFICATION_JS_ANS_DIALOG_CALLBACK_H

#include "ans_dialog_callback_native_interface.h"

#include "nocopyable.h"
#include "enable_notification.h"

namespace OHOS {
using Notification::AnsDialogCallbackNativeInterface;
using Notification::DialogStatusData;

namespace NotificationNapi {
using JsAnsDialogCallbackComplete = void(napi_env, void*);

class JsAnsDialogCallback final : public AnsDialogCallbackNativeInterface {
public:
    JsAnsDialogCallback() = default;
    ~JsAnsDialogCallback() override = default;
    DISALLOW_COPY_AND_MOVE(JsAnsDialogCallback);

    bool Init(napi_env env,
        AsyncCallbackInfoIsEnable* callbackInfo,
        JsAnsDialogCallbackComplete complete);
    void ProcessDialogStatusChanged(const DialogStatusData& data) override;

private:
    napi_env env_ = nullptr;
    AsyncCallbackInfoIsEnable* callbackInfo_ = nullptr;
    JsAnsDialogCallbackComplete* complete_ = nullptr;

    static int32_t GetErrCodeFromStatus(EnabledDialogStatus status);
};
} // namespace NotificationNapi
} // namespace OHOS

#endif // BASE_NOTIFICATION_JS_ANS_DIALOG_CALLBACK_H
