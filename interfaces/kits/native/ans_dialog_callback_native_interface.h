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

#ifndef BASE_NOTIFICATION_ANS_DIALOG_CALLBACK_NATIVE_INTERFACE_H
#define BASE_NOTIFICATION_ANS_DIALOG_CALLBACK_NATIVE_INTERFACE_H

#include "ans_dialog_callback_interface.h"
#include "nocopyable.h"

namespace OHOS::Notification {
class AnsDialogCallbackNativeInterface {
public:
    AnsDialogCallbackNativeInterface() = default;
    virtual ~AnsDialogCallbackNativeInterface() = default;
    DISALLOW_COPY_AND_MOVE(AnsDialogCallbackNativeInterface);

    virtual void ProcessDialogStatusChanged(const DialogStatusData& data) = 0;
};
} // namespace OHOS::Notification

#endif // BASE_NOTIFICATION_ANS_DIALOG_CALLBACK_NATIVE_INTERFACE_H
