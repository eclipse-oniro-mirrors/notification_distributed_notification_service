/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_ANS_DIALOG_HOST_CLIENT_H
#define BASE_NOTIFICATION_ANS_DIALOG_HOST_CLIENT_H

#include "ans_dialog_callback_stub.h"

#include <memory>
#include <mutex>
#include <refbase.h>

#include "ans_dialog_callback_native_interface.h"
#include "ffrt.h"

namespace OHOS::Notification {
class AnsDialogHostClient final : public AnsDialogCallbackStub {
public:
    static bool IsNullptr();
    static bool CreateIfNullptr(sptr<AnsDialogHostClient>& result);
    static sptr<AnsDialogHostClient> GetInstance();
    static void Destroy();
    static bool SetDialogCallbackInterface(std::unique_ptr<AnsDialogCallbackNativeInterface> dialogCallbackInterface);

    virtual ~AnsDialogHostClient() = default;
    DISALLOW_COPY_AND_MOVE(AnsDialogHostClient);

    ErrCode OnDialogStatusChanged(const DialogStatusData& statusData) override;

private:
    inline static sptr<AnsDialogHostClient> instance_ = nullptr;
    inline static ffrt::mutex instanceMutex_;
    AnsDialogHostClient() = default;

    std::unique_ptr<AnsDialogCallbackNativeInterface> dialogCallbackInterface_ = nullptr;
    std::atomic<bool> hasBeenCalled { false };
};
} // namespace OHOS::Notification

#endif // BASE_NOTIFICATION_ANS_DIALOG_HOST_CLIENT_H
