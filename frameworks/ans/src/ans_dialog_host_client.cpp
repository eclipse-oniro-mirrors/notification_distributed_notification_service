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

#include "ans_dialog_host_client.h"

#include "ans_log_wrapper.h"

namespace OHOS::Notification {
bool AnsDialogHostClient::CreateIfNullptr(sptr<AnsDialogHostClient>& result)
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> lock(AnsDialogHostClient::instanceMutex_);
    if (instance_ != nullptr) {
        result = instance_;
        return false;
    }
    AnsDialogHostClient::instance_ = new (std::nothrow) AnsDialogHostClient();
    result = AnsDialogHostClient::instance_;
    return result != nullptr;
}

sptr<AnsDialogHostClient> AnsDialogHostClient::GetInstance()
{
    std::lock_guard<std::mutex> lock(AnsDialogHostClient::instanceMutex_);
    return AnsDialogHostClient::instance_;
}

void AnsDialogHostClient::Destroy()
{
    std::lock_guard<std::mutex> lock(AnsDialogHostClient::instanceMutex_);
    AnsDialogHostClient::instance_ = nullptr;
}

bool AnsDialogHostClient::SetDialogCallbackInterface(
    std::unique_ptr<AnsDialogCallbackNativeInterface> dialogCallbackInterface)
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> lock(AnsDialogHostClient::instanceMutex_);
    if (dialogCallbackInterface == nullptr || AnsDialogHostClient::instance_ == nullptr) {
        return false;
    }
    AnsDialogHostClient::instance_->dialogCallbackInterface_ = std::move(dialogCallbackInterface);
    return true;
}

ErrCode AnsDialogHostClient::OnDialogStatusChanged(const DialogStatusData& statusData)
{
    ANS_LOGD("enter");
    if (dialogCallbackInterface_ == nullptr) {
        ANS_LOGE("AnsDialogCallbackNativeInterface is null.");
        return ERR_OK;
    }
    if (hasBeenCalled.exchange(true)) {
        ANS_LOGE("Has been called.");
        return ERR_INVALID_DATA;
    }
    dialogCallbackInterface_->ProcessDialogStatusChanged(statusData);
    return ERR_OK;
}
} // namespace OHOS::Notification
