/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "voice_extension_wrapper.h"

#include <dlfcn.h>
#include <string>

#include "ans_log_wrapper.h"
#include "ans_const_define.h"

namespace OHOS::Notification::Infra {

const std::string EXTENSION_VOICE_PATH = "libnotification_voice.z.so";

VoiceExtensionWrapper& VoiceExtensionWrapper::GetInstance()
{
    static VoiceExtensionWrapper extensionWrapper;
    return extensionWrapper;
}

VoiceExtensionWrapper::VoiceExtensionWrapper() {}

VoiceExtensionWrapper::~VoiceExtensionWrapper()
{
    CloseExtensionWrapper();
}

void VoiceExtensionWrapper::EnsureLoaded()
{
    if (loaded_.load(std::memory_order_acquire)) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (loaded_.load(std::memory_order_relaxed)) {
        return;
    }

    ExtensionHandle_ = dlopen(EXTENSION_VOICE_PATH.c_str(), RTLD_NOW);
    if (ExtensionHandle_ == nullptr) {
        ANS_LOGE("voice extension wrapper dlopen failed, error: %{public}s", dlerror());
        return;
    }

    generateVoiceContent_ = (GENERATE_VOICE_CONTENT)dlsym(ExtensionHandle_, "GenerateVoiceContent");
    if (generateVoiceContent_ == nullptr) {
        ANS_LOGE("voice extension wrapper dlsym GenerateVoiceContent failed, error: %{public}s", dlerror());
        dlclose(ExtensionHandle_);
        ExtensionHandle_ = nullptr;
        return;
    }

    updateVoiceConfig_ = (UPDATE_VOICE_CONFIG)dlsym(ExtensionHandle_, "UpdateVoiceConfig");
    if (updateVoiceConfig_ == nullptr) {
        ANS_LOGE("voice extension wrapper dlsym UpdateVoiceConfig failed, error: %{public}s", dlerror());
        dlclose(ExtensionHandle_);
        ExtensionHandle_ = nullptr;
        generateVoiceContent_ = nullptr;
        return;
    }

    notifyVoiceEvent_ = (NOTIFY_VOICE_EVENT)dlsym(ExtensionHandle_, "NotifyVoiceEvent");
    if (notifyVoiceEvent_ == nullptr) {
        ANS_LOGE("voice extension wrapper dlsym NotifyVoiceEvent failed, error: %{public}s", dlerror());
        dlclose(ExtensionHandle_);
        ExtensionHandle_ = nullptr;
        generateVoiceContent_ = nullptr;
        updateVoiceConfig_ = nullptr;
        return;
    }

    if (!cachedVoiceConfig_.empty()) {
        ANS_LOGI("Apply cached voice config");
        updateVoiceConfig_(cachedVoiceConfig_);
        cachedVoiceConfig_.clear();
    }

    loaded_.store(true, std::memory_order_release);
    ANS_LOGI("voice extension wrapper init success");
}

int32_t VoiceExtensionWrapper::GenerateVoiceContent(
    const sptr<NotificationRequest>& request, std::string& content, std::string& externInfo)
{
    EnsureLoaded();

    if (!loaded_.load(std::memory_order_acquire) || generateVoiceContent_ == nullptr) {
        ANS_LOGE("Voice extension not loaded");
        return ErrorCode::ERR_FAIL;
    }

    return generateVoiceContent_(request, content, externInfo);
}

int32_t VoiceExtensionWrapper::UpdateVoiceConfig(const std::string& configs)
{
    if (loaded_.load(std::memory_order_acquire) && updateVoiceConfig_ != nullptr) {
        return updateVoiceConfig_(configs);
    }

    std::lock_guard<std::mutex> lock(mutex_);
    cachedVoiceConfig_ = configs;
    if (loaded_.load(std::memory_order_relaxed) && updateVoiceConfig_ != nullptr) {
        updateVoiceConfig_(cachedVoiceConfig_);
        cachedVoiceConfig_.clear();
        return ErrorCode::ERR_OK;
    }
    ANS_LOGI("Voice config cached, will apply when extension loaded");
    return ErrorCode::ERR_OK;
}

int32_t VoiceExtensionWrapper::NotifyVoiceEvent(
    const std::string& event, const sptr<NotificationRequest>& request)
{
    if (!loaded_.load(std::memory_order_acquire) || notifyVoiceEvent_ == nullptr) {
        ANS_LOGI("Voice extension not loaded, skip NotifyVoiceEvent: %{public}s", event.c_str());
        return ErrorCode::ERR_OK;
    }

    return notifyVoiceEvent_(event, request);
}

void VoiceExtensionWrapper::CloseExtensionWrapper()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (ExtensionHandle_ != nullptr) {
        dlclose(ExtensionHandle_);
        ExtensionHandle_ = nullptr;
        generateVoiceContent_ = nullptr;
        updateVoiceConfig_ = nullptr;
        notifyVoiceEvent_ = nullptr;
    }
    loaded_.store(false, std::memory_order_release);
    cachedVoiceConfig_.clear();
    ANS_LOGI("Voice extension wrapper close success");
}

} // namespace OHOS::Notification::Infra