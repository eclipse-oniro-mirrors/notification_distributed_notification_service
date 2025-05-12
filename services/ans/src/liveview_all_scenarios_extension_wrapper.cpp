/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "liveview_all_scenarios_extension_wrapper.h"

#include <dlfcn.h>
#include <string>

namespace OHOS::Notification {
const std::string EXTENTION_LIVEVIEW_ALL_SCENARIOS_PATH = "libliveview.z.so";
LiveviewAllScenariosExtensionWrapper::LiveviewAllScenariosExtensionWrapper()
{
    InitExtentionWrapper();
}
LiveviewAllScenariosExtensionWrapper::~LiveviewAllScenariosExtensionWrapper()
{
    CloseExtentionWrapper();
}

void LiveviewAllScenariosExtensionWrapper::InitExtentionWrapper()
{
    ExtensionHandle_ = dlopen(EXTENTION_LIVEVIEW_ALL_SCENARIOS_PATH.c_str(), RTLD_NOW);
    if (ExtensionHandle_ == nullptr) {
        ANS_LOGE("liveview all scenarios extension wrapper dlopen failed, error: %{public}s", dlerror());
        return;
    }

    updateLiveviewReminderFlags_ = (UPDATE_LIVEVIEW_REMINDER_FLAGS)dlsym(ExtensionHandle_,
        "UpdateLiveviewReminderFlags");
    if (updateLiveviewReminderFlags_ == nullptr) {
        ANS_LOGE("liveview all scenarios extension wrapper dlsym updateLiveviewReminderFlags_ failed, "
            "error: %{public}s", dlerror());
        return;
    }

    updateLiveviewVoiceContent_ = (UPDATE_LIVEVIEW_VOICE_CONTENT)dlsym(ExtensionHandle_,
        "UpdateLiveviewVoiceContent");
    if (updateLiveviewVoiceContent_ == nullptr) {
        ANS_LOGE("liveview all scenarios extension wrapper dlsym updateLiveviewVoiceContent_ failed, "
            "error: %{public}s", dlerror());
        return;
    }

    ANS_LOGI("liveview all scenarios extension wrapper init success");
}

void LiveviewAllScenariosExtensionWrapper::CloseExtentionWrapper()
{
    if (ExtensionHandle_ != nullptr) {
        dlclose(ExtensionHandle_);
        ExtensionHandle_ = nullptr;
        updateLiveviewReminderFlags_ = nullptr;
        updateLiveviewVoiceContent_ = nullptr;
    }
    ANS_LOGI("liveview all scenarios extension wrapper close success");
}

ErrCode LiveviewAllScenariosExtensionWrapper::UpdateLiveviewReminderFlags(const sptr<NotificationRequest> &request)
{
    if (updateLiveviewReminderFlags_ == nullptr) {
        ANS_LOGE("UpdateLiveviewReminderFlags wrapper symbol failed");
        return 0;
    }
    return updateLiveviewReminderFlags_(request);
}

ErrCode LiveviewAllScenariosExtensionWrapper::UpdateLiveviewVoiceContent(const sptr<NotificationRequest> &request)
{
    if (updateLiveviewVoiceContent_ == nullptr) {
        ANS_LOGE("UpdateLiveviewVoiceContent wrapper symbol failed");
        return 0;
    }
    return updateLiveviewVoiceContent_(request);
}
}