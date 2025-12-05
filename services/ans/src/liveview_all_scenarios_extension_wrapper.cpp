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

    updateLiveViewConfig_ = (UPDATE_LIVEVIEW_CONFIG)dlsym(ExtensionHandle_, "UpdateLiveViewConfig");
    if (updateLiveViewConfig_  == nullptr) {
        ANS_LOGE("liveview update config %{public}s.", dlerror());
        return;
    }

    checkLiveViewConfig_ = (CHECK_LIVEVIEW_CONFIG)dlsym(ExtensionHandle_, "CheckLiveViewConfig");
    if (checkLiveViewConfig_   == nullptr) {
        ANS_LOGE("liveview check config %{public}s.", dlerror());
        return;
    }

    getLiveViewConfigVersion_ = (GET_LIVEVIEW_CONFIG_VERSION)dlsym(ExtensionHandle_,
        "GetLiveViewConfigVersion");
    if (getLiveViewConfigVersion_ == nullptr) {
        ANS_LOGE("liveview get version %{public}s.", dlerror());
        return;
    }

    notifyLiveViewEvent_  = (NOTIFY_LIVEVIEW_EVENT)dlsym(ExtensionHandle_, "NotifyLiveViewEvent");
    if (notifyLiveViewEvent_ == nullptr) {
        ANS_LOGE("liveview notify config %{public}s.", dlerror());
        return;
    }

    onNotifyDelayedNotification_ =
        (ON_NOTIFY_DELAYED_NOTIFICATION)dlsym(ExtensionHandle_, "OnNotifyDelayedNotification");

    onNotifyClearNotification_ =
        (ON_NOTIFY_CLEAR_NOTIFICATION)dlsym(ExtensionHandle_, "OnNotifyClearNotification");
    ANS_LOGI("liveview all scenarios extension wrapper init success");
}

void LiveviewAllScenariosExtensionWrapper::CloseExtentionWrapper()
{
    if (ExtensionHandle_ != nullptr) {
        dlclose(ExtensionHandle_);
        ExtensionHandle_ = nullptr;
        updateLiveviewReminderFlags_ = nullptr;
        updateLiveviewVoiceContent_ = nullptr;
        updateLiveViewConfig_ = nullptr;
        checkLiveViewConfig_ = nullptr;
        getLiveViewConfigVersion_ = nullptr;
        notifyLiveViewEvent_ = nullptr;
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

ErrCode LiveviewAllScenariosExtensionWrapper::UpdateLiveViewConfig(const std::string& config)
{
    if (updateLiveViewConfig_ == nullptr) {
        ANS_LOGE("Liveview update config failed");
        return -1;
    }

    return updateLiveViewConfig_(config);
}

ErrCode LiveviewAllScenariosExtensionWrapper::CheckLiveViewConfig(const std::string& bundleName,
    const std::string& event, int32_t userId, bool& enable)
{
    if (checkLiveViewConfig_ == nullptr) {
        ANS_LOGE("Liveview check config failed");
        return -1;
    }

    return checkLiveViewConfig_(bundleName, event, userId, enable);
}

ErrCode LiveviewAllScenariosExtensionWrapper::GetLiveViewConfigVersion(int32_t& version)
{
    if (getLiveViewConfigVersion_ == nullptr) {
        ANS_LOGE("Liveview get version");
        return -1;
    }

    return getLiveViewConfigVersion_(version);
}

ErrCode LiveviewAllScenariosExtensionWrapper::NotifyLiveViewEvent(const std::string& event,
    const sptr<NotificationBundleOption>& bundleInfo)
{
    if (notifyLiveViewEvent_ == nullptr) {
        ANS_LOGE("Liveview notify config failed");
        return -1;
    }

    return notifyLiveViewEvent_(event, bundleInfo);
}

ErrCode LiveviewAllScenariosExtensionWrapper::OnNotifyDelayedNotification(
    const sptr<NotificationRequest> &request)
{
    if (onNotifyDelayedNotification_ == nullptr) {
        ANS_LOGE("OnNotifyDelayedNotification wrapper symbol failed");
        return -1;
    }
    return onNotifyDelayedNotification_(request);
}

ErrCode LiveviewAllScenariosExtensionWrapper::OnNotifyClearNotification(
    const std::vector<std::string> &triggerKeys)
{
    if (onNotifyClearNotification_ == nullptr) {
        ANS_LOGE("OnNotifyClearNotification wrapper symbol failed");
        return -1;
    }
    return onNotifyClearNotification_(triggerKeys);
}
}
