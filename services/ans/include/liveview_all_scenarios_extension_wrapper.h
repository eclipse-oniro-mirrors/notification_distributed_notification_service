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

#ifndef BASE_NOTIFICATION_ANS_SERVICES_LIVEVIEW_ALL_SCENARIOS_EXTENSION_WRAPPER_H
#define BASE_NOTIFICATION_ANS_SERVICES_LIVEVIEW_ALL_SCENARIOS_EXTENSION_WRAPPER_H

#include <vector>

#include "refbase.h"
#include "singleton.h"
#include "notification_request.h"

namespace OHOS::Notification {
class LiveviewAllScenariosExtensionWrapper final {
    DECLARE_DELAYED_SINGLETON(LiveviewAllScenariosExtensionWrapper);
public:
    void InitExtentionWrapper();
    void CloseExtentionWrapper();
    typedef ErrCode (*UPDATE_LIVEVIEW_REMINDER_FLAGS)(const sptr<NotificationRequest> &request);
    ErrCode UpdateLiveviewReminderFlags(const sptr<NotificationRequest> &request);
    typedef ErrCode (*UPDATE_LIVEVIEW_VOICE_CONTENT)(const sptr<NotificationRequest> &request);
    ErrCode UpdateLiveviewVoiceContent(const sptr<NotificationRequest> &request);

    typedef ErrCode (*UPDATE_LIVEVIEW_CONFIG)(const std::string& config);
    ErrCode UpdateLiveViewConfig(const std::string& config);
    typedef ErrCode (*CHECK_LIVEVIEW_CONFIG)(const std::string& bundleName, const std::string& event,
        int32_t userId, bool& enable);
    ErrCode CheckLiveViewConfig(const std::string& bundleName, const std::string& event,
        int32_t userId, bool& enable);
    typedef ErrCode (*GET_LIVEVIEW_CONFIG_VERSION)(int32_t& version);
    ErrCode GetLiveViewConfigVersion(int32_t& version);
    typedef ErrCode (*NOTIFY_LIVEVIEW_EVENT)(const std::string& event,
        const sptr<NotificationBundleOption>& bundleInfo);
    ErrCode NotifyLiveViewEvent(const std::string& event, const sptr<NotificationBundleOption>& bundleInfo);
private:
    void* ExtensionHandle_ = nullptr;
    CHECK_LIVEVIEW_CONFIG checkLiveViewConfig_ = nullptr;
    NOTIFY_LIVEVIEW_EVENT notifyLiveViewEvent_ = nullptr;
    UPDATE_LIVEVIEW_CONFIG updateLiveViewConfig_ = nullptr;
    GET_LIVEVIEW_CONFIG_VERSION getLiveViewConfigVersion_ = nullptr;
    UPDATE_LIVEVIEW_REMINDER_FLAGS updateLiveviewReminderFlags_ = nullptr;
    UPDATE_LIVEVIEW_VOICE_CONTENT updateLiveviewVoiceContent_ = nullptr;
};

#define LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER \
    ::OHOS::DelayedSingleton<LiveviewAllScenariosExtensionWrapper>::GetInstance()
} // namespace OHOS::Notification
#endif  // BASE_NOTIFICATION_ANS_SERVICES_LIVEVIEW_ALL_SCENARIOS_EXTENSION_WRAPPER_H
