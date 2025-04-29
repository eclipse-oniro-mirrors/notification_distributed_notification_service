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

private:
    void* ExtensionHandle_ = nullptr;
    UPDATE_LIVEVIEW_REMINDER_FLAGS updateLiveviewReminderFlags_ = nullptr;
    UPDATE_LIVEVIEW_VOICE_CONTENT updateLiveviewVoiceContent_ = nullptr;
};

#define LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER \
    ::OHOS::DelayedSingleton<LiveviewAllScenariosExtensionWrapper>::GetInstance()
} // namespace OHOS::Notification
#endif  // BASE_NOTIFICATION_ANS_SERVICES_LIVEVIEW_ALL_SCENARIOS_EXTENSION_WRAPPER_H