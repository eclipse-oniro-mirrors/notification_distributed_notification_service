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

#ifndef NOTIFICATION_INFRA_VOICE_EXTENSION_WRAPPER_H
#define NOTIFICATION_INFRA_VOICE_EXTENSION_WRAPPER_H

#include <atomic>
#include <mutex>
#include <string>

#include "notification_request.h"

namespace OHOS::Notification::Infra {

class VoiceExtensionWrapper final {
public:
    static VoiceExtensionWrapper& GetInstance();

    int32_t GenerateVoiceContent(const sptr<NotificationRequest>& request,
                                  std::string& content, std::string& externInfo);
    int32_t UpdateVoiceConfig(const std::string& configs);
    int32_t NotifyVoiceEvent(const std::string& event, const sptr<NotificationRequest>& request);
    void CloseExtensionWrapper();

    enum ErrorCode : int32_t {
        ERR_FAIL = -1,
        ERR_OK = 0,
    };

private:
    VoiceExtensionWrapper();
    ~VoiceExtensionWrapper();

    void EnsureLoaded();

    std::mutex mutex_;
    std::atomic<bool> loaded_{false};
    std::string cachedVoiceConfig_;

    void* ExtensionHandle_ = nullptr;

    typedef int32_t (*GENERATE_VOICE_CONTENT)(const sptr<NotificationRequest>&, std::string&, std::string&);
    typedef int32_t (*UPDATE_VOICE_CONFIG)(const std::string&);
    typedef int32_t (*NOTIFY_VOICE_EVENT)(const std::string&, const sptr<NotificationRequest>&);

    GENERATE_VOICE_CONTENT generateVoiceContent_ = nullptr;
    UPDATE_VOICE_CONFIG updateVoiceConfig_ = nullptr;
    NOTIFY_VOICE_EVENT notifyVoiceEvent_ = nullptr;
};

#define VOICE_EXTENSION_WRAPPER OHOS::Notification::Infra::VoiceExtensionWrapper::GetInstance()

} // namespace OHOS::Notification::Infra
#endif // NOTIFICATION_INFRA_VOICE_EXTENSION_WRAPPER_H