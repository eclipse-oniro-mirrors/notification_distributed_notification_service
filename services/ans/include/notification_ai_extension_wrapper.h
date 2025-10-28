/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_ANS_SERVICES_NOTIFICATION_AI_EXTENSION_WRAPPER_H
#define BASE_NOTIFICATION_ANS_SERVICES_NOTIFICATION_AI_EXTENSION_WRAPPER_H

#include <vector>
#include <unordered_map>

#include "refbase.h"
#include "singleton.h"
#include "notification_request.h"

namespace OHOS::Notification {

struct IResult : public RefBase {
    int32_t returnCode;
    int32_t type;
};

class NotificationAiExtensionWrapper final {
    DECLARE_DELAYED_SINGLETON(NotificationAiExtensionWrapper);
public:
    void InitExtensionWrapper();
    void CloseExtensionWrapper();
    typedef int32_t (*INIT)();
    typedef int32_t (*GET_SUPPORT_COMMANDS)(std::set<std::string> &commands);
    typedef int32_t (*SYNC_RULES)(const std::string &rules);
    typedef int32_t (*UPDATE_NOTIFICATION)(
            const sptr<NotificationRequest> &request,
            const std::list<std::string> &commands,
            std::unordered_map<std::string, sptr<IResult>> &results);
    void Init();
    int32_t GetSupportCommands(std::set<std::string> &commands);
    int32_t SyncRules(const std::string &rules);
    int32_t UpdateNotification(
        const sptr<NotificationRequest> &request, std::unordered_map<std::string, sptr<IResult>> results);

    enum ErrorCode : int32_t {
        ERR_FAIL = -1,
        ERR_OK,
    };

private:
    void* ExtensionHandle_ = nullptr;
    UPDATE_NOTIFICATION updateNotification_ = nullptr;
    INIT init_ = nullptr;
    SYNC_RULES syncRules_ = nullptr;
    GET_SUPPORT_COMMANDS getSupportCommands_ = nullptr;
};

#define NOTIFICATION_AI_EXTENSION_WRAPPER \
    ::OHOS::DelayedSingleton<NotificationAiExtensionWrapper>::GetInstance()
} // namespace OHOS::Notification
#endif  // BASE_NOTIFICATION_ANS_SERVICES_NOTIFICATION_AI_EXTENSION_WRAPPER_H