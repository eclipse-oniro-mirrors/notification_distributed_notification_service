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
#include "notification.h"
#include "notification_request.h"

namespace OHOS::Notification {
class NotificationAiExtensionWrapper final {
    DECLARE_DELAYED_SINGLETON(NotificationAiExtensionWrapper);
public:
    void InitExtensionWrapper();
    void CloseExtensionWrapper();
    typedef int32_t (*INIT)();
    typedef int32_t (*SYNC_RULES)(const std::string &rules);
    typedef int32_t (*UPDATE_NOTIFICATION)(
        const std::vector<sptr<NotificationRequest>> &requests,
        const std::string &command, std::vector<int32_t> &results,
        const uint32_t aiStatus, const std::vector<int64_t> strategies);
    typedef int32_t (*SYNC_BUNDLE_KEYWORDS)(
        const sptr<NotificationBundleOption> &bundleOption, const std::string &keyword);
    typedef int32_t (*NOTIFY_PRIORITY_EVENT)(const std::string &event,
        const std::vector<sptr<NotificationBundleOption>> &bundleOptions,
        const std::vector<sptr<NotificationRequest>> &requests);
    void Init();
    int32_t SyncRules(const std::string &rules);
    int32_t UpdateNotification(
        const std::vector<sptr<NotificationRequest>> &requests,
        const std::string &command, std::vector<int32_t> &results,
        const uint32_t aiStatus, const std::vector<int64_t> strategies);
    int32_t SyncBundleKeywords(const sptr<NotificationBundleOption> &bundleOption, const std::string &keyword);
    int32_t NotifyPriorityEvent(const std::string &event,
        const std::vector<sptr<NotificationBundleOption>> &bundleOptions,
        const std::vector<sptr<NotificationRequest>> &requests);

    enum ErrorCode : int32_t {
        ERR_FAIL = -1,
        ERR_OK,
    };

    static constexpr const char *UPDATE_PRIORITY_TYPE = "update.priorityNotificationType";
    static constexpr const char *REFRESH_KEYWORD_PRIORITY_TYPE = "refresh.keyword.priorityNotificationType";
    static constexpr const char *REFRESH_SWITCH_PRIORITY_TYPE = "refresh.switch.priorityNotificationType";

private:
    void* ExtensionHandle_ = nullptr;
    UPDATE_NOTIFICATION updateNotification_ = nullptr;
    INIT init_ = nullptr;
    SYNC_RULES syncRules_ = nullptr;
    SYNC_BUNDLE_KEYWORDS syncBundleKeywords_ = nullptr;
    NOTIFY_PRIORITY_EVENT notifyPriorityEvent_ = nullptr;
};

#define NOTIFICATION_AI_EXTENSION_WRAPPER \
    ::OHOS::DelayedSingleton<NotificationAiExtensionWrapper>::GetInstance()
} // namespace OHOS::Notification
#endif  // BASE_NOTIFICATION_ANS_SERVICES_NOTIFICATION_AI_EXTENSION_WRAPPER_H