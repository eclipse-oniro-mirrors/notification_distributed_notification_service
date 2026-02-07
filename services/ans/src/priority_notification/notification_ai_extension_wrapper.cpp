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

#include "notification_ai_extension_wrapper.h"

#include <dlfcn.h>
#include <string>

#include "ans_const_define.h"
#include "notification_bundle_option.h"
#include "notification_preferences.h"

namespace OHOS::Notification {
const std::string EXTENSION_NOTIFICATION_AI_PATH = "libnotification_ai.z.so";
NotificationAiExtensionWrapper::NotificationAiExtensionWrapper()
{
    InitExtensionWrapper();
}

NotificationAiExtensionWrapper::~NotificationAiExtensionWrapper()
{
    CloseExtensionWrapper();
}

void NotificationAiExtensionWrapper::InitExtensionWrapper()
{
    ExtensionHandle_ = dlopen(EXTENSION_NOTIFICATION_AI_PATH.c_str(), RTLD_NOW);
    if (ExtensionHandle_ == nullptr) {
        ANS_LOGE("notification ai extension wrapper dlopen failed, error: %{public}s", dlerror());
        return;
    }

    updateNotification_ = (UPDATE_NOTIFICATION)dlsym(ExtensionHandle_, "UpdateNotification");
    if (updateNotification_ == nullptr) {
        ANS_LOGE("failed to update priority notification extension %{public}s.", dlerror());
        return;
    }

    init_ = (INIT)dlsym(ExtensionHandle_, "Init");
    if (init_ == nullptr) {
        ANS_LOGE("failed to init notification ai extension %{public}s.", dlerror());
        return;
    }

    syncRules_ = (SYNC_RULES)dlsym(ExtensionHandle_, "SyncRules");
    if (syncRules_ == nullptr) {
        ANS_LOGE("failed to sync ai rules extension %{public}s.", dlerror());
        return;
    }

    syncBundleKeywords_ = (SYNC_BUNDLE_KEYWORDS)dlsym(ExtensionHandle_, "SyncBundleKeywords");
    if (syncBundleKeywords_ == nullptr) {
        ANS_LOGE("failed to sync bundle keywords extension %{public}s.", dlerror());
        return;
    }

    notifyPriorityEvent_ = (NOTIFY_PRIORITY_EVENT)dlsym(ExtensionHandle_, "NotifyPriorityEvent");
    if (notifyPriorityEvent_ == nullptr) {
        ANS_LOGE("failed to notify priority event extension %{public}s.", dlerror());
        return;
    }

    ANS_LOGI("notification ai extension wrapper init success");
}

void NotificationAiExtensionWrapper::CloseExtensionWrapper()
{
    if (ExtensionHandle_ != nullptr) {
        dlclose(ExtensionHandle_);
        ExtensionHandle_ = nullptr;
        updateNotification_ = nullptr;
        init_ = nullptr;
        syncRules_ = nullptr;
        syncBundleKeywords_ = nullptr;
        notifyPriorityEvent_ = nullptr;
    }
    ANS_LOGI("notification ai extension wrapper close success");
}

int32_t NotificationAiExtensionWrapper::UpdateNotification(
    const std::vector<sptr<NotificationRequest>> &requests,
    const std::string &command, std::vector<int32_t> &results,
    const uint32_t aiStatus, const std::vector<int64_t> strategies)
{
    if (updateNotification_ == nullptr) {
        ANS_LOGE("update priority notification wrapper symbol failed");
        return ErrorCode::ERR_FAIL;
    }
    
    return updateNotification_(requests, command, results, aiStatus, strategies);
}

void NotificationAiExtensionWrapper::Init()
{
    if (init_ == nullptr) {
        ANS_LOGE("init notification ai wrapper symbol failed");
        return;
    }

    int32_t result = init_();
    if (result != ErrorCode::ERR_OK) {
        ANS_LOGE("init notification ai with rules failed");
        return;
    }

    std::string rules = NotificationPreferences::GetInstance()->GetAdditionalConfig(PRIORITY_RULE_CONFIG_KEY);
    if (!rules.empty()) {
        result = SyncRules(rules);
        if (result != ErrorCode::ERR_OK) {
            ANS_LOGE("sync ai rules failed");
        }
    }
}

int32_t NotificationAiExtensionWrapper::SyncRules(const std::string &rules)
{
    if (syncRules_ == nullptr) {
        ANS_LOGE("sync rules wrapper symbol failed");
        return ErrorCode::ERR_FAIL;
    }
    return syncRules_(rules);
}

int32_t NotificationAiExtensionWrapper::SyncBundleKeywords(
    const sptr<NotificationBundleOption> &bundleOption, const std::string &keyword)
{
    if (syncBundleKeywords_ == nullptr) {
        ANS_LOGE("sync bundle keywords wrapper symbol failed");
        return ErrorCode::ERR_FAIL;
    }
    return syncBundleKeywords_(bundleOption, keyword);
}

int32_t NotificationAiExtensionWrapper::NotifyPriorityEvent(
    const std::string &event,
    const std::vector<sptr<NotificationBundleOption>> &bundleOptions,
    const std::vector<sptr<NotificationRequest>> &requests)
{
    if (notifyPriorityEvent_ == nullptr || bundleOptions.size() <= 0) {
        ANS_LOGE("notify priority event wrapper symbol failed");
        return ErrorCode::ERR_FAIL;
    }
    return notifyPriorityEvent_(event, bundleOptions, requests);
}
}