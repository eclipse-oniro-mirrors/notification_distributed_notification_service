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

    getSupportCommands_ = (GET_SUPPORT_COMMANDS)dlsym(ExtensionHandle_, "GetSupportCommands");
    if (getSupportCommands_ == nullptr) {
        ANS_LOGE("failed to get support ai commands extension %{public}s.", dlerror());
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
        getSupportCommands_ = nullptr;
    }
    ANS_LOGI("notification ai extension wrapper close success");
}

int32_t NotificationAiExtensionWrapper::UpdateNotification(
    const sptr<NotificationRequest> &request, std::unordered_map<std::string, sptr<IResult>> results)
{
    if (updateNotification_ == nullptr) {
        ANS_LOGE("update priority notification wrapper symbol failed");
        return ErrorCode::ERR_FAIL;
    }
    updateNotification_(request, { "update.priorityNotificationType" }, results);
    return ErrorCode::ERR_OK;
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
    if (rules.empty()) {
        ANS_LOGE("query addition config failed or rules empty");
        return;
    }

    result = SyncRules(rules);
    if (result != ErrorCode::ERR_OK) {
        ANS_LOGE("sync ai rules failed");
    }
}

int32_t NotificationAiExtensionWrapper::GetSupportCommands(std::set<std::string> &commands)
{
    if (getSupportCommands_ == nullptr) {
        ANS_LOGE("get support ai commands wrapper symbol failed");
        return ErrorCode::ERR_FAIL;
    }
    return getSupportCommands_(commands);
}

int32_t NotificationAiExtensionWrapper::SyncRules(const std::string &rules)
{
    if (syncRules_ == nullptr) {
        ANS_LOGE("sync rules wrapper symbol failed");
        return ErrorCode::ERR_FAIL;
    }
    return syncRules_(rules);
}
}