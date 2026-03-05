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

#include "system_sound_dynamic_wrapper.h"

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
namespace {
static const int32_t REMOVE_SUCCESS_COUNT = 1;
}

SystemSoundDynamicWrapper SystemSoundDynamicWrapper::GetInstance()
{
    static SystemSoundDynamicWrapper instance;
    return instance;
}

SystemSoundDynamicWrapper::SystemSoundDynamicWrapper()
{
    systemSoundClient_ = Media::SystemSoundManagerFactory::CreateSystemSoundManager();
}

bool SystemSoundDynamicWrapper::RemoveCustomizedTone(const std::string uri)
{
    if (uri.empty()) {
        return true;
    }
    if (systemSoundClient_ == nullptr) {
        ANS_LOGW("AnsSystemSystemSoundRemoveTone: not initialized");
        return false;
    }
    
    int32_t result = systemSoundClient_->RemoveCustomizedTone(nullptr, std::string(uri));
    ANS_LOGI("Remove Customized tone, uri: %{public}s, result: %{public}d",
        uri.c_str(), result);
    return result == REMOVE_SUCCESS_COUNT;
}

bool SystemSoundDynamicWrapper::RemoveCustomizedToneList(const std::vector<std::string> uris)
{
    if (uris.empty()) {
        return true;
    }
    if (systemSoundClient_ == nullptr) {
        ANS_LOGW("Get system clint failed.");
        return false;
    }
    Media::SystemSoundError errCode = Media::SystemSoundError::ERROR_OK;
    auto results = systemSoundClient_->RemoveCustomizedToneList(uris, errCode);
    std::vector<std::string> failedUris;
    for (auto& item : results) {
        if (item.second != Media::SystemSoundError::ERROR_OK) {
            failedUris.push_back(item.first);
        }
    }
    if (!failedUris.empty()) {
        results = systemSoundClient_->RemoveCustomizedToneList(uris, errCode);
    }
    return true;
}
}
}