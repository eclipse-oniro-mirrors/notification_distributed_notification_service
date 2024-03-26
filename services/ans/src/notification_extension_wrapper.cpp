/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <dlfcn.h>

#include "notification_extension_wrapper.h"

namespace OHOS::Notification {
const std::string EXTENTION_WRAPPER_PATH = "libans_ext.z.so";

ExtensionWrapper::ExtensionWrapper() = default;
ExtensionWrapper::~ExtensionWrapper() = default;

void ExtensionWrapper::InitExtentionWrapper()
{
    extensionWrapperHandle_ = dlopen(EXTENTION_WRAPPER_PATH.c_str(), RTLD_NOW);
    if (extensionWrapperHandle_ == nullptr) {
        ANS_LOGE("extension wrapper symbol failed, error: %{public}s", dlerror());
        return;
    }

    syncAdditionConfig_ = (SYNC_ADDITION_CONFIG)dlsym(extensionWrapperHandle_, "SyncAdditionConfig");
    getUnifiedGroupInfo_ = (GET_UNIFIED_GROUP_INFO)dlsym(extensionWrapperHandle_, "GetUnifiedGroupInfo");
    updateByCancel_ = (UPDATE_BY_CANCEL)dlsym(extensionWrapperHandle_, "UpdateByCancel");
    if (syncAdditionConfig_ == nullptr || getUnifiedGroupInfo_ == nullptr || updateByCancel_ == nullptr) {
        ANS_LOGE("extension wrapper symbol failed, error: %{public}s", dlerror());
        return;
    }
    ANS_LOGD("extension wrapper init success");
}

void ExtensionWrapper::SyncAdditionConfig(const std::string& key, const std::string& value)
{
    if (syncAdditionConfig_ == nullptr) {
        ANS_LOGE("syncAdditionConfig wrapper symbol failed");
        return;
    }
    syncAdditionConfig_(key, value);
}

void ExtensionWrapper::UpdateByCancel(std::vector<std::string>& hashCodes)
{
    if (updateByCancel_ == nullptr) {
        ANS_LOGE("updateUnifiedGroupByCancel wrapper symbol failed");
        return;
    }
    updateByCancel_(hashCodes);
}

ErrCode ExtensionWrapper::GetUnifiedGroupInfo(const sptr<NotificationRequest> &request)
{
    if (getUnifiedGroupInfo_ == nullptr) {
        ANS_LOGE("getUnifiedGroupInfo wrapper symbol failed");
        return 0;
    }
    return getUnifiedGroupInfo_(request);
}
} // namespace OHOS::Notification