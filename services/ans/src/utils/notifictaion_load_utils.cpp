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

#include "notifictaion_load_utils.h"

#include <dlfcn.h>
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {

NotificationLoadUtils::NotificationLoadUtils(const std::string& path) : path_(path)
{
    proxyHandle_ = dlopen(path_.c_str(), RTLD_NOW);
    if (proxyHandle_ == nullptr) {
        ANS_LOGE("Open symbol failed %{public}s, error: %{public}s", path_.c_str(), dlerror());
    }
    ANS_LOGI("Open symbol name: %{public}s", path_.c_str());
}

NotificationLoadUtils::~NotificationLoadUtils()
{
    if (proxyHandle_ == nullptr) {
        return;
    }
    int result = dlclose(proxyHandle_);
    ANS_LOGI("Release symbol %{public}d, name: %{public}s", result, path_.c_str());
    proxyHandle_ = nullptr;
}

void* NotificationLoadUtils::GetProxyFunc(const std::string& func)
{
    if (proxyHandle_ == nullptr) {
        ANS_LOGW("Get func failed: %{public}s %{public}s", path_.c_str(), func.c_str());
        return nullptr;
    }

    return dlsym(proxyHandle_, func.c_str());
}

bool NotificationLoadUtils::IsValid()
{
    return (proxyHandle_ != nullptr);
}

}
}
