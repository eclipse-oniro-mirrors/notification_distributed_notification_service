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

#include "distributed_liveview_all_scenarios_extension_wrapper.h"

#include <dlfcn.h>
#include <string>

namespace OHOS::Notification {
const std::string DISTRIBUTED_EXTENTION_LIVEVIEW_ALL_SCENARIOS_PATH = "libnotification_all_scenarios.z.so";
DistributedLiveviewAllScenariosExtensionWrapper::DistributedLiveviewAllScenariosExtensionWrapper() = default;
DistributedLiveviewAllScenariosExtensionWrapper::~DistributedLiveviewAllScenariosExtensionWrapper() = default;

void DistributedLiveviewAllScenariosExtensionWrapper::InitExtentionWrapper()
{
    ExtensionHandle_ = dlopen(DISTRIBUTED_EXTENTION_LIVEVIEW_ALL_SCENARIOS_PATH.c_str(), RTLD_NOW);
    if (ExtensionHandle_ == nullptr) {
        ANS_LOGE("distributed liveview all scenarios extension wrapper dlopen failed, error: %{public}s", dlerror());
        return;
    }

    updateLiveviewEncodeContent_ = (UPDATE_LIVEVIEW_ENCODE_CONTENT)dlsym(ExtensionHandle_,
        "UpdateLiveviewEncodeContent");
    if (updateLiveviewEncodeContent_ == nullptr) {
        ANS_LOGE("distributed liveview all scenarios extension wrapper dlsym updateLiveviewEncodeContent_ failed, "
            "error: %{public}s", dlerror());
        return;
    }

    updateLiveviewDecodeContent_ = (UPDATE_LIVEVIEW_DECODE_CONTENT)dlsym(ExtensionHandle_,
        "UpdateLiveviewDecodeContent");
    if (updateLiveviewDecodeContent_ == nullptr) {
        ANS_LOGE("distributed liveview all scenarios extension wrapper dlsym updateLiveviewDecodeContent_ failed, "
            "error: %{public}s", dlerror());
        return;
    }

    ANS_LOGI("distributed liveview all scenarios extension wrapper init success");
}

void DistributedLiveviewAllScenariosExtensionWrapper::CloseExtentionWrapper()
{
    if (ExtensionHandle_ != nullptr) {
        dlclose(ExtensionHandle_);
        ExtensionHandle_ = nullptr;
    }
}

ErrCode DistributedLiveviewAllScenariosExtensionWrapper::UpdateLiveviewEncodeContent(
    const sptr<NotificationRequest> &request, std::vector<uint8_t> &buffer)
{
    if (updateLiveviewEncodeContent_ == nullptr) {
        ANS_LOGE("distributed UpdateLiveviewEncodeContent wrapper symbol failed");
        return 0;
    }
    return updateLiveviewEncodeContent_(request, buffer);
}

ErrCode DistributedLiveviewAllScenariosExtensionWrapper::UpdateLiveviewDecodeContent(
    const sptr<NotificationRequest> &request, std::vector<uint8_t> &buffer)
{
    if (updateLiveviewDecodeContent_ == nullptr) {
        ANS_LOGE("distributed UpdateLiveviewDecodeContent wrapper symbol failed");
        return 0;
    }
    return updateLiveviewDecodeContent_(request, buffer);
}
}