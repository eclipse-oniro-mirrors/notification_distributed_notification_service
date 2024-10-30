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

#include <dlfcn.h>
#include <string>

#include "advanced_notification_service.h"
#include "telephony_extension_wrapper.h"
#include "notification_preferences.h"

namespace OHOS::Notification {
const std::string EXTENTION_TELEPHONY_PATH = "libtelephony_cust_api.z.so";
TelExtensionWrapper::TelExtensionWrapper() = default;
TelExtensionWrapper::~TelExtensionWrapper() = default;

void TelExtensionWrapper::InitTelExtentionWrapper()
{
    telephonyCustHandle_ = dlopen(EXTENTION_TELEPHONY_PATH.c_str(), RTLD_NOW);
    if (telephonyCustHandle_ == nullptr) {
        ANS_LOGE("telephony extension wrapper symbol failed, error: %{public}s", dlerror());
        return;
    }

    getCallerIndex_ = (GET_CALLER_INDEX)dlsym(telephonyCustHandle_, "GetCallerNumIndex");
    if (getCallerIndex_ == nullptr) {
        ANS_LOGE("telephony extension wrapper getCallerIndex symbol failed, error: %{public}s", dlerror());
        return;
    }
    ANS_LOGI("telephony extension wrapper init success");
}

ErrCode TelExtensionWrapper::GetCallerIndex(
    std::shared_ptr<DataShare::DataShareResultSet> resultSet, std::string compNum)
{
    if (getCallerIndex_ == nullptr) {
        ANS_LOGE("GetCallerIndex wrapper symbol failed");
        return -1;
    }
    return getCallerIndex_(resultSet, compNum);
}

void TelExtensionWrapper::CloseTelExtentionWrapper()
{
    if (telephonyCustHandle_ != nullptr) {
        dlclose(telephonyCustHandle_);
        telephonyCustHandle_ = nullptr;
    }
}
} // namespace OHOS::Notification