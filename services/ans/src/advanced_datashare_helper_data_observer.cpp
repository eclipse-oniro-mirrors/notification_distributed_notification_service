/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "advanced_datashare_helper_data_observer.h"

#include "advanced_datashare_helper.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
AdvancedDatashareHelperDataObserver::AdvancedDatashareHelperDataObserver(
    Uri uri, std::vector<std::string> keys): uri_(uri), keys_(keys)
{}

AdvancedDatashareHelperDataObserver::~AdvancedDatashareHelperDataObserver() = default;

void AdvancedDatashareHelperDataObserver::OnChange()
{
    ANS_LOGI("OnChange uri %{public}s", uri_.ToString().c_str());
    auto datashareHelper = DelayedSingleton<AdvancedDatashareHelper>::GetInstance();
    if (datashareHelper == nullptr) {
        ANS_LOGE("null datashareHelper");
        return;
    }
    for (std::string key : keys_) {
        std::string value;
        datashareHelper->QueryByDataShare(uri_, key, value);
    }
}

Uri AdvancedDatashareHelperDataObserver::GetUri()
{
    return uri_;
}
} // namespace Notification
} // namespace OHOS
