/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "reminder_config_change_observer.h"

#include "ans_log_wrapper.h"
#include "reminder_data_manager.h"

namespace OHOS {
namespace Notification {

void ReminderConfigChangeObserver::OnConfigurationUpdated(const AppExecFwk::Configuration &configuration)
{
    ANSR_LOGD("called");
    auto reminderDataMgr = ReminderDataManager::GetInstance();
    if (reminderDataMgr == nullptr) {
        ANSR_LOGE("null reminderDataMgr");
        return;
    }
    std::string newLanguageInfo = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE);
    if (!newLanguageInfo.empty() && newLanguageInfo != languageInfo_) {
        ANSR_LOGD("language change: %{public}s -> %{public}s", languageInfo_.c_str(), newLanguageInfo.c_str());
        reminderDataMgr->OnLanguageChanged();
        languageInfo_ = newLanguageInfo;
    }
}

} // namespace Notification
} // namespace OHOS
