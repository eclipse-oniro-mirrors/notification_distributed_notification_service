/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef NOTIFICATION_ADVANCED_DATASHAER_HELPER_H
#define NOTIFICATION_ADVANCED_DATASHAER_HELPER_H

#include "datashare_helper.h"
#include "iremote_broker.h"
#include "singleton.h"
#include "system_ability_definition.h"
#include "uri.h"

namespace OHOS {
namespace Notification {
namespace {
constexpr const char *KEY_FOCUS_MODE_ENABLE = "focus_mode_enable";
constexpr const char *KEY_FOCUS_MODE_PROFILE = "focus_mode_profile";
} // namespace

class AdvancedDatashareHelper : DelayedSingleton<AdvancedDatashareHelper> {
public:
    AdvancedDatashareHelper();
    ~AdvancedDatashareHelper() = default;
    bool Query(Uri &uri, const std::string &key, std::string &value);
    std::string GetFocusModeEnableUri() const;
    std::string GetFocusModeProfileUri() const;
    std::string GetUnifiedGroupEnableUri() const;

private:
    void CreateDataShareHelper();
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper_ = nullptr;
};
} // namespace Notification
} // namespace OHOS
#endif // NOTIFICATION_ADVANCED_DATASHAER_HELPER_H
