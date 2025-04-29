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

#ifndef NOTIFICATION_ADVANCED_DATASHAER_HELPER_EXT_H
#define NOTIFICATION_ADVANCED_DATASHAER_HELPER_EXT_H

#include "datashare_helper.h"
#include "iremote_broker.h"
#include "singleton.h"
#include "system_ability_definition.h"
#include "uri.h"

namespace OHOS {
namespace Notification {
namespace {
constexpr const char *KEY_FOCUS_MODE_ENABLE_EXT = "focus_mode_enable";
constexpr const char *KEY_FOCUS_MODE_PROFILE_EXT = "focus_mode_profile";
constexpr const char *KEY_FOCUS_MODE_CALL_MESSAGE_POLICY_EXT = "focus_mode_call_message_policy";
} // namespace

class AdvancedDatashareHelperExt : DelayedSingleton<AdvancedDatashareHelperExt> {
public:
    AdvancedDatashareHelperExt();
    ~AdvancedDatashareHelperExt() = default;
    bool Query(Uri &uri, const std::string &key, std::string &value);
    std::string GetUnifiedGroupEnableUri() const;

private:
    std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper();
};
} // namespace Notification
} // namespace OHOS
#endif // NOTIFICATION_ADVANCED_DATASHAER_HELPER_EXT_H
