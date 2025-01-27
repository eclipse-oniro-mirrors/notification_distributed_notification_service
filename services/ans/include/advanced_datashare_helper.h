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
constexpr const char *KEY_FOCUS_MODE_CALL_MESSAGE_POLICY = "focus_mode_call_message_policy";
constexpr const char *KEY_FOCUS_MODE_REPEAT_CALLERS_ENABLE = "focus_mode_repeate_callers_enable";
constexpr const char *KEY_INTELLIGENT_SCENE_DATA = "intelligent_scene_data";
constexpr const char *KEY_INTELLIGENT_URI = "intelligent_uri";
} // namespace

class AdvancedDatashareHelper : DelayedSingleton<AdvancedDatashareHelper> {
public:
    AdvancedDatashareHelper();
    ~AdvancedDatashareHelper() = default;
    bool Query(Uri &uri, const std::string &key, std::string &value);
    bool isRepeatCall(const std::string &phoneNumber);
    ErrCode QueryContact(Uri &uri, const std::string &phoneNumber,
        const std::string &policy, const std::string &profileId, const std::string isSupportIntelligentScene);
    std::string GetFocusModeEnableUri(const int32_t &userId) const;
    std::string GetFocusModeProfileUri(const int32_t &userId) const;
    std::string GetFocusModeCallPolicyUri(const int32_t &userId) const;
    std::string GetFocusModeRepeatCallUri(const int32_t &userId) const;
    std::string GetIntelligentUri();
    std::string GetUnifiedGroupEnableUri() const;

private:
    enum ContactPolicy {
        ALLOW_FAVORITE_CONTACTS = 4,
        ALLOW_SPECIFIED_CONTACTS = 5,
        FORBID_SPECIFIED_CONTACTS = 6,
    };
    std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper();
    std::shared_ptr<DataShare::DataShareHelper> CreateContactDataShareHelper(std::string uri);
    std::shared_ptr<DataShare::DataShareHelper> CreateIntelligentDataShareHelper(std::string uri);
    std::shared_ptr<DataShare::DataShareResultSet> GetContactResultSet(Uri &uri, const std::string &phoneNumber,
        const std::string &policy, const std::string &profileId, const std::string isSupportIntelligentScene);
    bool dealWithContactResult(std::shared_ptr<DataShare::DataShareResultSet> resultSet, const std::string &policy);
    std::string GetIntelligentData(const std::string &uri, const std::string &key);
};
} // namespace Notification
} // namespace OHOS
#endif // NOTIFICATION_ADVANCED_DATASHAER_HELPER_H
