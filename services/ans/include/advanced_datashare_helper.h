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

#include <vector>

#include "advanced_datashare_helper_data_observer.h"
#include "datashare_helper.h"
#include "ffrt.h"
#include "iremote_broker.h"
#include "singleton.h"
#include "system_ability_definition.h"
#include "uri.h"

namespace OHOS {
namespace Notification {
namespace {
constexpr const char *KEY_FOCUS_MODE_ENABLE = "focus_mode_enable";
constexpr const char *KEY_FOCUS_MODE_PROFILE = "focus_mode_profile";
constexpr const char *KEY_INTELLIGENT_EXPERIENCE = "intelligent_experience";
constexpr const char *KEY_FOCUS_MODE_CALL_MESSAGE_POLICY = "focus_mode_call_message_policy";
constexpr const char *KEY_FOCUS_MODE_REPEAT_CALLERS_ENABLE = "focus_mode_repeate_callers_enable";
constexpr const char *KEY_INTELLIGENT_SCENE_DATA = "intelligent_scene_data";
constexpr const char *KEY_INTELLIGENT_URI = "intelligent_uri";
constexpr const char *KEY_FOCUS_MODE_SOUND_WHITE_LIST = "intelligent_scene_notification_white_list";
} // namespace

class AdvancedDatashareHelper : DelayedSingleton<AdvancedDatashareHelper> {
public:
    AdvancedDatashareHelper();
    ~AdvancedDatashareHelper();
    bool Query(Uri &uri, const std::string &key, std::string &value);
    bool isRepeatCall(const std::string &phoneNumber);
    ErrCode QueryContact(Uri &uri, const std::string &phoneNumber,
        const std::string &policy, const std::string &profileId, const std::string isSupportIntelligentScene);
    ErrCode QueryContact(Uri &uri, const std::string &phoneNumber,
        const std::string &policy, const std::string &profileId,
        const std::string isSupportIntelligentScene, const int32_t userId);
    std::string GetFocusModeEnableUri(const int32_t &userId) const;
    std::string GetFocusModeProfileUri(const int32_t &userId) const;
    std::string GetIntelligentExperienceUri(const int32_t &userId) const;
    std::string GetFocusModeCallPolicyUri(const int32_t &userId) const;
    std::string GetFocusModeRepeatCallUri(const int32_t &userId) const;
    std::string GetIntelligentUri();
    std::string GetIntelligentUri(const int32_t userId);
    std::string GetUnifiedGroupEnableUri() const;
    std::string GetNodistubrSoundWhiteListUri(const int32_t &userId) const;
    static void SetIsDataShareReady(bool isDataShareReady);
    bool QueryByDataShare(Uri &uri, const std::string &key, std::string &value);
    void OnUserSwitch(const int32_t userId);
    void Init();

    struct DatashareItem {
        Uri uri;
        std::string key;
        std::string value;
    };

private:
    enum ContactPolicy {
        ALLOW_FAVORITE_CONTACTS = 4,
        ALLOW_SPECIFIED_CONTACTS = 5,
        FORBID_SPECIFIED_CONTACTS = 6,
    };
    bool CreateDataShareHelper();
    std::shared_ptr<DataShare::DataShareHelper> CreateContactDataShareHelper(std::string uri);
    std::shared_ptr<DataShare::DataShareHelper> CreateIntelligentDataShareHelper(std::string uri);
    std::shared_ptr<DataShare::DataShareHelper> CreateIntelligentDataShareHelper(std::string uri, const int32_t userId);
    std::shared_ptr<DataShare::DataShareHelper> CreateIntelligentDataShareHelperInner(
        std::string uri, int32_t userId = -1);
    std::shared_ptr<DataShare::DataShareResultSet> GetContactResultSet(Uri &uri, const std::string &phoneNumber,
        const std::string &policy, const std::string &profileId, const std::string isSupportIntelligentScene);
    std::shared_ptr<DataShare::DataShareResultSet> GetContactResultSet(Uri &uri, const std::string &phoneNumber,
        const std::string &policy, const std::string &profileId,
        const std::string isSupportIntelligentScene, const int32_t userId);
    std::shared_ptr<DataShare::DataShareResultSet> GetContactResultSetInner(Uri &uri, const std::string &phoneNumber,
        const std::string &policy, const std::string &profileId,
        const std::string isSupportIntelligentScene, int32_t userId = -1);
    bool dealWithContactResult(std::shared_ptr<DataShare::DataShareResultSet> resultSet, const std::string &policy);
    std::string GetIntelligentData(const std::string &uri, const std::string &key);
    std::string GetIntelligentData(const std::string &uri, const std::string &key, const int32_t userId);
    void SetPhoneNumQueryCondition(DataShare::DataSharePredicates &predicates, const std::string &phoneNumber);
    void RegisterObserver(const int32_t userId, const std::string &uri, const std::vector<std::string> &keys);
    void UnregisterObserver();
    void AddDataShareItems(Uri &uri, const std::string &key, const std::string &value);
    bool QuerydataShareItems(Uri &uri, const std::string &key, std::string &value);
    ErrCode QueryContactInner(Uri &uri, const std::string &phoneNumber,
        const std::string &policy, const std::string &profileId,
        const std::string isSupportIntelligentScene, int32_t userId = -1);
private:
    static bool isDataShareReady_;
    ffrt::mutex dataShareItemMutex_;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper_;
    std::vector<DatashareItem> dataShareItems_;
    std::vector<std::pair<int32_t, sptr<AdvancedDatashareHelperDataObserver>>> dataObservers_;
};
} // namespace Notification
} // namespace OHOS
#endif // NOTIFICATION_ADVANCED_DATASHAER_HELPER_H
