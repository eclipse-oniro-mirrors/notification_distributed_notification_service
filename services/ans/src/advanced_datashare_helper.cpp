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

#include "advanced_datashare_helper.h"

#include "ans_log_wrapper.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "message_parcel.h"
#include "os_account_manager.h"
#include "singleton.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Notification {
namespace {
constexpr const char *SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
constexpr const char *SETTINGS_DATASHARE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
constexpr const char *USER_SETTINGS_DATA_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_";
constexpr const char *USER_SETTINGS_DATA_SECURE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_";
constexpr const char *FOCUS_MODE_ENABLE_URI = "?Proxy=true&key=focus_mode_enable";
constexpr const char *FOCUS_MODE_PROFILE_URI = "?Proxy=true&key=focus_mode_profile";
constexpr const char *UNIFIED_GROUP_ENABLE_URI = "?Proxy=true&key=unified_group_enable";
constexpr const char *ADVANCED_DATA_COLUMN_KEYWORD = "KEYWORD";
constexpr const char *ADVANCED_DATA_COLUMN_VALUE = "VALUE";
} // namespace
AdvancedDatashareHelper::AdvancedDatashareHelper()
{
    CreateDataShareHelper();
}

std::shared_ptr<DataShare::DataShareHelper> AdvancedDatashareHelper::CreateDataShareHelper()
{
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        ANS_LOGE("The sa manager is nullptr.");
        return nullptr;
    }
    sptr<IRemoteObject> remoteObj = saManager->GetSystemAbility(ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID);
    if (remoteObj == nullptr) {
        ANS_LOGE("The remoteObj is nullptr.");
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObj, SETTINGS_DATASHARE_URI, SETTINGS_DATA_EXT_URI);
}

bool AdvancedDatashareHelper::Query(Uri &uri, const std::string &key, std::string &value)
{
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper();
    if (dataShareHelper == nullptr) {
        ANS_LOGE("The data share helper is nullptr.");
        return false;
    }
    DataShare::DataSharePredicates predicates;
    std::vector<std::string> columns;
    predicates.EqualTo(ADVANCED_DATA_COLUMN_KEYWORD, key);
    auto result = dataShareHelper->Query(uri, predicates, columns);
    if (result == nullptr) {
        ANS_LOGE("Query error, result is null.");
        dataShareHelper->Release();
        return false;
    }
    if (result->GoToFirstRow() != DataShare::E_OK) {
        ANS_LOGE("Query failed, go to first row error.");
        result->Close();
        dataShareHelper->Release();
        return false;
    }
    int32_t columnIndex;
    result->GetColumnIndex(ADVANCED_DATA_COLUMN_VALUE, columnIndex);
    result->GetString(columnIndex, value);
    result->Close();
    ANS_LOGD("Query success, value[%{public}s]", value.c_str());
    dataShareHelper->Release();
    return true;
}

std::string AdvancedDatashareHelper::GetFocusModeEnableUri() const
{
    std::vector<int32_t> accountIds;
    OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(accountIds);
    std::string userId = "100";
    if (!accountIds.empty()) {
        userId = std::to_string(accountIds[0]);
    }
    return USER_SETTINGS_DATA_URI + userId + FOCUS_MODE_ENABLE_URI;
}

std::string AdvancedDatashareHelper::GetFocusModeProfileUri() const
{
    std::vector<int32_t> accountIds;
    OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(accountIds);
    std::string userId = "100";
    if (!accountIds.empty()) {
        userId = std::to_string(accountIds[0]);
    }
    return USER_SETTINGS_DATA_URI + userId + FOCUS_MODE_PROFILE_URI;
}
std::string AdvancedDatashareHelper::GetUnifiedGroupEnableUri() const
{
    std::vector<int32_t> accountIds;
    OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(accountIds);
    std::string userId = "100";
    if (!accountIds.empty()) {
        userId = std::to_string(accountIds[0]);
    }
    return USER_SETTINGS_DATA_SECURE_URI + userId + UNIFIED_GROUP_ENABLE_URI;
}
} // namespace Notification
} // namespace OHOS
