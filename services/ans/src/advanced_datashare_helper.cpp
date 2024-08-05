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
#include "ipc_skeleton.h"
#ifdef OHOS_BUILD_ENABLE_TELEPHONY_CUST
#include "tel_cust_manager.h"
#endif

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
constexpr const char *FOCUS_MODE_CALL_POLICY_URI = "?Proxy=true&key=focus_mode_call_message_policy";
constexpr const char *UNIFIED_GROUP_ENABLE_URI = "?Proxy=true&key=unified_group_enable";
constexpr const char *CONTACT_URI = "datashare:///com.ohos.contactsdataability";
constexpr const char *RAW_CONTACT_URI = "datashare:///com.ohos.contactsdataability/contacts/raw_contact";
constexpr const char *CONTACT_DATA = "datashare:///com.ohos.contactsdataability/contacts/contact_data";
constexpr const char *PHONE_NUMBER = "phone_number";
constexpr const char *IS_DELETED = "is_deleted";
constexpr const char *TYPE_ID = "type_id";
constexpr const char *DETAIL_INFO = "detail_info";
constexpr const char *FORMAT_PHONE_NUMBER = "format_phone_number";
constexpr const char *FAVORITE = "favorite";
constexpr const char *FOCUS_MODE_LIST = "focus_mode_list";
constexpr const char *ADVANCED_DATA_COLUMN_KEYWORD = "KEYWORD";
constexpr const char *ADVANCED_DATA_COLUMN_VALUE = "VALUE";
std::vector<std::string> QUERY_CONTACT_COLUMN_LIST = {FORMAT_PHONE_NUMBER, FAVORITE, FOCUS_MODE_LIST, DETAIL_INFO};
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

std::shared_ptr<DataShare::DataShareHelper> AdvancedDatashareHelper::CreateContactDataShareHelper(std::string uri)
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
    return DataShare::DataShareHelper::Creator(remoteObj, CONTACT_URI);
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

bool AdvancedDatashareHelper::QueryContact(Uri &uri, const std::string &phoneNumber, const std::string &policy)
{
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    std::shared_ptr<DataShare::DataShareHelper> helper = CreateContactDataShareHelper(CONTACT_DATA);
    if (helper == nullptr) {
        ANS_LOGE("The data share helper is nullptr.");
        return false;
    }
    DataShare::DataSharePredicates predicates;
    std::vector<std::string> columns;
    predicates.EqualTo(IS_DELETED, 0);
    predicates.EqualTo(TYPE_ID, 5);
    if (phoneNumber.size() >= 7) {
        predicates.EndsWith(DETAIL_INFO, phoneNumber.substr(phoneNumber.size() - 7, phoneNumber.size()));
    } else {
        predicates.EqualTo(DETAIL_INFO, phoneNumber);
    }
    auto resultSet = helper->Query(uri, predicates, QUERY_CONTACT_COLUMN_LIST);
    IPCSkeleton::SetCallingIdentity(identity);
    if (resultSet == nullptr) {
        ANS_LOGE("Query error, resultSet is null.");
        helper->Release();
        return false;
    }
    int rowCount = 0;
    resultSet->GetRowCount(rowCount);
    if (rowCount <= 0) {
        ANS_LOGE("Query failed failed");
        return false;
    } else {
        int resultId = -1;
        #ifdef OHOS_BUILD_ENABLE_TELEPHONY_CUST
        resultId = TelCustManager::GetInstance().GetCallerIndex(resultSet, phoneNumber);
        #endif
        if ((phoneNumber.size() >= 7 && resultSet->GoToRow(resultId) == DataShare::E_OK) ||
            (phoneNumber.size() < 7 && resultSet->GoToFirstRow() == DataShare::E_OK)) {
            return dealWithContactResult(helper, resultSet, policy);
        }
    }
    return false;
}

bool AdvancedDatashareHelper::dealWithContactResult(std::shared_ptr<DataShare::DataShareHelper> helper,
    std::shared_ptr<DataShare::DataShareResultSet> resultSet, const std::string &policy)
{
    bool isNeedSilent = false;
    int32_t columnIndex;
    int32_t favorite;
    std::string focus_mode_list;
    switch (atoi(policy.c_str())) {
        case ContactPolicy::ALLOW_FAVORITE_CONTACTS:
            resultSet->GetColumnIndex(FAVORITE, columnIndex);
            resultSet->GetInt(columnIndex, favorite);
            ANS_LOGI("dealWithContactResult: favorite = %{public}d", favorite);
            isNeedSilent = favorite == 1;
            break;
        case ContactPolicy::ALLOW_SPECIFIED_CONTACTS:
            resultSet->GetColumnIndex(FOCUS_MODE_LIST, columnIndex);
            resultSet->GetString(columnIndex, focus_mode_list);
            ANS_LOGI("dealWithContactResult: focus_mode_list = %{public}s", focus_mode_list.c_str());
            if (focus_mode_list.empty() || focus_mode_list.c_str()[0] == '0') {
                isNeedSilent = false;
                break;
            }
            if (focus_mode_list.c_str()[0] == '1') {
                isNeedSilent = true;
                break;
            }
            break;
        default:
            isNeedSilent = true;
            break;
    }
    resultSet->Close();
    helper->Release();
    return isNeedSilent;
}

std::string AdvancedDatashareHelper::GetFocusModeEnableUri(const int32_t &userId) const
{
    return USER_SETTINGS_DATA_SECURE_URI + std::to_string(userId) + FOCUS_MODE_ENABLE_URI;
}

std::string AdvancedDatashareHelper::GetFocusModeProfileUri(const int32_t &userId) const
{
    return USER_SETTINGS_DATA_SECURE_URI + std::to_string(userId) + FOCUS_MODE_PROFILE_URI;
}

std::string AdvancedDatashareHelper::GetFocusModeCallPolicyUri(const int32_t &userId) const
{
    return USER_SETTINGS_DATA_URI + std::to_string(userId) + FOCUS_MODE_CALL_POLICY_URI;
}
} // namespace Notification
} // namespace OHOS
