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

#include "ans_const_define.h"
#include "ans_log_wrapper.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "message_parcel.h"
#include "os_account_manager.h"
#include "singleton.h"
#include "system_ability_definition.h"
#include "ipc_skeleton.h"
#include "telephony_extension_wrapper.h"

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
constexpr const char *FOCUS_MODE_REPEAT_CALLERS_ENABLE_URI = "?Proxy=true&key=focus_mode_repeate_callers_enable";
constexpr const char *UNIFIED_GROUP_ENABLE_URI = "?Proxy=true&key=unified_group_enable";
constexpr const char *CONTACT_URI = "datashare:///com.ohos.contactsdataability";
constexpr const char *CALLLOG_URI = "datashare:///com.ohos.calllogability";
constexpr const char *CALL_SUBSECTION = "datashare:///com.ohos.calllogability/calls/calllog?Proxy=true";
constexpr const char *PHONE_NUMBER = "phone_number";
constexpr const char *IS_DELETED = "is_deleted";
constexpr const char *TYPE_ID = "type_id";
constexpr const char *DETAIL_INFO = "detail_info";
constexpr const char *FORMAT_PHONE_NUMBER = "format_phone_number";
constexpr const char *FAVORITE = "favorite";
constexpr const char *FOCUS_MODE_LIST = "focus_mode_list";
constexpr const char *ADVANCED_DATA_COLUMN_KEYWORD = "KEYWORD";
constexpr const char *ADVANCED_DATA_COLUMN_VALUE = "VALUE";
constexpr const char *CALL_DIRECTION = "call_direction";
constexpr const char *CREATE_TIME = "create_time";
constexpr const unsigned int PHONE_NUMBER_LENGTH = 7;
constexpr const unsigned int MAX_TIME_INTERVAL = 15 * 60;
constexpr const int TYPE_ID_FIVE = 5;
constexpr const int ERROR_QUERY_INFO_FAILED = -1;
constexpr const int QUERY_INFO_SUCCESS = 1;
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
    return DataShare::DataShareHelper::Creator(remoteObj, uri);
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

ErrCode AdvancedDatashareHelper::QueryContact(Uri &uri, const std::string &phoneNumber, const std::string &policy)
{
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    std::shared_ptr<DataShare::DataShareHelper> helper = CreateContactDataShareHelper(CONTACT_URI);
    if (helper == nullptr) {
        ANS_LOGE("The data share helper is nullptr.");
        return ERROR_QUERY_INFO_FAILED;
    }
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(IS_DELETED, 0);
    predicates.EqualTo(TYPE_ID, TYPE_ID_FIVE);
    if (phoneNumber.size() >= PHONE_NUMBER_LENGTH) {
        predicates.EndsWith(DETAIL_INFO,
            phoneNumber.substr(phoneNumber.size() - PHONE_NUMBER_LENGTH, phoneNumber.size()));
    } else {
        predicates.EqualTo(DETAIL_INFO, phoneNumber);
    }
    auto resultSet = helper->Query(uri, predicates, QUERY_CONTACT_COLUMN_LIST);
    IPCSkeleton::SetCallingIdentity(identity);
    if (resultSet == nullptr) {
        ANS_LOGE("Query error, resultSet is null.");
        helper->Release();
        return ERROR_QUERY_INFO_FAILED;
    }
    int isFound = 0;
    int rowCount = 0;
    resultSet->GetRowCount(rowCount);
    if (rowCount <= 0) {
        ANS_LOGI("Query success, but rowCount is 0.");
    } else {
        int resultId = -1;
#ifdef ENABLE_ANS_TELEPHONY_CUST_WRAPPER
        resultId = TEL_EXTENTION_WRAPPER->GetCallerIndex(resultSet, phoneNumber);
        ANS_LOGI("QueryContact resultId: %{public}d.", resultId);
#endif
        if ((phoneNumber.size() >= PHONE_NUMBER_LENGTH && resultSet->GoToRow(resultId) == DataShare::E_OK) ||
            (phoneNumber.size() < PHONE_NUMBER_LENGTH && resultSet->GoToFirstRow() == DataShare::E_OK)) {
            isFound = dealWithContactResult(helper, resultSet, policy) ? QUERY_INFO_SUCCESS : ERR_OK;
        }
    }
    resultSet->Close();
    helper->Release();
    return isFound;
}

bool AdvancedDatashareHelper::dealWithContactResult(std::shared_ptr<DataShare::DataShareHelper> helper,
    std::shared_ptr<DataShare::DataShareResultSet> resultSet, const std::string &policy)
{
    bool isNoNeedSilent = false;
    int32_t columnIndex;
    int32_t favorite;
    std::string focus_mode_list;
    switch (atoi(policy.c_str())) {
        case ContactPolicy::ALLOW_FAVORITE_CONTACTS:
            do {
                resultSet->GetColumnIndex(FAVORITE, columnIndex);
                resultSet->GetInt(columnIndex, favorite);
                isNoNeedSilent = favorite == 1;
                if (isNoNeedSilent) {
                    break;
                }
            } while (resultSet->GoToNextRow() == DataShare::E_OK);
            ANS_LOGI("dealWithContactResult: favorite = %{public}d", favorite);
            break;
        case ContactPolicy::ALLOW_SPECIFIED_CONTACTS:
            do {
                resultSet->GetColumnIndex(FOCUS_MODE_LIST, columnIndex);
                resultSet->GetString(columnIndex, focus_mode_list);
                if (focus_mode_list.empty() || focus_mode_list.c_str()[0] == '0') {
                    isNoNeedSilent = false;
                }
                if (focus_mode_list.c_str()[0] == '1') {
                    isNoNeedSilent = true;
                    break;
                }
            } while (resultSet->GoToNextRow() == DataShare::E_OK);
            ANS_LOGI("dealWithContactResult: focus_mode_list = %{public}s", focus_mode_list.c_str());
            break;
        default:
            isNoNeedSilent = true;
            break;
    }
    return isNoNeedSilent;
}

bool AdvancedDatashareHelper::isRepeatCall(const std::string &phoneNumber)
{
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    std::shared_ptr<DataShare::DataShareHelper> helper = CreateContactDataShareHelper(CALLLOG_URI);
    if (helper == nullptr) {
        ANS_LOGE("The data share helper is nullptr.");
        return false;
    }
    bool isRepeat = false;
    DataShare::DataSharePredicates predicates;
    std::vector<std::string> columns;
    Uri uri(CALL_SUBSECTION);
    predicates.EqualTo(PHONE_NUMBER, phoneNumber);
    predicates.EqualTo(CALL_DIRECTION, 0);
    predicates.OrderByDesc(CREATE_TIME);
    columns.push_back(CREATE_TIME);
    auto resultSet = helper->Query(uri, predicates, columns);
    IPCSkeleton::SetCallingIdentity(identity);
    if (resultSet == nullptr) {
        helper->Release();
        return false;
    }
    int rowCount = 0;
    resultSet->GetRowCount(rowCount);
    if (rowCount > 0) {
        int32_t callTime = 0;
        if (resultSet->GoToFirstRow() == 0) {
            int32_t columnIndex;
            resultSet->GetColumnIndex(CREATE_TIME, columnIndex);
            resultSet->GetInt(columnIndex, callTime);
        }
        if (time(NULL) - callTime < MAX_TIME_INTERVAL) {
            isRepeat = true;
        }
    }
    resultSet->Close();
    helper->Release();
    return isRepeat;
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

std::string AdvancedDatashareHelper::GetFocusModeRepeatCallUri(const int32_t &userId) const
{
    return USER_SETTINGS_DATA_URI + std::to_string(userId) + FOCUS_MODE_REPEAT_CALLERS_ENABLE_URI;
}
} // namespace Notification
} // namespace OHOS
