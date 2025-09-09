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
#include "os_account_manager_helper.h"
#include "singleton.h"
#include "system_ability_definition.h"
#include "ipc_skeleton.h"
#include "telephony_extension_wrapper.h"

namespace OHOS {
namespace Notification {
bool AdvancedDatashareHelper::isDataShareReady_ = false;
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
constexpr const char *INTELLIGENT_EXPERIENCE_URI = "?Proxy=true&key=intelligent_experience";
constexpr const char *FOCUS_MODE_CALL_POLICY_URI = "?Proxy=true&key=focus_mode_call_message_policy";
constexpr const char *FOCUS_MODE_REPEAT_CALLERS_ENABLE_URI = "?Proxy=true&key=focus_mode_repeate_callers_enable";
constexpr const char *UNIFIED_GROUP_ENABLE_URI = "?Proxy=true&key=unified_group_enable";
constexpr const char *INTELLIGENT_SCENE_DATA = "?Proxy=true&key=intelligent_scene_data";
constexpr const char *INTELLIGENT_URI = "?Proxy=true&key=intelligent_uri";
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
constexpr const char *MODE_ID = "modeId";
constexpr const char *ADVANCED_DATA_COLUMN_KEYWORD = "KEYWORD";
constexpr const char *ADVANCED_DATA_COLUMN_VALUE = "VALUE";
constexpr const char *CALL_DIRECTION = "call_direction";
constexpr const char *CREATE_TIME = "create_time";
constexpr const char *WHITE_LIST = "1";
constexpr const char *BLACK_LIST = "2";
constexpr const char *SUPPORT_INTEGELLIGENT_SCENE = "true";
constexpr const unsigned int PHONE_NUMBER_LENGTH = 7;
constexpr const unsigned int MAX_TIME_INTERVAL = 15 * 60;
constexpr const int TYPE_ID_FIVE = 5;
constexpr const int ERROR_QUERY_INFO_FAILED = -1;
constexpr const int QUERY_INFO_SUCCESS = 1;
std::vector<std::string> QUERY_CONTACT_COLUMN_LIST = {FORMAT_PHONE_NUMBER, FAVORITE, FOCUS_MODE_LIST, DETAIL_INFO};
std::vector<std::string> QUERY_INTELLIGENT_COLUMN_LIST = {FORMAT_PHONE_NUMBER, FOCUS_MODE_LIST, DETAIL_INFO};
} // namespace
AdvancedDatashareHelper::AdvancedDatashareHelper()
{
    CreateDataShareHelper();
}

std::shared_ptr<DataShare::DataShareHelper> AdvancedDatashareHelper::CreateDataShareHelper()
{
    if (!isDataShareReady_) {
        ANS_LOGE("dataShare is not ready");
        return nullptr;
    }
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

std::shared_ptr<DataShare::DataShareHelper> AdvancedDatashareHelper::CreateIntelligentDataShareHelper(std::string uri)
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
    auto [error, helper] = DataShare::DataShareHelper::Create(remoteObj, uri, GetIntelligentUri());
    if (error != DataShare::E_OK) {
        ANS_LOGE("Create Intelligent DataShareHelper failed.");
        return nullptr;
    }
    return helper;
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

ErrCode AdvancedDatashareHelper::QueryContact(Uri &uri, const std::string &phoneNumber, const std::string &policy,
    const std::string &profileId, const std::string isSupportIntelligentScene)
{
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    auto resultSet = GetContactResultSet(uri, phoneNumber, policy, profileId, isSupportIntelligentScene);
    IPCSkeleton::SetCallingIdentity(identity);
    if (resultSet == nullptr) {
        ANS_LOGE("QueryContact error, resultSet is null.");
        return ERROR_QUERY_INFO_FAILED;
    }
    int isFound = 0;
    int rowCount = 0;
    resultSet->GetRowCount(rowCount);
    if (rowCount <= 0) {
        ANS_LOGI("Query success, but rowCount is 0.");
        if (atoi(policy.c_str()) == ContactPolicy::FORBID_SPECIFIED_CONTACTS) {
            isFound = 1;
        }
    } else {
        int resultId = -1;
#ifdef ENABLE_ANS_TELEPHONY_CUST_WRAPPER
        resultId = TEL_EXTENTION_WRAPPER->GetCallerIndex(resultSet, phoneNumber);
        ANS_LOGI("QueryContact resultId: %{public}d.", resultId);
#endif
        if ((phoneNumber.size() >= PHONE_NUMBER_LENGTH && resultSet->GoToRow(resultId) == DataShare::E_OK) ||
            (phoneNumber.size() < PHONE_NUMBER_LENGTH && resultSet->GoToFirstRow() == DataShare::E_OK)) {
            isFound = dealWithContactResult(resultSet, policy) ? QUERY_INFO_SUCCESS : ERR_OK;
        }
    }
    resultSet->Close();
    return isFound;
}

std::shared_ptr<DataShare::DataShareResultSet> AdvancedDatashareHelper::GetContactResultSet(Uri &uri,
    const std::string &phoneNumber, const std::string &policy, const std::string &profileId,
    const std::string isSupportIntelligentScene)
{
    std::shared_ptr<DataShare::DataShareHelper> helper;
    std::shared_ptr<DataShare::DataShareResultSet> resultSet;
    if (isSupportIntelligentScene == SUPPORT_INTEGELLIGENT_SCENE &&
        (atoi(policy.c_str()) == ContactPolicy::ALLOW_SPECIFIED_CONTACTS ||
        atoi(policy.c_str()) == ContactPolicy::FORBID_SPECIFIED_CONTACTS)) {
        helper = CreateIntelligentDataShareHelper(GetIntelligentData(INTELLIGENT_URI, KEY_INTELLIGENT_URI));
        if (helper == nullptr) {
            ANS_LOGE("GetContactResultSet, The data share helper is nullptr.");
            return nullptr;
        }
        std::string focusModeList = atoi(policy.c_str()) == ContactPolicy::ALLOW_SPECIFIED_CONTACTS ?
            WHITE_LIST : BLACK_LIST;
        ANS_LOGI("GetContactResultSet, profileId: %{public}s, focusModeList: %{public}s",
            profileId.c_str(), focusModeList.c_str());
        DataShare::DataSharePredicates predicates;
        predicates.EqualTo(MODE_ID, profileId);
        predicates.EqualTo(FOCUS_MODE_LIST, focusModeList);
        if (phoneNumber.size() >= PHONE_NUMBER_LENGTH) {
            predicates.EndsWith(DETAIL_INFO,
                phoneNumber.substr(phoneNumber.size() - PHONE_NUMBER_LENGTH, phoneNumber.size()));
        } else {
            predicates.EqualTo(DETAIL_INFO, phoneNumber);
        }
        resultSet = helper->Query(uri, predicates, QUERY_INTELLIGENT_COLUMN_LIST);
    } else {
        helper = CreateContactDataShareHelper(CONTACT_URI);
        if (helper == nullptr) {
            ANS_LOGE("GetContactResultSet, The data share helper is nullptr.");
            return nullptr;
        }
        ANS_LOGE("GetContactResultSet, not support IntelligentScene.");
        DataShare::DataSharePredicates predicates;
        predicates.EqualTo(IS_DELETED, 0);
        predicates.EqualTo(TYPE_ID, TYPE_ID_FIVE);
        if (phoneNumber.size() >= PHONE_NUMBER_LENGTH) {
            predicates.EndsWith(DETAIL_INFO,
                phoneNumber.substr(phoneNumber.size() - PHONE_NUMBER_LENGTH, phoneNumber.size()));
        } else {
            predicates.EqualTo(DETAIL_INFO, phoneNumber);
        }
        resultSet = helper->Query(uri, predicates, QUERY_CONTACT_COLUMN_LIST);
    }
    helper->Release();
    return resultSet;
}

bool AdvancedDatashareHelper::dealWithContactResult(std::shared_ptr<DataShare::DataShareResultSet> resultSet,
    const std::string &policy)
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
        case ContactPolicy::FORBID_SPECIFIED_CONTACTS:
            {
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
                    if (focus_mode_list.c_str()[0] == '2') {
                        isNoNeedSilent = false;
                        break;
                    }
                } while (resultSet->GoToNextRow() == DataShare::E_OK);
                ANS_LOGI("dealWithContactResult: focus_mode_list = %{public}s", focus_mode_list.c_str());
                break;
            }
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
        IPCSkeleton::SetCallingIdentity(identity);
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

std::string AdvancedDatashareHelper::GetIntelligentExperienceUri(const int32_t &userId) const
{
    return USER_SETTINGS_DATA_SECURE_URI + std::to_string(userId) + INTELLIGENT_EXPERIENCE_URI;
}

std::string AdvancedDatashareHelper::GetFocusModeCallPolicyUri(const int32_t &userId) const
{
    return USER_SETTINGS_DATA_URI + std::to_string(userId) + FOCUS_MODE_CALL_POLICY_URI;
}

std::string AdvancedDatashareHelper::GetFocusModeRepeatCallUri(const int32_t &userId) const
{
    return USER_SETTINGS_DATA_URI + std::to_string(userId) + FOCUS_MODE_REPEAT_CALLERS_ENABLE_URI;
}

std::string AdvancedDatashareHelper::GetIntelligentData(const std::string &uri, const std::string &key)
{
    std::string value;
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGD("GetActiveUserId is false");
        return "";
    }

    Uri tempUri(USER_SETTINGS_DATA_SECURE_URI + std::to_string(userId) + uri);
    bool ret = Query(tempUri, key, value);
    if (!ret) {
        ANS_LOGE("Query Intelligent Data id fail.");
        return "";
    }
    return value + std::to_string(userId);
}

std::string AdvancedDatashareHelper::GetIntelligentUri()
{
    return GetIntelligentData(INTELLIGENT_SCENE_DATA, KEY_INTELLIGENT_SCENE_DATA);
}

void AdvancedDatashareHelper::SetIsDataShareReady(bool isDataShareReady)
{
    isDataShareReady_ = isDataShareReady;
}
} // namespace Notification
} // namespace OHOS
