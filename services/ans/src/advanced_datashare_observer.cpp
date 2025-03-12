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

#include "advanced_datashare_observer.h"

#include "ans_log_wrapper.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Notification {
namespace {
constexpr const char *SETTING_URI_PROXY =
        "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
constexpr const char *SETTINGS_DATASHARE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_100?Proxy=true";
constexpr const char *SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
constexpr const int32_t E_OK = 0;
constexpr const int32_t E_DATA_SHARE_NOT_READY = 1055;
} // namespace

AdvancedDatashareObserver::AdvancedDatashareObserver() = default;
AdvancedDatashareObserver::~AdvancedDatashareObserver() = default;

std::shared_ptr<DataShare::DataShareHelper> AdvancedDatashareObserver::CreateDataShareHelper()
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

void AdvancedDatashareObserver::UnRegisterSettingsObserver(
    const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    std::shared_ptr<DataShare::DataShareHelper> settingHelper = CreateDataShareHelper();
    if (settingHelper == nullptr) {
        ANS_LOGE("UnRegister settings observer failed by nullptr");
        return;
    }
    settingHelper->UnregisterObserver(uri, dataObserver);
}

void AdvancedDatashareObserver::RegisterSettingsObserver(
    const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    ANS_LOGD("AdvancedDatashareObserver::RegisterSettingsObserver enter");
    std::shared_ptr<DataShare::DataShareHelper> settingHelper = CreateDataShareHelper();
    if (settingHelper == nullptr) {
        ANS_LOGE("Register settings observer by nullptr");
        return;
    }
    settingHelper->RegisterObserver(uri, dataObserver);
    settingHelper->Release();
}

bool AdvancedDatashareObserver::CheckIfSettingsDataReady()
{
    if (isDataShareReady_) {
        return true;
    }
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        ANS_LOGE("The sa manager is nullptr.");
        return false;
    }
    sptr<IRemoteObject> remoteObj = saManager->GetSystemAbility(ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID);
    if (remoteObj == nullptr) {
        ANS_LOGE("The remoteObj is nullptr.");
        return false;
    }
    std::pair<int, std::shared_ptr<DataShare::DataShareHelper>> ret =
        DataShare::DataShareHelper::Create(remoteObj, SETTING_URI_PROXY, SETTINGS_DATA_EXT_URI);
    ANS_LOGI("create data_share helper, ret=%{public}d", ret.first);
    if (ret.first == E_OK) {
        ANS_LOGI("create data_share helper success");
        auto helper = ret.second;
        if (helper != nullptr) {
            bool releaseRet = helper->Release();
            ANS_LOGI("release data_share helper, releaseRet=%{public}d", releaseRet);
        }
        isDataShareReady_ = true;
        return true;
    } else if (ret.first == E_DATA_SHARE_NOT_READY) {
        isDataShareReady_ = false;
        return false;
    }
    ANS_LOGI("data_share unknown.");
    return true;
}

} // namespace Notification
} // namespace OHOS
