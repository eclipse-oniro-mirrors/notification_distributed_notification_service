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
#include "message_parcel.h"
#include "os_account_manager.h"
#include "singleton.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Notification {
namespace {
constexpr const char *SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
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
    return DataShare::DataShareHelper::Creator(remoteObj, SETTINGS_DATA_EXT_URI);
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
    settingHelper->Release();
}

void AdvancedDatashareObserver::RegisterSettingsObserver(
    const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    ANS_LOGI("fengyunfei AdvancedDatashareObserver::RegisterSettingsObserver enter");
    std::shared_ptr<DataShare::DataShareHelper> settingHelper = CreateDataShareHelper();
    if (settingHelper == nullptr) {
        ANS_LOGE("Register settings observer by nullptr");
        return;
    }
    settingHelper->RegisterObserver(uri, dataObserver);
    settingHelper->Release();
}

void AdvancedDatashareObserver::NotifyChange(const Uri &uri)
{
    std::shared_ptr<DataShare::DataShareHelper> settingHelper = CreateDataShareHelper();
    if (settingHelper == nullptr) {
        ANS_LOGE("notify settings changed fail by nullptr");
        return;
    }
    settingHelper->NotifyChange(uri);
    settingHelper->Release();
}

} // namespace Notification
} // namespace OHOS