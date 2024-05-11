/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <dlfcn.h>
#include <string>

#include "advanced_notification_service.h"
#include "notification_extension_wrapper.h"
#include "notification_preferences.h"
#include "advanced_datashare_observer.h"

namespace OHOS::Notification {
const std::string EXTENTION_WRAPPER_PATH = "libans_ext.z.so";
const int32_t ACTIVE_DELETE = 0;
const int32_t PASSITIVE_DELETE = 1;
static constexpr const char *SETTINGS_DATA_UNIFIED_GROUP_ENABLE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/"
    "USER_SETTINGSDATA_SECURE_100?Proxy=true&key=unified_group_enable";
ExtensionWrapper::ExtensionWrapper() = default;
ExtensionWrapper::~ExtensionWrapper() = default;


#ifdef __cplusplus
extern "C" {
#endif

void UpdateUnifiedGroupInfo(std::string &key, std::shared_ptr<NotificationUnifiedGroupInfo> &groupInfo)
{
    AdvancedNotificationService::GetInstance()->UpdateUnifiedGroupInfo(key, groupInfo);
}

#ifdef __cplusplus
}
#endif

void ExtensionWrapper::InitExtentionWrapper()
{
    extensionWrapperHandle_ = dlopen(EXTENTION_WRAPPER_PATH.c_str(), RTLD_NOW);
    if (extensionWrapperHandle_ == nullptr) {
        ANS_LOGE("extension wrapper symbol failed, error: %{public}s", dlerror());
        return;
    }

    syncAdditionConfig_ = (SYNC_ADDITION_CONFIG)dlsym(extensionWrapperHandle_, "SyncAdditionConfig");
    getUnifiedGroupInfo_ = (GET_UNIFIED_GROUP_INFO)dlsym(extensionWrapperHandle_, "GetUnifiedGroupInfo");
    updateByCancel_ = (UPDATE_BY_CANCEL)dlsym(extensionWrapperHandle_, "UpdateByCancel");
    setLocalSwitch_ = (SET_LOCAL_SWITCH)dlsym(extensionWrapperHandle_, "SetlocalSwitch");
    initSummary_ = (INIT_SUMMARY)dlsym(extensionWrapperHandle_, "InitSummary");
    if (syncAdditionConfig_ == nullptr
        || getUnifiedGroupInfo_ == nullptr
        || updateByCancel_ == nullptr
        || initSummary_ == nullptr) {
        ANS_LOGE("extension wrapper symbol failed, error: %{public}s", dlerror());
        return;
    }
    RegisterDataSettingObserver();
    string enable = "";
    AdvancedNotificationService::GetInstance()->GetUnifiedGroupInfoFromDb(enable);
    SetlocalSwitch(enable);

    std::string configKey = NotificationPreferences::GetInstance().GetAdditionalConfig();
    if (!configKey.empty()) {
        syncAdditionConfig_("AGGREGATE_CONFIG", configKey);
    }
    initSummary_(UpdateUnifiedGroupInfo);
    ANS_LOGD("extension wrapper init success");
}

void ExtensionWrapper::SetlocalSwitch(std::string &enable)
{
    if (setLocalSwitch_ == nullptr) {
        ANS_LOGE("SetlocalSwitch wrapper symbol failed");
        return;
    }
    bool status = (enable == "true" ? true : false);
    setLocalSwitch_(status);
}

void ExtensionWrapper::RegisterDataSettingObserver()
{
    ANS_LOGI("fengyunfei ExtensionWrapper::RegisterDataSettingObserver enter");
    if (aggregationRoamingObserver_ == nullptr) {
        aggregationRoamingObserver_ = new (std::nothrow) AdvancedAggregationDataRoamingObserver();
    }

    if (aggregationRoamingObserver_ == nullptr) {
        ANS_LOGI("aggregationRoamingObserver_ is null");
        return;
    }
    
    Uri dataEnableUri(SETTINGS_DATA_UNIFIED_GROUP_ENABLE_URI);
    AdvancedDatashareObserver::GetInstance().RegisterSettingsObserver(dataEnableUri, aggregationRoamingObserver_);
}

void ExtensionWrapper::SyncAdditionConfig(const std::string& key, const std::string& value)
{
    if (syncAdditionConfig_ == nullptr) {
        ANS_LOGE("syncAdditionConfig wrapper symbol failed");
        return;
    }
    syncAdditionConfig_(key, value);
}

void ExtensionWrapper::UpdateByCancel(const std::vector<sptr<Notification>>& notifications, int deleteReason)
{
    if (updateByCancel_ == nullptr) {
        ANS_LOGE("updateUnifiedGroupByCancel wrapper symbol failed");
        return;
    }
    int32_t deleteType = convertToDelType(deleteReason);
    updateByCancel_(notifications, deleteReason);
}

ErrCode ExtensionWrapper::GetUnifiedGroupInfo(const sptr<NotificationRequest> &request)
{
    if (getUnifiedGroupInfo_ == nullptr) {
        ANS_LOGE("getUnifiedGroupInfo wrapper symbol failed");
        return 0;
    }
    return getUnifiedGroupInfo_(request);
}

int32_t ExtensionWrapper::convertToDelType(int32_t deleteReason)
{
    int32_t delType = ACTIVE_DELETE;
    switch (deleteReason) {
        case NotificationConstant::APP_CANCEL_ALL_REASON_DELETE:
        case NotificationConstant::PACKAGE_CHANGED_REASON_DELETE:
        case NotificationConstant::USER_REMOVED_REASON_DELETE:
        case NotificationConstant::DISABLE_SLOT_REASON_DELETE:
        case NotificationConstant::DISABLE_NOTIFICATION_REASON_DELETE:
            delType = PASSITIVE_DELETE;
            break;
        default:
            delType = ACTIVE_DELETE;
    }

    ANS_LOGD("convertToDelType from delete reason %d to delete type %d", deleteReason, delType);
    return delType;
}
} // namespace OHOS::Notification
