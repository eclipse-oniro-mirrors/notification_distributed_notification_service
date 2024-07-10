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
#include "common_event_manager.h"
#include "common_event_support.h"
 
#include "common_event_subscriber.h"
#include "system_event_observer.h"
#include "interface_system_event.h"
#include "system_event_subscriber.h"

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

void UpdateUnifiedGroupInfo(const std::string &key, std::shared_ptr<NotificationUnifiedGroupInfo> &groupInfo)
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
    localControl_ = (LOCAL_CONTROL)dlsym(extensionWrapperHandle_, "LocalControl");
    reminderControl_ = (REMINDER_CONTROL)dlsym(extensionWrapperHandle_, "ReminderControl");
    if (syncAdditionConfig_ == nullptr
        || getUnifiedGroupInfo_ == nullptr
        || updateByCancel_ == nullptr
        || initSummary_ == nullptr
        || localControl_ == nullptr
        || reminderControl_ == nullptr
        || updateByBundle_ == nullptr) {
        ANS_LOGE("extension wrapper symbol failed, error: %{public}s", dlerror());
        return;
    }

    std::string ctrlConfig = NotificationPreferences::GetInstance().GetAdditionalConfig("NOTIFICATION_CTL_LIST_PKG");
    if (!ctrlConfig.empty()) {
        syncAdditionConfig_("NOTIFICATION_CTL_LIST_PKG", ctrlConfig);
    }

    std::string aggregateConfig = NotificationPreferences::GetInstance().GetAdditionalConfig("AGGREGATE_CONFIG");
    if (!aggregateConfig.empty()) {
        syncAdditionConfig_("AGGREGATE_CONFIG", aggregateConfig);
    }
    initSummary_(UpdateUnifiedGroupInfo);
    ANS_LOGD("extension wrapper init success");
}

void ExtensionWrapper::CheckIfSetlocalSwitch()
{
    ANS_LOGD("CheckIfSetlocalSwitch enter");
    if (extensionWrapperHandle_ == nullptr) {
        ANS_LOGE("CheckIfSetlocalSwitch extension wrapper symbol failed");
    }
    if (!isRegisterDataSettingObserver) {
        RegisterDataSettingObserver();
        isRegisterDataSettingObserver = true;
    }
    std::string enable = "";
    AdvancedNotificationService::GetInstance()->GetUnifiedGroupInfoFromDb(enable);
    SetlocalSwitch(enable);
}

void ExtensionWrapper::SetlocalSwitch(std::string &enable)
{
    if (setLocalSwitch_ == nullptr) {
        ANS_LOGE("SetlocalSwitch wrapper symbol failed");
        return;
    }
    bool status = (enable == "false" ? false : true);
    setLocalSwitch_(status);
}

void ExtensionWrapper::RegisterDataSettingObserver()
{
    ANS_LOGD("ExtensionWrapper::RegisterDataSettingObserver enter");
    sptr<AdvancedAggregationDataRoamingObserver> aggregationRoamingObserver_;
    if (aggregationRoamingObserver_ == nullptr) {
        aggregationRoamingObserver_ = new (std::nothrow) AdvancedAggregationDataRoamingObserver();
    }

    if (aggregationRoamingObserver_ == nullptr) {
        return;
    }
    
    Uri dataEnableUri(SETTINGS_DATA_UNIFIED_GROUP_ENABLE_URI);
    AdvancedDatashareObserver::GetInstance().RegisterSettingsObserver(dataEnableUri, aggregationRoamingObserver_);
}

ErrCode ExtensionWrapper::SyncAdditionConfig(const std::string& key, const std::string& value)
{
    if (syncAdditionConfig_ == nullptr) {
        ANS_LOGE("syncAdditionConfig wrapper symbol failed");
        return 0;
    }
    return syncAdditionConfig_(key, value);
}

void ExtensionWrapper::UpdateByCancel(const std::vector<sptr<Notification>>& notifications, int deleteReason)
{
    if (updateByCancel_ == nullptr) {
        ANS_LOGE("updateUnifiedGroupByCancel wrapper symbol failed");
        return;
    }
    int32_t deleteType = convertToDelType(deleteReason);
    updateByCancel_(notifications, deleteType);
}

ErrCode ExtensionWrapper::GetUnifiedGroupInfo(const sptr<NotificationRequest> &request)
{
    if (getUnifiedGroupInfo_ == nullptr) {
        ANS_LOGE("getUnifiedGroupInfo wrapper symbol failed");
        return 0;
    }
    return getUnifiedGroupInfo_(request);
}

int32_t ExtensionWrapper::LocalControl(const sptr<NotificationRequest> &request)
{
    if (localControl_ == nullptr) {
        ANS_LOGE("LocalControl wrapper symbol failed");
        return 0;
    }
    return localControl_(request);
}

void ExtensionWrapper::UpdateByBundle(const std::string bundleName, int deleteReason)
{
    if(updateByBundle_ == nullptr) {
        ANS_LOGE("UpdateByBundle wrapper symbol failed");
        return;
    }
    int32_t deleteType = convertToDelType(deleteReason);
    updateByBundle_(bundleName, deleteType);
}

int32_t ExtensionWrapper::ReminderControl(const std::string &bundleName)
{
    if (reminderControl_ == nullptr) {
        ANS_LOGE("ReminderControl wrapper symbol failed");
        return 0;
    }
    return reminderControl_(bundleName);
}

int32_t ExtensionWrapper::convertToDelType(int32_t deleteReason)
{
    int32_t delType = ACTIVE_DELETE;
    switch (deleteReason) {
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
