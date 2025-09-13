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

#ifndef SYMBOL_EXPORT
#define SYMBOL_EXPORT __attribute__ ((visibility("default")))
#endif

namespace OHOS::Notification {
const std::string EXTENTION_WRAPPER_PATH = "libans_ext.z.so";
const int32_t ACTIVE_DELETE = 0;
const int32_t PASSITIVE_DELETE = 1;
static constexpr const char *SETTINGS_DATA_UNIFIED_GROUP_ENABLE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/"
    "USER_SETTINGSDATA_SECURE_100?Proxy=true&key=unified_group_enable";
ExtensionWrapper::ExtensionWrapper()
{
    InitExtentionWrapper();
}
ExtensionWrapper::~ExtensionWrapper() = default;


#ifdef __cplusplus
extern "C" {
#endif

void UpdateUnifiedGroupInfo(const std::string &key, std::shared_ptr<NotificationUnifiedGroupInfo> &groupInfo)
{
    AdvancedNotificationService::GetInstance()->UpdateUnifiedGroupInfo(key, groupInfo);
}

#ifdef ENABLE_ANS_PRIVILEGED_MESSAGE_EXT_WRAPPER
SYMBOL_EXPORT void GetAdditionalConfig(const std::string &key, std::string &value)
{
    value = NotificationPreferences::GetInstance()->GetAdditionalConfig(key);
    ANS_LOGD("GetAdditionalConfig SYMBOL_EXPORT valiue %{public}s", value.c_str());
}

SYMBOL_EXPORT int32_t SetKvToDb(const std::string &key, const std::string &value, const int32_t &userId)
{
    return NotificationPreferences::GetInstance()->SetKvToDb(key, value, userId);
}

SYMBOL_EXPORT int32_t GetKvFromDb(const std::string &key, std::string &value, const int32_t &userId, int32_t& retCode)
{
    return NotificationPreferences::GetInstance()->GetKvFromDb(key, value, userId, retCode);
}

SYMBOL_EXPORT ErrCode GetNotificationSlotFlagsForBundle(const sptr<NotificationBundleOption> &bundleOption,
    uint32_t &slotFlags)
{
    return NotificationPreferences::GetInstance()->GetNotificationSlotFlagsForBundle(bundleOption, slotFlags);
}
#endif

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
    if (syncAdditionConfig_ == nullptr) {
        ANS_LOGE("extension wrapper symbol failed, error: %{public}s", dlerror());
        return;
    }
#ifdef ENABLE_ANS_ADDITIONAL_CONTROL
    localControl_ = (LOCAL_CONTROL)dlsym(extensionWrapperHandle_, "LocalControl");
    reminderControl_ = (REMINDER_CONTROL)dlsym(extensionWrapperHandle_, "ReminderControl");
    bannerControl_ = (BANNER_CONTROL)dlsym(extensionWrapperHandle_, "BannerControl");
    if (bannerControl_ == nullptr || localControl_ == nullptr || reminderControl_ == nullptr) {
        ANS_LOGE("extension wrapper symbol failed, error: %{public}s", dlerror());
        return;
    }

    std::string ctrlConfig = NotificationPreferences::GetInstance()->GetAdditionalConfig("NOTIFICATION_CTL_LIST_PKG");
    if (!ctrlConfig.empty()) {
        syncAdditionConfig_("NOTIFICATION_CTL_LIST_PKG", ctrlConfig);
    }
    subscribeControl_ = (SUBSCRIBE_CONTROL)dlsym(extensionWrapperHandle_, "SubscribeControl");
#endif
#ifdef ENABLE_ANS_PRIVILEGED_MESSAGE_EXT_WRAPPER
    isPrivilegeMessage_ = (IS_PRIVILEGE_MESSAGE)dlsym(extensionWrapperHandle_, "IsPrivilegeMessage");
    if (isPrivilegeMessage_ == nullptr) {
        ANS_LOGE("extension wrapper isPrivilegeMessage_ symbol failed, error: %{public}s", dlerror());
        return;
    }
    handlePrivilegeMessage_ = (HANDLE_PRIVILEGE_MESSAGE)dlsym(extensionWrapperHandle_, "HandlePrivilegeMessage");
    if (handlePrivilegeMessage_ == nullptr) {
        ANS_LOGE("extension wrapper handlePrivilegeMessage_ symbol failed, error: %{public}s", dlerror());
        return;
    }
    getPrivilegeDialogPopped_ = (GET_PRIVILEGE_DIALOG_POPPED)dlsym(extensionWrapperHandle_, "GetPrivilegeDialogPopped");
    if (getPrivilegeDialogPopped_ == nullptr) {
        ANS_LOGE("extension wrapper symbol failed, error: %{public}s", dlerror());
        return;
    }
    setDialogOpenSuccessTimeStamp_ =
        (SET_DIALOG_OPENSUCCESS_TIMESTAMP)dlsym(extensionWrapperHandle_, "SetDialogOpenSuccessTimeStamp");
    if (setDialogOpenSuccessTimeStamp_ == nullptr) {
        ANS_LOGE("extension wrapper symbol failed, error: %{public}s", dlerror());
        return;
    }
    
    setDialogOpenSuccessTimeInterval_ =
        (SET_DIALOG_OPENSUCCESS_TIMEINTERVAL)dlsym(extensionWrapperHandle_, "SetDialogOpenSuccessTimeInterval");
    if (setDialogOpenSuccessTimeInterval_ == nullptr) {
        ANS_LOGE("extension wrapper symbol failed, error: %{public}s", dlerror());
        return;
    }
#endif
#ifdef ENABLE_ANS_AGGREGATION
    std::string aggregateConfig = NotificationPreferences::GetInstance()->GetAdditionalConfig("AGGREGATE_CONFIG");
    if (!aggregateConfig.empty()) {
        syncAdditionConfig_("AGGREGATE_CONFIG", aggregateConfig);
    }
    if (initSummary_ != nullptr) {
        initSummary_(UpdateUnifiedGroupInfo);
    }
#endif
    notificationDialogControl_ = (NOTIFICATIONDIALOGCONTROL)dlsym(extensionWrapperHandle_, "NotificationDialogControl");
    if (notificationDialogControl_ == nullptr) {
        ANS_LOGE("extension wrapper symbol failed, error: %{public}s", dlerror());
        return;
    }
    verifyCloudCapability_ = (VERIFY_CLOUD_CAPABILITY)dlsym(extensionWrapperHandle_, "VerifyCloudCapability");
    if (verifyCloudCapability_ == nullptr) {
        ANS_LOGE("extension wrapper symbol failed, error: %{public}s", dlerror());
        return;
    }
    ANS_LOGI("extension wrapper init success");
}

void ExtensionWrapper::CheckIfSetlocalSwitch()
{
    ANS_LOGD("CheckIfSetlocalSwitch enter");
    if (extensionWrapperHandle_ == nullptr) {
        return;
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
        return;
    }
    bool status = (enable == "false" ? false : true);
    setLocalSwitch_(status);
}

void ExtensionWrapper::RegisterDataSettingObserver()
{
    ANS_LOGD("ExtensionWrapper::RegisterDataSettingObserver enter");
    sptr<AdvancedAggregationDataRoamingObserver> aggregationRoamingObserver;
    if (aggregationRoamingObserver == nullptr) {
        aggregationRoamingObserver = new (std::nothrow) AdvancedAggregationDataRoamingObserver();
    }

    if (aggregationRoamingObserver == nullptr) {
        return;
    }

    Uri dataEnableUri(SETTINGS_DATA_UNIFIED_GROUP_ENABLE_URI);
    AdvancedDatashareObserver::GetInstance().RegisterSettingsObserver(dataEnableUri, aggregationRoamingObserver);
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
        return;
    }
    int32_t deleteType = convertToDelType(deleteReason);
    updateByCancel_(notifications, deleteType);
}

ErrCode ExtensionWrapper::GetUnifiedGroupInfo(const sptr<NotificationRequest> &request)
{
    if (getUnifiedGroupInfo_ == nullptr) {
        return 0;
    }
    return getUnifiedGroupInfo_(request);
}

int32_t ExtensionWrapper::ReminderControl(const std::string &bundleName)
{
    if (reminderControl_ == nullptr) {
        ANS_LOGE("ReminderControl wrapper symbol failed");
        return 0;
    }
    return reminderControl_(bundleName);
}

int32_t ExtensionWrapper::BannerControl(const std::string &bundleName)
{
    if (bannerControl_ == nullptr) {
        ANS_LOGE("ReminderControl wrapper symbol failed");
        return -1;
    }
    return bannerControl_(bundleName);
}

bool ExtensionWrapper::IsSubscribeControl(const std::string &bundleName, NotificationConstant::SlotType slotType)
{
    if (subscribeControl_ == nullptr) {
        ANS_LOGE("SubscribeControl wrapper symbol failed");
        return false;
    }
    return subscribeControl_(bundleName, slotType);
}

int32_t ExtensionWrapper::VerifyCloudCapability(const int32_t &uid, const std::string &capability)
{
    if (verifyCloudCapability_ == nullptr) {
        ANS_LOGE("VerifyCloudCapability wrapper symbol failed");
        return -1;
    }
    return verifyCloudCapability_(uid, capability);
}


#ifdef ENABLE_ANS_PRIVILEGED_MESSAGE_EXT_WRAPPER
bool ExtensionWrapper::IsPrivilegeMessage(const sptr<NotificationRequest> &request)
{
    if (isPrivilegeMessage_ == nullptr) {
        ANS_LOGE("IsPrivilegeMessage wrapper symbol failed");
        return false;
    }
    return isPrivilegeMessage_(request);
}

void ExtensionWrapper::HandlePrivilegeMessage(const sptr<NotificationBundleOption>& bundleOption,
    const sptr<NotificationRequest> &request, bool isAgentController)
{
    if (handlePrivilegeMessage_ == nullptr) {
        ANS_LOGE("HandlePrivilegeMessage wrapper symbol failed");
        return;
    }
    return handlePrivilegeMessage_(bundleOption, request, isAgentController);
}

bool ExtensionWrapper::GetPrivilegeDialogPopped(const sptr<NotificationBundleOption>& bundleOption,
    const int32_t &userId)
{
    return false;
}

bool ExtensionWrapper::SetDialogOpenSuccessTimeStamp(const sptr<NotificationBundleOption>& bundleOption,
    const int32_t &userId)
{
    return true;
}

bool ExtensionWrapper::SetDialogOpenSuccessTimeInterval(const sptr<NotificationBundleOption>& bundleOption,
    const int32_t &userId)
{
    return true;
}
#endif

__attribute__((no_sanitize("cfi"))) int32_t ExtensionWrapper::LocalControl(const sptr<NotificationRequest> &request)
{
    if (localControl_ == nullptr) {
        ANS_LOGE("LocalControl wrapper symbol failed");
        return 0;
    }
    return localControl_(request);
}

void ExtensionWrapper::UpdateByBundle(const std::string bundleName, int deleteReason)
{
    if (updateByBundle_ == nullptr) {
        return;
    }
    int32_t deleteType = convertToDelType(deleteReason);
    updateByBundle_(bundleName, deleteType);
}

bool ExtensionWrapper::NotificationDialogControl()
{
    if (notificationDialogControl_ == nullptr) {
        ANS_LOGE("isSampleDevice_ is null");
        return true;
    }
    bool result = notificationDialogControl_();
    ANS_LOGI("result = %{public}d", result);
    return result;
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
