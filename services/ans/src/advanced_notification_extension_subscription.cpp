/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "access_token_helper.h"
#include "advanced_notification_service.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_permission_def.h"
#include "bluetooth_remote_device.h"
#include "bundle_manager_helper.h"
#include "errors.h"
#include "notification_config_parse.h"
#include "notification_preferences.h"
#include "os_account_manager_helper.h"
#include "parameters.h"

namespace OHOS {
namespace Notification {

using STARTUP = int32_t (*)();
using SHUTDOWN = void (*)();
using SUBSCRIBE = void (*)(const sptr<NotificationBundleOption>,
    const std::vector<sptr<NotificationBundleOption>> &);
using UNSUBSCRIBE = void (*)(const sptr<NotificationBundleOption>);
using GETSUBSCRIBECOUNT = size_t (*)();
namespace {
constexpr const char* ANS_EXTENSION_SERVICE_MODULE_NAME = "libans_extension_service.z.so";
}

bool AdvancedNotificationService::isExtensionServiceExist()
{
    return notificationExtensionLoaded_.load() && notificationExtensionHandler_ != nullptr
        && notificationExtensionHandler_->IsValid();
}

int32_t AdvancedNotificationService::LoadExtensionService()
{
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
    if (isExtensionServiceExist()) {
        return 0;
    }
    notificationExtensionHandler_ = std::make_shared<NotificationLoadUtils>(ANS_EXTENSION_SERVICE_MODULE_NAME);
    if (notificationExtensionHandler_ == nullptr) {
        ANS_LOGW("notificationExtensionHandle init failed.");
        return -1;
    }

    STARTUP startup = (STARTUP)notificationExtensionHandler_->GetProxyFunc("Startup");
    if (startup == nullptr) {
        ANS_LOGW("GetProxyFunc Startup init failed.");
        return -1;
    }
    if (startup() != 0) {
        notificationExtensionLoaded_.store(false);
        return -1;
    }
    notificationExtensionLoaded_.store(true);
    return 0;
#else
    return 0;
#endif
}

int32_t AdvancedNotificationService::SubscribeExtensionService(
    const sptr<NotificationBundleOption> &bundleOption,
    const std::vector<sptr<NotificationBundleOption>> &bundles)
{
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
    if (!isExtensionServiceExist()) {
        return -1;
    }

    SUBSCRIBE subscribe = (SUBSCRIBE)notificationExtensionHandler_->GetProxyFunc("Subscribe");
    if (subscribe == nullptr) {
        ANS_LOGW("GetProxyFunc Subscribe init failed.");
        return -1;
    }
    subscribe(bundleOption, bundles);
    return 0;
#else
    return 0;
#endif
}

int32_t AdvancedNotificationService::UnSubscribeExtensionService(const sptr<NotificationBundleOption> &bundleOption)
{
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
    if (!isExtensionServiceExist()) {
        return -1;
    }

    UNSUBSCRIBE unsubscribe = (UNSUBSCRIBE)notificationExtensionHandler_->GetProxyFunc("Unsubscribe");
    if (unsubscribe == nullptr) {
        ANS_LOGW("GetProxyFunc Unsubscribe init failed.");
        return -1;
    }
    unsubscribe(bundleOption);
    return 0;
#else
    return 0;
#endif
}

int32_t AdvancedNotificationService::ShutdownExtensionService()
{
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
    if (!isExtensionServiceExist()) {
        return -1;
    }

    SHUTDOWN shutdown = (SHUTDOWN)notificationExtensionHandler_->GetProxyFunc("Shutdown");
    if (shutdown == nullptr) {
        ANS_LOGW("GetProxyFunc Shutdown init failed.");
        return -1;
    }
    shutdown();
    return 0;
#else
    return 0;
#endif
}

size_t AdvancedNotificationService::GetSubscriberCount()
{
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
    if (!isExtensionServiceExist()) {
        return -1;
    }

    GETSUBSCRIBECOUNT getsubscribecount =
        (GETSUBSCRIBECOUNT)notificationExtensionHandler_->GetProxyFunc("GetSubscriberCount");
    if (getsubscribecount == nullptr) {
        ANS_LOGW("GetProxyFunc GetSubscriberCount init failed.");
        return -1;
    }
    return getsubscribecount();
#else
    return 0;
#endif
}

void AdvancedNotificationService::CheckExtensionServiceCondition(
    std::vector<std::pair<sptr<NotificationBundleOption>,
    std::vector<sptr<NotificationBundleOption>>>> &extensionBundleInfos,
    std::vector<sptr<NotificationBundleOption>> &bundles)
{
    extensionBundleInfos.clear();

    std::string isPCMode = OHOS::system::GetParameter("persist.sceneboard.ispcmode", "false");
    if (isPCMode == "true") {
        ANS_LOGW("PC Mode, skip loading ExtensionService");
        return;
    }

    bool hasPermission = false;
    for (const auto &bundle : bundles) {
        AppExecFwk::BundleInfo bundleInfo;
        int32_t userId = -1;
        OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundle->GetUid(), userId);
        int32_t flags = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
        if (!BundleManagerHelper::GetInstance()->GetBundleInfoV9(bundle->GetBundleName(), flags, bundleInfo, userId)) {
            ANS_LOGW("CheckExtensionServiceCondition GetBundleInfoV9 faild");
            continue;
        }
        if (AccessTokenHelper::VerifyCallerPermission(
            bundleInfo.applicationInfo.accessTokenId, OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
            hasPermission = true;
            break;
        }
    }

    if (!hasPermission) {
        ANS_LOGW("User has no permission, skip loading ExtensionService");
        return;
    }
    
    FilterGrantedBundles(bundles);
    if (bundles.empty()) {
        ANS_LOGW("No bundle is granted, skip loading ExtensionService");
        return;
    }
    FilterBundlesByBluetoothConnection(bundles);
    if (bundles.empty()) {
        ANS_LOGW("No valid bluetooth connections found, skip loading ExtensionService");
        return;
    }

    std::vector<sptr<NotificationBundleOption>> enableBundles;
    for (auto it = bundles.begin(); it != bundles.end(); ++it) {
        if (NotificationPreferences::GetInstance()->GetExtensionSubscriptionBundles(*it, enableBundles) == ERR_OK &&
            !enableBundles.empty()) {
            extensionBundleInfos.emplace_back(*it, enableBundles);
        }
    }
}

void AdvancedNotificationService::FilterGrantedBundles(std::vector<sptr<NotificationBundleOption>> &bundles)
{
    for (auto it = bundles.begin(); it != bundles.end();) {
        NotificationConstant::SWITCH_STATE state;
        if (NotificationPreferences::GetInstance()->GetExtensionSubscriptionEnabled(*it, state) == ERR_OK &&
            state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) {
            ++it;
        } else {
            it = bundles.erase(it);
        }
    }
}

void AdvancedNotificationService::FilterBundlesByBluetoothConnection(
    std::vector<sptr<NotificationBundleOption>> &bundles)
{
    for (auto it = bundles.begin(); it != bundles.end();) {
        std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
        ErrCode result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionInfos(*it, infos);
        if (result != ERR_OK || infos.empty()) {
            it = bundles.erase(it);
            continue;
        }
        bool hasValidConnection = CheckBluetoothConnectionInInfos(*it, infos);
        if (hasValidConnection) {
            ++it;
        } else {
            it = bundles.erase(it);
        }
    }
}

bool AdvancedNotificationService::CheckBluetoothConnectionInInfos(
    const sptr<NotificationBundleOption> &bundleOption,
    const std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos)
{
    for (const auto& info : infos) {
        if (info == nullptr) {
            continue;
        }
        std::string bluetoothAddress = info->GetAddr();
        if (bluetoothAddress.empty()) {
            continue;
        }
        if (supportHfp_) {
            if (CheckAndUpdateHfpDeviceStatus(bundleOption, info, infos, bluetoothAddress)) {
                return true;
            }
            if (info->IsHfp()) {
                continue;
            }
        }
        if (CheckBluetoothConditions(bluetoothAddress)) {
            return true;
        }
    }
    return false;
}

bool AdvancedNotificationService::CheckAndUpdateHfpDeviceStatus(
    const sptr<NotificationBundleOption> &bundleOption,
    const sptr<NotificationExtensionSubscriptionInfo> &info,
    const std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos,
    const std::string& bluetoothAddress)
{
    OHOS::Bluetooth::BluetoothRemoteDevice remoteDevice(bluetoothAddress, OHOS::Bluetooth::BT_TRANSPORT_NONE);
    int32_t btConnectState = static_cast<int32_t>(Bluetooth::BTConnectState::DISCONNECTED);
    int32_t ret = OHOS::Bluetooth::HandsFreeAudioGateway::GetProfile()->GetDeviceState(remoteDevice, btConnectState);
    if (ret == ERR_OK && btConnectState == static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTED)) {
        ANS_LOGI("Bluetooth HFP device connected: %{public}s", bluetoothAddress.c_str());
        info->SetHfp(true);
        ErrCode updateResult = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundleOption,
            infos);
        if (updateResult != ERR_OK) {
            ANS_LOGW("Failed to update HFP status to database for device: %{public}s", bluetoothAddress.c_str());
        }
        return true;
    }
    return false;
}

bool AdvancedNotificationService::CheckBluetoothConditions(const std::string& addr)
{
    bool result = false;
    std::shared_ptr<OHOS::Bluetooth::BluetoothRemoteDevice> remoteDevice =
        std::make_shared<OHOS::Bluetooth::BluetoothRemoteDevice>(addr, OHOS::Bluetooth::BT_TRANSPORT_NONE);
    int32_t state = OHOS::Bluetooth::PAIR_NONE;
    remoteDevice->GetPairState(state);
    if (state == OHOS::Bluetooth::PAIR_PAIRED) {
        result = true;
    } else {
        ANS_LOGW("Bluetooth device not paired: %{public}s, state: %{public}d", addr.c_str(), state);
    }
    return result;
}

bool AdvancedNotificationService::HasGrantedBundleStateChanged(
    const sptr<NotificationBundleOption>& bundle,
    const std::vector<sptr<NotificationBundleOption>>& enabledBundles)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    ErrCode result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionBundles(bundle, bundles);
    if (result != ERR_OK) {
        return true;
    }
    
    if (bundles.size() == 0) {
        return true;
    }
    
    if (bundles.size() != enabledBundles.size()) {
        return true;
    }
    
    for (size_t i = 0; i < bundles.size(); ++i) {
        if (bundles[i] == nullptr || enabledBundles[i] == nullptr) {
            return true;
        }
        if (bundles[i]->GetBundleName() != enabledBundles[i]->GetBundleName() ||
            bundles[i]->GetUid() != enabledBundles[i]->GetUid()) {
            return true;
        }
    }
    return false;
}

bool AdvancedNotificationService::HasExtensionSubscriptionStateChanged(
    const sptr<NotificationBundleOption> &bundle, bool enabled)
{
    if (bundle == nullptr) {
        return true;
    }
    
    NotificationConstant::SWITCH_STATE state;
    ErrCode result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionEnabled(bundle, state);
    if (result != ERR_OK) {
        return true;
    }
    
    bool oldEnabled = (state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    
    if (state == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF) {
        return true;
    }
    
    return (oldEnabled != enabled);
}

bool AdvancedNotificationService::HasExtensionSubscriptionInfosChanged(const sptr<NotificationBundleOption> &bundle,
    const std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos)
{
    if (bundle == nullptr) {
        return true;
    }

    std::vector<sptr<NotificationExtensionSubscriptionInfo>> oldInfos;
    ErrCode result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionInfos(bundle, oldInfos);
    if (result != ERR_OK) {
        return true;
    }

    if (oldInfos.size() == 0) {
        return true;
    }

    if (oldInfos.size() != infos.size()) {
        return true;
    }

    for (size_t i = 0; i < oldInfos.size(); ++i) {
        if (oldInfos[i] == nullptr || infos[i] == nullptr) {
            return true;
        }
        if (oldInfos[i]->GetAddr() != infos[i]->GetAddr() ||
            oldInfos[i]->GetType() != infos[i]->GetType() ||
            oldInfos[i]->IsHfp() != infos[i]->IsHfp()) {
            return true;
        }
    }
    return false;
}

bool AdvancedNotificationService::EnsureExtensionServiceLoadedAndSubscribed(
    const sptr<NotificationBundleOption> &bundle)
{
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
    std::vector<sptr<NotificationBundleOption>> subscribeBundles;
    if (NotificationPreferences::GetInstance()->GetExtensionSubscriptionBundles(bundle, subscribeBundles) != ERR_OK) {
        return false;
    }
    EnsureExtensionServiceLoadedAndSubscribed(bundle, subscribeBundles);
    return true;
#else
    return true;
#endif
}

bool AdvancedNotificationService::EnsureExtensionServiceLoadedAndSubscribed(
    const sptr<NotificationBundleOption> &bundle, const std::vector<sptr<NotificationBundleOption>> &subscribeBundles)
{
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
    std::vector<std::pair<sptr<NotificationBundleOption>,
        std::vector<sptr<NotificationBundleOption>>>> extensionBundleInfos;
    std::vector<sptr<NotificationBundleOption>> bundles{bundle};
    
    if (!isExtensionServiceExist()) {
        CheckExtensionServiceCondition(extensionBundleInfos, bundles);
        if (extensionBundleInfos.size() == 0) {
            ANS_LOGW("No extension bundle info found, skip subscribe.");
            return false;
        }
        if (LoadExtensionService() != 0) {
            return false;
        }
        if (SubscribeExtensionService(bundle, subscribeBundles) != 0) {
            return false;
        }
    } else {
        if (SubscribeExtensionService(bundle, subscribeBundles) != 0) {
            return false;
        }
    }
    return true;
#else
    return true;
#endif
}

bool AdvancedNotificationService::ShutdownExtensionServiceAndUnSubscribed(const sptr<NotificationBundleOption> &bundle)
{
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
    if (UnSubscribeExtensionService(bundle) != 0) {
        return false;
    }
    if (GetSubscriberCount() <= 0) {
        if (ShutdownExtensionService() != 0) {
            return false;
        }
        notificationExtensionHandler_.reset();
        notificationExtensionLoaded_.store(false);
    }
    return true;
#else
    return true;
#endif
}

void AdvancedNotificationService::HandleBundleInstall(const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("HandleBundleUpdate bundleOption is nullptr");
        return;
    }
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleOption->GetUid(), userId);
    if (!BundleManagerHelper::GetInstance()->
        CheckBundleImplExtensionAbility(bundleOption->GetBundleName(), userId)) {
        ShutdownExtensionServiceAndUnSubscribed(bundleOption);
        return;
    }
    
    std::vector<sptr<NotificationBundleOption>> insertBundles;
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        EnsureExtensionServiceLoadedAndSubscribed(bundleOption);
        std::vector<std::string> bundleNames;
        NotificationConfigParse::GetInstance()->GetNotificationExtensionEnabledBundlesWriteList(bundleNames);
        for (const auto& bundleName : bundleNames) {
            auto uid = BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(bundleName, userId);
            if (uid == -1) {
                continue;
            }
            sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundleName, uid);
            insertBundles.emplace_back(bundleOption);
        }
        
        result = NotificationPreferences::GetInstance()->AddExtensionSubscriptionBundles(bundleOption, insertBundles);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to set enabled bundles into database, ret: %{public}d", result);
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);
    std::vector<sptr<NotificationBundleOption>> bundles;
    GetNotificationExtensionEnabledBundles(bundles);
    if (cacheNotificationExtensionBundles_.size() != bundles.size()) {
        PublishExtensionServiceStateChange(NotificationConstant::EXTENSION_ABILITY_ADDED, bundleOption, false, {});
        cacheNotificationExtensionBundles_ = bundles;
    }
}

ErrCode AdvancedNotificationService::RefreshExtensionSubscriptionBundlesFromConfig(
    int32_t userId, const sptr<NotificationBundleOption>& bundleOption,
    std::vector<sptr<NotificationBundleOption>>& enabledBundles)
{
    ErrCode result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionBundles(
        bundleOption, enabledBundles);
    if (result != ERR_OK) {
        ANS_LOGE("Failed to get enabled bundles from database, ret: %{public}d", result);
        return result;
    }

    std::vector<std::string> bundleNames;
    NotificationConfigParse::GetInstance()->GetNotificationExtensionEnabledBundlesWriteList(bundleNames);
    for (const auto& name : bundleNames) {
        auto uid = BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(name, userId);
        sptr<NotificationBundleOption> opt = new (std::nothrow) NotificationBundleOption(name, uid);
        enabledBundles.emplace_back(opt);
    }

    result = NotificationPreferences::GetInstance()->AddExtensionSubscriptionBundles(bundleOption, enabledBundles);
    if (result != ERR_OK) {
        ANS_LOGE("Failed to set enabled bundles into database, ret: %{public}d", result);
        return result;
    }
    return ERR_OK;
}

void AdvancedNotificationService::HandleBundleUpdate(const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("HandleBundleUpdate bundleOption is nullptr");
        return;
    }
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleOption->GetUid(), userId);
    if (!BundleManagerHelper::GetInstance()->
        CheckBundleImplExtensionAbility(bundleOption->GetBundleName(), userId)) {
        ShutdownExtensionServiceAndUnSubscribed(bundleOption);
        return;
    }
    
    std::vector<sptr<NotificationBundleOption>> enabledBundles;
    ErrCode result = ERR_OK;
    bool enabled = false;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        EnsureExtensionServiceLoadedAndSubscribed(bundleOption);
        ErrCode refreshResult = RefreshExtensionSubscriptionBundlesFromConfig(userId, bundleOption, enabledBundles);
        if (refreshResult != ERR_OK) {
            ANS_LOGE("RefreshExtensionSubscriptionBundlesFromConfig failed: %{public}d", refreshResult);
            return;
        }
        NotificationConstant::SWITCH_STATE state;
        result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionEnabled(bundleOption, state);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to get user granted state for bundle: %{public}s, ret: %{public}d",
                bundleOption->GetBundleName().c_str(), result);
            return;
        }
        enabled = ((state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) ? true : false);
    }));
    notificationSvrQueue_->wait(handler);
    std::vector<sptr<NotificationBundleOption>> bundles;
    GetNotificationExtensionEnabledBundles(bundles);
    if (cacheNotificationExtensionBundles_.size() == bundles.size()) {
        return;
    }
    NotificationConstant::EventCodeType eventcode = NotificationConstant::EXTENSION_ABILITY_ADDED;
    if (cacheNotificationExtensionBundles_.size() > bundles.size()) {
        eventcode = NotificationConstant::EXTENSION_ABILITY_REMOVED;
    }
    
    PublishExtensionServiceStateChange(eventcode, bundleOption, enabled, {});
    cacheNotificationExtensionBundles_ = bundles;
}

void AdvancedNotificationService::HandleBundleUninstall(const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("HandleBundleUninstall bundleOption is nullptr");
        return;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ShutdownExtensionServiceAndUnSubscribed(bundleOption);
        std::vector<sptr<NotificationBundleOption>> bundles;
        GetNotificationExtensionEnabledBundles(bundles);
        if (cacheNotificationExtensionBundles_.size() != bundles.size()) {
            PublishExtensionServiceStateChange(
                NotificationConstant::EXTENSION_ABILITY_REMOVED, bundleOption, false, {});
        }
        cacheNotificationExtensionBundles_ = bundles;
    }));
    notificationSvrQueue_->wait(handler);
}

void AdvancedNotificationService::RegisterHfpObserver()
{
    if (hfpObserver_ == nullptr) {
        hfpObserver_ = std::make_shared<HfpStateObserver>();
    }
    
    auto profile = OHOS::Bluetooth::HandsFreeAudioGateway::GetProfile();
    if (profile != nullptr) {
        profile->RegisterObserver(hfpObserver_);
        ANS_LOGI("HFP observer registered successfully");
    }
}

void AdvancedNotificationService::OnHfpDeviceConnected()
{
    if (!isExtensionServiceExist()) {
        std::vector<std::pair<sptr<NotificationBundleOption>,
        std::vector<sptr<NotificationBundleOption>>>> extensionBundleInfos;
        CheckExtensionServiceCondition(extensionBundleInfos, cacheNotificationExtensionBundles_);
        if (extensionBundleInfos.size() > 0) {
            LoadExtensionService();
        }
    }
}

bool AdvancedNotificationService::isExistHfpAddress(
    const std::vector<sptr<NotificationBundleOption>> &ExtensionBundles)
{
    for (auto const &bundle : ExtensionBundles) {
        std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
        ErrCode result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionInfos(bundle, infos);
        if (result != ERR_OK || infos.empty()) {
            return false;
        }
        for (const auto& info : infos) {
            if (info == nullptr) {
                continue;
            }
            std::string bluetoothAddress = info->GetAddr();
            if (!bluetoothAddress.empty() && info->IsHfp()) {
                return true;
            }
        }
    }
    return false;
}

bool AdvancedNotificationService::TryStartExtensionSubscribeService()
{
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
    NotificationConfigParse::GetInstance()->IsNotificationExtensionSubscribeSupportHfp(supportHfp_);
    std::vector<std::pair<sptr<NotificationBundleOption>,
        std::vector<sptr<NotificationBundleOption>>>> extensionBundleInfos;
    std::vector<sptr<NotificationBundleOption>> bundles;
    if (GetNotificationExtensionEnabledBundles(bundles) != ERR_OK || bundles.empty()) {
        ANS_LOGI("No bundle has extensionAbility, skip loading ExtensionService");
        return false;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        CheckExtensionServiceCondition(extensionBundleInfos, bundles);
        if (extensionBundleInfos.size() > 0) {
            LoadExtensionService();
        } else {
            if (isExistHfpAddress(cacheNotificationExtensionBundles_)) {
                RegisterHfpObserver();
            }
        }
    }));
    notificationSvrQueue_->wait(handler);
    return true;
#else
    return true;
#endif
}

ErrCode AdvancedNotificationService::GetNotificationExtensionEnabledBundles(
    std::vector<sptr<NotificationBundleOption>>& bundles)
{
    ANS_LOGD("AdvancedNotificationService::GetNotificationExtensionEnabledBundles");
    int32_t userId = -1;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    ErrCode result = ERR_OK;
    OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    if (!BundleManagerHelper::GetInstance()->QueryExtensionInfos(extensionInfos, userId)) {
        ANS_LOGE("Failed to QueryExtensionInfos, ret: %{public}d", result);
        return ERR_ANS_INVALID_PARAM;
    }
    
    for (const auto& extensionInfo : extensionInfos) {
        AppExecFwk::BundleInfo bundleInfo;
        int32_t flags = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
        if (!BundleManagerHelper::GetInstance()->GetBundleInfoV9(extensionInfo.bundleName, flags, bundleInfo, userId)) {
            ANS_LOGW("CheckExtensionServiceCondition GetBundleInfoV9 faild");
            continue;
        }

        if (!AccessTokenHelper::VerifyCallerPermission(
            bundleInfo.applicationInfo.accessTokenId, OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
            ANS_LOGW("GetNotificationExtensionEnabledBundles No Permission");
            continue;
        }

        auto uid = BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(extensionInfo.bundleName, userId);
        sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(
            extensionInfo.bundleName, uid);
        if (bundleOption == nullptr) {
            ANS_LOGE("Failed to create NotificationBundleOption for %{public}s", extensionInfo.bundleName.c_str());
            continue;
        }
        bundles.emplace_back(bundleOption);
    }

    if (cacheNotificationExtensionBundles_.size() == 0) {
        cacheNotificationExtensionBundles_ = bundles;
    }
    
    return ERR_OK;
}

ErrCode AdvancedNotificationService::NotificationExtensionSubscribe(
    const std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos)
{
    ANS_LOGD("AdvancedNotificationService::NotificationExtensionSubscribe");
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION) ||
        !AccessTokenHelper::CheckPermission(OHOS_PERMISSION_ACCESS_BLUETOOTH)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (infos.empty()) {
        ANS_LOGE("subscribe list is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption");
        return ERR_ANS_INVALID_PARAM;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }

    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleOption->GetUid(), userId);
    if (!BundleManagerHelper::GetInstance()->
        CheckBundleImplExtensionAbility(bundleOption->GetBundleName(), userId)) {
        ANS_LOGE("App Not Implement NotificationSubscriberExtensionAbility.");
        return ERR_ANS_NOT_IMPL_EXTENSIONABILITY;
    }
    
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        if (!HasExtensionSubscriptionInfosChanged(bundleOption, infos)) {
            ANS_LOGW("No change in extension subscription infos, skip db insert.");
            return;
        }
        result = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundleOption, infos);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to insert subscription info into db, ret: %{public}d", result);
            return;
        }
        if (!EnsureExtensionServiceLoadedAndSubscribed(bundleOption)) {
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::NotificationExtensionUnsubscribe()
{
    ANS_LOGD("AdvancedNotificationService::NotificationExtensionUnsubscribe");
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption");
        return ERR_ANS_INVALID_PARAM;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->ClearExtensionSubscriptionInfos(bundleOption);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to clean subscription info into db, ret: %{public}d", result);
            return;
        }
        if (!ShutdownExtensionServiceAndUnSubscribed(bundleOption)) {
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::GetSubscribeInfo(std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos)
{
    ANS_LOGD("AdvancedNotificationService::GetSubscribeInfo");
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption");
        return ERR_ANS_INVALID_PARAM;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionInfos(bundleOption, infos);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to get subscription info from db, ret: %{public}d", result);
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::GetAllSubscriptionBundles(std::vector<sptr<NotificationBundleOption>>& bundles)
{
    ANS_LOGD("AdvancedNotificationService::GetAllSubscriptionBundles");
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }
    auto result = GetNotificationExtensionEnabledBundles(bundles);
    return result;
}

ErrCode AdvancedNotificationService::IsUserGranted(bool& isEnabled)
{
    ANS_LOGD("AdvancedNotificationService::IsUserGranted");
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption");
        return ERR_ANS_INVALID_PARAM;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    NotificationConstant::SWITCH_STATE state;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionEnabled(bundleOption, state);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to get extensionsubscriptionenabled info from db, ret: %{public}d", result);
            return;
        }
        isEnabled = ((state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) ? true : false);
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::GetUserGrantedState(
    const sptr<NotificationBundleOption>& targetBundle, bool& enabled)
{
    ANS_LOGD("AdvancedNotificationService::GetUserGrantedState");
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(targetBundle);
    if (bundle == nullptr) {
        ANS_LOGE("Bundle is null.");
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    NotificationConstant::SWITCH_STATE state;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionEnabled(bundle, state);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to get user granted state for bundle: %{public}s, ret: %{public}d",
                targetBundle->GetBundleName().c_str(), result);
            return;
        }
        enabled = ((state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) ? true : false);
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::SetUserGrantedState(
    const sptr<NotificationBundleOption>& targetBundle, bool enabled)
{
    ANS_LOGD("AdvancedNotificationService::SetUserGrantedState");
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(targetBundle);
    if (bundle == nullptr) {
        ANS_LOGE("Bundle is null.");
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        if (!HasExtensionSubscriptionStateChanged(bundle, enabled)) {
            ANS_LOGW("User State No change for bundle: %{public}s", bundle->GetBundleName().c_str());
            return;
        }
        PublishExtensionServiceStateChange(NotificationConstant::USER_GRANTED_STATE, bundle, enabled, {});
        NotificationConstant::SWITCH_STATE state = enabled ? NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON
            : NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
        result = NotificationPreferences::GetInstance()->SetExtensionSubscriptionEnabled(bundle, state);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to set user granted state for bundle: %{public}s, ret: %{public}d",
                bundle->GetBundleName().c_str(), result);
        }
        if (enabled) {
            if (!EnsureExtensionServiceLoadedAndSubscribed(bundle)) {
                return;
            }
        } else {
            if (!ShutdownExtensionServiceAndUnSubscribed(bundle)) {
                return;
            }
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::GetUserGrantedEnabledBundles(
    const sptr<NotificationBundleOption>& targetBundle, std::vector<sptr<NotificationBundleOption>>& enabledBundles)
{
    ANS_LOGD("AdvancedNotificationService::GetUserGrantedEnabledBundles");
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(targetBundle);
    if (bundle == nullptr) {
        ANS_LOGE("Bundle is null.");
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter GetUserGrantedEnabledBundles!");
        result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionBundles(bundle, enabledBundles);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to get enabled bundles from database, ret: %{public}d", result);
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::GetUserGrantedEnabledBundlesForSelf(
    std::vector<sptr<NotificationBundleOption>>& bundles)
{
    ANS_LOGD("AdvancedNotificationService::GetUserGrantedEnabledBundlesForSelf");
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption");
        return ERR_ANS_INVALID_PARAM;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter GetUserGrantedEnabledBundlesForSelf!");
        result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionBundles(bundleOption, bundles);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to get enabled bundles from database, ret: %{public}d", result);
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::SetUserGrantedBundleState(
    const sptr<NotificationBundleOption>& targetBundle,
    const std::vector<sptr<NotificationBundleOption>>& enabledBundles, bool enabled)
{
    ANS_LOGD("AdvancedNotificationService::SetUserGrantedBundleState");
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(targetBundle);
    if (bundle == nullptr) {
        ANS_LOGE("Bundle is null.");
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }
    
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        if (!HasGrantedBundleStateChanged(bundle, enabledBundles)) {
            ANS_LOGW("User granted bundle state has no change");
            return;
        }
        PublishExtensionServiceStateChange(NotificationConstant::USER_GRANTED_BUNDLE_STATE, bundle, enabled,
            enabledBundles);
        result = enabled ?
            NotificationPreferences::GetInstance()->AddExtensionSubscriptionBundles(bundle, enabledBundles) :
            NotificationPreferences::GetInstance()->RemoveExtensionSubscriptionBundles(bundle, enabledBundles);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to set enabled bundles to database, ret: %{public}d", result);
            return;
        }
        std::vector<sptr<NotificationBundleOption>> existBundles;
        result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionBundles(bundle, existBundles);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to get enabled bundles from database, ret: %{public}d", result);
            return;
        }
        if (existBundles.size() > 0) {
            if (!EnsureExtensionServiceLoadedAndSubscribed(bundle)) {
                return;
            }
        } else {
            if (!ShutdownExtensionServiceAndUnSubscribed(bundle)) {
                return;
            }
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::CanOpenSubscribeSettings()
{
    ANS_LOGD("AdvancedNotificationService::CanOpenSubscribeSettings");
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        return ERR_ANS_PERMISSION_DENIED;
    }
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption");
        return ERR_ANS_INVALID_PARAM;
    }
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleOption->GetUid(), userId);
    if (!BundleManagerHelper::GetInstance()->
        CheckBundleImplExtensionAbility(bundleOption->GetBundleName(), userId)) {
        ANS_LOGE("App Not Implement NotificationSubscriberExtensionAbility.");
        return ERR_ANS_NOT_IMPL_EXTENSIONABILITY;
    }
    return ERR_OK;
}

void HfpStateObserver::OnConnectionStateChanged(
    const OHOS::Bluetooth::BluetoothRemoteDevice &device, int state, int cause)
{
    ANS_LOGI("HFP connection state changed: %{public}s, state: %{public}d",
             device.GetDeviceAddr().c_str(), state);
    
    if (state == static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTED)) {
        AdvancedNotificationService::GetInstance()->OnHfpDeviceConnected();
    }
}
}  // namespace Notification
}  // namespace OHOS