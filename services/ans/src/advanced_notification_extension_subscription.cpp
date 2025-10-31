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

#include "advanced_notification_service.h"
#include "access_token_helper.h"
#include "aes_gcm_helper.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_permission_def.h"
#include "bluetooth_remote_device.h"
#include "bundle_manager_helper.h"
#include "errors.h"
#include "notification_config_parse.h"
#include "notification_preferences.h"
#include "notification_timer_info.h"
#include "os_account_manager_helper.h"
#include "parameters.h"
#include "time_service_client.h"

namespace OHOS {
namespace Notification {

using STARTUP = int32_t (*)(std::function<void()>, std::function<void(uint32_t, uint32_t, int32_t, std::string)>);
using SHUTDOWN = void (*)();
using SUBSCRIBE = void (*)(const sptr<NotificationBundleOption>,
    const std::vector<sptr<NotificationBundleOption>> &);
using UNSUBSCRIBE = void (*)(const sptr<NotificationBundleOption>);
using GETSUBSCRIBECOUNT = size_t (*)();
namespace {
constexpr const char* ANS_EXTENSION_SERVICE_MODULE_NAME = "libans_extension_service.z.so";
constexpr const int64_t SHUTDOWN_DELAY_TIME = 1;    // 1s
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
    startup(nullptr, [](uint32_t sceneId, uint32_t branchId, int32_t errorCode, std::string message) {
        HaMetaMessage msg = HaMetaMessage(sceneId, branchId);
        NotificationAnalyticsUtil::ReportModifyEvent(msg.Message(message));
    });
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

void AdvancedNotificationService::CheckExtensionServiceCondition(
    std::vector<std::pair<sptr<NotificationBundleOption>,
    std::vector<sptr<NotificationBundleOption>>>> &extensionBundleInfos,
    std::vector<sptr<NotificationBundleOption>> &bundles)
{
    extensionBundleInfos.clear();
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_27, EventBranchId::BRANCH_7);
    std::string isPCMode = OHOS::system::GetParameter("persist.sceneboard.ispcmode", "false");
    if (isPCMode == "true") {
        ANS_LOGW("PC Mode, skip loading ExtensionService");
        NotificationAnalyticsUtil::ReportModifyEvent(message.Message("cannot subscribe, due to PC Mode"));
        return;
    }

    FilterPermissionBundles(bundles);
    if (bundles.empty()) {
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

void AdvancedNotificationService::FilterPermissionBundles(std::vector<sptr<NotificationBundleOption>> &bundles)
{
    std::string noPermissionBundles = "";
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_27, EventBranchId::BRANCH_7);
    for (auto it = bundles.begin(); it != bundles.end();) {
        AppExecFwk::BundleInfo bundleInfo;
        int32_t userId = -1;
        OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid((*it)->GetUid(), userId);
        int32_t flags = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
        auto result = BundleManagerHelper::GetInstance()->GetBundleInfoV9(
            (*it)->GetBundleName(), flags, bundleInfo, userId);
        if (result && AccessTokenHelper::VerifyCallerPermission(
            bundleInfo.applicationInfo.accessTokenId, OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)
            && AccessTokenHelper::VerifyCallerPermission(
                bundleInfo.applicationInfo.accessTokenId, OHOS_PERMISSION_ACCESS_BLUETOOTH)) {
            ++it;
        } else {
            noPermissionBundles.append((*it)->GetBundleName())
                .append(":")
                .append(std::to_string((*it)->GetUid()))
                .append(",");
            it = bundles.erase(it);
        }
    }
    if (!noPermissionBundles.empty()) {
        std::string errMessage = noPermissionBundles;
        errMessage.append(" cannot subscribe, due to User has no permission");
        NotificationAnalyticsUtil::ReportModifyEvent(message.Message(errMessage));
    }
}

void AdvancedNotificationService::FilterGrantedBundles(std::vector<sptr<NotificationBundleOption>> &bundles)
{
    std::string noGrantedBundles = "";
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_27, EventBranchId::BRANCH_7);
    for (auto it = bundles.begin(); it != bundles.end();) {
        NotificationConstant::SWITCH_STATE state;
        if (NotificationPreferences::GetInstance()->GetExtensionSubscriptionEnabled(*it, state) == ERR_OK &&
            state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) {
            ++it;
        } else {
            noGrantedBundles.append((*it)->GetBundleName())
                .append(":")
                .append(std::to_string((*it)->GetUid()))
                .append(",");
            it = bundles.erase(it);
        }
    }
    if (!noGrantedBundles.empty()) {
        std::string errMessage = noGrantedBundles;
        errMessage.append(" cannot subscribe, due to No bundle is granted");
        NotificationAnalyticsUtil::ReportModifyEvent(message.Message(errMessage));
    }
}

void AdvancedNotificationService::FilterBundlesByBluetoothConnection(
    std::vector<sptr<NotificationBundleOption>> &bundles)
{
    std::string noBluetoothBundles = "";
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_27, EventBranchId::BRANCH_7);
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
            noBluetoothBundles.append((*it)->GetBundleName())
                .append(":")
                .append(std::to_string((*it)->GetUid()))
                .append(",");
            it = bundles.erase(it);
        }
    }
    if (!noBluetoothBundles.empty()) {
        std::string errMessage = noBluetoothBundles;
        errMessage.append(" cannot subscribe, due to No valid bluetooth connections found");
        NotificationAnalyticsUtil::ReportModifyEvent(message.Message(errMessage));
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
            if (CheckHfpState(bluetoothAddress)) {
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
        std::string encryptedAddr;
        if (AesGcmHelper::Encrypt(addr, encryptedAddr) == ERR_OK) {
            ANS_LOGW("Bluetooth device not paired: %{public}s, state: %{public}d", encryptedAddr.c_str(), state);
        }
    }
    return result;
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

    return true;
#else
    return true;
#endif
}

void AdvancedNotificationService::HandleBundleInstall(const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("HandleBundleInstall bundleOption is nullptr");
        return;
    }
    
    if (!BundleManagerHelper::GetInstance()->CheckBundleImplExtensionAbility(bundleOption)) {
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
            sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundleName, 0);
            if (bundleOption == nullptr) {
                ANS_LOGE("Failed to create NotificationBundleOption");
                continue;
            }
            sptr<NotificationBundleOption> bundle = GenerateValidBundleOptionV2(bundleOption);
            if (bundle == nullptr) {
                ANS_LOGE("Failed to create GenerateValidBundleOptionV2 for %{public}s", bundleName.c_str());
                continue;
            }
            insertBundles.emplace_back(bundle);
        }
        
        result = NotificationPreferences::GetInstance()->AddExtensionSubscriptionBundles(bundleOption, insertBundles);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to set enabled bundles into database, ret: %{public}d", result);
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);
    PublishExtensionServiceStateChange(NotificationConstant::EXTENSION_ABILITY_ADDED, bundleOption, false, {});
    cacheNotificationExtensionBundles_.emplace_back(bundleOption);
}

ErrCode AdvancedNotificationService::RefreshExtensionSubscriptionBundlesFromConfig(
    const sptr<NotificationBundleOption>& bundleOption,
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
        sptr<NotificationBundleOption> opt = new (std::nothrow) NotificationBundleOption(name, 0);
        if (opt == nullptr) {
            ANS_LOGE("Failed to create NotificationBundleOption");
            continue;
        }
        sptr<NotificationBundleOption> bundle = GenerateValidBundleOptionV2(opt);
        if (bundle == nullptr) {
            ANS_LOGE("Failed to create GenerateValidBundleOptionV2 for %{public}s", name.c_str());
            continue;
        }
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

    if (!BundleManagerHelper::GetInstance()->CheckBundleImplExtensionAbility(bundleOption)) {
        auto it = FindBundleInCache(bundleOption);
        if (it != cacheNotificationExtensionBundles_.end()) {
            cacheNotificationExtensionBundles_.erase(it);
            ShutdownExtensionServiceAndUnSubscribed(bundleOption);
            PublishExtensionServiceStateChange(
                NotificationConstant::EXTENSION_ABILITY_REMOVED, bundleOption, false, {});
        }
        return;
    }
    
    std::vector<sptr<NotificationBundleOption>> enabledBundles;
    ErrCode result = ERR_OK;
    bool enabled = false;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        EnsureExtensionServiceLoadedAndSubscribed(bundleOption);
        ErrCode refreshResult = RefreshExtensionSubscriptionBundlesFromConfig(bundleOption, enabledBundles);
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
    auto it = FindBundleInCache(bundleOption);
    if (it != cacheNotificationExtensionBundles_.end()) {
        ANS_LOGW("HandleBundleUpdate bundle already exists, skip publish event");
        return;
    }
    cacheNotificationExtensionBundles_.emplace_back(bundleOption);
    PublishExtensionServiceStateChange(NotificationConstant::EXTENSION_ABILITY_ADDED, bundleOption, enabled, {});
}

void AdvancedNotificationService::HandleBundleUninstall(const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("HandleBundleUninstall bundleOption is nullptr");
        return;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([=]() {
        auto it = FindBundleInCache(bundleOption);
        if (it != cacheNotificationExtensionBundles_.end()) {
            cacheNotificationExtensionBundles_.erase(it);
            ShutdownExtensionServiceAndUnSubscribed(bundleOption);
            PublishExtensionServiceStateChange(
                NotificationConstant::EXTENSION_ABILITY_REMOVED, bundleOption, false, {});
        }
    }));
}

void AdvancedNotificationService::RegisterHfpObserver()
{
    if (hfpObserver_ == nullptr) {
        hfpObserver_ = std::make_shared<HfpStateObserver>();
    }
    
    if (isHfpObserverRegistered_.load()) {
        return;
    }

    isHfpObserverRegistered_.store(true);
    auto profile = OHOS::Bluetooth::HandsFreeAudioGateway::GetProfile();
    if (profile != nullptr) {
        profile->RegisterObserver(hfpObserver_);
        ANS_LOGI("HFP observer registered successfully");
    }
}

void AdvancedNotificationService::OnHfpDeviceConnectChanged(
    const OHOS::Bluetooth::BluetoothRemoteDevice &device, int state)
{
    ProcessHfpDeviceStateChange(device, state);
}

void AdvancedNotificationService::OnBluetoothStateChanged(int status)
{
    ProcessBluetoothStateChanged(status);
}

void AdvancedNotificationService::ProcessHfpDeviceStateChange(
    const OHOS::Bluetooth::BluetoothRemoteDevice &device, int state)
{
    std::vector<sptr<NotificationBundleOption>> processBundles;
    std::vector<sptr<NotificationBundleOption>> bundles;
    if (cacheNotificationExtensionBundles_.size() != 0) {
        bundles = cacheNotificationExtensionBundles_;
    } else {
        GetNotificationExtensionEnabledBundles(bundles);
    }
    
    for (const auto& bundle : bundles) {
        std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
        ErrCode result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionInfos(bundle, infos);
        if (result != ERR_OK || infos.empty()) {
            continue;
        }
        for (const auto& info : infos) {
            if (info == nullptr && !info->IsHfp()) {
                continue;
            }
            std::string bluetoothAddress = info->GetAddr();
            if (!bluetoothAddress.empty() && bluetoothAddress == device.GetDeviceAddr()) {
                processBundles.emplace_back(bundle);
                break;
            }
        }
    }
    if (processBundles.size() == 0) {
        std::string encryptedAddr;
        if (AesGcmHelper::Encrypt(device.GetDeviceAddr(), encryptedAddr) == ERR_OK) {
            ANS_LOGW("No matching bundle found for device: %{public}s", encryptedAddr.c_str());
        }
        return;
    }
    
    for (const auto& processBundle : processBundles) {
        if (state == static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTED)) {
            EnsureExtensionServiceLoadedAndSubscribed(processBundle);
        } else {
            ShutdownExtensionServiceAndUnSubscribed(processBundle);
        }
    }
}

bool AdvancedNotificationService::TryStartExtensionSubscribeService()
{
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
    NotificationConfigParse::GetInstance()->IsNotificationExtensionSubscribeSupportHfp(supportHfp_);
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([=]() {
        ANS_LOGD("ffrt enter!");
        RegisterHfpObserver();
        std::vector<std::pair<sptr<NotificationBundleOption>,
            std::vector<sptr<NotificationBundleOption>>>> extensionBundleInfos;
        std::vector<sptr<NotificationBundleOption>> bundles;
        if (!CheckBluetoothSwitchState()) {
            ANS_LOGW("Bluetooth is not enabled, skip checking extension service condition");
            RegisterBluetoothAccessObserver();
            return;
        }
        if (GetNotificationExtensionEnabledBundles(bundles) != ERR_OK || bundles.empty()) {
            ANS_LOGW("No bundle has extensionAbility, skip loading ExtensionService");
            return;
        }
        CheckExtensionServiceCondition(extensionBundleInfos, bundles);
        if (extensionBundleInfos.size() > 0) {
            LoadExtensionService();
        }
    }));
    return true;
#else
    return true;
#endif
}

ErrCode AdvancedNotificationService::GetNotificationExtensionEnabledBundles(
    std::vector<sptr<NotificationBundleOption>>& bundles)
{
    ANS_LOGD("AdvancedNotificationService::GetNotificationExtensionEnabledBundles");
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_27, EventBranchId::BRANCH_0);
    int32_t userId = -1;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    ErrCode result = ERR_OK;
    OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    if (!BundleManagerHelper::GetInstance()->QueryExtensionInfos(extensionInfos, userId)) {
        ANS_LOGE("Failed to QueryExtensionInfos, ret: %{public}d", result);
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_PERMISSION_DENIED).BranchId(BRANCH_4));
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
            NotificationAnalyticsUtil::ReportModifyEvent(
                message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Message("Permission denied").BranchId(BRANCH_1));
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
    cacheNotificationExtensionBundles_ = bundles;
    return ERR_OK;
}

ErrCode AdvancedNotificationService::NotificationExtensionSubscribe(
    const std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos)
{
    ANS_LOGD("AdvancedNotificationService::NotificationExtensionSubscribe");
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_27, EventBranchId::BRANCH_0);
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Message("Permission denied").BranchId(BRANCH_1));
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (infos.empty()) {
        ANS_LOGE("subscribe list is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_INVALID_PARAM).BranchId(BRANCH_5));
        return ERR_ANS_INVALID_PARAM;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_INVALID_PARAM).Message("Serial queue is invalid").BranchId(BRANCH_2));
        return ERR_ANS_INVALID_PARAM;
    }

    if (!BundleManagerHelper::GetInstance()->CheckBundleImplExtensionAbility(bundleOption)) {
        ANS_LOGE("App Not Implement NotificationSubscriberExtensionAbility.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_NOT_IMPL_EXTENSIONABILITY).Message(
            "Not implement NotificationSubscriberExtensionAbility").BranchId(BRANCH_3));
        return ERR_ANS_NOT_IMPL_EXTENSIONABILITY;
    }
    
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        for (auto &info : infos) {
            if (CheckHfpState(info->GetAddr())) {
                info->SetHfp(true);
            }
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
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_27, EventBranchId::BRANCH_0);
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Message("Permission denied").BranchId(BRANCH_1));
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_INVALID_PARAM).BranchId(BRANCH_5));
        return ERR_ANS_INVALID_PARAM;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_INVALID_PARAM).Message("Serial queue is invalid").BranchId(BRANCH_2));
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
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_27, EventBranchId::BRANCH_0);
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Message("Permission denied").BranchId(BRANCH_1));
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_INVALID_PARAM).BranchId(BRANCH_5));
        return ERR_ANS_INVALID_PARAM;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_INVALID_PARAM).Message("Serial queue is invalid").BranchId(BRANCH_2));
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
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_27, EventBranchId::BRANCH_0);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Message("Not systemApp").BranchId(BRANCH_1));
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Message("Permission denied").BranchId(BRANCH_1));
        return ERR_ANS_PERMISSION_DENIED;
    }
    auto result = GetNotificationExtensionEnabledBundles(bundles);
    return result;
}

ErrCode AdvancedNotificationService::IsUserGranted(bool& isEnabled)
{
    ANS_LOGD("AdvancedNotificationService::IsUserGranted");
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_27, EventBranchId::BRANCH_0);
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Message("Permission denied").BranchId(BRANCH_1));
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_INVALID_PARAM).BranchId(BRANCH_5));
        return ERR_ANS_INVALID_PARAM;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_INVALID_PARAM).Message("Serial queue is invalid").BranchId(BRANCH_2));
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
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_27, EventBranchId::BRANCH_0);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Message("Not systemApp"));
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Message("Permission denied").BranchId(BRANCH_1));
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOptionV2(targetBundle);
    if (bundle == nullptr) {
        ANS_LOGE("Bundle is null.");
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_INVALID_BUNDLE_OPTION).BranchId(BRANCH_6));
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }

    if (!BundleManagerHelper::GetInstance()->CheckBundleImplExtensionAbility(bundle)) {
        ANS_LOGE("App Not Implement NotificationSubscriberExtensionAbility.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_NOT_IMPL_EXTENSIONABILITY).Message(
            "Not implement NotificationSubscriberExtensionAbility").BranchId(BRANCH_3));
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_INVALID_PARAM).Message("Serial queue is invalid").BranchId(BRANCH_2));
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
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_27, EventBranchId::BRANCH_0);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Message("Not systemApp"));
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Message("Permission denied").BranchId(BRANCH_1));
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOptionV2(targetBundle);
    if (bundle == nullptr) {
        ANS_LOGE("Bundle is null.");
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_INVALID_BUNDLE_OPTION).BranchId(BRANCH_6));
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }

    if (!BundleManagerHelper::GetInstance()->CheckBundleImplExtensionAbility(bundle)) {
        ANS_LOGE("App Not Implement NotificationSubscriberExtensionAbility.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_NOT_IMPL_EXTENSIONABILITY).Message(
            "Not implement NotificationSubscriberExtensionAbility").BranchId(BRANCH_3));
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_INVALID_PARAM).Message("Serial queue is invalid").BranchId(BRANCH_2));
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ProcessSetUserGrantedState(bundle, enabled, result);
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::GetUserGrantedEnabledBundles(
    const sptr<NotificationBundleOption>& targetBundle, std::vector<sptr<NotificationBundleOption>>& enabledBundles)
{
    ANS_LOGD("AdvancedNotificationService::GetUserGrantedEnabledBundles");
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_27, EventBranchId::BRANCH_0);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Message("Not systemApp"));
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Message("Permission denied").BranchId(BRANCH_1));
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOptionV2(targetBundle);
    if (bundle == nullptr) {
        ANS_LOGE("Bundle is null.");
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_INVALID_BUNDLE_OPTION).BranchId(BRANCH_6));
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }

    if (!BundleManagerHelper::GetInstance()->CheckBundleImplExtensionAbility(bundle)) {
        ANS_LOGE("App Not Implement NotificationSubscriberExtensionAbility.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_NOT_IMPL_EXTENSIONABILITY).Message(
            "Not implement NotificationSubscriberExtensionAbility").BranchId(BRANCH_3));
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_INVALID_PARAM).Message("Serial queue is invalid").BranchId(BRANCH_2));
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
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_27, EventBranchId::BRANCH_0);
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Message("Permission denied").BranchId(BRANCH_1));
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_INVALID_PARAM).BranchId(BRANCH_5));
        return ERR_ANS_INVALID_PARAM;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_INVALID_PARAM).Message("Serial queue is invalid").BranchId(BRANCH_2));
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
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_27, EventBranchId::BRANCH_0);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Message("Not systemApp"));
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Message("Permission denied").BranchId(BRANCH_1));
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOptionV2(targetBundle);
    if (bundle == nullptr) {
        ANS_LOGE("Bundle is null.");
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }

    std::vector<sptr<NotificationBundleOption>> enabledBundlesProcessed;
    for (const auto& bundle : enabledBundles) {
        sptr<NotificationBundleOption> bundleProcessed = GenerateValidBundleOptionV2(bundle);
        if (bundleProcessed == nullptr) {
            ANS_LOGE("Failed to create NotificationBundleOption");
            return ERR_ANS_INVALID_BUNDLE_OPTION;
        }
        enabledBundlesProcessed.emplace_back(bundleProcessed);
    }

    if (!BundleManagerHelper::GetInstance()->CheckBundleImplExtensionAbility(bundle)) {
        ANS_LOGE("App Not Implement NotificationSubscriberExtensionAbility.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_NOT_IMPL_EXTENSIONABILITY).Message(
            "Not implement NotificationSubscriberExtensionAbility").BranchId(BRANCH_3));
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }
    
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_INVALID_PARAM).Message("Serial queue is invalid").BranchId(BRANCH_2));
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ProcessSetUserGrantedBundleState(bundle, enabledBundlesProcessed, enabled, result);
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::CanOpenSubscribeSettings()
{
    ANS_LOGD("AdvancedNotificationService::CanOpenSubscribeSettings");
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_27, EventBranchId::BRANCH_0);
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Message("Permission denied").BranchId(BRANCH_1));
        return ERR_ANS_PERMISSION_DENIED;
    }
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_INVALID_PARAM).BranchId(BRANCH_5));
        return ERR_ANS_INVALID_PARAM;
    }

    if (!BundleManagerHelper::GetInstance()->CheckBundleImplExtensionAbility(bundleOption)) {
        ANS_LOGE("App Not Implement NotificationSubscriberExtensionAbility.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_NOT_IMPL_EXTENSIONABILITY).Message(
            "Not implement NotificationSubscriberExtensionAbility").BranchId(BRANCH_3));
        return ERR_ANS_NOT_IMPL_EXTENSIONABILITY;
    }
    return ERR_OK;
}

void HfpStateObserver::OnConnectionStateChanged(
    const OHOS::Bluetooth::BluetoothRemoteDevice &device, int state, int cause)
{
    ANS_LOGI("HFP connection state changed with state: %{public}d", state);
    auto queue = AdvancedNotificationService::GetInstance()->GetNotificationSvrQueue();
    if (queue == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return;
    }
    ffrt::task_handle handler = queue->submit_h(std::bind([=]() {
        AdvancedNotificationService::GetInstance()->OnHfpDeviceConnectChanged(device, state);
    }));
}

void BluetoothAccessObserver::OnStateChanged(const int transport, const int status)
{
    ANS_LOGI("Bluetooth state changed: transport: %{public}d, status: %{public}d", transport, status);
    auto queue = AdvancedNotificationService::GetInstance()->GetNotificationSvrQueue();
    if (queue == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return;
    }
    ffrt::task_handle handler = queue->submit_h(std::bind([=]() {
        AdvancedNotificationService::GetInstance()->OnBluetoothStateChanged(status);
    }));
}

void AdvancedNotificationService::ProcessSetUserGrantedState(
    const sptr<NotificationBundleOption>& bundle, bool enabled, ErrCode& result)
{
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
}

void AdvancedNotificationService::ProcessSetUserGrantedBundleState(
    const sptr<NotificationBundleOption>& bundle,
    const std::vector<sptr<NotificationBundleOption>>& enabledBundles, bool enabled, ErrCode& result)
{
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
}

bool AdvancedNotificationService::CheckBluetoothSwitchState()
{
    Bluetooth::BluetoothState state = Bluetooth::BluetoothHost::GetDefaultHost().GetBluetoothState();
    if (state != Bluetooth::BluetoothState::STATE_ON) {
        return false;
    }
    return true;
}

void AdvancedNotificationService::RegisterBluetoothAccessObserver()
{
    if (bluetoothAccessObserver_ == nullptr) {
        bluetoothAccessObserver_ = std::make_shared<BluetoothAccessObserver>();
    }
    
    if (isBluetoothObserverRegistered_.load()) {
        return;
    }

    isBluetoothObserverRegistered_.store(true);
    Bluetooth::BluetoothHost::GetDefaultHost().RegisterObserver(bluetoothAccessObserver_);
}

void AdvancedNotificationService::ProcessBluetoothStateChanged(const int status)
{
    ANS_LOGD("ProcessBluetoothStateChanged");
    if (status == OHOS::Bluetooth::BTStateID::STATE_TURN_ON) {
        std::vector<sptr<NotificationBundleOption>> bundles;
        if (cacheNotificationExtensionBundles_.size() != 0) {
            bundles = cacheNotificationExtensionBundles_;
        } else {
            GetNotificationExtensionEnabledBundles(bundles);
        }
    
        if (bundles.size() == 0) {
            ANS_LOGD("No bundle match conditon");
            return;
        }
    
        std::vector<std::pair<sptr<NotificationBundleOption>,
            std::vector<sptr<NotificationBundleOption>>>> extensionBundleInfos;
        CheckExtensionServiceCondition(extensionBundleInfos, bundles);
        if (extensionBundleInfos.size() > 0) {
            LoadExtensionService();
            for (const auto& extensionBundleInfo : extensionBundleInfos) {
                SubscribeExtensionService(extensionBundleInfo.first, extensionBundleInfo.second);
            }
        }
    }
    if (status == OHOS::Bluetooth::BTStateID::STATE_TURN_OFF) {
        ShutdownExtensionService();
    }
}

bool AdvancedNotificationService::CheckHfpState(const std::string &bluetoothAddress)
{
    if (!supportHfp_) {
        return false;
    }
    OHOS::Bluetooth::BluetoothRemoteDevice remoteDevice(bluetoothAddress, OHOS::Bluetooth::BT_TRANSPORT_NONE);
    int32_t btConnectState = static_cast<int32_t>(Bluetooth::BTConnectState::DISCONNECTED);
    int32_t ret = OHOS::Bluetooth::HandsFreeAudioGateway::GetProfile()->GetDeviceState(remoteDevice, btConnectState);
    if (ret == ERR_OK && btConnectState == static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTED)) {
        std::string encryptedAddr;
        if (AesGcmHelper::Encrypt(bluetoothAddress, encryptedAddr) == ERR_OK) {
            ANS_LOGI("Bluetooth HFP device connected: %{public}s", encryptedAddr.c_str());
        }
        return true;
    }
    return false;
}

std::vector<sptr<NotificationBundleOption>>::iterator AdvancedNotificationService::FindBundleInCache(
    const sptr<NotificationBundleOption> &bundleOption)
{
    return std::find_if(cacheNotificationExtensionBundles_.begin(), cacheNotificationExtensionBundles_.end(),
        [&](const sptr<NotificationBundleOption>& option) {
            return option != nullptr && bundleOption != nullptr &&
                option->GetBundleName() == bundleOption->GetBundleName() &&
                option->GetUid() == bundleOption->GetUid();
        });
}
}  // namespace Notification
}  // namespace OHOS