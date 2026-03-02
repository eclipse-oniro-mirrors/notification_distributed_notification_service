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

#include "distributed_bundle_service.h"

#include "ans_log_wrapper.h"
#include "ans_inner_errors.h"
#include "ans_const_define.h"
#include "ans_permission_def.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "common_event_publish_info.h"
#include "distributed_data_define.h"
#include "bundle_manager_helper.h"
#include "os_account_manager_helper.h"
#include "notification_subscriber_manager.h"
#include "notification_application_change_info.h"

namespace OHOS {
namespace Notification {

DistributedBundleService& DistributedBundleService::GetInstance()
{
    static DistributedBundleService distributedBundleService;
    return distributedBundleService;
}

bool DistributedBundleService::GetCurrentDeviceBundles(std::vector<NotificationBundleOption>& bundleOptions)
{
    int32_t userId = DEFAULT_USER_ID;
    OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    if (BundleManagerHelper::GetInstance()->GetAllBundleOption(bundleOptions, userId) != ERR_OK) {
        return false;
    }

    ANS_LOGI("Get current device bundles %{public}zu,.", bundleOptions.size());
    return true;
}

ErrCode DistributedBundleService::HandleCollaborationInit()
{
    std::unique_lock lock(lock_);
    connected.store(true);
    PublishDistributedStateChange(DistributedEventType::INIT_DISTRIBUTED_BUNDLES, nullptr);
    ANS_LOGI("Collaboration start.");
    return ERR_OK;
}

ErrCode DistributedBundleService::HandleCollaborationFinish()
{
    std::unique_lock lock(lock_);
    connected.store(false);
    bundleList_.clear();
    PublishDistributedStateChange(DistributedEventType::CLEAR_DISTRIBUTED_BUNDLES, nullptr);
    ANS_LOGI("Collaboration finish.");
    return ERR_OK;
}

ErrCode DistributedBundleService::HandleMasterBundleRemove(
    const std::vector<NotificationDistributedBundle>& bundles)
{
    std::unique_lock lock(lock_);
    for (auto& bundle : bundles) {
        std::string key = bundle.GetBundleName() + std::to_string(bundle.GetBundleUid());
        bundleList_.erase(key);
        ANS_LOGI("Bundle remove %{public}s.", bundle.Dump().c_str());
        sptr<NotificationBundleOption> bundleOption =
            new (std::nothrow) NotificationBundleOption(bundle.GetBundleName(), bundle.GetBundleUid());
        if (bundleOption) {
            PublishDistributedStateChange(DistributedEventType::REMVOE_DISTRIBUTED_BUNDLE, bundleOption);
        }
    }
    return ERR_OK;
}

ErrCode DistributedBundleService::HandleMasterBundleAdd(const std::vector<NotificationDistributedBundle>& bundles)
{
    std::vector<NotificationBundleOption> bundleOptions;
    if (!GetCurrentDeviceBundles(bundleOptions)) {
        return ERR_ANS_TASK_ERR;
    }

    std::unique_lock lock(lock_);
    for (auto& bundle : bundles) {
        if (bundle.GetBundleName().empty() && bundle.GetBundleLabel().empty()) {
            continue;
        }
        NotificationDistributedBundle copy = bundle;
        std::string key = copy.GetBundleName() + std::to_string(copy.GetBundleUid());
        for (auto bundleOption : bundleOptions) {
            if (bundleOption.GetAppName() != copy.GetBundleLabel() &&
                bundleOption.GetBundleName() != copy.GetBundleName()) {
                continue;
            }
            copy.SetInstalledbundle(bundleOption.GetBundleName(), bundleOption.GetAppName());
            break;
        }
        bundleList_[key] = copy;
        ANS_LOGI("Bundle add %{public}s.", copy.Dump().c_str());
    }
    ANS_LOGI("Bundle add total %{public}zu.", bundleList_.size());
    return ERR_OK;
}

ErrCode DistributedBundleService::HandleMasterEnableChange(DistributedBundleChangeType type,
    const std::vector<NotificationDistributedBundle>& bundles)
{
    std::vector<NotificationBundleOption> bundleOptions;
    if (!GetCurrentDeviceBundles(bundleOptions)) {
        return ERR_ANS_TASK_ERR;
    }

    std::unique_lock lock(lock_);
    for (auto& bundle : bundles) {
        sptr<NotificationBundleOption> application =
            new (std::nothrow) NotificationBundleOption(bundle.GetBundleName(), bundle.GetBundleUid());
        if (application) {
            PublishDistributedStateChange(DistributedEventType::UPDATE_DISTRIBUTED_BUNDLE, application);
        }
        std::string key = bundle.GetBundleName() + std::to_string(bundle.GetBundleUid());
        if (bundleList_.find(key) != bundleList_.end()) {
            if (type == DistributedBundleChangeType::MASTER_LIVEVIEW_ENABLE) {
                bundleList_[key].SetLiveViewEnable(bundle.GetLiveViewEnable());
            }

            if (type == DistributedBundleChangeType::MASTER_NOTIFICATION_ENABLE) {
                bundleList_[key].SetNotificationEnable(bundle.GetNotificationEnable());
            }
            ANS_LOGI("Bundle master enable %{public}s.", bundleList_[key].Dump().c_str());
            continue;
        }

        ANS_LOGI("Master enable change add %{public}s.", key.c_str());
        NotificationDistributedBundle copy = bundle;
        if (type == DistributedBundleChangeType::MASTER_LIVEVIEW_ENABLE) {
            copy.SetNotificationEnable(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
        } else {
            copy.SetLiveViewEnable(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
        }
        for (auto bundleOption : bundleOptions) {
            if (bundleOption.GetAppName() != copy.GetBundleLabel() &&
                bundleOption.GetBundleName() != copy.GetBundleName()) {
                continue;
            }
            copy.SetInstalledbundle(bundleOption.GetBundleName(), bundleOption.GetAppName());
            break;
        }
        bundleList_[key] = copy;
        ANS_LOGI("Bundle master enable change %{public}s.", copy.Dump().c_str());
    }
    return ERR_OK;
}

void DistributedBundleService::HandleSlaveBundleChange(DistributedBundleChangeType type,
    const sptr<NotificationBundleOption> &bundle)
{
    std::unique_lock lock(lock_);
    ANS_LOGI("Slave bundle change %{public}d %{public}s.", type, bundle->Dump().c_str());
    // salve bundle add
    if (type == DistributedBundleChangeType::SLAVE_BUNDLE_ADD) {
        for (auto& saveBundle : bundleList_) {
            if (saveBundle.second.GetBundleName() != bundle->GetBundleName() &&
                saveBundle.second.GetBundleLabel() != bundle->GetAppName()) {
                continue;
            }
            saveBundle.second.SetInstalledbundle(bundle->GetBundleName(), bundle->GetAppName());
            ANS_LOGI("Slave bundle set %{public}s.", saveBundle.second.Dump().c_str());
            sptr<NotificationBundleOption> application = new (std::nothrow) NotificationBundleOption(
                saveBundle.second.GetBundleName(), saveBundle.second.GetBundleUid());
            if (application) {
                PublishDistributedStateChange(DistributedEventType::UPDATE_DISTRIBUTED_BUNDLE, application);
            }
        }
        return;
    }
    // salve bundle remove
    ANS_LOGI("Slave bundle change %{public}zu.", bundleList_.size());
    for (auto& saveBundle : bundleList_) {
        if (!saveBundle.second.CheckInstalledBundle(bundle->GetBundleName(), bundle->GetAppName())) {
            continue;
        }

        int32_t userId = DEFAULT_USER_ID;
        OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
        AppExecFwk::BundleInfo bundleInfo;
        int32_t flag = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
        if (BundleManagerHelper::GetInstance()->GetBundleInfoV9(bundle->GetBundleName(), flag, bundleInfo, userId)) {
            ANS_LOGI("Slave same bundle %{public}d %{public}s.", bundleInfo.applicationInfo.uid,
                bundle->GetBundleName().c_str());
            return;
        }

        saveBundle.second.SetInstalledbundle(std::string(), std::string());
        ANS_LOGI("Slave bundle set %{public}s.", saveBundle.second.Dump().c_str());
        sptr<NotificationBundleOption> application = new (std::nothrow) NotificationBundleOption(
            saveBundle.second.GetBundleName(), saveBundle.second.GetBundleUid());
        if (application) {
            PublishDistributedStateChange(DistributedEventType::UPDATE_DISTRIBUTED_BUNDLE, application);
        }
    }
}

ErrCode DistributedBundleService::HandleCollaborationEnabelChange(DistributedBundleChangeType type,
    const std::vector<NotificationDistributedBundle>& bundles)
{
    std::unique_lock lock(lock_);
    for (auto& bundle : bundles) {
        std::string key = bundle.GetBundleName() + std::to_string(bundle.GetBundleUid());
        if (bundleList_.find(key) == bundleList_.end()) {
            ANS_LOGI("Collaboration change invalid %{public}s.", key.c_str());
            return ERR_ANS_INVALID_PARAM;
        }
        if (type == DistributedBundleChangeType::COLLABORATION_LIVEVIEW_ENABLE) {
            bundleList_[key].SetLiveViewEnable(bundle.GetLiveViewEnable());
        }

        if (type == DistributedBundleChangeType::COLLABORATION_NOTIFICATION_ENABLE) {
            bundleList_[key].SetNotificationEnable(bundle.GetNotificationEnable());
        }
        ANS_LOGI("Collaboration change %{public}s.", bundle.Dump().c_str());
    }
    return ERR_OK;
}

ErrCode DistributedBundleService::SetDeviceDistributedBundleList(DistributedBundleChangeType type,
    const std::vector<NotificationDistributedBundle>& bundles)
{
    ANS_LOGI("Set device bundles %{public}zu,%{public}d", bundles.size(), static_cast<int32_t>(type));
    switch (type) {
        case DistributedBundleChangeType::INIT_DEVICE_CONNECT:
            return HandleCollaborationInit();
        case DistributedBundleChangeType::END_DEVICE_CONNECT:
            return HandleCollaborationFinish();
        case DistributedBundleChangeType::MASTER_BUNDLE_ADD:
            return HandleMasterBundleAdd(bundles);
        case DistributedBundleChangeType::MASTER_BUNDLE_REMOVE:
            return HandleMasterBundleRemove(bundles);
        case DistributedBundleChangeType::MASTER_NOTIFICATION_ENABLE:
        case DistributedBundleChangeType::MASTER_LIVEVIEW_ENABLE:
            return HandleMasterEnableChange(type, bundles);
        case DistributedBundleChangeType::COLLABORATION_NOTIFICATION_ENABLE:
        case DistributedBundleChangeType::COLLABORATION_LIVEVIEW_ENABLE:
            return HandleCollaborationEnabelChange(type, bundles);
        default:
            return ERR_ANS_INVALID_PARAM;
    }
    return ERR_OK;
}

void DistributedBundleService::HandleLocalSwitchEvent(DistributedBundleChangeType type, const std::string& bundleName,
    int32_t uid, bool enable)
{
    sptr<NotificationApplicationChangeInfo> changeInfo = new (std::nothrow) NotificationApplicationChangeInfo();
    if (changeInfo == nullptr) {
        ANS_LOGE("invalid bundle change info.");
        return;
    }
    std::shared_ptr<NotificationBundleOption> bundle = std::make_shared<NotificationBundleOption>(bundleName, uid);
    changeInfo->SetEnable(enable);
    changeInfo->SetChangeType(type);
    changeInfo->SetBundle(bundle);
    NotificationSubscriberManager::GetInstance()->NotifyApplicationInfoNeedChanged(changeInfo);
}


void DistributedBundleService::HandleSlaveBundleChange(const sptr<NotificationBundleOption> &bundleOption,
    const bool addBundle)
{
#if defined(ALL_SCENARIO_COLLABORATION) && !defined(DISTRIBUTED_FEATURE_MASTER)
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return;
    }

    DistributedBundleChangeType type = DistributedBundleChangeType::SLAVE_BUNDLE_REMOVE;
    if (addBundle) {
        type = DistributedBundleChangeType::SLAVE_BUNDLE_ADD;
        std::string label = BundleManagerHelper::GetInstance()->GetBundleLabel(bundleOption->GetBundleName());
        bundleOption->SetAppName(label);
    }

    HandleSlaveBundleChange(type, bundleOption);
#endif
}

void DistributedBundleService::PublishDistributedStateChange(
    DistributedEventType eventCode, const sptr<NotificationBundleOption> &bundleOption)
{
    if (eventCode < DistributedEventType::INIT_DISTRIBUTED_BUNDLES ||
        eventCode > DistributedEventType::REMVOE_DISTRIBUTED_BUNDLE) {
        ANS_LOGE("Invalid event code: %{public}d", eventCode);
        return;
    }

    EventFwk::Want want;
    want.SetAction("notification.event.DISTRIBUTED_APPLICTION_CHANGE");
    if (eventCode == DistributedEventType::CLEAR_DISTRIBUTED_BUNDLES ||
        eventCode == DistributedEventType::UPDATE_DISTRIBUTED_BUNDLE) {
        if (bundleOption == nullptr) {
            ANS_LOGE("Invalid bundle option");
            return;
        }
        nlohmann::json targetBundle = {{"bundle", bundleOption->GetBundleName()}, {"uid", bundleOption->GetUid()}};
        want.SetParam("targetBundle", targetBundle.dump());
    }

    EventFwk::CommonEventData commonData;
    commonData.SetWant(want);
    commonData.SetCode(static_cast<int32_t>(eventCode));
    std::vector<std::string> permission { OHOS_PERMISSION_NOTIFICATION_CONTROLLER };
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberPermissions(permission);
    bool result = EventFwk::CommonEventManager::PublishCommonEvent(commonData, publishInfo);
    ANS_LOGI("Publish event %{public}d, %{public}d.", eventCode, result);
}
}
}
