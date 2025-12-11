/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "extension_service_subscribe_service.h"
#include "notification_helper.h"
#include "os_account_manager.h"

namespace OHOS {
namespace Notification {

ExtensionServiceSubscribeService& ExtensionServiceSubscribeService::GetInstance()
{
    static ExtensionServiceSubscribeService ExtensionServiceSubscribeService;
    return ExtensionServiceSubscribeService;
}

void ExtensionServiceSubscribeService::SubscribeNotification(
    const sptr<NotificationBundleOption> bundle, const std::vector<sptr<NotificationBundleOption>>& subscribeBundles)
{
    ANS_LOGD("ExtensionServiceSubscribeService::SubscribeNotification");
    if (bundle == nullptr) {
        ANS_LOGE("null bundle");
        return;
    }
    if (subscribeBundles.empty()) {
        ANS_LOGE("subscribeBundles is empty");
        return;
    }
    
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    const std::string bundleKey = MakeBundleKey(*bundle);
    auto iter = subscriberMap_.find(bundleKey);
    std::shared_ptr<ExtensionServiceSubscriber> subscriber =
        iter == subscriberMap_.end() ? std::make_shared<ExtensionServiceSubscriber>() : iter->second;
    if (!subscriber->Init(bundle)) {
        ANS_LOGE("Failed to init notification subscriber for %{public}s_%{public}d", bundle->GetBundleName().c_str(),
            bundle->GetUid());
        return;
    }
    sptr<NotificationSubscribeInfo> subscribeInfo = new (std::nothrow) NotificationSubscribeInfo();
    subscribeInfo->AddDeviceType(NotificationConstant::THIRD_PARTY_WEARABLE_DEVICE_TYPE);
    
    int32_t userId = -1;
    int result = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(bundle->GetUid(), userId);
    if (result != ERR_OK) {
        ANS_LOGW("Failed to GetOsAccountLocalIdFromUid for extension, uid: %{public}d, ret: %{public}d",
            bundle->GetUid(), result);
        return;
    }
    subscribeInfo->AddAppUserId(userId);
    for (const auto& subscribeBundle : subscribeBundles) {
        if (subscribeBundle == nullptr) {
            ANS_LOGW("null subscribeBundle");
            continue;
        }
        subscribeInfo->AddAppUid(subscribeBundle->GetUid());
    }
    result = NotificationHelper::SubscribeNotification(subscriber, subscribeInfo);
    if (result == 0) {
        subscriberMap_.insert_or_assign(bundleKey, subscriber);
    } else {
        ANS_LOGW("SubscribeNotification failed with %{public}d.", result);
    }
}

void ExtensionServiceSubscribeService::UnsubscribeNotification(const sptr<NotificationBundleOption> bundle)
{
    ANS_LOGD("ExtensionServiceSubscribeService::UnsubscribeNotification");
    if (bundle == nullptr) {
        ANS_LOGE("null bundle");
        return;
    }
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    const std::string bundleKey = MakeBundleKey(*bundle);
    auto iter = subscriberMap_.find(bundleKey);
    if (iter == subscriberMap_.end()) {
        ANS_LOGW("UnSubscribe invalid %{public}s.", bundleKey.c_str());
        return;
    }

    int32_t result = NotificationHelper::UnSubscribeNotification(iter->second);
    if (result == ERR_OK) {
        subscriberMap_.erase(iter);
    }
}

void ExtensionServiceSubscribeService::UnsubscribeAllNotification()
{
    ANS_LOGD("ExtensionServiceSubscribeService::UnsubscribeAllNotification");
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    for (auto& subscriberInfo : subscriberMap_) {
        int32_t result = NotificationHelper::UnSubscribeNotification(subscriberInfo.second);
        ANS_LOGI("UnSubscribe %{public}s %{public}d.", subscriberInfo.first.c_str(), result);
    }
    subscriberMap_.clear();
}

std::string ExtensionServiceSubscribeService::MakeBundleKey(const NotificationBundleOption& bundle)
{
    return bundle.GetBundleName().append("_").append(std::to_string(bundle.GetUid()));
}
}
}
