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
    if (bundle == nullptr) {
        ANS_LOGE("null bundle");
        return;
    }
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    const std::string bundleKey = MakeBundleKey(*bundle);
    auto iter = subscriberMap_.find(bundleKey);
    std::shared_ptr<ExtensionServiceSubscriber> subscriber =
        iter == subscriberMap_.end() ? std::make_shared<ExtensionServiceSubscriber>(*bundle) : iter->second;
    sptr<NotificationSubscribeInfo> subscribeInfo = new (std::nothrow) NotificationSubscribeInfo();
    subscribeInfo->AddDeviceType(NotificationConstant::THIRD_PARTY_WEARABLE_DEVICE_TYPE);
    for (const auto& subscribeBundle : subscribeBundles) {
        if (subscribeBundle == nullptr) {
            ANS_LOGW("null subscribeBundle");
            continue;
        }
        subscribeInfo->AddAppName(subscribeBundle->GetBundleName());
    }
    int result = NotificationHelper::SubscribeNotification(subscriber, subscribeInfo);
    if (result == 0) {
        subscriberMap_.insert_or_assign(bundleKey, subscriber);
    } else {
        ANS_LOGW("SubscribeNotification failed with %{public}d.", result);
    }
}

void ExtensionServiceSubscribeService::UnsubscribeNotification(const sptr<NotificationBundleOption> bundle)
{
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
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    for (auto& subscriberInfo : subscriberMap_) {
        int32_t result = NotificationHelper::UnSubscribeNotification(subscriberInfo.second);
        ANS_LOGI("UnSubscribe %{public}s %{public}d.", subscriberInfo.first.c_str(), result);
    }
}

size_t ExtensionServiceSubscribeService::GetSubscriberCount()
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    return subscriberMap_.size();
}

std::string ExtensionServiceSubscribeService::MakeBundleKey(const NotificationBundleOption& bundle)
{
    return bundle.GetBundleName().append("_").append(std::to_string(bundle.GetUid()));
}
}
}
