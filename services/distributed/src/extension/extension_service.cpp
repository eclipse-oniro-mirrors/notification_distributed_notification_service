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

#include "ans_log_wrapper.h"
#include "extension_service_connection.h"
#include "extension_service.h"
#include "extension_service_subscribe_service.h"
#include "notification_config_parse.h"

namespace OHOS {
namespace Notification {

NotificationExtensionService& NotificationExtensionService::GetInstance()
{
    static NotificationExtensionService notificationExtensionService;
    return notificationExtensionService;
}

NotificationExtensionService::NotificationExtensionService()
{
    serviceQueue_ = std::make_shared<ffrt::queue>("ans_extension_service");
    if (serviceQueue_ == nullptr) {
        ANS_LOGW("ffrt create failed!");
        return;
    }
    ANS_LOGI("Extension service init successfully.");
}

int32_t NotificationExtensionService::InitService()
{
    uint32_t destroyTime = 0;
    if (NotificationConfigParse::GetInstance()->IsNotificationExtensionLifecycleDestroyTimeConfigured(destroyTime)) {
        ExtensionServiceConnection::SetExtensionLifecycleDestroyTime(destroyTime);
    }
    return 0;
}

void NotificationExtensionService::DestroyService()
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    ffrt::task_handle handler = serviceQueue_->submit_h([&]() {
        ANS_LOGI("Start destory service.");
        ExtensionServiceSubscribeService::GetInstance().UnsubscribeAllNotification();
    });
    serviceQueue_->wait(handler);
}

void NotificationExtensionService::SubscribeNotification(const sptr<NotificationBundleOption> bundle,
    const std::vector<sptr<NotificationBundleOption>>& subscribedBundles)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    ffrt::task_handle handler = serviceQueue_->submit_h([&]() {
        ExtensionServiceSubscribeService::GetInstance().SubscribeNotification(bundle, subscribedBundles);
    });
    serviceQueue_->wait(handler);
}

void NotificationExtensionService::UnsubscribeNotification(const sptr<NotificationBundleOption> bundle)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    ffrt::task_handle handler = serviceQueue_->submit_h([&]() {
        ExtensionServiceSubscribeService::GetInstance().UnsubscribeNotification(bundle);
    });
    serviceQueue_->wait(handler);
}

size_t NotificationExtensionService::GetSubscriberCount()
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return 0;
    }
    size_t count = 0;
    ffrt::task_handle handler = serviceQueue_->submit_h([&]() {
        count = ExtensionServiceSubscribeService::GetInstance().GetSubscriberCount();
    });
    serviceQueue_->wait(handler);
    return count;
}
}
}
