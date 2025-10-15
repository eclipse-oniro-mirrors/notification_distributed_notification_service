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
#include "extension_service_connection_service.h"
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

int32_t NotificationExtensionService::InitService(std::function<void()> shutdownCallback)
{
    ANS_LOGD("NotificationExtensionService::InitService");
    shutdownCallback_ = shutdownCallback;
    ExtensionServiceConnectionService::GetInstance().SetOnAllConnectionsClosed([this]() {
        ANS_LOGD("onAllConnectionsClosed");
        if (serviceQueue_ == nullptr) {
            ANS_LOGE("null serviceQueue.");
            return;
        }
        serviceQueue_->submit([this]() {
            ANS_LOGD("call shutdownCallback");
            if (shutdownCallback_) {
                shutdownCallback_();
            }
            ANS_LOGD("leave shutdownCallback");
        });
    });
    uint32_t destroyTime = 0;
    if (NotificationConfigParse::GetInstance()->IsNotificationExtensionLifecycleDestroyTimeConfigured(destroyTime)) {
        ExtensionServiceConnection::SetExtensionLifecycleDestroyTime(destroyTime);
    }
    return 0;
}

void NotificationExtensionService::DestroyService()
{
    ANS_LOGE("NotificationExtensionService::DestroyService");
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("null serviceQueue.");
        return;
    }

    ffrt::task_handle handler = serviceQueue_->submit_h([&]() {
        ANS_LOGD("Start destroy service.");
        ExtensionServiceSubscribeService::GetInstance().UnsubscribeAllNotification();
    });
    serviceQueue_->wait(handler);
}

void NotificationExtensionService::SubscribeNotification(const sptr<NotificationBundleOption> bundle,
    const std::vector<sptr<NotificationBundleOption>>& subscribedBundles)
{
    ANS_LOGD("NotificationExtensionService::SubscribeNotification");
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("null serviceQueue.");
        return;
    }
    ffrt::task_handle handler = serviceQueue_->submit_h([&]() {
        ExtensionServiceSubscribeService::GetInstance().SubscribeNotification(bundle, subscribedBundles);
    });
    serviceQueue_->wait(handler);
}

void NotificationExtensionService::UnsubscribeNotification(const sptr<NotificationBundleOption> bundle)
{
    ANS_LOGD("NotificationExtensionService::UnsubscribeNotification");
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("null serviceQueue.");
        return;
    }
    ffrt::task_handle handler = serviceQueue_->submit_h([&]() {
        ExtensionServiceSubscribeService::GetInstance().UnsubscribeNotification(bundle);
    });
    serviceQueue_->wait(handler);
}
}
}
