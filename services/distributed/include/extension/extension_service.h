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

#ifndef DISTRIBUTED_INCLUDE_EXTENSION_EXTENSION_SERVICE_H
#define DISTRIBUTED_INCLUDE_EXTENSION_EXTENSION_SERVICE_H

#include "ffrt.h"
#include "notification_bundle_option.h"

namespace OHOS {
namespace Notification {

class NotificationExtensionService {
public:
    NotificationExtensionService();
    static NotificationExtensionService& GetInstance();
    int32_t InitService();
    void DestroyService();
    void SubscribeNotification(const sptr<NotificationBundleOption> bundle,
        const std::vector<sptr<NotificationBundleOption>>& subscribedBundles);
    void UnsubscribeNotification(const sptr<NotificationBundleOption> bundle);
    size_t GetSubscriberCount();

private:
    std::shared_ptr<ffrt::queue> serviceQueue_ = nullptr;
};
}
}
#endif // DISTRIBUTED_INCLUDE_EXTENSION_EXTENSION_SERVICE_H
