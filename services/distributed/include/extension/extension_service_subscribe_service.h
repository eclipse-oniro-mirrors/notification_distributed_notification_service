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

#ifndef DISTRIBUTED_INCLUDE_EXTENSION_EXTENSION_SERVICE_SUBSCRIBE_SERVICE_H
#define DISTRIBUTED_INCLUDE_EXTENSION_EXTENSION_SERVICE_SUBSCRIBE_SERVICE_H

#include "extension_service_subscriber.h"
#include "ffrt.h"
#include "refbase.h"
#include <string>
#include <thread>

namespace OHOS {
namespace Notification {
class ExtensionServiceSubscribeService {
public:
    static ExtensionServiceSubscribeService& GetInstance();
    void SubscribeNotification(const sptr<NotificationBundleOption> bundle,
        const std::vector<sptr<NotificationBundleOption>>& subscribeBundles);
    void UnsubscribeNotification(const sptr<NotificationBundleOption> bundle);
    void UnsubscribeAllNotification();
private:
    std::string MakeBundleKey(const NotificationBundleOption& bundle);
private:
    ffrt::mutex mapLock_;
    std::map<std::string, std::shared_ptr<ExtensionServiceSubscriber>> subscriberMap_;
};
}
}
#endif // DISTRIBUTED_INCLUDE_EXTENSION_EXTENSION_SERVICE_SUBSCRIBE_SERVICE_H

