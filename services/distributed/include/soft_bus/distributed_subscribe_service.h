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

#ifndef DISTRIBUTED_INCLUDE_SOFTBUS_DISTRIBUTED_SUBSCRIBE_SERVICE_H
#define DISTRIBUTED_INCLUDE_SOFTBUS_DISTRIBUTED_SUBSCRIBE_SERVICE_H

#include "distributed_subscriber.h"
#include <thread>
#include "distributed_device_data.h"

namespace OHOS {
namespace Notification {
class DistributedSubscribeService {
public:
    static DistributedSubscribeService& GetInstance();
    static int32_t GetCurrentActiveUserId();
    void UnSubscribeAllNotification();
    void SubscribeNotification(const DistributedDeviceInfo peerDevice);
    void UnSubscribeNotification(const std::string &deviceId, uint16_t deviceType);
private:
    std::mutex mapLock_;
    std::map<std::string, std::shared_ptr<DistribuedSubscriber>> subscriberMap_;
};
}
}
#endif // DISTRIBUTED_INCLUDE_SOFTBUS_DISTRIBUTED_SUBSCRIBE_SERVICE_H

