/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_SEND_ADAPTER_H
#define BASE_NOTIFICATION_DISTRIBUTED_SEND_ADAPTER_H

#include <list>

#include "distributed_client.h"

namespace OHOS {
namespace Notification {

class PackageInfo {
public:
    PackageInfo(const std::shared_ptr<BoxBase>& box, DistributedDeviceInfo deviceInfo,
        TransDataType dataType, int32_t eventType);
    ~PackageInfo() = default;
    int32_t messageType_ = 0;
    int32_t eventType_;
    TransDataType dataType_;
    DistributedDeviceInfo deviceInfo_;
    std::shared_ptr<BoxBase> boxInfo_;
};

class DistributedSendAdapter {
public:
    static DistributedSendAdapter& GetInstance();
    void SendPackage(const std::shared_ptr<PackageInfo>& packageInfo);
    void DoSendPackage(const std::shared_ptr<PackageInfo>& packageInfo);
private:
    ffrt::mutex lock_;
    std::atomic<bool> isRunning = false;
    std::list<std::shared_ptr<PackageInfo>> packageCached_;
};
}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_SEND_ADAPTER_H
