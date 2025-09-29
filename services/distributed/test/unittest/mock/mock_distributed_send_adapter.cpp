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

#include "distributed_send_adapter.h"

#include "mock_invoke_counting.h"

namespace OHOS {
namespace Notification {
PackageInfo::PackageInfo(const std::shared_ptr<BoxBase>& box, DistributedDeviceInfo deviceInfo,
    TransDataType dataType, int32_t eventType)
{
    boxInfo_ = box;
    deviceInfo_ = deviceInfo;
    dataType_ = dataType;
    eventType_ = eventType;
    if (boxInfo_ != nullptr && boxInfo_->box_ != nullptr) {
        boxInfo_->box_->GetMessageType(messageType_);
    }
}

DistributedSendAdapter& DistributedSendAdapter::GetInstance()
{
    static DistributedSendAdapter distributedSendAdapter;
    return distributedSendAdapter;
}

void DistributedSendAdapter::DoSendPackage(const std::shared_ptr<PackageInfo>& packageInfo)
{
}

void DistributedSendAdapter::SendPackage(const std::shared_ptr<PackageInfo>& packageInfo)
{
    if (packageInfo == nullptr) {
        return;
    }
    MockInvokeCounting::GetInstance().MockSetCount();
}
}
}