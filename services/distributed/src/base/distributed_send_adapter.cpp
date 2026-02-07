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

#include "distributed_send_adapter.h"

#include "ans_inner_errors.h"
#include "softbus_error_code.h"
#include "distributed_data_define.h"
namespace OHOS {
namespace Notification {

const int32_t DEFAULT_RETRY_TIME = 1;

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
    int32_t result = DistributedClient::GetInstance().SendMessage(packageInfo->boxInfo_,
        packageInfo->dataType_, packageInfo->deviceInfo_.deviceId_, packageInfo->eventType_);
    ANS_LOGI("Dans adapter send %{public}s %{public}u %{public}d %{public}d %{public}d.",
        StringAnonymous(packageInfo->deviceInfo_.deviceId_).c_str(), packageInfo->deviceInfo_.deviceType_,
        packageInfo->messageType_, packageInfo->dataType_, result);

    std::shared_ptr<PackageInfo> nextPackageInfo;
    std::lock_guard<ffrt::mutex> lock(lock_);
    if (packageCached_.empty()) {
        isRunning.store(false);
        ANS_LOGI("Dans submit end.");
        return;
    }
    nextPackageInfo = packageCached_.front();
    if (nextPackageInfo == nullptr) {
        ANS_LOGW("Dans submit invalid.");
        return;
    }
    packageCached_.pop_front();
    std::function<void()> sendTask = [nextPackageInfo]() {
        DistributedSendAdapter::GetInstance().DoSendPackage(nextPackageInfo);
    };
    ffrt::submit(sendTask);
}

void DistributedSendAdapter::SendPackage(const std::shared_ptr<PackageInfo>& packageInfo)
{
    if (packageInfo == nullptr) {
        return;
    }
    ANS_LOGI("Dans adapter add %{public}s %{public}u %{public}d %{public}d.",
        StringAnonymous(packageInfo->deviceInfo_.deviceId_).c_str(), packageInfo->deviceInfo_.deviceType_,
        packageInfo->messageType_, packageInfo->dataType_);
    std::lock_guard<ffrt::mutex> lock(lock_);
    if (isRunning.load() || !packageCached_.empty()) {
        packageCached_.push_back(packageInfo);
        return;
    }

    ANS_LOGI("Dans submit start.");
    isRunning.store(true);
    std::function<void()> sendTask = [packageInfo]() {
        DistributedSendAdapter::GetInstance().DoSendPackage(packageInfo);
    };
    ffrt::submit(sendTask);
}

}
}
