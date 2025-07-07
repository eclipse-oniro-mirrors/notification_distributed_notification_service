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
#include "analytics_util.h"
#include "distributed_device_service.h"

namespace OHOS {
namespace Notification {

AnalyticsUtil& AnalyticsUtil::GetInstance()
{
    static AnalyticsUtil analyticsUtil;
    return analyticsUtil;
}

void AnalyticsUtil::InitHACallBack(std::function<void(int32_t, int32_t, uint32_t, std::string)> callback)
{
    haCallback_ = callback;
}

void AnalyticsUtil::InitSendReportCallBack(std::function<void(int32_t, int32_t, std::string)> callback)
{
    sendReportCallback_ = callback;
}

void AnalyticsUtil::InitOperationCallback(
    std::function<void(const std::string&, int32_t, int32_t, std::string)>callback)
{
    operationCallback_ = callback;
}

void AnalyticsUtil::SendHaReport(int32_t eventCode, int32_t errorCode, uint32_t branchId,
    const std::string& errorReason, int32_t code)
{
    if (haCallback_ == nullptr || !DistributedDeviceService::GetInstance().IsReportDataByHa()) {
        return;
    }
    if (code == -1) {
        haCallback_(eventCode, errorCode, branchId, errorReason);
    } else {
        haCallback_(code, errorCode, branchId, errorReason);
    }
}

void AnalyticsUtil::SendEventReport(int32_t messageType, int32_t errCode, const std::string& errorReason)
{
    if (sendReportCallback_ == nullptr || !DistributedDeviceService::GetInstance().IsReportDataByHa()) {
        return;
    }
    sendReportCallback_(messageType, errCode, errorReason);
}

void AnalyticsUtil::OperationalReporting(int32_t deviceType, int32_t sceneType, int32_t slotType,
    const std::string& reason)
{
    if (operationCallback_ == nullptr || !DistributedDeviceService::GetInstance().IsReportDataByHa()) {
        return;
    }
    std::string deviceString = DistributedDeviceService::DeviceTypeToTypeString(deviceType);
    operationCallback_(deviceString, sceneType, slotType, reason);
}

void AnalyticsUtil::AbnormalReporting(int32_t eventCode, int result, uint32_t branchId,
    const std::string &errorReason)
{
    if (!DistributedDeviceService::GetInstance().IsReportDataByHa()) {
        return;
    }

    if (result != 0) {
        SendEventReport(0, result, errorReason);
    }
    if (haCallback_ == nullptr) {
        return;
    }
    haCallback_(eventCode, result, branchId, errorReason);
}
}
}
