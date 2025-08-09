/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "distributed_extension_service.h"
#undef private
#undef protected
#include "notification_capsule.h"
#include "notification_disable.h"
#include "notification_do_not_disturb_profile.h"
#include "notification_icon_button.h"
#include "notification_live_view_content.h"
#include "notification_local_live_view_button.h"
#include "notification_local_live_view_content.h"
#include "notification_operation_info.h"
#include "notification_unified_group_Info.h"
#include "resource_manager.h"
#include "notificationextension_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "notification_content.h"
#include "notification_check_request.h"

namespace OHOS {
namespace Notification {

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        bool result = DistributedExtensionService::GetInstance().initConfig();
        const int32_t MIN_LENGTH = 1;
        const int32_t MAX_LENGTH = 10;
        const int32_t messageType = 7;
        std::string reason = "ok";
        std::string deviceType = DistributedExtensionService::TransDeviceTypeToName(DmDeviceType::DEVICE_TYPE_WATCH);
        deviceType = DistributedExtensionService::TransDeviceTypeToName(DmDeviceType::DEVICE_TYPE_PAD);
        deviceType = DistributedExtensionService::TransDeviceTypeToName(DmDeviceType::DEVICE_TYPE_PHONE);
        deviceType = DistributedExtensionService::TransDeviceTypeToName(DmDeviceType::DEVICE_TYPE_2IN1);
        deviceType = DistributedExtensionService::TransDeviceTypeToName(DmDeviceType::DEVICE_TYPE_PC);
        deviceType = DistributedExtensionService::TransDeviceTypeToName(DmDeviceType::DEVICE_TYPE_WIFI_CAMERA);
        deviceType = DistributedExtensionService::DeviceTypeToTypeString(DmDeviceType::DEVICE_TYPE_PAD);
        deviceType = DistributedExtensionService::DeviceTypeToTypeString(DmDeviceType::DEVICE_TYPE_PC);
        deviceType = DistributedExtensionService::DeviceTypeToTypeString(DmDeviceType::DEVICE_TYPE_2IN1);
        deviceType = DistributedExtensionService::DeviceTypeToTypeString(DmDeviceType::DEVICE_TYPE_WATCH);

        DistributedExtensionService::GetInstance().InitDans();
        DistributedExtensionService::GetInstance().ReleaseLocalDevice();
        DistributedHardware::DmDeviceInfo deviceInfo;
        DistributedExtensionService::GetInstance().OnDeviceOnline(deviceInfo);
        DistributedExtensionService::GetInstance().OnDeviceOffline(deviceInfo);
        DistributedExtensionService::GetInstance().HADotCallback(0, 0, 0, "{\"deviceType\":\"pc\"}");
        DistributedExtensionService::GetInstance().SendReportCallback(messageType, 0, reason);

        DistributedHardware::DmDeviceInfo info;
        strcpy_s(info.deviceId, sizeof(info.deviceId) - 1, "device");
        DistributedExtensionService::GetInstance().OnDeviceOffline(info);
        DistributedExtensionService::GetInstance().OnDeviceChanged(info);
        nlohmann::json contentJson;
        contentJson["operationReplyTimeout"] = fdp->ConsumeIntegralInRange<int32_t>(MIN_LENGTH, MAX_LENGTH);
        contentJson["maxContentLength"] = fdp->ConsumeIntegralInRange<int32_t>(MIN_LENGTH, MAX_LENGTH);
        contentJson["localType"] = fdp->ConsumeRandomLengthString(MAX_LENGTH);
        contentJson["supportPeerDevice"] = fdp->ConsumeRandomLengthString(MAX_LENGTH);
        contentJson["maxTitleLength"] = fdp->ConsumeIntegralInRange<int32_t>(MIN_LENGTH, MAX_LENGTH);
        DistributedExtensionService::GetInstance().SetOperationReplyTimeout(contentJson);
        DistributedExtensionService::GetInstance().SetMaxContentLength(contentJson);
        DistributedExtensionService::GetInstance().SetLocalType(contentJson);
        DistributedExtensionService::GetInstance().SetSupportPeerDevice(contentJson);
        DistributedExtensionService::GetInstance().SetMaxTitleLength(contentJson);

        return true;
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
