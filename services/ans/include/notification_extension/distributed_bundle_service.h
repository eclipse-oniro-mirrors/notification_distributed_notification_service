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

#ifndef NOTIFICATION_DISTRIBUTED_EXTENSION_DISTRIBUTED_BUNDLE_SERVICE_H
#define NOTIFICATION_DISTRIBUTED_EXTENSION_DISTRIBUTED_BUNDLE_SERVICE_H

#include <vector>
#include <unordered_map>

#include "ffrt.h"
#include "ans_inner_errors.h"
#include "distributed_data_define.h"
#include "notification_bundle_option.h"
#include "notification_distributed_bundle.h"

namespace OHOS {
namespace Notification {

enum DistributedEventType {
    INIT_DISTRIBUTED_BUNDLES = 1,
    CLEAR_DISTRIBUTED_BUNDLES = 2,
    UPDATE_DISTRIBUTED_BUNDLE = 3,
    REMVOE_DISTRIBUTED_BUNDLE = 4,
};

class DistributedBundleService {
public:
    static DistributedBundleService& GetInstance();

    ErrCode SetDeviceDistributedBundleList(DistributedBundleChangeType type,
        const std::vector<NotificationDistributedBundle>& bundles);
    void HandleLocalSwitchEvent(DistributedBundleChangeType type, const std::string& bundleName,
        int32_t uid, bool enable);
    void HandleSlaveBundleChange(const sptr<NotificationBundleOption> &bundleOption, const bool addBundle);

private:
    DistributedBundleService() = default;
    ~DistributedBundleService() = default;
    ErrCode HandleCollaborationInit();
    ErrCode HandleCollaborationFinish();
    ErrCode HandleMasterBundleRemove(const std::vector<NotificationDistributedBundle>& bundles);
    ErrCode HandleMasterBundleAdd(const std::vector<NotificationDistributedBundle>& bundles);
    ErrCode HandleMasterEnableChange(DistributedBundleChangeType type,
        const std::vector<NotificationDistributedBundle>& bundles);
    void HandleSlaveBundleChange(DistributedBundleChangeType type,
        const sptr<NotificationBundleOption> &bundle);
    ErrCode HandleCollaborationEnabelChange(DistributedBundleChangeType type,
        const std::vector<NotificationDistributedBundle>& bundles);
    bool GetCurrentDeviceBundles(std::vector<NotificationBundleOption>& bundleOptions);
    void PublishDistributedStateChange(DistributedEventType eventCode,
        const sptr<NotificationBundleOption> &bundleOption);

    ffrt::mutex lock_;
    std::atomic<bool> connected = false;
    std::unordered_map<std::string, NotificationDistributedBundle> bundleList_;
};
}
}
#endif // NOTIFICATION_DISTRIBUTED_EXTENSION_DISTRIBUTED_BUNDLE_INFO_SERVICE_H
