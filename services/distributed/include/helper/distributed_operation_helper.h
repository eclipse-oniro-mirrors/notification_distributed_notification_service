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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_OPERATION_SERVICE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_OPERATION_SERVICE_H

#include <map>
#include <memory>
#include <string>
#include "iremote_stub.h"
#include "ans_log_wrapper.h"
#include "ability_manager_client.h"
#include "power_mgr_client.h"
#include "screenlock_callback_interface.h"
#include "notification_operation_info.h"

namespace OHOS {
namespace Notification {

struct OperationInfo {
    int32_t deviceTypeId;
    OperationType type;
    std::string eventId;
    AAFwk::Want want;
};

class UnlockScreenCallback : public IRemoteStub<ScreenLock::ScreenLockCallbackInterface> {
public:
    explicit UnlockScreenCallback(const std::string& eventId);
    ~UnlockScreenCallback() override;
    void OnCallBack(int32_t screenLockResult) override;

private:
    std::string eventId_;
};

class OperationService {
public:
    static OperationService& GetInstance();
    void AddOperation(OperationInfo operationInfo);
    void HandleScreenEvent();
    void TriggerOperation(std::string eventId);
    void TimeOutOperation(std::string eventId);

private:
    OperationService() = default;
    ~OperationService() = default;
    std::mutex operationMutex_;
    std::map<std::string, OperationInfo> operationInfoMaps_;
};
}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_OPERATION_SERVICE_H
