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

#ifndef DISTRIBUTED_INCLUDE_SOFTBUS_DISTRIBUTED_OPERATION_SERVICE_H
#define DISTRIBUTED_INCLUDE_SOFTBUS_DISTRIBUTED_OPERATION_SERVICE_H

#include <set>
#include <map>

#include "response_box.h"
#include "distributed_device_data.h"
#include "notification_operation_info.h"

namespace OHOS {
namespace Notification {
class DistributedOperationService {
public:
    static DistributedOperationService& GetInstance();

    void HandleNotificationOperation(const std::shared_ptr<TlvBox>& boxMessage);
#ifdef DISTRIBUTED_FEATURE_MASTER
    void ReplyOperationResponse(const std::string& hashCode, const NotificationResponseBox& responseBox,
        OperationType operationType, uint32_t result);
    int32_t TriggerReplyApplication(const std::string& hashCode, const NotificationResponseBox& responseBox);
    void TriggerJumpApplication(const std::string& hashCode);
#else
    int32_t OnOperationResponse(const std::shared_ptr<NotificationOperationInfo>& operationInfo,
        const DistributedDeviceInfo& device);
    void ResponseOperationResult(const std::string& hashCode, const NotificationResponseBox& responseBox);
#endif
};
}
}
#endif // DISTRIBUTED_INCLUDE_SOFTBUS_DISTRIBUTED_OPERATION_SERVICE_H
