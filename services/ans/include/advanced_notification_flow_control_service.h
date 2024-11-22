/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_FLOW_CONTROL_SERVICE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_FLOW_CONTROL_SERVICE_H

#include <ctime>
#include <list>
#include <memory>
#include <mutex>

#include "errors.h"
#include "singleton.h"
#include "ans_const_define.h"
#include "notification_record.h"

namespace OHOS {
namespace Notification {
struct FlowControlThreshold {
    uint32_t maxCreateNumPerSecond = MAX_CREATE_NUM_PERSECOND;
    uint32_t maxUpdateNumPerSecond = MAX_UPDATE_NUM_PERSECOND;
    uint32_t maxCreateNumPerSecondPerApp = MAX_CREATE_NUM_PERSECOND_PERAPP;
    uint32_t maxUpdateNumPerSecondPerApp = MAX_UPDATE_NUM_PERSECOND_PERAPP;
};

class FlowControlService : public DelayedSingleton<FlowControlService> {
public:
    FlowControlService();
    ErrCode FlowControl(const std::shared_ptr<NotificationRecord> &record,
        const int32_t callingUid, bool isNotificationExists);

private:
    ErrCode PublishFlowCtrl(const std::shared_ptr<NotificationRecord> &record, const int32_t callingUid);
    ErrCode PublishGlobalFlowCtrl(const std::shared_ptr<NotificationRecord> &record,
        std::chrono::system_clock::time_point now);
    ErrCode PublishSingleAppFlowCtrl(const std::shared_ptr<NotificationRecord> &record,
        std::chrono::system_clock::time_point now, const int32_t callingUid);
    void PublishRecordTimestamp(const std::shared_ptr<NotificationRecord> &record,
        std::chrono::system_clock::time_point now, const int32_t callingUid);
    void PublishSingleAppFlowCtrlRemoveExpire(std::chrono::system_clock::time_point now);

    ErrCode UpdateFlowCtrl(const std::shared_ptr<NotificationRecord> &record, const int32_t callingUid);
    ErrCode UpdateGlobalFlowCtrl(const std::shared_ptr<NotificationRecord> &record,
        std::chrono::system_clock::time_point now);
    ErrCode UpdateSingleAppFlowCtrl(const std::shared_ptr<NotificationRecord> &record,
        std::chrono::system_clock::time_point now, const int32_t callingUid);
    void UpdateRecordTimestamp(const std::shared_ptr<NotificationRecord> &record,
        std::chrono::system_clock::time_point now, const int32_t callingUid);
    void UpdateSingleAppFlowCtrlRemoveExpire(std::chrono::system_clock::time_point now);

private:
    static std::mutex flowControlMutex_;
    std::list<std::chrono::system_clock::time_point> flowControlUpdateTimestampList_;
    std::list<std::chrono::system_clock::time_point> flowControlPublishTimestampList_;
    static std::mutex systemFlowControlMutex_;
    std::list<std::chrono::system_clock::time_point> systemFlowControlUpdateTimestampList_;
    std::list<std::chrono::system_clock::time_point> systemFlowControlPublishTimestampList_;
    static std::mutex singleAppFlowControlMutex_;
    std::map<int32_t,
        std::shared_ptr<std::list<std::chrono::system_clock::time_point>>> singleAppFlowControlUpdateTimestampMap_;
    std::map<int32_t,
        std::shared_ptr<std::list<std::chrono::system_clock::time_point>>> singleAppFlowControlPublishTimestampMap_;

    FlowControlThreshold threshold_;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_FLOW_CONTROL_SERVICE_H