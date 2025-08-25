/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_UNLOCK_LISTENER_TIMER_INFO_H
#define BASE_NOTIFICATION_UNLOCK_LISTENER_TIMER_INFO_H
#ifdef DISTRIBUTED_FEATURE_MASTER

#include <functional>

#include "ffrt.h"
#include "itimer_info.h"
#include "notification_constant.h"
#include "notification_request.h"

namespace OHOS {
namespace Notification {
struct UnlockListenerWant {
    uint64_t timer;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgentPtr = nullptr;
};

class UnlockListenerTimerInfo : public MiscServices::ITimerInfo {
public:
    UnlockListenerTimerInfo(std::string timerHashCode) : timerHashCode_(timerHashCode) {};
    virtual ~UnlockListenerTimerInfo() {};
    /**
     * When timing is up, this function will execute as call back.
     */
    void OnTrigger() override;

    /**
     * Indicates the timing type.
     */
    void SetType(const int32_t &type) override {};

    /**
     * Indicates the repeat policy.
     */
    void SetRepeat(bool repeat) override {};

    /**
     * Indicates the interval time for repeat timing.
     */
    void SetInterval(const uint64_t &interval) override {};

    /**
     * Indicates the want agent information.
     */
    void SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent) override {};

private:
    std::string timerHashCode_;
};

struct NotifictionJumpInfo {
public:
    NotifictionJumpInfo() {}
    NotifictionJumpInfo(int32_t jump, int32_t index, int32_t typeId, int64_t time)
        : jumpType(jump), btnIndex(index), deviceTypeId(typeId), timeStamp(time) {}
    int32_t jumpType;
    int32_t btnIndex;
    int32_t deviceTypeId;
    int64_t timeStamp;
};

class UnlockListenerOperService {
public:
    static UnlockListenerOperService& GetInstance();
    void AddDelayTask(const std::string& hashCode, const int32_t jumpType, const int32_t deviceType,
        const int32_t btnIndex);
    void ReplyOperationResponse();
    void HandleOperationTimeOut(const std::string& hashCode);
    void RemoveOperationResponse(const std::string& hashCode);
    void TriggerByJumpType(const std::string& hashCode, const int32_t jumpType,
        const int32_t deviceType, const int32_t btnIndex);

private:
    UnlockListenerOperService();
    ~UnlockListenerOperService() = default;

    int64_t GetCurrentTime();
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> GetNtfWantAgentPtr(const std::string& hashCode);
    ErrCode LaunchWantAgent(const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgentPtr);
    ErrCode GetNtfBtnWantAgentPtr(const std::string& hashCode,
        const int32_t btnIndex, std::shared_ptr<AbilityRuntime::WantAgent::WantAgent>& wantAgentPtr);
    void TriggerLiveViewNotification(
        sptr<NotificationRequest>& notificationRequest,
        const NotificationConstant::SlotType& slotType,
        const int32_t jumpType, const int32_t deviceType, const int32_t btnIndex);
    bool TriggerAncoNotification(const sptr<NotificationRequest>& notificationRequest,
        const std::string& hashCode, const int32_t deviceType, const NotificationConstant::SlotType& slotType);
    void TriggerNotification(const std::string& hashCode, const int32_t jumpType,
        const int32_t deviceType, const int32_t btnIndex, const NotificationConstant::SlotType& slotType);

private:
    ffrt::mutex mapLock_;
    std::shared_ptr<ffrt::queue> operationQueue_ = nullptr;
    std::vector<std::string> hashCodeOrder_;
    std::map<std::string, uint64_t> timerMap_;
    std::map<std::string, NotifictionJumpInfo> delayTaskMap_;
};
} // namespace OHOS
} // namespace Notification
#endif  // DISTRIBUTED_FEATURE_MASTER
#endif  // BASE_NOTIFICATION_UNLOCK_LISTENER_TIMER_INFO_H
