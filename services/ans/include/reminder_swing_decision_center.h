/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_REMINDER_SWING_DECISION_CENTER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_REMINDER_SWING_DECISION_CENTER_H
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED

#include <functional>

#include "refbase.h"
#include "singleton.h"

#include "ans_log_wrapper.h"
#include "ans_inner_errors.h"
#include "common_event_subscriber.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "nlohmann/json.hpp"
#include "notification_config_parse.h"
#include "swing_callback_proxy.h"
#include "system_event_subscriber.h"

namespace OHOS {
namespace Notification {
using namespace std;
class ReminderSwingDecisionCenter {
public:
    ReminderSwingDecisionCenter();
    ~ReminderSwingDecisionCenter();
    static ReminderSwingDecisionCenter &GetInstance();
    static sptr<ISwingCallBack> swingCallback_;
    void ResetSwingCallbackProxy();
    ErrCode RegisterSwingCallback(const sptr<IRemoteObject> &swingCallback);
    void UpdateCrossDeviceNotificationStatus(bool isEnable);
    string GetSwingDeviceType();
    void OnScreenLock();
    void OnScreenUnlock();
    void OnUpdateDeviceStatus(const std::string &deviceType);
    void OnSmartReminderStatusChanged();
    void SwingExecuteDecision(bool isScreenUnlockTrigger = false);
private:
    void GetCcmSwingRemind();
    bool IsStatifySwingCrossDeviceStatus();
    void DisableSwingStatus();
private:
    static mutex swingMutex_;
    string enableSwingDeviceType_;
    string enableSwingDeviceStatus_;
    bool isCrossDeviceNotificationEnable_ = false;
    bool isSupportSwingSmartRemind_ = false;
    bool isSwingExecuting_ = false;
    bool isScreenUnlock_ = false;
    sptr<IRemoteObject::DeathRecipient> swingRecipient_ = nullptr;

    constexpr static inline const char* AFFTECED_BY = "affectedBy";
    constexpr static inline const char* SWING_FILTER = "swingEnableFilter";
    constexpr static inline const uint32_t UNLOCK_TRIGGER = 0;
    constexpr static inline const uint32_t NONE_UNLOCK_TRIGGER = 1;
};

class SwingCallbackRecipient : public IRemoteObject::DeathRecipient {
public:
    SwingCallbackRecipient();
    virtual ~SwingCallbackRecipient();
    void OnRemoteDied(const wptr<IRemoteObject> &remote);
};
}
}
#endif
#endif