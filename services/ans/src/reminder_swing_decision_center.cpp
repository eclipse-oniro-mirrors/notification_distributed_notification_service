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
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include "reminder_swing_decision_center.h"
#include "notification_preferences.h"
#include "smart_reminder_center.h"
#include "reminder_affected.h"

namespace OHOS {
namespace Notification {
using namespace std;
mutex ReminderSwingDecisionCenter::swingMutex_;
sptr<ISwingCallBack> ReminderSwingDecisionCenter::swingCallback_ = nullptr;

ReminderSwingDecisionCenter::ReminderSwingDecisionCenter()
{
    GetCcmSwingRemind();
}

ReminderSwingDecisionCenter::~ReminderSwingDecisionCenter() {}

ReminderSwingDecisionCenter &ReminderSwingDecisionCenter::GetInstance()
{
    return DelayedRefSingleton<ReminderSwingDecisionCenter>::GetInstance();
}

ErrCode ReminderSwingDecisionCenter::RegisterSwingCallback(const sptr<IRemoteObject> &swingCallback)
{
    if (swingCallback == nullptr) {
        ANS_LOGW("swingCallback is null.");
        return ERR_INVALID_VALUE;
    }
    swingRecipient_ = new (nothrow) SwingCallbackRecipient();
    if (!swingRecipient_) {
        ANS_LOGE("Failed to create death Recipient ptr SwingCallbackRecipient!");
        return ERR_NO_INIT;
    }
    swingCallback->AddDeathRecipient(swingRecipient_);
    lock_guard<mutex> lock(swingMutex_);
    swingCallback_ = iface_cast<ISwingCallBack>(swingCallback);
    ANS_LOGI("RegisterSwingCallback OK");
    return ERR_OK;
}

void ReminderSwingDecisionCenter::ResetSwingCallbackProxy()
{
    ANS_LOGD("enter");
    lock_guard<mutex> lock(swingMutex_);
    if (swingCallback_ == nullptr || swingCallback_->AsObject() == nullptr) {
        ANS_LOGE("invalid proxy state");
        return;
    }
    swingCallback_->AsObject()->RemoveDeathRecipient(swingRecipient_);
    swingCallback_ = nullptr;
}

void ReminderSwingDecisionCenter::GetCcmSwingRemind()
{
    nlohmann::json root;
    string swingJsonPoint = "/";
    swingJsonPoint.append(NotificationConfigParse::CFG_KEY_NOTIFICATION_SERVICE);
    swingJsonPoint.append("/");
    swingJsonPoint.append(SWING_FILTER);
    swingJsonPoint.append("/");
    swingJsonPoint.append(AFFTECED_BY);
    isSupportSwingSmartRemind_ = false;
    if (!NotificationConfigParse::GetInstance()->GetConfigJson(swingJsonPoint, root)) {
        ANS_LOGI("Failed to get swingJsonPoint CCM config file.");
        return;
    }

    nlohmann::json affects = root[NotificationConfigParse::CFG_KEY_NOTIFICATION_SERVICE][SWING_FILTER][AFFTECED_BY];

    if (affects.is_null() || !affects.is_array() || affects.empty()) {
        ANS_LOGI("GetCcmSwingRemind failed as invalid ccmSwingRemind json.");
        return;
    }

    for (auto &affect : affects) {
        if (affect.is_null() || !affect.is_object()) {
            continue;
        }
        if (affect[ReminderAffected::DEVICE_TYPE].is_null() ||
            !affect[ReminderAffected::DEVICE_TYPE].is_string() ||
            affect[ReminderAffected::STATUS].is_null() ||
            !affect[ReminderAffected::STATUS].is_string()) {
            continue;
        }
        enableSwingDeviceType_ = affect[ReminderAffected::DEVICE_TYPE].get<string>();
        enableSwingDeviceStatus_ = affect[ReminderAffected::STATUS].get<string>();
        ANS_LOGI("GetCcmSwingRemind deviceType: %{public}s  status: %{public}s", enableSwingDeviceType_.c_str(),
            enableSwingDeviceStatus_.c_str());
        isSupportSwingSmartRemind_ = true;
    }
}

string ReminderSwingDecisionCenter::GetSwingDeviceType()
{
    return enableSwingDeviceType_;
}

void ReminderSwingDecisionCenter::UpdateCrossDeviceNotificationStatus(bool isEnable)
{
    isCrossDeviceNotificationEnable_ = isEnable;
    ANS_LOGD("UpdateCrossDeviceNotificationStatus %{public}d", isEnable);
}

void ReminderSwingDecisionCenter::OnSmartReminderStatusChanged()
{
    SwingExecuteDecision(false);
}

void ReminderSwingDecisionCenter::DisableSwingStatus()
{
    if (!isSwingExecuting_) {
        return;
    }
    isSwingExecuting_ = false;
    lock_guard<mutex> lock(swingMutex_);
    if (swingCallback_ == nullptr) {
        return;
    }
    ANS_LOGD("DisableSwingStatus");
    swingCallback_->OnUpdateStatus(false, NONE_UNLOCK_TRIGGER);
}

void ReminderSwingDecisionCenter::SwingExecuteDecision(bool isScreenUnlockTrigger)
{
    ANS_LOGD("SwingExecuteDecision");
    if (!isSupportSwingSmartRemind_) {
        ANS_LOGI("is not SupportSwingSmartRemind");
        return;
    }

    if (!isCrossDeviceNotificationEnable_) {
        ANS_LOGI("crossDeviceNotification disable");
        DisableSwingStatus();
        return;
    }

    bool isSmartReminderEnable = false;
    if (ERR_OK != NotificationPreferences::GetInstance().IsSmartReminderEnabled(enableSwingDeviceType_,
        isSmartReminderEnable)) {
        ANS_LOGI("IsSmartReminderEnable error");
        return;
    }

    if (!isSmartReminderEnable) {
        ANS_LOGI("IsSmartReminderEnable false");
        DisableSwingStatus();
        return;
    }
    lock_guard<mutex> lock(swingMutex_);
    if (swingCallback_ == nullptr) {
        ANS_LOGI("swingCallback_ is null");
        return;
    }

    int triggerMode = isScreenUnlockTrigger ? UNLOCK_TRIGGER : NONE_UNLOCK_TRIGGER;
    bool isSwingCrossDeviceStatusStatified = IsStatifySwingCrossDeviceStatus();
    if (isScreenUnlock_ && isSwingCrossDeviceStatusStatified) {
        if (!isSwingExecuting_) {
            isSwingExecuting_ = true;
            swingCallback_->OnUpdateStatus(true, triggerMode);
            ANS_LOGI("swing OnUpdateStatus enable triggerMode %{public}d", triggerMode);
        } else {
            ANS_LOGD("isSwingExecuting_ %{public}d", isSwingExecuting_);
        }
    } else {
        if (isSwingExecuting_) {
            isSwingExecuting_ = false;
            swingCallback_->OnUpdateStatus(false, triggerMode);
            ANS_LOGI("swing OnUpdateStatus disable triggerMode %{public}d", triggerMode);
        } else {
            ANS_LOGD("isScreenUnlock_  %{public}d  isSwingCrossDeviceStatusStatified %{public}d ",
                isScreenUnlock_, isSwingCrossDeviceStatusStatified);
        }
    }
}

bool ReminderSwingDecisionCenter::IsStatifySwingCrossDeviceStatus()
{
    uint32_t status =
        DelayedSingleton<DistributedDeviceStatus>::GetInstance()->GetDeviceStatus(enableSwingDeviceType_);
    bool isSatisfied = SmartReminderCenter::GetInstance()->CompareStatus(enableSwingDeviceStatus_, bitset<4>(status));
    return isSatisfied;
}

void ReminderSwingDecisionCenter::OnUpdateDeviceStatus(const std::string &deviceType)
{
    if (deviceType.empty() || enableSwingDeviceType_.empty()) {
        return;
    }
    if (deviceType.compare(enableSwingDeviceType_) == 0) {
        SwingExecuteDecision(false);
    }
}

void ReminderSwingDecisionCenter::OnScreenLock()
{
    ANS_LOGI("OnScreenLock");
    if (isScreenUnlock_) {
        isScreenUnlock_ = false;
        SwingExecuteDecision(true);
    }
}

void ReminderSwingDecisionCenter::OnScreenUnlock()
{
    ANS_LOGI("OnScreenUnlock");
    if (!isScreenUnlock_) {
        isScreenUnlock_ = true;
        SwingExecuteDecision(true);
    }
}

void SwingCallbackRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    ANS_LOGI("Swing Callback died, remove the proxy object");
    ReminderSwingDecisionCenter::GetInstance().ResetSwingCallbackProxy();
}

SwingCallbackRecipient::SwingCallbackRecipient() {}

SwingCallbackRecipient::~SwingCallbackRecipient() {}
}
}
#endif