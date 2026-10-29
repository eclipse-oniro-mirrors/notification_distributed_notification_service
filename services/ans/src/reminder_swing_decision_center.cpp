/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "singleton.h"
#include "notification_preferences.h"
#include "smart_reminder_center.h"
#include "reminder_affected.h"

namespace OHOS {
namespace Notification {
using namespace std;
mutex ReminderSwingDecisionCenter::swingMutex_;
sptr<ISwingCallBack> ReminderSwingDecisionCenter::swingCallback_ = nullptr;

ReminderSwingDecisionCenter::ReminderSwingDecisionCenter()
{}

ReminderSwingDecisionCenter::~ReminderSwingDecisionCenter() {}

ReminderSwingDecisionCenter &ReminderSwingDecisionCenter::GetInstance()
{
    return DelayedRefSingleton<ReminderSwingDecisionCenter>::GetInstance();
}

ErrCode ReminderSwingDecisionCenter::RegisterSwingCallback(const sptr<IRemoteObject> &swingCallback)
{
    if (swingCallback == nullptr) {
        ANS_LOGE("swingCallback is null.");
        return ERR_INVALID_VALUE;
    }
    sptr<ISwingCallBack> swingCallBackProxy = iface_cast<ISwingCallBack>(swingCallback);
    if (swingCallBackProxy == nullptr) {
        ANS_LOGE("swingCallback is invalid.");
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject::DeathRecipient> recipient = nullptr;
    sptr<IRemoteObject> previousCallback = nullptr;
    {
        lock_guard<mutex> lock(swingMutex_);
        if (swingCallback_ != nullptr && swingCallback_->AsObject() == swingCallback) {
            ANS_LOGI("Swing callback is already registered.");
            return ERR_OK;
        }
        if (swingRecipient_ == nullptr) {
            swingRecipient_ = new (std::nothrow) SwingCallbackRecipient();
            if (swingRecipient_ == nullptr) {
                ANS_LOGE("Failed to create death Recipient ptr SwingCallbackRecipient!");
                return ERR_NO_INIT;
            }
        }
        recipient = swingRecipient_;
        if (swingCallback_ != nullptr) {
            previousCallback = swingCallback_->AsObject();
        }
        swingCallback_ = swingCallBackProxy;
    }
    if (previousCallback != nullptr && previousCallback != swingCallback) {
        previousCallback->RemoveDeathRecipient(recipient);
    }
    swingCallback->AddDeathRecipient(recipient);
    ANS_LOGI("RegisterSwingCallback OK");
    return ERR_OK;
}

void ReminderSwingDecisionCenter::ResetSwingCallbackProxy()
{
    ANS_LOGD("enter");
    sptr<IRemoteObject> callbackObj = nullptr;
    sptr<IRemoteObject::DeathRecipient> recipient = nullptr;
    {
        lock_guard<mutex> lock(swingMutex_);
        if (swingCallback_ == nullptr || swingCallback_->AsObject() == nullptr) {
            ANS_LOGE("invalid proxy state");
            return;
        }
        callbackObj = swingCallback_->AsObject();
        recipient = swingRecipient_;
        swingCallback_ = nullptr;
    }
    if (recipient != nullptr) {
        callbackObj->RemoveDeathRecipient(recipient);
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