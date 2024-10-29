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

#include "notification_subscriber.h"

#include "notification_constant.h"
#include "hitrace_meter_adapter.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Notification {
NotificationSubscriber::NotificationSubscriber()
{
    deviceType_ = NotificationConstant::CURRENT_DEVICE_TYPE;
};

NotificationSubscriber::~NotificationSubscriber()
{}

void NotificationSubscriber::SetDeviceType(const std::string &deviceType)
{
    deviceType_ = deviceType;
}

std::string NotificationSubscriber::GetDeviceType() const
{
    return deviceType_;
}

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
bool NotificationSubscriber::ProcessSyncDecision(
    const std::string &deviceType, std::shared_ptr<Notification> &notification) const
{
    sptr<NotificationRequest> request = notification->GetNotificationRequestPoint();
    if (request == nullptr) {
        ANS_LOGE("No need to consume cause invalid reqeuest.");
        return false;
    }
    auto flagsMap = request->GetDeviceFlags();
    if (flagsMap == nullptr || flagsMap->size() <= 0) {
        return true;
    }
    auto flagIter = flagsMap->find(deviceType);
    if (flagIter != flagsMap->end() && flagIter->second != nullptr) {
        ANS_LOGI("SetFlags-before filte, notificationKey = %{public}s flagIter \
            flags = %{public}d, deviceType:%{public}s",
            request->GetKey().c_str(), flagIter->second->GetReminderFlags(), deviceType.c_str());
        std::shared_ptr<NotificationFlags> tempFlags = request->GetFlags();
        tempFlags->SetSoundEnabled(DowngradeReminder(tempFlags->IsSoundEnabled(), flagIter->second->IsSoundEnabled()));
        tempFlags->SetVibrationEnabled(
            DowngradeReminder(tempFlags->IsVibrationEnabled(), flagIter->second->IsVibrationEnabled()));
        tempFlags->SetLockScreenVisblenessEnabled(
            tempFlags->IsLockScreenVisblenessEnabled() && flagIter->second->IsLockScreenVisblenessEnabled());
        tempFlags->SetBannerEnabled(
            tempFlags->IsBannerEnabled() && flagIter->second->IsBannerEnabled());
        tempFlags->SetLightScreenEnabled(
            tempFlags->IsLightScreenEnabled() && flagIter->second->IsLightScreenEnabled());
        request->SetFlags(tempFlags);
        ANS_LOGI("SetFlags-after filte, notificationKey = %{public}s flags = %{public}d",
            request->GetKey().c_str(), tempFlags->GetReminderFlags());
        return true;
    }
    if (deviceType.size() <= 0 || deviceType.compare(NotificationConstant::CURRENT_DEVICE_TYPE) == 0) {
        return true;
    }
    ANS_LOGD("No need to consume cause cannot find deviceFlags. deviceType: %{public}s.", deviceType.c_str());
    return false;
}

NotificationConstant::FlagStatus NotificationSubscriber::DowngradeReminder(
    const NotificationConstant::FlagStatus &oldFlags, const NotificationConstant::FlagStatus &judgeFlags) const
{
    if (judgeFlags == NotificationConstant::FlagStatus::NONE || oldFlags == NotificationConstant::FlagStatus::NONE) {
        return NotificationConstant::FlagStatus::NONE;
    }
    if (judgeFlags > oldFlags) {
        return judgeFlags;
    } else {
        return oldFlags;
    }
}
#endif

std::shared_ptr<NotificationSubscriber> NotificationSubscriber::GetSharedPtr() const
{
    std::weak_ptr<const NotificationSubscriber> wptr = weak_from_this();
    return std::const_pointer_cast<NotificationSubscriber>(wptr.lock());
}
}  // namespace Notification
}  // namespace OHOS
