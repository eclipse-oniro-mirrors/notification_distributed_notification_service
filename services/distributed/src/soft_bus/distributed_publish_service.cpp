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
#include "distributed_service.h"

#include "notification_helper.h"
#include "distributed_client.h"
#include "request_box.h"
#include "state_box.h"
#include "in_process_call_wrapper.h"

namespace OHOS {
namespace Notification {

namespace {
constexpr char const DISTRIBUTED_LABEL[] = "ans_distributed";
}

void DistributedService::MakeNotifictaionContent(const NotifticationRequestBox& box, NotificationRequest& request)
{
    std::string context;
    std::shared_ptr<NotificationNormalContent> noramlContent = std::make_shared<NotificationNormalContent>();
    if (box.GetNotificationText(context)) {
        noramlContent->SetText(context);
    }
    if (box.GetNotificationTitle(context)) {
        noramlContent->SetTitle(context);
    }
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(noramlContent);
    request.SetContent(content);
}

void DistributedService::MakeNotifictaionIcon(const NotifticationRequestBox& box, NotificationRequest& request)
{
    std::shared_ptr<Media::PixelMap> icon;
    if (box.GetBigIcon(icon)) {
        request.SetBigIcon(icon);
    }
    if (box.GetOverlayIcon(icon)) {
        request.SetOverlayIcon(icon);
    }
}

void DistributedService::MakeNotifictaionReminderFlag(const NotifticationRequestBox& box,
    NotificationRequest& request)
{
    int32_t type = 0;
    std::string context;
    if (box.GetSlotType(type)) {
        request.SetSlotType(static_cast<NotificationConstant::SlotType>(type));
    }
    if (box.GetReminderFlag(type)) {
        uint32_t controlFlags = 0;
        if (!(type & NotificationConstant::ReminderFlag::SOUND_FLAG)) {
            controlFlags |= NotificationConstant::ReminderFlag::SOUND_FLAG;
        }
        if (!(type & NotificationConstant::ReminderFlag::VIBRATION_FLAG)) {
            controlFlags |= NotificationConstant::ReminderFlag::VIBRATION_FLAG;
        }
        request.SetNotificationControlFlags(controlFlags);
    }
    if (box.GetCreatorBundleName(context)) {
        request.SetCreatorBundleName(context);
    }
    if (box.GetNotificationHashCode(context)) {
        request.SetDistributedHashCode(context);
    }
    request.SetDistributedCollaborate(true);
    request.SetLabel(DISTRIBUTED_LABEL);
}

void DistributedService::PublishNotifictaion(const std::shared_ptr<TlvBox>& boxMessage)
{
    NotificationRequest request;
    NotifticationRequestBox requestBox = NotifticationRequestBox(boxMessage);
    MakeNotifictaionContent(requestBox, request);
    MakeNotifictaionIcon(requestBox, request);
    MakeNotifictaionReminderFlag(requestBox, request);
    int result = IN_PROCESS_CALL(NotificationHelper::PublishNotification(request));
    ANS_LOGI("Dans publish message %{public}s %{public}d.", request.Dump().c_str(), result);
}

}
}
