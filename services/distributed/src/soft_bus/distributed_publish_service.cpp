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
#include "distributed_liveview_all_scenarios_extension_wrapper.h"

namespace OHOS {
namespace Notification {

namespace {
constexpr char const DISTRIBUTED_LABEL[] = "ans_distributed";
}

void DistributedService::MakeNotifictaionContent(const NotifticationRequestBox& box, sptr<NotificationRequest>& request)
{
    int32_t slotType = 0;
    int32_t contentType = 0;
    bool isCommonLiveView = false;
    if (box.GetSlotType(slotType) && box.GetContentType(contentType)) {
        isCommonLiveView =
            (static_cast<NotificationConstant::SlotType>(slotType) == NotificationConstant::SlotType::LIVE_VIEW) &&
            (static_cast<NotificationContent::Type>(contentType) == NotificationContent::Type::LIVE_VIEW);
    }
    if (isCommonLiveView) {
        std::vector<uint8_t> buffer;
        if (box.GetCommonLiveView(buffer)) {
            auto liveviewContent = std::make_shared<NotificationLiveViewContent>();
            auto content = std::make_shared<NotificationContent>(liveviewContent);
            request->SetContent(content);
            std::shared_ptr<AAFwk::WantParams> extraInfo = std::make_shared<AAFwk::WantParams>();
            liveviewContent->SetExtraInfo(extraInfo);
            DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewDecodeContent(request, buffer);
        }
    } else {
        std::string context;
        std::shared_ptr<NotificationNormalContent> noramlContent = std::make_shared<NotificationNormalContent>();
        if (box.GetNotificationText(context)) {
            noramlContent->SetText(context);
        }
        if (box.GetNotificationTitle(context)) {
            noramlContent->SetTitle(context);
        }
        std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(noramlContent);
        request->SetContent(content);
    }
}

void DistributedService::MakeNotifictaionIcon(const NotifticationRequestBox& box, sptr<NotificationRequest>& request)
{
    std::shared_ptr<Media::PixelMap> icon;
    if (box.GetBigIcon(icon)) {
        request->SetBigIcon(icon);
    }
    if (box.GetOverlayIcon(icon)) {
        request->SetOverlayIcon(icon);
    }
}

void DistributedService::MakeNotifictaionReminderFlag(const NotifticationRequestBox& box,
    sptr<NotificationRequest>& request)
{
    int32_t type = 0;
    std::string context;
    if (box.GetSlotType(type)) {
        request->SetSlotType(static_cast<NotificationConstant::SlotType>(type));
    }
    if (box.GetReminderFlag(type)) {
        uint32_t controlFlags = 0;
        if (!(type & NotificationConstant::ReminderFlag::SOUND_FLAG)) {
            controlFlags |= NotificationConstant::ReminderFlag::SOUND_FLAG;
        }
        if (!(type & NotificationConstant::ReminderFlag::VIBRATION_FLAG)) {
            controlFlags |= NotificationConstant::ReminderFlag::VIBRATION_FLAG;
        }
        request->SetNotificationControlFlags(controlFlags);
    }
    if (box.GetCreatorBundleName(context)) {
        request->SetCreatorBundleName(context);
    }
    if (box.GetNotificationHashCode(context)) {
        request->SetDistributedHashCode(context);
    }
    request->SetDistributedCollaborate(true);
    request->SetLabel(DISTRIBUTED_LABEL);
}

void DistributedService::PublishNotifictaion(const std::shared_ptr<TlvBox>& boxMessage)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    if (request == nullptr) {
        ANS_LOGE("NotificationRequest is nullptr");
        return;
    }
    NotifticationRequestBox requestBox = NotifticationRequestBox(boxMessage);
    MakeNotifictaionContent(requestBox, request);
    MakeNotifictaionIcon(requestBox, request);
    MakeNotifictaionReminderFlag(requestBox, request);
    int result = IN_PROCESS_CALL(NotificationHelper::PublishNotification(*request));
    ANS_LOGI("Dans publish message %{public}s %{public}d.", request->Dump().c_str(), result);
}

void DistributedService::RemoveNotifictaion(const std::shared_ptr<TlvBox>& boxMessage)
{
    std::string hasdCode;
    if (boxMessage == nullptr) {
        ANS_LOGE("boxMessage is nullptr");
        return;
    }
    boxMessage->GetStringValue(NOTIFICATION_HASHCODE, hasdCode);
    int result = IN_PROCESS_CALL(NotificationHelper::RemoveNotification(
        hasdCode, NotificationConstant::REMOVE_REASON_CROSS_DEVICE));
    ANS_LOGI("dans remove message %{public}d.", result);
}

void DistributedService::RemoveNotifictaions(const std::shared_ptr<TlvBox>& boxMessage)
{
    std::vector<std::string> hasdCodes;
    if (boxMessage == nullptr) {
        ANS_LOGE("boxMessage is nullptr");
        return;
    }
    boxMessage->GetVectorValue(NOTIFICATION_KEYS, hasdCodes);
    int result = IN_PROCESS_CALL(
        NotificationHelper::RemoveNotifications(hasdCodes, NotificationConstant::REMOVE_REASON_CROSS_DEVICE));
    ANS_LOGI("dans batch remove message %{public}d.", result);
}
}
}
