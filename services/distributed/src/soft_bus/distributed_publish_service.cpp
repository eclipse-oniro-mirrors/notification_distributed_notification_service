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
#include "ans_image_util.h"
#include "in_process_call_wrapper.h"
#include "distributed_preference.h"
#include "distributed_liveview_all_scenarios_extension_wrapper.h"

namespace OHOS {
namespace Notification {

namespace {
constexpr char const DISTRIBUTED_LABEL[] = "ans_distributed";
}

void DistributedService::SetNotifictaionContent(const NotifticationRequestBox& box, sptr<NotificationRequest>& request,
    int32_t contentType)
{
    std::string title;
    std::string context;
    box.GetNotificationText(context);
    box.GetNotificationTitle(title);
    std::shared_ptr<NotificationContent> content;
    NotificationContent::Type type = static_cast<NotificationContent::Type>(contentType);
    switch (type) {
        case NotificationContent::Type::BASIC_TEXT: {
            auto pContent = std::make_shared<NotificationNormalContent>();
            pContent->SetText(context);
            pContent->SetTitle(title);
            content = std::make_shared<NotificationContent>(pContent);
            break;
        }
        case NotificationContent::Type::CONVERSATION: {
            auto pContent = std::make_shared<NotificationConversationalContent>();
            pContent->SetText(context);
            pContent->SetTitle(title);
            content = std::make_shared<NotificationContent>(pContent);
            break;
        }
        case NotificationContent::Type::LONG_TEXT: {
            auto pContent = std::make_shared<NotificationLongTextContent>();
            pContent->SetLongText(context);
            pContent->SetTitle(title);
            content = std::make_shared<NotificationContent>(pContent);
            break;
        }
        case NotificationContent::Type::MULTILINE: {
            auto pContent = std::make_shared<NotificationMultiLineContent>();
            pContent->SetText(context);
            pContent->SetTitle(title);
            content = std::make_shared<NotificationContent>(pContent);
            break;
        }
        case NotificationContent::Type::PICTURE: {
            auto pContent = std::make_shared<NotificationPictureContent>();
            pContent->SetText(context);
            pContent->SetTitle(title);
            content = std::make_shared<NotificationContent>(pContent);
            break;
        }
        default:
            break;
    }
    request->SetContent(content);
}

void DistributedService::MakeNotifictaionContent(const NotifticationRequestBox& box, sptr<NotificationRequest>& request,
    bool isCommonLiveView, int32_t contentType)
{
    if (isCommonLiveView) {
        std::vector<uint8_t> buffer;
        if (box.GetCommonLiveView(buffer)) {
            std::string title;
            std::string context;
            box.GetNotificationText(context);
            box.GetNotificationTitle(title);
            auto liveviewContent = std::make_shared<NotificationLiveViewContent>();
            liveviewContent->SetText(context);
            liveviewContent->SetTitle(title);
            auto content = std::make_shared<NotificationContent>(liveviewContent);
            request->SetContent(content);
            std::shared_ptr<AAFwk::WantParams> extraInfo = std::make_shared<AAFwk::WantParams>();
            liveviewContent->SetExtraInfo(extraInfo);
            DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewDecodeContent(request, buffer);
        }
        return;
    }
    SetNotifictaionContent(box, request, contentType);
}

void DistributedService::MakeNotifictaionIcon(const NotifticationRequestBox& box, sptr<NotificationRequest>& request,
    bool isCommonLiveView)
{
    std::shared_ptr<Media::PixelMap> icon;
    if (box.GetBigIcon(icon)) {
        request->SetBigIcon(icon);
    }
    if (box.GetOverlayIcon(icon)) {
        request->SetOverlayIcon(icon);
    }

    if (isCommonLiveView) {
        std::string bundleName;
        if (!box.GetCreatorBundleName(bundleName)) {
            return;
        }
        std::string icon;
        DistributedPreferences::GetInstance().GetIconByBundleName(bundleName, icon);
        if (!icon.empty()) {
            auto iconPixelMap = AnsImageUtil::UnPackImage(icon);
            request->SetLittleIcon(iconPixelMap);
        }
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
    int32_t slotType = 0;
    int32_t contentType = 0;
    NotifticationRequestBox requestBox = NotifticationRequestBox(boxMessage);
    bool isCommonLiveView = false;
    if (requestBox.GetSlotType(slotType) && requestBox.GetContentType(contentType)) {
        isCommonLiveView =
            (static_cast<NotificationContent::Type>(contentType) == NotificationContent::Type::LIVE_VIEW) &&
            (static_cast<NotificationConstant::SlotType>(slotType) == NotificationConstant::SlotType::LIVE_VIEW);
    }
    MakeNotifictaionContent(requestBox, request, isCommonLiveView, contentType);
    MakeNotifictaionIcon(requestBox, request, isCommonLiveView);
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
        hasdCode, NotificationConstant::DISTRIBUTED_COLLABORATIVE_DELETE));
    ANS_LOGI("dans remove message %{public}d.", result);
}

void DistributedService::RemoveNotifictaions(const std::shared_ptr<TlvBox>& boxMessage)
{
    std::vector<std::string> hasdCodes;
    if (boxMessage == nullptr) {
        ANS_LOGE("boxMessage is nullptr");
        return;
    }
    boxMessage->GetVectorValue(BATCH_REMOVE_NOTIFICATIONS, hasdCodes);
    int result = IN_PROCESS_CALL(
        NotificationHelper::RemoveNotifications(hasdCodes, NotificationConstant::DISTRIBUTED_COLLABORATIVE_DELETE));
    ANS_LOGI("dans batch remove message %{public}d.", result);
}
}
}
