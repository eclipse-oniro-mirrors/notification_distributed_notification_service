/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef MOCK_NOTIFICATION_REQUEST_BUILDER_H
#define MOCK_NOTIFICATION_REQUEST_BUILDER_H

#include "mock_fuzz_object.h"
#include "mock_notification_content.h"
#include "mock_notification_distributed_options.h"
#include "mock_notification_template.h"
#include "mock_notification_flags.h"
#include "mock_notification_bundle_option.h"
#include "mock_notification_action_button.h"
#include "mock_pixel_map.h"
#include "mock_want_params.h"
#include "notification_request.h"


namespace OHOS {
namespace Notification {
void GenerateBooleanTypeVeriables(FuzzedDataProvider* fdp, NotificationRequest* request)
{
    request->SetColorEnabled(fdp->ConsumeBool());
    request->SetAlertOneTime(fdp->ConsumeBool());
    request->SetShowStopwatch(fdp->ConsumeBool());
    request->SetCountdownTimer(fdp->ConsumeBool());
    request->SetInProgress(fdp->ConsumeBool());
    request->SetGroupOverview(fdp->ConsumeBool());
    request->SetUnremovable(fdp->ConsumeBool());
    request->SetFloatingIcon(fdp->ConsumeBool());
    request->SetOnlyLocal(fdp->ConsumeBool());
    request->SetPermitSystemGeneratedContextualActionButtons(fdp->ConsumeBool());
    request->SetIsAgentNotification(fdp->ConsumeBool());
    request->SetRemoveAllowed(fdp->ConsumeBool());
    request->SetIsCoverActionButtons(fdp->ConsumeBool());
    request->SetUpdateByOwnerAllowed(fdp->ConsumeBool());
    request->SetUpdateOnly(fdp->ConsumeBool());
    request->SetForceDistributed(fdp->ConsumeBool());
    request->SetNotDistributed(fdp->ConsumeBool());
    request->SetInProgress(fdp->ConsumeBool());
    request->SetIsSystemApp(fdp->ConsumeBool());
    request->SetIsDoNotDisturbByPassed(fdp->ConsumeBool());
    request->SetDistributedCollaborate(fdp->ConsumeBool());
    ANS_LOGE("Build mock veriables");
}

void GenerateIntegerTypeVeriables(FuzzedDataProvider* fdp, NotificationRequest* request)
{
    request->SetPublishDelayTime(fdp->ConsumeIntegral<uint32_t>());
    request->SetNotificationId(fdp->ConsumeIntegral<int32_t>());
    request->SetColor(fdp->ConsumeIntegral<uint32_t>());
    request->SetBadgeNumber(fdp->ConsumeIntegral<uint32_t>());
    request->SetNotificationControlFlags(fdp->ConsumeIntegral<uint32_t>());
    request->SetCreateTime(fdp->ConsumeIntegral<int64_t>());
    request->SetDeliveryTime(fdp->ConsumeIntegral<int64_t>());
    request->SetAutoDeletedTime(fdp->ConsumeIntegral<int64_t>());
    request->SetUpdateDeadLine(fdp->ConsumeIntegral<int64_t>());
    request->SetFinishDeadLine(fdp->ConsumeIntegral<int64_t>());
    request->SetArchiveDeadLine(fdp->ConsumeIntegral<int64_t>());
    if (fdp->ConsumeIntegral<uint32_t>() % 3 == 0) {
        request->SetCreatorPid(fdp->ConsumeIntegral<pid_t>());
    }
    if (fdp->ConsumeIntegral<uint32_t>() % 3 == 0) {
        request->SetCreatorUid(fdp->ConsumeIntegralInRange<int32_t>(0, 10000));
    }
    if (fdp->ConsumeIntegral<uint32_t>() % 3 == 0) {
        request->SetOwnerUid(fdp->ConsumeIntegralInRange<int32_t>(0, 10000));
    }
    if (fdp->ConsumeIntegral<uint32_t>() % 3 == 0) {
        request->SetCreatorUserId(fdp->ConsumeIntegralInRange<int32_t>(0, 105));
    }
    if (fdp->ConsumeIntegral<uint32_t>() % 3 == 0) {
        request->SetOwnerUserId(fdp->ConsumeIntegralInRange<int32_t>(0, 105));
    }
    if (fdp->ConsumeIntegral<uint32_t>() % 3 == 0) {
        request->SetReceiverUserId(fdp->ConsumeIntegralInRange<int32_t>(0, 105));
    }
    request->SetCreatorInstanceKey(fdp->ConsumeIntegral<int32_t>());
    request->SetHashCodeGenerateType(fdp->ConsumeIntegral<uint32_t>());
    request->SetCollaboratedReminderFlag(fdp->ConsumeIntegral<uint32_t>());
    ANS_LOGE("Build mock veriables");
}

void GenerateStringTypeVeriables(FuzzedDataProvider* fdp, NotificationRequest* request)
{
    request->SetAppInstanceKey(fdp->ConsumeRandomLengthString(20));
    request->SetSettingsText(fdp->ConsumeRandomLengthString(20));
    if (fdp->ConsumeIntegral<uint32_t>() % 3 == 0) {
        request->SetCreatorBundleName(fdp->ConsumeRandomLengthString(20));
    }
    if (fdp->ConsumeIntegral<uint32_t>() % 3 == 0) {
        request->SetOwnerBundleName(fdp->ConsumeRandomLengthString(20));
    }
    request->SetGroupName(fdp->ConsumeRandomLengthString(20));
    request->SetStatusBarText(fdp->ConsumeRandomLengthString(20));
    request->SetLabel(fdp->ConsumeRandomLengthString(20));
    request->SetShortcutId(fdp->ConsumeRandomLengthString(20));
    request->SetSortingKey(fdp->ConsumeRandomLengthString(20));
    request->SetClassification(fdp->ConsumeRandomLengthString(20));
    request->SetAppMessageId(fdp->ConsumeRandomLengthString(20));
    request->SetSound(fdp->ConsumeRandomLengthString(20));
    request->SetDistributedHashCode(fdp->ConsumeRandomLengthString(20));
    ANS_LOGE("Build mock veriables");
}

void GenerateEnumTypeVeriables(FuzzedDataProvider* fdp, NotificationRequest* request)
{
    request->SetBadgeIconStyle(static_cast<OHOS::Notification::NotificationRequest::BadgeStyle>(
        fdp->ConsumeIntegralInRange<int>(0, 3)));
    request->SetGroupAlertType(static_cast<OHOS::Notification::NotificationRequest::GroupAlertType>(
        fdp->ConsumeIntegralInRange<int>(0, 3)));
    request->SetSlotType(static_cast<OHOS::Notification::NotificationConstant::SlotType>(
        fdp->ConsumeIntegralInRange<int>(0, 5)));
    request->SetVisibleness(static_cast<OHOS::Notification::NotificationConstant::VisiblenessType>(
        fdp->ConsumeIntegralInRange<int>(0, 2)));
    ANS_LOGE("Build mock veriables");
}

template <>
NotificationRequest* ObjectBuilder<NotificationRequest>::Build(FuzzedDataProvider *fdp)
{
    auto request = new NotificationRequest();
    GenerateIntegerTypeVeriables(fdp, request);
    GenerateBooleanTypeVeriables(fdp, request);
    GenerateStringTypeVeriables(fdp, request);
    GenerateEnumTypeVeriables(fdp, request);

    if (NotificationConstant::SlotType::LIVE_VIEW == request->GetSlotType()) {
        std::shared_ptr<NotificationLiveViewContent> liveViewContent (
            ObjectBuilder<NotificationLiveViewContent>::Build(fdp));
        std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
        request->SetContent(content);
    } else {
        request->SetContent(ObjectBuilder<NotificationContent>::BuildSharedPtr(fdp));
    }
    request->SetTemplate(ObjectBuilder<NotificationTemplate>::BuildSharedPtr(fdp));
    request->SetBundleOption(ObjectBuilder<NotificationBundleOption>::BuildSharedPtr(fdp));
    request->SetAgentBundle(ObjectBuilder<NotificationBundleOption>::BuildSharedPtr(fdp));
    request->SetAdditionalData(ObjectBuilder<AAFwk::WantParams>::BuildSharedPtr(fdp));
    request->SetLittleIcon(ObjectBuilder<Media::PixelMap>::BuildSharedPtr(fdp));
    request->SetBigIcon(ObjectBuilder<Media::PixelMap>::BuildSharedPtr(fdp));
    request->SetOverlayIcon(ObjectBuilder<Media::PixelMap>::BuildSharedPtr(fdp));

    size_t actionCount = fdp->ConsumeIntegralInRange<size_t>(0, 3);
    for (size_t i = 0; i < actionCount; ++i) {
        request->AddActionButton(ObjectBuilder<NotificationActionButton>::BuildSharedPtr(fdp));
    }
    std::vector<std::string> devicesSupportDisplay;
    for(int i = 0; i < fdp->ConsumeIntegralInRange(0, 10); i++) {
        devicesSupportDisplay.push_back(fdp->ConsumeRandomLengthString());
    }
    request->SetDevicesSupportDisplay(devicesSupportDisplay);
    std::vector<std::string> devicesSupportOperate;
    for(int i = 0; i < fdp->ConsumeIntegralInRange(0, 10); i++) {
        devicesSupportOperate.push_back(fdp->ConsumeRandomLengthString());
    }
    request->SetDevicesSupportOperate(devicesSupportOperate);
    std::vector<std::string> userInputHistory;
    for(int i = 0; i < fdp->ConsumeIntegralInRange(0, 10); i++) {
        userInputHistory.push_back(fdp->ConsumeRandomLengthString());
    }
    request->SetNotificationUserInputHistory(userInputHistory);
    ANS_LOGE("Build mock veriables");
    return request;
}

} // namespace Notification
} // namespace OHOS

#endif // MOCK_NOTIFICATION_REQUEST_BUILDER_H
