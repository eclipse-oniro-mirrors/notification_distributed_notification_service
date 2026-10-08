/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "notificationrequest_fuzzer.h"
#define private public
#define protected public
#include "notification_request.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "message_user.h"
#include "notification_action_button.h"
#include "notification_conversational_content.h"
#include "notification_local_live_view_content.h"
#include "notification_long_text_content.h"
#include "notification_multiline_content.h"
#include "notification_normal_content.h"
#include "notification_picture_content.h"

namespace OHOS {
    namespace {
        constexpr uint8_t FLAG_STATUS = 11;
        constexpr uint8_t SLOT_TYPE_NUM = 9;
        constexpr uint8_t SLOT_VISIBLENESS_TYPE_NUM = 5;
        constexpr uint8_t BADGE_STYLE_NUM = 4;
        constexpr uint8_t GROUP_ALERT_TYPE_NUM = 4;
        constexpr uint8_t LIVE_VIEW_STATUS_NUM = 7;
        constexpr size_t OVERLONG_STRING_LEN = 1024;
        constexpr size_t FUZZ_STRING_MAX_LEN = 64;
        constexpr size_t FUZZ_STRING_SHORT_LEN = 32;
        constexpr size_t FUZZ_STRING_BUNDLE_LEN = 16;
        constexpr uint8_t FIXED_BOUNDARY_COUNT = 5;
        constexpr uint8_t BOUNDARY_KIND_COUNT = FIXED_BOUNDARY_COUNT + 1;

        std::string BuildBoundaryString(FuzzedDataProvider *fdp)
        {
            static const std::string fixedBoundaries[] = {
                std::string(),
                std::string(OVERLONG_STRING_LEN, 'x'),
                "\xe4\xbd\xa0\xe5\xa5\xbd\xe4\xb8\x96\xe7\x95\x8c\xf0\x9f\x8e\x89",
                "%s%s%d%n\\\\..\\/..\\/etc",
                "\x01\x02\x03\x7f\xff",
            };
            uint8_t kind = fdp->ConsumeIntegralInRange<uint8_t>(0, BOUNDARY_KIND_COUNT - 1);
            if (kind < FIXED_BOUNDARY_COUNT) {
                return fixedBoundaries[kind];
            }
            return fdp->ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN);
        }

        void TestIntegerFieldCombinations(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
        {
            request.SetNotificationId(fdp->ConsumeIntegral<int32_t>());
            request.GetNotificationId();
            request.SetBadgeNumber(fdp->ConsumeIntegral<uint32_t>());
            request.SetNotificationControlFlags(fdp->ConsumeIntegral<uint32_t>());
            request.GetNotificationControlFlags();
            request.SetDeliveryTime(fdp->ConsumeIntegral<int64_t>());
            request.SetAutoDeletedTime(fdp->ConsumeIntegral<int64_t>());
            request.GetAutoDeletedTime();
            request.SetUpdateDeadLine(fdp->ConsumeIntegral<int64_t>());
            request.GetUpdateDeadLine();
            request.SetFinishDeadLine(fdp->ConsumeIntegral<int64_t>());
            request.GetFinishDeadLine();
            request.SetGeofenceTriggerDeadLine(fdp->ConsumeIntegral<int64_t>());
            request.GetGeofenceTriggerDeadLine();
            request.SetArchiveDeadLine(fdp->ConsumeIntegral<int64_t>());
            request.GetArchiveDeadLine();
            request.SetCreateTime(fdp->ConsumeIntegral<int64_t>());
            request.GetCreateTime();
            request.SetColor(fdp->ConsumeIntegral<uint32_t>());
            request.GetColor();
            request.SetProgressBar(fdp->ConsumeIntegral<int32_t>(), fdp->ConsumeIntegral<int32_t>(),
                fdp->ConsumeBool());
            request.GetProgressMax();
            request.GetProgressValue();
            request.IsProgressIndeterminate();
            request.SetCreatorUid(fdp->ConsumeIntegral<int32_t>());
            request.GetCreatorUid();
            request.GetCreatorPid();
            request.SetOwnerUid(fdp->ConsumeIntegral<int32_t>());
            request.GetOwnerUid();
            request.SetCreatorUserId(fdp->ConsumeIntegral<int32_t>());
            request.GetCreatorUserId();
            request.SetCreatorInstanceKey(fdp->ConsumeIntegral<int32_t>());
            request.GetCreatorInstanceKey();
            request.SetOwnerUserId(fdp->ConsumeIntegral<int32_t>());
            request.GetOwnerUserId();
            request.SetReceiverUserId(fdp->ConsumeIntegral<int32_t>());
            request.GetReceiverUserId();
            request.SetHashCodeGenerateType(fdp->ConsumeIntegral<uint32_t>());
            request.SetCollaboratedReminderFlag(fdp->ConsumeIntegral<uint32_t>());
            request.GetCollaboratedReminderFlag();
            request.SetPublishDelayTime(fdp->ConsumeIntegral<uint32_t>());
            request.GetPublishDelayTime();
            request.SetAppIndex(fdp->ConsumeIntegral<int32_t>());
            request.GetAppIndex();
            request.GetConsumedDeviceFlag();
        }

        void TestStringFieldCombinations(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
        {
            std::string boundary = BuildBoundaryString(fdp);
            request.SetClassification(boundary);
            request.GetClassification();
            request.SetGroupName(boundary);
            request.GetGroupName();
            request.SetSettingsText(boundary);
            request.GetSettingsText();
            request.SetSortingKey(boundary);
            request.GetSortingKey();
            request.SetStatusBarText(boundary);
            request.GetStatusBarText();
            request.SetShortcutId(boundary);
            request.GetShortcutId();
            request.SetOwnerBundleName(boundary);
            request.GetOwnerBundleName();
            request.SetCreatorBundleName(boundary);
            request.GetCreatorBundleName();
            request.SetLabel(boundary);
            request.GetLabel();
            request.SetAppInstanceKey(boundary);
            request.GetAppInstanceKey();
            request.SetAppMessageId(boundary);
            request.GetAppMessageId();
            request.SetSound(boundary);
            request.GetSound();
            request.SetDistributedHashCode(boundary);
            request.GetDistributedHashCode();
            request.SetAppName(boundary);
            request.GetAppName();
            request.SetPriorityNotificationType(boundary);
            request.SetInnerPriorityNotificationType(boundary);
            request.GetPriorityNotificationType();
            request.AdddeviceStatu(boundary, boundary);
            request.GetdeviceStatus();
        }

        void TestBoolFieldCombinations(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
        {
            bool enabled = fdp->ConsumeBool();
            request.SetIsAgentNotification(enabled);
            request.IsAlertOneTime();
            request.SetAlertOneTime(enabled);
            request.IsCountdownTimer();
            request.SetCountdownTimer(enabled);
            request.IsGroupOverview();
            request.SetGroupOverview(enabled);
            request.IsOnlyLocal();
            request.SetOnlyLocal(enabled);
            request.IsShowStopwatch();
            request.SetShowStopwatch(enabled);
            request.IsTapDismissed();
            request.SetTapDismissed(enabled);
            request.SetFloatingIcon(enabled);
            request.IsFloatingIcon();
            request.IsColorEnabled();
            request.SetColorEnabled(enabled);
            request.IsRemoveAllowed();
            request.SetRemoveAllowed(enabled);
            request.IsForceDistributed();
            request.SetForceDistributed(enabled);
            request.IsNotDistributed();
            request.SetNotDistributed(enabled);
            request.IsSystemApp();
            request.SetIsSystemApp(enabled);
            request.IsDoNotDisturbByPassed();
            request.SetIsDoNotDisturbByPassed(enabled);
            request.SetIsCoverActionButtons(enabled);
            request.IsCoverActionButtons();
            request.SetUpdateByOwnerAllowed(enabled);
            request.IsUpdateByOwnerAllowed();
            request.SetUpdateOnly(enabled);
            request.IsUpdateOnly();
            request.SetDistributedCollaborate(enabled);
            request.GetDistributedCollaborate();
            request.SetDistributed(enabled);
        }

        void TestEnumFieldCombinations(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
        {
            Notification::NotificationConstant::SlotType slotType =
                Notification::NotificationConstant::SlotType(fdp->ConsumeIntegral<uint8_t>() % SLOT_TYPE_NUM);
            request.SetSlotType(slotType);
            request.GetSlotType();
            Notification::NotificationConstant::VisiblenessType visibleness =
                Notification::NotificationConstant::VisiblenessType(
                    fdp->ConsumeIntegral<uint8_t>() % SLOT_VISIBLENESS_TYPE_NUM);
            request.SetVisibleness(visibleness);
            request.GetVisibleness();
            Notification::NotificationRequest::BadgeStyle badgeStyle =
                Notification::NotificationRequest::BadgeStyle(
                    fdp->ConsumeIntegral<uint8_t>() % BADGE_STYLE_NUM);
            request.SetBadgeIconStyle(badgeStyle);
            request.GetBadgeIconStyle();
            Notification::NotificationRequest::GroupAlertType groupAlertType =
                Notification::NotificationRequest::GroupAlertType(
                    fdp->ConsumeIntegral<uint8_t>() % GROUP_ALERT_TYPE_NUM);
            request.SetGroupAlertType(groupAlertType);
            request.GetGroupAlertType();
            Notification::NotificationLiveViewContent::LiveViewStatus liveViewStatus =
                Notification::NotificationLiveViewContent::LiveViewStatus(
                    fdp->ConsumeIntegral<uint8_t>() % LIVE_VIEW_STATUS_NUM);
            request.SetLiveViewStatus(liveViewStatus);
            request.GetLiveViewStatus();
        }

        void TestContentFieldCombinations(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
        {
            std::shared_ptr<Notification::NotificationNormalContent> normalContent =
                std::make_shared<Notification::NotificationNormalContent>();
            normalContent->SetText(fdp->ConsumeRandomLengthString(FUZZ_STRING_SHORT_LEN));
            normalContent->SetTitle(fdp->ConsumeRandomLengthString(FUZZ_STRING_SHORT_LEN));
            std::shared_ptr<Notification::NotificationContent> content =
                std::make_shared<Notification::NotificationContent>(normalContent);
            request.SetContent(content);
            request.GetContent();
            request.GetNotificationType();
            request.SetContent(nullptr);
            request.GetNotificationType();

            std::shared_ptr<Media::PixelMap> pixelMap = std::make_shared<Media::PixelMap>();
            request.SetLittleIcon(pixelMap);
            request.GetLittleIcon();
            request.SetBigIcon(pixelMap);
            request.ResetBigIcon();
            request.GetBigIcon();
            request.SetOverlayIcon(pixelMap);
            request.GetOverlayIcon();
            Notification::NotificationRequest::CheckImageOverSizeForPixelMap(nullptr, 1);
            Notification::NotificationRequest::CheckImageOverSizeForPixelMap(pixelMap, 0);

            std::shared_ptr<Notification::MessageUser> messageUser =
                std::make_shared<Notification::MessageUser>();
            request.AddMessageUser(messageUser);
            request.AddMessageUser(nullptr);
            request.GetMessageUsers();

            std::shared_ptr<AAFwk::WantParams> extendInfo = std::make_shared<AAFwk::WantParams>();
            request.SetExtendInfo(extendInfo);
            request.GetExtendInfo();
            request.SetMaxScreenWantAgent(nullptr);
        }

        void TestParcelableFieldCombinations(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
        {
            request.SetTemplate(std::make_shared<Notification::NotificationTemplate>());
            request.GetTemplate();
            std::shared_ptr<Notification::NotificationFlags> flags =
                std::make_shared<Notification::NotificationFlags>();
            flags->SetSoundEnabled(Notification::NotificationConstant::FlagStatus::OPEN);
            flags->SetVibrationEnabled(Notification::NotificationConstant::FlagStatus::CLOSE);
            flags->SetLockScreenEnabled(Notification::NotificationConstant::FlagStatus::OPEN);
            flags->SetBannerEnabled(Notification::NotificationConstant::FlagStatus::CLOSE);
            request.SetFlags(flags);
            request.GetFlags();
            using FlagsMap = std::map<std::string, std::shared_ptr<Notification::NotificationFlags>>;
            auto deviceFlags = std::make_shared<FlagsMap>();
            deviceFlags->emplace(fdp->ConsumeRandomLengthString(FUZZ_STRING_BUNDLE_LEN), flags);
            request.SetDeviceFlags(deviceFlags);
            request.GetDeviceFlags();

            request.SetBundleOption(std::make_shared<Notification::NotificationBundleOption>());
            request.GetBundleOption();
            request.SetAgentBundle(std::make_shared<Notification::NotificationBundleOption>());
            request.GetAgentBundle();
            request.SetNotificationTrigger(std::make_shared<Notification::NotificationTrigger>());
            request.GetNotificationTrigger();
            request.SetUnifiedGroupInfo(std::make_shared<Notification::NotificationUnifiedGroupInfo>());
            request.GetUnifiedGroupInfo();
            request.SetGroupInfo(std::make_shared<Notification::NotificationGroupInfo>());
            request.GetGroupInfo();

            std::vector<std::string> devices = { "", fdp->ConsumeRandomLengthString(FUZZ_STRING_BUNDLE_LEN) };
            request.SetDevicesSupportDisplay(devices);
            request.SetDevicesSupportOperate(devices);
            request.GetNotificationDistributedOptions();
            request.SetDistributedFlagBit(Notification::NotificationConstant::ReminderFlag::SOUND_FLAG,
                fdp->ConsumeBool(), { fdp->ConsumeRandomLengthString(FUZZ_STRING_BUNDLE_LEN) });

            std::vector<std::string> userInputHistory = { "", BuildBoundaryString(fdp) };
            request.SetNotificationUserInputHistory(userInputHistory);
            request.GetNotificationUserInputHistory();
            request.HasUserInputButton();
        }

        void TestKeyAndUtility(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
        {
            request.GetNotificationHashCode();
            request.GetKey();
            request.GetSecureKey();
            request.GetTriggerKey();
            request.GetTriggerSecureKey();
            request.GetBaseKey(fdp->ConsumeRandomLengthString(FUZZ_STRING_BUNDLE_LEN));
            request.GenerateUniqueKey();
            request.GenerateDistributedUniqueKey();
            request.IsCommonLiveView();
            request.IsSharedThirdpartyLiveView();
            request.IsSystemLiveView();
            request.IsTriggerLiveView();
            request.IsUpdateLiveView();
            request.IsAtomicServiceNotification();
            int32_t installStatus = 0;
            request.GetAtomicServiceInstallStatus(installStatus);
            request.CheckImageSizeForContent(fdp->ConsumeBool());

            sptr<Notification::NotificationRequest> other = new Notification::NotificationRequest();
            if (other != nullptr) {
                request.CheckNotificationRequest(other);
                request.FillMissingParameters(other);
                request.IncrementalUpdateLiveview(other);
            }
        }

        void TestJsonConversion(Notification::NotificationRequest &request)
        {
            nlohmann::json jsonObject;
            request.ToJson(jsonObject);
            Notification::NotificationRequest::FromJson(jsonObject);
            std::string collaborationData;
            request.CollaborationToJson(collaborationData);
            Notification::NotificationRequest::CollaborationFromJson(collaborationData);
            Notification::NotificationRequest *target = new (std::nothrow) Notification::NotificationRequest();
            if (target != nullptr) {
                Notification::NotificationRequest::ConvertJsonToTemplate(target, jsonObject);
                Notification::NotificationRequest::ConvertJsonToGroupInfo(target, jsonObject);
                delete target;
            }
        }

        void TestParcelRoundTrip(Notification::NotificationRequest &request)
        {
            Parcel parcel;
            if (!request.Marshalling(parcel)) {
                return;
            }
            parcel.RewindRead(0);
            Notification::NotificationRequest *unmarshalled = Notification::NotificationRequest::Unmarshalling(parcel);
            if (unmarshalled != nullptr) {
                unmarshalled->Dump();
                delete unmarshalled;
            }
        }
    }

    namespace {
        void TestActionButtonCombinations(FuzzedDataProvider *fdp, Notification::NotificationRequest &request,
            bool enabled)
        {
            // the default ctor is private; the public Create() factory is the supported entry
            std::shared_ptr<Notification::NotificationActionButton> actionButton =
                Notification::NotificationActionButton::Create(nullptr, "", nullptr);
            int32_t semanticAction = fdp->ConsumeIntegral<int32_t>() % FLAG_STATUS;
            Notification::NotificationConstant::SemanticActionButton semanticActionButton =
                Notification::NotificationConstant::SemanticActionButton(semanticAction);
            actionButton->SetSemanticActionButton(semanticActionButton);
            actionButton->SetAutoCreatedReplies(enabled);
            actionButton->SetContextDependent(enabled);
            request.AddActionButton(actionButton);
            request.GetActionButtons();
            request.ClearActionButtons();
            request.IsPermitSystemGeneratedContextualActionButtons();
            request.SetPermitSystemGeneratedContextualActionButtons(enabled);
        }
    }

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        std::string stringData = fdp->ConsumeRandomLengthString();
        int32_t notificationId = fdp->ConsumeIntegral<int32_t>();
        Notification::NotificationRequest request(notificationId);
        request.IsInProgress();
        bool enabled = fdp->ConsumeBool();
        request.SetInProgress(enabled);
        request.IsUnremovable();
        request.SetUnremovable(enabled);
        request.GetBadgeNumber();
        request.GetNotificationId();
        std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent = nullptr;
        request.SetWantAgent(wantAgent);
        request.GetWantAgent();
        request.SetRemovalWantAgent(wantAgent);
        request.GetRemovalWantAgent();
        request.GetMaxScreenWantAgent();
        std::shared_ptr<AAFwk::WantParams> extras = nullptr;
        request.SetAdditionalData(extras);
        request.GetAdditionalData();
        request.GetDeliveryTime();
        request.IsShowDeliveryTime();
        request.SetShowDeliveryTime(enabled);
        TestActionButtonCombinations(fdp, request, enabled);

        TestIntegerFieldCombinations(fdp, request);
        TestStringFieldCombinations(fdp, request);
        TestBoolFieldCombinations(fdp, request);
        TestEnumFieldCombinations(fdp, request);
        TestContentFieldCombinations(fdp, request);
        TestParcelableFieldCombinations(fdp, request);
        TestKeyAndUtility(fdp, request);
        TestJsonConversion(request);
        Notification::NotificationRequest copied(request);
        Notification::NotificationRequest assigned = copied;
        assigned = request;
        TestParcelRoundTrip(assigned);
        request.Dump();
        return request.IsAgentNotification();
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
