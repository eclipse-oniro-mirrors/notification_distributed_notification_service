/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "notificationrequestdeadlinesHXF_fuzzer.h"
#include "message_user.h"
#include "notification_action_button.h"
#include "notification_bundle_option.h"
#include "notification_constant.h"
#include "notification_content.h"
#include "notification_conversational_content.h"
#include "notification_flags.h"
#include "notification_geofence.h"
#include "notification_group_info.h"
#include "notification_live_view_content.h"
#include "notification_long_text_content.h"
#include "notification_media_content.h"
#include "notification_multiline_content.h"
#include "notification_normal_content.h"
#include "notification_picture_content.h"
#define private public // NOLINT
#define protected public // NOLINT
#include "notification_request.h"
#undef private // NOLINT
#undef protected // NOLINT
#include "notification_template.h"
#include "notification_trigger.h"
#include "notification_unified_group_Info.h"
#include "notification_user_input.h"
#include "parcel.h"
#include "pixel_map.h"
#include "string_wrapper.h"
#include "uri.h"
#include "want_params.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <array>
#include <cstdlib>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace OHOS {
    namespace {
        constexpr uint8_t VISIBLENESS_TYPE_NUM = 5;
        constexpr uint8_t GROUP_ALERT_TYPE_NUM  = 3;
        constexpr uint8_t BADGE_STYLE_NUM       = 3;
        constexpr uint8_t SLOT_TYPE_NUM         = 9;
        constexpr uint8_t MAX_PROGRESS          = 200;
        constexpr uint8_t DEVICE_LIST_MAX       = 4;
        constexpr size_t SHORT_STRING_MAX       = 64;
        constexpr size_t COMMON_STRING_MAX      = 128;
        constexpr size_t LONG_STRING_MAX        = 256;
        constexpr size_t LONG_TEXT_STRING_MAX   = 1200;
        constexpr size_t HISTORY_STRING_MAX     = 32;
        constexpr size_t DEVICE_STRING_MAX      = 32;
        constexpr size_t STRING_PROBE_MAX       = 256;
        constexpr int32_t SMALL_PIXEL_SIZE      = 16;
        constexpr int32_t LARGE_PIXEL_SIZE      = 256;
        constexpr int32_t PIXEL_BYTES           = 4;
        constexpr int64_t NEGATIVE_TIME         = -1;
        constexpr int64_t ZERO_TIME             = 0;
        constexpr int64_t ONE_TIME              = 1;
        constexpr int64_t TIME_BOUNDARY_STEP    = 1;
        constexpr int32_t DEFAULT_CREATOR_UID   = 1;
        constexpr uint8_t HISTORY_COUNT_EMPTY   = 0;
        constexpr uint8_t HISTORY_COUNT_SINGLE  = 1;
        constexpr uint8_t HISTORY_COUNT_LIMIT   = 5;
        constexpr uint8_t HISTORY_COUNT_OVER    = 6;
        constexpr uint8_t MULTI_LINE_COUNT      = 9;
        constexpr uint8_t INPUT_EDIT_TYPE_NUM   = 3;
        constexpr int16_t GEOFENCE_LONGITUDE_RANGE = 181;
        constexpr int16_t GEOFENCE_LATITUDE_RANGE  = 91;
        constexpr uint16_t GEOFENCE_RADIUS_RANGE   = 2000;
        constexpr uint16_t GEOFENCE_RADIUS_OFFSET  = 1;
        constexpr uint16_t GEOFENCE_DELAY_RANGE    = 400;
        constexpr uint32_t LIVE_OLD_VERSION        = 1;
        constexpr uint32_t LIVE_UPDATE_VERSION     = 2;
        constexpr uint32_t LIVE_END_VERSION        = 3;
        constexpr uint32_t HASH_CODE_GENERATE_TYPE = 1;
        constexpr uint32_t MEDIA_ACTION_PREVIOUS = 0;
        constexpr uint32_t MEDIA_ACTION_PLAY = 1;
        constexpr uint32_t MEDIA_ACTION_NEXT = 2;
        constexpr size_t AUTO_DELETE_TIME_COUNT = 9;
        constexpr size_t UPDATE_DEADLINE_COUNT = 9;
        constexpr size_t FINISH_DEADLINE_COUNT = 9;
        constexpr size_t TRIGGER_ARCHIVE_DEADLINE_COUNT = 11;
        constexpr size_t DELIVERY_TIME_COUNT = 10;
        constexpr uint8_t EMPTY_VECTOR_COUNT = 0;
        constexpr uint8_t SAFE_DIVISOR_FALLBACK = 1;

        constexpr uint8_t MODULO_ZERO_FALLBACK = 0;

        template <typename ValueType, typename DivisorType>
        DivisorType ModuloByNonZero(ValueType value, DivisorType divisor)
        {
            if (divisor == static_cast<DivisorType>(MODULO_ZERO_FALLBACK)) {
                return static_cast<DivisorType>(MODULO_ZERO_FALLBACK);
            }
            return static_cast<DivisorType>(value % divisor);
        }
        constexpr char WEARABLE_DEVICE_TYPE[] = "wearable";

        using AutoDeleteTimeValues = std::array<int64_t, AUTO_DELETE_TIME_COUNT>;
        using UpdateDeadlineValues = std::array<int64_t, UPDATE_DEADLINE_COUNT>;
        using FinishDeadlineValues = std::array<int64_t, FINISH_DEADLINE_COUNT>;
        using TriggerArchiveDeadlineValues = std::array<int64_t, TRIGGER_ARCHIVE_DEADLINE_COUNT>;
        using DeliveryTimeValues = std::array<int64_t, DELIVERY_TIME_COUNT>;
        using DeviceFlagMap = std::map<std::string, std::shared_ptr<Notification::NotificationFlags>>;
        using RequestPtr = sptr<Notification::NotificationRequest>;

        struct DeadlineFieldValues {
            AutoDeleteTimeValues autoDeleteTimes;
            UpdateDeadlineValues updateDeadLines;
            FinishDeadlineValues finishDeadLines;
            TriggerArchiveDeadlineValues triggerAndArchiveDeadLines;
            DeliveryTimeValues deliveryTimes;
        };
    }

    std::string ConsumeStringOrDefault(FuzzedDataProvider *fdp, size_t maxLength, const std::string &fallback)
    {
        std::string value = fdp->ConsumeRandomLengthString(maxLength);
        return value.empty() ? fallback : value;
    }

    uint8_t GetBoundedCount(uint8_t rawCount, uint8_t maxCount)
    {
        uint8_t divisor = maxCount == EMPTY_VECTOR_COUNT ? SAFE_DIVISOR_FALLBACK : maxCount;
        return ModuloByNonZero(rawCount, divisor);
    }

    std::vector<std::string> ConsumeStringVector(FuzzedDataProvider *fdp, uint8_t maxCount, size_t maxLength)
    {
        uint8_t itemCount = GetBoundedCount(fdp->ConsumeIntegral<uint8_t>(), maxCount);
        std::vector<std::string> values;
        for (uint8_t index = 0; index < itemCount; ++index) {
            values.emplace_back(fdp->ConsumeRandomLengthString(maxLength));
        }
        return values;
    }

    template<size_t N>
    int64_t PickBoundaryValue(FuzzedDataProvider *fdp, const std::array<int64_t, N> &values)
    {
        return values[ModuloByNonZero(fdp->ConsumeIntegral<uint8_t>(), N)];
    }

    std::shared_ptr<Media::PixelMap> MakePixelMap(int32_t width, int32_t height)
    {
        if (width <= ZERO_TIME || height <= ZERO_TIME) {
            return nullptr;
        }
        auto pixelMap = std::make_shared<Media::PixelMap>();
        if (pixelMap == nullptr) {
            return nullptr;
        }
        Media::ImageInfo info;
        info.size.width = width;
        info.size.height = height;
        info.pixelFormat = Media::PixelFormat::ARGB_8888;
        info.colorSpace = Media::ColorSpace::SRGB;
        pixelMap->SetImageInfo(info);

        int32_t rowDataSize = width * PIXEL_BYTES;
        uint32_t bufferSize = static_cast<uint32_t>(rowDataSize * height);
        void *buffer = std::malloc(bufferSize);
        if (buffer != nullptr) {
            pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, Media::AllocatorType::HEAP_ALLOC, nullptr);
        }
        return pixelMap;
    }

    std::shared_ptr<AAFwk::WantParams> MakeWantParams()
    {
        auto params = std::make_shared<AAFwk::WantParams>();
        if (params != nullptr) {
            params->SetParam("sys_traceid", AAFwk::String::Box("trace"));
            params->SetParam("TriggerPath", AAFwk::String::Box("cloud"));
        }
        return params;
    }

    Notification::MessageUser BuildMessageUser(FuzzedDataProvider *fdp,
        const std::shared_ptr<Media::PixelMap> &pixelMap)
    {
        Notification::MessageUser user;
        user.SetKey(ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, "message.user.key"));
        user.GetKey();
        user.SetName(ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, "message.user.name"));
        user.GetName();
        user.SetUri(Uri(ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, "uri://message.user")));
        user.SetMachine(fdp->ConsumeBool());
        user.IsMachine();
        user.SetUserAsImportant(fdp->ConsumeBool());
        user.IsUserImportant();
        user.SetPixelMap(pixelMap);
        user.GetPixelMap();
        user.Dump();
        return user;
    }

    std::shared_ptr<Notification::NotificationContent> BuildNormalContent(FuzzedDataProvider *fdp,
        const std::shared_ptr<Media::PixelMap> &pixelMap)
    {
        auto normalContent = std::make_shared<Notification::NotificationNormalContent>();
        normalContent->SetTitle(ConsumeStringOrDefault(fdp, COMMON_STRING_MAX, "normal.title"));
        normalContent->SetText(ConsumeStringOrDefault(fdp, LONG_STRING_MAX, "normal.text"));
        normalContent->SetAdditionalText(fdp->ConsumeRandomLengthString(COMMON_STRING_MAX));
        normalContent->SetLockScreenPicture(pixelMap);
        std::vector<std::pair<std::string, std::string>> structuredText = {
            {"key", fdp->ConsumeRandomLengthString(SHORT_STRING_MAX)},
            {"value", "normal"},
        };
        normalContent->SetStructuredText(structuredText);
        normalContent->Dump();
        return std::make_shared<Notification::NotificationContent>(normalContent);
    }

    std::shared_ptr<Notification::NotificationContent> BuildLongTextContent(FuzzedDataProvider *fdp,
        const std::shared_ptr<Media::PixelMap> &pixelMap)
    {
        auto longTextContent = std::make_shared<Notification::NotificationLongTextContent>();
        longTextContent->SetTitle(ConsumeStringOrDefault(fdp, COMMON_STRING_MAX, "long.title"));
        longTextContent->SetText(ConsumeStringOrDefault(fdp, LONG_STRING_MAX, "long.text"));
        longTextContent->SetAdditionalText(fdp->ConsumeRandomLengthString(COMMON_STRING_MAX));
        longTextContent->SetLongText(fdp->ConsumeRandomLengthString(LONG_TEXT_STRING_MAX));
        longTextContent->SetExpandedTitle(fdp->ConsumeRandomLengthString(LONG_STRING_MAX));
        longTextContent->SetBriefText(fdp->ConsumeRandomLengthString(LONG_STRING_MAX));
        longTextContent->SetLockScreenPicture(pixelMap);
        longTextContent->Dump();
        return std::make_shared<Notification::NotificationContent>(longTextContent);
    }

    std::shared_ptr<Notification::NotificationContent> BuildMultiLineContent(FuzzedDataProvider *fdp,
        const std::shared_ptr<Media::PixelMap> &pixelMap)
    {
        auto multiLineContent = std::make_shared<Notification::NotificationMultiLineContent>();
        multiLineContent->SetTitle(ConsumeStringOrDefault(fdp, COMMON_STRING_MAX, "multi.title"));
        multiLineContent->SetText(ConsumeStringOrDefault(fdp, LONG_STRING_MAX, "multi.text"));
        multiLineContent->SetAdditionalText(fdp->ConsumeRandomLengthString(COMMON_STRING_MAX));
        multiLineContent->SetExpandedTitle(fdp->ConsumeRandomLengthString(LONG_STRING_MAX));
        multiLineContent->SetBriefText(fdp->ConsumeRandomLengthString(LONG_STRING_MAX));
        for (uint8_t i = 0; i < MULTI_LINE_COUNT; ++i) {
            multiLineContent->AddSingleLine(fdp->ConsumeRandomLengthString(COMMON_STRING_MAX));
        }
        multiLineContent->GetAllLines();
        multiLineContent->SetLineWantAgents({nullptr, nullptr});
        multiLineContent->GetLineWantAgents();
        multiLineContent->SetLockScreenPicture(pixelMap);
        multiLineContent->Dump();
        return std::make_shared<Notification::NotificationContent>(multiLineContent);
    }

    std::shared_ptr<Notification::NotificationContent> BuildPictureContent(FuzzedDataProvider *fdp,
        const std::shared_ptr<Media::PixelMap> &pixelMap)
    {
        auto pictureContent = std::make_shared<Notification::NotificationPictureContent>();
        pictureContent->SetTitle(ConsumeStringOrDefault(fdp, COMMON_STRING_MAX, "picture.title"));
        pictureContent->SetText(ConsumeStringOrDefault(fdp, LONG_STRING_MAX, "picture.text"));
        pictureContent->SetAdditionalText(fdp->ConsumeRandomLengthString(COMMON_STRING_MAX));
        pictureContent->SetExpandedTitle(fdp->ConsumeRandomLengthString(LONG_STRING_MAX));
        pictureContent->SetBriefText(fdp->ConsumeRandomLengthString(LONG_STRING_MAX));
        pictureContent->SetBigPicture(pixelMap);
        pictureContent->SetLockScreenPicture(pixelMap);
        pictureContent->Dump();
        return std::make_shared<Notification::NotificationContent>(pictureContent);
    }

    std::shared_ptr<Notification::NotificationContent> BuildConversationContent(FuzzedDataProvider *fdp,
        const std::shared_ptr<Media::PixelMap> &pixelMap)
    {
        auto sender = BuildMessageUser(fdp, pixelMap);
        auto conversationContent = std::make_shared<Notification::NotificationConversationalContent>(sender);
        conversationContent->SetTitle(ConsumeStringOrDefault(fdp, COMMON_STRING_MAX, "conversation.title"));
        conversationContent->SetText(ConsumeStringOrDefault(fdp, LONG_STRING_MAX, "conversation.text"));
        conversationContent->SetAdditionalText(fdp->ConsumeRandomLengthString(COMMON_STRING_MAX));
        conversationContent->SetConversationTitle(fdp->ConsumeRandomLengthString(COMMON_STRING_MAX));
        conversationContent->GetConversationTitle();
        conversationContent->SetConversationGroup(fdp->ConsumeBool());
        conversationContent->IsConversationGroup();
        conversationContent->AddConversationalMessage(fdp->ConsumeRandomLengthString(COMMON_STRING_MAX),
            fdp->ConsumeIntegral<int64_t>(), sender);
        conversationContent->GetAllConversationalMessages();
        conversationContent->SetLockScreenPicture(pixelMap);
        conversationContent->Dump();
        return std::make_shared<Notification::NotificationContent>(conversationContent);
    }

    std::shared_ptr<Notification::NotificationContent> BuildMediaContent(FuzzedDataProvider *fdp,
        const std::shared_ptr<Media::PixelMap> &pixelMap)
    {
        auto mediaContent = std::make_shared<Notification::NotificationMediaContent>();
        mediaContent->SetTitle(ConsumeStringOrDefault(fdp, COMMON_STRING_MAX, "media.title"));
        mediaContent->SetText(ConsumeStringOrDefault(fdp, LONG_STRING_MAX, "media.text"));
        mediaContent->SetAdditionalText(fdp->ConsumeRandomLengthString(COMMON_STRING_MAX));
        mediaContent->SetShownActions({
            MEDIA_ACTION_PREVIOUS,
            MEDIA_ACTION_PLAY,
            MEDIA_ACTION_NEXT,
            fdp->ConsumeIntegral<uint32_t>(),
        });
        mediaContent->GetShownActions();
        mediaContent->SetLockScreenPicture(pixelMap);
        mediaContent->Dump();
        return std::make_shared<Notification::NotificationContent>(mediaContent);
    }

    std::shared_ptr<Notification::NotificationContent> BuildLiveViewContent(FuzzedDataProvider *fdp,
        const std::shared_ptr<Media::PixelMap> &pixelMap,
        Notification::NotificationLiveViewContent::LiveViewStatus status)
    {
        auto liveViewContent = std::make_shared<Notification::NotificationLiveViewContent>();
        liveViewContent->SetTitle(ConsumeStringOrDefault(fdp, COMMON_STRING_MAX, "live.title"));
        liveViewContent->SetText(ConsumeStringOrDefault(fdp, LONG_STRING_MAX, "live.text"));
        liveViewContent->SetAdditionalText(fdp->ConsumeRandomLengthString(COMMON_STRING_MAX));
        liveViewContent->SetLiveViewStatus(status);
        liveViewContent->GetLiveViewStatus();
        liveViewContent->SetVersion(fdp->ConsumeIntegral<uint32_t>());
        liveViewContent->GetVersion();
        liveViewContent->SetExtraInfo(MakeWantParams());
        liveViewContent->GetExtraInfo();
        liveViewContent->SetIsOnlyLocalUpdate(fdp->ConsumeBool());
        liveViewContent->GetIsOnlyLocalUpdate();
        liveViewContent->SetRemoveOnProcessExitState(
            static_cast<Notification::NotificationLiveViewContent::LiveViewRemoveStatus>(
                ModuloByNonZero(fdp->ConsumeIntegral<uint8_t>(), INPUT_EDIT_TYPE_NUM)));
        liveViewContent->GetRemoveOnProcessExitState();
        liveViewContent->SetCreatePid(fdp->ConsumeIntegral<int32_t>());
        liveViewContent->GetCreatePid();
        liveViewContent->SetUid(fdp->ConsumeIntegral<int32_t>());
        liveViewContent->GetUid();
        Notification::PictureMap pictureMap;
        pictureMap["small"].push_back(MakePixelMap(SMALL_PIXEL_SIZE, SMALL_PIXEL_SIZE));
        pictureMap["large"].push_back(pixelMap);
        liveViewContent->SetPicture(pictureMap);
        liveViewContent->SetLockScreenPicture(pixelMap);
        liveViewContent->Dump();
        return std::make_shared<Notification::NotificationContent>(liveViewContent);
    }

    AutoDeleteTimeValues BuildAutoDeleteTimes(FuzzedDataProvider *fdp)
    {
        const int64_t minTime = std::numeric_limits<int64_t>::min();
        const int64_t maxTime = std::numeric_limits<int64_t>::max();
        const int64_t defaultAutoDeleteTime = Notification::NotificationConstant::DEFAULT_AUTO_DELETE_TIME;
        return {
            minTime,
            Notification::NotificationConstant::INVALID_AUTO_DELETE_TIME,
            Notification::NotificationConstant::NO_DELAY_DELETE_TIME,
            ONE_TIME,
            defaultAutoDeleteTime - TIME_BOUNDARY_STEP,
            defaultAutoDeleteTime,
            defaultAutoDeleteTime + TIME_BOUNDARY_STEP,
            maxTime,
            fdp->ConsumeIntegral<int64_t>(),
        };
    }

    void ApplyAutoDeleteTimes(const AutoDeleteTimeValues &autoDeleteTimes,
        Notification::NotificationRequest &request)
    {
        for (int64_t autoDeleteTime : autoDeleteTimes) {
            request.SetAutoDeletedTime(autoDeleteTime);
            request.GetAutoDeletedTime();
        }
    }

    UpdateDeadlineValues BuildUpdateDeadLines(FuzzedDataProvider *fdp)
    {
        const int64_t minTime = std::numeric_limits<int64_t>::min();
        const int64_t maxTime = std::numeric_limits<int64_t>::max();
        const int64_t maxUpdateTime = Notification::NotificationConstant::MAX_UPDATE_TIME;
        return {
            minTime,
            NEGATIVE_TIME,
            ZERO_TIME,
            ONE_TIME,
            maxUpdateTime - TIME_BOUNDARY_STEP,
            maxUpdateTime,
            maxUpdateTime + TIME_BOUNDARY_STEP,
            maxTime,
            fdp->ConsumeIntegral<int64_t>(),
        };
    }

    void ApplyUpdateDeadLines(const UpdateDeadlineValues &updateDeadLines,
        Notification::NotificationRequest &request)
    {
        for (int64_t updateDeadLine : updateDeadLines) {
            request.SetUpdateDeadLine(updateDeadLine);
            request.GetUpdateDeadLine();
        }
    }

    FinishDeadlineValues BuildFinishDeadLines(FuzzedDataProvider *fdp)
    {
        const int64_t minTime = std::numeric_limits<int64_t>::min();
        const int64_t maxTime = std::numeric_limits<int64_t>::max();
        const int64_t maxFinishTime = Notification::NotificationConstant::MAX_FINISH_TIME;
        return {
            minTime,
            NEGATIVE_TIME,
            ZERO_TIME,
            ONE_TIME,
            maxFinishTime - TIME_BOUNDARY_STEP,
            maxFinishTime,
            maxFinishTime + TIME_BOUNDARY_STEP,
            maxTime,
            fdp->ConsumeIntegral<int64_t>(),
        };
    }

    void ApplyFinishDeadLines(const FinishDeadlineValues &finishDeadLines,
        Notification::NotificationRequest &request)
    {
        for (int64_t finishDeadLine : finishDeadLines) {
            request.SetFinishDeadLine(finishDeadLine);
            request.GetFinishDeadLine();
        }
    }

    TriggerArchiveDeadlineValues BuildTriggerAndArchiveDeadLines(FuzzedDataProvider *fdp)
    {
        const int64_t minTime = std::numeric_limits<int64_t>::min();
        const int64_t maxTime = std::numeric_limits<int64_t>::max();
        return {
            minTime,
            NEGATIVE_TIME,
            ZERO_TIME,
            ONE_TIME,
            Notification::NotificationConstant::TEN_MINUTES,
            Notification::NotificationConstant::FIFTEEN_MINUTES,
            Notification::NotificationConstant::THIRTY_MINUTES,
            Notification::NotificationConstant::MAX_UPDATE_TIME,
            Notification::NotificationConstant::MAX_FINISH_TIME,
            maxTime,
            fdp->ConsumeIntegral<int64_t>(),
        };
    }

    void ApplyTriggerAndArchiveDeadLines(const TriggerArchiveDeadlineValues &deadLines,
        Notification::NotificationRequest &request)
    {
        for (int64_t triggerDeadLine : deadLines) {
            request.SetGeofenceTriggerDeadLine(triggerDeadLine);
            request.GetGeofenceTriggerDeadLine();
        }
        for (int64_t archiveDeadLine : deadLines) {
            request.SetArchiveDeadLine(archiveDeadLine);
            request.GetArchiveDeadLine();
        }
    }

    DeliveryTimeValues BuildDeliveryTimes(FuzzedDataProvider *fdp)
    {
        const int64_t minTime = std::numeric_limits<int64_t>::min();
        const int64_t maxTime = std::numeric_limits<int64_t>::max();
        return {
            minTime,
            NEGATIVE_TIME,
            ZERO_TIME,
            ONE_TIME,
            Notification::NotificationConstant::SECOND_TO_MS,
            Notification::NotificationConstant::TEN_MINUTES,
            Notification::NotificationConstant::MAX_UPDATE_TIME,
            Notification::NotificationConstant::MAX_FINISH_TIME,
            maxTime,
            fdp->ConsumeIntegral<int64_t>(),
        };
    }

    void ApplyDeliveryTimes(const DeliveryTimeValues &deliveryTimes,
        Notification::NotificationRequest &request)
    {
        for (int64_t deliveryTime : deliveryTimes) {
            request.SetDeliveryTime(deliveryTime);
            request.GetDeliveryTime();
        }
    }

    void PickDeadlineFields(FuzzedDataProvider *fdp, Notification::NotificationRequest &request,
        const DeadlineFieldValues &deadlines)
    {
        request.SetAutoDeletedTime(PickBoundaryValue(fdp, deadlines.autoDeleteTimes));
        request.SetUpdateDeadLine(PickBoundaryValue(fdp, deadlines.updateDeadLines));
        request.SetFinishDeadLine(PickBoundaryValue(fdp, deadlines.finishDeadLines));
        request.SetGeofenceTriggerDeadLine(PickBoundaryValue(fdp, deadlines.triggerAndArchiveDeadLines));
        request.SetArchiveDeadLine(PickBoundaryValue(fdp, deadlines.triggerAndArchiveDeadLines));
        request.SetDeliveryTime(PickBoundaryValue(fdp, deadlines.deliveryTimes));
    }

    void FuzzTimingFlags(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
    {
        request.SetShowDeliveryTime(fdp->ConsumeBool());
        request.IsShowDeliveryTime();
        request.SetCountdownTimer(fdp->ConsumeBool());
        request.IsCountdownTimer();
        request.SetShowStopwatch(fdp->ConsumeBool());
        request.IsShowStopwatch();
        request.SetAlertOneTime(fdp->ConsumeBool());
        request.IsAlertOneTime();
    }

    void FuzzDeadlineFields(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
    {
        DeadlineFieldValues deadlines;
        deadlines.autoDeleteTimes = BuildAutoDeleteTimes(fdp);
        ApplyAutoDeleteTimes(deadlines.autoDeleteTimes, request);
        deadlines.updateDeadLines = BuildUpdateDeadLines(fdp);
        ApplyUpdateDeadLines(deadlines.updateDeadLines, request);
        deadlines.finishDeadLines = BuildFinishDeadLines(fdp);
        ApplyFinishDeadLines(deadlines.finishDeadLines, request);
        deadlines.triggerAndArchiveDeadLines = BuildTriggerAndArchiveDeadLines(fdp);
        ApplyTriggerAndArchiveDeadLines(deadlines.triggerAndArchiveDeadLines, request);
        deadlines.deliveryTimes = BuildDeliveryTimes(fdp);
        ApplyDeliveryTimes(deadlines.deliveryTimes, request);
        PickDeadlineFields(fdp, request, deadlines);
        FuzzTimingFlags(fdp, request);
    }

    void FuzzProgressBar(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
    {
        int32_t progressValue = static_cast<int32_t>(ModuloByNonZero(fdp->ConsumeIntegral<uint8_t>(), MAX_PROGRESS));
        int32_t progressMax   = static_cast<int32_t>(ModuloByNonZero(fdp->ConsumeIntegral<uint8_t>(), MAX_PROGRESS));
        bool    indeterminate = fdp->ConsumeBool();
        request.SetProgressBar(progressValue, progressMax, indeterminate);
        request.GetProgressValue();
        request.GetProgressMax();
        request.IsProgressIndeterminate();
    }

    void FuzzStringFields(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
    {
        request.SetGroupName(fdp->ConsumeRandomLengthString(STRING_PROBE_MAX));
        request.GetGroupName();
        request.SetClassification(fdp->ConsumeRandomLengthString(SHORT_STRING_MAX));
        request.GetClassification();
        request.SetLabel(fdp->ConsumeRandomLengthString(SHORT_STRING_MAX));
        request.GetLabel();
        request.SetSortingKey(fdp->ConsumeRandomLengthString(SHORT_STRING_MAX));
        request.GetSortingKey();
        request.SetStatusBarText(fdp->ConsumeRandomLengthString(COMMON_STRING_MAX));
        request.GetStatusBarText();
        request.SetSettingsText(fdp->ConsumeRandomLengthString(COMMON_STRING_MAX));
        request.GetSettingsText();
        request.SetShortcutId(fdp->ConsumeRandomLengthString(SHORT_STRING_MAX));
        request.GetShortcutId();
        request.SetSound(fdp->ConsumeRandomLengthString(COMMON_STRING_MAX));
        request.GetSound();
        request.SetAppMessageId(fdp->ConsumeRandomLengthString(SHORT_STRING_MAX));
        request.GetAppMessageId();
    }

    void FuzzEnumFields(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
    {
        uint8_t visiblenessRaw = ModuloByNonZero(fdp->ConsumeIntegral<uint8_t>(), VISIBLENESS_TYPE_NUM);
        request.SetVisibleness(
            static_cast<Notification::NotificationConstant::VisiblenessType>(visiblenessRaw));
        request.GetVisibleness();

        uint8_t groupAlertRaw = ModuloByNonZero(fdp->ConsumeIntegral<uint8_t>(), GROUP_ALERT_TYPE_NUM);
        request.SetGroupAlertType(
            static_cast<Notification::NotificationRequest::GroupAlertType>(groupAlertRaw));
        request.GetGroupAlertType();

        uint8_t badgeStyleRaw = ModuloByNonZero(fdp->ConsumeIntegral<uint8_t>(), BADGE_STYLE_NUM);
        request.SetBadgeIconStyle(
            static_cast<Notification::NotificationRequest::BadgeStyle>(badgeStyleRaw));
        request.GetBadgeIconStyle();
    }

    void FuzzUserInputHistory(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
    {
        const uint8_t historyCounts[] = {
            HISTORY_COUNT_EMPTY, HISTORY_COUNT_SINGLE, HISTORY_COUNT_LIMIT, HISTORY_COUNT_OVER,
        };
        for (uint8_t historyCount : historyCounts) {
            std::vector<std::string> history;
            for (uint8_t i = 0; i < historyCount; ++i) {
                history.push_back(fdp->ConsumeRandomLengthString(HISTORY_STRING_MAX));
            }
            request.SetNotificationUserInputHistory(history);
            request.GetNotificationUserInputHistory();
        }
    }

    void FuzzBooleanFlags(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
    {
        request.SetNotificationId(fdp->ConsumeIntegral<int32_t>());
        request.GetNotificationId();
        request.SetInProgress(fdp->ConsumeBool());
        request.IsInProgress();
        request.SetUnremovable(fdp->ConsumeBool());
        request.IsUnremovable();
        uint8_t slotTypeRaw = ModuloByNonZero(fdp->ConsumeIntegral<uint8_t>(), SLOT_TYPE_NUM);
        request.SetSlotType(static_cast<Notification::NotificationConstant::SlotType>(slotTypeRaw));
        request.GetSlotType();
        request.SetBadgeNumber(fdp->ConsumeIntegral<uint32_t>());
        request.GetBadgeNumber();
        request.SetNotificationControlFlags(fdp->ConsumeIntegral<uint32_t>());
        request.GetNotificationControlFlags();
        request.SetGroupOverview(fdp->ConsumeBool());
        request.IsGroupOverview();
        request.SetOnlyLocal(fdp->ConsumeBool());
        request.IsOnlyLocal();
        request.SetFloatingIcon(fdp->ConsumeBool());
        request.IsFloatingIcon();
        request.SetTapDismissed(fdp->ConsumeBool());
        request.IsTapDismissed();
        request.SetColorEnabled(fdp->ConsumeBool());
        request.IsColorEnabled();
        request.SetColor(fdp->ConsumeIntegral<uint32_t>());
        request.GetColor();
        request.SetRemoveAllowed(fdp->ConsumeBool());
        request.IsRemoveAllowed();
        request.SetUpdateOnly(fdp->ConsumeBool());
        request.IsUpdateOnly();
        request.SetDistributed(fdp->ConsumeBool());
        request.SetForceDistributed(fdp->ConsumeBool());
        request.IsForceDistributed();
        request.SetNotDistributed(fdp->ConsumeBool());
        request.IsNotDistributed();
    }

    void FuzzIdentityNumberFields(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
    {
        request.SetCreateTime(fdp->ConsumeIntegral<int64_t>());
        request.GetCreateTime();
        request.SetCreatorPid(fdp->ConsumeIntegral<int32_t>());
        request.GetCreatorPid();

        int32_t creatorUid = fdp->ConsumeIntegral<int32_t>();
        if (creatorUid == ZERO_TIME) {
            creatorUid = DEFAULT_CREATOR_UID;
        }
        request.SetCreatorUid(creatorUid);
        request.GetCreatorUid();
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
    }

    void FuzzIdentityNameFields(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
    {
        request.SetCreatorBundleName(ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, "creator.bundle"));
        request.GetCreatorBundleName();
        request.SetOwnerBundleName(ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, "owner.bundle"));
        request.GetOwnerBundleName();
        request.SetAppInstanceKey(ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, "app.instance"));
        request.GetAppInstanceKey();
        request.SetAppName(ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, "app.name"));
        request.GetAppName();
        request.SetAppIndex(fdp->ConsumeIntegral<int32_t>());
        request.GetAppIndex();
    }

    void FuzzIdentityStateFields(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
    {
        request.SetIsSystemApp(fdp->ConsumeBool());
        request.IsSystemApp();
        request.SetIsAgentNotification(fdp->ConsumeBool());
        request.IsAgentNotification();
        request.SetPermitSystemGeneratedContextualActionButtons(fdp->ConsumeBool());
        request.IsPermitSystemGeneratedContextualActionButtons();
        request.SetIsDoNotDisturbByPassed(fdp->ConsumeBool());
        request.IsDoNotDisturbByPassed();
        request.SetIsCoverActionButtons(fdp->ConsumeBool());
        request.IsCoverActionButtons();
    }

    void FuzzIdentityFields(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
    {
        request.GetNotificationHashCode();

        FuzzIdentityNumberFields(fdp, request);
        FuzzIdentityNameFields(fdp, request);
        FuzzIdentityStateFields(fdp, request);

        request.GetNotificationHashCode();
    }

    void FuzzDistributedFields(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
    {
        std::vector<std::string> displayDevices = ConsumeStringVector(fdp, DEVICE_LIST_MAX, DEVICE_STRING_MAX);
        displayDevices.emplace_back(Notification::NotificationConstant::HEADSET_DEVICE_TYPE);
        request.SetDevicesSupportDisplay(displayDevices);

        std::vector<std::string> operateDevices = ConsumeStringVector(fdp, DEVICE_LIST_MAX, DEVICE_STRING_MAX);
        operateDevices.emplace_back(Notification::NotificationConstant::GLASSES_DEVICE_TYPE);
        request.SetDevicesSupportOperate(operateDevices);
        request.GetNotificationDistributedOptions();

        request.SetHashCodeGenerateType(fdp->ConsumeIntegral<uint32_t>());
        request.GetHashCodeGenerateType();
        request.SetCollaboratedReminderFlag(fdp->ConsumeIntegral<uint32_t>());
        request.GetCollaboratedReminderFlag();
        request.SetPublishDelayTime(fdp->ConsumeIntegral<uint32_t>());
        request.GetPublishDelayTime();
        request.SetUpdateByOwnerAllowed(fdp->ConsumeBool());
        request.IsUpdateByOwnerAllowed();
        request.SetDistributedCollaborate(fdp->ConsumeBool());
        request.GetDistributedCollaborate();
        request.SetDistributedHashCode(ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, "distributed.hash"));
        request.GetDistributedHashCode();
        request.SetPriorityNotificationType(fdp->ConsumeRandomLengthString(SHORT_STRING_MAX));
        request.GetPriorityNotificationType();

        std::string deviceType = ConsumeStringOrDefault(fdp, DEVICE_STRING_MAX,
            Notification::NotificationConstant::HEADSET_DEVICE_TYPE);
        request.AdddeviceStatu(deviceType, fdp->ConsumeRandomLengthString(DEVICE_STRING_MAX));
        request.GetdeviceStatus();
        request.AddConsumedDevices(Notification::NotificationConstant::HEADSET_DEVICE_TYPE);
        request.IsConsumedDevices(Notification::NotificationConstant::HEADSET_DEVICE_TYPE);
        request.IsConsumedDevices(deviceType);
        request.IsAtomicServiceNotification();
        request.GetLittleIconType();
    }

    void FuzzIconAndWantAgentFields(Notification::NotificationRequest &request,
        const std::shared_ptr<Media::PixelMap> &smallPixelMap,
        const std::shared_ptr<Media::PixelMap> &largePixelMap)
    {
        request.SetLittleIcon(smallPixelMap);
        request.GetLittleIcon();
        request.SetBigIcon(largePixelMap);
        request.GetBigIcon();
        request.SetOverlayIcon(smallPixelMap);
        request.GetOverlayIcon();
        request.ResetBigIcon();
        request.SetBigIcon(largePixelMap);
        request.SetAdditionalData(MakeWantParams());
        request.GetAdditionalData();
        request.SetExtendInfo(MakeWantParams());
        request.GetExtendInfo();
        request.SetWantAgent(nullptr);
        request.GetWantAgent();
        request.SetRemovalWantAgent(nullptr);
        request.GetRemovalWantAgent();
        request.SetMaxScreenWantAgent(nullptr);
        request.GetMaxScreenWantAgent();
    }

    std::shared_ptr<Notification::NotificationBundleOption> BuildBundleOption(FuzzedDataProvider *fdp,
        const std::string &bundleFallback, const std::string &appFallback, const std::string &instanceFallback)
    {
        auto bundleOption = std::make_shared<Notification::NotificationBundleOption>(
            ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, bundleFallback), fdp->ConsumeIntegral<int32_t>());
        bundleOption->SetAppName(ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, appFallback));
        bundleOption->SetInstanceKey(fdp->ConsumeIntegral<int32_t>());
        bundleOption->SetAppInstanceKey(ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, instanceFallback));
        bundleOption->SetAppIndex(fdp->ConsumeIntegral<int32_t>());
        bundleOption->Dump();
        return bundleOption;
    }

    std::shared_ptr<Notification::NotificationBundleOption> BuildAgentBundleOption(FuzzedDataProvider *fdp)
    {
        return std::make_shared<Notification::NotificationBundleOption>(
            ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, "agent.bundle"), fdp->ConsumeIntegral<int32_t>());
    }

    void FuzzBundleOptionFields(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
    {
        auto bundleOption = BuildBundleOption(fdp, "bundle.option", "bundle.app", "bundle.instance");
        request.SetBundleOption(bundleOption);
        request.GetBundleOption();
        auto agentBundle = BuildAgentBundleOption(fdp);
        request.SetAgentBundle(agentBundle);
        request.GetAgentBundle();
    }

    std::shared_ptr<Notification::NotificationFlags> BuildNotificationFlags(FuzzedDataProvider *fdp)
    {
        auto flags = std::make_shared<Notification::NotificationFlags>(fdp->ConsumeIntegral<uint32_t>());
        flags->SetSoundEnabled(Notification::NotificationConstant::FlagStatus::OPEN);
        flags->SetVibrationEnabled(Notification::NotificationConstant::FlagStatus::CLOSE);
        flags->SetLockScreenEnabled(Notification::NotificationConstant::FlagStatus::OPEN);
        flags->SetBannerEnabled(Notification::NotificationConstant::FlagStatus::CLOSE);
        flags->SetLightScreenEnabled(fdp->ConsumeBool());
        flags->SetStatusIconEnabled(fdp->ConsumeBool());
        flags->SetReminderFlags(fdp->ConsumeIntegral<uint32_t>());
        flags->Dump();
        return flags;
    }

    std::shared_ptr<Notification::NotificationFlags> BuildDeviceFlags(FuzzedDataProvider *fdp)
    {
        return std::make_shared<Notification::NotificationFlags>(fdp->ConsumeIntegral<uint32_t>());
    }

    void FuzzFlagFields(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
    {
        request.SetFlags(BuildNotificationFlags(fdp));
        request.GetFlags();
        auto deviceFlags = std::make_shared<DeviceFlagMap>();
        (*deviceFlags)[Notification::NotificationConstant::HEADSET_DEVICE_TYPE] = BuildDeviceFlags(fdp);
        (*deviceFlags)[Notification::NotificationConstant::GLASSES_DEVICE_TYPE] = BuildDeviceFlags(fdp);
        (*deviceFlags)[WEARABLE_DEVICE_TYPE] = BuildDeviceFlags(fdp);
        request.SetDeviceFlags(deviceFlags);
        request.GetDeviceFlags();
        request.SetDistributedFlagBit(Notification::NotificationConstant::ReminderFlag::SOUND_FLAG, true);
        request.SetDistributedFlagBit(Notification::NotificationConstant::ReminderFlag::LOCKSCREEN_FLAG, false,
            {Notification::NotificationConstant::GLASSES_DEVICE_TYPE});
        request.SetDistributedFlagBit(Notification::NotificationConstant::ReminderFlag::BANNER_FLAG, false);
        request.SetDistributedFlagBit(Notification::NotificationConstant::ReminderFlag::LIGHTSCREEN_FLAG, false);
        request.SetDistributedFlagBit(Notification::NotificationConstant::ReminderFlag::VIBRATION_FLAG, false);
        request.SetDistributedFlagBit(Notification::NotificationConstant::ReminderFlag::STATUSBAR_ICON_FLAG, false);
    }

    std::shared_ptr<Notification::NotificationTrigger> BuildNotificationTrigger(FuzzedDataProvider *fdp)
    {
        auto geofence = std::make_shared<Notification::NotificationGeofence>(
            static_cast<double>(ModuloByNonZero(fdp->ConsumeIntegral<int16_t>(), GEOFENCE_LONGITUDE_RANGE)),
            static_cast<double>(ModuloByNonZero(fdp->ConsumeIntegral<int16_t>(), GEOFENCE_LATITUDE_RANGE)),
            static_cast<double>((ModuloByNonZero(fdp->ConsumeIntegral<uint16_t>(), GEOFENCE_RADIUS_RANGE)) +
                GEOFENCE_RADIUS_OFFSET),
            static_cast<int32_t>(ModuloByNonZero(fdp->ConsumeIntegral<uint16_t>(), GEOFENCE_DELAY_RANGE)),
            Notification::NotificationConstant::CoordinateSystemType::COORDINATE_TYPE_WGS84,
            Notification::NotificationConstant::MonitorEvent::MONITOR_TYPE_ENTRY);
        auto trigger = std::make_shared<Notification::NotificationTrigger>();
        trigger->SetTriggerType(Notification::NotificationConstant::TriggerType::TRIGGER_TYPE_FENCE);
        trigger->SetConfigPath(Notification::NotificationConstant::ConfigPath::CONFIG_PATH_CLOUD_CONFIG);
        trigger->SetGeofence(geofence);
        trigger->SetDisplayTime(fdp->ConsumeIntegral<int32_t>());
        trigger->Dump();
        return trigger;
    }

    void FuzzGroupAndTemplateFields(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
    {
        auto groupInfo = std::make_shared<Notification::NotificationGroupInfo>();
        groupInfo->SetGroupTitle(ConsumeStringOrDefault(fdp, COMMON_STRING_MAX, "group.title"));
        groupInfo->SetIsGroupIcon(fdp->ConsumeBool());
        groupInfo->Dump();
        request.SetGroupInfo(groupInfo);
        request.GetGroupInfo();

        auto unifiedGroupInfo = std::make_shared<Notification::NotificationUnifiedGroupInfo>();
        unifiedGroupInfo->SetKey(ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, "unified.key"));
        unifiedGroupInfo->SetTitle(ConsumeStringOrDefault(fdp, COMMON_STRING_MAX, "unified.title"));
        unifiedGroupInfo->SetContent(ConsumeStringOrDefault(fdp, COMMON_STRING_MAX, "unified.content"));
        unifiedGroupInfo->SetSceneName(ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, "scene"));
        unifiedGroupInfo->SetExtraInfo(MakeWantParams());
        unifiedGroupInfo->Dump();
        request.SetUnifiedGroupInfo(unifiedGroupInfo);
        request.GetUnifiedGroupInfo();

        auto notificationTemplate = std::make_shared<Notification::NotificationTemplate>();
        notificationTemplate->SetTemplateName(ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, "template.name"));
        notificationTemplate->SetTemplateData(MakeWantParams());
        notificationTemplate->Dump();
        request.SetTemplate(notificationTemplate);
        request.GetTemplate();
    }

    std::shared_ptr<Notification::NotificationUserInput> BuildUserInput(FuzzedDataProvider *fdp)
    {
        auto userInput = Notification::NotificationUserInput::Create(
            ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, "input.key"));
        if (userInput) {
            userInput->SetTag(fdp->ConsumeRandomLengthString(SHORT_STRING_MAX));
            userInput->SetOptions({"yes", "no", fdp->ConsumeRandomLengthString(HISTORY_STRING_MAX)});
            userInput->SetPermitFreeFormInput(fdp->ConsumeBool());
            userInput->SetPermitMimeTypes("image/png", true);
            userInput->SetPermitMimeTypes("text/plain", fdp->ConsumeBool());
            userInput->SetEditType(static_cast<Notification::NotificationConstant::InputEditType>(
                ModuloByNonZero(fdp->ConsumeIntegral<uint8_t>(), INPUT_EDIT_TYPE_NUM)));
            userInput->Dump();
        }
        return userInput;
    }

    void FuzzActionButtonFields(FuzzedDataProvider *fdp, Notification::NotificationRequest &request,
        const std::shared_ptr<Media::PixelMap> &smallPixelMap)
    {
        auto userInput = BuildUserInput(fdp);
        auto actionButton = Notification::NotificationActionButton::Create(smallPixelMap,
            ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, "action.title"), nullptr, MakeWantParams(),
            Notification::NotificationConstant::REPLY_ACTION_BUTTON, fdp->ConsumeBool(), {}, userInput, false);
        if (actionButton) {
            actionButton->SetSemanticActionButton(Notification::NotificationConstant::ARCHIVE_ACTION_BUTTON);
            actionButton->SetAutoCreatedReplies(fdp->ConsumeBool());
            actionButton->SetContextDependent(false);
            if (userInput) {
                actionButton->AddNotificationUserInput(userInput);
                actionButton->AddMimeTypeOnlyUserInput(userInput);
            }
            actionButton->Dump();
            request.AddActionButton(actionButton);
            request.GetActionButtons();
            request.HasUserInputButton();
        }

        request.AddMessageUser(std::make_shared<Notification::MessageUser>(BuildMessageUser(fdp, smallPixelMap)));
        request.GetMessageUsers();
        Notification::NotificationRequest tempRequest;
        tempRequest.AddActionButton(actionButton);
        tempRequest.GetActionButtons();
        tempRequest.ClearActionButtons();
        tempRequest.GetActionButtons();
    }

    void FuzzRequestObjectFields(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
    {
        auto smallPixelMap = MakePixelMap(SMALL_PIXEL_SIZE, SMALL_PIXEL_SIZE);
        auto largePixelMap = MakePixelMap(LARGE_PIXEL_SIZE, LARGE_PIXEL_SIZE);
        FuzzIconAndWantAgentFields(request, smallPixelMap, largePixelMap);
        FuzzBundleOptionFields(fdp, request);
        FuzzFlagFields(fdp, request);
        request.SetNotificationTrigger(BuildNotificationTrigger(fdp));
        request.GetNotificationTrigger();
        FuzzGroupAndTemplateFields(fdp, request);
        FuzzActionButtonFields(fdp, request, smallPixelMap);
    }

    void FuzzContentFields(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
    {
        auto smallPixelMap = MakePixelMap(SMALL_PIXEL_SIZE, SMALL_PIXEL_SIZE);
        auto largePixelMap = MakePixelMap(LARGE_PIXEL_SIZE, LARGE_PIXEL_SIZE);

        request.SetContent(nullptr);
        request.GetContent();
        request.GetNotificationType();
        request.CheckImageSizeForContent(fdp->ConsumeBool());

        std::vector<std::shared_ptr<Notification::NotificationContent>> contents = {
            BuildNormalContent(fdp, smallPixelMap),
            BuildLongTextContent(fdp, smallPixelMap),
            BuildMultiLineContent(fdp, smallPixelMap),
            BuildPictureContent(fdp, largePixelMap),
            BuildConversationContent(fdp, largePixelMap),
            BuildMediaContent(fdp, smallPixelMap),
            BuildLiveViewContent(fdp, largePixelMap,
                Notification::NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE),
        };

        for (auto &content : contents) {
            request.SetContent(content);
            request.GetContent();
            request.GetNotificationType();
            request.CheckImageSizeForContent(fdp->ConsumeBool());
            request.Dump();
            Parcel parcel;
            if (content && content->Marshalling(parcel)) {
                Notification::NotificationContent *restoredContent =
                    Notification::NotificationContent::Unmarshalling(parcel);
                delete restoredContent;
            }
        }
    }

    RequestPtr BuildLiveViewRequest(FuzzedDataProvider *fdp,
        Notification::NotificationLiveViewContent::LiveViewStatus status, uint32_t version)
    {
        RequestPtr request = new Notification::NotificationRequest(fdp->ConsumeIntegral<int32_t>());
        request->SetSlotType(Notification::NotificationConstant::SlotType::LIVE_VIEW);
        request->SetContent(BuildLiveViewContent(fdp, MakePixelMap(SMALL_PIXEL_SIZE, SMALL_PIXEL_SIZE), status));
        request->SetNotificationId(fdp->ConsumeIntegral<int32_t>());
        request->SetCreatorBundleName(ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, "live.creator"));
        request->SetCreatorUid(fdp->ConsumeIntegral<int32_t>());
        request->SetCreatorUserId(fdp->ConsumeIntegral<int32_t>());
        request->SetOwnerBundleName(ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, "live.owner"));
        request->SetOwnerUid(fdp->ConsumeIntegral<int32_t>());
        request->SetOwnerUserId(fdp->ConsumeIntegral<int32_t>());
        request->SetAppInstanceKey(ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, "live.instance"));
        request->SetLabel(ConsumeStringOrDefault(fdp, SHORT_STRING_MAX, "live.label"));
        request->SetAutoDeletedTime(fdp->ConsumeBool() ?
            Notification::NotificationConstant::INVALID_AUTO_DELETE_TIME :
            Notification::NotificationConstant::NO_DELAY_DELETE_TIME);
        request->SetUpdateDeadLine(fdp->ConsumeIntegral<int64_t>());
        request->SetFinishDeadLine(fdp->ConsumeIntegral<int64_t>());
        request->SetGeofenceTriggerDeadLine(fdp->ConsumeIntegral<int64_t>());
        auto basicContent = request->GetContent()->GetNotificationContent();
        auto liveViewContent = std::static_pointer_cast<Notification::NotificationLiveViewContent>(basicContent);
        liveViewContent->SetVersion(version);
        return request;
    }

    struct LiveViewRequestSet {
        RequestPtr liveCreate;
        RequestPtr liveUpdate;
        RequestPtr liveOld;
        RequestPtr liveEnd;
        RequestPtr liveMaxNew;
        RequestPtr liveMaxOld;
    };

    LiveViewRequestSet BuildLiveViewRequestSet(FuzzedDataProvider *fdp)
    {
        LiveViewRequestSet requests;
        requests.liveCreate = BuildLiveViewRequest(fdp,
            Notification::NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE,
            Notification::NotificationLiveViewContent::MAX_VERSION);
        requests.liveUpdate = BuildLiveViewRequest(fdp,
            Notification::NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE,
            LIVE_UPDATE_VERSION);
        requests.liveOld = BuildLiveViewRequest(fdp,
            Notification::NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE, LIVE_OLD_VERSION);
        requests.liveEnd = BuildLiveViewRequest(fdp,
            Notification::NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END, LIVE_END_VERSION);
        requests.liveMaxNew = BuildLiveViewRequest(fdp,
            Notification::NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE,
            Notification::NotificationLiveViewContent::MAX_VERSION);
        requests.liveMaxOld = BuildLiveViewRequest(fdp,
            Notification::NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE,
            Notification::NotificationLiveViewContent::MAX_VERSION);
        return requests;
    }

    void FuzzLiveViewCheckPaths(Notification::NotificationRequest &request, const LiveViewRequestSet &requests)
    {
        request.CheckNotificationRequest(nullptr);
        request.SetContent(nullptr);
        request.SetSlotType(Notification::NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
        request.CheckNotificationRequest(requests.liveOld);
        requests.liveCreate->CheckNotificationRequest(nullptr);
        requests.liveUpdate->CheckNotificationRequest(nullptr);
        requests.liveUpdate->CheckNotificationRequest(requests.liveOld);
        requests.liveOld->CheckNotificationRequest(requests.liveUpdate);
        requests.liveMaxNew->CheckNotificationRequest(requests.liveOld);
        requests.liveUpdate->CheckNotificationRequest(requests.liveMaxOld);
        requests.liveCreate->CheckNotificationRequest(requests.liveOld);
        requests.liveUpdate->CheckNotificationRequest(requests.liveEnd);
        requests.liveUpdate->FillMissingParameters(requests.liveOld);
    }

    void FuzzLiveViewStatePaths(FuzzedDataProvider *fdp, const RequestPtr &liveUpdate)
    {
        liveUpdate->GetLiveViewStatus();
        liveUpdate->SetLiveViewStatus(Notification::NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE);
        liveUpdate->IsCommonLiveView();
        liveUpdate->IsSystemLiveView();
        liveUpdate->IsTriggerLiveView();
        liveUpdate->IsUpdateLiveView();
        liveUpdate->GetTriggerKey();
        liveUpdate->GetTriggerSecureKey();
        liveUpdate->CheckImageSizeForContent(fdp->ConsumeBool());
    }

    void FuzzLiveViewJsonPaths(FuzzedDataProvider *fdp, const RequestPtr &liveUpdate)
    {
        std::string collaborationJson;
        liveUpdate->CollaborationToJson(collaborationJson);
        Notification::NotificationRequest *collaborationRequest =
            Notification::NotificationRequest::CollaborationFromJson(collaborationJson);
        delete collaborationRequest;
        Notification::NotificationRequest *badCollaborationRequest =
            Notification::NotificationRequest::CollaborationFromJson(fdp->ConsumeRandomLengthString(COMMON_STRING_MAX));
        delete badCollaborationRequest;
    }

    void FuzzLiveViewRequestPaths(FuzzedDataProvider *fdp, Notification::NotificationRequest &request)
    {
        LiveViewRequestSet requests = BuildLiveViewRequestSet(fdp);
        FuzzLiveViewCheckPaths(request, requests);
        FuzzLiveViewStatePaths(fdp, requests.liveUpdate);
        FuzzLiveViewJsonPaths(fdp, requests.liveUpdate);
        request.SetSlotType(Notification::NotificationConstant::SlotType::LIVE_VIEW);
        request.SetContent(BuildLiveViewContent(fdp, MakePixelMap(SMALL_PIXEL_SIZE, SMALL_PIXEL_SIZE),
            Notification::NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE));
    }

    void TestRequestKeyAndCopyPaths(Notification::NotificationRequest &request)
    {
        request.GetBaseKey("localDevice");
        request.GetKey();
        request.GetSecureKey();
        request.GetTriggerKey();
        request.GetTriggerSecureKey();
        request.GenerateUniqueKey();
        request.GenerateDistributedUniqueKey();

        request.SetDistributedCollaborate(false);
        request.SetIsAgentNotification(false);
        request.SetHashCodeGenerateType(HASH_CODE_GENERATE_TYPE);
        request.GetBaseKey("hashDevice");
        request.SetIsAgentNotification(true);
        request.GetBaseKey("agentDevice");
        request.SetDistributedCollaborate(true);
        request.GetBaseKey("distributedDevice");

        Notification::NotificationRequest copiedRequest(request);
        Notification::NotificationRequest assignedRequest = request;
        copiedRequest.GetKey();
        assignedRequest.GetKey();
    }

    void TestRequestMarshalling(Notification::NotificationRequest &request)
    {
        Notification::NotificationRequest defaultRequest;
        Parcel defaultParcel;
        if (defaultRequest.Marshalling(defaultParcel)) {
            Notification::NotificationRequest *defaultRestored =
                Notification::NotificationRequest::Unmarshalling(defaultParcel);
            delete defaultRestored;
        }
        nlohmann::json defaultJsonObject;
        defaultRequest.ToJson(defaultJsonObject);
        Notification::NotificationRequest *defaultFromJson =
            Notification::NotificationRequest::FromJson(defaultJsonObject);
        delete defaultFromJson;

        Parcel parcel;
        if (request.Marshalling(parcel)) {
            Notification::NotificationRequest *restored =
                Notification::NotificationRequest::Unmarshalling(parcel);
            delete restored;
        }

        nlohmann::json jsonObject;
        request.ToJson(jsonObject);
        Notification::NotificationRequest *fromJson =
            Notification::NotificationRequest::FromJson(jsonObject);
        delete fromJson;

        Notification::NotificationRequest *fromNullJson =
            Notification::NotificationRequest::FromJson(nlohmann::json());
        delete fromNullJson;
        Notification::NotificationRequest *fromArrayJson =
            Notification::NotificationRequest::FromJson(nlohmann::json::array());
        delete fromArrayJson;

        std::string collaborationJson;
        request.CollaborationToJson(collaborationJson);
        Notification::NotificationRequest *fromCollaborationJson =
            Notification::NotificationRequest::CollaborationFromJson(collaborationJson);
        delete fromCollaborationJson;
    }

    bool FuzzNotificationRequestDeadlines(FuzzedDataProvider *fdp)
    {
        int32_t notificationId = fdp->ConsumeIntegral<int32_t>();
        Notification::NotificationRequest request(notificationId);

        FuzzDeadlineFields(fdp, request);
        FuzzProgressBar(fdp, request);
        FuzzUserInputHistory(fdp, request);
        FuzzIdentityFields(fdp, request);
        FuzzDistributedFields(fdp, request);
        FuzzRequestObjectFields(fdp, request);
        FuzzContentFields(fdp, request);
        FuzzStringFields(fdp, request);
        FuzzEnumFields(fdp, request);
        FuzzBooleanFlags(fdp, request);
        FuzzLiveViewRequestPaths(fdp, request);
        TestRequestKeyAndCopyPaths(request);
        TestRequestMarshalling(request);

        return true;
    }
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::FuzzNotificationRequestDeadlines(&fdp);
    return 0;
}
