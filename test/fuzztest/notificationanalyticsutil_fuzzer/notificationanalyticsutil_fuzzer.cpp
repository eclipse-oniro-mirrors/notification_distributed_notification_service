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

#include <thread>
#define private public

#include <fuzzer/FuzzedDataProvider.h>
#include "ans_permission_def.h"
#include "badge_number_callback_data.h"
#include "int_wrapper.h"
#include "notification_analytics_util.h"
#include "notificationanalyticsutil_fuzzer.h"
#include "notification_bundle_option.h"
#include "notification_clone_bundle_info.h"
#include "notification_content.h"
#include "notification_flags.h"
#include "notification_live_view_content.h"
#include "notification_local_live_view_content.h"
#include "notification_request.h"
#include "ans_status.h"
#include "string_wrapper.h"

namespace OHOS {
namespace Notification {
    namespace {
        // mirror notification_analytics_util.cpp subcode constants (cpp-local there)
        constexpr int32_t FUZZ_PUBLISH_ERROR_EVENT_CODE = 0;
        constexpr int32_t FUZZ_ANS_CUSTOMIZE_CODE = 7;
        constexpr int32_t FUZZ_MODIFY_ERROR_EVENT_CODE = 6;
        constexpr uint32_t SCENE_ID_MAX = 29;
        constexpr uint32_t BRANCH_ID_MAX = 31;
        constexpr uint32_t SLOT_TYPE_COUNT = 9;
        constexpr int32_t TYPE_CODE_MAX = 100;
        constexpr int32_t UID_MAX = 10000;
        constexpr size_t FUZZ_MESSAGE_LEN = 32;
        constexpr size_t FUZZ_BUNDLE_NAME_LEN = 16;
        constexpr size_t FUZZ_DEVICE_TYPE_LEN = 8;
        constexpr size_t FUZZ_STRING_MAX_LEN = 64;
        constexpr size_t TRUNCATED_DETAIL_LEN = 2048;
        constexpr size_t OVERLONG_DETAIL_LEN = 4096;
        constexpr uint8_t TRIGGER_BUNDLE_MAX = 4;
    }

    bool TestAnsStatus(FuzzedDataProvider *fdp)
    {
        int32_t errCode = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        int32_t sceneId = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        int32_t branchId = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        bool isPrint = fdp->ConsumeBool();
        std::string msg = fdp->ConsumeRandomLengthString();
        AnsStatus as(errCode, msg);
        AnsStatus as2(errCode, msg, sceneId, branchId);
        as.FormatSceneBranchStr(sceneId, branchId);
        as.AppendSceneBranch(sceneId, branchId, msg);
        as.InvalidParam(sceneId, branchId);
        as.InvalidParam(msg, sceneId, branchId);
        as.BuildMessage(isPrint);
        return true;
    }

    bool TestHaMetaMessage(FuzzedDataProvider *fdp)
    {
        HaMetaMessage message;
        bool flag = fdp->ConsumeBool();
        int32_t type = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        message.NeedReport();
        message.Checkfailed(flag);
        message.TypeCode(type);
        message.GetMessage();
        message.DeleteReason(type);
        OperationalMeta operMeta;
        nlohmann::json jsonObject;
        operMeta.ToJson(jsonObject);
        return true;
    }

    bool TestHaOperationMessage(FuzzedDataProvider *fdp)
    {
        bool flag = fdp->ConsumeBool();
        HaOperationMessage operationMessage = HaOperationMessage(false);
        std::string str1 = fdp->ConsumeRandomLengthString();
        std::string str2 = fdp->ConsumeRandomLengthString();
        std::string str3 = fdp->ConsumeRandomLengthString();
        std::vector<std::string> deviceTypes;
        deviceTypes.push_back(str1);
        deviceTypes.push_back(str2);
        deviceTypes.push_back(str3);
        operationMessage.KeyNode(true).SyncPublish("notification_1", deviceTypes);
        operationMessage.ToJson();
        operationMessage.ResetData();
        operationMessage.KeyNode(true).SyncDelete("notification_1");
        operationMessage = HaOperationMessage(true);
        deviceTypes.clear();
        deviceTypes.push_back("abc");
        deviceTypes.push_back("wearable");
        deviceTypes.push_back("headset");
        operationMessage.KeyNode(false).SyncPublish("notification_1", deviceTypes);
        operationMessage.ToJson();
        operationMessage.KeyNode(false).SyncDelete("notification_1");
        operationMessage.KeyNode(false).SyncDelete(str1, str2);
        operationMessage.notificationData.countTime = 0;
        operationMessage.SyncDelete(str1, std::string()).SyncClick(str1).SyncReply(str1);
        operationMessage.ResetData();
        operationMessage.liveViewData.countTime = 0;
        operationMessage = HaOperationMessage(true);
        operationMessage.ResetData();
        operationMessage.SyncDelete(str2, std::string()).SyncClick(str2).SyncReply(str2);

        operationMessage.ResetData();
        operationMessage.isLiveView_ = flag;
        operationMessage.DetermineWhetherToSend();
        operationMessage.liveViewData.keyNode++;
        operationMessage.DetermineWhetherToSend();
        operationMessage.liveViewData.countTime++;
        operationMessage.DetermineWhetherToSend();
        operationMessage.liveViewData.time = 0;
        operationMessage.DetermineWhetherToSend();
        operationMessage.ResetData();
        return true;
    }

    bool TestAnalyticsUtil(FuzzedDataProvider *fdp)
    {
        HaMetaMessage message;
        message.errorCode_ = ERR_OK;
        message.checkfailed_ = false;
        std::string bundle = fdp->ConsumeRandomLengthString();
        std::string bundle2 = fdp->ConsumeRandomLengthString();
        int32_t status = fdp->ConsumeIntegralInRange<int32_t>(0, 2);

        NotificationAnalyticsUtil::AddLiveViewSuccessNum(bundle, status);
        NotificationAnalyticsUtil::AddLiveViewFailedNum(bundle, status);
        NotificationAnalyticsUtil::AddLiveViewFailedNum(bundle2, status);
        NotificationAnalyticsUtil::AddLocalLiveViewFailedNum(bundle);
        NotificationAnalyticsUtil::AddLocalLiveViewFailedNum(bundle2);
        NotificationAnalyticsUtil::AddLocalLiveViewSuccessNum(bundle);
        NotificationAnalyticsUtil::AddLocalLiveViewSuccessNum(bundle2);
        return true;
    }

    HaMetaMessage BuildFuzzedMetaMessage(FuzzedDataProvider *fdp)
    {
        HaMetaMessage message;
        message.SceneId(fdp->ConsumeIntegralInRange<uint32_t>(0, SCENE_ID_MAX));
        message.BranchId(fdp->ConsumeIntegralInRange<uint32_t>(0, BRANCH_ID_MAX));
        message.ErrorCode(fdp->ConsumeIntegral<uint32_t>());
        message.NotificationId(fdp->ConsumeIntegral<int32_t>());
        message.SlotType(fdp->ConsumeIntegral<uint32_t>() % SLOT_TYPE_COUNT);
        message.DeleteReason(fdp->ConsumeIntegral<int32_t>());
        message.TypeCode(fdp->ConsumeIntegralInRange<int32_t>(0, TYPE_CODE_MAX));
        std::string detail = fdp->ConsumeBool() ? fdp->ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN)
            : std::string(TRUNCATED_DETAIL_LEN, 'l');
        message.Message(detail, fdp->ConsumeBool());
        message.Append(detail);
        message.Path(fdp->ConsumeRandomLengthString(FUZZ_MESSAGE_LEN));
        message.BundleName(fdp->ConsumeRandomLengthString(FUZZ_MESSAGE_LEN));
        message.AgentBundleName(fdp->ConsumeRandomLengthString(FUZZ_MESSAGE_LEN));
        return message;
    }

    bool TestMetaMessageChain(FuzzedDataProvider *fdp)
    {
        HaMetaMessage message = BuildFuzzedMetaMessage(fdp);
        message.GetMessage();
        message.Build();
        message.NeedReport();
        message.Checkfailed(fdp->ConsumeBool());
        NotificationAnalyticsUtil::ReportModifyEvent(message, fdp->ConsumeBool());
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        NotificationAnalyticsUtil::ReportPublishFailedEvent(message);
        NotificationAnalyticsUtil::ReportSkipFailedEvent(message);
        NotificationAnalyticsUtil::ReportDeleteFailedEvent(message);
        NotificationAnalyticsUtil::GetCurrentTime();
        NotificationAnalyticsUtil::GetMsToNextMidnight();
        return true;
    }

    sptr<NotificationRequest> BuildLiveViewRequest(FuzzedDataProvider *fdp, bool isLocal,
        bool withExtraInfo, NotificationLiveViewContent::LiveViewStatus liveViewStatus)
    {
        sptr<NotificationRequest> request = new NotificationRequest();
        if (request == nullptr) {
            return nullptr;
        }
        request->SetOwnerBundleName(fdp->ConsumeRandomLengthString(FUZZ_BUNDLE_NAME_LEN));
        request->SetCreatorBundleName(fdp->ConsumeRandomLengthString(FUZZ_BUNDLE_NAME_LEN));
        request->SetNotificationId(fdp->ConsumeIntegral<int32_t>());
        request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
        if (isLocal) {
            auto localContent = std::make_shared<NotificationLocalLiveViewContent>();
            std::shared_ptr<NotificationContent> content =
                std::make_shared<NotificationContent>(localContent);
            request->SetContent(content);
            return request;
        }
        auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
        liveViewContent->SetLiveViewStatus(liveViewStatus);
        if (withExtraInfo) {
            auto extraInfo = std::make_shared<AAFwk::WantParams>();
            extraInfo->SetParam("event", AAFwk::String::Box(fdp->ConsumeRandomLengthString(FUZZ_BUNDLE_NAME_LEN)));
            extraInfo->SetParam("LayoutData.layoutType",
                AAFwk::Integer::Box(fdp->ConsumeIntegral<int32_t>()));
            liveViewContent->SetExtraInfo(extraInfo);
        }
        std::shared_ptr<NotificationContent> content =
            std::make_shared<NotificationContent>(liveViewContent);
        request->SetContent(content);
        return request;
    }

    sptr<NotificationRequest> BuildFuzzedReportRequest(FuzzedDataProvider *fdp)
    {
        sptr<NotificationRequest> request = new NotificationRequest();
        if (request == nullptr) {
            return nullptr;
        }
        bool emptyBundle = fdp->ConsumeBool();
        request->SetOwnerBundleName(emptyBundle ? std::string()
            : fdp->ConsumeRandomLengthString(FUZZ_BUNDLE_NAME_LEN));
        request->SetCreatorBundleName(emptyBundle ? std::string()
            : fdp->ConsumeRandomLengthString(FUZZ_BUNDLE_NAME_LEN));
        request->SetOwnerUid(fdp->ConsumeIntegralInRange<int32_t>(0, UID_MAX));
        request->SetNotificationId(fdp->ConsumeIntegral<int32_t>());
        request->SetBadgeNumber(fdp->ConsumeIntegral<uint32_t>());
        request->SetClassification(fdp->ConsumeRandomLengthString(FUZZ_BUNDLE_NAME_LEN));
        request->SetSlotType(NotificationConstant::SlotType(
            fdp->ConsumeIntegral<uint8_t>() % SLOT_TYPE_COUNT));
        request->AdddeviceStatu(fdp->ConsumeRandomLengthString(FUZZ_DEVICE_TYPE_LEN),
            fdp->ConsumeRandomLengthString(FUZZ_DEVICE_TYPE_LEN));
        auto flags = std::make_shared<NotificationFlags>();
        flags->SetSoundEnabled(fdp->ConsumeBool() ? NotificationConstant::FlagStatus::OPEN
            : NotificationConstant::FlagStatus::CLOSE);
        flags->SetVibrationEnabled(fdp->ConsumeBool() ? NotificationConstant::FlagStatus::OPEN
            : NotificationConstant::FlagStatus::CLOSE);
        flags->SetLockScreenEnabled(fdp->ConsumeBool() ? NotificationConstant::FlagStatus::OPEN
            : NotificationConstant::FlagStatus::CLOSE);
        flags->SetBannerEnabled(fdp->ConsumeBool() ? NotificationConstant::FlagStatus::OPEN
            : NotificationConstant::FlagStatus::CLOSE);
        request->SetFlags(flags);
        auto extendInfo = std::make_shared<AAFwk::WantParams>();
        extendInfo->SetParam("isShared", AAFwk::Integer::Box(fdp->ConsumeIntegral<int32_t>()));
        request->SetExtendInfo(extendInfo);
        auto unifiedGroupInfo = std::make_shared<NotificationUnifiedGroupInfo>();
        auto groupExtra = std::make_shared<AAFwk::WantParams>();
        groupExtra->SetParam("msgId", AAFwk::String::Box(fdp->ConsumeRandomLengthString(FUZZ_BUNDLE_NAME_LEN)));
        groupExtra->SetParam("mcMsgId", AAFwk::String::Box(fdp->ConsumeRandomLengthString(FUZZ_BUNDLE_NAME_LEN)));
        groupExtra->SetParam("pushType", AAFwk::String::Box(fdp->ConsumeRandomLengthString(FUZZ_BUNDLE_NAME_LEN)));
        unifiedGroupInfo->SetExtraInfo(groupExtra);
        request->SetUnifiedGroupInfo(unifiedGroupInfo);
        std::vector<std::string> userInputHistory = { fdp->ConsumeRandomLengthString(FUZZ_BUNDLE_NAME_LEN) };
        request->SetNotificationUserInputHistory(userInputHistory);
        auto normalContent = std::make_shared<NotificationNormalContent>();
        normalContent->SetTitle(fdp->ConsumeRandomLengthString(FUZZ_BUNDLE_NAME_LEN));
        normalContent->SetText(fdp->ConsumeRandomLengthString(FUZZ_BUNDLE_NAME_LEN));
        request->SetContent(std::make_shared<NotificationContent>(normalContent));
        return request;
    }

    bool TestReportEventBranches(FuzzedDataProvider *fdp)
    {
        HaMetaMessage message = BuildFuzzedMetaMessage(fdp);
        sptr<NotificationRequest> request = BuildFuzzedReportRequest(fdp);
        NotificationAnalyticsUtil::ReportTipsEvent(nullptr, message);
        NotificationAnalyticsUtil::ReportPublishFailedEvent(nullptr, message);
        NotificationAnalyticsUtil::ReportDeleteFailedEvent(nullptr, message);
        NotificationAnalyticsUtil::ReportPublishSuccessEvent(nullptr, message);
        NotificationAnalyticsUtil::ReportPublishBadge(nullptr);
        NotificationAnalyticsUtil::ReportPublishWithUserInput(nullptr);
        if (request == nullptr) {
            return true;
        }
        NotificationAnalyticsUtil::ReportTipsEvent(request, message);
        HaMetaMessage invalidScene = HaMetaMessage(static_cast<uint32_t>(INT32_MAX),
            static_cast<uint32_t>(INT32_MAX));
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, invalidScene);
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        HaMetaMessage needNoReport = BuildFuzzedMetaMessage(fdp);
        needNoReport.Checkfailed(true);
        NotificationAnalyticsUtil::ReportDeleteFailedEvent(request, needNoReport);
        HaMetaMessage needReport = BuildFuzzedMetaMessage(fdp);
        needReport.Checkfailed(false);
        NotificationAnalyticsUtil::ReportDeleteFailedEvent(request, needReport);
        NotificationAnalyticsUtil::ReportPublishSuccessEvent(request, message);
        NotificationAnalyticsUtil::ReportSAPublishSuccessEvent(request, fdp->ConsumeIntegral<int32_t>());
        NotificationAnalyticsUtil::ReportPublishWithUserInput(request);
        NotificationAnalyticsUtil::ReportPublishBadge(request);
        NotificationAnalyticsUtil::ReportBadgeChange(nullptr);
        return true;
    }

    bool TestLiveViewReportBranches(FuzzedDataProvider *fdp)
    {
        sptr<NotificationRequest> liveViewWithExtra =
            BuildLiveViewRequest(fdp, false, true, NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
        if (liveViewWithExtra != nullptr) {
            NotificationAnalyticsUtil::ReportLiveViewNumber(liveViewWithExtra, FUZZ_ANS_CUSTOMIZE_CODE);
            NotificationAnalyticsUtil::ReportLiveViewNumber(liveViewWithExtra, FUZZ_PUBLISH_ERROR_EVENT_CODE);
        }
        sptr<NotificationRequest> liveViewNoExtra =
            BuildLiveViewRequest(fdp, false, false, NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
        if (liveViewNoExtra != nullptr) {
            NotificationAnalyticsUtil::ReportLiveViewNumber(liveViewNoExtra, FUZZ_ANS_CUSTOMIZE_CODE);
        }
        sptr<NotificationRequest> liveViewNullContent = new NotificationRequest();
        if (liveViewNullContent != nullptr) {
            liveViewNullContent->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
            NotificationAnalyticsUtil::ReportLiveViewNumber(liveViewNullContent, FUZZ_ANS_CUSTOMIZE_CODE);
        }
        sptr<NotificationRequest> localLiveView = BuildLiveViewRequest(fdp, true, false,
            NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
        if (localLiveView != nullptr) {
            NotificationAnalyticsUtil::ReportLiveViewNumber(localLiveView, FUZZ_ANS_CUSTOMIZE_CODE);
            NotificationAnalyticsUtil::ReportLiveViewNumber(localLiveView, FUZZ_PUBLISH_ERROR_EVENT_CODE);
        }
        return true;
    }

    bool TestBadgeChangeBranches(FuzzedDataProvider *fdp)
    {
        // badge count boundaries 0/1/99/100/overflow drive the "99+" formatting branches
        static const int32_t badgeBoundaries[] = { 0, 1, 99, 100, INT32_MAX };
        std::string bundle = fdp->ConsumeRandomLengthString(FUZZ_BUNDLE_NAME_LEN);
        for (int32_t badgeNum : badgeBoundaries) {
            sptr<BadgeNumberCallbackData> badgeData =
                new BadgeNumberCallbackData(bundle, bundle, fdp->ConsumeIntegral<int32_t>(), badgeNum);
            NotificationAnalyticsUtil::ReportBadgeChange(badgeData);
        }
        return true;
    }

    bool TestCustomizeReports(FuzzedDataProvider *fdp)
    {
        nlohmann::json data;
        data["bundle"] = fdp->ConsumeRandomLengthString(FUZZ_BUNDLE_NAME_LEN);
        data["count"] = fdp->ConsumeIntegral<int32_t>();
        NotificationAnalyticsUtil::ReportCustomizeInfo(data, fdp->ConsumeIntegral<int32_t>());
        NotificationAnalyticsUtil::ReportVoiceBroadcastInfo(fdp->ConsumeIntegral<int32_t>(),
            fdp->ConsumeRandomLengthString(FUZZ_MESSAGE_LEN), fdp->ConsumeRandomLengthString(FUZZ_MESSAGE_LEN));
        NotificationCloneBundleInfo cloneInfo;
        cloneInfo.SetBundleName(fdp->ConsumeRandomLengthString(FUZZ_BUNDLE_NAME_LEN));
        cloneInfo.SetAppIndex(fdp->ConsumeIntegral<int32_t>());
        NotificationAnalyticsUtil::ReportCloneInfo(cloneInfo);
        std::vector<std::string> triggerBundles;
        uint8_t bundleCount = fdp->ConsumeIntegral<uint8_t>() % TRIGGER_BUNDLE_MAX;
        for (uint8_t i = 0; i < bundleCount; i++) {
            triggerBundles.push_back(fdp->ConsumeRandomLengthString(FUZZ_BUNDLE_NAME_LEN));
        }
        NotificationAnalyticsUtil::ReportTriggerLiveView(triggerBundles);
        HaOperationMessage operationMessage(fdp->ConsumeBool());
        NotificationAnalyticsUtil::ReportOperationsDotEvent(operationMessage);
        return true;
    }

    bool TestFlowControlAndExtraInfo(FuzzedDataProvider *fdp)
    {
        NotificationAnalyticsUtil::ReportFlowControl(FUZZ_MODIFY_ERROR_EVENT_CODE);
        NotificationAnalyticsUtil::ReportFlowControl(FUZZ_PUBLISH_ERROR_EVENT_CODE);
        NotificationAnalyticsUtil::ReportFlowControl(fdp->ConsumeIntegral<int32_t>());
        HaMetaMessage shortMessage = BuildFuzzedMetaMessage(fdp);
        shortMessage.Message("e");
        NotificationAnalyticsUtil::BuildExtraInfo(shortMessage);
        HaMetaMessage longMessage = BuildFuzzedMetaMessage(fdp);
        longMessage.Message(std::string(OVERLONG_DETAIL_LEN, 'd'));
        NotificationAnalyticsUtil::BuildExtraInfo(longMessage);
        sptr<NotificationRequest> request = BuildLiveViewRequest(fdp, false, true,
            NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
        if (request != nullptr) {
            NotificationAnalyticsUtil::BuildExtraInfoWithReq(shortMessage, request);
            NotificationAnalyticsUtil::BuildExtraInfoWithReq(longMessage, request);
        }
        sptr<NotificationRequest> plainRequest = BuildFuzzedReportRequest(fdp);
        if (plainRequest != nullptr) {
            NotificationAnalyticsUtil::BuildExtraInfoWithReq(shortMessage, plainRequest);
        }
        NotificationAnalyticsUtil::GetTraceIdStr();
        return true;
    }

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        TestAnsStatus(fdp);
        TestHaMetaMessage(fdp);
        TestHaOperationMessage(fdp);
        TestAnalyticsUtil(fdp);
        TestMetaMessageChain(fdp);
        TestReportEventBranches(fdp);
        TestLiveViewReportBranches(fdp);
        TestBadgeChangeBranches(fdp);
        TestCustomizeReports(fdp);
        TestFlowControlAndExtraInfo(fdp);
        return true;
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
