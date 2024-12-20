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

#include "notification_analytics_util.h"

#include "want_params_wrapper.h"
#include "string_wrapper.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "common_event_publish_info.h"
#include "ans_convert_enum.h"
#include "ans_permission_def.h"
#include "in_process_call_wrapper.h"
#include "report_timer_info.h"
#include "time_service_client.h"
#include "nlohmann/json.hpp"
#include "bundle_manager_helper.h"
namespace OHOS {
namespace Notification {
constexpr char MESSAGE_DELIMITER = '#';
constexpr const int32_t PUBLISH_ERROR_EVENT_CODE = 0;
constexpr const int32_t DELETE_ERROR_EVENT_CODE = 5;
constexpr const int32_t MODIFY_ERROR_EVENT_CODE = 6;

constexpr const int32_t DEFAULT_ERROR_EVENT_COUNT = 5;
constexpr const int32_t DEFAULT_ERROR_EVENT_TIME = 60;
constexpr const int32_t MODIFY_ERROR_EVENT_COUNT = 6;
constexpr const int32_t MODIFY_ERROR_EVENT_TIME = 60;

constexpr const int32_t REPORT_CACHE_MAX_SIZE = 50;
constexpr const int32_t REPORT_CACHE_INTERVAL_TIME = 30;
constexpr const int32_t REASON_MAX_LENGTH = 127;
const static std::string NOTIFICATION_EVENT_PUSH_AGENT = "notification.event.PUSH_AGENT";
static std::mutex reportFlowControlMutex_;
static std::map<int32_t, std::list<std::chrono::system_clock::time_point>> flowControlTimestampMap_ = {
    {MODIFY_ERROR_EVENT_CODE, {}},
    {PUBLISH_ERROR_EVENT_CODE, {}},
    {DELETE_ERROR_EVENT_CODE, {}},
};

static std::mutex reportCacheMutex_;
static uint64_t reportTimerId = 0;
static std::list<ReportCache> reportCacheList;
static bool g_reportFlag = false;
static std::shared_ptr<ReportTimerInfo> reportTimeInfo = std::make_shared<ReportTimerInfo>();

HaMetaMessage::HaMetaMessage(uint32_t sceneId, uint32_t branchId)
    : sceneId_(sceneId), branchId_(branchId)
{
}

bool HaMetaMessage::NeedReport() const
{
    if (errorCode_ == ERR_OK && checkfailed_) {
        return false;
    }
    return true;
}

HaMetaMessage& HaMetaMessage::SceneId(uint32_t sceneId)
{
    sceneId_ = sceneId;
    return *this;
}

HaMetaMessage& HaMetaMessage::BranchId(uint32_t branchId)
{
    branchId_ = branchId;
    return *this;
}

HaMetaMessage& HaMetaMessage::ErrorCode(uint32_t errorCode)
{
    errorCode_ = errorCode;
    return *this;
}

HaMetaMessage& HaMetaMessage::Message(const std::string& message, bool print)
{
    message_ = message;
    if (print) {
        ANSR_LOGE("%{public}s, %{public}d", message.c_str(), errorCode_);
    }
    return *this;
}

HaMetaMessage& HaMetaMessage::Append(const std::string& message)
{
    message_+=message;
    return *this;
}
HaMetaMessage& HaMetaMessage::Checkfailed(bool checkfailed)
{
    checkfailed_ = checkfailed;
    return *this;
}

HaMetaMessage& HaMetaMessage::BundleName(const std::string& bundleName)
{
    bundleName_ = bundleName;
    return *this;
}

HaMetaMessage& HaMetaMessage::AgentBundleName(const std::string& agentBundleName)
{
    agentBundleName_ = agentBundleName;
    return *this;
}

HaMetaMessage& HaMetaMessage::TypeCode(int32_t typeCode)
{
    typeCode_ = typeCode;
    return *this;
}

HaMetaMessage& HaMetaMessage::NotificationId(int32_t notificationId)
{
    notificationId_ = notificationId;
    return *this;
}

std::string HaMetaMessage::GetMessage() const
{
    return message_;
}

HaMetaMessage& HaMetaMessage::SlotType(int32_t slotType)
{
    slotType_ = static_cast<uint32_t>(slotType);
    return *this;
}

std::string HaMetaMessage::Build() const
{
    return std::to_string(sceneId_) + MESSAGE_DELIMITER +
        std::to_string(branchId_) + MESSAGE_DELIMITER + std::to_string(errorCode_) +
        MESSAGE_DELIMITER + message_ + MESSAGE_DELIMITER;
}

void NotificationAnalyticsUtil::ReportPublishFailedEvent(const sptr<NotificationRequest>& request,
    const HaMetaMessage& message)
{
    CommonNotificationEvent(request, PUBLISH_ERROR_EVENT_CODE, message);
}

void NotificationAnalyticsUtil::ReportDeleteFailedEvent(const sptr<NotificationRequest>& request,
    HaMetaMessage& message)
{
    if (request == nullptr || !message.NeedReport()) {
        ANS_LOGE("request is null %{public}d", message.NeedReport());
        return;
    }
    std::shared_ptr<NotificationBundleOption> agentBundleNameOption = request->GetAgentBundle();
    if (agentBundleNameOption != nullptr) {
        std::string agentBundleName = agentBundleNameOption->GetBundleName();
        if (!agentBundleName.empty()) {
            message = message.AgentBundleName(agentBundleName);
        }
    }
    CommonNotificationEvent(request, DELETE_ERROR_EVENT_CODE, message);
}

void NotificationAnalyticsUtil::CommonNotificationEvent(const sptr<NotificationRequest>& request,
    int32_t eventCode, const HaMetaMessage& message)
{
    if (request == nullptr) {
        return;
    }

    if (!ReportFlowControl(eventCode)) {
        ANS_LOGI("Publish event failed, eventCode:%{public}d, reason:%{public}s",
            eventCode, message.Build().c_str());
        return;
    }
    EventFwk::Want want;
    std::string extraInfo;
    if (eventCode == PUBLISH_ERROR_EVENT_CODE) {
        extraInfo = NotificationAnalyticsUtil::BuildExtraInfoWithReqPublishFail(message, request);
    } else {
        extraInfo = NotificationAnalyticsUtil::BuildExtraInfoWithReq(message, request);
    }
    NotificationAnalyticsUtil::SetCommonWant(want, message, extraInfo);

    want.SetParam("typeCode", message.typeCode_);
    IN_PROCESS_CALL_WITHOUT_RET(ReportNotificationEvent(
        request, want, eventCode, message.Build()));
}

void NotificationAnalyticsUtil::ReportNotificationEvent(const sptr<NotificationRequest>& request,
    EventFwk::Want want, int32_t eventCode, const std::string& reason)
{
    NotificationNapi::SlotType slotType;
    NotificationNapi::AnsEnumUtil::SlotTypeCToJS(
        static_cast<NotificationConstant::SlotType>(request->GetSlotType()), slotType);
    NotificationNapi::ContentType contentType;
    NotificationNapi::AnsEnumUtil::ContentTypeCToJS(
        static_cast<NotificationContent::Type>(request->GetNotificationType()), contentType);

    want.SetParam("id", request->GetNotificationId());
    want.SetParam("uid", request->GetOwnerUid());
    want.SetParam("slotType", static_cast<int32_t>(slotType));
    want.SetParam("contentType", std::to_string(static_cast<int32_t>(contentType)));

    if (!request->GetCreatorBundleName().empty()) {
        want.SetParam("agentBundleName", request->GetCreatorBundleName());
    }
    if (!request->GetOwnerBundleName().empty()) {
        want.SetBundle(request->GetOwnerBundleName());
    }
    IN_PROCESS_CALL_WITHOUT_RET(AddListCache(want, eventCode));
}

void NotificationAnalyticsUtil::ReportModifyEvent(const HaMetaMessage& message)
{
    if (!ReportFlowControl(MODIFY_ERROR_EVENT_CODE)) {
        ANS_LOGI("Publish event failed, reason:%{public}s", message.Build().c_str());
        return;
    }
    EventFwk::Want want;
    std::string extraInfo = NotificationAnalyticsUtil::BuildExtraInfo(message);
    NotificationAnalyticsUtil::SetCommonWant(want, message, extraInfo);

    std::string bundle;
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager != nullptr) {
        bundle = bundleManager->GetBundleNameByUid(callingUid);
    }
    want.SetBundle(bundle + "_" + std::to_string(callingUid));
    want.SetParam("slotType", static_cast<int32_t>(message.slotType_));
    IN_PROCESS_CALL_WITHOUT_RET(AddListCache(want, MODIFY_ERROR_EVENT_CODE));
}

void NotificationAnalyticsUtil::ReportDeleteFailedEvent(const HaMetaMessage& message)
{
    if (!ReportFlowControl(DELETE_ERROR_EVENT_CODE)) {
        ANS_LOGI("Publish event failed, reason:%{public}s", message.Build().c_str());
        return;
    }
    EventFwk::Want want;
    std::string extraInfo = NotificationAnalyticsUtil::BuildExtraInfo(message);
    NotificationAnalyticsUtil::SetCommonWant(want, message, extraInfo);

    want.SetParam("agentBundleName", message.agentBundleName_);
    want.SetParam("typeCode", message.typeCode_);
    want.SetParam("id", message.notificationId_);

    IN_PROCESS_CALL_WITHOUT_RET(AddListCache(want, DELETE_ERROR_EVENT_CODE));
}

void NotificationAnalyticsUtil::ReportNotificationEvent(EventFwk::Want want,
    int32_t eventCode, const std::string& reason)
{
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberPermissions({OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER});
    EventFwk::CommonEventData commonData {want, eventCode, ""};
    ANS_LOGD("Publish event success %{public}d, %{public}s", eventCode, reason.c_str());
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonData, publishInfo)) {
        ANS_LOGE("Publish event failed %{public}d, %{public}s", eventCode, reason.c_str());
    }
}

bool NotificationAnalyticsUtil::ReportFlowControl(const int32_t reportType)
{
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    std::lock_guard<std::mutex> lock(reportFlowControlMutex_);
    auto iter = flowControlTimestampMap_.find(reportType);
    if (iter == flowControlTimestampMap_.end()) {
        return false;
    }
    auto& list = iter->second;
    FlowControllerOption option = GetFlowOptionByType(reportType);
    RemoveExpired(list, now, option.time);
    int32_t size = static_cast<int32_t>(list.size());
    int32_t count = option.count;
    if (size >= count) {
        return false;
    }
    list.push_back(now);
    return true;
}

void NotificationAnalyticsUtil::RemoveExpired(std::list<std::chrono::system_clock::time_point> &list,
    const std::chrono::system_clock::time_point &now, int32_t time)
{
    auto iter = list.begin();
    while (iter != list.end()) {
        if (abs(now - *iter) > std::chrono::seconds(time)) {
            iter = list.erase(iter);
        } else {
            break;
        }
    }
}

FlowControllerOption NotificationAnalyticsUtil::GetFlowOptionByType(const int32_t reportType)
{
    FlowControllerOption option;
    switch (reportType) {
        case MODIFY_ERROR_EVENT_CODE:
            option.count = MODIFY_ERROR_EVENT_COUNT;
            option.time = MODIFY_ERROR_EVENT_TIME;
            break;
        default:
            option.count = DEFAULT_ERROR_EVENT_COUNT;
            option.time = DEFAULT_ERROR_EVENT_TIME;
            break;
    }
    return option;
}

std::string NotificationAnalyticsUtil::BuildExtraInfo(const HaMetaMessage& message)
{
    nlohmann::json reason;
    reason["scene"] = message.sceneId_;
    reason["branch"] = message.branchId_;
    reason["innerErr"] = message.errorCode_;
    reason["detail"] = message.message_;

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    reason["time"] = now;

    std::shared_ptr<AAFwk::WantParams> extraInfo = std::make_shared<AAFwk::WantParams>();

    reason["detail"] = "";
    int32_t reasonFixedSize =
        static_cast<int32_t>(reason.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace).size());
    int32_t leftSpace = REASON_MAX_LENGTH - reasonFixedSize;
    if (leftSpace < 0) {
        std::string basicInfo = std::to_string(message.sceneId_) + MESSAGE_DELIMITER +
            std::to_string(message.branchId_) + MESSAGE_DELIMITER +
            std::to_string(message.errorCode_) + MESSAGE_DELIMITER +
            std::to_string(now) + " Reason fixed size exceeds limit";
        extraInfo->SetParam("reason", AAFwk::String::Box(basicInfo));
        ANS_LOGI("%{public}s", basicInfo.c_str());
    } else {
        reason["detail"] = message.message_.substr(0, leftSpace);
        extraInfo->SetParam("reason",
            AAFwk::String::Box(reason.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace)));
    }

    AAFwk::WantParamWrapper wWrapper(*extraInfo);

    return wWrapper.ToString();
}

std::string NotificationAnalyticsUtil::BuildExtraInfoWithReq(const HaMetaMessage& message,
    const sptr<NotificationRequest>& request)
{
    NotificationNapi::ContentType contentType;
    NotificationNapi::AnsEnumUtil::ContentTypeCToJS(
        static_cast<NotificationContent::Type>(request->GetNotificationType()), contentType);
    nlohmann::json reason;
    if (contentType == NotificationNapi::ContentType::NOTIFICATION_CONTENT_LIVE_VIEW) {
        auto content = request->GetContent()->GetNotificationContent();
        auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(content);
        reason["status"] = static_cast<int32_t>(liveViewContent->GetLiveViewStatus());
    }

    reason["scene"] = message.sceneId_;
    reason["branch"] = message.branchId_;
    reason["innerErr"] = message.errorCode_;
    reason["detail"] = message.message_;

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    reason["time"] = now;

    std::shared_ptr<AAFwk::WantParams> extraInfo = nullptr;
    if (request->GetUnifiedGroupInfo() != nullptr &&
        request->GetUnifiedGroupInfo()->GetExtraInfo() != nullptr) {
        extraInfo = request->GetUnifiedGroupInfo()->GetExtraInfo();
    } else {
        extraInfo = std::make_shared<AAFwk::WantParams>();
    }

    reason["detail"] = "";
    int32_t reasonFixedSize =
        static_cast<int32_t>(reason.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace).size());
    int32_t leftSpace = REASON_MAX_LENGTH - reasonFixedSize;
    if (leftSpace < 0) {
        std::string basicInfo = std::to_string(message.sceneId_) + MESSAGE_DELIMITER +
            std::to_string(message.branchId_) + MESSAGE_DELIMITER +
            std::to_string(message.errorCode_) + MESSAGE_DELIMITER +
            std::to_string(now) + " Reason fixed size exceeds limit";
        extraInfo->SetParam("reason", AAFwk::String::Box(basicInfo));
        ANS_LOGI("%{public}s", basicInfo.c_str());
    } else {
        reason["detail"] = message.message_.substr(0, leftSpace);
        extraInfo->SetParam("reason",
            AAFwk::String::Box(reason.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace)));
    }
    
    AAFwk::WantParamWrapper wWrapper(*extraInfo);

    return wWrapper.ToString();
}

std::string NotificationAnalyticsUtil::BuildExtraInfoWithReqPublishFail(const HaMetaMessage& message,
    const sptr<NotificationRequest>& request)
{
    NotificationNapi::ContentType contentType;
    NotificationNapi::AnsEnumUtil::ContentTypeCToJS(
        static_cast<NotificationContent::Type>(request->GetNotificationType()), contentType);
    nlohmann::json reason;
    if (contentType == NotificationNapi::ContentType::NOTIFICATION_CONTENT_LIVE_VIEW) {
        auto content = request->GetContent()->GetNotificationContent();
        auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(content);
        reason["status"] = static_cast<int32_t>(liveViewContent->GetLiveViewStatus());
    }
    
    reason["scene"] = message.sceneId_;
    reason["branch"] = message.branchId_;
    reason["innerErr"] = message.errorCode_;
    reason["detail"] = message.message_;
    reason["fg"] = std::to_string(request->GetNotificationControlFlags());

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    reason["time"] = now;

    std::shared_ptr<AAFwk::WantParams> extraInfo = nullptr;
    if (request->GetUnifiedGroupInfo() != nullptr &&
        request->GetUnifiedGroupInfo()->GetExtraInfo() != nullptr) {
        extraInfo = request->GetUnifiedGroupInfo()->GetExtraInfo();
    } else {
        extraInfo = std::make_shared<AAFwk::WantParams>();
    }

    reason["detail"] = "";
    int32_t reasonFixedSize =
        static_cast<int32_t>(reason.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace).size());
    int32_t leftSpace = REASON_MAX_LENGTH - reasonFixedSize;
    if (leftSpace < 0) {
        std::string basicInfo = std::to_string(message.sceneId_) + MESSAGE_DELIMITER +
            std::to_string(message.branchId_) + MESSAGE_DELIMITER +
            std::to_string(message.errorCode_) + MESSAGE_DELIMITER +
            std::to_string(now) + " Reason fixed size exceeds limit";
        extraInfo->SetParam("reason", AAFwk::String::Box(basicInfo));
        ANS_LOGI("%{public}s", basicInfo.c_str());
    } else {
        reason["detail"] = message.message_.substr(0, leftSpace);
        extraInfo->SetParam("reason",
            AAFwk::String::Box(reason.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace)));
    }
    
    AAFwk::WantParamWrapper wWrapper(*extraInfo);

    return wWrapper.ToString();
}

void NotificationAnalyticsUtil::SetCommonWant(EventFwk::Want& want, const HaMetaMessage& message,
    std::string& extraInfo)
{
    want.SetBundle(message.bundleName_);
    want.SetParam("extraInfo", extraInfo);
    want.SetAction(NOTIFICATION_EVENT_PUSH_AGENT);
}

void NotificationAnalyticsUtil::AddListCache(EventFwk::Want& want, int32_t eventCode)
{
    std::lock_guard<std::mutex> lock(reportCacheMutex_);
    int32_t size = static_cast<int32_t>(reportCacheList.size());
    if (size >= REPORT_CACHE_MAX_SIZE) {
        ANS_LOGW("list size is max");
        return;
    }

    if (reportTimerId == 0) {
        sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
        if (timer == nullptr) {
            ANS_LOGE("Failed to start timer due to get TimeServiceClient is null.");
            return;
        }
        reportTimerId = timer->CreateTimer(reportTimeInfo);
    }

    ReportCache reportCache;
    reportCache.want = want;
    reportCache.eventCode = eventCode;
    reportCacheList.push_back(reportCache);
    if (!g_reportFlag) {
        ExecuteCacheList();
    }
}

void NotificationAnalyticsUtil::ExecuteCacheList()
{
    if (reportCacheList.empty()) {
        g_reportFlag = false;
        ANS_LOGI("reportCacheList is end");
        return;
    }
    auto reportCache = reportCacheList.front();
    ReportCommonEvent(reportCache);
    auto triggerFunc = [] {
        std::lock_guard<std::mutex> lock(reportCacheMutex_);
        NotificationAnalyticsUtil::ExecuteCacheList();
    };
    reportCacheList.pop_front();
    reportTimeInfo->SetCallbackInfo(triggerFunc);
    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr || reportTimerId == 0) {
        g_reportFlag = false;
        ANS_LOGE("Failed to start timer due to get TimeServiceClient is null.");
        return;
    }
    timer->StartTimer(reportTimerId, NotificationAnalyticsUtil::GetCurrentTime() +
        REPORT_CACHE_INTERVAL_TIME * NotificationConstant::SECOND_TO_MS);
    g_reportFlag = true;
}

void NotificationAnalyticsUtil::ReportCommonEvent(const ReportCache& reportCache)
{
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberPermissions({OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER});
    EventFwk::CommonEventData commonData {reportCache.want, reportCache.eventCode, ""};
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonData, publishInfo)) {
        ANS_LOGE("Publish event failed %{public}d", reportCache.eventCode);
    }
}

int64_t NotificationAnalyticsUtil::GetCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return duration.count();
}
} // namespace Notification
} // namespace OHOS
