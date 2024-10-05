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
#include "nlohmann/json.hpp"
namespace OHOS {
namespace Notification {
constexpr char MESSAGE_DELIMITER = '#';
constexpr const int32_t PUBLISH_ERROR_EVENT_CODE = 0;
constexpr const int32_t DELETE_ERROR_EVENT_CODE = 5;
constexpr const int32_t MODIFY_ERROR_EVENT_CODE = 6;
constexpr const int32_t DEFAULT_ERROR_EVENT_COUNT = 6;
constexpr const int32_t DEFAULT_ERROR_EVENT_TIME = 60;
constexpr const int32_t PUBLISH_ERROR_EVENT_COUNT = 3;
constexpr const int32_t PUBLISH_ERROR_EVENT_TIME = 60;
constexpr const int32_t DELETE_ERROR_EVENT_COUNT = 3;
constexpr const int32_t DELETE_ERROR_EVENT_TIME = 60;
const static std::string NOTIFICATION_EVENT_PUSH_AGENT = "notification.event.PUSH_AGENT";
static std::mutex reportFlowControlMutex_;
static std::map<int32_t, std::list<std::chrono::system_clock::time_point>> flowControlTimestampMap_ = {
    {MODIFY_ERROR_EVENT_CODE, {}},
    {PUBLISH_ERROR_EVENT_CODE, {}},
    {DELETE_ERROR_EVENT_CODE, {}},
};

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
    nlohmann::json reason;
    std::string extraInfo = NotificationAnalyticsUtil::BuildExtraInfoWithReq(message, request, reason);
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
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberPermissions({OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER});
    EventFwk::CommonEventData commonData {want, eventCode, ""};
    ANS_LOGD("Publish event success %{public}d, %{public}s", eventCode, reason.c_str());
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonData, publishInfo)) {
        ANS_LOGE("Publish event failed %{public}d, %{public}s", eventCode, reason.c_str());
    }
}

void NotificationAnalyticsUtil::ReportModifyEvent(const HaMetaMessage& message)
{
    if (!ReportFlowControl(MODIFY_ERROR_EVENT_CODE)) {
        ANS_LOGI("Publish event failed, reason:%{public}s", message.Build().c_str());
        return;
    }
    EventFwk::Want want;
    nlohmann::json reason;
    std::string extraInfo = NotificationAnalyticsUtil::BuildExtraInfo(message, reason);
    NotificationAnalyticsUtil::SetCommonWant(want, message, extraInfo);

    want.SetParam("slotType", static_cast<int32_t>(message.slotType_));
    IN_PROCESS_CALL_WITHOUT_RET(ReportNotificationEvent(want, MODIFY_ERROR_EVENT_CODE,
        message.Build()));
}

void NotificationAnalyticsUtil::ReportDeleteFailedEvent(const HaMetaMessage& message)
{
    if (!ReportFlowControl(DELETE_ERROR_EVENT_CODE)) {
        ANS_LOGI("Publish event failed, reason:%{public}s", message.Build().c_str());
        return;
    }
    EventFwk::Want want;
    nlohmann::json reason;
    std::string extraInfo = NotificationAnalyticsUtil::BuildExtraInfo(message, reason);
    NotificationAnalyticsUtil::SetCommonWant(want, message, extraInfo);

    want.SetParam("agentBundleName", message.agentBundleName_);
    want.SetParam("typeCode", message.typeCode_);
    want.SetParam("id", message.notificationId_);

    IN_PROCESS_CALL_WITHOUT_RET(ReportNotificationEvent(
        want, DELETE_ERROR_EVENT_CODE, message.Build()));
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
            option.count = DEFAULT_ERROR_EVENT_COUNT;
            option.time = DEFAULT_ERROR_EVENT_TIME;
            break;
        case PUBLISH_ERROR_EVENT_CODE:
            option.count = PUBLISH_ERROR_EVENT_COUNT;
            option.time = PUBLISH_ERROR_EVENT_TIME;
            break;
        case DELETE_ERROR_EVENT_CODE:
            option.count = DELETE_ERROR_EVENT_COUNT;
            option.time = DELETE_ERROR_EVENT_TIME;
            break;
        default:
            option.count = DEFAULT_ERROR_EVENT_COUNT;
            option.time = DEFAULT_ERROR_EVENT_TIME;
            break;
    }
    return option;
}

std::string NotificationAnalyticsUtil::BuildExtraInfo(const HaMetaMessage& message, nlohmann::json& reason)
{
    reason["scene"] = message.sceneId_;
    reason["branch"] = message.branchId_;
    reason["innerErr"] = message.errorCode_;
    reason["detail"] = message.message_;

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    reason["time"] = now;

    std::shared_ptr<AAFwk::WantParams> extraInfo = std::make_shared<AAFwk::WantParams>();
    extraInfo->SetParam("reason", AAFwk::String::Box(reason.dump()));
    AAFwk::WantParamWrapper wWrapper(*extraInfo);

    return wWrapper.ToString();
}

std::string NotificationAnalyticsUtil::BuildExtraInfoWithReq(const HaMetaMessage& message,
    const sptr<NotificationRequest>& request, nlohmann::json& reason)
{
    NotificationNapi::ContentType contentType;
    NotificationNapi::AnsEnumUtil::ContentTypeCToJS(
        static_cast<NotificationContent::Type>(request->GetNotificationType()), contentType);
    if (contentType == NotificationNapi::ContentType::NOTIFICATION_CONTENT_LOCAL_LIVE_VIEW ||
        contentType == NotificationNapi::ContentType::NOTIFICATION_CONTENT_LIVE_VIEW) {
        ANS_LOGI("ContentType is liveview type");
        auto content = request->GetContent()->GetNotificationContent();
        auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(content);
        if (liveViewContent != nullptr) {
            reason["status"] = static_cast<int32_t>(liveViewContent->GetLiveViewStatus());
        } else {
            ANS_LOGW("liveViewContent is nullptr");
        }
    }

    return NotificationAnalyticsUtil::BuildExtraInfo(message, reason);
}

void NotificationAnalyticsUtil::SetCommonWant(EventFwk::Want& want, const HaMetaMessage& message,
    std::string& extraInfo)
{
    want.SetBundle(message.bundleName_);
    want.SetParam("extraInfo", extraInfo);
    want.SetAction(NOTIFICATION_EVENT_PUSH_AGENT);
}
} // namespace Notification
} // namespace OHOS
