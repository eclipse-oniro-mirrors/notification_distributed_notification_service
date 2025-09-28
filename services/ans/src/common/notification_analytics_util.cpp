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

#include <regex>

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
#include "notification_config_parse.h"
#include "notification_preferences.h"
#include "os_account_manager_helper.h"
#include "notification_constant.h"
#include "advanced_notification_inline.h"
#include "hitrace_util.h"
#include "ffrt.h"

namespace OHOS {
namespace Notification {

const static std::string LINE = "_";
const static std::string ANS_BUNDLE_BEGIN = "ans_bundle";
const static std::string LIVE_VIEW_SLOT_ENABLE_END = "slot_type_5_enabled";
const static std::string SLOT_ENABLE_REG_PATTERN = "^ans_bundle_(.*)_slot_type_5_enabled$";
const static std::string NAME = "name";
const static std::string UID = "uid";

constexpr char MESSAGE_DELIMITER = '#';
constexpr const int32_t SYNC_WATCH_HEADSET = 2;
constexpr const int32_t PUBLISH_ERROR_EVENT_CODE = 0;
constexpr const int32_t DELETE_ERROR_EVENT_CODE = 5;
constexpr const int32_t MODIFY_ERROR_EVENT_CODE = 6;
constexpr const int32_t ANS_CUSTOMIZE_CODE = 7;
constexpr const int32_t BADGE_CHANGE_CODE = 201;
static int32_t LIVEVIEW_TRIGGER_SUB_CODE = 103;
constexpr const int32_t CLONE_SUB_CODE = 104;

constexpr const int32_t DEFAULT_ERROR_EVENT_COUNT = 5;
constexpr const int32_t DEFAULT_ERROR_EVENT_TIME = 60;
constexpr const int32_t MODIFY_ERROR_EVENT_COUNT = 6;
constexpr const int32_t MODIFY_ERROR_EVENT_TIME = 60;
constexpr const int32_t MAX_NUMBER_EVERY_REPORT = 20;
constexpr const int32_t MAX_REPORT_COUNT = 3;
constexpr const int32_t MAX_BADGE_AGGRATE_NUM = 20;
constexpr const int32_t MAX_NUMBER_EVERY_BADGE_DATA = 20;

constexpr const int32_t REPORT_CACHE_MAX_SIZE = 50;
constexpr const int32_t SUCCESS_REPORT_CACHE_MAX_SIZE = 60;
constexpr const int32_t REPORT_CACHE_INTERVAL_TIME = 30;
constexpr const int32_t SUCCESS_REPORT_CACHE_INTERVAL_TIME = 1800;
constexpr const int32_t REASON_MAX_LENGTH = 255;
constexpr const int32_t MAX_BADGE_NUMBER = 99;
constexpr const int32_t SUB_CODE = 100;
constexpr const int32_t MAX_TIME = 43200000;
constexpr const int32_t MAX_BADGE_CHANGE_REPORT_TIME = 1800000;
constexpr const int32_t TIMEOUT_TIME_OF_BADGE = 5400000;
constexpr const int32_t NOTIFICATION_MAX_DATA = 100;
constexpr const int32_t SOUND_FLAG = 1 << 10;
constexpr const int32_t LOCKSCREEN_FLAG = 1 << 11;
constexpr const int32_t BANNER_FLAG = 1 << 12;
constexpr const int32_t VIBRATION_FLAG = 1 << 13;

const static std::string NOTIFICATION_EVENT_PUSH_AGENT = "notification.event.PUSH_AGENT";
static ffrt::mutex reportFlowControlMutex_;
static std::map<int32_t, std::list<std::chrono::system_clock::time_point>> flowControlTimestampMap_ = {
    {MODIFY_ERROR_EVENT_CODE, {}},
    {PUBLISH_ERROR_EVENT_CODE, {}},
    {DELETE_ERROR_EVENT_CODE, {}},
    {ANS_CUSTOMIZE_CODE, {}},
};
static std::map<std::string, BadgeInfo> badgeInfos;
static std::map<std::string, ReportLiveViewMessage> liveViewMessages;

static ffrt::mutex reportCacheMutex_;
static uint64_t reportTimerId = 0;
static std::list<ReportCache> reportCacheList;
static bool g_reportFlag = false;
static std::shared_ptr<ReportTimerInfo> reportTimeInfo = std::make_shared<ReportTimerInfo>();

static ffrt::mutex badgeInfosMutex_;
static ffrt::mutex reportSuccessCacheMutex_;
static uint64_t reportAggregateTimeId = 0;
static std::list<ReportCache> successReportCacheList;
static bool g_successReportFlag = false;
static std::shared_ptr<ReportTimerInfo> reportAggregateTimeInfo = std::make_shared<ReportTimerInfo>();
static ffrt::mutex reportAggListMutex_;
static std::list<ReportCache> reportAggList;

static int32_t SLOT_REPORT_INTERVAL = 7 * 24 * NotificationConstant::HOUR_TO_MS;
static int64_t lastReportTime_ = 0;
static ffrt::mutex lastReportTimeMutex_;
static int32_t SLOT_SUB_CODE = 101;
static int32_t DISTRIBUTED_SUB_CODE = 102;
static int32_t SLOT_ONCE_REPORT = 10;
static uint32_t SLOT_MAX_REPORT = 200;
static uint64_t reportSlotEnabledTimerId_ = 0;
static std::shared_ptr<ReportTimerInfo> slotTimeInfo = std::make_shared<ReportTimerInfo>();
static std::list<ReportSlotMessage> slotEnabledList_;
static ffrt::mutex slotEnabledListMutex_;
static bool g_reportSlotFlag = false;
static ffrt::mutex reportSlotEnabledMutex_;

static int32_t LIVEVIEW_SUB_CODE = 202;
static int32_t LIVEVIEW_AGGREGATE_NUM = 10;
static ffrt::mutex ReportLiveViewMessageMutex_;
static uint64_t reportLiveViewMessageTimerId_ = 0;
static std::shared_ptr<ReportTimerInfo> liveViewTimeInfo = std::make_shared<ReportTimerInfo>();
static int32_t LIVEVIEW_REPORT_INTERVAL = 2 * NotificationConstant::HOUR_TO_MS;
static const int32_t LIVE_VIEW_CREATE = 0;
static bool g_reportLiveViewFlag = false;
OperationalData HaOperationMessage::notificationData = OperationalData();
OperationalData HaOperationMessage::liveViewData = OperationalData();

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

HaMetaMessage& HaMetaMessage::Path(const std::string &path)
{
    path_ = path;
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

HaMetaMessage& HaMetaMessage::DeleteReason(int32_t deleteReason)
{
    deleteReason_ = deleteReason;
    return *this;
}

std::string HaMetaMessage::Build() const
{
    return std::to_string(sceneId_) + MESSAGE_DELIMITER +
        std::to_string(branchId_) + MESSAGE_DELIMITER + std::to_string(errorCode_) +
        MESSAGE_DELIMITER + message_ + MESSAGE_DELIMITER;
}

void OperationalMeta::ToJson(nlohmann::json& jsonObject)
{
    jsonObject["cr"] = createTime;
    jsonObject["sy"] = syncTime;
    jsonObject["de"] = delTime;
    jsonObject["cl"] = clickTime;
    jsonObject["re"] = replyTime;
}

OperationalData::OperationalData()
{
    for (std::string deviceType : NotificationConstant::DEVICESTYPES) {
        dataMap.insert({deviceType, OperationalMeta()});
    }
    time = NotificationAnalyticsUtil::GetCurrentTime();
}

void OperationalData::ToJson(nlohmann::json& jsonObject)
{
    for (auto& deviceData : dataMap) {
        nlohmann::json dataJson;
        deviceData.second.ToJson(dataJson);
        jsonObject[deviceData.first] = dataJson;
    }

    jsonObject["key"] = keyNode;
    jsonObject["both"] = syncWatchHead;
}

HaOperationMessage& HaOperationMessage::KeyNode(bool keyNodeFlag)
{
    if (keyNodeFlag) {
        liveViewData.keyNode++;
    }
    return *this;
}

std::string HaOperationMessage::ToJson()
{
    nlohmann::json jsonMessage;
    nlohmann::json jsonObject;
    if (isLiveView_) {
        liveViewData.ToJson(jsonMessage);
        jsonObject["liveview"] = jsonMessage;
    } else {
        notificationData.ToJson(jsonMessage);
        jsonObject["notification"] =  jsonMessage;
    }
    return jsonObject.dump();
}

void SetPublishTime(const std::string& hashCode, const std::vector<std::string>& deviceTypes,
    OperationalData& data)
{
    int32_t isWatchHeadSet = 0;
    for (auto& device : deviceTypes) {
        if (data.dataMap.find(device) != data.dataMap.end()) {
            if (!data.dataMap[device].hashCodes.count(hashCode)) {
                data.dataMap[device].createTime++;
                data.dataMap[device].hashCodes.insert(hashCode);
                data.countTime++;
            }
            data.dataMap[device].syncTime++;
            if (device == NotificationConstant::HEADSET_DEVICE_TYPE ||
                device == NotificationConstant::WEARABLE_DEVICE_TYPE ||
                device == NotificationConstant::LITEWEARABLE_DEVICE_TYPE) {
                isWatchHeadSet++;
            }
            data.countTime++;
        }
    }
    if (isWatchHeadSet >= SYNC_WATCH_HEADSET) {
        data.syncWatchHead++;
    }
}

void SetDeleteTime(const std::string& hashCode, OperationalData& data)
{
    for (auto& device : data.dataMap) {
        device.second.hashCodes.erase(hashCode);
    }
}

HaOperationMessage& HaOperationMessage::SyncPublish(const std::string& hashCode,
    std::vector<std::string>& deviceTypes)
{
    if (isLiveView_) {
        SetPublishTime(hashCode, deviceTypes, liveViewData);
    } else {
        SetPublishTime(hashCode, deviceTypes, notificationData);
    }
    return *this;
}

HaOperationMessage& HaOperationMessage::SyncDelete(const std::string& hashCode)
{
    if (isLiveView_) {
        SetDeleteTime(hashCode, liveViewData);
    } else {
        SetDeleteTime(hashCode, notificationData);
    }
    return *this;
}

HaOperationMessage& HaOperationMessage::SyncDelete(std::string deviceType, const std::string& reason)
{
    if (isLiveView_) {
        if (liveViewData.dataMap.find(deviceType) != liveViewData.dataMap.end()) {
            liveViewData.dataMap[deviceType].delTime++;
            liveViewData.countTime++;
        }
    } else {
        if (notificationData.dataMap.find(deviceType) != notificationData.dataMap.end()) {
            notificationData.dataMap[deviceType].delTime++;
            notificationData.countTime++;
        }
    }
    return *this;
}

HaOperationMessage& HaOperationMessage::SyncClick(std::string deviceType)
{
    if (isLiveView_) {
        if (liveViewData.dataMap.find(deviceType) != liveViewData.dataMap.end()) {
            liveViewData.dataMap[deviceType].clickTime++;
            liveViewData.countTime++;
        }
    } else {
        if (notificationData.dataMap.find(deviceType) != notificationData.dataMap.end()) {
            notificationData.dataMap[deviceType].clickTime++;
            notificationData.countTime++;
        }
    }
    return *this;
}

HaOperationMessage& HaOperationMessage::SyncReply(std::string deviceType)
{
    if (isLiveView_) {
        if (liveViewData.dataMap.find(deviceType) != liveViewData.dataMap.end()) {
            liveViewData.dataMap[deviceType].replyTime++;
            liveViewData.countTime++;
        }
    } else {
        if (notificationData.dataMap.find(deviceType) != notificationData.dataMap.end()) {
            notificationData.dataMap[deviceType].replyTime++;
            notificationData.countTime++;
        }
    }
    return *this;
}

bool HaOperationMessage::DetermineWhetherToSend()
{
    if (isLiveView_ && liveViewData.keyNode != 0) {
        return true;
    }
    if (isLiveView_) {
        if (liveViewData.countTime >= NOTIFICATION_MAX_DATA ||
            (NotificationAnalyticsUtil::GetCurrentTime() - liveViewData.time) >= MAX_TIME) {
            return true;
        }
    } else {
        if (notificationData.countTime >= NOTIFICATION_MAX_DATA ||
            (NotificationAnalyticsUtil::GetCurrentTime() - notificationData.time) >= MAX_TIME) {
            return true;
        }
    }
    return false;
}

void ResetOperationalData(OperationalData& data)
{
    data.countTime = 0;
    data.keyNode = 0;
    data.syncWatchHead = 0;
    data.time = NotificationAnalyticsUtil::GetCurrentTime();
    for (auto& item : data.dataMap) {
        item.second = { 0 };
    }
}

void HaOperationMessage::ResetData()
{
    if (isLiveView_) {
        ResetOperationalData(liveViewData);
    } else {
        ResetOperationalData(notificationData);
    }
}

void NotificationAnalyticsUtil::MakeRequestBundle(const sptr<NotificationRequest>& request)
{
    if (request->GetOwnerBundleName().empty() && request->GetCreatorBundleName().empty()) {
        request->SetCreatorUid(IPCSkeleton::GetCallingUid());
        request->SetCreatorBundleName(GetClientBundleName());
    }
}

void NotificationAnalyticsUtil::ReportTipsEvent(const sptr<NotificationRequest>& request,
    const HaMetaMessage& message)
{
    if (request == nullptr) {
        return;
    }
    MakeRequestBundle(request);
    CommonNotificationEvent(request, PUBLISH_ERROR_EVENT_CODE, message);
}

void NotificationAnalyticsUtil::ReportPublishFailedEvent(const sptr<NotificationRequest>& request,
    const HaMetaMessage& message)
{
    if (request == nullptr) {
        return;
    }
    MakeRequestBundle(request);
    CommonNotificationEvent(request, PUBLISH_ERROR_EVENT_CODE, message);
    ReportLiveViewNumber(request, PUBLISH_ERROR_EVENT_CODE);
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

void NotificationAnalyticsUtil::ReportPublishSuccessEvent(const sptr<NotificationRequest>& request,
    const HaMetaMessage& message)
{
    ANS_LOGD("called");
    if (request == nullptr) {
        return;
    }
    ReportLiveViewNumber(request, ANS_CUSTOMIZE_CODE);
    if (!IsAllowedBundle(request)) {
        ANS_LOGW("This Bundle not allowed.");
        return;
    }

    EventFwk::Want want;
    if (!request->GetOwnerBundleName().empty()) {
        want.SetBundle(request->GetOwnerBundleName());
    }
    if (!request->GetCreatorBundleName().empty()) {
        want.SetParam("agentBundleName", request->GetCreatorBundleName());
    }
    std::string ansData = NotificationAnalyticsUtil::BuildAnsData(request, message);
    want.SetParam("ansData", ansData);

    IN_PROCESS_CALL_WITHOUT_RET(AddSuccessListCache(want, ANS_CUSTOMIZE_CODE));
}

void NotificationAnalyticsUtil::ReportLiveViewNumber(const sptr<NotificationRequest>& request, const int32_t reportType)
{
    NotificationNapi::ContentType contentType;
    std::string bundleName = request->GetOwnerBundleName().empty() ? request->GetCreatorBundleName() :
        request->GetOwnerBundleName();
    NotificationNapi::AnsEnumUtil::ContentTypeCToJS(
        static_cast<NotificationContent::Type>(request->GetNotificationType()), contentType);
    if (contentType == NotificationNapi::ContentType::NOTIFICATION_CONTENT_LIVE_VIEW) {
        auto content = request->GetContent()->GetNotificationContent();
        auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(content);
        if (liveViewContent->GetExtraInfo() != nullptr) {
            std::string bundle = bundleName + MESSAGE_DELIMITER +
                liveViewContent->GetExtraInfo()->GetStringParam("event");
                std::lock_guard<ffrt::mutex> lock(ReportLiveViewMessageMutex_);
                if (reportType == ANS_CUSTOMIZE_CODE) {
                    AddLiveViewSuccessNum(bundle, static_cast<int32_t>(liveViewContent->GetLiveViewStatus()));
                } else if (reportType == PUBLISH_ERROR_EVENT_CODE) {
                    AddLiveViewFailedNum(bundle, static_cast<int32_t>(liveViewContent->GetLiveViewStatus()));
                }
            CreateLiveViewTimerExecute();
        }
    }
    if (contentType == NotificationNapi::ContentType::NOTIFICATION_CONTENT_LOCAL_LIVE_VIEW) {
        std::lock_guard<ffrt::mutex> lock(ReportLiveViewMessageMutex_);
        std::string bundle = bundleName + "#-99";
        if (reportType == ANS_CUSTOMIZE_CODE) {
            AddLocalLiveViewSuccessNum(bundle);
        } else if (reportType == PUBLISH_ERROR_EVENT_CODE) {
            AddLocalLiveViewFailedNum(bundle);
        }
        CreateLiveViewTimerExecute();
    }
}

void NotificationAnalyticsUtil::AddLiveViewSuccessNum(std::string bundle, int32_t status)
{
    auto iter = liveViewMessages.find(bundle);
    switch (status) {
        case LIVE_VIEW_CREATE:
            if (iter != liveViewMessages.end()) {
                iter->second.successNum ++;
            } else {
                ReportLiveViewMessage liveViewMessage;
                liveViewMessage.FailedNum = 0;
                liveViewMessage.successNum = 1;
                liveViewMessage.startTime = GetCurrentTime();
                liveViewMessages[bundle] = liveViewMessage;
            }
            break;
        default:
            break;
    }
}

void NotificationAnalyticsUtil::AddLiveViewFailedNum(std::string bundle, int32_t status)
{
    auto iter = liveViewMessages.find(bundle);
    switch (status) {
        case LIVE_VIEW_CREATE:
            if (iter != liveViewMessages.end()) {
                iter->second.FailedNum ++;
            } else {
                ReportLiveViewMessage liveViewMessage;
                liveViewMessage.FailedNum = 1;
                liveViewMessage.successNum = 0;
                liveViewMessage.startTime = GetCurrentTime();
                liveViewMessages[bundle] = liveViewMessage;
            }
            break;
        default:
            break;
    }
}

void NotificationAnalyticsUtil::AddLocalLiveViewFailedNum(std::string bundle)
{
    auto iter = liveViewMessages.find(bundle);
    if (iter != liveViewMessages.end()) {
        iter->second.FailedNum ++;
    } else {
        ReportLiveViewMessage liveViewMessage;
        liveViewMessage.FailedNum = 1;
        liveViewMessage.successNum = 0;
        liveViewMessage.startTime = GetCurrentTime();
        liveViewMessages[bundle] = liveViewMessage;
    }
}

void NotificationAnalyticsUtil::AddLocalLiveViewSuccessNum(std::string bundle)
{
    auto iter = liveViewMessages.find(bundle);
    if (iter != liveViewMessages.end()) {
        iter->second.successNum ++;
    } else {
        ReportLiveViewMessage liveViewMessage;
        liveViewMessage.FailedNum = 0;
        liveViewMessage.successNum = 1;
        liveViewMessage.startTime = GetCurrentTime();
        liveViewMessages[bundle] = liveViewMessage;
    }
}

void NotificationAnalyticsUtil::CreateLiveViewTimerExecute()
{
    if (g_reportLiveViewFlag) {
        ANS_LOGW("now has liveview message is reporting");
        return;
    }
    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANS_LOGE("null timer");
        g_reportLiveViewFlag = false;
        return;
    }
    if (reportLiveViewMessageTimerId_ == 0) {
        reportLiveViewMessageTimerId_ = timer->CreateTimer(liveViewTimeInfo);
    }

    auto triggerFunc = [] {
        ExecuteLiveViewReport();
    };

    liveViewTimeInfo->SetCallbackInfo(triggerFunc);
    timer->StartTimer(reportLiveViewMessageTimerId_, NotificationAnalyticsUtil::GetCurrentTime() +
        LIVEVIEW_REPORT_INTERVAL);
    g_reportLiveViewFlag = true;
}

void NotificationAnalyticsUtil::ExecuteLiveViewReport()
{
    {
        std::lock_guard<ffrt::mutex> lockReportLiveView(ReportLiveViewMessageMutex_);
        if (liveViewMessages.empty()) {
            ANS_LOGD("report end");
            g_reportLiveViewFlag = false;
            return;
        }
        if (reportAggregateTimeId == 0) {
            sptr<MiscServices::TimeServiceClient> aggregateTimer = MiscServices::TimeServiceClient::GetInstance();
            if (aggregateTimer == nullptr) {
                ANS_LOGE("null aggregateTimer");
                g_reportLiveViewFlag = false;
                return;
            }
            reportAggregateTimeId = aggregateTimer->CreateTimer(reportAggregateTimeInfo);
        }
        ReportCache reportCache = AggregateLiveView();
        std::lock_guard<ffrt::mutex> lockReportAggList(reportAggListMutex_);
        reportAggList.emplace_back(reportCache);
    }
    if (!g_successReportFlag) {
        ExecuteSuccessCacheList();
    }
    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANS_LOGE("null timer");
        return;
    }
    auto triggerFunc = [] {
        ExecuteLiveViewReport();
    };
    liveViewTimeInfo->SetCallbackInfo(triggerFunc);
    timer->StartTimer(reportLiveViewMessageTimerId_, NotificationAnalyticsUtil::GetCurrentTime() +
        LIVEVIEW_REPORT_INTERVAL);
    g_reportLiveViewFlag = true;
}

ReportCache NotificationAnalyticsUtil::AggregateLiveView()
{
    nlohmann::json ansData;
    ansData["subCode"] = std::to_string(LIVEVIEW_SUB_CODE);
    int32_t aggreCount = LIVEVIEW_AGGREGATE_NUM;
    std::string data;
    std::vector<std::string> reportBundles;
    int64_t startTime = GetCurrentTime();

    std::vector<std::pair<std::string, ReportLiveViewMessage>> messageVector(liveViewMessages.begin(),
        liveViewMessages.end());
    std::sort(messageVector.begin(), messageVector.end(), [](const std::pair<std::string, ReportLiveViewMessage> &a,
        std::pair<std::string, ReportLiveViewMessage> &b) {
            return a.second.startTime < b.second.startTime;
    });
    for (const auto &message : messageVector) {
        ReportLiveViewMessage liveViewData = message.second;
        std::string create = std::to_string(liveViewData.successNum) + "," + std::to_string(liveViewData.FailedNum);
        std::string update;
        std::string end;
        std::string cancel;
        std::string singleData = message.first + ":" + create + MESSAGE_DELIMITER +
            update + MESSAGE_DELIMITER + end + MESSAGE_DELIMITER + cancel + MESSAGE_DELIMITER;
        data += singleData;
        startTime = startTime < liveViewData.startTime ? startTime : liveViewData.startTime;
        reportBundles.emplace_back(message.first);
        aggreCount --;
        if (aggreCount <= 0) {
            break;
        }
        data += ",";
    }
    for (auto bundle : reportBundles) {
        liveViewMessages.erase(bundle);
    }
    ansData["data"] = data;
    ansData["startTime"] = startTime;
    ansData["endTime"] = GetCurrentTime();
    std::string message = ansData.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    EventFwk::Want want;
    want.SetAction(NOTIFICATION_EVENT_PUSH_AGENT);
    want.SetParam("ansData", message);

    ReportCache reportCache;
    reportCache.want = want;
    reportCache.eventCode = ANS_CUSTOMIZE_CODE;
    return reportCache;
}

bool NotificationAnalyticsUtil::IsAllowedBundle(const sptr<NotificationRequest>& request)
{
    ANS_LOGD("called");
    std::string bundleName = request->GetOwnerBundleName();
    return DelayedSingleton<NotificationConfigParse>::GetInstance()->IsReportTrustList(bundleName);
}

std::string NotificationAnalyticsUtil::BuildAnsData(const sptr<NotificationRequest>& request,
    const HaMetaMessage& message)
{
    ANS_LOGD("called");
    nlohmann::json ansData;
    std::shared_ptr<AAFwk::WantParams> extraInfo = nullptr;
    if (request->GetUnifiedGroupInfo() != nullptr &&
        request->GetUnifiedGroupInfo()->GetExtraInfo() != nullptr) {
        extraInfo = request->GetUnifiedGroupInfo()->GetExtraInfo();
    } else {
        extraInfo = std::make_shared<AAFwk::WantParams>();
    }
    nlohmann::json extraInfoJson;
    std::string msgId = extraInfo->GetWantParams("pushData").GetStringParam("msgId");
    if (!msgId.empty()) {
        extraInfoJson["msgId"] = msgId;
    }
    std::string uniqMsgId = extraInfo->GetWantParams("pushData").GetStringParam("mcMsgId");
    if (!uniqMsgId.empty()) {
        extraInfoJson["mcMsgId"] = uniqMsgId;
    }

    ansData["extraInfo"] = extraInfoJson.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    ansData["uid"] = std::to_string(request->GetOwnerUid());
    ansData["id"] = std::to_string(request->GetNotificationId());
    NotificationNapi::SlotType slotType;
    NotificationNapi::AnsEnumUtil::SlotTypeCToJS(
        static_cast<NotificationConstant::SlotType>(request->GetSlotType()), slotType);
    NotificationNapi::ContentType contentType;
    NotificationNapi::AnsEnumUtil::ContentTypeCToJS(
        static_cast<NotificationContent::Type>(request->GetNotificationType()), contentType);
    ansData["slotType"] = static_cast<int32_t>(slotType);
    ansData["contentType"] = std::to_string(static_cast<int32_t>(contentType));
    ansData["reminderFlags"] = std::to_string(static_cast<int32_t>(request->GetFlags()->GetReminderFlags()));
    uint32_t controlFlags = request->GetNotificationControlFlags();
    std::shared_ptr<NotificationFlags> tempFlags = request->GetFlags();
    ansData["ControlFlags"] = SetControlFlags(tempFlags, controlFlags);
    ansData["class"] = request->GetClassification();
    ansData["deviceStatus"] = GetDeviceStatus(request);
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
    ansData["time"] = now;
    ansData["traceId"] = GetTraceIdStr();
    ANS_LOGI("Ansdata built, the controlFlags is %{public}d, deviceStatus is %{public}s",
        controlFlags, GetDeviceStatus(request).c_str());
    return ansData.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

std::string NotificationAnalyticsUtil::GetDeviceStatus(const sptr<NotificationRequest>& request)
{
    std::map<std::string, std::string> deviceStatus = request->GetdeviceStatus();
    nlohmann::json deviceStatusJson;
    for (std::map<std::string, std::string>::const_iterator iter = deviceStatus.begin();
        iter != deviceStatus.end(); ++iter) {
        deviceStatusJson[iter->first] = iter->second;
    }
    return deviceStatusJson.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}
uint32_t NotificationAnalyticsUtil::SetControlFlags(const std::shared_ptr<NotificationFlags> &flags,
    uint32_t &controlFlags)
{
    if (flags->IsSoundEnabled() == NotificationConstant::FlagStatus::OPEN) {
        controlFlags |= SOUND_FLAG;
    } else {
        controlFlags &= ~SOUND_FLAG;
    }
    if (flags->IsVibrationEnabled() == NotificationConstant::FlagStatus::OPEN) {
        controlFlags |= VIBRATION_FLAG;
    } else {
        controlFlags &= ~VIBRATION_FLAG;
    }
    if (flags->IsLockScreenVisblenessEnabled()) {
        controlFlags |= LOCKSCREEN_FLAG;
    } else {
        controlFlags &= ~LOCKSCREEN_FLAG;
    }
    if (flags->IsBannerEnabled()) {
        controlFlags |= BANNER_FLAG;
    } else {
        controlFlags &= ~BANNER_FLAG;
    }
    return controlFlags;
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
    extraInfo = NotificationAnalyticsUtil::BuildExtraInfoWithReq(message, request);
    NotificationAnalyticsUtil::SetCommonWant(want, message, extraInfo);

    want.SetParam("typeCode", message.typeCode_);
    IN_PROCESS_CALL_WITHOUT_RET(ReportNotificationEvent(
        request, want, eventCode, message.Build()));
}

void NotificationAnalyticsUtil::ReportSAPublishSuccessEvent(const sptr<NotificationRequest>& request, int32_t callUid)
{
    ANS_LOGD("called");
    if (request == nullptr) {
        return;
    }

    EventFwk::Want want;
    nlohmann::json ansData;
    ansData["ownerUid"] = std::to_string(request->GetOwnerUid());
    ansData["createUid"] = std::to_string(request->GetCreatorUid());
    ansData["rvUserId"] = std::to_string(request->GetReceiverUserId());
    ansData["owUserId"] = std::to_string(request->GetOwnerUserId());
    ansData["crUserId"] = std::to_string(request->GetCreatorUserId());
    ansData["callUid"] = std::to_string(callUid);
    ansData["slotType"] = static_cast<int32_t>(request->GetSlotType());
    ansData["contentType"] = static_cast<int32_t>(request->GetNotificationType());
    ansData["isAgent"] = static_cast<int32_t>(request->IsAgentNotification());
    std::string message = ansData.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    want.SetParam("ansData", message);
    want.SetAction(NOTIFICATION_EVENT_PUSH_AGENT);

    IN_PROCESS_CALL_WITHOUT_RET(AddListCache(want, ANS_CUSTOMIZE_CODE));
}

void NotificationAnalyticsUtil::ReportPublishWithUserInput(const sptr<NotificationRequest>& request)
{
    ANS_LOGD("called");
    if (request == nullptr || !request->HasUserInputButton()) {
        return;
    }

    EventFwk::Want want;
    nlohmann::json ansData;
    if (!request->GetOwnerBundleName().empty()) {
        ansData["ownerBundleName"] = request->GetOwnerBundleName();
    }
    if (!request->GetCreatorBundleName().empty()) {
        ansData["createBundleName"] = request->GetCreatorBundleName();
    }
    ansData["userInput"] = true;
    ansData["slotType"] = static_cast<int32_t>(request->GetSlotType());
    ansData["contentType"] = static_cast<int32_t>(request->GetNotificationType());
    std::string message = ansData.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    want.SetParam("ansData", message);
    want.SetAction(NOTIFICATION_EVENT_PUSH_AGENT);

    IN_PROCESS_CALL_WITHOUT_RET(AddListCache(want, ANS_CUSTOMIZE_CODE));
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
        ANS_LOGE("Publish event failed, reason:%{public}s", message.Build().c_str());
        return;
    }
    EventFwk::Want want;
    std::string extraInfo = NotificationAnalyticsUtil::BuildExtraInfo(message);
    NotificationAnalyticsUtil::SetCommonWant(want, message, extraInfo);

    want.SetParam("agentBundleName", message.agentBundleName_);
    want.SetParam("typeCode", message.typeCode_);
    want.SetParam("id", message.notificationId_);
    want.SetParam("deleteReason", message.deleteReason_);

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
    std::lock_guard<ffrt::mutex> lock(reportFlowControlMutex_);
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
        ANS_LOGD("%{public}s", basicInfo.c_str());
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
        if (liveViewContent->GetExtraInfo() != nullptr) {
            reason["et"] = liveViewContent->GetExtraInfo()->GetStringParam("event");
            reason["lt"] = liveViewContent->GetExtraInfo()->GetIntParam("LayoutData.layoutType", -1);
        }
    }

    reason["scene"] = message.sceneId_;
    reason["branch"] = message.branchId_;
    reason["innerErr"] = message.errorCode_;
    reason["detail"] = message.message_;

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    reason["time"] = now;

    reason["traceId"] = GetTraceIdStr();
    std::shared_ptr<AAFwk::WantParams> extraInfo = nullptr;
    if (request->GetUnifiedGroupInfo() != nullptr &&
        request->GetUnifiedGroupInfo()->GetExtraInfo() != nullptr) {
        const auto originExtraInfo = request->GetUnifiedGroupInfo()->GetExtraInfo();
        extraInfo = std::make_shared<AAFwk::WantParams>(*originExtraInfo);
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
        ANS_LOGD("%{public}s", basicInfo.c_str());
    } else {
        reason["detail"] = message.message_.substr(0, leftSpace);
        extraInfo->SetParam("reason",
            AAFwk::String::Box(reason.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace)));
    }

    AAFwk::WantParamWrapper wWrapper(*extraInfo);

    return wWrapper.ToString();
}

std::string NotificationAnalyticsUtil::GetTraceIdStr()
{
    OHOS::HiviewDFX::HiTraceId traceId = OHOS::HiviewDFX::HiTraceChain::GetId();
    std::stringstream chainId;
    chainId << std::hex << traceId.GetChainId();
    std::string hexTransId;
    chainId >> std::hex >> hexTransId;
    return hexTransId;
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
    std::lock_guard<ffrt::mutex> lock(reportCacheMutex_);
    int32_t size = static_cast<int32_t>(reportCacheList.size());
    if (size >= REPORT_CACHE_MAX_SIZE) {
        ANS_LOGW("list size is max");
        return;
    }

    if (reportTimerId == 0) {
        sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
        if (timer == nullptr) {
            ANS_LOGE("null timer");
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

void NotificationAnalyticsUtil::ReportBadgeChange(const sptr<BadgeNumberCallbackData> &badgeData)
{
    ANS_LOGD("called");
    if (badgeData == nullptr) {
        return;
    }

    BadgeInfo badgeInfo;
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::string bundle = badgeData->GetBundle() + "_"  + std::to_string(badgeData->GetUid());
    int32_t badgeNumber = badgeData->GetBadgeNumber();
    std::string badgeNumStr = (badgeNumber > MAX_BADGE_NUMBER) ? "99+" : std::to_string(badgeNumber);
    {
        std::lock_guard<ffrt::mutex> lock(badgeInfosMutex_);
        auto iter = badgeInfos.find(bundle);
        if (iter != badgeInfos.end()) {
            badgeInfo.badgeNum = iter->second.badgeNum + "_" + badgeNumStr;
            badgeInfo.time = iter->second.time + "_" + std::to_string(now - iter->second.startTime);
            badgeInfo.changeCount = ++ iter->second.changeCount;
            badgeInfo.startTime = iter->second.startTime;
            badgeInfo.isNeedReport = iter->second.isNeedReport;
        } else {
            badgeInfo.badgeNum = badgeNumStr;
            badgeInfo.startTime = now;
            badgeInfo.time = std::to_string(now);
            badgeInfo.changeCount = 1;
            badgeInfo.isNeedReport = false;
        }
        AddToBadgeInfos(bundle, badgeInfo);
    }

    CheckBadgeReport();
}

void NotificationAnalyticsUtil::ReportPublishBadge(const sptr<NotificationRequest>& request)
{
    ANS_LOGD("called");
    if (request == nullptr) {
        return;
    }

    if (request->GetBadgeNumber() <= 0) {
        return;
    }
    BadgeInfo badgeInfo;
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::string bundle = request->GetOwnerBundleName() + "_"  + std::to_string(request->GetOwnerUid());
    uint32_t badgeNumber = request->GetBadgeNumber();
    std::string badgeNumStr = (badgeNumber > MAX_BADGE_NUMBER) ? "99+" : std::to_string(badgeNumber);
    {
        std::lock_guard<ffrt::mutex> lock(badgeInfosMutex_);
        auto iter = badgeInfos.find(bundle);
        if (iter != badgeInfos.end()) {
            badgeInfo.badgeNum = iter->second.badgeNum + "_+" + badgeNumStr;
            badgeInfo.time = iter->second.time + "_" + std::to_string(now - iter->second.startTime);
            badgeInfo.changeCount = ++ iter->second.changeCount;
            badgeInfo.startTime = iter->second.startTime;
            badgeInfo.isNeedReport = iter->second.isNeedReport;
        } else {
            badgeInfo.badgeNum = "+" + badgeNumStr;
            badgeInfo.startTime = now;
            badgeInfo.time = std::to_string(now);
            badgeInfo.changeCount = 1;
            badgeInfo.isNeedReport = false;
        }
        AddToBadgeInfos(bundle, badgeInfo);
    }

    CheckBadgeReport();
}

void NotificationAnalyticsUtil::AddToBadgeInfos(std::string bundle, BadgeInfo& badgeInfo)
{
    int32_t count = 0;
    auto iter = badgeInfos.find(bundle);
    if (iter != badgeInfos.end() && badgeInfo.changeCount == MAX_NUMBER_EVERY_BADGE_DATA) {
        for (const auto& pair : badgeInfos) {
            if (pair.first.find(bundle) != std::string::npos) {
                count++;
            }
        }
        std::string newBundle = bundle + "_" + std::to_string(count);
        badgeInfos[newBundle] = badgeInfo;
        badgeInfos.erase(bundle);
    } else {
        badgeInfos[bundle] = badgeInfo;
    }
}

void NotificationAnalyticsUtil::CheckBadgeReport()
{
    int32_t needReportCount = 0;
    bool timeoutReport = false;
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    {
        std::lock_guard<ffrt::mutex> lock(badgeInfosMutex_);
        for (auto& pair : badgeInfos) {
            if (pair.second.changeCount == MAX_NUMBER_EVERY_BADGE_DATA ||
                now - pair.second.startTime > MAX_BADGE_CHANGE_REPORT_TIME) {
                pair.second.isNeedReport = true;
            }
            if (pair.second.isNeedReport == true) {
                needReportCount ++;
            }
            if (now - pair.second.startTime > TIMEOUT_TIME_OF_BADGE) {
                timeoutReport = true;
            }
        }
    }

    if (timeoutReport || needReportCount >= MAX_BADGE_AGGRATE_NUM) {
        AggregateBadgeChange();
    }
}

void NotificationAnalyticsUtil::AggregateBadgeChange()
{
    EventFwk::Want want;
    nlohmann::json ansData;
    std::string badgeMessage;
    std::vector<std::string> removeBundles;
    want.SetAction(NOTIFICATION_EVENT_PUSH_AGENT);
    ansData["subCode"] = std::to_string(BADGE_CHANGE_CODE);
    {
        std::lock_guard<ffrt::mutex> lock(badgeInfosMutex_);
        for (const auto& pair : badgeInfos) {
            const std::string bundle = pair.first;
            const BadgeInfo info = pair.second;
            if (!info.isNeedReport) {
                continue;
            }
            if (!badgeMessage.empty()) {
                badgeMessage += ",";
            }
            badgeMessage += bundle + ":{" + info.badgeNum + "," + info.time + "}";
            removeBundles.emplace_back(bundle);
        }
        ansData["data"] = badgeMessage;
        std::string message = ansData.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
        want.SetParam("ansData", message);

        if (reportAggregateTimeId == 0) {
            sptr<MiscServices::TimeServiceClient> aggregateTimer = MiscServices::TimeServiceClient::GetInstance();
            if (aggregateTimer == nullptr) {
                ANS_LOGE("null aggregateTimer");
                return;
            }
            reportAggregateTimeId = aggregateTimer->CreateTimer(reportAggregateTimeInfo);
        }

        for (auto bundle : removeBundles) {
            badgeInfos.erase(bundle);
        }
    }
    {
        std::lock_guard<ffrt::mutex> lock(reportAggListMutex_);
        ReportCache reportInfo;
        reportInfo.want = want;
        reportInfo.eventCode = ANS_CUSTOMIZE_CODE ;
        reportAggList.emplace_back(reportInfo);
    }

    if (!g_successReportFlag) {
        ExecuteSuccessCacheList();
    }
}

void NotificationAnalyticsUtil::AddSuccessListCache(EventFwk::Want& want, int32_t eventCode)
{
    {
        std::lock_guard<ffrt::mutex> lock(reportSuccessCacheMutex_);
        int32_t size = static_cast<int32_t>(successReportCacheList.size());
        if (size >= SUCCESS_REPORT_CACHE_MAX_SIZE) {
            ANS_LOGW("Success list size is max.");
            return;
        }

        if (reportAggregateTimeId == 0) {
            sptr<MiscServices::TimeServiceClient> aggregateTimer = MiscServices::TimeServiceClient::GetInstance();
            if (aggregateTimer == nullptr) {
                ANS_LOGE("null aggregateTimer");
                return;
            }
            reportAggregateTimeId = aggregateTimer->CreateTimer(reportAggregateTimeInfo);
        }

        ReportCache reportCache;
        reportCache.want = want;
        reportCache.eventCode = eventCode;
        successReportCacheList.push_back(reportCache);
    }
    if (!g_successReportFlag) {
        ExecuteSuccessCacheList();
    }
}

ReportCache NotificationAnalyticsUtil::Aggregate()
{
    ANS_LOGD("called");
    EventFwk::Want want;
    auto reportCachetemp = successReportCacheList.front();

    std::shared_ptr<AAFwk::WantParams> extraInfo = std::make_shared<AAFwk::WantParams>();
    AAFwk::WantParamWrapper wWrapper(*extraInfo);
    std::string extralInfoStr = wWrapper.ToString();
    want.SetParam("extraInfo", extralInfoStr);
    want.SetBundle(reportCachetemp.want.GetBundle());
    std::string agentBundleName = reportCachetemp.want.GetStringParam("agentBundleName");
    if (!agentBundleName.empty()) {
        want.SetParam("agentBundleName", agentBundleName);
    }
    want.SetAction(NOTIFICATION_EVENT_PUSH_AGENT);

    std::string ansData = reportCachetemp.want.GetStringParam("ansData");
    successReportCacheList.pop_front();
    int32_t aggreCount = MAX_NUMBER_EVERY_REPORT - 1;
    while (aggreCount > 0) {
        if (successReportCacheList.empty()) {
            break;
        }
        auto reportCache = successReportCacheList.front();

        ansData += "|" + reportCache.want.GetStringParam("ansData");
        successReportCacheList.pop_front();
        aggreCount--;
    }
    want.SetParam("ansData", ansData);
    ReportCache reportInfo;
    reportInfo.want = want;
    reportInfo.eventCode = ANS_CUSTOMIZE_CODE ;
    return reportInfo;
}

void NotificationAnalyticsUtil::ExecuteSuccessCacheList()
{
    {
        std::lock_guard<ffrt::mutex> lockReportSuccessCache(reportSuccessCacheMutex_);
        if (successReportCacheList.empty()) {
            ANS_LOGI("successReportCacheList is empty");
            std::lock_guard<ffrt::mutex> lockReportAggList(reportAggListMutex_);
            if (reportAggList.empty()) {
                g_successReportFlag = false;
                ANS_LOGI("No aggregate data need report");
                return;
            }
            auto reportCount = MAX_REPORT_COUNT;
            while (reportCount > 0 && !reportAggList.empty()) {
                auto reportCache = reportAggList.front();
                ReportCommonEvent(reportCache);
                reportAggList.pop_front();
                reportCount--;
            }
        } else {
            auto reportCache = Aggregate();
            std::lock_guard<ffrt::mutex> lockReportAggList(reportAggListMutex_);
            reportAggList.emplace_back(reportCache);
            auto reportCount = MAX_REPORT_COUNT;
            while (reportCount > 0 && !reportAggList.empty()) {
                auto reportCache = reportAggList.front();
                ReportCommonEvent(reportCache);
                reportAggList.pop_front();
                reportCount--;
            }
        }
    }

    CheckBadgeReport();
    auto triggerFunc = [] {
        NotificationAnalyticsUtil::ExecuteSuccessCacheList();
    };
    reportAggregateTimeInfo->SetCallbackInfo(triggerFunc);
    sptr<MiscServices::TimeServiceClient> aggregateTimer = MiscServices::TimeServiceClient::GetInstance();
    if (aggregateTimer == nullptr || reportAggregateTimeId == 0) {
        g_successReportFlag = false;
        ANS_LOGE("Failed to start timer due to get TimeServiceClient is null.");
        return;
    }
    aggregateTimer->StartTimer(reportAggregateTimeId, NotificationAnalyticsUtil::GetCurrentTime() +
        SUCCESS_REPORT_CACHE_INTERVAL_TIME * NotificationConstant::SECOND_TO_MS);
    g_successReportFlag = true;
}


void NotificationAnalyticsUtil::ExecuteCacheList()
{
    if (reportCacheList.empty()) {
        g_reportFlag = false;
        ANS_LOGE("empty reportCacheList");
        return;
    }
    auto reportCache = reportCacheList.front();
    ReportCommonEvent(reportCache);
    auto triggerFunc = [] {
        std::lock_guard<ffrt::mutex> lock(reportCacheMutex_);
        NotificationAnalyticsUtil::ExecuteCacheList();
    };
    reportCacheList.pop_front();
    reportTimeInfo->SetCallbackInfo(triggerFunc);
    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr || reportTimerId == 0) {
        g_reportFlag = false;
        ANS_LOGE("null timer or reportTimerId");
        return;
    }
    timer->StartTimer(reportTimerId, NotificationAnalyticsUtil::GetCurrentTime() +
        REPORT_CACHE_INTERVAL_TIME * NotificationConstant::SECOND_TO_MS);
    g_reportFlag = true;
}

void NotificationAnalyticsUtil::ReportTriggerLiveView(const std::vector<std::string>& bundles)
{
    nlohmann::json dataArray = nlohmann::json::array();
    for (auto bundle : bundles) {
        dataArray.push_back(bundle);
    }
    ReportCustomizeInfo(dataArray, LIVEVIEW_TRIGGER_SUB_CODE);
}

void NotificationAnalyticsUtil::ReportCloneInfo(const NotificationCloneBundleInfo& cloneBundleInfo)
{
    if (DelayedSingleton<NotificationConfigParse>::GetInstance()->IsReportTrustBundles(
        cloneBundleInfo.GetBundleName())) {
        nlohmann::json data;
        cloneBundleInfo.ToJson(data);
        ReportCustomizeInfo(data, CLONE_SUB_CODE);
    }
}

void NotificationAnalyticsUtil::ReportCustomizeInfo(const nlohmann::json& data, int32_t subCode)
{
    nlohmann::json ansData;
    ansData["subCode"] = std::to_string(subCode);
    ansData["data"] = data;
    std::string message = ansData.dump(-1, ' ', false,
        nlohmann::json::error_handler_t::replace);

    EventFwk::Want want;
    want.SetAction(NOTIFICATION_EVENT_PUSH_AGENT);
    want.SetParam("ansData", message);
    ReportCache reportCache;
    reportCache.want = want;
    reportCache.eventCode = ANS_CUSTOMIZE_CODE;
    ReportCommonEvent(reportCache);
}

void NotificationAnalyticsUtil::ReportCommonEvent(const ReportCache& reportCache)
{
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberPermissions({OHOS_PERMISSION_NOTIFICATION_CONTROLLER});
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

void NotificationAnalyticsUtil::ReportOperationsDotEvent(HaOperationMessage& operationMessage)
{
    if (!operationMessage.DetermineWhetherToSend()) {
        return;
    }

    if (!ReportFlowControl(ANS_CUSTOMIZE_CODE)) {
        ANS_LOGE("Publish event failed, reason:%{public}s", operationMessage.ToJson().c_str());
        return;
    }
    EventFwk::Want want;
    HaMetaMessage message;
    std::string extraInfo = NotificationAnalyticsUtil::BuildExtraInfo(message);
    NotificationAnalyticsUtil::SetCommonWant(want, message, extraInfo);
    nlohmann::json ansData;
    ansData["data"] = operationMessage.ToJson();
    ansData["subCode"] = std::to_string(DISTRIBUTED_SUB_CODE);
    want.SetParam("ansData", ansData.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
    ANS_LOGI("Publish operation event :%{public}s", operationMessage.ToJson().c_str());
    operationMessage.ResetData();
    IN_PROCESS_CALL_WITHOUT_RET(AddListCache(want, ANS_CUSTOMIZE_CODE));
}

void NotificationAnalyticsUtil::ReportPublishFailedEvent(const HaMetaMessage& message)
{
    if (!ReportFlowControl(PUBLISH_ERROR_EVENT_CODE)) {
        ANS_LOGE("Publish event failed, reason:%{public}s", message.Build().c_str());
        return;
    }
    EventFwk::Want want;
    std::string extraInfo = NotificationAnalyticsUtil::BuildExtraInfo(message);
    NotificationAnalyticsUtil::SetCommonWant(want, message, extraInfo);

    want.SetParam("typeCode", message.typeCode_);

    IN_PROCESS_CALL_WITHOUT_RET(AddListCache(want, PUBLISH_ERROR_EVENT_CODE));
}

void NotificationAnalyticsUtil::ReportSkipFailedEvent(const HaMetaMessage& message)
{
    if (!ReportFlowControl(MODIFY_ERROR_EVENT_CODE)) {
        ANS_LOGE("Publish event failed, reason:%{public}s", message.Build().c_str());
        return;
    }
    EventFwk::Want want;
    std::string extraInfo = NotificationAnalyticsUtil::BuildExtraInfo(message);
    NotificationAnalyticsUtil::SetCommonWant(want, message, extraInfo);

    IN_PROCESS_CALL_WITHOUT_RET(AddListCache(want, MODIFY_ERROR_EVENT_CODE));
}

bool NotificationAnalyticsUtil::ReportAllBundlesSlotEnabled()
{
    if (!CheckSlotNeedReport()) {
        return false;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);

    if (userId == SUBSCRIBE_USER_INIT) {
        ANS_LOGE("userId is failed");
        return false;
    }

    if (!CreateSlotTimerExecute(userId)) {
        return false;
    }
    return true;
}

bool NotificationAnalyticsUtil::CreateSlotTimerExecute(const int32_t &userId)
{
    std::lock_guard<ffrt::mutex> lock(reportSlotEnabledMutex_);
    if (g_reportSlotFlag) {
        ANS_LOGW("now has message is reporting");
        return false;
    }

    sptr<MiscServices::TimeServiceClient> timer =
        MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANS_LOGE("null timer");
        g_reportSlotFlag = false;
        return false;
    }
    if (reportSlotEnabledTimerId_ == 0) {
        reportSlotEnabledTimerId_ = timer->CreateTimer(slotTimeInfo);
    }

    auto triggerFunc = [userId] {
        ANS_LOGI("trigger is arrived, userid:%{public}d", userId);
        GetAllSlotMessageCache(userId);
        ExecuteSlotReportList();
    };

    slotTimeInfo->SetCallbackInfo(triggerFunc);
    timer->StartTimer(reportSlotEnabledTimerId_, NotificationAnalyticsUtil::GetCurrentTime() +
        DEFAULT_ERROR_EVENT_TIME * NotificationConstant::SECOND_TO_MS);
    g_reportSlotFlag = true;
    return true;
}

void NotificationAnalyticsUtil::ExecuteSlotReportList()
{
    std::lock_guard<ffrt::mutex> lock(reportSlotEnabledMutex_);

    if (!ReportSlotEnable()) {
        g_reportSlotFlag = false;
        return;
    }

    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANS_LOGE("null timer");
        g_reportSlotFlag = false;
        return;
    }
    auto triggerFunc = [] {
        ExecuteSlotReportList();
    };

    slotTimeInfo->SetCallbackInfo(triggerFunc);
    timer->StartTimer(reportSlotEnabledTimerId_, NotificationAnalyticsUtil::GetCurrentTime() +
        DEFAULT_ERROR_EVENT_TIME * NotificationConstant::SECOND_TO_MS);
    g_reportSlotFlag = true;
}

bool NotificationAnalyticsUtil::ReportSlotEnable()
{
    std::lock_guard<ffrt::mutex> lock(slotEnabledListMutex_);
    if (slotEnabledList_.empty()) {
        ANS_LOGI("report end");
        return false;
    }

    std::list<ReportSlotMessage> slotEnabledReportList;
    int count = SLOT_ONCE_REPORT;
    while (count-- > 0 && !slotEnabledList_.empty()) {
        auto slotMessage = slotEnabledList_.front();
        slotEnabledReportList.push_back(slotMessage);
        slotEnabledList_.pop_front();
    }

    ReportCache reportCache;
    BuildSlotReportCache(reportCache, slotEnabledReportList);
    ReportCommonEvent(reportCache);
    return true;
}

bool NotificationAnalyticsUtil::BuildSlotReportCache(ReportCache &reportCache,
    std::list<ReportSlotMessage> &slotEnabledReportList)
{
    nlohmann::json ansData;
    ansData["subCode"] = std::to_string(SLOT_SUB_CODE);
    nlohmann::json dataArray;
    for (const auto &report : slotEnabledReportList) {
        nlohmann::json dataItem;
        dataItem["slotType"] = report.slotType;
        dataItem["status"] = report.status;
        dataItem["bundleName"] = report.bundleName;
        dataItem["uid"] = report.uid;
        dataArray.push_back(dataItem);
    }
    ansData["data"] = dataArray;

    std::string message = ansData.dump(-1, ' ', false,
        nlohmann::json::error_handler_t::replace);
    EventFwk::Want want;
    want.SetAction(NOTIFICATION_EVENT_PUSH_AGENT);
    want.SetParam("ansData", message);

    reportCache.want = want;
    reportCache.eventCode = ANS_CUSTOMIZE_CODE;
    return true;
}

bool NotificationAnalyticsUtil::CheckSlotNeedReport()
{
    std::lock_guard<ffrt::mutex> lock(lastReportTimeMutex_);
    auto now = GetCurrentTime();
    if (lastReportTime_ != 0 && abs(now - lastReportTime_) <= SLOT_REPORT_INTERVAL) {
        ANS_LOGD("no need report");
        return false;
    }

    ANS_LOGI("slot enabled need report");
    lastReportTime_ = now;
    return true;
}

bool NotificationAnalyticsUtil::GetAllSlotMessageCache(const int32_t &userId)
{
    std::unordered_map<std::string, std::string> slotEnablesMap;
    auto res = NotificationPreferences::GetInstance()->GetBatchKvsFromDbContainsKey(
        LIVE_VIEW_SLOT_ENABLE_END, slotEnablesMap, userId);
    if (res != ERR_OK) {
        ANS_LOGW("message is err:%{public}d, userId:%{public}d ", res, userId);
        return false;
    }

    if (slotEnablesMap.size() == 0 || slotEnablesMap.size() > SLOT_MAX_REPORT) {
        ANS_LOGW("slotEnablesMap size %{public}zu", slotEnablesMap.size());
        return false;
    }
    std::lock_guard<ffrt::mutex> lock(slotEnabledListMutex_);
    for (const auto& budleEntry : slotEnablesMap) {
        std::string budleEntryKey = budleEntry.first;
        // enable
        ReportSlotMessage reportSlotMessage;
        std::string budleEntryValue = budleEntry.second;
        bool isGetMsgSucc = NotificationAnalyticsUtil::GetReportSlotMessage(budleEntryKey,
            budleEntryValue, reportSlotMessage, userId);
        if (!isGetMsgSucc) {
            continue;
        }
        slotEnabledList_.push_back(reportSlotMessage);
    }
    return true;
}

bool NotificationAnalyticsUtil::GetReportSlotMessage(std::string& budleEntryKey,
    std::string& budleEntryValue, ReportSlotMessage& reportSlotMessage, const int32_t &userId)
{
    std::string extracted;
    std::regex pattern(SLOT_ENABLE_REG_PATTERN);
    std::smatch matches;
    if (std::regex_search(budleEntryKey, matches, pattern) && matches.size() > 1) {
        extracted = matches[1].str();
    } else {
        return false;
    }

    std::unordered_map<std::string, std::string> bundleInfoMap;
    auto res = NotificationPreferences::GetInstance()->GetBatchKvsFromDbContainsKey(
        extracted, bundleInfoMap, userId);
    if (res != ERR_OK) {
        ANS_LOGW("get bundleInfoMap is err:%{public}d", res);
        return false;
    }

    auto nameIt = bundleInfoMap.find(ANS_BUNDLE_BEGIN + LINE + extracted + LINE + NAME);
    auto uidIt = bundleInfoMap.find(ANS_BUNDLE_BEGIN + LINE + extracted + LINE + UID);
    if (nameIt == bundleInfoMap.end() || uidIt == bundleInfoMap.end()) {
        ANS_LOGW("bundleInfoMap is empty, database error");
        return false;
    }

    // data process
    std::string bundleName = nameIt->second;
    int32_t uid = std::atoi(uidIt->second.c_str());
    bool enable = std::atoi(budleEntryValue.c_str());
    ANS_LOGI("budleInfoEntry uid %{public}d, name is:%{public}s, enabled:%{public}d",
        uid, bundleName.c_str(), enable);
    reportSlotMessage.uid = uid;
    reportSlotMessage.status = enable;
    reportSlotMessage.slotType = static_cast<int32_t>(
        NotificationConstant::SlotType::LIVE_VIEW);
    reportSlotMessage.bundleName = bundleName;
    return true;
}
} // namespace Notification
} // namespace OHOS
