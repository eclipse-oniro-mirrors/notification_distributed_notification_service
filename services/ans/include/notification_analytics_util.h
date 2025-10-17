/*
* Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_ANALYTICS_UTIL_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_ANALYTICS_UTIL_H

#include <string>
#include <map>
#include "notification_request.h"
#include "badge_number_callback_data.h"
#include "notification_clone_bundle_info.h"

namespace OHOS {
namespace Notification {

enum EventSceneId {
    SCENE_0 = 0,
    SCENE_1 = 1,
    SCENE_2 = 2,
    SCENE_3 = 3,
    SCENE_4 = 4,
    SCENE_5 = 5,
    SCENE_6 = 6,
    SCENE_7 = 7,
    SCENE_8 = 8,
    SCENE_9 = 9,
    SCENE_10 = 10,
    SCENE_11 = 11,
    SCENE_12 = 12,
    SCENE_13 = 13,
    SCENE_14 = 14,
    SCENE_15 = 15,
    SCENE_16 = 16,
    SCENE_17 = 17,
    SCENE_18 = 18,
    SCENE_19 = 19,
    SCENE_20 = 20,
    SCENE_21 = 21,
    SCENE_22 = 22,
    SCENE_23 = 23,
    SCENE_24 = 24,
    SCENE_25 = 25,
    SCENE_26 = 26,
};

enum EventBranchId {
    BRANCH_0 = 0,
    BRANCH_1 = 1,
    BRANCH_2 = 2,
    BRANCH_3 = 3,
    BRANCH_4 = 4,
    BRANCH_5 = 5,
    BRANCH_6 = 6,
    BRANCH_7 = 7,
    BRANCH_8 = 8,
    BRANCH_9 = 9,
    BRANCH_10 = 10,
    BRANCH_11 = 11,
    BRANCH_12 = 12,
    BRANCH_13 = 13,
    BRANCH_14 = 14,
    BRANCH_15 = 15,
    BRANCH_16 = 16,
    BRANCH_17 = 17,
    BRANCH_18 = 18,
    BRANCH_19 = 19,
    BRANCH_20 = 20,
    BRANCH_21 = 21,
    BRANCH_22 = 22,
    BRANCH_23 = 23,
    BRANCH_24 = 24,
};

class OperationalMeta {
public:
    void ToJson(nlohmann::json& jsonObject);
public:
    int32_t createTime;
    int32_t syncTime;
    int32_t delTime;
    int32_t clickTime;
    int32_t replyTime;
    std::set<std::string> hashCodes;
};

class OperationalData {
public:
    OperationalData();
    void ToJson(nlohmann::json& jsonObject);
public:
    int32_t syncWatchHead = 0;
    int32_t keyNode = 0;
    int64_t time;
    int64_t countTime = 0;
    std::map<std::string, OperationalMeta> dataMap;
};

class HaOperationMessage {
public:
    HaOperationMessage() {}
    HaOperationMessage(bool isLiveView) : isLiveView_(isLiveView) {}
    void ResetData();
    std::string ToJson();
    bool DetermineWhetherToSend();
    HaOperationMessage& KeyNode(bool keyNodeFlag);
    HaOperationMessage& SyncPublish(const std::string& hashCode,
        std::vector<std::string>& deviceTypes);
    HaOperationMessage& SyncDelete(const std::string& hashCode);
    HaOperationMessage& SyncDelete(std::string deviceType, const std::string& reason);
    HaOperationMessage& SyncClick(std::string deviceType);
    HaOperationMessage& SyncReply(std::string deviceType);
public:
    bool isLiveView_ = false;
    static OperationalData notificationData;
    static OperationalData liveViewData;
};

class HaMetaMessage {
public:
    HaMetaMessage() = default;
    ~HaMetaMessage() = default;

    explicit HaMetaMessage(uint32_t sceneId, uint32_t branchId);

    HaMetaMessage& SceneId(uint32_t sceneId);
    HaMetaMessage& BranchId(uint32_t branchId);
    HaMetaMessage& ErrorCode(uint32_t errorCode);
    HaMetaMessage& Message(const std::string& message, bool print = false);
    HaMetaMessage& Path(const std::string &path);
    HaMetaMessage& Append(const std::string& message);
    HaMetaMessage& BundleName(const std::string& bundleName_);
    HaMetaMessage& AgentBundleName(const std::string& agentBundleName);
    HaMetaMessage& TypeCode(int32_t typeCode);
    HaMetaMessage& NotificationId(int32_t notificationId);
    HaMetaMessage& SlotType(int32_t slotType);
    HaMetaMessage& DeleteReason(int32_t deleteReason);
    std::string GetMessage() const;
    HaMetaMessage& Checkfailed(bool checkfailed);
    bool NeedReport() const;

    std::string Build() const;

    std::string bundleName_;
    int32_t notificationId_ = -1;
    std::string agentBundleName_ = "";
    int32_t typeCode_ = -1;
    uint32_t slotType_ = -1;
    uint32_t sceneId_;
    uint32_t branchId_;
    uint32_t errorCode_ = ERR_OK;
    std::string message_;
    std::string path_;
    bool checkfailed_ = true;
    int32_t deleteReason_ = -1;
};

struct FlowControllerOption {
    int32_t count;
    int32_t time;
};

struct ReportCache {
    EventFwk::Want want;
    int32_t eventCode;
};

struct BadgeInfo {
    std::int64_t startTime;
    std::int32_t changeCount;
    std::string badgeNum;
    std::string time;
    bool isNeedReport;
};

struct ReportSlotMessage {
    std::string bundleName;
    int32_t uid;
    int32_t slotType;
    bool status;
};

struct ReportLiveViewMessage {
    int32_t successNum;
    int32_t FailedNum;
    int64_t startTime;
};

class NotificationAnalyticsUtil {
public:
    static void ReportTipsEvent(const sptr<NotificationRequest>& request, const HaMetaMessage& message);

    static void ReportPublishFailedEvent(const sptr<NotificationRequest>& request, const HaMetaMessage& message);

    static void ReportDeleteFailedEvent(const sptr<NotificationRequest>& request, HaMetaMessage& message);

    static void ReportPublishSuccessEvent(const sptr<NotificationRequest>& request, const HaMetaMessage& message);

    static void ReportSAPublishSuccessEvent(const sptr<NotificationRequest>& request, int32_t callUid);

    static void ReportModifyEvent(const HaMetaMessage& message);

    static void ReportDeleteFailedEvent(const HaMetaMessage& message);

    static void RemoveExpired(std::list<std::chrono::system_clock::time_point> &list,
        const std::chrono::system_clock::time_point &now, int32_t time = 1);

    static int64_t GetCurrentTime();

    static void ReportOperationsDotEvent(HaOperationMessage& message);

    static void ReportPublishFailedEvent(const HaMetaMessage& message);

    static void ReportSkipFailedEvent(const HaMetaMessage& message);

    static void ReportPublishWithUserInput(const sptr<NotificationRequest>& request);

    static void ReportPublishBadge(const sptr<NotificationRequest>& request);

    static void ReportBadgeChange(const sptr<BadgeNumberCallbackData> &badgeData);

    static bool ReportAllBundlesSlotEnabled();

    static void ReportLiveViewNumber(const sptr<NotificationRequest>& request, const int32_t reportType);

    static void ReportTriggerLiveView(const std::vector<std::string>& bundles);

    static void ReportCustomizeInfo(const nlohmann::json& data, int32_t subCode);

    static void ReportCloneInfo(const NotificationCloneBundleInfo& cloneBundleInfo);
private:
    static void ReportNotificationEvent(const sptr<NotificationRequest>& request,
        EventFwk::Want want, int32_t eventCode, const std::string& reason);
    static void CommonNotificationEvent(const sptr<NotificationRequest>& request,
        int32_t eventCode, const HaMetaMessage& message);

    static void CommonNotificationEvent(int32_t eventCode, const HaMetaMessage& message);

    static void ReportNotificationEvent(EventFwk::Want want, int32_t eventCode, const std::string& reason);

    static bool ReportFlowControl(const int32_t reportType);

    static bool IsAllowedBundle(const sptr<NotificationRequest>& request);

    static std::string BuildAnsData(const sptr<NotificationRequest>& request, const HaMetaMessage& message);

    static ReportCache Aggregate();

    static uint32_t SetControlFlags(const std::shared_ptr<NotificationFlags> &flags, uint32_t &controlFlags);

    static std::string GetDeviceStatus(const sptr<NotificationRequest>& request);

    static std::list<std::chrono::system_clock::time_point> GetFlowListByType(const int32_t reportType);

    static FlowControllerOption GetFlowOptionByType(const int32_t reportType);

    static std::string BuildExtraInfo(const HaMetaMessage& message);

    static std::string BuildExtraInfoWithReq(const HaMetaMessage& message,
        const sptr<NotificationRequest>& request);

    static void SetCommonWant(EventFwk::Want& want, const HaMetaMessage& message, std::string& extraInfo);
    
    static void AddListCache(EventFwk::Want& want, int32_t eventCode);

    static void AddSuccessListCache(EventFwk::Want& want, int32_t eventCode);

    static void ExecuteCacheList();

    static void ExecuteSuccessCacheList();
    
    static void ReportCommonEvent(const ReportCache& reportCache);

    static bool DetermineWhetherToSend(uint32_t slotType);

    static void AddToBadgeInfos(std::string bundle, BadgeInfo& badgeInfo);

    static void CheckBadgeReport();

    static void AggregateBadgeChange();

    static bool CheckSlotNeedReport();

    static bool GetAllSlotMessageCache(const int32_t &userId);

    static bool GetReportSlotMessage(std::string& budleEntryKey, std::string& budleEntryValue,
        ReportSlotMessage& reportSlotMessage, const int32_t &userId);

    static bool CreateSlotTimerExecute(const int32_t &userId);

    static void ExecuteSlotReportList();

    static bool ReportSlotEnable();

    static bool BuildSlotReportCache(ReportCache& reportCache,
        std::list<ReportSlotMessage>& slotEnabledReportList);

    static void AddLiveViewSuccessNum(std::string bundle, int32_t status);

    static void AddLiveViewFailedNum(std::string bundle, int32_t status);

    static void CreateLiveViewTimerExecute();

    static ReportCache AggregateLiveView();

    static void ExecuteLiveViewReport();

    static void AddLocalLiveViewSuccessNum(std::string bundle);

    static void AddLocalLiveViewFailedNum(std::string bundle);

    static void MakeRequestBundle(const sptr<NotificationRequest>& request);

    static std::string GetTraceIdStr();
};
} // namespace Notification
} // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_ANALYTICS_UTIL_H
