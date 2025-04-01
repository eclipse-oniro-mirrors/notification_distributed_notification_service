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
    SCENE_20 = 20,
    SCENE_21 = 21,
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
    HaMetaMessage& Append(const std::string& message);
    HaMetaMessage& BundleName(const std::string& bundleName_);
    HaMetaMessage& AgentBundleName(const std::string& agentBundleName);
    HaMetaMessage& TypeCode(int32_t typeCode);
    HaMetaMessage& NotificationId(int32_t notificationId);
    HaMetaMessage& SlotType(int32_t slotType);
    HaMetaMessage& SyncWatch(bool isLiveView);
    HaMetaMessage& SyncHeadSet(bool isLiveView);
    HaMetaMessage& SyncWatchHeadSet(bool isLiveView);
    HaMetaMessage& KeyNode(bool isKeyNode);
    HaMetaMessage& DelByWatch(bool isLiveView);
    HaMetaMessage& DeleteReason(int32_t deleteReason);
    HaMetaMessage& ClickByWatch();
    HaMetaMessage& ReplyByWatch();
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
    bool checkfailed_ = true;
    int32_t deleteReason_ = -1;
    static int32_t syncWatch_;
    static int32_t syncHeadSet_;
    static int32_t syncWatchHeadSet_;
    static int32_t delByWatch_;
    static int32_t clickByWatch_;
    static int32_t replyByWatch_;
    static int32_t keyNode_;
    static int64_t time_;
    static int32_t syncLiveViewWatch_;
    static int32_t syncLiveViewHeadSet_;
    static int32_t syncLiveViewWatchHeadSet_;
    static int64_t liveViewTime_;
    static int32_t liveViewDelByWatch_;
};

struct FlowControllerOption {
    int32_t count;
    int32_t time;
};

struct ReportCache {
    EventFwk::Want want;
    int32_t eventCode;
};

class NotificationAnalyticsUtil {
public:
    static void ReportPublishFailedEvent(const sptr<NotificationRequest>& request, const HaMetaMessage& message);

    static void ReportDeleteFailedEvent(const sptr<NotificationRequest>& request, HaMetaMessage& message);

    static void ReportPublishSuccessEvent(const sptr<NotificationRequest>& request, const HaMetaMessage& message);

    static void ReportModifyEvent(const HaMetaMessage& message);

    static void ReportDeleteFailedEvent(const HaMetaMessage& message);

    static void RemoveExpired(std::list<std::chrono::system_clock::time_point> &list,
        const std::chrono::system_clock::time_point &now, int32_t time = 1);

    static int64_t GetCurrentTime();

    static void ReportOperationsDotEvent(const HaMetaMessage& message);

    static void ReportPublishFailedEvent(const HaMetaMessage& message);

    static void ReportSkipFailedEvent(const HaMetaMessage& message);

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

    static std::string BuildAnsData(const HaMetaMessage& message);
};
} // namespace Notification
} // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_ANALYTICS_UTIL_H
