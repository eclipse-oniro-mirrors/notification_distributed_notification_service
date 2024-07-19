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

class HaMetaMessage {
public:
    HaMetaMessage() = default;
    ~HaMetaMessage() = default;

    explicit HaMetaMessage(uint32_t sceneId, uint32_t branchId);

    HaMetaMessage& SceneId(uint32_t sceneId);
    HaMetaMessage& BranchId(uint32_t branchId);
    HaMetaMessage& ErrorCode(uint32_t errorCode);
    HaMetaMessage& Message(const std::string& message);
    HaMetaMessage& BundleName(const std::string& bundleName_);
    HaMetaMessage& AgentBundleName(const std::string& agentBundleName);
    HaMetaMessage& TypeCode(int32_t typeCode);
    HaMetaMessage& NotificationId(int32_t notificationId);
    std::string GetMessage() const;

    std::string Build() const;

    std::string bundleName_;
    int32_t notificationId_ = -1;
    std::string agentBundleName_ = "";
    int32_t typeCode_ = -1;
private:
    uint32_t sceneId_;
    uint32_t branchId_;
    uint32_t errorCode_;
    std::string message_;
};


class NotificationAnalyticsUtil {
public:
    static void ReportPublishFailedEvent(const sptr<NotificationRequest>& request, const HaMetaMessage& message);

    static void ReportDeleteFailedEvent(const sptr<NotificationRequest>& request, HaMetaMessage& message);

    static void ReportModifyFailedEvent(const sptr<NotificationRequest>& request, const HaMetaMessage& message);

    static void ReportModifySuccessEvent(const sptr<NotificationRequest>& request, const HaMetaMessage& message);

    static void ReportDeleteFailedEvent(const HaMetaMessage& message);

private:
    static void ReportNotificationEvent(const sptr<NotificationRequest>& request,
        EventFwk::Want want, int32_t eventCode, const std::string& reason);
    static void CommonNotificationEvent(const sptr<NotificationRequest>& request,
        int32_t eventCode, const HaMetaMessage& message);

    static void CommonNotificationEvent(int32_t eventCode, const HaMetaMessage& message);

    static void ReportNotificationEvent(EventFwk::Want want, int32_t eventCode, const std::string& reason);
};
} // namespace Notification
} // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_ANALYTICS_UTIL_H
