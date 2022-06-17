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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_EVENT_REPORT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_EVENT_REPORT_H

#include <unordered_map>

#ifdef HAS_HISYSEVENT_PART
#include "hisysevent.h"
#endif

namespace OHOS {
namespace Notification {
namespace {
// event name
const std::string SUBSCRIBE_ERROR = "SUBSCRIBE_ERROR";
const std::string ENABLE_NOTIFICATION_ERROR = "ENABLE_NOTIFICATION_ERROR";
const std::string ENABLE_NOTIFICATION_SLOT_ERROR = "ENABLE_NOTIFICATION_SLOT_ERROR";
const std::string PUBLISH_ERROR = "PUBLISH_ERROR";
const std::string FLOW_CONTROL_OCCUR = "FLOW_CONTROL_OCCUR";

const std::string SUBSCRIBE = "SUBSCRIBE";
const std::string UNSUBSCRIBE = "UNSUBSCRIBE";
const std::string ENABLE_NOTIFICATION = "ENABLE_NOTIFICATION";
const std::string ENABLE_NOTIFICATION_SLOT = "ENABLE_NOTIFICATION_SLOT";

const std::string PUBLISH = "PUBLISH";
const std::string CANCEL = "CANCEL";
const std::string REMOVE = "REMOVE";
} // namespace

struct EventInfo {
    int32_t notificationId;
    int32_t contentType;
    int32_t userId;
    int32_t pid;
    int32_t uid;
    int32_t slotType;
    int32_t errCode;
    bool enable;
    std::string bundleName;
    std::string notificationLabel;

    EventInfo() : userId(-1), pid(0), uid(0), errCode(0), enable(false) {}
};

class EventReport {
public:
    /**
     * @brief send hisysevent
     *
     * @param eventName event name, corresponding to the document 'hisysevent.yaml'
     * @param eventInfo event info
     */
    static void SendHiSysEvent(const std::string &eventName, const EventInfo &eventInfo);

private:
#ifdef HAS_HISYSEVENT_PART
    // fault event
    static void InnerSendSubscribeErrorEvent(const EventInfo &eventInfo);
    static void InnerSendEnableNotificationErrorEvent(const EventInfo &eventInfo);
    static void InnerSendEnableNotificationSlotErrorEvent(const EventInfo &eventInfo);
    static void InnerSendPublishErrorEvent(const EventInfo &eventInfo);
    static void InnerSendFlowControlOccurEvent(const EventInfo &eventInfo);

    // behavior event
    static void InnerSendSubscribeEvent(const EventInfo &eventInfo);
    static void InnerSendUnSubscribeEvent(const EventInfo &eventInfo);
    static void InnerSendEnableNotificationEvent(const EventInfo &eventInfo);
    static void InnerSendEnableNotificationSlotEvent(const EventInfo &eventInfo);

    // statistic event
    static void InnerSendPublishEvent(const EventInfo &eventInfo);
    static void InnerSendCancelEvent(const EventInfo &eventInfo);
    static void InnerSendRemoveEvent(const EventInfo &eventInfo);

    template<typename... Types>
    static void InnerEventWrite(const std::string &eventName,
        HiviewDFX::HiSysEvent::EventType type, Types... keyValues);

    static std::unordered_map<std::string, void (*)(const EventInfo &eventInfo)> ansSysEventFuncMap_;
#endif
};
} // namespace Notification
} // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_EVENT_REPORT_H