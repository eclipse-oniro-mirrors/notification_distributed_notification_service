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

#include "ans_log_wrapper.h"
#include "event_report.h"

namespace OHOS {
namespace Notification {
namespace {
// event params
const std::string EVENT_PARAM_USER_ID = "USER_ID";
const std::string EVENT_PARAM_BUNDLE_NAME = "BUNDLE_NAME";
const std::string EVENT_PARAM_ERROR_CODE = "ERROR_CODE";
const std::string EVENT_PARAM_PID = "PID";
const std::string EVENT_PARAM_UID = "UID";
const std::string EVENT_PARAM_ENABLE = "ENABLE";
const std::string EVENT_PARAM_SLOT_TYPE = "SLOT_TYPE";
const std::string EVENT_PARAM_NOTIFICATION_ID = "NOTIFICATION_ID";
const std::string EVENT_PARAM_NOTIFICATION_LABEL = "NOTIFICATION_LABEL";
const std::string EVENT_PARAM_CONTENT_TYPE = "CONTENT_TYPE";
const std::string EVENT_PARAM_OPERATE_FLAG = "OPERATE_FLAG";
const std::string EVENT_MESSAGE_TYPE = "MESSAGE_TYPE";
const std::string EVENT_REASON = "REASON";
const std::string EVENT_PARAM_REASON = "REASON";
const std::string EVENT_PARAM_CLASS = "CLASS";
const std::string EVENT_PARAM_REMINDERFLAGS = "REMINDERFLAGS";
const std::string EVENT_PARAM_CONTROLFLAGS = "CONTROLFLAGS";
} // namespace

void EventReport::SendHiSysEvent(const std::string &eventName, const EventInfo &eventInfo)
{
#ifndef HAS_HISYSEVENT_PART
    ANS_LOGD("Hisysevent is disabled");
#else
    auto iter = ansSysEventFuncMap_.find(eventName);
    if (iter == ansSysEventFuncMap_.end()) {
        return;
    }

    iter->second(eventInfo);
#endif
}

#ifdef HAS_HISYSEVENT_PART
std::unordered_map<std::string, void (*)(const EventInfo& eventInfo)> EventReport::ansSysEventFuncMap_ = {
    {SUBSCRIBE_ERROR, [](const EventInfo& eventInfo) {
        InnerSendSubscribeErrorEvent(eventInfo);
    }},
    {ENABLE_NOTIFICATION_ERROR, [](const EventInfo& eventInfo) {
        InnerSendEnableNotificationErrorEvent(eventInfo);
    }},
    {ENABLE_NOTIFICATION_SLOT_ERROR, [](const EventInfo& eventInfo) {
        InnerSendEnableNotificationSlotErrorEvent(eventInfo);
    }},
    {PUBLISH_ERROR, [](const EventInfo& eventInfo) {
        InnerSendPublishErrorEvent(eventInfo);
    }},
    {EVENT_NOTIFICATION_ERROR, [](const EventInfo& eventInfo) {
        InnerSendNotificationSystemErrorEvent(eventInfo);
    }},
    {FLOW_CONTROL_OCCUR, [](const EventInfo& eventInfo) {
        InnerSendFlowControlOccurEvent(eventInfo);
    }},
    {SUBSCRIBE, [](const EventInfo& eventInfo) {
        InnerSendSubscribeEvent(eventInfo);
    }},
    {UNSUBSCRIBE, [](const EventInfo& eventInfo) {
        InnerSendUnSubscribeEvent(eventInfo);
    }},
    {ENABLE_NOTIFICATION, [](const EventInfo& eventInfo) {
        InnerSendEnableNotificationEvent(eventInfo);
    }},
    {ENABLE_NOTIFICATION_SLOT, [](const EventInfo& eventInfo) {
        InnerSendEnableNotificationSlotEvent(eventInfo);
    }},
    {PUBLISH, [](const EventInfo& eventInfo) {
        InnerSendPublishEvent(eventInfo);
    }},
    {CANCEL, [](const EventInfo& eventInfo) {
        InnerSendCancelEvent(eventInfo);
    }},
    {REMOVE, [](const EventInfo& eventInfo) {
        InnerSendRemoveEvent(eventInfo);
    }},
    {STATIC_LIVE_VIEW_UPLOAD, [](const EventInfo& eventInfo) {
        InnerSendLiveviewUploadEvent(eventInfo);
    }},
};

void EventReport::InnerSendSubscribeErrorEvent(const EventInfo &eventInfo)
{
    InnerEventWrite(
        SUBSCRIBE_ERROR,
        HiviewDFX::HiSysEvent::EventType::FAULT,
        EVENT_PARAM_PID, eventInfo.pid,
        EVENT_PARAM_UID, eventInfo.uid,
        EVENT_PARAM_USER_ID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_ERROR_CODE, eventInfo.errCode);
}

void EventReport::InnerSendEnableNotificationErrorEvent(const EventInfo &eventInfo)
{
    InnerEventWrite(
        ENABLE_NOTIFICATION_ERROR,
        HiviewDFX::HiSysEvent::EventType::FAULT,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_UID, eventInfo.uid,
        EVENT_PARAM_ENABLE, eventInfo.enable,
        EVENT_PARAM_ERROR_CODE, eventInfo.errCode);
}

void EventReport::InnerSendEnableNotificationSlotErrorEvent(const EventInfo &eventInfo)
{
    InnerEventWrite(
        ENABLE_NOTIFICATION_SLOT_ERROR,
        HiviewDFX::HiSysEvent::EventType::FAULT,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_UID, eventInfo.uid,
        EVENT_PARAM_SLOT_TYPE, eventInfo.slotType,
        EVENT_PARAM_ENABLE, eventInfo.enable,
        EVENT_PARAM_ERROR_CODE, eventInfo.errCode);
}

void EventReport::InnerSendPublishErrorEvent(const EventInfo &eventInfo)
{
    InnerEventWrite(
        PUBLISH_ERROR,
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        EVENT_PARAM_NOTIFICATION_ID, eventInfo.notificationId,
        EVENT_PARAM_CONTENT_TYPE, eventInfo.contentType,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_USER_ID, eventInfo.userId,
        EVENT_PARAM_ERROR_CODE, eventInfo.errCode);
}

void EventReport::InnerSendFlowControlOccurEvent(const EventInfo &eventInfo)
{
    InnerEventWrite(
        FLOW_CONTROL_OCCUR,
        HiviewDFX::HiSysEvent::EventType::FAULT,
        EVENT_PARAM_NOTIFICATION_ID, eventInfo.notificationId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_UID, eventInfo.uid);
}

void EventReport::InnerSendNotificationSystemErrorEvent(const EventInfo &eventInfo)
{
    InnerEventWrite(
        EVENT_NOTIFICATION_ERROR,
        HiviewDFX::HiSysEvent::EventType::FAULT,
        EVENT_MESSAGE_TYPE, eventInfo.messageType,
        EVENT_PARAM_ERROR_CODE, eventInfo.errCode,
        EVENT_REASON, eventInfo.reason);
}

void EventReport::InnerSendSubscribeEvent(const EventInfo &eventInfo)
{
    InnerEventWrite(
        SUBSCRIBE,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        EVENT_PARAM_PID, eventInfo.pid,
        EVENT_PARAM_UID, eventInfo.uid,
        EVENT_PARAM_USER_ID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName);
}

void EventReport::InnerSendUnSubscribeEvent(const EventInfo &eventInfo)
{
    InnerEventWrite(
        UNSUBSCRIBE,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        EVENT_PARAM_PID, eventInfo.pid,
        EVENT_PARAM_UID, eventInfo.uid,
        EVENT_PARAM_USER_ID, eventInfo.userId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName);
}

void EventReport::InnerSendEnableNotificationEvent(const EventInfo &eventInfo)
{
    InnerEventWrite(
        ENABLE_NOTIFICATION,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_UID, eventInfo.uid,
        EVENT_PARAM_ENABLE, eventInfo.enable);
}

void EventReport::InnerSendEnableNotificationSlotEvent(const EventInfo &eventInfo)
{
    InnerEventWrite(
        ENABLE_NOTIFICATION_SLOT,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_UID, eventInfo.uid,
        EVENT_PARAM_SLOT_TYPE, eventInfo.slotType,
        EVENT_PARAM_ENABLE, eventInfo.enable);
}

void EventReport::InnerSendLiveviewUploadEvent(const EventInfo &eventInfo)
{
    InnerEventWrite(
        STATIC_LIVE_VIEW_UPLOAD,
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        EVENT_PARAM_NOTIFICATION_ID, eventInfo.notificationId,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_CONTENT_TYPE, eventInfo.contentType,
        EVENT_PARAM_OPERATE_FLAG, eventInfo.operateFlag);
}

void EventReport::InnerSendPublishEvent(const EventInfo &eventInfo)
{
    InnerEventWrite(
        PUBLISH,
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        EVENT_PARAM_NOTIFICATION_ID, eventInfo.notificationId,
        EVENT_PARAM_CONTENT_TYPE, eventInfo.contentType,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_USER_ID, eventInfo.userId,
        EVENT_PARAM_SLOT_TYPE, eventInfo.slotType,
        EVENT_PARAM_CLASS, eventInfo.classification,
        EVENT_PARAM_CONTROLFLAGS, eventInfo.notificationControlFlags,
        EVENT_PARAM_REMINDERFLAGS, eventInfo.reminderFlags);
}

void EventReport::InnerSendCancelEvent(const EventInfo &eventInfo)
{
    InnerEventWrite(
        CANCEL,
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        EVENT_PARAM_NOTIFICATION_ID, eventInfo.notificationId,
        EVENT_PARAM_NOTIFICATION_LABEL, eventInfo.notificationLabel,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_UID, eventInfo.uid);
}

void EventReport::InnerSendRemoveEvent(const EventInfo &eventInfo)
{
    InnerEventWrite(
        REMOVE,
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        EVENT_PARAM_NOTIFICATION_ID, eventInfo.notificationId,
        EVENT_PARAM_NOTIFICATION_LABEL, eventInfo.notificationLabel,
        EVENT_PARAM_BUNDLE_NAME, eventInfo.bundleName,
        EVENT_PARAM_UID, eventInfo.uid);
}

template<typename... Types>
void EventReport::InnerEventWrite(const std::string &eventName,
    HiviewDFX::HiSysEvent::EventType type, Types... keyValues)
{
    HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::NOTIFICATION,
        eventName,
        static_cast<HiviewDFX::HiSysEvent::EventType>(type),
        keyValues...);
}
#endif
} // namespace Notification
} // namespace OHOS