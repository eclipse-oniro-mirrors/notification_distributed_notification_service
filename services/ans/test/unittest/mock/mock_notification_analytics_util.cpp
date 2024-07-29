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

namespace OHOS {
namespace Notification {

HaMetaMessage::HaMetaMessage(uint32_t sceneId, uint32_t branchId)
    : sceneId_(sceneId), branchId_(branchId)
{
}

bool HaMetaMessage::NeedReport() const
{
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
    slotType_ = slotType;
    return *this;
}

std::string HaMetaMessage::Build() const
{
    return std::string("");
}

void NotificationAnalyticsUtil::ReportPublishFailedEvent(const sptr<NotificationRequest>& request,
    const HaMetaMessage& message)
{
    return;
}

void NotificationAnalyticsUtil::ReportDeleteFailedEvent(const sptr<NotificationRequest>& request,
    HaMetaMessage& message)
{
    return;
}

void NotificationAnalyticsUtil::CommonNotificationEvent(const sptr<NotificationRequest>& request,
    int32_t eventCode, const HaMetaMessage& message)
{
    return;
}

void NotificationAnalyticsUtil::ReportNotificationEvent(const sptr<NotificationRequest>& request,
    EventFwk::Want want, int32_t eventCode, const std::string& reason)
{
    return;
}

void NotificationAnalyticsUtil::ReportModifyEvent(const HaMetaMessage& message)
{
    return;
}

void NotificationAnalyticsUtil::ReportDeleteFailedEvent(const HaMetaMessage& message)
{
    return;
}

void NotificationAnalyticsUtil::ReportNotificationEvent(EventFwk::Want want,
    int32_t eventCode, const std::string& reason)
{
    return;
}
} // namespace Notification
} // namespace OHOS
