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

#include "advanced_notification_flow_control_service.h"

#include "ans_inner_errors.h"
#include "notification_config_parse.h"
#include "notification_analytics_util.h"

namespace OHOS {
namespace Notification {
std::mutex FlowControlService::flowControlMutex_;
std::mutex FlowControlService::systemFlowControlMutex_;
std::mutex FlowControlService::singleAppFlowControlMutex_;

FlowControlService::FlowControlService()
{
    DelayedSingleton<NotificationConfigParse>::GetInstance()->GetFlowCtrlConfigFromCCM(threshold_);
}

ErrCode FlowControlService::FlowControl(const std::shared_ptr<NotificationRecord> &record,
    const int32_t callingUid, bool isNotificationExists)
{
    if (record->isNeedFlowCtrl == false) {
        return ERR_OK;
    }

    ErrCode result = ERR_OK;
    if (!isNotificationExists) {
        if (record->request->IsUpdateOnly()) {
            ANS_LOGE("Notification not exists when update");
            return ERR_ANS_NOTIFICATION_NOT_EXISTS;
        }
        result = PublishFlowCtrl(record, callingUid);
    } else {
        result = UpdateFlowCtrl(record, callingUid);
    }

    return result;
}

ErrCode FlowControlService::PublishFlowCtrl(const std::shared_ptr<NotificationRecord> &record,
    const int32_t callingUid)
{
    if (record->isNeedFlowCtrl == false) {
        return ERR_OK;
    }
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    ErrCode result = ERR_OK;
    result = PublishSingleAppFlowCtrl(record, now, callingUid);
    if (result != ERR_OK) {
        return result;
    }
    result = PublishGlobalFlowCtrl(record, now);
    if (result != ERR_OK) {
        return result;
    }
    PublishRecordTimestamp(record, now, callingUid);
    PublishSingleAppFlowCtrlRemoveExpire(now);
    return ERR_OK;
}

ErrCode FlowControlService::PublishGlobalFlowCtrl(const std::shared_ptr<NotificationRecord> &record,
    std::chrono::system_clock::time_point now)
{
    ANS_LOGD("PublishGlobalFlowCtrl size %{public}zu,%{public}zu",
        flowControlPublishTimestampList_.size(), systemFlowControlPublishTimestampList_.size());
    if (record->isThirdparty == true) {
        // Third-part flow control
        std::lock_guard<std::mutex> lock(flowControlMutex_);
        NotificationAnalyticsUtil::RemoveExpired(flowControlPublishTimestampList_, now);
        if (flowControlPublishTimestampList_.size() >= threshold_.maxCreateNumPerSecond) {
            ANS_LOGE("Third-part PublishGlobalFlowCtrl failed");
            HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_3, EventBranchId::BRANCH_2)
                .ErrorCode(ERR_ANS_OVER_MAX_ACTIVE_PERSECOND).Message("Third-part PublishGlobalFlowCtrl failed");
            if (record != nullptr) {
                NotificationAnalyticsUtil::ReportPublishFailedEvent(record->request, message);
            }
            return ERR_ANS_OVER_MAX_ACTIVE_PERSECOND;
        }
    } else {
        // System flow control
        std::lock_guard<std::mutex> lock(systemFlowControlMutex_);
        NotificationAnalyticsUtil::RemoveExpired(systemFlowControlPublishTimestampList_, now);
        if (systemFlowControlPublishTimestampList_.size() >= threshold_.maxCreateNumPerSecond) {
            ANS_LOGE("System PublishGlobalFlowCtrl failed");
            HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_3, EventBranchId::BRANCH_3)
                .ErrorCode(ERR_ANS_OVER_MAX_ACTIVE_PERSECOND).Message("System PublishGlobalFlowCtrl failed");
            if (record != nullptr) {
                NotificationAnalyticsUtil::ReportPublishFailedEvent(record->request, message);
            }
            return ERR_ANS_OVER_MAX_ACTIVE_PERSECOND;
        }
    }
    return ERR_OK;
}

ErrCode FlowControlService::PublishSingleAppFlowCtrl(const std::shared_ptr<NotificationRecord> &record,
    std::chrono::system_clock::time_point now, const int32_t callingUid)
{
    std::lock_guard<std::mutex> lock(singleAppFlowControlMutex_);
    auto singleAppFlowControlIter = singleAppFlowControlPublishTimestampMap_.find(callingUid);
    if (singleAppFlowControlIter == singleAppFlowControlPublishTimestampMap_.end()) {
        return ERR_OK;
    }
    NotificationAnalyticsUtil::RemoveExpired(*(singleAppFlowControlIter->second), now);
    if (singleAppFlowControlIter->second->size() >= threshold_.maxCreateNumPerSecondPerApp) {
        ANS_LOGE("SingleAppPublishFlowControl failed");
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_3, EventBranchId::BRANCH_4)
            .ErrorCode(ERR_ANS_OVER_MAX_ACTIVE_PERSECOND).Message("SingleAppPublishFlowControl failed");
        if (record != nullptr) {
            NotificationAnalyticsUtil::ReportPublishFailedEvent(record->request, message);
        }
        return ERR_ANS_OVER_MAX_ACTIVE_PERSECOND;
    }
    return ERR_OK;
}

void FlowControlService::PublishRecordTimestamp(const std::shared_ptr<NotificationRecord> &record,
    std::chrono::system_clock::time_point now, const int32_t callingUid)
{
    if (record->isThirdparty == true) {
        std::lock_guard<std::mutex> lock(flowControlMutex_);
        flowControlPublishTimestampList_.push_back(now);
    } else {
        std::lock_guard<std::mutex> lock(systemFlowControlMutex_);
        systemFlowControlPublishTimestampList_.push_back(now);
    }

    std::lock_guard<std::mutex> lock(singleAppFlowControlMutex_);
    auto singleAppFlowControlIter = singleAppFlowControlPublishTimestampMap_.find(callingUid);
    if (singleAppFlowControlIter == singleAppFlowControlPublishTimestampMap_.end()) {
        singleAppFlowControlPublishTimestampMap_[callingUid] =
            std::make_shared<std::list<std::chrono::system_clock::time_point>>();
        singleAppFlowControlIter = singleAppFlowControlPublishTimestampMap_.find(callingUid);
    }
    singleAppFlowControlIter->second->push_back(now);
}

void FlowControlService::PublishSingleAppFlowCtrlRemoveExpire(std::chrono::system_clock::time_point now)
{
    std::lock_guard<std::mutex> lock(singleAppFlowControlMutex_);
    for (auto iter = singleAppFlowControlPublishTimestampMap_.begin();
        iter != singleAppFlowControlPublishTimestampMap_.end();) {
        auto latest = iter->second->back();
        if (std::chrono::abs(now - latest) > SINGLE_APP_FLOW_CONTRL_EXPIRE_TIME) {
            iter = singleAppFlowControlPublishTimestampMap_.erase(iter);
        } else {
            ++iter;
        }
    }
}

ErrCode FlowControlService::UpdateFlowCtrl(const std::shared_ptr<NotificationRecord> &record,
    const int32_t callingUid)
{
    if (record->isNeedFlowCtrl == false) {
        return ERR_OK;
    }
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    ErrCode result = ERR_OK;
    result = UpdateSingleAppFlowCtrl(record, now, callingUid);
    if (result != ERR_OK) {
        return result;
    }
    result = UpdateGlobalFlowCtrl(record, now);
    if (result != ERR_OK) {
        return result;
    }
    UpdateRecordTimestamp(record, now, callingUid);
    UpdateSingleAppFlowCtrlRemoveExpire(now);
    return result;
}

ErrCode FlowControlService::UpdateGlobalFlowCtrl(const std::shared_ptr<NotificationRecord> &record,
    std::chrono::system_clock::time_point now)
{
    ANS_LOGD("UpdateGlobalFlowCtrl size %{public}zu,%{public}zu",
        flowControlUpdateTimestampList_.size(), systemFlowControlUpdateTimestampList_.size());
    if (record->isThirdparty == true) {
        // Third-part flow control
        std::lock_guard<std::mutex> lock(flowControlMutex_);
        NotificationAnalyticsUtil::RemoveExpired(flowControlUpdateTimestampList_, now);
        if (flowControlUpdateTimestampList_.size() >= threshold_.maxUpdateNumPerSecond) {
            ANS_LOGE("Third-part UpdateGlobalFlowCtrl failed");
            HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_4, EventBranchId::BRANCH_3)
                .ErrorCode(ERR_ANS_OVER_MAX_UPDATE_PERSECOND).Message("Third-part updateGlobalFlowCtrl failed");
            if (record != nullptr) {
                NotificationAnalyticsUtil::ReportPublishFailedEvent(record->request, message);
            }
            return ERR_ANS_OVER_MAX_UPDATE_PERSECOND;
        }
    } else {
        // System flow control
        std::lock_guard<std::mutex> lock(systemFlowControlMutex_);
        NotificationAnalyticsUtil::RemoveExpired(systemFlowControlUpdateTimestampList_, now);
        if (systemFlowControlUpdateTimestampList_.size() >= threshold_.maxUpdateNumPerSecond) {
            ANS_LOGE("System UpdateGlobalFlowCtrl failed");
            HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_4, EventBranchId::BRANCH_4)
                .ErrorCode(ERR_ANS_OVER_MAX_UPDATE_PERSECOND).Message("System updateGlobalFlowCtrl failed");
            if (record != nullptr) {
                NotificationAnalyticsUtil::ReportPublishFailedEvent(record->request, message);
            }
            return ERR_ANS_OVER_MAX_UPDATE_PERSECOND;
        }
    }
    return ERR_OK;
}

ErrCode FlowControlService::UpdateSingleAppFlowCtrl(const std::shared_ptr<NotificationRecord> &record,
    std::chrono::system_clock::time_point now, const int32_t callingUid)
{
    std::lock_guard<std::mutex> lock(singleAppFlowControlMutex_);
    auto singleAppFlowControlIter = singleAppFlowControlUpdateTimestampMap_.find(callingUid);
    if (singleAppFlowControlIter == singleAppFlowControlUpdateTimestampMap_.end()) {
        return ERR_OK;
    }
    NotificationAnalyticsUtil::RemoveExpired(*(singleAppFlowControlIter->second), now);
    if (singleAppFlowControlIter->second->size() >= threshold_.maxUpdateNumPerSecondPerApp) {
        ANS_LOGE("SingleAppUpdateFlowControl failed");
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_4, EventBranchId::BRANCH_5)
            .ErrorCode(ERR_ANS_OVER_MAX_UPDATE_PERSECOND).Message("SingleAppUpdateFlowControl failed");
        if (record != nullptr) {
            NotificationAnalyticsUtil::ReportPublishFailedEvent(record->request, message);
        }
        return ERR_ANS_OVER_MAX_UPDATE_PERSECOND;
    }
    return ERR_OK;
}

void FlowControlService::UpdateRecordTimestamp(const std::shared_ptr<NotificationRecord> &record,
    std::chrono::system_clock::time_point now, const int32_t callingUid)
{
    if (record->isThirdparty == true) {
        std::lock_guard<std::mutex> lock(flowControlMutex_);
        flowControlUpdateTimestampList_.push_back(now);
    } else {
        std::lock_guard<std::mutex> lock(systemFlowControlMutex_);
        systemFlowControlUpdateTimestampList_.push_back(now);
    }

    std::lock_guard<std::mutex> lock(singleAppFlowControlMutex_);
    auto singleAppFlowControlIter = singleAppFlowControlUpdateTimestampMap_.find(callingUid);
    if (singleAppFlowControlIter == singleAppFlowControlUpdateTimestampMap_.end()) {
        singleAppFlowControlUpdateTimestampMap_[callingUid] =
            std::make_shared<std::list<std::chrono::system_clock::time_point>>();
        singleAppFlowControlIter = singleAppFlowControlUpdateTimestampMap_.find(callingUid);
    }
    singleAppFlowControlIter->second->push_back(now);
}

void FlowControlService::UpdateSingleAppFlowCtrlRemoveExpire(std::chrono::system_clock::time_point now)
{
    std::lock_guard<std::mutex> lock(singleAppFlowControlMutex_);
    for (auto iter = singleAppFlowControlUpdateTimestampMap_.begin();
        iter != singleAppFlowControlUpdateTimestampMap_.end();) {
        auto latest = iter->second->back();
        if (std::chrono::abs(now - latest) > SINGLE_APP_FLOW_CONTRL_EXPIRE_TIME) {
            iter = singleAppFlowControlUpdateTimestampMap_.erase(iter);
        } else {
            ++iter;
        }
    }
}
}  // namespace Notification
}  // namespace OHOS