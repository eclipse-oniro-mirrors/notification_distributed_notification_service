/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "advanced_notification_service.h"

#include "advanced_notification_priority_helper.h"
#include "accesstoken_kit.h"
#include "access_token_helper.h"
#include "advanced_notification_inline.h"
#include "aes_gcm_helper.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_trace_wrapper.h"
#include "ans_permission_def.h"

#include "ipc_skeleton.h"

#include "notification_preferences.h"
#include "notification_bundle_option.h"
#include "notification_analytics_util.h"
#include "notification_timer_info.h"

namespace OHOS {
namespace Notification {
ErrCode AdvancedNotificationService::SnoozeNotification(const std::string &hashCode, const int64_t delayTime)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("called");
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_33, EventBranchId::BRANCH_0);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("Is Not systemApp");
        message.Message("Not systemApp.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_NON_SYSTEM_APP));
        return ERR_ANS_NON_SYSTEM_APP;
    }
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission denied.");
        message.Message("Permission denied.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_PERMISSION_DENIED).BranchId(BRANCH_1));
        return ERR_ANS_PERMISSION_DENIED;
    }

    ErrCode result = ERR_OK;
    int64_t triggerTime = GetCurrentTime() + delayTime * NotificationConstant::SECOND_TO_MS;
    auto submitResult = notificationSvrQueue_.SyncSubmit(std::bind([&]() {
        result = ExcuteSnoozeNotification(hashCode, triggerTime);
    }));
    ANS_COND_DO_ERR(submitResult != ERR_OK, return submitResult, "Serial queue is valid");
    if (result == ERR_OK) {
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.Message(hashCode + " snooze " + std::to_string(delayTime) + "s").BranchId(BRANCH_5));
    }
    return result;
}

ErrCode AdvancedNotificationService::ExcuteSnoozeNotification(const std::string &hashCode, const int64_t delayTime)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_33, EventBranchId::BRANCH_0);
    std::shared_ptr<NotificationRecord> outRecord = nullptr;
    sptr<Notification> notification = nullptr;
    for (const auto &record : notificationList_) {
        if (record != nullptr && record->notification != nullptr &&
            record->notification->GetKey() == hashCode) {
            outRecord = record;
            break;
        }
    }
    if (outRecord == nullptr) {
        ANS_LOGE("notification is not exists");
        message.Message(hashCode + " is not exists");
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_NOTIFICATION_NOT_EXISTS).BranchId(BRANCH_3));
        return ERR_ANS_NOTIFICATION_NOT_EXISTS;
    }
    bool isCollaboration =
        AdvancedNotificationPriorityHelper::GetInstance()->IsCollaborationNotification(outRecord->request);
    if (outRecord->request->IsCommonLiveView() || outRecord->request->IsSystemLiveView() ||
        !outRecord->notification->IsRemoveAllowed() || isCollaboration) {
        ANS_LOGE("notification is not supported to snooze");
        message.Message(hashCode + " is not supported to snooze");
        NotificationAnalyticsUtil::ReportModifyEvent(
            message.ErrorCode(ERR_ANS_NOTIFICATION_SNOOZE_NOTALLOWED).BranchId(BRANCH_4));
        return ERR_ANS_NOTIFICATION_SNOOZE_NOTALLOWED;
    }

    ErrCode result = ERR_OK;
    int32_t reason = NotificationConstant::SNOOZE_REASON_DELETE;
    result = RemoveFromNotificationList(hashCode, notification, false, reason);
    if (result != ERR_OK) {
        return result;
    }
    if (notification != nullptr) {
        CancelTimer(notification->GetAutoDeletedTimer());
        NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, nullptr, reason);
    }
    if (!SetSnoozeDelayTimeToDB(delayTime, outRecord)) {
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
    
    StartSnoozeTimer();
    return ERR_OK;
}

bool AdvancedNotificationService::SetSnoozeDelayTimeToDB(const int64_t delayTime,
    const std::shared_ptr<NotificationRecord> &record)
{
    auto snoozeRecord = std::make_shared<NotificationRecord>();
    snoozeRecord->request = record->request;
    snoozeRecord->request->SetSnoozeDelayTime(delayTime);
    snoozeRecord->notification = new (std::nothrow) Notification(snoozeRecord->request);
    if (snoozeRecord->notification == nullptr) {
        ANS_LOGE("notification malloc error");
        return false;
    }
    snoozeRecord->bundleOption = record->bundleOption;
    SetNotificationRemindType(snoozeRecord->notification, true);
    snoozeRecord->request->SetAutoDeletedTime(NotificationConstant::INVALID_AUTO_DELETE_TIME);
    NotificationRequestDb requestDb = { .request = snoozeRecord->request, .bundleOption = snoozeRecord->bundleOption};
    if (!SetEncryptToDB(requestDb)) {
        ANS_LOGE("SetEncryptToDB failed");
        return false;
    }

    InsertsnoozeDelayTimer(snoozeRecord);
    return true;
}

void AdvancedNotificationService::SnoozeNotificationConsumed(const std::shared_ptr<NotificationRecord> &record)
{
    if (record == nullptr) {
        ANS_LOGE("No subscriber to notify.");
        return;
    }
    record->request->SetDeliveryTime(GetCurrentTime());
    CheckDoNotDisturbProfile(record);
    NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    NotificationPreferences::GetInstance()->IsSilentReminderEnabled(record->bundleOption, enableStatus);
    if (enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON ||
        enableStatus == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON) {
        record->notification->SetEnableLight(false);
        record->notification->SetEnableSound(false);
        record->notification->SetEnableVibration(false);
        record->request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::SOUND_FLAG, false);
        record->request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::LOCKSCREEN_FLAG, false);
        record->request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::BANNER_FLAG, false);
        record->request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::LIGHTSCREEN_FLAG, false);
        record->request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::VIBRATION_FLAG, false);
    }
    if (AssignToNotificationList(record) != ERR_OK) {
        return;
    }

    sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
    NotificationSubscriberManager::GetInstance()->NotifyConsumed(record->notification, sortingMap);
}

void AdvancedNotificationService::DeleteSnoozeNotificationFromDB(const std::shared_ptr<NotificationRecord> &record)
{
    int32_t userId = record->request->GetReceiverUserId();
    std::string secureKey = record->request->GetSecureKey();
    auto result = NotificationPreferences::GetInstance()->DeleteKvFromDb(secureKey, userId);
    if (result != ERR_OK) {
        ANS_LOGE("Delete notification request failed, secureKey %{public}s.", secureKey.c_str());
    }
}

bool AdvancedNotificationService::IsCanRecoverSnooze(const std::shared_ptr<NotificationRecord> &record)
{
    if (record->request->GetSnoozeDelayTime() > GetCurrentTime() &&
        !record->request->GetIsSnoozeTrigger()) {
        InsertsnoozeDelayTimer(record);
        return true;
    }

    return false;
}

bool AdvancedNotificationService::SetEncryptToDB(const NotificationRequestDb &requestDb)
{
#ifdef ANS_FEATURE_DIST_NOTIFICATION_PERSIST
    auto request = requestDb.request;
    auto bundleOption = requestDb.bundleOption;
    if (!request || !bundleOption) {
        return false;
    }
    nlohmann::json jsonObject;
    if (!NotificationJsonConverter::ConvertToJson(request, jsonObject)) {
        ANS_LOGE("Convert request to json object failed, bundle name %{public}s, id %{public}d.",
            request->GetCreatorBundleName().c_str(), request->GetNotificationId());
        return false;
    }
    if (!NotificationJsonConverter::ConvertToJson(bundleOption, jsonObject)) {
        ANS_LOGE("Convert bundle to json object failed, bundle name %{public}s, id %{public}d.",
            bundleOption->GetBundleName().c_str(), request->GetNotificationId());
        return false;
    }
    std::string encryptValue;
    ErrCode errorCode = AesGcmHelper::Encrypt(jsonObject.dump(), encryptValue);
    if (errorCode != ERR_OK) {
        ANS_LOGE("SetSnoozeDelayTimeToDB encrypt error %{public}d", errorCode);
        return false;
    }
    std::string secureKey = request->GetSecureKey();
    auto secureResult = NotificationPreferences::GetInstance()->SetKvToDb(
        secureKey, encryptValue, request->GetReceiverUserId());
    if (secureResult != ERR_OK) {
        ANS_LOGE("SetSnoozeDelayTimeToDB SetKvToDb error %{public}d", secureResult);
        return false;
    }

    return true;
#else
    return true;
#endif
}

void AdvancedNotificationService::TriggerSnoozeDelay()
{
    int64_t current = NotificationAnalyticsUtil::GetCurrentTime();
    {
        std::lock_guard<ffrt::mutex> locker(snoozeNotificationMutex_);
        for (const auto &iter : snoozeDelayTimerList_) {
            auto request = iter->request;
            if (!request || request->GetSnoozeDelayTime() >= current) {
                continue;
            }
            SnoozeNotificationConsumed(iter);
            std::string secureKey = request->GetSecureKey();
            request->SetIsSnoozeTrigger(true);
            NotificationRequestDb requestDb = { .request = request, .bundleOption = iter->bundleOption};
            SetEncryptToDB(requestDb);
        }
    }

    SetNextSnoozeTimer(current);
}

void AdvancedNotificationService::InsertsnoozeDelayTimer(const std::shared_ptr<NotificationRecord> &record)
{
    std::lock_guard<ffrt::mutex> locker(snoozeNotificationMutex_);
    if (record == nullptr) {
        return;
    }
    snoozeDelayTimerList_.push_back(record);
    snoozeDelayTimerList_.sort([](
        const std::shared_ptr<NotificationRecord> &first, const std::shared_ptr<NotificationRecord> &second) {
        return (first->request->GetSnoozeDelayTime() < second->request->GetSnoozeDelayTime());
    });
}

void AdvancedNotificationService::CreateSnoozeTimer()
{
    auto timerInfo = std::make_shared<NotificationTimerInfo>();
    wptr<AdvancedNotificationService> wThis = this;
    auto triggerFunc = [wThis] {
        sptr<AdvancedNotificationService> sThis = wThis.promote();
        if (sThis != nullptr) {
            sThis->TriggerSnoozeDelay();
        }
    };
    timerInfo->SetCallbackInfo(triggerFunc);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    uint8_t timerTypeWakeup = static_cast<uint8_t>(timerInfo->TIMER_TYPE_WAKEUP);
    uint8_t timerTypeExact = static_cast<uint8_t>(timerInfo->TIMER_TYPE_EXACT);
    int32_t timerType = static_cast<int32_t>(timerTypeWakeup | timerTypeExact);
    timerInfo->SetType(timerType);
    timerInfo->SetName("snoozeDelayTimer");
    timerImpl_.CreateTimer(timerInfo);
}

bool AdvancedNotificationService::StartSnoozeTimer()
{
    int64_t triggerTime = GetEarliestTriggerTime();
    if (triggerTime == 0) {
        return false;
    }

    timerImpl_.StopTimer();
    timerImpl_.DestroyTimer();
    CreateSnoozeTimer();
    timerImpl_.StartTimer(triggerTime);
    
    return true;
}

int64_t AdvancedNotificationService::GetEarliestTriggerTime()
{
    std::lock_guard<ffrt::mutex> locker(snoozeNotificationMutex_);
    if (!snoozeDelayTimerList_.empty()) {
        auto iter = snoozeDelayTimerList_.begin();
        return (*iter)->request->GetSnoozeDelayTime();
    }

    return 0;
}

void AdvancedNotificationService::CheckSnoozeTimer()
{
    if (snoozeDelayTimerList_.empty()) {
        timerImpl_.StopTimer();
        timerImpl_.DestroyTimer();
        return;
    }

    StartSnoozeTimer();
}

void AdvancedNotificationService::SetNextSnoozeTimer(int64_t currentTime)
{
    {
        std::lock_guard<ffrt::mutex> locker(snoozeNotificationMutex_);
        for (auto it = snoozeDelayTimerList_.begin(); it != snoozeDelayTimerList_.end();) {
            if ((*it)->request == nullptr) {
                continue;
            }
            if ((*it)->request->GetSnoozeDelayTime() < currentTime) {
                it = snoozeDelayTimerList_.erase(it);
            } else {
                break;
            }
        }
    }
    CheckSnoozeTimer();
}

void AdvancedNotificationService::RemoveAllFromSnoozeDelayList(const sptr<NotificationBundleOption> &bundle)
{
    if (bundle == nullptr) {
        return;
    }
    {
        std::lock_guard<ffrt::mutex> locker(snoozeNotificationMutex_);
        for (auto it = snoozeDelayTimerList_.begin(); it != snoozeDelayTimerList_.end();) {
            if ((*it) == nullptr || (*it)->bundleOption == nullptr) {
                ++it;
                continue;
            }
            if ((*it)->bundleOption->GetBundleName() == bundle->GetBundleName() &&
                (*it)->bundleOption->GetUid() == bundle->GetUid()) {
                DeleteSnoozeNotificationFromDB(*it);
                it = snoozeDelayTimerList_.erase(it);
            } else {
                ++it;
            }
        }
    }
    CheckSnoozeTimer();
}

void AdvancedNotificationService::RemoveAllFromSnoozeDelayListByUser(int32_t userId)
{
    {
        std::lock_guard<ffrt::mutex> locker(snoozeNotificationMutex_);
        for (auto it = snoozeDelayTimerList_.begin(); it != snoozeDelayTimerList_.end();) {
            if (((*it)->notification->GetUserId() == userId)) {
                DeleteSnoozeNotificationFromDB(*it);
                it = snoozeDelayTimerList_.erase(it);
            } else {
                ++it;
            }
        }
    }
    CheckSnoozeTimer();
}

bool AdvancedNotificationService::IsSetSnooze(const std::string &key)
{
    for (auto item : notificationList_) {
        if (item->notification->GetKey().find(key) == 0) {
            return true;
        }
    }
    std::lock_guard<ffrt::mutex> locker(snoozeNotificationMutex_);
    for (auto item : snoozeDelayTimerList_) {
        if (item->notification->GetKey().find(key) == 0) {
            return true;
        }
    }
    return false;
}
} // Notification
} // OHOS
