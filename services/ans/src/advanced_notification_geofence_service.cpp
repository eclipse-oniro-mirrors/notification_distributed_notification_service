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

#include "access_token_helper.h"
#include "advanced_notification_inline.h"
#include "aes_gcm_helper.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_permission_def.h"
#include "ans_trace_wrapper.h"
#include "ipc_skeleton.h"
#include "liveview_all_scenarios_extension_wrapper.h"
#include "notification_config_parse.h"
#include "notification_preferences.h"
#include "os_account_manager_helper.h"

namespace OHOS {
namespace Notification {
namespace {
constexpr size_t GEOFENCE_RECORDS_SIZE_ONE = 1;
constexpr int32_t ZERO_USER_ID = 0;
}  // namespace
ErrCode AdvancedNotificationService::SetGeofenceEnabled(bool enabled)
{
    auto result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }

    result = NotificationPreferences::GetInstance()->SetGeofenceEnabled(enabled);
    if (result != ERR_OK) {
        ANS_LOGE("Set GeofenceEnabled failed, errCode=%{public}d", result);
        return result;
    }
    if (!enabled) {
        int32_t userId = SUBSCRIBE_USER_INIT;
        OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
        return ClearAllGeofenceNotificationRequests(userId);
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::IsGeofenceEnabled(bool &enabled)
{
    return NotificationPreferences::GetInstance()->IsGeofenceEnabled(enabled);
}

ErrCode AdvancedNotificationService::OnNotifyDelayedNotification(const sptr<NotificationRequest> &request,
    const sptr<NotificationBundleOption> &bundleOption, bool isUpdateByOwner)
{
    auto result = CheckGeofenceNotificationRequest(request);
    if (result != ERR_OK) {
        ANS_LOGE("CheckGeofenceNotificationRequest failed, errCode=%{public}d", result);
        return result;
    }

    auto record = MakeNotificationRecord(request, bundleOption);
    if (record == nullptr) {
        ANS_LOGE("Make notification record failed.");
        return ERR_ANS_NO_MEMORY;
    }
    record->isUpdateByOwner = isUpdateByOwner;
    AddToTriggerNotificationList(record);

    result = LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->OnNotifyDelayedNotification(request);
    if (result == ERR_OK) {
        GeofencePublishNotificationRequestDb requestDb = { .request = request, .bundleOption = bundleOption,
            .isUpdateByOwner = isUpdateByOwner };
        result = SetTriggerNotificationRequestToDb(requestDb);
        if (result != ERR_OK) {
            ANS_LOGE("SetTriggerNotificationRequestToDb failed, errCode=%{public}d", result);
            std::lock_guard<ffrt::mutex> lock(triggerNotificationMutex_);
            auto it = std::find(triggerNotificationList_.begin(), triggerNotificationList_.end(), record);
            if (it != triggerNotificationList_.end()) {
                triggerNotificationList_.erase(it);
            }
            return result;
        }
        return ERR_OK;
    }
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_15, EventBranchId::BRANCH_0);
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
    std::lock_guard<ffrt::mutex> lock(triggerNotificationMutex_);
    auto it = std::find(triggerNotificationList_.begin(), triggerNotificationList_.end(), record);
    if (it != triggerNotificationList_.end()) {
        triggerNotificationList_.erase(it);
    }
    return result;
}

ErrCode AdvancedNotificationService::ClearDelayNotification(const std::vector<std::string> &triggerKeys,
    const std::vector<int32_t> &userIds)
{
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission denied.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (triggerKeys.empty() || userIds.empty()) {
        ANS_LOGE("Input parameters triggerKeys or userIds are empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (triggerKeys.size() != userIds.size()) {
        ANS_LOGE("TriggerKeys size not equal userIds size.");
        return ERR_ANS_INVALID_PARAM;
    }
    for (size_t i = 0; i < triggerKeys.size(); ++i) {
        RemoveTriggerNotificationListByTriggerKey(triggerKeys[i]);
        auto result = NotificationPreferences::GetInstance()->DeleteKvFromDb(triggerKeys[i],  userIds[i]);
        if (result != ERR_OK) {
            return result;
        }
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::PublishDelayedNotification(const std::string &triggerKey, int32_t userId)
{
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission denied.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    std::lock_guard<ffrt::mutex> lock(triggerNotificationMutex_);
    for (auto it = triggerNotificationList_.begin(); it != triggerNotificationList_.end();) {
        if ((*it)->request->GetTriggerSecureKey() != triggerKey) {
            ++it;
            continue;
        }
        auto request = (*it)->request;
        auto bundleOption = (*it)->bundleOption;
        auto isUpdateByOwner = (*it)->isUpdateByOwner;
        ConvertTriggerLiveviewStatus(request);
        auto result = PublishPreparedNotificationInner(request, bundleOption, isUpdateByOwner);
        if (result != ERR_OK) {
            ANS_LOGE("PublishPreparedNotificationInner failed, errCode=%{public}d", result);
            return result;
        }
        result = NotificationPreferences::GetInstance()->DeleteKvFromDb(request->GetTriggerSecureKey(), userId);
        if (result != ERR_OK) {
            return result;
        }
        it = triggerNotificationList_.erase(it);
        return ERR_OK;
    }

    return ERR_ANS_NOTIFICATION_NOT_EXISTS;
}

void AdvancedNotificationService::ConvertTriggerLiveviewStatus(sptr<NotificationRequest> &request)
{
    if (request == nullptr || !request->IsCommonLiveView()) {
        return;
    }
    auto content = request->GetContent();
    if (content == nullptr || content->GetNotificationContent() == nullptr) {
        return;
    }
    auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(content->GetNotificationContent());
    auto status = liveViewContent->GetLiveViewStatus();
    if (status == NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_CREATE) {
        liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    }
    if (status == NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_END) {
        liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    }
}

ErrCode AdvancedNotificationService::ParseGeofenceNotificationFromDb(const std::string &value,
    GeofencePublishNotificationRequestDb &requestDb)
{
    if (value.empty() || !nlohmann::json::accept(value)) {
        ANS_LOGE("Invalid json");
        return ERR_ANS_NOTIFICATION_NOT_EXISTS;
    }

    auto jsonObject = nlohmann::json::parse(value);
    auto requestPtr = NotificationJsonConverter::ConvertFromJson<NotificationRequest>(jsonObject);
    requestDb.request = sptr<NotificationRequest>::MakeSptr(*requestPtr);
    if (requestDb.request == nullptr) {
        ANS_LOGE("Parse json string to notification request failed.");
        return ERR_ANS_NOTIFICATION_NOT_EXISTS;
    }
    auto bundleOptionPtr = NotificationJsonConverter::ConvertFromJson<NotificationBundleOption>(jsonObject);
    requestDb.bundleOption = sptr<NotificationBundleOption>::MakeSptr(*bundleOptionPtr);
    if (requestDb.bundleOption == nullptr) {
        ANS_LOGE("Parse json string to bundle option failed.");
        return ERR_ANS_NOTIFICATION_NOT_EXISTS;
    }
    if (jsonObject.find("isUpdateByOwner") != jsonObject.end() && jsonObject.at("isUpdateByOwner").is_boolean()) {
        requestDb.isUpdateByOwner = jsonObject.at("isUpdateByOwner").get<bool>();
    }

    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetTriggerNotificationRequestToDb(
    const GeofencePublishNotificationRequestDb &requestDb)
{
    auto request = requestDb.request;
    if (!request->IsCommonLiveView()) {
        return ERR_OK;
    }

    auto content = std::static_pointer_cast<NotificationLiveViewContent>(
        request->GetContent()->GetNotificationContent());
    if (request->GetOwnerUid() != DEFAULT_UID) {
        content->SetUid(request->GetOwnerUid());
    }
    if (content->GetLiveViewStatus() == NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END &&
        request->GetAutoDeletedTime() == NotificationConstant::NO_DELAY_DELETE_TIME) {
        return ERR_OK;
    }
    if (content->GetIsOnlyLocalUpdate()) {
        return ERR_OK;
    }

    nlohmann::json jsonObject;
    if (!NotificationJsonConverter::ConvertToJson(request, jsonObject)) {
        ANS_LOGE("Convert request to json object failed, bundle name %{public}s, id %{public}d.",
            request->GetCreatorBundleName().c_str(), request->GetNotificationId());
        return ERR_ANS_TASK_ERR;
    }
    auto bundleOption = requestDb.bundleOption;
    if (!NotificationJsonConverter::ConvertToJson(bundleOption, jsonObject)) {
        ANS_LOGE("Convert bundle to json object failed, bundle name %{public}s, id %{public}d.",
            bundleOption->GetBundleName().c_str(), request->GetNotificationId());
        return ERR_ANS_TASK_ERR;
    }
    jsonObject["isUpdateByOwner"] = requestDb.isUpdateByOwner;

    std::string encryptValue;
    ErrCode errorCode = AesGcmHelper::Encrypt(jsonObject.dump(), encryptValue);
    if (errorCode != ERR_OK) {
        ANS_LOGE("SetTriggerNotificationRequestToDb encrypt error");
        return static_cast<int>(errorCode);
    }
    auto userId = request->GetReceiverUserId();
    auto result = NotificationPreferences::GetInstance()->SetKvToDb(
        request->GetTriggerSecureKey(), encryptValue, userId);
    if (result != ERR_OK) {
        ANS_LOGE("Set failed, bundle name %{public}s, id %{public}d, key %{public}s, ret %{public}d.",
            request->GetCreatorBundleName().c_str(), request->GetNotificationId(),
            request->GetTriggerKey().c_str(), result);
        return result;
    }

    return ERR_OK;
}

void AdvancedNotificationService::AddToTriggerNotificationList(const std::shared_ptr<NotificationRecord> &record)
{
    std::lock_guard<ffrt::mutex> lock(triggerNotificationMutex_);
    triggerNotificationList_.push_back(record);
}

int32_t AdvancedNotificationService::GetBatchNotificationRequestsFromDb(
    std::vector<GeofencePublishNotificationRequestDb> &requestsDb, int32_t userId)
{
    std::unordered_map<std::string, std::string> dbRecords;
    std::vector<int32_t> userIds;
    int ret = ERR_OK;
    if (userId == -1) {
        ret = OsAccountManagerHelper::GetInstance().GetAllActiveOsAccount(userIds);
    } else {
        userIds.push_back(userId);
    }

    if (ret != ERR_OK) {
        ANS_LOGE("Get all os account failed.");
        return ret;
    }
    for (const int32_t userId : userIds) {
        int32_t result =
            NotificationPreferences::GetInstance()->GetBatchKvsFromDb(REQUEST_STORAGE_SECURE_TRIGGER_LIVE_VIEW_PREFIX,
                dbRecords, userId);
        if (result != ERR_OK) {
            ANS_LOGE("Get batch notification request failed.");
            return result;
        }
    }
    for (const auto &iter : dbRecords) {
        std::string decryptValue = iter.second;
        if (iter.first.rfind(REQUEST_STORAGE_SECURE_TRIGGER_LIVE_VIEW_PREFIX, 0) != 0) {
            continue;
        }
        ErrCode errorCode = AesGcmHelper::Decrypt(decryptValue, iter.second);
        if (errorCode != ERR_OK) {
            ANS_LOGE("GetBatchNotificationRequestsFromDb decrypt error");
            return static_cast<int>(errorCode);
        }
        GeofencePublishNotificationRequestDb requestDb;
        errorCode = ParseGeofenceNotificationFromDb(decryptValue, requestDb);
        if (errorCode != ERR_OK) {
            ANS_LOGE("ParseGeofenceNotificationFromDb error");
            return static_cast<int>(errorCode);
        }
        requestsDb.emplace_back(requestDb);
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::ClearAllGeofenceNotificationRequests(const int32_t &userId)
{
    std::unordered_map<std::string, std::string> dbRecords;
    auto result = NotificationPreferences::GetInstance()->GetBatchKvsFromDb(
        REQUEST_STORAGE_SECURE_TRIGGER_LIVE_VIEW_PREFIX, dbRecords, userId);
    std::vector<std::string> triggerKeys;
    for (const auto &iter : dbRecords) {
        if (iter.first.rfind(REQUEST_STORAGE_SECURE_TRIGGER_LIVE_VIEW_PREFIX, 0) != 0) {
            continue;
        }
        result = NotificationPreferences::GetInstance()->DeleteKvFromDb(iter.first, userId);
        if (result != ERR_OK) {
            ANS_LOGE("Delete notification request failed, key %{public}s.", iter.first.c_str());
            return result;
        }
        std::shared_ptr<NotificationRecord> record;
        FindGeofenceNotificationRecordByTriggerKey(iter.first, record);
        std::lock_guard<ffrt::mutex> lock(triggerNotificationMutex_);
        auto it = std::find(triggerNotificationList_.begin(), triggerNotificationList_.end(), record);
        if (it != triggerNotificationList_.end()) {
            triggerNotificationList_.erase(it);
        }
        triggerKeys.push_back(iter.first);
    }

    result = LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->OnNotifyClearNotification(triggerKeys);
    if (result != ERR_OK) {
        ANS_LOGE("Notify clear notification request failed, err %{public}d.", result);
        return result;
    }
    return ERR_OK;
}

void AdvancedNotificationService::FindGeofenceNotificationRecordByTriggerKey(const std::string &triggerKey,
    std::shared_ptr<NotificationRecord> &outRecord)
{
    outRecord = nullptr;
    std::lock_guard<ffrt::mutex> lock(triggerNotificationMutex_);
    for (const auto &record : triggerNotificationList_) {
        if (record == nullptr || record->notification == nullptr || record->request == nullptr) {
            continue;
        }
        if ((record->request->GetTriggerSecureKey() == triggerKey)) {
            outRecord = record;
            return;
        }
    }
}

void AdvancedNotificationService::FindGeofenceNotificationRecordByKey(const std::string &key,
    std::vector<std::shared_ptr<NotificationRecord>> &outRecords)
{
    std::lock_guard<ffrt::mutex> lock(triggerNotificationMutex_);
    for (const auto &record : triggerNotificationList_) {
        if (record == nullptr || record->notification == nullptr || record->request == nullptr) {
            continue;
        }
        if ((record->request->GetSecureKey() == key)) {
            outRecords.push_back(record);
        }
    }
}

void AdvancedNotificationService::FindNotificationRecordByKey(const std::string &key,
    std::shared_ptr<NotificationRecord> &outRecord)
{
    outRecord = nullptr;
    for (const auto &record : notificationList_) {
        if (record == nullptr || record->notification == nullptr || record->request == nullptr) {
            continue;
        }
        if ((record->request->GetSecureKey() == key)) {
            outRecord = record;
            return;
        }
    }
}

ErrCode AdvancedNotificationService::RecoverGeofenceLiveViewFromDb(int32_t userId)
{
    std::vector<GeofencePublishNotificationRequestDb> requestsDb;
    auto result = GetBatchNotificationRequestsFromDb(requestsDb, userId);
    if (result != ERR_OK) {
        ANS_LOGE("Get geofence liveView from db failed.");
        return result;
    }
    ANS_LOGD("The number of live views to recover: %{public}zu.", requestsDb.size());
    std::vector<std::string> keys;
    for (const auto &requestObj : requestsDb) {
        auto record = MakeNotificationRecord(requestObj.request, requestObj.bundleOption);
        if (record == nullptr) {
            ANS_LOGE("Make notification record failed.");
            continue;
        }
        record->isUpdateByOwner = requestObj.isUpdateByOwner;
        AddToTriggerNotificationList(record);
    }
    return ERR_OK;
}

void AdvancedNotificationService::ProcForDeleteGeofenceLiveView(const std::shared_ptr<NotificationRecord> &record)
{
    if ((record->request == nullptr) || !(record->request->IsCommonLiveView())) {
        return;
    }
    NotificationPreferences::GetInstance()->DeleteKvFromDb(record->request->GetTriggerSecureKey(),
        record->request->GetReceiverUserId());
    std::vector<std::string> triggerKeys;
    triggerKeys.push_back(record->request->GetTriggerSecureKey());
    LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->OnNotifyClearNotification(triggerKeys);
}

ErrCode AdvancedNotificationService::SetGeofenceTriggerTimer(const std::shared_ptr<NotificationRecord> &record)
{
    auto trigger = record->request->GetNotificationTrigger();
    if (trigger == nullptr) {
        return ERR_ANS_TASK_ERR;
    }
    int64_t maxExpiredTime = GetCurrentTime() + trigger->GetDisplayTime() * NotificationConstant::SECOND_TO_MS;
    auto result = StartGeofenceTriggerTimer(record, maxExpiredTime,
        NotificationConstant::TRIGGER_GEOFENCE_REASON_DELETE);
    if (result != ERR_OK) {
        return result;
    }
    record->request->SetGeofenceTriggerDeadLine(maxExpiredTime);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::StartGeofenceTriggerTimer(const std::shared_ptr<NotificationRecord> &record,
    int64_t expiredTimePoint, const int32_t reason)
{
    uint64_t timerId = StartAutoDelete(record,
        expiredTimePoint, reason);
    if (timerId == NotificationConstant::INVALID_TIMER_ID) {
        std::string message = "Start trigger auto delete timer failed.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(7, 1)
            .ErrorCode(ERR_ANS_TASK_ERR);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_TASK_ERR;
    }
    record->notification->SetGeofenceTriggerTimer(timerId);
    return ERR_OK;
}

void AdvancedNotificationService::CancelGeofenceTriggerTimer(const std::shared_ptr<NotificationRecord> &record)
{
    record->request->SetGeofenceTriggerDeadLine(0);
    CancelTimer(record->notification->GetGeofenceTriggerTimer());
    record->notification->SetGeofenceTriggerTimer(NotificationConstant::INVALID_TIMER_ID);
}

ErrCode AdvancedNotificationService::UpdateTriggerNotification(const sptr<NotificationRequest> &request,
    const sptr<NotificationBundleOption> &bundleOption, bool isUpdateByOwner,
    std::vector<std::shared_ptr<NotificationRecord>> &records)
{
    if (records.size() != GEOFENCE_RECORDS_SIZE_ONE) {
        return ERR_ANS_INVALID_PARAM;
    }

    auto oldRecord = records.front();
    if (oldRecord == nullptr || oldRecord->request == nullptr) {
        ANS_LOGE("oldRecord or oldRecord's request is null.");
        return ERR_ANS_INVALID_PARAM;
    }

    auto status = oldRecord->request->GetLiveViewStatus();
    if (status != NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_CREATE) {
        ANS_LOGE("Invalid live view status %{public}d", static_cast<int>(status));
        return ERR_ANS_EXPIRED_NOTIFICATION;
    }

    auto newRecord = MakeNotificationRecord(request, bundleOption);
    if (newRecord == nullptr) {
        ANS_LOGE("Make notification record failed.");
        return ERR_ANS_NO_MEMORY;
    }
    auto result = newRecord->request->CheckNotificationRequest(oldRecord->request);
    if (result != ERR_OK) {
        ANS_LOGE("Geofence notification isn't ready on publish failed with %{public}d.", result);
        return result;
    }
    newRecord->isUpdateByOwner = isUpdateByOwner;
    newRecord->request->FillMissingParameters(oldRecord->request);
    newRecord->request->SetLiveViewStatus(status);
    {
        std::lock_guard<ffrt::mutex> lock(triggerNotificationMutex_);
        for (auto it = triggerNotificationList_.begin(); it != triggerNotificationList_.end(); ++it) {
            if ((*it)->request->GetTriggerSecureKey() == oldRecord->request->GetTriggerSecureKey()) {
                *it = newRecord;
                break;
            }
        }
    }
    GeofencePublishNotificationRequestDb requestDb = { .request = newRecord->request,
        .bundleOption = newRecord->bundleOption, .isUpdateByOwner = newRecord->isUpdateByOwner };
    result = SetTriggerNotificationRequestToDb(requestDb);
    if (result != ERR_OK) {
        ANS_LOGE("SetTriggerNotificationRequestToDb failed, errCode=%{public}d", result);
        return result;
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::CheckGeofenceNotificationRequest(const sptr<NotificationRequest> &request)
{
    if (request == nullptr) {
        ANS_LOGE("null request.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    if (IsNeedPushCheck(request)) {
        result = PushCheck(request);
    }
    if (result != ERR_OK) {
        return result;
    }

    result = CheckSwitchStatus(request);
    if (result != ERR_OK) {
        return result;
    }

    return CheckGeofenceNotificationRequestLiveViewStatus(request);
}

void AdvancedNotificationService::RemoveTriggerNotificationListByTriggerKey(std::string triggerKey)
{
    std::lock_guard<ffrt::mutex> lock(triggerNotificationMutex_);
    for (auto it = triggerNotificationList_.begin(); it != triggerNotificationList_.end();) {
        if ((*it)->request->GetTriggerSecureKey() == triggerKey) {
            it = triggerNotificationList_.erase(it);
            return;
        } else {
            ++it;
        }
    }
}

ErrCode AdvancedNotificationService::CheckTriggerNotificationRequest(const sptr<NotificationRequest> &request)
{
    auto status = request->GetLiveViewStatus();
    if (request->GetNotificationTrigger() != nullptr) {
        if (status != NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_CREATE &&
            status != NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_END) {
            ANS_LOGE("Invalid live view status with trigger: %{public}d", static_cast<int>(status));
            return ERR_ANS_INVALID_PARAM;
        }
        return ERR_OK;
    }
    if (status == NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_CREATE ||
        status == NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_END) {
            ANS_LOGE("Invalid live view status with no trigger: %{public}d", static_cast<int>(status));
        return ERR_ANS_INVALID_PARAM;
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::TriggerNotificationRecordFilter(const std::shared_ptr<NotificationRecord> &record)
{
    if (record == nullptr || record->request == nullptr) {
        return ERR_ANS_INVALID_PARAM;
    }
    std::vector<std::shared_ptr<NotificationRecord>> oldRecords;
    FindGeofenceNotificationRecordByKey(record->request->GetSecureKey(), oldRecords);
    if (oldRecords.empty()) {
        return ERR_ANS_NOTIFICATION_NOT_EXISTS;
    }
    return ERR_OK;
}

void AdvancedNotificationService::ExecuteCancelGroupCancelFromTriggerNotificationList(
    const sptr<NotificationBundleOption>& bundleOption, const std::string &groupName)
{
    std::lock_guard<ffrt::mutex> lock(triggerNotificationMutex_);
    for (auto it = triggerNotificationList_.begin(); it != triggerNotificationList_.end();) {
        if (((*it)->bundleOption->GetBundleName() == bundleOption->GetBundleName()) &&
            ((*it)->bundleOption->GetUid() == bundleOption->GetUid()) &&
            ((*it)->notification->GetInstanceKey() == bundleOption->GetAppInstanceKey()) &&
            ((*it)->request->GetGroupName() == groupName)) {
            ProcForDeleteGeofenceLiveView(*it);
            it = triggerNotificationList_.erase(it);
        } else {
            ++it;
        }
    }
}

void AdvancedNotificationService::RemoveFromTriggerNotificationList(const sptr<NotificationBundleOption> &bundleOption,
    NotificationKey notificationKey)
{
    std::lock_guard<ffrt::mutex> lock(triggerNotificationMutex_);
    for (auto it = triggerNotificationList_.begin(); it != triggerNotificationList_.end();) {
        if (((*it)->bundleOption->GetBundleName() == bundleOption->GetBundleName()) &&
            ((*it)->bundleOption->GetUid() == bundleOption->GetUid()) &&
            ((*it)->notification->GetInstanceKey() == bundleOption->GetAppInstanceKey()) &&
            ((*it)->notification->GetLabel() == notificationKey.label) &&
            ((*it)->notification->GetId() == notificationKey.id)) {
            ProcForDeleteGeofenceLiveView(*it);
            it = triggerNotificationList_.erase(it);
        } else {
            ++it;
        }
    }
}

ErrCode AdvancedNotificationService::CheckSwitchStatus(const sptr<NotificationRequest> &request)
{
    bool isGeofenceEnabled = false;
    auto result = NotificationPreferences::GetInstance()->IsGeofenceEnabled(isGeofenceEnabled);
    if (result != ERR_OK) {
        ANS_LOGE("Get geofence enabled failed, errCode=%{public}d", result);
        return result;
    }
    if (!isGeofenceEnabled) {
        ANS_LOGE("The geofencing is not enabled");
        return ERR_ANS_GEOFENCE_ENABLED;
    }

    bool isSlotEnabled = false;
    result = GetEnabledForBundleSlotSelf(request->GetSlotType(), isSlotEnabled);
    if (result != ERR_OK) {
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST) {
            ANS_LOGI("GetEnabledForBundleSlotSelf, errCode=%{public}d", result);
            isSlotEnabled = true;
        } else {
            ANS_LOGE("Get slot enabled failed, errCode=%{public}d", result);
            return result;
        }
    }
    if (!isSlotEnabled) {
        ANS_LOGE("The slot is not enabled");
        return ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_ENABLED;
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::CheckGeofenceNotificationRequestLiveViewStatus(
    const sptr<NotificationRequest> &request)
{
    auto status = request->GetLiveViewStatus();
    if (status == NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_BUTT) {
        ANS_LOGE("get live view status failed.");
        return ERR_ANS_INVALID_PARAM;
    }

    std::shared_ptr<NotificationRecord> record = nullptr;
    if (status == NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_CREATE) {
        FindGeofenceNotificationRecordByTriggerKey(request->GetTriggerSecureKey(), record);
        if (record != nullptr) {
            ANS_LOGE("notification is already exists in geofence list");
            return ERR_ANS_REPEAT_CREATE;
        }

        FindNotificationRecordByKey(request->GetSecureKey(), record);
        if (record != nullptr) {
            ANS_LOGE("notification is already exists in notification list");
            return ERR_ANS_REPEAT_CREATE;
        }
        return ERR_OK;
    }

    if (status == NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_END) {
        std::vector<std::shared_ptr<NotificationRecord>> records;
        bool isExist = false;
        FindGeofenceNotificationRecordByKey(request->GetSecureKey(), records);
        if (!records.empty()) {
            isExist = true;
        }
        for (const auto &record : records) {
            if (record->request->GetLiveViewStatus() ==
                NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_END) {
                return ERR_ANS_END_NOTIFICATION;
            }
        }

        FindNotificationRecordByKey(request->GetSecureKey(), record);
        if (record != nullptr && record->request != nullptr && record->request->GetLiveViewStatus() ==
            NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END) {
            return ERR_ANS_END_NOTIFICATION;
        }
        if (record != nullptr || isExist) {
            return ERR_OK;
        }
        return ERR_ANS_NOTIFICATION_NOT_EXISTS;
    }
    return ERR_ANS_INVALID_PARAM;
}

void AdvancedNotificationService::DeleteAllByUserStoppedFromTriggerNotificationList(std::string key, int32_t userId)
{
    std::lock_guard<ffrt::mutex> lock(triggerNotificationMutex_);
    for (auto it = triggerNotificationList_.begin(); it != triggerNotificationList_.end();) {
        if (((*it)->notification->GetKey() == key) &&
            (((*it)->notification->GetRecvUserId() == userId) ||
            ((*it)->notification->GetRecvUserId() == ZERO_USER_ID))) {
            ProcForDeleteGeofenceLiveView(*it);
            it = triggerNotificationList_.erase(it);
        } else {
            ++it;
        }
    }
}

void AdvancedNotificationService::ExecuteRemoveNotificationFromTriggerNotificationList(
    const sptr<NotificationBundleOption> &bundle, int32_t notificationId, const std::string &label)
{
    std::lock_guard<ffrt::mutex> lock(triggerNotificationMutex_);
    for (auto it = triggerNotificationList_.begin(); it != triggerNotificationList_.end();) {
        if (((*it)->bundleOption->GetBundleName() == bundle->GetBundleName()) &&
            ((*it)->bundleOption->GetUid() == bundle->GetUid()) &&
            ((*it)->notification->GetId() == notificationId) && ((*it)->notification->GetLabel() == label)) {
            ProcForDeleteGeofenceLiveView(*it);
            it = triggerNotificationList_.erase(it);
        } else {
            ++it;
        }
    }
}

void AdvancedNotificationService::RemoveGroupByBundleFromTriggerNotificationList(
    const sptr<NotificationBundleOption> &bundle, const std::string &groupName)
{
    std::lock_guard<ffrt::mutex> lock(triggerNotificationMutex_);
    for (auto it = triggerNotificationList_.begin(); it != triggerNotificationList_.end();) {
        if (((*it)->bundleOption->GetBundleName() == bundle->GetBundleName()) &&
            ((*it)->bundleOption->GetUid() == bundle->GetUid()) &&
            ((*it)->request->GetGroupName() == groupName)) {
            ProcForDeleteGeofenceLiveView(*it);
            it = triggerNotificationList_.erase(it);
        } else {
            ++it;
        }
    }
}
}  // namespace Notification
}  // namespace OHOS
