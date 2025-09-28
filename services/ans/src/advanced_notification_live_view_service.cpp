/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "cpp/task.h"
#include "errors.h"
#include "ans_inner_errors.h"
#include "notification_constant.h"
#include "notification_record.h"
#include "notification_request.h"
#include "want_params_wrapper.h"
#include "notification_preferences.h"
#include "access_token_helper.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "image_source.h"
#include "os_account_manager_helper.h"
#include "time_service_client.h"
#include "notification_timer_info.h"
#include "advanced_notification_inline.h"
#include <cstdint>
#include <memory>
#include "notification_analytics_util.h"
#include "aes_gcm_helper.h"

namespace OHOS {
namespace Notification {
const std::string LOCK_SCREEN_PICTURE_TAG = "lock_screen_picture";
const std::string PROGRESS_VALUE = "progressValue";
constexpr int32_t BGTASK_UID = 3051;
constexpr int32_t TYPE_CODE_DOWNLOAD = 8;
void AdvancedNotificationService::RecoverLiveViewFromDb(int32_t userId)
{
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("notificationSvrQueue_ is nullptr.");
        return;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([=]() {
        ANS_LOGI("Start recover live view. userId:%{public}d", userId);
        std::vector<NotificationRequestDb> requestsdb;
        if (GetBatchNotificationRequestsFromDb(requestsdb, userId) != ERR_OK) {
            ANS_LOGE("Get liveView from db failed.");
            return;
        }
        ANS_LOGI("The number of live views to recover: %{public}zu.", requestsdb.size());
        std::vector<std::string> keys;
        for (const auto &requestObj : requestsdb) {
            if (!IsLiveViewCanRecover(requestObj.request)) {
                int32_t userId = requestObj.request->GetReceiverUserId();
                keys.emplace_back(requestObj.request->GetBaseKey(""));
                if (DoubleDeleteNotificationFromDb(requestObj.request->GetKey(),
                    requestObj.request->GetSecureKey(), userId) != ERR_OK) {
                    ANS_LOGE("Delete notification failed.");
                }
                continue;
            }

            auto record = std::make_shared<NotificationRecord>();
            record->isNeedFlowCtrl = false;
            if (FillNotificationRecord(requestObj, record) != ERR_OK) {
                ANS_LOGE("Fill notification record failed.");
                continue;
            }

            if (Filter(record, true) != ERR_OK) {
                ANS_LOGE("Filter record failed.");
                continue;
            }

            record->slot->SetAuthorizedStatus(NotificationSlot::AuthorizedStatus::AUTHORIZED);
            // Turn off ringtone and vibration during recovery process
            record->request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::SOUND_FLAG, false);
            record->request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::VIBRATION_FLAG, false);
            ANS_LOGD("SetFlags-Recovery,flags = %{public}d", record->request->GetFlags()->GetReminderFlags());
            if (AssignToNotificationList(record) != ERR_OK) {
                ANS_LOGE("Add notification to record list failed.");
                continue;
            }
            UpdateRecentNotification(record->notification, false, 0);

            StartFinishTimer(record, requestObj.request->GetFinishDeadLine(),
                NotificationConstant::TRIGGER_EIGHT_HOUR_REASON_DELETE);
            StartUpdateTimer(record, requestObj.request->GetUpdateDeadLine(),
                NotificationConstant::TRIGGER_FOUR_HOUR_REASON_DELETE);
        }

        if (!keys.empty()) {
            OnRecoverLiveView(keys);
        }
        // publish notifications
        for (const auto &subscriber : NotificationSubscriberManager::GetInstance()->GetSubscriberRecords()) {
            OnSubscriberAdd(subscriber, userId);
        }
        ANS_LOGI("End recover live view from db.");
    }));
}

ErrCode AdvancedNotificationService::UpdateNotificationTimerInfo(const std::shared_ptr<NotificationRecord> &record)
{
    ErrCode result = ERR_OK;

    if (!record->request->IsCommonLiveView()) {
        if ((record->request->GetAutoDeletedTime() > GetCurrentTime())) {
            StartAutoDeletedTimer(record);
        }
        return ERR_OK;
    }

    auto content = record->request->GetContent()->GetNotificationContent();
    auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(content);
    auto status = liveViewContent->GetLiveViewStatus();
    switch (status) {
        case NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE:
            result = SetFinishTimer(record);
            if (result != ERR_OK) {
                return result;
            }

            result = SetUpdateTimer(record);
            return result;
        case NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE:
        case NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE:
            // delete old, then add new
            CancelUpdateTimer(record);
            result = SetUpdateTimer(record);
            return result;

        case NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END:
            CancelUpdateTimer(record);
            CancelFinishTimer(record);
            StartArchiveTimer(record);
            break;
        default:
            ANS_LOGE("Invalid status %{public}d.", status);
            return ERR_ANS_INVALID_PARAM;
    }
    return result;
}

void AdvancedNotificationService::ProcForDeleteLiveView(const std::shared_ptr<NotificationRecord> &record)
{
    if ((record->request == nullptr) ||
        (!(record->request->IsCommonLiveView()) && !(record->request->IsSystemLiveView()))) {
        return;
    }
    int32_t userId = record->request->GetReceiverUserId();
    if (DoubleDeleteNotificationFromDb(record->request->GetKey(),
        record->request->GetSecureKey(), userId) != ERR_OK) {
        ANS_LOGE("Live View cancel, delete notification failed.");
    }

    CancelUpdateTimer(record);
    CancelFinishTimer(record);
    CancelArchiveTimer(record);
}

ErrCode AdvancedNotificationService::OnSubscriberAdd(
    const std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> &record, const int32_t userId)
{
    if (record == nullptr) {
        ANS_LOGE("No subscriber to notify.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
    std::vector<sptr<Notification>> notifications;
    for (auto notificationRecord : notificationList_) {
        if (notificationRecord != nullptr &&
            notificationRecord->notification != nullptr &&
            notificationRecord->notification->GetNotificationRequest().IsCommonLiveView()) {
            notifications.emplace_back(notificationRecord->notification);
        }
    }

    if (notifications.empty() || currentUserId.count(userId)) {
        ANS_LOGI("No notification to consume %{public}d %{public}zu.", userId, currentUserId.count(userId));
        return ERR_ANS_NOTIFICATION_NOT_EXISTS;
    }
    if (userId != INVALID_USER_ID) {
        currentUserId.insert(userId);
    }
    ANS_LOGI("Consume notification count is %{public}zu %{public}d.", notifications.size(), userId);
    NotificationSubscriberManager::GetInstance()->BatchNotifyConsumed(notifications, sortingMap, record);
    return ERR_OK;
}

bool AdvancedNotificationService::IsLiveViewCanRecover(const sptr<NotificationRequest> request)
{
    if (request == nullptr) {
        ANS_LOGE("Invalid liveview.");
        return false;
    }

    using StatusType = NotificationLiveViewContent::LiveViewStatus;
    auto liveViewContent =
        std::static_pointer_cast<NotificationLiveViewContent>(request->GetContent()->GetNotificationContent());
    auto liveViewStatus = liveViewContent->GetLiveViewStatus();
    if (liveViewStatus == StatusType::LIVE_VIEW_BUTT || liveViewStatus == StatusType::LIVE_VIEW_END) {
        ANS_LOGE("Only update or create status can reconver.");
        return false;
    }

    auto epoch = std::chrono::system_clock::now().time_since_epoch();
    auto curTime = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    if (curTime > request->GetUpdateDeadLine() || curTime > request->GetFinishDeadLine()) {
        ANS_LOGE("The liveView has expired.");
        return false;
    }

    return true;
}

int32_t AdvancedNotificationService::SetNotificationRequestToDb(const NotificationRequestDb &requestDb)
{
    auto request = requestDb.request;
    if (!request->IsCommonLiveView()) {
        ANS_LOGD("Slot type %{public}d, content type %{public}d.",
            request->GetSlotType(), request->GetNotificationType());

        return ERR_OK;
    }

    ANS_LOGD("Enter.");
    auto content = std::static_pointer_cast<NotificationLiveViewContent>(
        request->GetContent()->GetNotificationContent());
    if (request->GetOwnerUid() != DEFAULT_UID) {
        content->SetUid(request->GetOwnerUid());
    }
    if (content->GetLiveViewStatus() == NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END &&
        request->GetAutoDeletedTime() == NotificationConstant::NO_DELAY_DELETE_TIME) {
        ANS_LOGI("Don't need set to db when liveview is in end status and no delay delete time.");
        return ERR_OK;
    }

    if (content->GetIsOnlyLocalUpdate()) {
        ANS_LOGI("Not saving notification request to db for common live view with isOnlyLocalUpdate set to true.");
        return ERR_OK;
    }
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_6, EventBranchId::BRANCH_3).
        BundleName(request->GetCreatorBundleName()).NotificationId(request->GetNotificationId());
    nlohmann::json jsonObject;
    if (!NotificationJsonConverter::ConvertToJson(request, jsonObject)) {
        ANS_LOGE("Convert request to json object failed, bundle name %{public}s, id %{public}d.",
            request->GetCreatorBundleName().c_str(), request->GetNotificationId());
        NotificationAnalyticsUtil::ReportModifyEvent(message.Message("convert request failed"));
        return ERR_ANS_TASK_ERR;
    }
    auto bundleOption = requestDb.bundleOption;
    if (!NotificationJsonConverter::ConvertToJson(bundleOption, jsonObject)) {
        ANS_LOGE("Convert bundle to json object failed, bundle name %{public}s, id %{public}d.",
            bundleOption->GetBundleName().c_str(), request->GetNotificationId());
        NotificationAnalyticsUtil::ReportModifyEvent(message.Message("convert option failed"));
        return ERR_ANS_TASK_ERR;
    }
    
    std::string encryptValue;
    ErrCode errorCode = AesGcmHelper::Encrypt(jsonObject.dump(), encryptValue);
    if (errorCode != ERR_OK) {
        ANS_LOGE("SetNotificationRequestToDb encrypt error");
        return static_cast<int>(errorCode);
    }
    auto result = NotificationPreferences::GetInstance()->SetKvToDb(
        request->GetSecureKey(), encryptValue, request->GetReceiverUserId());
    if (result != ERR_OK) {
        ANS_LOGE("Set failed, bundle name %{public}s, id %{public}d, key %{public}s, ret %{public}d.",
            request->GetCreatorBundleName().c_str(), request->GetNotificationId(), request->GetKey().c_str(), result);
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(result).Message("set failed"));
        return result;
    } else {
        DeleteNotificationRequestFromDb(request->GetKey(), request->GetReceiverUserId());
    }

    result = SetLockScreenPictureToDb(request);
    if (result != ERR_OK) {
        ANS_LOGE("Failed to set lock screen picture to db");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(result).Message("SetToDb failed"));
    }
    return result;
}

int32_t AdvancedNotificationService::GetBatchNotificationRequestsFromDb(
    std::vector<NotificationRequestDb> &requests, int32_t userId)
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
            NotificationPreferences::GetInstance()->GetBatchKvsFromDb(REQUEST_STORAGE_KEY_PREFIX, dbRecords, userId);
        int32_t secureResult =
            NotificationPreferences::GetInstance()->GetBatchKvsFromDb(
                REQUEST_STORAGE_SECURE_KEY_PREFIX, dbRecords, userId);
        if (result != ERR_OK && secureResult != ERR_OK) {
            ANS_LOGE("Get batch notification request failed.");
            return result;
        }
    }
    for (const auto &iter : dbRecords) {
        std::string decryptValue = iter.second;
        if (iter.first.rfind(REQUEST_STORAGE_SECURE_KEY_PREFIX, 0) == 0) {
            ErrCode errorCode = AesGcmHelper::Decrypt(decryptValue, iter.second);
            if (errorCode != ERR_OK) {
                ANS_LOGE("GetBatchNotificationRequestsFromDb decrypt error");
                return static_cast<int>(errorCode);
            }
        }
        if (decryptValue.empty() || !nlohmann::json::accept(decryptValue)) {
            ANS_LOGE("Invalid json");
            continue;
        }
        auto jsonObject = nlohmann::json::parse(decryptValue);
        auto *request = NotificationJsonConverter::ConvertFromJson<NotificationRequest>(jsonObject);
        if (request == nullptr) {
            ANS_LOGE("Parse json string to request failed.");
            continue;
        }
        auto *bundleOption = NotificationJsonConverter::ConvertFromJson<NotificationBundleOption>(jsonObject);
        if (bundleOption == nullptr) {
            ANS_LOGE("Parse json string to bundle option failed.");
            (void)DoubleDeleteNotificationFromDb(request->GetKey(),
                request->GetSecureKey(), request->GetReceiverUserId());
            continue;
        }

        if (GetLockScreenPictureFromDb(request) != ERR_OK) {
            ANS_LOGE("Get request lock screen picture failed.");
        }
        NotificationRequestDb requestDb = { .request = request, .bundleOption = bundleOption };
        requests.emplace_back(requestDb);
    }
    return ERR_OK;
}


int32_t AdvancedNotificationService::DoubleDeleteNotificationFromDb(const std::string &key,
    const std::string &secureKey, const int32_t userId)
{
    auto result = NotificationPreferences::GetInstance()->DeleteKvFromDb(secureKey, userId);
    if (result != ERR_OK) {
        ANS_LOGE("Delete notification request failed, key %{public}s.", key.c_str());
        return result;
    }
    result = DeleteNotificationRequestFromDb(key, userId);
    return result;
}

int32_t AdvancedNotificationService::DeleteNotificationRequestFromDb(const std::string &key, const int32_t userId)
{
    auto result = NotificationPreferences::GetInstance()->DeleteKvFromDb(key, userId);
    if (result != ERR_OK) {
        ANS_LOGE("Delete notification request failed, key %{public}s.", key.c_str());
        return result;
    }

    std::string lockScreenPictureKey = LOCK_SCREEN_PICTURE_TAG + key;
    result = NotificationPreferences::GetInstance()->DeleteKvFromDb(lockScreenPictureKey, userId);
    if (result != ERR_OK) {
        ANS_LOGE("Delete notification lock screen picture failed, key %{public}s.", lockScreenPictureKey.c_str());
        return result;
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::IsAllowedRemoveSlot(const sptr<NotificationBundleOption> &bundleOption,
    const NotificationConstant::SlotType &slotType)
{
    if (slotType != NotificationConstant::SlotType::LIVE_VIEW) {
        return ERR_OK;
    }

    sptr<NotificationSlot> slot;
    if (NotificationPreferences::GetInstance()->GetNotificationSlot(bundleOption, slotType, slot) != ERR_OK) {
        ANS_LOGE("Failed to get slot.");
        return ERR_OK;
    }

    if (!slot->GetForceControl()) {
        ANS_LOGI("Liveview slot is not force control.");
        return ERR_OK;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("Only sa or systemapp can remove liveview slot.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    return ERR_OK;
}

void AdvancedNotificationService::FillLockScreenPicture(const sptr<NotificationRequest> &newRequest,
    const sptr<NotificationRequest> &oldRequest)
{
    if (oldRequest->GetContent() == nullptr ||
        newRequest->GetContent() == nullptr) {
        return;
    }
    if (oldRequest->GetContent()->GetNotificationContent() == nullptr ||
        newRequest->GetContent()->GetNotificationContent() == nullptr) {
        return;
    }
    if (newRequest->GetSlotType() != NotificationConstant::SlotType::LIVE_VIEW) {
        return;
    }

    auto oldContent = oldRequest->GetContent()->GetNotificationContent();
    auto newContent = newRequest->GetContent()->GetNotificationContent();
    if (newContent->GetLockScreenPicture() == nullptr) {
        newContent->SetLockScreenPicture(oldContent->GetLockScreenPicture());
    }
}

ErrCode AdvancedNotificationService::SetLockScreenPictureToDb(const sptr<NotificationRequest> &request)
{
    auto lockScreenPicture = request->GetContent()->GetNotificationContent()->GetLockScreenPicture();
    if (!request->IsCommonLiveView() || lockScreenPicture == nullptr) {
        return ERR_OK;
    }

    auto size = static_cast<size_t>(lockScreenPicture->GetCapacity());
    auto pixels = lockScreenPicture->GetPixels();
    std::vector<uint8_t> pixelsVec(pixels, pixels + size);

    std::string key = LOCK_SCREEN_PICTURE_TAG + request->GetKey();
    auto res = NotificationPreferences::GetInstance()->SetByteToDb(key, pixelsVec, request->GetReceiverUserId());
    if (res != ERR_OK) {
        ANS_LOGE("Failed to set lock screen picture to db, res is %{public}d.", res);
        return res;
    }

    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetLockScreenPictureFromDb(NotificationRequest *request)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_12, EventBranchId::BRANCH_0);
    if (request == nullptr) {
        ANS_LOGE("Request is nullptr");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_INVALID_PARAM));
        return ERR_ANS_INVALID_PARAM;
    }
    std::string key = LOCK_SCREEN_PICTURE_TAG + request->GetKey();
    std::vector<uint8_t> pixelsVec;
    uint32_t res = NotificationPreferences::GetInstance()->GetByteFromDb(key, pixelsVec, request->GetReceiverUserId());
    if (res != ERR_OK) {
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(res).BranchId(BRANCH_1));
        ANS_LOGE("Failed to get lock screen picture from db, res is %{public}d.", res);
        return res;
    }

    Media::SourceOptions sourceOptions;
    auto imageSource = Media::ImageSource::CreateImageSource((const uint8_t *)pixelsVec.data(), pixelsVec.size(),
        sourceOptions, res);
    if (res != ERR_OK) {
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(res).BranchId(BRANCH_2));
        ANS_LOGE("Failed to create image source, res is %{public}d.", res);
        return res;
    }

    Media::DecodeOptions decodeOpts;
    auto pixelMapPtr = imageSource->CreatePixelMap(decodeOpts, res);
    if (res != ERR_OK) {
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(res).BranchId(BRANCH_3));
        ANS_LOGE("Failed to create pixel map, res is %{public}d.", res);
        return res;
    }

    std::shared_ptr<Media::PixelMap> picture = std::shared_ptr<Media::PixelMap>(pixelMapPtr.release());
    request->GetContent()->GetNotificationContent()->SetLockScreenPicture(picture);

    return ERR_OK;
}

void AdvancedNotificationService::UpdateInDelayNotificationList(const std::shared_ptr<NotificationRecord> &record)
{
    std::lock_guard<ffrt::mutex> lock(delayNotificationMutext_);
    auto iter = delayNotificationList_.begin();
    while (iter != delayNotificationList_.end()) {
        if ((*iter).first->notification->GetKey() == record->notification->GetKey()) {
            CancelTimer((*iter).second);
            (*iter).first = record;
            auto request = record->notification->GetNotificationRequest();
            (*iter).second = StartDelayPublishTimer(request.GetOwnerUid(),
                request.GetNotificationId(), request.GetPublishDelayTime());
            break;
        }
        iter++;
    }
}

void AdvancedNotificationService::AddToDelayNotificationList(const std::shared_ptr<NotificationRecord> &record)
{
    std::lock_guard<ffrt::mutex> lock(delayNotificationMutext_);
    auto request = record->notification->GetNotificationRequest();
    auto timerId = StartDelayPublishTimer(
        request.GetOwnerUid(), request.GetNotificationId(), request.GetPublishDelayTime());
    delayNotificationList_.emplace_back(std::make_pair(record, timerId));
}

ErrCode AdvancedNotificationService::SaPublishSystemLiveViewAsBundle(const std::shared_ptr<NotificationRecord> &record)
{
    uint32_t delayTime = record->notification->GetNotificationRequest().GetPublishDelayTime();
    if (delayTime == 0) {
        return StartPublishDelayedNotification(record);
    }

    if (IsNotificationExistsInDelayList(record->notification->GetKey())) {
        UpdateInDelayNotificationList(record);
        return ERR_OK;
    }

    AddToDelayNotificationList(record);
    return ERR_OK;
}

bool AdvancedNotificationService::IsNotificationExistsInDelayList(const std::string &key)
{
    std::lock_guard<ffrt::mutex> lock(delayNotificationMutext_);
    for (auto delayNotification : delayNotificationList_) {
        if (delayNotification.first->notification->GetKey() == key) {
            return true;
        }
    }

    return false;
}

uint64_t AdvancedNotificationService::StartDelayPublishTimer(
    const int32_t ownerUid, const int32_t notificationId, const uint32_t delayTime)
{
    ANS_LOGD("Enter");

    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_12, EventBranchId::BRANCH_4);
    wptr<AdvancedNotificationService> wThis = this;
    auto timeoutFunc = [wThis, ownerUid, notificationId] {
        sptr<AdvancedNotificationService> sThis = wThis.promote();
        if (sThis != nullptr) {
            sThis->StartPublishDelayedNotificationTimeOut(ownerUid, notificationId);
        }
    };
    std::shared_ptr<NotificationTimerInfo> notificationTimerInfo = std::make_shared<NotificationTimerInfo>();
    notificationTimerInfo->SetCallbackInfo(timeoutFunc);

    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANS_LOGE("Failed to start timer due to get TimeServiceClient is null.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(NotificationConstant::INVALID_TIMER_ID));
        return NotificationConstant::INVALID_TIMER_ID;
    }

    uint64_t timerId = timer->CreateTimer(notificationTimerInfo);
    int64_t delayPublishPoint = GetCurrentTime() + delayTime * NotificationConstant::SECOND_TO_MS;
    timer->StartTimer(timerId, delayPublishPoint);
    return timerId;
}

void AdvancedNotificationService::StartPublishDelayedNotificationTimeOut(
    const int32_t ownerUid, const int32_t notificationId)
{
    auto record = GetFromDelayedNotificationList(ownerUid, notificationId);
    if (record == nullptr) {
        ANS_LOGE("Failed to get delayed notification from list.");
        return;
    }

    int ret = StartPublishDelayedNotification(record);
    if (ret != ERR_OK) {
        ANS_LOGE("Failed to StartPublishDelayedNotification, ret is %{public}d", ret);
        return;
    }
}

ErrCode AdvancedNotificationService::StartPublishDelayedNotification(const std::shared_ptr<NotificationRecord> &record)
{
    RemoveFromDelayedNotificationList(record->notification->GetKey());
    ErrCode result = AssignToNotificationList(record);
    if (result != ERR_OK) {
        ANS_LOGE("Failed to assign notification list");
        return result;
    }

    UpdateRecentNotification(record->notification, false, 0);
    NotificationSubscriberManager::GetInstance()->NotifyConsumed(record->notification, GenerateSortingMap());
    if ((record->request->GetAutoDeletedTime() > GetCurrentTime())) {
        StartAutoDeletedTimer(record);
    }

    record->finish_status = UploadStatus::FIRST_UPDATE_TIME_OUT;
    StartFinishTimer(record, GetCurrentTime() + NotificationConstant::TEN_MINUTES,
        NotificationConstant::TRIGGER_TEN_MINUTES_REASON_DELETE);

    return ERR_OK;
}

bool AdvancedNotificationService::IsUpdateSystemLiveviewByOwner(const sptr<NotificationRequest> &request)
{
    if (!request->IsSystemLiveView()) {
        return false;
    }

    auto ownerUid = IPCSkeleton::GetCallingUid();
    auto oldRecord = GetFromDelayedNotificationList(ownerUid, request->GetNotificationId());
    if (oldRecord != nullptr) {
        return true;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return false;
    }

    ffrt::task_handle handler = notificationSvrQueue_->submit_h([&]() {
        oldRecord = GetFromNotificationList(ownerUid, request->GetNotificationId());
    });
    notificationSvrQueue_->wait(handler);

    return oldRecord != nullptr;
}

bool AdvancedNotificationService::IsSaCreateSystemLiveViewAsBundle(
    const std::shared_ptr<NotificationRecord> &record, int32_t ipcUid)
{
    if (record == nullptr) {
        ANS_LOGE("Invalid record.");
        return false;
    }

    auto request = record->notification->GetNotificationRequest();
    if (!request.IsSystemLiveView()) {
        return false;
    }

    if (request.GetCreatorUid() == ipcUid &&
        request.GetCreatorUid() != request.GetOwnerUid() &&
        !IsNotificationExists(record->notification->GetKey())) {
        return true;
    }

    return false;
}

void AdvancedNotificationService::UpdateRecordByOwner(
    const std::shared_ptr<NotificationRecord> &record, bool isSystemApp)
{
    auto creatorUid = record->notification->GetNotificationRequest().GetCreatorUid();
    auto notificationId =  record->notification->GetNotificationRequest().GetNotificationId();
    auto oldRecord = GetFromDelayedNotificationList(creatorUid, notificationId);
    if (oldRecord == nullptr) {
        oldRecord = GetFromNotificationList(creatorUid, notificationId);
    }
    if (oldRecord == nullptr) {
        return;
    }
    auto downloadTemplate = record->notification->GetNotificationRequest().GetTemplate();
    auto content = record->notification->GetNotificationRequest().GetContent();
    auto wantAgent = record->notification->GetNotificationRequest().GetWantAgent();
    record->request = new (std::nothrow) NotificationRequest(*(oldRecord->request));
    if (record->request == nullptr) {
        ANS_LOGE("request is nullptr.");
        return;
    }
    if (wantAgent != nullptr) {
        record->request->SetWantAgent(wantAgent);
    }
    uint64_t timerId = 0;
    uint64_t process = NotificationConstant::DEFAULT_FINISH_STATUS;
    CancelTimer(oldRecord->notification->GetFinishTimer());
    if (isSystemApp) {
        record->request->SetContent(content);
    } else {
        record->request->SetTemplate(downloadTemplate);
        auto data = downloadTemplate->GetTemplateData();
        AAFwk::WantParamWrapper wrapper(*data);
        ANS_LOGD("Update the template data: %{public}s.", wrapper.ToString().c_str());
        if (data->HasParam(PROGRESS_VALUE)) {
            process = data->GetIntParam(PROGRESS_VALUE, 0);
        }
    }
    StartFinishTimerForUpdate(record, process);
    timerId = record->notification->GetFinishTimer();
    ANS_LOGI("TimerForUpdate,oldTimeId: %{public}" PRIu64 ", newTimeId: %{public}" PRIu64 "",
        oldRecord->notification->GetFinishTimer(), timerId);
    record->notification = new (std::nothrow) Notification(record->request);
    if (record->notification == nullptr) {
        ANS_LOGE("Failed to create notification.");
        return;
    }
    record->bundleOption = oldRecord->bundleOption;
    record->notification->SetFinishTimer(timerId);
}

void AdvancedNotificationService::StartFinishTimerForUpdate(
    const std::shared_ptr<NotificationRecord> &record, uint64_t process)
{
    if (process == NotificationConstant::FINISH_PER) {
        record->finish_status = UploadStatus::FINISH;
        StartFinishTimer(record, GetCurrentTime() + NotificationConstant::THIRTY_MINUTES,
            NotificationConstant::TRIGGER_FIFTEEN_MINUTES_REASON_DELETE);
    } else {
        record->finish_status = UploadStatus::CONTINUOUS_UPDATE_TIME_OUT;
        StartFinishTimer(record, GetCurrentTime() + NotificationConstant::FIFTEEN_MINUTES,
            NotificationConstant::TRIGGER_THIRTY_MINUTES_REASON_DELETE);
    }
}

void AdvancedNotificationService::HandleUpdateLiveViewNotificationTimer(const int32_t uid, const bool isPaused)
{
    for (const auto &record : notificationList_) {
        const auto &request = record->request;
        if (!request || request->GetOwnerUid() != uid) {
            continue;
        }
        if (!request->GetContent() || !request->GetContent()->GetNotificationContent()) {
            continue;
        }
        bool isContinuousLiveView = request->IsSystemLiveView() && request->GetCreatorUid() == BGTASK_UID;
        if (!isContinuousLiveView) {
            continue;
        }
        const auto &liveViewContent = std::static_pointer_cast<NotificationLocalLiveViewContent>(
            request->GetContent()->GetNotificationContent());
        if (liveViewContent->GetType() == TYPE_CODE_DOWNLOAD) {
            if (isPaused) {
                ANS_LOGI("liveview notification timer is being cancelled, uid: %{public}d", uid);
                CancelTimer(record->notification->GetFinishTimer());
            } else {
                ANS_LOGI("liveview notification timer is being reset, uid: %{public}d", uid);
                StartFinishTimer(record, GetCurrentTime() + NotificationConstant::FIFTEEN_MINUTES,
                    NotificationConstant::TRIGGER_THIRTY_MINUTES_REASON_DELETE);
            }
        }
    }
}
}
}
