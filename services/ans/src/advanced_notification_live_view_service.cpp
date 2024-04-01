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

#include "errors.h"
#include "ans_inner_errors.h"
#include "notification_record.h"
#include "notification_request.h"
#include "want_params_wrapper.h"
#include "notification_preferences.h"
#include "access_token_helper.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "image_source.h"
#include <memory>

namespace OHOS {
namespace Notification {
const std::string LOCK_SCREEN_PICTURE_TAG = "lock_screen_picture";
void AdvancedNotificationService::RecoverLiveViewFromDb()
{
    ANS_LOGI("Start recover live view from db.");

    std::vector<NotificationRequestDb> requestsdb;
    if (GetBatchNotificationRequestsFromDb(requestsdb) != ERR_OK) {
        ANS_LOGE("Get liveView from db failed.");
        return;
    }

    for (const auto &requestObj : requestsdb) {
        ANS_LOGD("Recover request: %{public}s.", requestObj.request->Dump().c_str());
        if (!IsLiveViewCanRecover(requestObj.request)) {
            if (DeleteNotificationRequestFromDb(requestObj.request->GetKey()) != ERR_OK) {
                ANS_LOGE("Delete notification failed.");
            }
            continue;
        }

        auto record = std::make_shared<NotificationRecord>();
        if (FillNotificationRecord(requestObj, record) != ERR_OK) {
            ANS_LOGE("Fill notification record failed.");
            continue;
        }

        if (Filter(record, true) != ERR_OK) {
            ANS_LOGE("Filter record failed.");
            continue;
        }

        if (FlowControl(record) != ERR_OK) {
            ANS_LOGE("Flow control failed.");
            continue;
        }

        if (AssignToNotificationList(record) != ERR_OK) {
            ANS_LOGE("Add notification to record list failed.");
            continue;
        }
        UpdateRecentNotification(record->notification, false, 0);

        StartFinishTimer(record, requestObj.request->GetFinishDeadLine());
        StartUpdateTimer(record, requestObj.request->GetUpdateDeadLine());
    }

    // publish notifications
    for (const auto &subscriber : NotificationSubscriberManager::GetInstance()->GetSubscriberRecords()) {
        OnSubscriberAdd(subscriber);
    }

    ANS_LOGI("End recover live view from db.");
}

ErrCode AdvancedNotificationService::UpdateNotificationTimerInfo(const std::shared_ptr<NotificationRecord> &record)
{
    ErrCode result = ERR_OK;

    if (!record->request->IsCommonLiveView()) {
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
    if ((record->request == nullptr) || !(record->request->IsCommonLiveView())) {
        return;
    }

    if (DeleteNotificationRequestFromDb(record->request->GetKey()) != ERR_OK) {
        ANS_LOGE("Live View cancel, delete notification failed.");
    }

    CancelUpdateTimer(record);
    CancelFinishTimer(record);
    CancelArchiveTimer(record);
}

void AdvancedNotificationService::OnSubscriberAdd(
    const std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> &record)
{
    if (record == nullptr) {
        ANS_LOGE("No subscriber to notify.");
        return;
    }

    sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
    std::vector<sptr<Notification>> notifications;
    for (auto notificationRecord : notificationList_) {
        if (notificationRecord->notification != nullptr &&
            notificationRecord->notification->GetNotificationRequest().IsCommonLiveView()) {
            notifications.emplace_back(notificationRecord->notification);
        }
    }

    if (notifications.empty()) {
        ANS_LOGI("No notification to consume.");
        return;
    }

    ANS_LOGI("Consume notification count is %{public}zu.", notifications.size());
    NotificationSubscriberManager::GetInstance()->BatchNotifyConsumed(notifications, sortingMap, record);
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

    ANS_LOGI("Enter.");
    auto content = std::static_pointer_cast<NotificationLiveViewContent>(
        request->GetContent()->GetNotificationContent());
    if (content->GetLiveViewStatus() == NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END &&
        request->GetAutoDeletedTime() == NotificationConstant::NO_DELAY_DELETE_TIME) {
        ANS_LOGI("Don't need set to db when liveview is in end status and no delay delete time.");
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

    auto result = NotificationPreferences::GetInstance().SetKvToDb(request->GetKey(), jsonObject.dump());
    if (result != ERR_OK) {
        ANS_LOGE(
            "Set notification request failed, bundle name %{public}s, id %{public}d, key %{public}s, ret %{public}d.",
            request->GetCreatorBundleName().c_str(), request->GetNotificationId(), request->GetKey().c_str(), result);
        return result;
    }

    result = SetLockScreenPictureToDb(request);
    if (result != ERR_OK) {
        ANS_LOGE("Failed to set lock screen picture to db");
        return result;
    }
    return ERR_OK;
}

int32_t AdvancedNotificationService::GetNotificationRequestFromDb(
    const std::string &key, NotificationRequestDb &requestDb)
{
    std::string value;
    int32_t result = NotificationPreferences::GetInstance().GetKvFromDb(key, value);
    if (result != ERR_OK) {
        ANS_LOGE("Get notification request failed, key %{public}s.", key.c_str());
        return result;
    }
    auto jsonObject = nlohmann::json::parse(value);
    auto *request = NotificationJsonConverter::ConvertFromJson<NotificationRequest>(jsonObject);
    if (request == nullptr) {
        ANS_LOGE("Parse json string to request failed, str: %{public}s.", value.c_str());
        return ERR_ANS_TASK_ERR;
    }
    auto *bundleOption = NotificationJsonConverter::ConvertFromJson<NotificationBundleOption>(jsonObject);
    if (bundleOption == nullptr) {
        ANS_LOGE("Parse json string to bundle option failed, str: %{public}s.", value.c_str());
        return ERR_ANS_TASK_ERR;
    }

    if (GetLockScreenPictureFromDb(request) != ERR_OK) {
        ANS_LOGE("Get request lock screen picture failed, key %{public}s.", key.c_str());
        return ERR_ANS_TASK_ERR;
    }
    requestDb.request = request;
    requestDb.bundleOption = bundleOption;
    return ERR_OK;
}

int32_t AdvancedNotificationService::GetBatchNotificationRequestsFromDb(std::vector<NotificationRequestDb> &requests)
{
    std::unordered_map<std::string, std::string> dbRecords;
    int32_t result =
        NotificationPreferences::GetInstance().GetBatchKvsFromDb(REQUEST_STORAGE_KEY_PREFIX, dbRecords);
    if (result != ERR_OK) {
        ANS_LOGE("Get batch notification request failed.");
        return result;
    }
    for (const auto &iter : dbRecords) {
        auto jsonObject = nlohmann::json::parse(iter.second);
        auto *request = NotificationJsonConverter::ConvertFromJson<NotificationRequest>(jsonObject);
        if (request == nullptr) {
            ANS_LOGE("Parse json string to request failed.");
            continue;
        }
        auto *bundleOption = NotificationJsonConverter::ConvertFromJson<NotificationBundleOption>(jsonObject);
        if (bundleOption == nullptr) {
            ANS_LOGE("Parse json string to bundle option failed.");
            (void)DeleteNotificationRequestFromDb(request->GetKey());
            continue;
        }

        if (GetLockScreenPictureFromDb(request) != ERR_OK) {
            ANS_LOGE("Get request lock screen picture failed.");
            continue;
        }
        NotificationRequestDb requestDb = { .request = request, .bundleOption = bundleOption };
        requests.emplace_back(requestDb);
    }
    return ERR_OK;
}

int32_t AdvancedNotificationService::DeleteNotificationRequestFromDb(const std::string &key)
{
    auto result = NotificationPreferences::GetInstance().DeleteKvFromDb(key);
    if (result != ERR_OK) {
        ANS_LOGE("Delete notification request failed, key %{public}s.", key.c_str());
        return result;
    }

    std::string lockScreenPictureKey = LOCK_SCREEN_PICTURE_TAG + key;
    result = NotificationPreferences::GetInstance().DeleteKvFromDb(lockScreenPictureKey);
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
    if (NotificationPreferences::GetInstance().GetNotificationSlot(bundleOption, slotType, slot) != ERR_OK) {
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
    auto res = NotificationPreferences::GetInstance().SetByteToDb(key, pixelsVec);
    if (res != ERR_OK) {
        ANS_LOGE("Failed to set lock screen picture to db, res is %{public}d.", res);
        return res;
    }

    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetLockScreenPictureFromDb(NotificationRequest *request)
{
    std::string key = LOCK_SCREEN_PICTURE_TAG + request->GetKey();
    std::vector<uint8_t> pixelsVec;
    uint32_t res = NotificationPreferences::GetInstance().GetByteFromDb(key, pixelsVec);
    if (res != ERR_OK) {
        ANS_LOGE("Failed to get lock screen picture from db, res is %{public}d.", res);
        return res;
    }

    Media::SourceOptions sourceOptions;
    auto imageSource = Media::ImageSource::CreateImageSource((const uint8_t *)pixelsVec.data(), pixelsVec.size(),
        sourceOptions, res);
    if (res != ERR_OK) {
        ANS_LOGE("Failed to create image source, res is %{public}d.", res);
        return res;
    }

    Media::DecodeOptions decodeOpts;
    auto pixelMapPtr = imageSource->CreatePixelMap(decodeOpts, res);
    if (res != ERR_OK) {
        ANS_LOGE("Failed to create pixel map, res is %{public}d.", res);
        return res;
    }

    std::shared_ptr<Media::PixelMap> picture = std::shared_ptr<Media::PixelMap>(pixelMapPtr.release());
    request->GetContent()->GetNotificationContent()->SetLockScreenPicture(picture);

    return ERR_OK;
}
}
}
