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

#include "notification_request.h"

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_image_util.h"
#include "ans_log_wrapper.h"
#include "errors.h"
#include "notification_live_view_content.h"
#include "refbase.h"
#include "want_agent_helper.h"
#include "want_params_wrapper.h"
#include "notification_action_button.h"
#include <memory>

namespace OHOS {
namespace Notification {
const std::string NotificationRequest::CLASSIFICATION_ALARM {"alarm"};
const std::string NotificationRequest::CLASSIFICATION_CALL {"call"};
const std::string NotificationRequest::CLASSIFICATION_EMAIL {"email"};
const std::string NotificationRequest::CLASSIFICATION_ERROR {"err"};
const std::string NotificationRequest::CLASSIFICATION_EVENT {"event"};
const std::string NotificationRequest::CLASSIFICATION_MESSAGE {"msg"};
const std::string NotificationRequest::CLASSIFICATION_NAVIGATION {"navigation"};
const std::string NotificationRequest::CLASSIFICATION_PROGRESS {"progress"};
const std::string NotificationRequest::CLASSIFICATION_PROMO {"promo"};
const std::string NotificationRequest::CLASSIFICATION_RECOMMENDATION {"recommendation"};
const std::string NotificationRequest::CLASSIFICATION_REMINDER {"reminder"};
const std::string NotificationRequest::CLASSIFICATION_SERVICE {"service"};
const std::string NotificationRequest::CLASSIFICATION_SOCIAL {"social"};
const std::string NotificationRequest::CLASSIFICATION_STATUS {"status"};
const std::string NotificationRequest::CLASSIFICATION_SYSTEM {"sys"};
const std::string NotificationRequest::CLASSIFICATION_TRANSPORT {"transport"};

const uint32_t NotificationRequest::COLOR_DEFAULT {0};

const uint32_t NotificationRequest::COLOR_MASK {0xFF000000};
const std::size_t NotificationRequest::MAX_USER_INPUT_HISTORY {5};
const std::size_t NotificationRequest::MAX_ACTION_BUTTONS {3};
const std::size_t NotificationRequest::MAX_MESSAGE_USERS {1000};

constexpr int32_t MAX_MAP_SIZE = 1000;

NotificationRequest::NotificationRequest(int32_t notificationId) : notificationId_(notificationId)
{
    createTime_ = GetNowSysTime();
    deliveryTime_ = GetNowSysTime();
}

NotificationRequest::NotificationRequest(const NotificationRequest &other)
{
    CopyBase(other);
    CopyOther(other);
}

NotificationRequest &NotificationRequest::operator=(const NotificationRequest &other)
{
    CopyBase(other);
    CopyOther(other);

    return *this;
}

NotificationRequest::~NotificationRequest()
{}

bool NotificationRequest::IsInProgress() const
{
    return inProgress_;
}

void NotificationRequest::SetInProgress(bool isOngoing)
{
    inProgress_ = isOngoing;
}

bool NotificationRequest::IsUnremovable() const
{
    return unremovable_;
}

void NotificationRequest::SetUnremovable(bool isUnremovable)
{
    unremovable_ = isUnremovable;
}

void NotificationRequest::SetBadgeNumber(uint32_t number)
{
    badgeNumber_ = number;
}

uint32_t NotificationRequest::GetBadgeNumber() const
{
    return badgeNumber_;
}

void NotificationRequest::SetNotificationControlFlags(uint32_t notificationControlFlags)
{
    notificationControlFlags_ = notificationControlFlags;
}

uint32_t NotificationRequest::GetNotificationControlFlags() const
{
    return notificationControlFlags_;
}

void NotificationRequest::SetNotificationId(int32_t notificationId)
{
    notificationId_ = notificationId;
}

int32_t NotificationRequest::GetNotificationId() const
{
    return notificationId_;
}

void NotificationRequest::SetWantAgent(const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> &wantAgent)
{
    wantAgent_ = wantAgent;
}

const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> NotificationRequest::GetWantAgent() const
{
    return wantAgent_;
}

void NotificationRequest::SetRemovalWantAgent(const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> &wantAgent)
{
    removalWantAgent_ = wantAgent;
}

const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> NotificationRequest::GetRemovalWantAgent() const
{
    return removalWantAgent_;
}

void NotificationRequest::SetMaxScreenWantAgent(const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> &wantAgent)
{
    maxScreenWantAgent_ = wantAgent;
}

const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> NotificationRequest::GetMaxScreenWantAgent() const
{
    return maxScreenWantAgent_;
}

void NotificationRequest::SetAdditionalData(const std::shared_ptr<AAFwk::WantParams> &extras)
{
    additionalParams_ = extras;
}

const std::shared_ptr<AAFwk::WantParams> NotificationRequest::GetAdditionalData() const
{
    return additionalParams_;
}

void NotificationRequest::SetDeliveryTime(int64_t deliveryTime)
{
    deliveryTime_ = deliveryTime;
}

int64_t NotificationRequest::GetDeliveryTime() const
{
    return deliveryTime_;
}

bool NotificationRequest::IsShowDeliveryTime() const
{
    return (deliveryTime_ != 0) && showDeliveryTime_;
}

void NotificationRequest::SetShowDeliveryTime(bool showDeliveryTime)
{
    showDeliveryTime_ = showDeliveryTime;
}

void NotificationRequest::AddActionButton(const std::shared_ptr<NotificationActionButton> &actionButton)
{
    if (!actionButton) {
        ANS_LOGW("actionButton can not be null");
        return;
    }

    if (actionButtons_.size() >= NotificationRequest::MAX_ACTION_BUTTONS) {
        ANS_LOGW("three action buttons have been already added");
        return;
    }

    actionButtons_.emplace_back(actionButton);
}

const std::vector<std::shared_ptr<NotificationActionButton>> NotificationRequest::GetActionButtons() const
{
    return actionButtons_;
}

void NotificationRequest::ClearActionButtons()
{
    actionButtons_.clear();
}

bool NotificationRequest::IsPermitSystemGeneratedContextualActionButtons() const
{
    return permitted_;
}

void NotificationRequest::SetPermitSystemGeneratedContextualActionButtons(bool permitted)
{
    permitted_ = permitted;
}

bool NotificationRequest::IsAgentNotification() const
{
    return isAgent_;
}

void NotificationRequest::SetIsAgentNotification(bool isAgent)
{
    isAgent_ = isAgent;
}

void NotificationRequest::AddMessageUser(const std::shared_ptr<MessageUser> &messageUser)
{
    if (!messageUser) {
        ANS_LOGI("messageUser can not be null");
        return;
    }

    messageUsers_.emplace_back(messageUser);
}

const std::vector<std::shared_ptr<MessageUser>> NotificationRequest::GetMessageUsers() const
{
    return messageUsers_;
}

bool NotificationRequest::IsAlertOneTime() const
{
    return alertOneTime_;
}

void NotificationRequest::SetAlertOneTime(bool isAlertOnce)
{
    alertOneTime_ = isAlertOnce;
}

void NotificationRequest::SetAutoDeletedTime(int64_t deletedTime)
{
    autoDeletedTime_ = deletedTime;
}

int64_t NotificationRequest::GetAutoDeletedTime() const
{
    return autoDeletedTime_;
}

void NotificationRequest::SetUpdateDeadLine(int64_t updateDeadLine)
{
    updateDeadLine_ = updateDeadLine;
}

int64_t NotificationRequest::GetUpdateDeadLine() const
{
    return updateDeadLine_;
}

void NotificationRequest::SetFinishDeadLine(int64_t finishDeadLine)
{
    finishDeadLine_ = finishDeadLine;
}

int64_t NotificationRequest::GetFinishDeadLine() const
{
    return finishDeadLine_;
}

void NotificationRequest::SetArchiveDeadLine(int64_t archiveDeadLine)
{
    archiveDeadLine_ = archiveDeadLine;
}

int64_t NotificationRequest::GetArchiveDeadLine() const
{
    return archiveDeadLine_;
}

void NotificationRequest::SetLittleIcon(const std::shared_ptr<Media::PixelMap> &littleIcon)
{
    littleIcon_ = littleIcon;
}

const std::shared_ptr<Media::PixelMap> NotificationRequest::GetLittleIcon() const
{
    return littleIcon_;
}

void NotificationRequest::SetBigIcon(const std::shared_ptr<Media::PixelMap> &bigIcon)
{
    bigIcon_ = bigIcon;
}

void NotificationRequest::ResetBigIcon() const
{
    bigIcon_ = nullptr;
}

const std::shared_ptr<Media::PixelMap> NotificationRequest::GetBigIcon() const
{
    return bigIcon_;
}

void NotificationRequest::SetOverlayIcon(const std::shared_ptr<Media::PixelMap> &overlayIcon)
{
    overlayIcon_ = overlayIcon;
}

const std::shared_ptr<Media::PixelMap> NotificationRequest::GetOverlayIcon() const
{
    return overlayIcon_;
}

void NotificationRequest::SetClassification(const std::string &classification)
{
    classification_ = classification;
}

std::string NotificationRequest::GetClassification() const
{
    return classification_;
}

void NotificationRequest::SetColor(uint32_t color)
{
    color_ = color;
    if (NotificationRequest::COLOR_DEFAULT != color_) {
        color_ = color_ | NotificationRequest::COLOR_MASK;
    }
}

uint32_t NotificationRequest::GetColor() const
{
    return color_;
}

bool NotificationRequest::IsColorEnabled() const
{
    if (!colorEnabled_) {
        return false;
    }

    // no valid content
    if (!notificationContent_) {
        ANS_LOGI("no valid notification content");
        return false;
    }

    // not a media content
    if (NotificationContent::Type::MEDIA != notificationContentType_) {
        ANS_LOGI("not a media notification content");
        return false;
    }

    auto basicContent = notificationContent_->GetNotificationContent();
    auto mediaContent = std::static_pointer_cast<NotificationMediaContent>(basicContent);
    if (!mediaContent->GetAVToken()) {
        ANS_LOGI("AVToken has not been attached");
        return false;
    }

    return true;
}

void NotificationRequest::SetColorEnabled(bool colorEnabled)
{
    colorEnabled_ = colorEnabled;
}

void NotificationRequest::SetContent(const std::shared_ptr<NotificationContent> &content)
{
    notificationContent_ = content;

    if (notificationContent_) {
        notificationContentType_ = notificationContent_->GetContentType();
        return;
    }

    notificationContentType_ = NotificationContent::Type::NONE;
}

const std::shared_ptr<NotificationContent> NotificationRequest::GetContent() const
{
    return notificationContent_;
}

NotificationContent::Type NotificationRequest::GetNotificationType() const
{
    return notificationContentType_;
}

bool NotificationRequest::IsCountdownTimer() const
{
    return isCountdown_;
}

void NotificationRequest::SetCountdownTimer(bool isCountDown)
{
    isCountdown_ = isCountDown;
}

void NotificationRequest::SetGroupAlertType(NotificationRequest::GroupAlertType type)
{
    groupAlertType_ = type;
}

NotificationRequest::GroupAlertType NotificationRequest::GetGroupAlertType() const
{
    return groupAlertType_;
}

bool NotificationRequest::IsGroupOverview() const
{
    return groupOverview_;
}

void NotificationRequest::SetGroupOverview(bool overView)
{
    groupOverview_ = overView;
}

void NotificationRequest::SetGroupName(const std::string &groupName)
{
    groupName_ = groupName;
}

std::string NotificationRequest::GetGroupName() const
{
    return groupName_;
}

bool NotificationRequest::IsOnlyLocal() const
{
    return onlyLocal_;
}

void NotificationRequest::SetOnlyLocal(bool flag)
{
    onlyLocal_ = flag;
}

void NotificationRequest::SetSettingsText(const std::string &text)
{
    if ((NotificationContent::Type::LONG_TEXT == notificationContentType_) ||
        (NotificationContent::Type::PICTURE == notificationContentType_)) {
        ANS_LOGW("This method is invalid if the notification content type has been set to LONG_TEXT or PICTURE.");
        return;
    }

    settingsText_ = text;
}

std::string NotificationRequest::GetSettingsText() const
{
    return settingsText_;
}

int64_t NotificationRequest::GetCreateTime() const
{
    return createTime_;
}

void NotificationRequest::SetCreateTime(int64_t createTime)
{
    createTime_ = createTime;
}

bool NotificationRequest::IsShowStopwatch() const
{
    return showStopwatch_;
}

void NotificationRequest::SetShowStopwatch(bool isShow)
{
    showStopwatch_ = isShow;
}

void NotificationRequest::SetSlotType(NotificationConstant::SlotType slotType)
{
    slotType_ = slotType;
}

NotificationConstant::SlotType NotificationRequest::GetSlotType() const
{
    return slotType_;
}

void NotificationRequest::SetSortingKey(const std::string &key)
{
    sortingKey_ = key;
}

std::string NotificationRequest::GetSortingKey() const
{
    return sortingKey_;
}

void NotificationRequest::SetStatusBarText(const std::string &text)
{
    statusBarText_ = text;
}

std::string NotificationRequest::GetStatusBarText() const
{
    return statusBarText_;
}

bool NotificationRequest::IsTapDismissed() const
{
    return tapDismissed_;
}

void NotificationRequest::SetTapDismissed(bool isDismissed)
{
    tapDismissed_ = isDismissed;
}

void NotificationRequest::SetVisibleness(NotificationConstant::VisiblenessType type)
{
    visiblenessType_ = type;
}

NotificationConstant::VisiblenessType NotificationRequest::GetVisibleness() const
{
    return visiblenessType_;
}

void NotificationRequest::SetBadgeIconStyle(NotificationRequest::BadgeStyle style)
{
    badgeStyle_ = style;
}

NotificationRequest::BadgeStyle NotificationRequest::GetBadgeIconStyle() const
{
    return badgeStyle_;
}

void NotificationRequest::SetShortcutId(const std::string &shortcutId)
{
    shortcutId_ = shortcutId;
}

std::string NotificationRequest::GetShortcutId() const
{
    return shortcutId_;
}

void NotificationRequest::SetFloatingIcon(bool floatingIcon)
{
    floatingIcon_ = floatingIcon;
}

bool NotificationRequest::IsFloatingIcon() const
{
    return floatingIcon_;
}

void NotificationRequest::SetProgressBar(int32_t progress, int32_t progressMax, bool indeterminate)
{
    progressValue_ = progress;
    progressMax_ = progressMax;
    progressIndeterminate_ = indeterminate;
}

int32_t NotificationRequest::GetProgressMax() const
{
    return progressMax_;
}

int32_t NotificationRequest::GetProgressValue() const
{
    return progressValue_;
}

bool NotificationRequest::IsProgressIndeterminate() const
{
    return progressIndeterminate_;
}

void NotificationRequest::SetNotificationUserInputHistory(const std::vector<std::string> &text)
{
    if (text.empty()) {
        userInputHistory_.clear();
        return;
    }

    auto vsize = std::min(NotificationRequest::MAX_USER_INPUT_HISTORY, text.size());
    userInputHistory_.assign(text.begin(), text.begin() + vsize);
}

std::vector<std::string> NotificationRequest::GetNotificationUserInputHistory() const
{
    return userInputHistory_;
}

std::string NotificationRequest::GetNotificationHashCode() const
{
    if (creatorBundleName_.empty() || (creatorUid_ == 0) || ownerBundleName_.empty()) {
        return "";
    }

    return std::to_string(notificationId_) + "_" + creatorBundleName_ + "_" + std::to_string(creatorUid_) + "_" +
           ownerBundleName_;
}

void NotificationRequest::SetOwnerBundleName(const std::string &ownerName)
{
    ownerBundleName_ = ownerName;
}

std::string NotificationRequest::GetOwnerBundleName() const
{
    return ownerBundleName_;
}

void NotificationRequest::SetCreatorBundleName(const std::string &creatorName)
{
    creatorBundleName_ = creatorName;
}

std::string NotificationRequest::GetCreatorBundleName() const
{
    return creatorBundleName_;
}

void NotificationRequest::SetCreatorPid(pid_t pid)
{
    creatorPid_ = pid;
}

pid_t NotificationRequest::GetCreatorPid() const
{
    return creatorPid_;
}

void NotificationRequest::SetCreatorUid(int32_t uid)
{
    creatorUid_ = uid;
}

int32_t NotificationRequest::GetCreatorUid() const
{
    return creatorUid_;
}

void NotificationRequest::SetOwnerUid(int32_t uid)
{
    ownerUid_ = uid;
}

int32_t NotificationRequest::GetOwnerUid() const
{
    return ownerUid_;
}

void NotificationRequest::SetLabel(const std::string &label)
{
    label_ = label;
}

std::string NotificationRequest::GetLabel() const
{
    return label_;
}

void NotificationRequest::SetDistributed(bool distribute)
{
    distributedOptions_.SetDistributed(distribute);
}

void NotificationRequest::SetDevicesSupportDisplay(const std::vector<std::string> &devices)
{
    distributedOptions_.SetDevicesSupportDisplay(devices);
}

void NotificationRequest::SetDevicesSupportOperate(const std::vector<std::string> &devices)
{
    distributedOptions_.SetDevicesSupportOperate(devices);
}

NotificationDistributedOptions NotificationRequest::GetNotificationDistributedOptions() const
{
    return distributedOptions_;
}

void NotificationRequest::SetCreatorUserId(int32_t userId)
{
    creatorUserId_ = userId;
}

int32_t NotificationRequest::GetCreatorUserId() const
{
    return creatorUserId_;
}

void NotificationRequest::SetCreatorInstanceKey(int32_t key)
{
    creatorInstanceKey_ = key;
}

int32_t NotificationRequest::GetCreatorInstanceKey() const
{
    return creatorInstanceKey_;
}

void NotificationRequest::SetOwnerUserId(int32_t userId)
{
    ownerUserId_ = userId;
}

int32_t NotificationRequest::GetOwnerUserId() const
{
    return ownerUserId_;
}

void NotificationRequest::SetHashCodeGenerateType(uint32_t type)
{
    hashCodeGenerateType_ = type;
}

uint32_t NotificationRequest::GetHashCodeGenerateType() const
{
    return hashCodeGenerateType_;
}

std::string NotificationRequest::Dump()
{
    return "NotificationRequest{ "
            "notificationId = " + std::to_string(notificationId_) +
            ", slotType = " + std::to_string(static_cast<int32_t>(slotType_)) +
            ", createTime = " + std::to_string(createTime_) + ", deliveryTime = " + std::to_string(deliveryTime_) +
            ", autoDeletedTime = " + std::to_string(autoDeletedTime_) + ", settingsText = " + settingsText_ +
            ", creatorBundleName = " + creatorBundleName_ +
            ", creatorPid = " + std::to_string(static_cast<int32_t>(creatorPid_)) +
            ", creatorUid = " + std::to_string(static_cast<int32_t>(creatorUid_)) +
            ", ownerBundleName = " + ownerBundleName_ +
            ", ownerUid = " + std::to_string(static_cast<int32_t>(ownerUid_)) +
            ", groupName = " + groupName_ + ", statusBarText = " + statusBarText_ + ", label = " + label_ +
            ", shortcutId = " + shortcutId_ + ", sortingKey = " + sortingKey_ +
            ", groupAlertType = " + std::to_string(static_cast<int32_t>(groupAlertType_)) +
            ", color = " + std::to_string(color_) + ", badgeNumber = " + std::to_string(badgeNumber_) +
            ", visiblenessType = " + std::to_string(static_cast<int32_t>(visiblenessType_)) +
            ", progressValue = " + std::to_string(progressValue_) + ", progressMax = " + std::to_string(progressMax_) +
            ", badgeStyle = " + std::to_string(static_cast<int32_t>(badgeStyle_)) +
            ", classification = " + classification_ +
            ", notificationContentType = " + std::to_string(static_cast<int32_t>(notificationContentType_)) +
            ", notificationControlFlags = " + std::to_string(notificationControlFlags_) +
            ", showDeliveryTime = " + (showDeliveryTime_ ? "true" : "false") +
            ", tapDismissed = " + (tapDismissed_ ? "true" : "false") +
            ", colorEnabled = " + (colorEnabled_ ? "true" : "false") +
            ", alertOneTime = " + (alertOneTime_ ? "true" : "false") +
            ", showStopwatch = " + (showStopwatch_ ? "true" : "false") +
            ", isCountdown = " + (isCountdown_ ? "true" : "false") +
            ", inProgress = " + (inProgress_ ? "true" : "false") +
            ", groupOverview = " + (groupOverview_ ? "true" : "false") +
            ", isRemoveAllowed = " + (isRemoveAllowed_ ? "true" : "false") +
            ", progressIndeterminate = " + (progressIndeterminate_ ? "true" : "false") +
            ", unremovable = " + (unremovable_ ? "true" : "false") +
            ", floatingIcon = " + (floatingIcon_ ? "true" : "false") +
            ", onlyLocal = " + (onlyLocal_ ? "true" : "false") + ", permitted = " + (permitted_ ? "true" : "false") +
            ", isAgent = " + (isAgent_ ? "true" : "false") +
            ", removalWantAgent = " + (removalWantAgent_ ? "not null" : "null") +
            ", maxScreenWantAgent = " + (maxScreenWantAgent_ ? "not null" : "null") +
            ", additionalParams = " + (additionalParams_ ? "not null" : "null") +
            ", littleIcon = " + (littleIcon_ ? "not null" : "null") +
            ", bigIcon = " + (bigIcon_ ? "not null" : "null") +
            ", overlayIcon = " + (overlayIcon_ ? "not null" : "null") +
            ", notificationContent = " + (notificationContent_ ? notificationContent_->Dump() : "null") +
            ", notificationTemplate = " + (notificationTemplate_ ? "not null" : "null") +
            ", actionButtons = " + (!actionButtons_.empty() ? actionButtons_.at(0)->Dump() : "empty") +
            ", messageUsers = " + (!messageUsers_.empty() ? messageUsers_.at(0)->Dump() : "empty") +
            ", userInputHistory = " + (!userInputHistory_.empty() ? userInputHistory_.at(0) : "empty") +
            ", distributedOptions = " + distributedOptions_.Dump() +
            ", notificationFlags = " + (notificationFlags_ ? "not null" : "null") +
            ", notificationFlagsOfDevices = " + (notificationFlagsOfDevices_ ? "not null" : "null") +
            ", notificationBundleOption = " + (notificationBundleOption_ != nullptr ? "not null" : "null") +
            ", agentBundle = " + (agentBundle_ != nullptr ? "not null" : "null") +
            ", creatorUserId = " + std::to_string(creatorUserId_) + ", ownerUserId = " + std::to_string(ownerUserId_) +
            ", receiverUserId = " + std::to_string(receiverUserId_) + ", updateDeadLine = " +
            std::to_string(updateDeadLine_) + ", finishDeadLine = " + std::to_string(finishDeadLine_) +
            ", sound = " + sound_ + ", unifiedGroupInfo_ = " +
            (unifiedGroupInfo_ ? unifiedGroupInfo_->Dump() : "null")+ " }";
}

bool NotificationRequest::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject["version"]         = 1;

    jsonObject["id"]              = notificationId_;
    jsonObject["color"]           = color_;
    jsonObject["deliveryTime"]    = deliveryTime_;
    jsonObject["autoDeletedTime"] = autoDeletedTime_;

    jsonObject["creatorBundleName"] = creatorBundleName_;
    jsonObject["ownerBundleName"]   = ownerBundleName_;
    jsonObject["groupName"]         = groupName_;
    jsonObject["label"]             = label_;
    jsonObject["classification"]    = classification_;

    jsonObject["slotType"]       = static_cast<int32_t>(slotType_);
    jsonObject["notificationSlotType"] = static_cast<int32_t>(slotType_);
    jsonObject["badgeIconStyle"] = static_cast<int32_t>(badgeStyle_);
    jsonObject["notificationContentType"] = static_cast<int32_t>(notificationContentType_);

    jsonObject["showDeliveryTime"] = showDeliveryTime_;
    jsonObject["tapDismissed"]     = tapDismissed_;
    jsonObject["colorEnabled"]     = colorEnabled_;
    jsonObject["isOngoing"]        = inProgress_;
    jsonObject["isAlertOnce"]      = alertOneTime_;
    jsonObject["isStopwatch"]      = showStopwatch_;
    jsonObject["isCountdown"]      = isCountdown_;
    jsonObject["isUnremovable"]    = unremovable_;
    jsonObject["isAgent"]          = isAgent_;
    jsonObject["isFloatingIcon"]   = floatingIcon_;

    jsonObject["creatorBundleName"] = creatorBundleName_;
    jsonObject["creatorUid"]        = creatorUid_;
    jsonObject["creatorPid"]        = creatorPid_;
    jsonObject["creatorUserId"]     = creatorUserId_;
    jsonObject["ownerUserId"]       = ownerUserId_;
    jsonObject["ownerUid"]          = ownerUid_;
    jsonObject["receiverUserId"]    = receiverUserId_;
    jsonObject["creatorInstanceKey"]    = creatorInstanceKey_;
    jsonObject["notificationControlFlags"] = notificationControlFlags_;
    jsonObject["updateDeadLine"]     = updateDeadLine_;
    jsonObject["finishDeadLine"]     = finishDeadLine_;
    jsonObject["hashCodeGenerateType"]    = hashCodeGenerateType_;

    if (!ConvertObjectsToJson(jsonObject)) {
        ANS_LOGE("Cannot convert objects to JSON");
        return false;
    }

    return true;
}

NotificationRequest *NotificationRequest::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    auto pRequest = new (std::nothrow) NotificationRequest();
    if (pRequest == nullptr) {
        ANS_LOGE("Failed to create request instance");
        return nullptr;
    }

    const auto &jsonEnd = jsonObject.cend();
    if (jsonObject.find("version") != jsonEnd && jsonObject.at("version").is_number_integer()) {
        jsonObject.at("version").get<int32_t>();
    }

    ConvertJsonToNum(pRequest, jsonObject);

    ConvertJsonToString(pRequest, jsonObject);

    ConvertJsonToEnum(pRequest, jsonObject);

    ConvertJsonToBool(pRequest, jsonObject);

    if (jsonObject.find("wantAgent") != jsonEnd && jsonObject.at("wantAgent").is_string()) {
        auto wantAgentValue  = jsonObject.at("wantAgent").get<std::string>();
        int32_t targetUid = -1;
        if (pRequest->GetOwnerUid() != DEFAULT_UID) {
            targetUid = pRequest->GetOwnerUid();
        }
        ANS_LOGI("wantAgent Fromjson, uid = %{public}d ", targetUid);
        pRequest->wantAgent_ = AbilityRuntime::WantAgent::WantAgentHelper::FromString(wantAgentValue, targetUid);
    }

    if (!ConvertJsonToNotificationContent(pRequest, jsonObject)) {
        delete pRequest;
        pRequest = nullptr;
        return nullptr;
    }

    if (!ConvertJsonToNotificationActionButton(pRequest, jsonObject)) {
        delete pRequest;
        pRequest = nullptr;
        return nullptr;
    }

    if (jsonObject.find("extraInfo") != jsonEnd && jsonObject.at("extraInfo").is_string()) {
        auto extraInfoStr = jsonObject.at("extraInfo").get<std::string>();
        if (!extraInfoStr.empty()) {
            AAFwk::WantParams params    = AAFwk::WantParamWrapper::ParseWantParams(extraInfoStr);
            pRequest->additionalParams_ = std::make_shared<AAFwk::WantParams>(params);
        }
    }

    ConvertJsonToPixelMap(pRequest, jsonObject);

    if (!ConvertJsonToNotificationDistributedOptions(pRequest, jsonObject)) {
        delete pRequest;
        pRequest = nullptr;
        return nullptr;
    }

    if (!ConvertJsonToNotificationFlags(pRequest, jsonObject)) {
        delete pRequest;
        pRequest = nullptr;
        return nullptr;
    }

    if (!ConvertJsonToNotificationBundleOption(pRequest, jsonObject)) {
        delete pRequest;
        pRequest = nullptr;
        return nullptr;
    }

    ConvertJsonToAgentBundle(pRequest, jsonObject);

    return pRequest;
}

bool NotificationRequest::Marshalling(Parcel &parcel) const
{
    // write int
    if (!parcel.WriteInt32(notificationId_)) {
        ANS_LOGE("Failed to write notification Id");
        return false;
    }

    if (!parcel.WriteUint32(color_)) {
        ANS_LOGE("Failed to write color");
        return false;
    }

    if (!parcel.WriteUint32(badgeNumber_)) {
        ANS_LOGE("Failed to write badge number");
        return false;
    }

    if (!parcel.WriteInt32(progressValue_)) {
        ANS_LOGE("Failed to write progress value");
        return false;
    }

    if (!parcel.WriteInt32(progressMax_)) {
        ANS_LOGE("Failed to write progress max");
        return false;
    }

    if (!parcel.WriteInt64(createTime_)) {
        ANS_LOGE("Failed to write create time");
        return false;
    }

    if (!parcel.WriteInt64(deliveryTime_)) {
        ANS_LOGE("Failed to write delivery time");
        return false;
    }

    if (!parcel.WriteInt64(autoDeletedTime_)) {
        ANS_LOGE("Failed to write auto deleted time");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(creatorPid_))) {
        ANS_LOGE("Failed to write creator pid");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(creatorUid_))) {
        ANS_LOGE("Failed to write creator uid");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(ownerUid_))) {
        ANS_LOGE("Failed to write owner uid");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(creatorUserId_))) {
        ANS_LOGE("Failed to write creator userId");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(ownerUserId_))) {
        ANS_LOGE("Failed to write owner userId");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(receiverUserId_))) {
        ANS_LOGE("Failed to write receiver userId");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(creatorInstanceKey_))) {
        ANS_LOGE("Failed to write creator instance key");
        return false;
    }

    if (!parcel.WriteUint32(notificationControlFlags_)) {
        ANS_LOGE("Failed to write notification control flags.");
        return false;
    }

    if (!parcel.WriteUint32(publishDelayTime_)) {
        ANS_LOGE("Failed to write publish delay time");
        return false;
    }

    if (!parcel.WriteUint32(hashCodeGenerateType_)) {
        ANS_LOGE("Failed to write hash code generatetype");
        return false;
    }

    // write std::string
    if (!parcel.WriteString(settingsText_)) {
        ANS_LOGE("Failed to write settings text");
        return false;
    }

    if (!parcel.WriteString(creatorBundleName_)) {
        ANS_LOGE("Failed to write creator bundle name");
        return false;
    }

    if (!parcel.WriteString(ownerBundleName_)) {
        ANS_LOGE("Failed to write owner bundle name");
        return false;
    }

    if (!parcel.WriteString(groupName_)) {
        ANS_LOGE("Failed to write group name");
        return false;
    }

    if (!parcel.WriteString(statusBarText_)) {
        ANS_LOGE("Failed to write status bar text");
        return false;
    }

    if (!parcel.WriteString(label_)) {
        ANS_LOGE("Failed to write label");
        return false;
    }

    if (!parcel.WriteString(shortcutId_)) {
        ANS_LOGE("Failed to write shortcut Id");
        return false;
    }

    if (!parcel.WriteString(sortingKey_)) {
        ANS_LOGE("Failed to write sorting key");
        return false;
    }

    if (!parcel.WriteString(classification_)) {
        ANS_LOGE("Failed to write classification");
        return false;
    }

    if (!parcel.WriteString(appMessageId_)) {
        ANS_LOGE("Failed to write appMessageId");
        return false;
    }

    if (!parcel.WriteString(sound_)) {
        ANS_LOGE("Failed to write sound");
        return false;
    }

    // write enum
    if (!parcel.WriteInt32(static_cast<int32_t>(slotType_))) {
        ANS_LOGE("Failed to write slot type");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(groupAlertType_))) {
        ANS_LOGE("Failed to write group alert type");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(visiblenessType_))) {
        ANS_LOGE("Failed to write visibleness type");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(badgeStyle_))) {
        ANS_LOGE("Failed to write badge type");
        return false;
    }

    if (!parcel.WriteInt32(static_cast<int32_t>(notificationContentType_))) {
        ANS_LOGE("Failed to write notification content type");
        return false;
    }

    // write bool
    if (!parcel.WriteBool(showDeliveryTime_)) {
        ANS_LOGE("Failed to write flag indicating whether to show delivery time");
        return false;
    }

    if (!parcel.WriteBool(tapDismissed_)) {
        ANS_LOGE("Failed to write flag tap dismissed");
        return false;
    }

    if (!parcel.WriteBool(colorEnabled_)) {
        ANS_LOGE("Failed to write flag indicating whether to enable background color");
        return false;
    }

    if (!parcel.WriteBool(alertOneTime_)) {
        ANS_LOGE("Failed to write flag indicating whether to have this notification alert only once");
        return false;
    }

    if (!parcel.WriteBool(showStopwatch_)) {
        ANS_LOGE("Failed to write flag show stop watch");
        return false;
    }

    if (!parcel.WriteBool(isCountdown_)) {
        ANS_LOGE("Failed to write flag indicating whether to show the notification creation time as a countdown timer");
        return false;
    }

    if (!parcel.WriteBool(inProgress_)) {
        ANS_LOGE("Failed to write flag indicating whether in progress");
        return false;
    }

    if (!parcel.WriteBool(groupOverview_)) {
        ANS_LOGE("Failed to write flag indicating whether to use this notification as the overview of its group");
        return false;
    }

    if (!parcel.WriteBool(progressIndeterminate_)) {
        ANS_LOGE("Failed to write progress indeterminate");
        return false;
    }

    if (!parcel.WriteBool(unremovable_)) {
        ANS_LOGE("Failed to write flag indicating whether unremovable");
        return false;
    }

    if (!parcel.WriteBool(floatingIcon_)) {
        ANS_LOGE("Failed to write flag floating icon");
        return false;
    }

    if (!parcel.WriteBool(onlyLocal_)) {
        ANS_LOGE("Failed to write flag only local");
        return false;
    }

    if (!parcel.WriteBool(permitted_)) {
        ANS_LOGE("Failed to write flag indicating whether to allow the platform to \
            generate contextual NotificationActionButton objects");
        return false;
    }

    if (!parcel.WriteBool(isAgent_)) {
        ANS_LOGE("Failed to write flag indicating whether an agent notification");
        return false;
    }

    if (!parcel.WriteBool(isRemoveAllowed_)) {
        ANS_LOGE("Failed to write flag isRemoveAllowed");
        return false;
    }

    // write objects which managed by std::shared_ptr
    bool valid {false};

    valid = wantAgent_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag which indicate whether wantAgent is null");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(wantAgent_.get())) {
            ANS_LOGE("Failed to write wantAgent");
            return false;
        }
    }

    valid = removalWantAgent_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag which indicate whether removalWantAgent is null");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(removalWantAgent_.get())) {
            ANS_LOGE("Failed to write removalWantAgent");
            return false;
        }
    }

    valid = maxScreenWantAgent_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag which indicate whether maxScreenWantAgent is null");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(maxScreenWantAgent_.get())) {
            ANS_LOGE("Failed to write maxScreenWantAgent");
            return false;
        }
    }

    valid = additionalParams_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag which indicate whether additionalParams is null");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(additionalParams_.get())) {
            ANS_LOGE("Failed to write additionalParams");
            return false;
        }
    }

    valid = littleIcon_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag which indicate whether littleIcon is null");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(littleIcon_.get())) {
            ANS_LOGE("Failed to write littleIcon");
            return false;
        }
    }

    valid = bigIcon_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag which indicate whether bigIcon is null");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(bigIcon_.get())) {
            ANS_LOGE("Failed to write bigIcon");
            return false;
        }
    }

    valid = overlayIcon_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag which indicate whether overlayIcon is null");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(overlayIcon_.get())) {
            ANS_LOGE("Failed to write overlayIcon");
            return false;
        }
    }

    valid = notificationContent_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag which indicate whether notificationContent is null");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(notificationContent_.get())) {
            ANS_LOGE("Failed to write notificationContent");
            return false;
        }
    }

    // write std::vector
    if (!parcel.WriteUint64(actionButtons_.size())) {
        ANS_LOGE("Failed to write the size of actionButtons");
        return false;
    }

    for (auto it = actionButtons_.begin(); it != actionButtons_.end(); ++it) {
        if (!parcel.WriteParcelable(it->get())) {
            ANS_LOGE("Failed to write actionButton");
            return false;
        }
    }

    if (!parcel.WriteBool(isCoverActionButtons_)) {
        ANS_LOGE("Failed to write isCoverActionButtons_");
        return false;
    }

    if (!parcel.WriteBool(isUpdateByOwnerAllowed_)) {
        ANS_LOGE("Failed to write isUpdateByOwnerAllowed_");
        return false;
    }

    if (!parcel.WriteUint64(messageUsers_.size())) {
        ANS_LOGE("Failed to write the size of messageUsers");
        return false;
    }

    for (auto it = messageUsers_.begin(); it != messageUsers_.end(); ++it) {
        if (!parcel.WriteParcelable(it->get())) {
            ANS_LOGE("Failed to write messageUser");
            return false;
        }
    }

    if (!parcel.WriteStringVector(userInputHistory_)) {
        ANS_LOGE("Failed to write userInputHistory");
        return false;
    }

    if (!parcel.WriteParcelable(&distributedOptions_)) {
        ANS_LOGE("Failed to write distributedOptions");
        return false;
    }

    valid = notificationTemplate_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag which indicate whether publicNotification is null");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(notificationTemplate_.get())) {
            ANS_LOGE("Failed to write notificationTemplate");
            return false;
        }
    }

    valid = notificationFlags_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write flags for the notification");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(notificationFlags_.get())) {
            ANS_LOGE("Failed to write notification flags");
            return false;
        }
    }

    valid = notificationFlagsOfDevices_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write notification device flags cause invalid sptr");
        return false;
    }

    if (valid) {
        if (!parcel.WriteInt32(static_cast<int32_t>(notificationFlagsOfDevices_->size()))) {
            ANS_LOGE("Failed to write notification devices flags size");
            return false;
        }
        for (auto deviceFlag : *notificationFlagsOfDevices_) {
            if (!parcel.WriteString(deviceFlag.first)) {
                ANS_LOGE("Failed to write notification devices flags key");
                return false;
            }
            if (!parcel.WriteParcelable(deviceFlag.second.get())) {
                ANS_LOGE("Failed to write notification devices flags value");
                return false;
            }
        }
    }

    valid = unifiedGroupInfo_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write unifiedGroupInfo for the notification");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(unifiedGroupInfo_.get())) {
            ANS_LOGE("Failed to write notification unifiedGroupInfo");
            return false;
        }
    }

    valid = notificationBundleOption_ != nullptr ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write bundleOption for the notification");
        return false;
    }
 
    if (valid) {
        if (!parcel.WriteParcelable(notificationBundleOption_.get())) {
            ANS_LOGE("Failed to write notification bundleOption");
            return false;
        }
    }

    valid = agentBundle_ != nullptr ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write agentBundle for the notification");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(agentBundle_.get())) {
            ANS_LOGE("Failed to write notification agentBundle");
            return false;
        }
    }

    if (!parcel.WriteInt64(updateDeadLine_)) {
        ANS_LOGE("Failed to write max update time");
        return false;
    }

    if (!parcel.WriteInt64(finishDeadLine_)) {
        ANS_LOGE("Failed to write max finish time");
        return false;
    }

    return true;
}

NotificationRequest *NotificationRequest::Unmarshalling(Parcel &parcel)
{
    auto objptr = new (std::nothrow) NotificationRequest();
    if ((objptr != nullptr) && !objptr->ReadFromParcel(parcel)) {
        delete objptr;
        objptr = nullptr;
    }

    return objptr;
}

bool NotificationRequest::ReadFromParcel(Parcel &parcel)
{
    notificationId_ = parcel.ReadInt32();
    color_ = parcel.ReadUint32();
    badgeNumber_ = parcel.ReadUint32();
    progressValue_ = parcel.ReadInt32();
    progressMax_ = parcel.ReadInt32();
    createTime_ = parcel.ReadInt64();
    deliveryTime_ = parcel.ReadInt64();
    autoDeletedTime_ = parcel.ReadInt64();

    creatorPid_ = static_cast<pid_t>(parcel.ReadInt32());
    creatorUid_ = parcel.ReadInt32();
    ownerUid_ = parcel.ReadInt32();
    creatorUserId_ = parcel.ReadInt32();
    ownerUserId_ = parcel.ReadInt32();
    receiverUserId_ = parcel.ReadInt32();
    creatorInstanceKey_ = parcel.ReadInt32();
    notificationControlFlags_ = parcel.ReadUint32();
    publishDelayTime_ = parcel.ReadUint32();
    hashCodeGenerateType_ = parcel.ReadUint32();

    if (!parcel.ReadString(settingsText_)) {
        ANS_LOGE("Failed to read settings text");
        return false;
    }

    if (!parcel.ReadString(creatorBundleName_)) {
        ANS_LOGE("Failed to read creator bundle name");
        return false;
    }

    if (!parcel.ReadString(ownerBundleName_)) {
        ANS_LOGE("Failed to read owner bundle name");
        return false;
    }

    if (!parcel.ReadString(groupName_)) {
        ANS_LOGE("Failed to read group name");
        return false;
    }

    if (!parcel.ReadString(statusBarText_)) {
        ANS_LOGE("Failed to read status bar text");
        return false;
    }

    if (!parcel.ReadString(label_)) {
        ANS_LOGE("Failed to read label");
        return false;
    }

    if (!parcel.ReadString(shortcutId_)) {
        ANS_LOGE("Failed to read shortcut Id");
        return false;
    }

    if (!parcel.ReadString(sortingKey_)) {
        ANS_LOGE("Failed to read sorting key");
        return false;
    }

    if (!parcel.ReadString(classification_)) {
        ANS_LOGE("Failed to read classification");
        return false;
    }

    if (!parcel.ReadString(appMessageId_)) {
        ANS_LOGE("Failed to read appMessageId");
        return false;
    }

    if (!parcel.ReadString(sound_)) {
        ANS_LOGE("Failed to read sound");
        return false;
    }

    int32_t slotTypeValue = parcel.ReadInt32();
    if (slotTypeValue < 0 ||
        slotTypeValue >= static_cast<int>(NotificationConstant::SlotType::ILLEGAL_TYPE)) {
        ANS_LOGE("Invalid slot type value :%{public}d. It should be in [0 , %{public}d).",
            slotTypeValue, static_cast<int>(NotificationConstant::SlotType::ILLEGAL_TYPE));
        return false;
    }
    slotType_ = static_cast<NotificationConstant::SlotType>(slotTypeValue);
    int32_t groupAlertTypeValue = parcel.ReadInt32();
    if (groupAlertTypeValue < 0 ||
        groupAlertTypeValue >= static_cast<int>(NotificationRequest::GroupAlertType::ILLEGAL_TYPE)) {
        ANS_LOGE("Invalid groupAlert type value :%{public}d. It should be in [0 , %{public}d).",
            groupAlertTypeValue, static_cast<int>(NotificationRequest::GroupAlertType::ILLEGAL_TYPE));
        return false;
    }
    groupAlertType_ = static_cast<NotificationRequest::GroupAlertType>(groupAlertTypeValue);
    int32_t visiblenessTypeValue = parcel.ReadInt32();
    if (visiblenessTypeValue < 0 ||
        visiblenessTypeValue >= static_cast<int>(NotificationConstant::VisiblenessType::ILLEGAL_TYPE)) {
        ANS_LOGE("Invalid visibleness type value :%{public}d. It should be in [0 , %{public}d).",
            visiblenessTypeValue, static_cast<int>(NotificationConstant::VisiblenessType::ILLEGAL_TYPE));
        return false;
    }
    visiblenessType_ = static_cast<NotificationConstant::VisiblenessType>(visiblenessTypeValue);
    int32_t badgeStyleValue = parcel.ReadInt32();
    if (badgeStyleValue < 0) {
        ANS_LOGE("Invalid badge style value :%{public}d. It should be greater than 0.", badgeStyleValue);
        return false;
    }
    if (badgeStyleValue >= static_cast<int>(NotificationRequest::BadgeStyle::ILLEGAL_TYPE)) {
        badgeStyleValue = static_cast<int>(NotificationRequest::BadgeStyle::NONE);
        ANS_LOGE("The badge style value is too large, set it to the default enumeration value: %{public}d.",
            static_cast<int>(NotificationRequest::BadgeStyle::NONE));
    }
    badgeStyle_ = static_cast<NotificationRequest::BadgeStyle>(badgeStyleValue);
    int32_t notificationContentTypeValue = parcel.ReadInt32();
    if (notificationContentTypeValue <= static_cast<int>(NotificationContent::Type::NONE) ||
        notificationContentTypeValue >= static_cast<int>(NotificationContent::Type::ILLEGAL_TYPE)) {
        ANS_LOGE("Invalid notification content type value :%{public}d. It should be in (%{public}d , %{public}d)",
            notificationContentTypeValue, static_cast<int>(NotificationContent::Type::NONE),
            static_cast<int>(NotificationContent::Type::ILLEGAL_TYPE));
        return false;
    }
    notificationContentType_ = static_cast<NotificationContent::Type>(notificationContentTypeValue);

    showDeliveryTime_ = parcel.ReadBool();
    tapDismissed_ = parcel.ReadBool();
    colorEnabled_ = parcel.ReadBool();
    alertOneTime_ = parcel.ReadBool();
    showStopwatch_ = parcel.ReadBool();
    isCountdown_ = parcel.ReadBool();
    inProgress_ = parcel.ReadBool();
    groupOverview_ = parcel.ReadBool();
    progressIndeterminate_ = parcel.ReadBool();
    unremovable_ = parcel.ReadBool();
    floatingIcon_ = parcel.ReadBool();
    onlyLocal_ = parcel.ReadBool();
    permitted_ = parcel.ReadBool();
    isAgent_ = parcel.ReadBool();
    isRemoveAllowed_ = parcel.ReadBool();

    bool valid {false};

    valid = parcel.ReadBool();
    if (valid) {
        wantAgent_ = std::shared_ptr<AbilityRuntime::WantAgent::WantAgent>(
            parcel.ReadParcelable<AbilityRuntime::WantAgent::WantAgent>());
        if (!wantAgent_) {
            ANS_LOGE("Failed to read wantAgent");
            return false;
        }
    }

    valid = parcel.ReadBool();
    if (valid) {
        removalWantAgent_ = std::shared_ptr<AbilityRuntime::WantAgent::WantAgent>(
            parcel.ReadParcelable<AbilityRuntime::WantAgent::WantAgent>());
        if (!removalWantAgent_) {
            ANS_LOGE("Failed to read removalWantAgent");
            return false;
        }
    }

    valid = parcel.ReadBool();
    if (valid) {
        maxScreenWantAgent_ = std::shared_ptr<AbilityRuntime::WantAgent::WantAgent>(
            parcel.ReadParcelable<AbilityRuntime::WantAgent::WantAgent>());
        if (!maxScreenWantAgent_) {
            ANS_LOGE("Failed to read maxScreenWantAgent");
            return false;
        }
    }

    valid = parcel.ReadBool();
    if (valid) {
        additionalParams_ = std::shared_ptr<AAFwk::WantParams>(parcel.ReadParcelable<AAFwk::WantParams>());
        if (!additionalParams_) {
            ANS_LOGE("Failed to read additionalParams");
            return false;
        }
    }

    valid = parcel.ReadBool();
    if (valid) {
        littleIcon_ = std::shared_ptr<Media::PixelMap>(parcel.ReadParcelable<Media::PixelMap>());
    }

    valid = parcel.ReadBool();
    if (valid) {
        bigIcon_ = std::shared_ptr<Media::PixelMap>(parcel.ReadParcelable<Media::PixelMap>());
        if (!bigIcon_) {
            ANS_LOGE("Failed to read bigIcon");
            return false;
        }
    }

    valid = parcel.ReadBool();
    if (valid) {
        overlayIcon_ = std::shared_ptr<Media::PixelMap>(parcel.ReadParcelable<Media::PixelMap>());
        if (!overlayIcon_) {
            ANS_LOGE("Failed to read overlayIcon");
            return false;
        }
    }

    valid = parcel.ReadBool();
    if (valid) {
        notificationContent_ = std::shared_ptr<NotificationContent>(parcel.ReadParcelable<NotificationContent>());
        if (!notificationContent_) {
            ANS_LOGE("Failed to read notificationContent");
            return false;
        }
    }

    auto vsize = parcel.ReadUint64();
    vsize = (vsize < NotificationRequest::MAX_ACTION_BUTTONS) ? vsize : NotificationRequest::MAX_ACTION_BUTTONS;
    for (uint64_t it = 0; it < vsize; ++it) {
        auto member = std::shared_ptr<NotificationActionButton>(parcel.ReadParcelable<NotificationActionButton>());
        if (member == nullptr) {
            actionButtons_.clear();
            ANS_LOGE("Failed to read actionButton");
            return false;
        }

        actionButtons_.emplace_back(member);
    }

    isCoverActionButtons_ = parcel.ReadBool();
    isUpdateByOwnerAllowed_ = parcel.ReadBool();

    vsize = parcel.ReadUint64();
    vsize = (vsize < NotificationRequest::MAX_MESSAGE_USERS) ? vsize : NotificationRequest::MAX_MESSAGE_USERS;
    for (uint64_t it = 0; it < vsize; ++it) {
        auto member = std::shared_ptr<MessageUser>(parcel.ReadParcelable<MessageUser>());
        if (member == nullptr) {
            ANS_LOGE("Failed to read messageUser");
            messageUsers_.clear();
            return false;
        }

        messageUsers_.emplace_back(member);
    }

    if (!parcel.ReadStringVector(&userInputHistory_)) {
        ANS_LOGE("Failed to read userInputHistory");
        return false;
    }

    auto pOpt = parcel.ReadParcelable<NotificationDistributedOptions>();
    if (pOpt == nullptr) {
        ANS_LOGE("Failed to read distributedOptions");
        return false;
    }
    distributedOptions_ = *pOpt;
    delete pOpt;
    pOpt = nullptr;

    valid = parcel.ReadBool();
    if (valid) {
        notificationTemplate_ = std::shared_ptr<NotificationTemplate>(parcel.ReadParcelable<NotificationTemplate>());
        if (!notificationTemplate_) {
            ANS_LOGE("Failed to read notificationTemplate");
            return false;
        }
    }

    valid = parcel.ReadBool();
    if (valid) {
        notificationFlags_ = std::shared_ptr<NotificationFlags>(parcel.ReadParcelable<NotificationFlags>());
        if (!notificationFlags_) {
            ANS_LOGE("Failed to read notificationFlags");
            return false;
        }
    }

    valid = parcel.ReadBool();
    if (valid) {
        notificationFlagsOfDevices_ = std::make_shared<std::map<std::string, std::shared_ptr<NotificationFlags>>>();
        int32_t mapSize = parcel.ReadInt32();
        mapSize = (mapSize < MAX_MAP_SIZE) ? mapSize : MAX_MAP_SIZE;
        for (int32_t seq = 0; seq < mapSize; seq++) {
            std::string deviceType = parcel.ReadString();
            std::shared_ptr<NotificationFlags> notificationFlags =
                std::shared_ptr<NotificationFlags>(parcel.ReadParcelable<NotificationFlags>());
            (*notificationFlagsOfDevices_)[deviceType] = notificationFlags;
        }
    }

    valid = parcel.ReadBool();
    if (valid) {
        unifiedGroupInfo_ =
            std::shared_ptr<NotificationUnifiedGroupInfo>(parcel.ReadParcelable<NotificationUnifiedGroupInfo>());
        if (!unifiedGroupInfo_) {
            ANS_LOGE("Failed to read unifiedGroupInfo+");
            return false;
        }
    }

    valid = parcel.ReadBool();
    if (valid) {
        notificationBundleOption_ =
            std::shared_ptr<NotificationBundleOption>(parcel.ReadParcelable<NotificationBundleOption>());
        if (!notificationBundleOption_) {
            ANS_LOGE("Failed to read notificationBundleOption");
            return false;
        }
    }

    valid = parcel.ReadBool();
    if (valid) {
        agentBundle_ =
            std::shared_ptr<NotificationBundleOption>(parcel.ReadParcelable<NotificationBundleOption>());
        if (!agentBundle_) {
            ANS_LOGE("Failed to read agentBundle");
            return false;
        }
    }

    updateDeadLine_ = parcel.ReadInt64();
    finishDeadLine_ = parcel.ReadInt64();

    return true;
}

int64_t NotificationRequest::GetNowSysTime()
{
    std::chrono::time_point<std::chrono::system_clock> nowSys = std::chrono::system_clock::now();
    auto epoch = nowSys.time_since_epoch();
    auto value = std::chrono::duration_cast<std::chrono::milliseconds>(epoch);
    int64_t duration = value.count();
    return duration;
}

void NotificationRequest::SetTemplate(const std::shared_ptr<NotificationTemplate> &templ)
{
    notificationTemplate_ = templ;
}

std::shared_ptr<NotificationTemplate> NotificationRequest::GetTemplate() const
{
    return notificationTemplate_;
}

void NotificationRequest::SetFlags(const std::shared_ptr<NotificationFlags> &flags)
{
    notificationFlags_ = flags;
}

std::shared_ptr<NotificationFlags> NotificationRequest::GetFlags() const
{
    return notificationFlags_;
}

void NotificationRequest::SetDeviceFlags(
    const std::shared_ptr<std::map<std::string, std::shared_ptr<NotificationFlags>>> &mapFlags)
{
    notificationFlagsOfDevices_ = mapFlags;
}

std::shared_ptr<std::map<std::string, std::shared_ptr<NotificationFlags>>> NotificationRequest::GetDeviceFlags() const
{
    return notificationFlagsOfDevices_;
}


void NotificationRequest::SetBundleOption(const std::shared_ptr<NotificationBundleOption> &bundleOption)
{
    notificationBundleOption_ = bundleOption;
}

std::shared_ptr<NotificationBundleOption> NotificationRequest::GetBundleOption() const
{
    return notificationBundleOption_;
}

void NotificationRequest::SetAgentBundle(const std::shared_ptr<NotificationBundleOption> &agentBundle)
{
    agentBundle_ = agentBundle;
}

std::shared_ptr<NotificationBundleOption> NotificationRequest::GetAgentBundle() const
{
    return agentBundle_;
}

void NotificationRequest::SetReceiverUserId(int32_t userId)
{
    receiverUserId_ = userId;
}

int32_t NotificationRequest::GetReceiverUserId() const
{
    if (receiverUserId_ == SUBSCRIBE_USER_INIT) {
        if (ownerUserId_ == SUBSCRIBE_USER_INIT) {
            return creatorUserId_;
        }
        return ownerUserId_;
    }
    return receiverUserId_;
}

bool NotificationRequest::IsRemoveAllowed() const
{
    return isRemoveAllowed_;
}

void NotificationRequest::SetRemoveAllowed(bool isRemoveAllowed)
{
    isRemoveAllowed_ = isRemoveAllowed;
}

void NotificationRequest::CopyBase(const NotificationRequest &other)
{
    this->notificationId_ = other.notificationId_;
    this->color_ = other.color_;
    this->badgeNumber_ = other.badgeNumber_;
    this->notificationControlFlags_ = other.notificationControlFlags_;
    this->progressValue_ = other.progressValue_;
    this->progressMax_ = other.progressMax_;
    this->createTime_ = other.createTime_;
    this->deliveryTime_ = other.deliveryTime_;
    this->autoDeletedTime_ = other.autoDeletedTime_;
    this->updateDeadLine_ = other.updateDeadLine_;
    this->finishDeadLine_ = other.finishDeadLine_;

    this->creatorPid_ = other.creatorPid_;
    this->creatorUid_ = other.creatorUid_;
    this->ownerUid_ = other.ownerUid_;
    this->creatorUserId_ = other.creatorUserId_;
    this->ownerUserId_ = other.ownerUserId_;
    this->receiverUserId_ = other.receiverUserId_;
    this->creatorInstanceKey_ = other.creatorInstanceKey_;
    this->isAgent_ = other.isAgent_;
    this->isRemoveAllowed_ = other.isRemoveAllowed_;
    this->isCoverActionButtons_ = other.isCoverActionButtons_;
    this->isUpdateByOwnerAllowed_ = other.isUpdateByOwnerAllowed_;

    this->slotType_ = other.slotType_;
    this->settingsText_ = other.settingsText_;
    this->creatorBundleName_ = other.creatorBundleName_;
    this->ownerBundleName_ = other.ownerBundleName_;
    this->groupName_ = other.groupName_;
    this->statusBarText_ = other.statusBarText_;
    this->label_ = other.label_;
    this->shortcutId_ = other.shortcutId_;
    this->sortingKey_ = other.sortingKey_;
    this->classification_ = other.classification_;
    this->appMessageId_ = other.appMessageId_;
    this->sound_ = other.sound_;

    this->groupAlertType_ = other.groupAlertType_;
    this->visiblenessType_ = other.visiblenessType_;
    this->badgeStyle_ = other.badgeStyle_;
    this->notificationContentType_ = other.notificationContentType_;
}

void NotificationRequest::CopyOther(const NotificationRequest &other)
{
    this->showDeliveryTime_ = other.showDeliveryTime_;
    this->tapDismissed_ = other.tapDismissed_;
    this->colorEnabled_ = other.colorEnabled_;
    this->alertOneTime_ = other.alertOneTime_;
    this->showStopwatch_ = other.showStopwatch_;
    this->isCountdown_ = other.isCountdown_;
    this->inProgress_ = other.inProgress_;
    this->groupOverview_ = other.groupOverview_;
    this->progressIndeterminate_ = other.progressIndeterminate_;
    this->unremovable_ = other.unremovable_;
    this->floatingIcon_ = other.floatingIcon_;
    this->onlyLocal_ = other.onlyLocal_;
    this->permitted_ = other.permitted_;

    this->wantAgent_ = other.wantAgent_;
    this->removalWantAgent_ = other.removalWantAgent_;
    this->maxScreenWantAgent_ = other.maxScreenWantAgent_;
    this->additionalParams_ = other.additionalParams_;
    this->littleIcon_ = other.littleIcon_;
    this->bigIcon_ = other.bigIcon_;
    this->overlayIcon_ = other.overlayIcon_;
    this->notificationContent_ = other.notificationContent_;

    this->actionButtons_ = other.actionButtons_;
    this->messageUsers_ = other.messageUsers_;
    this->userInputHistory_ = other.userInputHistory_;

    this->distributedOptions_ = other.distributedOptions_;

    this->notificationTemplate_ = other.notificationTemplate_;
    this->notificationFlags_ = other.notificationFlags_;
    this->agentBundle_ = other.agentBundle_;
    this->unifiedGroupInfo_ = other.unifiedGroupInfo_;
    this->notificationBundleOption_ = other.notificationBundleOption_;
    this->notificationFlagsOfDevices_ = other.notificationFlagsOfDevices_;
    this->publishDelayTime_ = other.publishDelayTime_;
    this->hashCodeGenerateType_ = other.hashCodeGenerateType_;
}

bool NotificationRequest::ConvertObjectsToJson(nlohmann::json &jsonObject) const
{
    jsonObject["wantAgent"] = wantAgent_ ? AbilityRuntime::WantAgent::WantAgentHelper::ToString(wantAgent_) : "";

    nlohmann::json contentObj;
    if (notificationContent_) {
        if (!NotificationJsonConverter::ConvertToJson(notificationContent_.get(), contentObj)) {
            ANS_LOGE("Cannot convert notificationContent to JSON");
            return false;
        }
    }
    jsonObject["content"] = contentObj;

    nlohmann::json buttonsArr = nlohmann::json::array();
    for (auto &btn : actionButtons_) {
        if (!btn) {
            continue;
        }

        nlohmann::json btnObj;
        if (!NotificationJsonConverter::ConvertToJson(btn.get(), btnObj)) {
            ANS_LOGE("Cannot convert actionButton to JSON");
            return false;
        }

        buttonsArr.emplace_back(btnObj);
    }
    jsonObject["actionButtons"] = buttonsArr;

    std::string extraInfoStr;
    if (additionalParams_) {
        AAFwk::WantParamWrapper wWrapper(*additionalParams_);
        extraInfoStr = wWrapper.ToString();
    }
    jsonObject["extraInfo"] = extraInfoStr;
    jsonObject["smallIcon"] = AnsImageUtil::PackImage(littleIcon_);
    jsonObject["largeIcon"] = AnsImageUtil::PackImage(bigIcon_);
    jsonObject["overlayIcon"] = overlayIcon_ ? AnsImageUtil::PackImage(overlayIcon_) : "";

    nlohmann::json optObj;
    if (!NotificationJsonConverter::ConvertToJson(&distributedOptions_, optObj)) {
        ANS_LOGE("Cannot convert distributedOptions to JSON");
        return false;
    }
    jsonObject["distributedOptions"] = optObj;

    if (notificationFlags_) {
        nlohmann::json flagsObj;
        if (!NotificationJsonConverter::ConvertToJson(notificationFlags_.get(), flagsObj)) {
            ANS_LOGE("Cannot convert notificationFlags to JSON");
            return false;
        }
        jsonObject["notificationFlags"] = flagsObj;
    }

    if (notificationBundleOption_ != nullptr) {
        nlohmann::json bundleOptionObj;
        if (!NotificationJsonConverter::ConvertToJson(notificationBundleOption_.get(), bundleOptionObj)) {
            ANS_LOGE("Cannot convert notificationBundleOption to JSON.");
            return false;
        }
        jsonObject["notificationBundleOption"] = bundleOptionObj;
    }

    if (agentBundle_ != nullptr) {
        nlohmann::json bundleOptionObj;
        if (!NotificationJsonConverter::ConvertToJson(agentBundle_.get(), bundleOptionObj)) {
            ANS_LOGE("Cannot convert agentBundle to JSON.");
            return false;
        }
        jsonObject["agentBundle"] = bundleOptionObj;
    }

    return true;
}

void NotificationRequest::ConvertJsonToNumExt(
    NotificationRequest *target, const nlohmann::json &jsonObject)
{
    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find("updateDeadLine") != jsonEnd && jsonObject.at("updateDeadLine").is_number_integer()) {
        target->updateDeadLine_ = jsonObject.at("updateDeadLine").get<int64_t>();
    }

    if (jsonObject.find("finishDeadLine") != jsonEnd && jsonObject.at("finishDeadLine").is_number_integer()) {
        target->finishDeadLine_ = jsonObject.at("finishDeadLine").get<int64_t>();
    }

    if (jsonObject.find("ownerUserId") != jsonEnd && jsonObject.at("ownerUserId").is_number_integer()) {
        target->ownerUserId_ = jsonObject.at("ownerUserId").get<int32_t>();
    }

    if (jsonObject.find("ownerUid") != jsonEnd && jsonObject.at("ownerUid").is_number_integer()) {
        target->ownerUid_ = jsonObject.at("ownerUid").get<int32_t>();
    }

    if (jsonObject.find("notificationControlFlags") != jsonEnd &&
        jsonObject.at("notificationControlFlags").is_number_integer()) {
        target->notificationControlFlags_ = jsonObject.at("notificationControlFlags").get<uint32_t>();
    }
}

void NotificationRequest::ConvertJsonToNum(NotificationRequest *target, const nlohmann::json &jsonObject)
{
    if (target == nullptr) {
        ANS_LOGE("Invalid input parameter");
        return;
    }

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find("id") != jsonEnd && jsonObject.at("id").is_number_integer()) {
        target->notificationId_ = jsonObject.at("id").get<int32_t>();
    }

    if (jsonObject.find("color") != jsonEnd && jsonObject.at("color").is_number_integer()) {
        target->color_ = jsonObject.at("color").get<uint32_t>();
    }

    if (jsonObject.find("deliveryTime") != jsonEnd && jsonObject.at("deliveryTime").is_number_integer()) {
        target->deliveryTime_ = jsonObject.at("deliveryTime").get<int64_t>();
    }

    if (jsonObject.find("autoDeletedTime") != jsonEnd && jsonObject.at("autoDeletedTime").is_number_integer()) {
        target->autoDeletedTime_ = jsonObject.at("autoDeletedTime").get<int64_t>();
    }

    if (jsonObject.find("creatorUid") != jsonEnd && jsonObject.at("creatorUid").is_number_integer()) {
        target->creatorUid_ = jsonObject.at("creatorUid").get<int32_t>();
    }

    if (jsonObject.find("creatorPid") != jsonEnd && jsonObject.at("creatorPid").is_number_integer()) {
        target->creatorPid_ = jsonObject.at("creatorPid").get<int32_t>();
    }

    if (jsonObject.find("creatorUserId") != jsonEnd && jsonObject.at("creatorUserId").is_number_integer()) {
        target->creatorUserId_ = jsonObject.at("creatorUserId").get<int32_t>();
    }

    if (jsonObject.find("receiverUserId") != jsonEnd && jsonObject.at("receiverUserId").is_number_integer()) {
        target->receiverUserId_ = jsonObject.at("receiverUserId").get<int32_t>();
    }

    if (jsonObject.find("creatorInstanceKey") != jsonEnd && jsonObject.at("creatorInstanceKey").is_number_integer()) {
        target->creatorInstanceKey_ = jsonObject.at("creatorInstanceKey").get<int32_t>();
    }

    if (jsonObject.find("badgeNumber") != jsonEnd && jsonObject.at("badgeNumber").is_number_integer()) {
        target->badgeNumber_ = jsonObject.at("badgeNumber").get<uint32_t>();
    }
    if (jsonObject.find("hashCodeGenerateType") != jsonEnd &&
        jsonObject.at("hashCodeGenerateType").is_number_integer()) {
        target->hashCodeGenerateType_ = jsonObject.at("hashCodeGenerateType").get<uint32_t>();
    }

    ConvertJsonToNumExt(target, jsonObject);
}

void NotificationRequest::ConvertJsonToString(NotificationRequest *target, const nlohmann::json &jsonObject)
{
    if (target == nullptr) {
        ANS_LOGE("Invalid input parameter");
        return;
    }

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find("creatorBundleName") != jsonEnd && jsonObject.at("creatorBundleName").is_string()) {
        target->creatorBundleName_ = jsonObject.at("creatorBundleName").get<std::string>();
    }

    if (jsonObject.find("ownerBundleName") != jsonEnd && jsonObject.at("ownerBundleName").is_string()) {
        target->ownerBundleName_ = jsonObject.at("ownerBundleName").get<std::string>();
    }

    if (jsonObject.find("groupName") != jsonEnd && jsonObject.at("groupName").is_string()) {
        target->groupName_ = jsonObject.at("groupName").get<std::string>();
    }

    if (jsonObject.find("label") != jsonEnd && jsonObject.at("label").is_string()) {
        target->label_ = jsonObject.at("label").get<std::string>();
    }

    if (jsonObject.find("classification") != jsonEnd && jsonObject.at("classification").is_string()) {
        target->classification_ = jsonObject.at("classification").get<std::string>();
    }

    if (jsonObject.find("creatorBundleName") != jsonEnd && jsonObject.at("creatorBundleName").is_string()) {
        target->creatorBundleName_ = jsonObject.at("creatorBundleName").get<std::string>();
    }
}

void NotificationRequest::ConvertJsonToEnum(NotificationRequest *target, const nlohmann::json &jsonObject)
{
    if (target == nullptr) {
        ANS_LOGE("Invalid input parameter");
        return;
    }

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find("slotType") != jsonEnd && jsonObject.at("slotType").is_number_integer()) {
        auto slotTypeValue  = jsonObject.at("slotType").get<int32_t>();
        target->slotType_ = static_cast<NotificationConstant::SlotType>(slotTypeValue);
    }

    if (jsonObject.find("badgeIconStyle") != jsonEnd && jsonObject.at("badgeIconStyle").is_number_integer()) {
        auto badgeStyleValue  = jsonObject.at("badgeIconStyle").get<int32_t>();
        target->badgeStyle_ = static_cast<NotificationRequest::BadgeStyle>(badgeStyleValue);
    }

    if (jsonObject.find("notificationContentType") != jsonEnd &&
        jsonObject.at("notificationContentType").is_number_integer()) {
        auto notificationContentType = jsonObject.at("notificationContentType").get<int32_t>();
        target->notificationContentType_ = static_cast<NotificationContent::Type>(notificationContentType);
    }
}

void NotificationRequest::ConvertJsonToBool(NotificationRequest *target, const nlohmann::json &jsonObject)
{
    if (target == nullptr) {
        ANS_LOGE("Invalid input parameter");
        return;
    }

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find("showDeliveryTime") != jsonEnd && jsonObject.at("showDeliveryTime").is_boolean()) {
        target->showDeliveryTime_ = jsonObject.at("showDeliveryTime").get<bool>();
    }

    if (jsonObject.find("tapDismissed") != jsonEnd && jsonObject.at("tapDismissed").is_boolean()) {
        target->tapDismissed_ = jsonObject.at("tapDismissed").get<bool>();
    }

    if (jsonObject.find("colorEnabled") != jsonEnd && jsonObject.at("colorEnabled").is_boolean()) {
        target->colorEnabled_ = jsonObject.at("colorEnabled").get<bool>();
    }

    if (jsonObject.find("isOngoing") != jsonEnd && jsonObject.at("isOngoing").is_boolean()) {
        target->inProgress_ = jsonObject.at("isOngoing").get<bool>();
    }

    if (jsonObject.find("isAlertOnce") != jsonEnd && jsonObject.at("isAlertOnce").is_boolean()) {
        target->alertOneTime_ = jsonObject.at("isAlertOnce").get<bool>();
    }

    if (jsonObject.find("isStopwatch") != jsonEnd && jsonObject.at("isStopwatch").is_boolean()) {
        target->showStopwatch_ = jsonObject.at("isStopwatch").get<bool>();
    }

    if (jsonObject.find("isCountdown") != jsonEnd && jsonObject.at("isCountdown").is_boolean()) {
        target->isCountdown_ = jsonObject.at("isCountdown").get<bool>();
    }

    if (jsonObject.find("isUnremovable") != jsonEnd && jsonObject.at("isUnremovable").is_boolean()) {
        target->unremovable_ = jsonObject.at("isUnremovable").get<bool>();
    }

    if (jsonObject.find("isFloatingIcon") != jsonEnd && jsonObject.at("isFloatingIcon").is_boolean()) {
        target->floatingIcon_ = jsonObject.at("isFloatingIcon").get<bool>();
    }

    ConvertJsonToBoolExt(target, jsonObject);
}

void NotificationRequest::ConvertJsonToBoolExt(NotificationRequest *target, const nlohmann::json &jsonObject)
{
    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find("isAgent") != jsonEnd && jsonObject.at("isAgent").is_boolean()) {
        target->isAgent_ = jsonObject.at("isAgent").get<bool>();
    }
}

void NotificationRequest::ConvertJsonToPixelMap(NotificationRequest *target, const nlohmann::json &jsonObject)
{
    if (target == nullptr) {
        ANS_LOGE("Invalid input parameter");
        return;
    }

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find("smallIcon") != jsonEnd && jsonObject.at("smallIcon").is_string()) {
        auto littleIconStr = jsonObject.at("smallIcon").get<std::string>();
        target->littleIcon_ = AnsImageUtil::UnPackImage(littleIconStr);
    }

    if (jsonObject.find("largeIcon") != jsonEnd && jsonObject.at("largeIcon").is_string()) {
        auto bigIconStr    = jsonObject.at("largeIcon").get<std::string>();
        target->bigIcon_ = AnsImageUtil::UnPackImage(bigIconStr);
    }

    if (jsonObject.find("overlayIcon") != jsonEnd && jsonObject.at("overlayIcon").is_string()) {
        auto overlayIconStr    = jsonObject.at("overlayIcon").get<std::string>();
        target->overlayIcon_ = AnsImageUtil::UnPackImage(overlayIconStr);
    }
}

bool NotificationRequest::ConvertJsonToNotificationContent(
    NotificationRequest *target, const nlohmann::json &jsonObject)
{
    if (target == nullptr) {
        ANS_LOGE("Invalid input parameter");
        return false;
    }

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find("content") != jsonEnd) {
        auto contentObj = jsonObject.at("content");
        if (!contentObj.is_null()) {
            auto pContent = NotificationJsonConverter::ConvertFromJson<NotificationContent>(contentObj);
            if (pContent == nullptr) {
                ANS_LOGE("Failed to parse notification content!");
                return false;
            }

            target->notificationContent_ = std::shared_ptr<NotificationContent>(pContent);
        }
    }

    return true;
}

bool NotificationRequest::ConvertJsonToNotificationActionButton(
    NotificationRequest *target, const nlohmann::json &jsonObject)
{
    if (target == nullptr) {
        ANS_LOGE("Invalid input parameter");
        return false;
    }
    int32_t targetUid = -1;
    if (target->GetOwnerUid() != DEFAULT_UID) {
        targetUid = target->GetOwnerUid();
    }
    ANS_LOGI("wantAgent Fromjson, uid = %{public}d ", targetUid);

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find("actionButtons") != jsonEnd) {
        auto buttonArr = jsonObject.at("actionButtons");
        for (auto &btnObj : buttonArr) {
            auto pBtn = NotificationActionButton::ConvertNotificationActionButton(targetUid, btnObj);
            if (pBtn == nullptr) {
                ANS_LOGE("Failed to parse actionButton!");
                return false;
            }

            target->actionButtons_.emplace_back(pBtn);
        }
    }

    return true;
}

bool NotificationRequest::ConvertJsonToNotificationDistributedOptions(
    NotificationRequest *target, const nlohmann::json &jsonObject)
{
    if (target == nullptr) {
        ANS_LOGE("Invalid input parameter");
        return false;
    }

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find("distributedOptions") != jsonEnd) {
        auto optObj = jsonObject.at("distributedOptions");
        if (!optObj.is_null()) {
            auto *pOpt = NotificationJsonConverter::ConvertFromJson<NotificationDistributedOptions>(optObj);
            if (pOpt == nullptr) {
                ANS_LOGE("Failed to parse distributedOptions!");
                return false;
            }

            target->distributedOptions_ = *pOpt;
            delete pOpt;
        }
    }

    return true;
}

bool NotificationRequest::ConvertJsonToNotificationFlags(
    NotificationRequest *target, const nlohmann::json &jsonObject)
{
    if (target == nullptr) {
        ANS_LOGE("Invalid input parameter");
        return false;
    }

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find("notificationFlags") != jsonEnd) {
        auto flagsObj = jsonObject.at("notificationFlags");
        if (!flagsObj.is_null()) {
            auto *pFlags = NotificationJsonConverter::ConvertFromJson<NotificationFlags>(flagsObj);
            if (pFlags == nullptr) {
                ANS_LOGE("Failed to parse notificationFlags!");
                return false;
            }

            target->notificationFlags_ = std::shared_ptr<NotificationFlags>(pFlags);
        }
    }

    return true;
}

bool NotificationRequest::ConvertJsonToNotificationBundleOption(
    NotificationRequest *target, const nlohmann::json &jsonObject)
{
    if (target == nullptr) {
        ANS_LOGE("Invalid input parameter.");
        return false;
    }

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find("notificationBundleOption") != jsonEnd) {
        auto bundleOptionObj = jsonObject.at("notificationBundleOption");
        if (!bundleOptionObj.is_null()) {
            auto *pBundleOption = NotificationJsonConverter::ConvertFromJson<NotificationBundleOption>(bundleOptionObj);
            if (pBundleOption == nullptr) {
                ANS_LOGE("Failed to parse notificationBundleOption!");
                return false;
            }

            target->notificationBundleOption_ = std::shared_ptr<NotificationBundleOption>(pBundleOption);
        }
    }

    return true;
}

bool NotificationRequest::ConvertJsonToAgentBundle(
    NotificationRequest *target, const nlohmann::json &jsonObject)
{
    if (target == nullptr) {
        ANS_LOGE("Invalid input parameter.");
        return false;
    }

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find("agentBundle") != jsonEnd) {
        auto bundleOptionObj = jsonObject.at("agentBundle");
        if (!bundleOptionObj.is_null()) {
            auto *pBundleOption = NotificationJsonConverter::ConvertFromJson<NotificationBundleOption>(bundleOptionObj);
            if (pBundleOption == nullptr) {
                ANS_LOGE("Failed to parse agentBundle!");
                return false;
            }

            target->agentBundle_ = std::shared_ptr<NotificationBundleOption>(pBundleOption);
        }
    }

    return true;
}

bool NotificationRequest::IsCommonLiveView() const
{
    return (slotType_ == NotificationConstant::SlotType::LIVE_VIEW) &&
        (notificationContentType_ == NotificationContent::Type::LIVE_VIEW);
}

bool NotificationRequest::IsSystemLiveView() const
{
    return (slotType_ == NotificationConstant::SlotType::LIVE_VIEW) &&
        (notificationContentType_ == NotificationContent::Type::LOCAL_LIVE_VIEW);
}

ErrCode NotificationRequest::CheckVersion(const sptr<NotificationRequest> &oldRequest) const
{
    auto content = notificationContent_->GetNotificationContent();
    auto liveView = std::static_pointer_cast<NotificationLiveViewContent>(content);
    auto oldContent = oldRequest->GetContent()->GetNotificationContent();
    auto oldLiveView = std::static_pointer_cast<NotificationLiveViewContent>(oldContent);

    if (oldLiveView->GetVersion() == NotificationLiveViewContent::MAX_VERSION) {
        return ERR_OK;
    }
    if (liveView->GetVersion() == NotificationLiveViewContent::MAX_VERSION) {
        ANS_LOGE("Invalid version, creator bundle name %{public}s, id %{public}d, "
            "old version %{public}u, new version %{public}u.", GetCreatorBundleName().c_str(),
            GetNotificationId(), oldLiveView->GetVersion(), liveView->GetVersion());
        return ERR_ANS_EXPIRED_NOTIFICATION;
    }
    if (oldLiveView->GetVersion() >= liveView->GetVersion()) {
        ANS_LOGE("Live view has finished, creator bundle name %{public}s, id %{public}d, "
            "old version %{public}u, new version %{public}u.", GetCreatorBundleName().c_str(),
            GetNotificationId(), oldLiveView->GetVersion(), liveView->GetVersion());
        return ERR_ANS_EXPIRED_NOTIFICATION;
    }
    return ERR_OK;
}

ErrCode NotificationRequest::CheckNotificationRequest(const sptr<NotificationRequest> &oldRequest) const
{
    if (!IsCommonLiveView()) {
        if ((oldRequest != nullptr) && oldRequest->IsCommonLiveView()) {
            ANS_LOGE("Invalid new request param, slot type %{public}d, content type %{public}d.",
                GetSlotType(), GetNotificationType());
            return ERR_ANS_INVALID_PARAM;
        }
        return ERR_OK;
    }

    using StatusType = NotificationLiveViewContent::LiveViewStatus;
    auto content = notificationContent_->GetNotificationContent();
    auto liveView = std::static_pointer_cast<NotificationLiveViewContent>(content);
    auto status = liveView->GetLiveViewStatus();
    if (oldRequest == nullptr) {
        if (status != StatusType::LIVE_VIEW_CREATE) {
            ANS_LOGE("Doesn't exist live view, bundle name %{public}s, id %{public}d.",
                GetCreatorBundleName().c_str(), GetNotificationId());
            return ERR_ANS_NOTIFICATION_NOT_EXISTS;
        }
        return ERR_OK;
    }

    if (!oldRequest->IsCommonLiveView()) {
        ANS_LOGE("Invalid old request param, slot type %{public}d, content type %{public}d.",
            oldRequest->GetSlotType(), oldRequest->GetNotificationType());
        return ERR_ANS_INVALID_PARAM;
    }

    if (status == StatusType::LIVE_VIEW_CREATE) {
        ANS_LOGW("Repeat create live view, bundle name %{public}s, id %{public}d.",
            GetCreatorBundleName().c_str(), GetNotificationId());
        return ERR_ANS_REPEAT_CREATE;
    }

    auto oldContent = oldRequest->GetContent()->GetNotificationContent();
    auto oldLiveView = std::static_pointer_cast<NotificationLiveViewContent>(oldContent);
    auto oldStatus = oldLiveView->GetLiveViewStatus();
    if (oldStatus == StatusType::LIVE_VIEW_END) {
        ANS_LOGW("Live view has finished, bundle name %{public}s, id %{public}d.",
            GetCreatorBundleName().c_str(), GetNotificationId());
        return ERR_ANS_END_NOTIFICATION;
    }

    return CheckVersion(oldRequest);
}

void NotificationRequest::FillMissingParameters(const sptr<NotificationRequest> &oldRequest)
{
    if (!IsCommonLiveView() || (oldRequest == nullptr)) {
        return;
    }

    updateDeadLine_ = oldRequest->updateDeadLine_;
    finishDeadLine_ = oldRequest->finishDeadLine_;
    if (autoDeletedTime_ == NotificationConstant::INVALID_AUTO_DELETE_TIME) {
        autoDeletedTime_ = oldRequest->autoDeletedTime_;
    }
    if (wantAgent_ == nullptr) {
        wantAgent_ = oldRequest->wantAgent_;
    }

    auto content = notificationContent_->GetNotificationContent();
    auto newLiveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(content);
    if (newLiveViewContent->GetLiveViewStatus() ==
        NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE) {
        return;
    }
    auto newExtraInfo = newLiveViewContent->GetExtraInfo();
    auto oldContent = oldRequest->GetContent()->GetNotificationContent();
    auto oldLiveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(oldContent);
    auto oldExtraInfo = oldLiveViewContent->GetExtraInfo();
    if (newExtraInfo == nullptr) {
        newLiveViewContent->SetExtraInfo(oldExtraInfo);
    } else if (oldExtraInfo != nullptr) {
        auto oldKeySet = oldExtraInfo->KeySet();
        for (const auto &key : oldKeySet) {
            if (!newExtraInfo->HasParam(key)) {
                newExtraInfo->SetParam(key, oldExtraInfo->GetParam(key));
            }
        }
    }

    auto oldIsOnlyLocalUpdate = oldLiveViewContent->GetIsOnlyLocalUpdate();
    if (oldIsOnlyLocalUpdate!= newLiveViewContent->GetIsOnlyLocalUpdate()) {
        newLiveViewContent->SetIsOnlyLocalUpdate(oldIsOnlyLocalUpdate);
    }

    auto newPicture = newLiveViewContent->GetPicture();
    auto oldPicture = oldLiveViewContent->GetPicture();
    bool isSet = false;
    for (const auto &pictureRecord : oldPicture) {
        if (newPicture.find(pictureRecord.first) != newPicture.end()) {
            continue;
        }
        newPicture[pictureRecord.first] = pictureRecord.second;
        isSet = true;
    }
    if (isSet) {
        newLiveViewContent->SetPicture(newPicture);
    }
}

std::string NotificationRequest::GetBaseKey(const std::string &deviceId)
{
    const char *keySpliter = "_";

    std::stringstream stream;
    uint32_t hashCodeGeneratetype = GetHashCodeGenerateType();
    if (IsAgentNotification()) {
        if (hashCodeGeneratetype ==  1) {
            stream << deviceId << keySpliter <<
                creatorUserId_ << keySpliter << creatorUid_ << keySpliter <<
                ownerUserId_ << keySpliter << label_ << keySpliter << notificationId_;
        } else {
            stream << deviceId << keySpliter <<
                ownerUserId_ << keySpliter << ownerUid_ << keySpliter <<
                ownerBundleName_ << keySpliter << label_ << keySpliter << notificationId_;
        }
    } else {
        stream << deviceId << keySpliter << creatorUserId_ << keySpliter <<
            creatorUid_ << keySpliter << creatorBundleName_ << keySpliter <<
            label_ << keySpliter << notificationId_;
    }
    return stream.str();
}

std::string NotificationRequest::GetKey()
{
    std::stringstream stream;
    const char *keySpliter = "_";
    stream << REQUEST_STORAGE_KEY_PREFIX << keySpliter << GetBaseKey("");
    return stream.str();
}

std::string NotificationRequest::GetSecureKey()
{
    std::stringstream stream;
    const char *keySpliter = "_";
    stream << REQUEST_STORAGE_SECURE_KEY_PREFIX << keySpliter << GetBaseKey("");
    return stream.str();
}

bool NotificationRequest::CheckImageOverSizeForPixelMap(
    const std::shared_ptr<Media::PixelMap> &pixelMap, uint32_t maxSize)
{
    if (pixelMap == nullptr) {
        return false;
    }

    auto size = static_cast<uint32_t>(pixelMap->GetByteCount());
    return size > maxSize;
}

ErrCode NotificationRequest::CheckImageSizeForConverSation(std::shared_ptr<NotificationBasicContent> &content)
{
    auto conversationalContent = std::static_pointer_cast<NotificationConversationalContent>(content);
    auto picture = conversationalContent->GetMessageUser().GetPixelMap();
    if (CheckImageOverSizeForPixelMap(picture, MAX_ICON_SIZE)) {
        ANS_LOGE("The size of picture in ConversationalContent's message user exceeds limit");
        return ERR_ANS_ICON_OVER_SIZE;
    }

    auto messages = conversationalContent->GetAllConversationalMessages();
    for (auto &msg : messages) {
        if (!msg) {
            continue;
        }
        auto img = msg->GetSender().GetPixelMap();
        if (CheckImageOverSizeForPixelMap(img, MAX_ICON_SIZE)) {
            ANS_LOGE("The size of picture in ConversationalContent's message exceeds limit");
            return ERR_ANS_ICON_OVER_SIZE;
        }
    }
    return ERR_OK;
}

ErrCode NotificationRequest::CheckImageSizeForPicture(std::shared_ptr<NotificationBasicContent> &content)
{
    auto pictureContent = std::static_pointer_cast<NotificationPictureContent>(content);
    auto bigPicture = pictureContent->GetBigPicture();
    if (CheckImageOverSizeForPixelMap(bigPicture, MAX_PICTURE_SIZE)) {
        ANS_LOGE("The size of big picture in PictureContent exceeds limit");
        return ERR_ANS_PICTURE_OVER_SIZE;
    }
    return ERR_OK;
}

ErrCode NotificationRequest::CheckImageSizeForLiveView(std::shared_ptr<NotificationBasicContent> &content)
{
    auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(content);
    auto pictureMap = liveViewContent->GetPicture();
    for (const auto &pixelMapRecord : pictureMap) {
        if (pixelMapRecord.second.empty()) {
            ANS_LOGE("Picture key exist, but picture content is empty.");
            return ERR_ANS_INVALID_PARAM;
        }
        if (pixelMapRecord.second.size() > MAX_LIVE_VIEW_ICON_NUM) {
            ANS_LOGE("Picture key exist, but picture content count exceeds limit.");
            return ERR_ANS_INVALID_PARAM;
        }
        for (const auto &pixelMap : pixelMapRecord.second) {
            if (CheckImageOverSizeForPixelMap(pixelMap, MAX_ICON_SIZE)) {
                ANS_LOGE("The size of big picture in PictureContent exceeds limit.");
                return ERR_ANS_ICON_OVER_SIZE;
            }
        }
    }
    return ERR_OK;
}

ErrCode NotificationRequest::CheckImageSizeForContent() const
{
    auto content = GetContent();
    if (content == nullptr) {
        ANS_LOGE("Invalid content in NotificationRequest");
        return ERR_OK;
    }

    auto basicContent = GetContent()->GetNotificationContent();
    if (basicContent == nullptr) {
        ANS_LOGE("Invalid content in NotificationRequest");
        return ERR_OK;
    }

    if (GetSlotType() == NotificationConstant::SlotType::LIVE_VIEW) {
        auto result = CheckLockScreenPictureSizeForLiveView(basicContent);
        if (result != ERR_OK) {
            return result;
        }
    }

    auto contentType = GetNotificationType();
    switch (contentType) {
        case NotificationContent::Type::CONVERSATION:
            return CheckImageSizeForConverSation(basicContent);
        case NotificationContent::Type::PICTURE:
            return CheckImageSizeForPicture(basicContent);
        case NotificationContent::Type::LIVE_VIEW:
            return CheckImageSizeForLiveView(basicContent);
        default:
            return ERR_OK;
    }
}

void NotificationRequest::SetIsCoverActionButtons(bool isCoverActionButtons)
{
    isCoverActionButtons_ = isCoverActionButtons;
}

bool NotificationRequest::IsCoverActionButtons() const
{
    return isCoverActionButtons_;
}

void NotificationRequest::SetAppMessageId(const std::string &appMessageId)
{
    appMessageId_ = appMessageId;
}

std::string NotificationRequest::GetAppMessageId() const
{
    return appMessageId_;
}

void NotificationRequest::SetSound(const std::string &sound)
{
    sound_ = sound;
}

std::string NotificationRequest::GetSound() const
{
    return sound_;
}

std::string NotificationRequest::GenerateUniqueKey()
{
    const char *keySpliter = "_";
    int typeFlag = 0;
    if (GetSlotType() == NotificationConstant::SlotType::LIVE_VIEW) {
        typeFlag = 1;
    }

    std::stringstream stream;
    if (IsAgentNotification()) {
        stream << ownerUid_ << keySpliter << ownerBundleName_ << keySpliter << ownerUserId_ << keySpliter <<
            typeFlag << keySpliter << appMessageId_;
    } else {
        stream << creatorUid_ << keySpliter << creatorBundleName_ << keySpliter << creatorUserId_ << keySpliter <<
            typeFlag << keySpliter << appMessageId_;
    }
    return stream.str();
}

void NotificationRequest::SetUnifiedGroupInfo(const std::shared_ptr<NotificationUnifiedGroupInfo> &unifiedGroupInfo)
{
    unifiedGroupInfo_ = unifiedGroupInfo;
}

std::shared_ptr<NotificationUnifiedGroupInfo> NotificationRequest::GetUnifiedGroupInfo() const
{
    return unifiedGroupInfo_;
}

ErrCode NotificationRequest::CheckLockScreenPictureSizeForLiveView(std::shared_ptr<NotificationBasicContent> &content)
{
    auto lockScreenPicture = content->GetLockScreenPicture();
    if (CheckImageOverSizeForPixelMap(lockScreenPicture, MAX_PICTURE_SIZE)) {
        ANS_LOGE("The size of lockScreen picture in live view exceeds limit");
        return ERR_ANS_PICTURE_OVER_SIZE;
    }
    return ERR_OK;
}

void NotificationRequest::SetPublishDelayTime(uint32_t delayTime)
{
    publishDelayTime_ = delayTime;
}

uint32_t NotificationRequest::GetPublishDelayTime() const
{
    return publishDelayTime_;
}

void NotificationRequest::SetUpdateByOwnerAllowed(bool isUpdateByOwnerAllowed)
{
    isUpdateByOwnerAllowed_ = isUpdateByOwnerAllowed;
}

bool NotificationRequest::IsUpdateByOwnerAllowed() const
{
    return isUpdateByOwnerAllowed_;
}

const std::string NotificationRequest::GetLittleIconType() const
{
    return littleIconType_;
}

void NotificationRequest::AdddeviceStatu(const std::string &deviceType,
    const std::string deviceStatu)
{
    deviceStatus_[deviceType] = deviceStatu;
}

const std::map<std::string, std::string> NotificationRequest::GetdeviceStatus() const
{
    return deviceStatus_;
}
}  // namespace Notification
}  // namespace OHOS
