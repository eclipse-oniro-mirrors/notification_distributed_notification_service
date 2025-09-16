/*
* Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "notification_clone_bundle_info.h"

#include "ans_log_wrapper.h"
#include "notification_slot.h"

namespace OHOS {
namespace Notification {
using ExtensionSubscriptionVectorPtr = std::vector<sptr<NotificationExtensionSubscriptionInfo>>;
namespace {
constexpr const char *BUNDLE_INFO_NAME = "name";
constexpr const char *BUNDLE_INFO_APP_INDEX = "index";
constexpr const char *BUNDLE_INFO_SLOT_FLAGS = "slotFlags";
constexpr const char *BUNDLE_INFO_SHOW_BADGE = "badge";
constexpr const char *BUNDLE_INFO_ENABLE_NOTIFICATION = "enable";
constexpr const char *BUNDLE_INFO_SLOT_LIST = "slotList";
constexpr const char *BUNDLE_INFO_SLOT_TYPE = "slotType";
constexpr const char *BUNDLE_INFO_SLOT_ENABLE = "slotEnable";
constexpr const char *BUNDLE_INFO_SLOT_CONTROL = "slotControl";
constexpr const char *BUNDLE_INFO_SILENT_REMINDER = "enabledSilentReminder";
constexpr const char *BUNDLE_INFO_SLOT_AUTHSTATUS = "slotAuthorized";
constexpr const char *BUNDLE_INFO_SUBSCRIPTION_INFO = "extensionSubscriptionInfo";
constexpr int32_t CONST_ENABLE_INT = 1;
}
void NotificationCloneBundleInfo::SetBundleName(const std::string &name)
{
    bundleName_ = name;
}

std::string NotificationCloneBundleInfo::GetBundleName() const
{
    return bundleName_;
}

void NotificationCloneBundleInfo::SetAppIndex(const int32_t &appIndex)
{
    appIndex_ = appIndex;
}

int32_t NotificationCloneBundleInfo::GetAppIndex() const
{
    return appIndex_;
}

void NotificationCloneBundleInfo::SetUid(const int32_t &uid)
{
    uid_ = uid;
}

int32_t NotificationCloneBundleInfo::GetUid() const
{
    return uid_;
}

void NotificationCloneBundleInfo::SetSlotFlags(const uint32_t &slotFlags)
{
    slotFlags_ = slotFlags;
}

uint32_t NotificationCloneBundleInfo::GetSlotFlags() const
{
    return slotFlags_;
}

void NotificationCloneBundleInfo::SetIsShowBadge(const bool &isShowBadge)
{
    isShowBadge_ = isShowBadge;
}

bool NotificationCloneBundleInfo::GetIsShowBadge() const
{
    return isShowBadge_;
}

void NotificationCloneBundleInfo::SetEnableNotification(const NotificationConstant::SWITCH_STATE &state)
{
    isEnabledNotification_ = state;
}

NotificationConstant::SWITCH_STATE NotificationCloneBundleInfo::GetEnableNotification() const
{
    return isEnabledNotification_;
}

void NotificationCloneBundleInfo::SetSilentReminderEnabled(
    const NotificationConstant::SWITCH_STATE &silentReminderEnabled)
{
    silentReminderEnabled_ = silentReminderEnabled;
}

NotificationConstant::SWITCH_STATE NotificationCloneBundleInfo::GetSilentReminderEnabled() const
{
    return silentReminderEnabled_;
}

void NotificationCloneBundleInfo::AddSlotInfo(const SlotInfo &slotInfo)
{
    for (auto& item : slotsInfo_) {
        if (item.slotType_ == slotInfo.slotType_) {
            item.enable_ = slotInfo.enable_;
            item.isForceControl_ = slotInfo.isForceControl_;
            item.authorizedStatus_ = slotInfo.authorizedStatus_;
            return;
        }
    }
    slotsInfo_.push_back(slotInfo);
}

std::vector<NotificationCloneBundleInfo::SlotInfo> NotificationCloneBundleInfo::GetSlotInfo() const
{
    return slotsInfo_;
}

void NotificationCloneBundleInfo::SetExtensionSubscriptionInfos(
    const std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos)
{
    extensionSubscriptionInfos_ = infos;
}

const ExtensionSubscriptionVectorPtr& NotificationCloneBundleInfo::GetExtensionSubscriptionInfos() const
{
    return extensionSubscriptionInfos_;
}

void NotificationCloneBundleInfo::ToJson(nlohmann::json &jsonObject) const
{
    if (!slotsInfo_.empty()) {
        nlohmann::json jsonNodes = nlohmann::json::array();
        for (size_t index = 0; index < slotsInfo_.size(); index++) {
            nlohmann::json jsonNode;
            jsonNode[BUNDLE_INFO_SLOT_TYPE] = static_cast<int32_t>(slotsInfo_[index].slotType_);
            jsonNode[BUNDLE_INFO_SLOT_ENABLE] = slotsInfo_[index].enable_ ? 1 : 0;
            jsonNode[BUNDLE_INFO_SLOT_CONTROL] = slotsInfo_[index].isForceControl_ ? 1 : 0;
            jsonNode[BUNDLE_INFO_SLOT_AUTHSTATUS] = slotsInfo_[index].authorizedStatus_ ? 1 : 0;
            jsonNodes.emplace_back(jsonNode);
        }
        jsonObject[BUNDLE_INFO_SLOT_LIST] = jsonNodes;
    }

    if (!extensionSubscriptionInfos_.empty()) {
        nlohmann::json jsonNodes = nlohmann::json::array();
        for (const auto& info : extensionSubscriptionInfos_) {
            nlohmann::json jsonNode;
            info->ToJson(jsonNode);
            jsonNodes.emplace_back(jsonNode);
        }
        jsonObject[BUNDLE_INFO_SUBSCRIPTION_INFO] = jsonNodes;
    }

    jsonObject[BUNDLE_INFO_NAME] =  bundleName_;
    jsonObject[BUNDLE_INFO_APP_INDEX] =  appIndex_;
    jsonObject[BUNDLE_INFO_SLOT_FLAGS] =  slotFlags_;
    jsonObject[BUNDLE_INFO_SHOW_BADGE] =  isShowBadge_ ? 1 : 0;
    jsonObject[BUNDLE_INFO_ENABLE_NOTIFICATION] =  static_cast<int32_t>(isEnabledNotification_);
    jsonObject[BUNDLE_INFO_SILENT_REMINDER] =  static_cast<int32_t>(silentReminderEnabled_);
}

void NotificationCloneBundleInfo::SlotsFromJson(const nlohmann::json &jsonObject)
{
    if (!jsonObject.contains(BUNDLE_INFO_SLOT_LIST) || !jsonObject[BUNDLE_INFO_SLOT_LIST].is_array()) {
        return;
    }

    for (auto &slotJson : jsonObject.at(BUNDLE_INFO_SLOT_LIST)) {
        SlotInfo slotInfo;
        if (slotJson.contains(BUNDLE_INFO_SLOT_TYPE) && slotJson[BUNDLE_INFO_SLOT_TYPE].is_number()) {
            slotInfo.slotType_ = static_cast<NotificationConstant::SlotType>(
                slotJson.at(BUNDLE_INFO_SLOT_TYPE).get<int32_t>());
        }
        if (slotJson.contains(BUNDLE_INFO_SLOT_ENABLE) && slotJson[BUNDLE_INFO_SLOT_ENABLE].is_number()) {
            int32_t slotEnable = slotJson.at(BUNDLE_INFO_SLOT_ENABLE).get<int32_t>();
            slotInfo.enable_ = (slotEnable == CONST_ENABLE_INT);
        }
        if (slotJson.contains(BUNDLE_INFO_SLOT_CONTROL) && slotJson[BUNDLE_INFO_SLOT_CONTROL].is_number()) {
            int32_t forceControl = slotJson.at(BUNDLE_INFO_SLOT_CONTROL).get<int32_t>();
            slotInfo.isForceControl_ = (forceControl == CONST_ENABLE_INT);
        }
        if (slotJson.contains(BUNDLE_INFO_SLOT_AUTHSTATUS) && slotJson[BUNDLE_INFO_SLOT_AUTHSTATUS].is_number()) {
            int32_t auth = slotJson.at(BUNDLE_INFO_SLOT_AUTHSTATUS).get<int32_t>();
            slotInfo.authorizedStatus_ = (auth == CONST_ENABLE_INT);
        }
        slotsInfo_.emplace_back(slotInfo);
    }
}

void NotificationCloneBundleInfo::SubscriptionInfosFromJson(const nlohmann::json &jsonObject)
{
    if (!jsonObject.contains(BUNDLE_INFO_SUBSCRIPTION_INFO) || !jsonObject[BUNDLE_INFO_SUBSCRIPTION_INFO].is_array()) {
        return;
    }

    for (auto &infoJson : jsonObject.at(BUNDLE_INFO_SUBSCRIPTION_INFO)) {
        extensionSubscriptionInfos_.emplace_back(NotificationExtensionSubscriptionInfo::FromJson(infoJson));
    }
}

void NotificationCloneBundleInfo::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() || !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return;
    }
    if (jsonObject.is_discarded()) {
        ANS_LOGE("Failed to parse json string.");
        return;
    }

    if (jsonObject.contains(BUNDLE_INFO_NAME) && jsonObject[BUNDLE_INFO_NAME].is_string()) {
        bundleName_ = jsonObject.at(BUNDLE_INFO_NAME).get<std::string>();
    }
    if (jsonObject.contains(BUNDLE_INFO_APP_INDEX) && jsonObject[BUNDLE_INFO_APP_INDEX].is_number()) {
        appIndex_ = jsonObject.at(BUNDLE_INFO_APP_INDEX).get<int32_t>();
    }
    if (jsonObject.contains(BUNDLE_INFO_SLOT_FLAGS) && jsonObject[BUNDLE_INFO_SLOT_FLAGS].is_number()) {
        slotFlags_ = jsonObject.at(BUNDLE_INFO_SLOT_FLAGS).get<uint32_t>();
    }
    if (jsonObject.contains(BUNDLE_INFO_SHOW_BADGE) && jsonObject[BUNDLE_INFO_SHOW_BADGE].is_number()) {
        int32_t showBadge = jsonObject.at(BUNDLE_INFO_SHOW_BADGE).get<int32_t>();
        isShowBadge_ = (showBadge == CONST_ENABLE_INT);
    }
    if (jsonObject.contains(BUNDLE_INFO_ENABLE_NOTIFICATION) &&
        jsonObject[BUNDLE_INFO_ENABLE_NOTIFICATION].is_number()) {
        int32_t enabledNotification = jsonObject.at(BUNDLE_INFO_ENABLE_NOTIFICATION).get<int32_t>();
        if (enabledNotification >= static_cast<int32_t>(NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF) &&
            enabledNotification <= static_cast<int32_t>(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON)) {
            isEnabledNotification_ = static_cast<NotificationConstant::SWITCH_STATE>(enabledNotification);
        }
    }
    if (jsonObject.contains(BUNDLE_INFO_SILENT_REMINDER) && jsonObject[BUNDLE_INFO_SILENT_REMINDER].is_number()) {
        int32_t silentReminderEnabled = jsonObject.at(BUNDLE_INFO_SILENT_REMINDER).get<int32_t>();
        if (silentReminderEnabled >= static_cast<int32_t>(NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF) &&
            silentReminderEnabled <= static_cast<int32_t>(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON)) {
            silentReminderEnabled_ = static_cast<NotificationConstant::SWITCH_STATE>(silentReminderEnabled);
        }
    }
    SlotsFromJson(jsonObject);
    SubscriptionInfosFromJson(jsonObject);
}
std::string NotificationCloneBundleInfo::SlotInfo::Dump() const
{
    return "type: " + std::to_string(slotType_) + " " + std::to_string(enable_) + " "
        + std::to_string(isForceControl_)  + " " + std::to_string(authorizedStatus_);
}

int32_t NotificationCloneBundleInfo::SlotInfo::GetAuthStaus() const
{
    return authorizedStatus_ ? NotificationSlot::AuthorizedStatus::AUTHORIZED :
        NotificationSlot::AuthorizedStatus::NOT_AUTHORIZED;
}

std::string NotificationCloneBundleInfo::Dump() const
{
    std::string slotDump = "{";
    for (auto& slot : slotsInfo_) {
        slotDump += slot.Dump();
        slotDump += ",";
    }
    slotDump += "}";
    return "CloneBundle{ name = " + bundleName_ +
            ", index = " + std::to_string(appIndex_) +
            ", uid = " + std::to_string(uid_) +
            ", slotFlags = " + std::to_string(slotFlags_) +
            ", ShowBadge = " + std::to_string(isShowBadge_) +
            ", isEnabled = " + std::to_string(static_cast<int32_t>(isEnabledNotification_)) +
            ", slotsInfo = " + slotDump +
            ", silentReminderEnabled = " + std::to_string(static_cast<int32_t>(silentReminderEnabled_)) +
            " }";
}
}
}
