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
#include "notification_preferences_info.h"

#include "ans_log_wrapper.h"
#include "notification_constant.h"
#include "bundle_manager_helper.h"

namespace OHOS {
namespace Notification {
namespace {
const static std::string KEY_UNDER_LINE = "_";
} // namespace

NotificationPreferencesInfo::BundleInfo::BundleInfo()
{
}

NotificationPreferencesInfo::BundleInfo::~BundleInfo()
{
}

void NotificationPreferencesInfo::BundleInfo::SetBundleName(const std::string &name)
{
    bundleName_ = name;
}

std::string NotificationPreferencesInfo::BundleInfo::GetBundleName() const
{
    return bundleName_;
}

void NotificationPreferencesInfo::BundleInfo::SetImportance(const int32_t &level)
{
    importance_ = level;
}

int32_t NotificationPreferencesInfo::BundleInfo::GetImportance() const
{
    return importance_;
}

void NotificationPreferencesInfo::BundleInfo::SetIsShowBadge(const bool &isShowBadge)
{
    isShowBadge_ = isShowBadge;
}

bool NotificationPreferencesInfo::BundleInfo::GetIsShowBadge() const
{
    return isShowBadge_;
}

void NotificationPreferencesInfo::BundleInfo::SetBadgeTotalNum(const int32_t &num)
{
    badgeTotalNum_ = num;
}

int32_t NotificationPreferencesInfo::BundleInfo::GetBadgeTotalNum() const
{
    return badgeTotalNum_;
}

void NotificationPreferencesInfo::BundleInfo::SetEnableNotification(const bool &enable)
{
    isEnabledNotification_ = enable;
}

bool NotificationPreferencesInfo::BundleInfo::GetEnableNotification() const
{
    return isEnabledNotification_;
}


void NotificationPreferencesInfo::BundleInfo::SetHasPoppedDialog(const bool &hasPopped)
{
    hasPoppedDialog_ = hasPopped;
}

bool NotificationPreferencesInfo::BundleInfo::GetHasPoppedDialog() const
{
    return hasPoppedDialog_;
}

void NotificationPreferencesInfo::BundleInfo::SetSlot(const sptr<NotificationSlot> &slot)
{
    slots_.insert_or_assign(slot->GetType(), slot);
}

bool NotificationPreferencesInfo::BundleInfo::GetSlot(
    const NotificationConstant::SlotType &type, sptr<NotificationSlot> &slot) const
{
    auto iter = slots_.find(type);
    if (iter != slots_.end()) {
        slot = iter->second;
        return true;
    }
    return false;
}

const char* NotificationPreferencesInfo::BundleInfo::GetSlotFlagsKeyFromType(
    const NotificationConstant::SlotType &type) const
{
    switch (type) {
        case NotificationConstant::SlotType::SOCIAL_COMMUNICATION:
            return NotificationConstant::SLOTTYPECCMNAMES[NotificationConstant::SlotType::SOCIAL_COMMUNICATION];
        case NotificationConstant::SlotType::SERVICE_REMINDER:
            return NotificationConstant::SLOTTYPECCMNAMES[NotificationConstant::SlotType::SERVICE_REMINDER];
        case NotificationConstant::SlotType::CONTENT_INFORMATION:
            return NotificationConstant::SLOTTYPECCMNAMES[NotificationConstant::SlotType::CONTENT_INFORMATION];
        case NotificationConstant::SlotType::OTHER:
            return NotificationConstant::SLOTTYPECCMNAMES[NotificationConstant::SlotType::OTHER];
        case NotificationConstant::SlotType::CUSTOM:
            return NotificationConstant::SLOTTYPECCMNAMES[NotificationConstant::SlotType::CUSTOM];
        case NotificationConstant::SlotType::LIVE_VIEW:
            return NotificationConstant::SLOTTYPECCMNAMES[NotificationConstant::SlotType::LIVE_VIEW];
        case NotificationConstant::SlotType::CUSTOMER_SERVICE:
            return NotificationConstant::SLOTTYPECCMNAMES[NotificationConstant::SlotType::CUSTOMER_SERVICE];
        case NotificationConstant::SlotType::EMERGENCY_INFORMATION:
            return NotificationConstant::SLOTTYPECCMNAMES[NotificationConstant::SlotType::EMERGENCY_INFORMATION];
        default:
            return nullptr;
    }
}

void NotificationPreferencesInfo::BundleInfo::SetSlotFlagsForSlot(
    const NotificationConstant::SlotType &type)
{
    uint32_t bundleSlotFlags = GetSlotFlags();
    std::string key = GetSlotFlagsKeyFromType(type);
    std::map<std::string, uint32_t>& slotFlagsDefaultMap = AdvancedNotificationService::GetDefaultSlotConfig();
    if (slotFlagsDefaultMap.find(key) == slotFlagsDefaultMap.end()) {
        return;
    }
    uint32_t finalSlotFlags = bundleSlotFlags&slotFlagsDefaultMap[key];
    if (slotFlagsMap_.find(key) == slotFlagsMap_.end()) {
        slotFlagsMap_.insert_or_assign(key, finalSlotFlags);
    } else {
        for (auto it = slotFlagsMap_.begin(); it != slotFlagsMap_.end(); ++it) {
            if (it->first.compare(key) == 0 && it->second != finalSlotFlags) {
                    it->second = finalSlotFlags;
                }
        }
    }
}

uint32_t NotificationPreferencesInfo::BundleInfo::GetSlotFlagsForSlot(const NotificationConstant::SlotType &type) const
{
    std::string key = GetSlotFlagsKeyFromType(type);
    auto it = slotFlagsMap_.find(key);
    if (it != slotFlagsMap_.end()) {
        return it->second;
    } else {
        return 0;
    }
}

bool NotificationPreferencesInfo::BundleInfo::GetAllSlots(std::vector<sptr<NotificationSlot>> &slots)
{
    slots.clear();
    std::for_each(slots_.begin(),
        slots_.end(),
        [&slots](std::map<NotificationConstant::SlotType, sptr<NotificationSlot>>::reference iter) {
            slots.emplace_back(iter.second);
        });
    return true;
}

uint32_t NotificationPreferencesInfo::BundleInfo::GetAllSlotsSize()
{
    return slots_.size();
}

bool NotificationPreferencesInfo::BundleInfo::IsExsitSlot(const NotificationConstant::SlotType &type) const
{
    auto iter = slots_.find(type);
    return (iter != slots_.end());
}

bool NotificationPreferencesInfo::BundleInfo::RemoveSlot(const NotificationConstant::SlotType &type)
{
    auto iter = slots_.find(type);
    if (iter != slots_.end()) {
        slots_.erase(iter);
        return true;
    }
    return false;
}

uint32_t NotificationPreferencesInfo::BundleInfo::GetSlotFlags()
{
    return slotFlags_;
}

void NotificationPreferencesInfo::BundleInfo::SetSlotFlags(uint32_t slotFlags)
{
    slotFlags_ = slotFlags;
}

void NotificationPreferencesInfo::BundleInfo::RemoveAllSlots()
{
    slots_.clear();
}

void NotificationPreferencesInfo::BundleInfo::SetBundleUid(const int32_t &uid)
{
    uid_ = uid;
}

int32_t NotificationPreferencesInfo::BundleInfo::GetBundleUid() const
{
    return uid_;
}

void NotificationPreferencesInfo::SetBundleInfo(BundleInfo &info)
{
    std::string bundleKey = info.GetBundleName().append(std::to_string(info.GetBundleUid()));
    infos_.insert_or_assign(bundleKey, info);
}

bool NotificationPreferencesInfo::GetBundleInfo(
    const sptr<NotificationBundleOption> &bundleOption, BundleInfo &info) const
{
    std::string bundleKey = bundleOption->GetBundleName() + std::to_string(bundleOption->GetUid());
    auto iter = infos_.find(bundleKey);
    if (iter != infos_.end()) {
        info = iter->second;
        return true;
    }
    return false;
}

bool NotificationPreferencesInfo::RemoveBundleInfo(const sptr<NotificationBundleOption> &bundleOption)
{
    std::string bundleKey = bundleOption->GetBundleName() + std::to_string(bundleOption->GetUid());
    auto iter = infos_.find(bundleKey);
    if (iter != infos_.end()) {
        infos_.erase(iter);
        return true;
    }
    return false;
}

bool NotificationPreferencesInfo::IsExsitBundleInfo(const sptr<NotificationBundleOption> &bundleOption) const
{
    std::string bundleKey = bundleOption->GetBundleName() + std::to_string(bundleOption->GetUid());
    auto iter = infos_.find(bundleKey);
    if (iter != infos_.end()) {
        return true;
    }
    return false;
}

void NotificationPreferencesInfo::ClearBundleInfo()
{
    infos_.clear();
}

void NotificationPreferencesInfo::SetDoNotDisturbDate(const int32_t &userId,
    const sptr<NotificationDoNotDisturbDate> &doNotDisturbDate)
{
    doNotDisturbDate_.insert_or_assign(userId, doNotDisturbDate);
}

std::string NotificationPreferencesInfo::MakeDoNotDisturbProfileKey(int32_t userId, int64_t profileId)
{
    return std::to_string(userId).append(KEY_UNDER_LINE).append(std::to_string(profileId));
}

void NotificationPreferencesInfo::AddDoNotDisturbProfiles(
    int32_t userId, const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    for (auto profile : profiles) {
        if (profile == nullptr) {
            ANS_LOGE("The profile is nullptr.");
            continue;
        }
        std::string key = MakeDoNotDisturbProfileKey(userId, profile->GetProfileId());
        ANS_LOGI("AddDoNotDisturbProfiles key: %{public}s.", key.c_str());
        doNotDisturbProfiles_.insert_or_assign(key, profile);
    }
}

void NotificationPreferencesInfo::RemoveDoNotDisturbProfiles(
    int32_t userId, const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    for (auto profile : profiles) {
        if (profile == nullptr) {
            ANS_LOGE("The profile is nullptr.");
            continue;
        }
        std::string key = MakeDoNotDisturbProfileKey(userId, profile->GetProfileId());
        ANS_LOGI("RemoveDoNotDisturbProfiles  key: %{public}s.", key.c_str());
        doNotDisturbProfiles_.erase(key);
    }
}

bool NotificationPreferencesInfo::GetDoNotDisturbProfiles(
    int64_t profileId, int32_t userId, sptr<NotificationDoNotDisturbProfile> &profile)
{
    if (profile == nullptr) {
        ANS_LOGE("The profile is nullptr.");
        return false;
    }
    std::string key = MakeDoNotDisturbProfileKey(userId, profileId);
    auto iter = doNotDisturbProfiles_.find(key);
    if (iter != doNotDisturbProfiles_.end()) {
        profile = iter->second;
        return true;
    }
    return false;
}

void NotificationPreferencesInfo::GetAllDoNotDisturbProfiles(
    int32_t userId, std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    for (const auto &doNotDisturbProfile : doNotDisturbProfiles_) {
        std::string key = doNotDisturbProfile.first;
        ANS_LOGI("GetAllDoNotDisturbProfiles key: %{public}s.", key.c_str());
        auto result = key.find(std::to_string(userId));
        if (result != std::string::npos) {
            auto profile = doNotDisturbProfile.second;
            profiles.emplace_back(profile);
        }
    }
}

void NotificationPreferencesInfo::GetAllCLoneBundlesInfo(const int32_t &userId,
    const std::unordered_map<std::string, std::string> &bunlesMap,
    std::vector<NotificationCloneBundleInfo> &cloneBundles)
{
    for (const auto& bundleItem : bunlesMap) {
        auto iter = infos_.find(bundleItem.second);
        if (iter == infos_.end()) {
            ANS_LOGI("No finde bundle info %{public}s.", bundleItem.second.c_str());
            continue;
        }

        std::vector<sptr<NotificationSlot>> slots;
        NotificationCloneBundleInfo cloneBundleInfo;
        int32_t index = BundleManagerHelper::GetInstance()->GetAppIndexByUid(iter->second.GetBundleUid());
        cloneBundleInfo.SetBundleName(iter->second.GetBundleName());
        cloneBundleInfo.SetAppIndex(index);
        cloneBundleInfo.SetSlotFlags(iter->second.GetSlotFlags());
        cloneBundleInfo.SetIsShowBadge(iter->second.GetIsShowBadge());
        cloneBundleInfo.SetEnableNotification(iter->second.GetEnableNotification());
        iter->second.GetAllSlots(slots);
        for (auto& slot : slots) {
            NotificationCloneBundleInfo::SlotInfo slotInfo;
            slotInfo.slotType_ = slot->GetType();
            slotInfo.enable_ = slot->GetEnable();
            slotInfo.isForceControl_ = slot->GetForceControl();
            cloneBundleInfo.AddSlotInfo(slotInfo);
        }
        cloneBundles.emplace_back(cloneBundleInfo);
    }
    ANS_LOGI("GetAllCLoneBundlesInfo size: %{public}zu.", cloneBundles.size());
}

bool NotificationPreferencesInfo::GetDoNotDisturbDate(const int32_t &userId,
    sptr<NotificationDoNotDisturbDate> &doNotDisturbDate) const
{
    auto iter = doNotDisturbDate_.find(userId);
    if (iter != doNotDisturbDate_.end()) {
        doNotDisturbDate = iter->second;
        return true;
    }
    return false;
}

void NotificationPreferencesInfo::SetEnabledAllNotification(const int32_t &userId, const bool &enable)
{
    isEnabledAllNotification_.insert_or_assign(userId, enable);
}

bool NotificationPreferencesInfo::GetEnabledAllNotification(const int32_t &userId, bool &enable) const
{
    auto iter = isEnabledAllNotification_.find(userId);
    if (iter != isEnabledAllNotification_.end()) {
        enable = iter->second;
        return true;
    }
    return false;
}

void NotificationPreferencesInfo::RemoveNotificationEnable(const int32_t userId)
{
    isEnabledAllNotification_.erase(userId);
}

void NotificationPreferencesInfo::RemoveDoNotDisturbDate(const int32_t userId)
{
    doNotDisturbDate_.erase(userId);
}

void NotificationPreferencesInfo::SetBundleInfoFromDb(BundleInfo &info, std::string bundleKey)
{
    infos_.insert_or_assign(bundleKey, info);
}

void NotificationPreferencesInfo::SetDisableNotificationInfo(const sptr<NotificationDisable> &notificationDisable)
{
    if (notificationDisable == nullptr) {
        ANS_LOGE("the notificationDisable is nullptr");
        return;
    }
    if (notificationDisable->GetBundleList().empty()) {
        ANS_LOGE("the bundle list is empty");
        return;
    }
    DisableNotificationInfo disableNotificationInfo;
    if (notificationDisable->GetDisabled()) {
        disableNotificationInfo_.disabled = 1;
    } else {
        disableNotificationInfo_.disabled = 0;
    }
    disableNotificationInfo_.bundleList = notificationDisable->GetBundleList();
}

bool NotificationPreferencesInfo::GetDisableNotificationInfo(NotificationDisable &notificationDisable)
{
    if (disableNotificationInfo_.disabled == -1) {
        ANS_LOGD("notificationDisable is invalid");
        return false;
    }
    if (disableNotificationInfo_.bundleList.empty()) {
        ANS_LOGE("notificationDisable bundleList is empty");
        return false;
    }
    notificationDisable.SetDisabled(disableNotificationInfo_.disabled);
    notificationDisable.SetBundleList(disableNotificationInfo_.bundleList);
    return true;
}

void NotificationPreferencesInfo::SetkioskAppTrustList(const std::vector<std::string> &kioskAppTrustList)
{
    kioskAppTrustList_ = kioskAppTrustList;
}

bool NotificationPreferencesInfo::GetkioskAppTrustList(std::vector<std::string> &kioskAppTrustList) const
{
    if (kioskAppTrustList_.empty()) {
        ANS_LOGE("kioskAppTrustList is empty");
        return false;
    }
    kioskAppTrustList = kioskAppTrustList_;
    return true;
}

void NotificationPreferencesInfo::AddDisableNotificationInfo(const std::string &value)
{
    NotificationDisable notificationDisable;
    notificationDisable.FromJson(value);
    DisableNotificationInfo disableNotificationInfo;
    if (notificationDisable.GetDisabled()) {
        disableNotificationInfo_.disabled = 1;
    } else {
        disableNotificationInfo_.disabled = 0;
    }
    disableNotificationInfo_.bundleList = notificationDisable.GetBundleList();
}

ErrCode NotificationPreferencesInfo::GetAllLiveViewEnabledBundles(const int32_t userId,
    std::vector<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("Called.");
    auto iter = isEnabledAllNotification_.find(userId);
    if (iter == isEnabledAllNotification_.end()) {
        ANS_LOGW("Get user all notification info failed.");
        return ERR_OK;
    }

    if (iter->second == false) {
        ANS_LOGI("Get user all notification enable is false.");
        return ERR_OK;
    }

    sptr<NotificationSlot> liveSlot;
    for (auto bundleInfo : infos_) {
        if (!bundleInfo.second.GetSlot(NotificationConstant::SlotType::LIVE_VIEW, liveSlot)) {
            continue;
        }
        if (liveSlot->GetEnable()) {
            NotificationBundleOption bundleItem(bundleInfo.second.GetBundleName(), bundleInfo.second.GetBundleUid());
            bundleOption.push_back(bundleItem);
        }
    }
    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS
