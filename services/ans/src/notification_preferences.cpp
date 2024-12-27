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

#include "notification_preferences.h"

#include <fstream>
#include <memory>
#include <mutex>

#include "access_token_helper.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_permission_def.h"
#include "bundle_manager_helper.h"
#include "hitrace_meter_adapter.h"
#include "nlohmann/json.hpp"
#include "os_account_manager_helper.h"
#include "notification_analytics_util.h"
#include "notification_config_parse.h"

namespace OHOS {
namespace Notification {
namespace {
const static std::string KEY_BUNDLE_LABEL = "label_ans_bundle_";
}
std::mutex NotificationPreferences::instanceMutex_;
std::shared_ptr<NotificationPreferences> NotificationPreferences::instance_;

NotificationPreferences::NotificationPreferences()
{
    preferncesDB_ = std::make_unique<NotificationPreferencesDatabase>();
    if (preferncesDB_ == nullptr) {
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_7, EventBranchId::BRANCH_1)
           .Message("preferncesDB is null.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
    }
    InitSettingFromDisturbDB();
}

std::shared_ptr<NotificationPreferences> NotificationPreferences::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(instanceMutex_);
        if (instance_ == nullptr) {
            auto instance = std::make_shared<NotificationPreferences>();
            instance_ = instance;
        }
    }
    return instance_;
}

ErrCode NotificationPreferences::AddNotificationSlots(
    const sptr<NotificationBundleOption> &bundleOption, const std::vector<sptr<NotificationSlot>> &slots)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_5, EventBranchId::BRANCH_6)
        .BundleName(bundleOption == nullptr ? "" : bundleOption->GetBundleName());
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty() || slots.empty()) {
        message.Message("Invalid param.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    ErrCode result = ERR_OK;
    for (auto slot : slots) {
        result = CheckSlotForCreateSlot(bundleOption, slot, preferencesInfo);
        if (result != ERR_OK) {
            return result;
        }
    }

    ANS_LOGD("ffrt: add slot to db!");
    if (result == ERR_OK &&
        (!preferncesDB_->PutSlotsToDisturbeDB(bundleOption->GetBundleName(), bundleOption->GetUid(), slots))) {
        message.Message("put slot for to db failed.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }

    if (result == ERR_OK) {
        preferencesInfo_ = preferencesInfo;
    }
    return result;
}

ErrCode NotificationPreferences::AddNotificationBundleProperty(const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    preferencesInfo.SetBundleInfo(bundleInfo);
    ErrCode result = ERR_OK;
    if (preferncesDB_->PutBundlePropertyToDisturbeDB(bundleInfo)) {
        preferencesInfo_ = preferencesInfo;
    } else {
        result = ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
    ANS_LOGD("AddNotificationBundleProperty.result: %{public}d", result);
    return result;
}

ErrCode NotificationPreferences::RemoveNotificationSlot(
    const sptr<NotificationBundleOption> &bundleOption, const NotificationConstant::SlotType &slotType)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_5, EventBranchId::BRANCH_5);
    message.Message(bundleOption->GetBundleName() + "_" +std::to_string(bundleOption->GetUid()) +
        " slotType: " + std::to_string(static_cast<uint32_t>(slotType)));
    message.SlotType(static_cast<uint32_t>(slotType));
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    ErrCode result = ERR_OK;
    result = CheckSlotForRemoveSlot(bundleOption, slotType, preferencesInfo);
    if (result == ERR_OK &&
        (!preferncesDB_->RemoveSlotFromDisturbeDB(GenerateBundleKey(bundleOption), slotType, bundleOption->GetUid()))) {
        message.ErrorCode(result).Append(" Remove slot failed.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("%{public}s_%{public}d, remove slot failed.",
            bundleOption->GetBundleName().c_str(), bundleOption->GetUid());
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }

    if (result == ERR_OK) {
        preferencesInfo_ = preferencesInfo;
    }
    ANS_LOGI("%{public}s_%{public}d, Remove slot successful.",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid());
    return result;
}

ErrCode NotificationPreferences::RemoveNotificationAllSlots(const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_5, EventBranchId::BRANCH_3);
    message.Message(bundleOption->GetBundleName() + "_" +std::to_string(bundleOption->GetUid()));
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    ErrCode result = ERR_OK;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    if (GetBundleInfo(preferencesInfo, bundleOption, bundleInfo)) {
        bundleInfo.RemoveAllSlots();
        preferencesInfo.SetBundleInfo(bundleInfo);
        if (!preferncesDB_->RemoveAllSlotsFromDisturbeDB(GenerateBundleKey(bundleOption), bundleOption->GetUid())) {
            result = ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
            message.ErrorCode(result).Append(" Db operation failed.");
            ANS_LOGE("%{public}s_%{public}d, Db operation failed.",
                bundleOption->GetBundleName().c_str(), bundleOption->GetUid());
        }
    } else {
        result = ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST;
        message.ErrorCode(result).Append(" Notification bundle not exist.");
        ANS_LOGE("%{public}s_%{public}d, Notification bundle not exist.",
            bundleOption->GetBundleName().c_str(), bundleOption->GetUid());
    }

    if (result == ERR_OK) {
        preferencesInfo_ = preferencesInfo;
        message.ErrorCode(result).Append(" Remove all slot successful.");
        ANS_LOGI("%{public}s_%{public}d, Remove all slot successful.",
            bundleOption->GetBundleName().c_str(), bundleOption->GetUid());
    }
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    return result;
}

ErrCode NotificationPreferences::RemoveNotificationForBundle(const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;

    ErrCode result = ERR_OK;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    if (GetBundleInfo(preferencesInfo, bundleOption, bundleInfo)) {
        preferencesInfo.RemoveBundleInfo(bundleOption);
        if (!preferncesDB_->RemoveBundleFromDisturbeDB(GenerateBundleKey(bundleOption), bundleOption->GetUid())) {
            result = ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
        }
    } else {
        result = ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST;
    }

    if (result == ERR_OK) {
        preferencesInfo_ = preferencesInfo;
    }

    return result;
}

ErrCode NotificationPreferences::UpdateNotificationSlots(
    const sptr<NotificationBundleOption> &bundleOption, const std::vector<sptr<NotificationSlot>> &slots)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty() || slots.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_5, EventBranchId::BRANCH_2)
        .BundleName(bundleOption->GetBundleName());
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    ErrCode result = ERR_OK;
    for (auto slotIter : slots) {
        result = CheckSlotForUpdateSlot(bundleOption, slotIter, preferencesInfo);
        if (result != ERR_OK) {
            message.Message("Check slot for update failed." + std::to_string(result));
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            return result;
        }
    }

    if ((result == ERR_OK) &&
        (!preferncesDB_->PutSlotsToDisturbeDB(bundleOption->GetBundleName(), bundleOption->GetUid(), slots))) {
        message.Message("Update put slot for to db failed.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }

    if (result == ERR_OK) {
        preferencesInfo_ = preferencesInfo;
    }

    return result;
}

ErrCode NotificationPreferences::GetNotificationSlot(const sptr<NotificationBundleOption> &bundleOption,
    const NotificationConstant::SlotType &type, sptr<NotificationSlot> &slot)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    if (GetBundleInfo(preferencesInfo_, bundleOption, bundleInfo)) {
        if (!bundleInfo.GetSlot(type, slot)) {
            result = ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST;
        }
    } else {
        ANS_LOGW("bundle not exist");
        result = ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST;
    }
    ANS_LOGD("%{public}s status  = %{public}d ", __FUNCTION__, result);
    return result;
}

ErrCode NotificationPreferences::GetNotificationAllSlots(
    const sptr<NotificationBundleOption> &bundleOption, std::vector<sptr<NotificationSlot>> &slots)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    if (GetBundleInfo(preferencesInfo_, bundleOption, bundleInfo)) {
        bundleInfo.GetAllSlots(slots);
    } else {
        ANS_LOGW("Notification bundle does not exsit.");
        result = ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST;
    }

    return result;
}

ErrCode NotificationPreferences::GetNotificationSlotsNumForBundle(
    const sptr<NotificationBundleOption> &bundleOption, uint64_t &num)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    if (GetBundleInfo(preferencesInfo_, bundleOption, bundleInfo)) {
        num = static_cast<uint64_t>(bundleInfo.GetAllSlotsSize());
    } else {
        result = ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST;
    }
    return result;
}

ErrCode NotificationPreferences::GetNotificationSlotFlagsForBundle(
    const sptr<NotificationBundleOption> &bundleOption, uint32_t &slotFlags)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    return GetBundleProperty(bundleOption, BundleType::BUNDLE_SLOTFLGS_TYPE, slotFlags);
}

bool NotificationPreferences::IsNotificationSlotFlagsExists(
    const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return false;
    }
    return preferncesDB_->IsNotificationSlotFlagsExists(bundleOption);
}

ErrCode NotificationPreferences::SetNotificationSlotFlagsForBundle(
    const sptr<NotificationBundleOption> &bundleOption, uint32_t slotFlags)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    ErrCode result = SetBundleProperty(preferencesInfo, bundleOption, BundleType::BUNDLE_SLOTFLGS_TYPE, slotFlags);
    if (result == ERR_OK) {
        preferencesInfo_ = preferencesInfo;
    }
    return result;
}

ErrCode NotificationPreferences::IsShowBadge(const sptr<NotificationBundleOption> &bundleOption, bool &enable)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }
    return GetBundleProperty(bundleOption, BundleType::BUNDLE_SHOW_BADGE_TYPE, enable);
}

ErrCode NotificationPreferences::SetShowBadge(const sptr<NotificationBundleOption> &bundleOption, const bool enable)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    ErrCode result = SetBundleProperty(preferencesInfo, bundleOption, BundleType::BUNDLE_SHOW_BADGE_TYPE, enable);
    if (result == ERR_OK) {
        preferencesInfo_ = preferencesInfo;
    }
    return result;
}

ErrCode NotificationPreferences::GetImportance(const sptr<NotificationBundleOption> &bundleOption, int32_t &importance)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    return GetBundleProperty(bundleOption, BundleType::BUNDLE_IMPORTANCE_TYPE, importance);
}


ErrCode NotificationPreferences::SetImportance(
    const sptr<NotificationBundleOption> &bundleOption, const int32_t &importance)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    ErrCode result = SetBundleProperty(preferencesInfo, bundleOption, BundleType::BUNDLE_IMPORTANCE_TYPE, importance);
    if (result == ERR_OK) {
        preferencesInfo_ = preferencesInfo;
    }
    return result;
}

ErrCode NotificationPreferences::GetTotalBadgeNums(
    const sptr<NotificationBundleOption> &bundleOption, int32_t &totalBadgeNum)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }
    return GetBundleProperty(bundleOption, BundleType::BUNDLE_BADGE_TOTAL_NUM_TYPE, totalBadgeNum);
}

ErrCode NotificationPreferences::SetTotalBadgeNums(
    const sptr<NotificationBundleOption> &bundleOption, const int32_t num)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    ErrCode result = SetBundleProperty(preferencesInfo, bundleOption, BundleType::BUNDLE_BADGE_TOTAL_NUM_TYPE, num);
    if (result == ERR_OK) {
        preferencesInfo_ = preferencesInfo;
    }
    return result;
}

ErrCode NotificationPreferences::GetNotificationsEnabledForBundle(
    const sptr<NotificationBundleOption> &bundleOption, bool &enabled)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }
    return GetBundleProperty(bundleOption, BundleType::BUNDLE_ENABLE_NOTIFICATION_TYPE, enabled);
}

ErrCode NotificationPreferences::SetNotificationsEnabledForBundle(
    const sptr<NotificationBundleOption> &bundleOption, const bool enabled)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    ErrCode result =
        SetBundleProperty(preferencesInfo, bundleOption, BundleType::BUNDLE_ENABLE_NOTIFICATION_TYPE, enabled);
    if (result == ERR_OK) {
        preferencesInfo_ = preferencesInfo;
    }
    return result;
}

ErrCode NotificationPreferences::GetNotificationsEnabled(const int32_t &userId, bool &enabled)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    if (!preferencesInfo_.GetEnabledAllNotification(userId, enabled)) {
        result = ERR_ANS_INVALID_PARAM;
    }
    return result;
}

ErrCode NotificationPreferences::SetNotificationsEnabled(const int32_t &userId, const bool &enabled)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        return ERR_ANS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    preferencesInfo.SetEnabledAllNotification(userId, enabled);
    ErrCode result = ERR_OK;
    if (!preferncesDB_->PutNotificationsEnabled(userId, enabled)) {
        result = ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }

    if (result == ERR_OK) {
        preferencesInfo_ = preferencesInfo;
    }
    return result;
}

ErrCode NotificationPreferences::GetHasPoppedDialog(const sptr<NotificationBundleOption> &bundleOption, bool &hasPopped)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }
    return GetBundleProperty(bundleOption, BundleType::BUNDLE_POPPED_DIALOG_TYPE, hasPopped);
}

ErrCode NotificationPreferences::SetHasPoppedDialog(const sptr<NotificationBundleOption> &bundleOption, bool hasPopped)
{
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    ErrCode result = ERR_OK;
    result = SetBundleProperty(preferencesInfo, bundleOption, BundleType::BUNDLE_POPPED_DIALOG_TYPE, hasPopped);
    if (result == ERR_OK) {
        preferencesInfo_ = preferencesInfo;
    }
    return result;
}

ErrCode NotificationPreferences::GetDoNotDisturbDate(const int32_t &userId,
    sptr<NotificationDoNotDisturbDate> &date)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    if (!preferencesInfo.GetDoNotDisturbDate(userId, date)) {
        result = ERR_ANS_INVALID_PARAM;
    }
    return result;
}

ErrCode NotificationPreferences::SetDoNotDisturbDate(const int32_t &userId,
    const sptr<NotificationDoNotDisturbDate> date)
{
    ANS_LOGE("enter.");
    if (userId <= SUBSCRIBE_USER_INIT) {
        return ERR_ANS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    preferencesInfo.SetDoNotDisturbDate(userId, date);

    ErrCode result = ERR_OK;
    if (!preferncesDB_->PutDoNotDisturbDate(userId, date)) {
        result = ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }

    if (result == ERR_OK) {
        preferencesInfo_ = preferencesInfo;
    }
    return result;
}

bool NotificationPreferences::CheckDoNotDisturbProfileID(int32_t profileId)
{
    if (profileId < DO_NOT_DISTURB_PROFILE_MIN_ID || profileId > DO_NOT_DISTURB_PROFILE_MAX_ID) {
        ANS_LOGE("The profile id is out of range.");
        return false;
    }
    return true;
}

ErrCode NotificationPreferences::AddDoNotDisturbProfiles(
    int32_t userId, std::vector<sptr<NotificationDoNotDisturbProfile>> profiles)
{
    ANS_LOGD("Called.");
    for (auto profile : profiles) {
        if (profile == nullptr) {
            ANS_LOGE("The profile is nullptr.");
            return ERR_ANS_INVALID_PARAM;
        }
        if (!CheckDoNotDisturbProfileID(profile->GetProfileId())) {
            return ERR_ANS_INVALID_PARAM;
        }
        auto trustList = profile->GetProfileTrustList();
        for (auto& bundleInfo : trustList) {
            int32_t index = BundleManagerHelper::GetInstance()->GetAppIndexByUid(bundleInfo.GetUid());
            bundleInfo.SetAppIndex(index);
            ANS_LOGI("Get app index by uid %{public}d %{public}s %{public}d", bundleInfo.GetUid(),
                bundleInfo.GetBundleName().c_str(), index);
        }
        profile->SetProfileTrustList(trustList);
    }
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    preferencesInfo.AddDoNotDisturbProfiles(userId, profiles);
    if (preferncesDB_ == nullptr) {
        ANS_LOGE("The prefernces db is nullptr.");
        return ERR_ANS_SERVICE_NOT_READY;
    }
    if (!preferncesDB_->AddDoNotDisturbProfiles(userId, profiles)) {
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
    preferencesInfo_ = preferencesInfo;
    return ERR_OK;
}

bool NotificationPreferences::GetBundleInfo(NotificationPreferencesInfo &preferencesInfo,
    const sptr<NotificationBundleOption> &bundleOption, NotificationPreferencesInfo::BundleInfo &info) const
{
    if (preferencesInfo.GetBundleInfo(bundleOption, info)) {
        return true;
    } else if (preferncesDB_->GetBundleInfo(bundleOption, info)) {
        preferencesInfo.SetBundleInfo(info);
        return true;
    }
    return false;
}

ErrCode NotificationPreferences::RemoveDoNotDisturbProfiles(
    int32_t userId, const std::vector<sptr<NotificationDoNotDisturbProfile>> profiles)
{
    ANS_LOGD("Called.");
    for (auto profile : profiles) {
        if (profile == nullptr) {
            ANS_LOGE("The profile is nullptr.");
            return ERR_ANS_INVALID_PARAM;
        }
        if (!CheckDoNotDisturbProfileID(profile->GetProfileId())) {
            return ERR_ANS_INVALID_PARAM;
        }
    }
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    preferencesInfo.RemoveDoNotDisturbProfiles(userId, profiles);
    if (preferncesDB_ == nullptr) {
        ANS_LOGE("The prefernces db is nullptr.");
        return ERR_ANS_SERVICE_NOT_READY;
    }
    if (!preferncesDB_->RemoveDoNotDisturbProfiles(userId, profiles)) {
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
    preferencesInfo_ = preferencesInfo;
    return ERR_OK;
}

void NotificationPreferences::UpdateProfilesUtil(std::vector<NotificationBundleOption>& trustList,
    const std::vector<NotificationBundleOption> bundleList)
{
    for (auto& item : bundleList) {
        bool exit = false;
        for (auto& bundle: trustList) {
            if (item.GetUid() == bundle.GetUid()) {
                exit = true;
                break;
            }
        }
        if (!exit) {
            trustList.push_back(item);
        }
    }
}

ErrCode NotificationPreferences::UpdateDoNotDisturbProfiles(int32_t userId, int32_t profileId,
    const std::string& name, const std::vector<NotificationBundleOption>& bundleList)
{
    ANS_LOGI("Called update Profile %{public}d %{public}d %{public}zu.", userId, profileId, bundleList.size());
    if (!CheckDoNotDisturbProfileID(profileId) || bundleList.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    if (preferencesInfo.GetDoNotDisturbProfiles(profileId, userId, profile)) {
        auto trustList = profile->GetProfileTrustList();
        UpdateProfilesUtil(trustList, bundleList);
        profile->SetProfileTrustList(trustList);
    } else {
        profile->SetProfileId(profileId);
        profile->SetProfileName(name);
        profile->SetProfileTrustList(bundleList);
    }
    ANS_LOGI("Update profile %{public}d %{public}d %{public}zu", userId, profile->GetProfileId(),
        profile->GetProfileTrustList().size());
    preferencesInfo.AddDoNotDisturbProfiles(userId, {profile});
    if (preferncesDB_ == nullptr) {
        ANS_LOGE("The prefernces db is nullptr.");
        return ERR_ANS_SERVICE_NOT_READY;
    }
    if (!preferncesDB_->AddDoNotDisturbProfiles(userId, {profile})) {
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
    preferencesInfo_ = preferencesInfo;
    return ERR_OK;
}

void NotificationPreferences::UpdateCloneBundleInfo(int32_t userId,
    const NotificationCloneBundleInfo& cloneBundleInfo)
{
    ANS_LOGI("Event bundle update %{public}s.", cloneBundleInfo.Dump().c_str());
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bundleOption->SetBundleName(cloneBundleInfo.GetBundleName());
    bundleOption->SetUid(cloneBundleInfo.GetUid());
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    if (!GetBundleInfo(preferencesInfo, bundleOption, bundleInfo)) {
        bundleInfo.SetBundleName(cloneBundleInfo.GetBundleName());
        bundleInfo.SetBundleUid(cloneBundleInfo.GetUid());
    }

    /* after clone, override these witch */
    bundleInfo.SetSlotFlags(cloneBundleInfo.GetSlotFlags());
    bundleInfo.SetIsShowBadge(cloneBundleInfo.GetIsShowBadge());
    bundleInfo.SetEnableNotification(cloneBundleInfo.GetEnableNotification());
    /* update property to db */
    if (!preferncesDB_->UpdateBundlePropertyToDisturbeDB(userId, bundleInfo)) {
        ANS_LOGW("Clone bundle info failed %{public}s.", cloneBundleInfo.Dump().c_str());
        return;
    }
    preferencesInfo.SetBundleInfo(bundleInfo);

    /* update slot info */
    std::vector<sptr<NotificationSlot>> slots;
    for (auto& cloneSlot : cloneBundleInfo.GetSlotInfo()) {
        sptr<NotificationSlot> slotInfo = new (std::nothrow) NotificationSlot(cloneSlot.slotType_);
        uint32_t slotFlags = bundleInfo.GetSlotFlags();
        auto configSlotReminderMode = DelayedSingleton<NotificationConfigParse>::GetInstance()->
            GetConfigSlotReminderModeByType(slotInfo->GetType(), bundleOption);
        slotInfo->SetReminderMode(configSlotReminderMode & slotFlags);
        slotInfo->SetEnable(cloneSlot.enable_);
        slotInfo->SetForceControl(cloneSlot.isForceControl_);
        slotInfo->SetAuthorizedStatus(NotificationSlot::AuthorizedStatus::AUTHORIZED);
        slots.push_back(slotInfo);
        bundleInfo.SetSlot(slotInfo);
    }

    if (!preferncesDB_->UpdateBundleSlotToDisturbeDB(userId, cloneBundleInfo.GetBundleName(),
        cloneBundleInfo.GetUid(), slots)) {
        ANS_LOGW("Clone bundle slot failed %{public}s.", cloneBundleInfo.Dump().c_str());
        preferencesInfo_ = preferencesInfo;
        return;
    }
    preferencesInfo.SetBundleInfo(bundleInfo);
    preferencesInfo_ = preferencesInfo;
}

void NotificationPreferences::GetAllCLoneBundlesInfo(int32_t userId,
    std::vector<NotificationCloneBundleInfo> &cloneBundles)
{
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    std::unordered_map<std::string, std::string> bundlesMap;
    if (GetBatchKvsFromDb(KEY_BUNDLE_LABEL, bundlesMap, userId) != ERR_OK) {
        ANS_LOGE("Get bundle map info failed.");
        return;
    }
    preferencesInfo.GetAllCLoneBundlesInfo(userId, bundlesMap, cloneBundles);
    preferencesInfo_ = preferencesInfo;
}

void NotificationPreferences::GetDoNotDisturbProfileListByUserId(int32_t userId,
    std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    preferencesInfo_.GetAllDoNotDisturbProfiles(userId, profiles);
}

ErrCode NotificationPreferences::GetAllNotificationEnabledBundles(std::vector<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("Called.");
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    if (preferncesDB_ == nullptr) {
        return ERR_ANS_SERVICE_NOT_READY;
    }
    if (!preferncesDB_->GetAllNotificationEnabledBundles(bundleOption)) {
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
    return ERR_OK;
}

ErrCode NotificationPreferences::ClearNotificationInRestoreFactorySettings()
{
    ErrCode result = ERR_OK;
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    if (!preferncesDB_->RemoveAllDataFromDisturbeDB()) {
        result = ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }

    if (result == ERR_OK) {
        preferencesInfo_ = NotificationPreferencesInfo();
    }
    return result;
}

ErrCode NotificationPreferences::GetDoNotDisturbProfile(
    int32_t profileId, int32_t userId, sptr<NotificationDoNotDisturbProfile> &profile)
{
    if (!CheckDoNotDisturbProfileID(profileId)) {
        return ERR_ANS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    if (!preferencesInfo_.GetDoNotDisturbProfiles(profileId, userId, profile)) {
        return ERR_ANS_NO_PROFILE_TEMPLATE;
    }
    return ERR_OK;
}

void NotificationPreferences::RemoveDoNotDisturbProfileTrustList(
    int32_t userId, const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("The bundle option is nullptr.");
        return;
    }
    int32_t uid = bundleOption->GetUid();
    int32_t appIndex = bundleOption->GetAppIndex();
    auto bundleName = bundleOption->GetBundleName();
    ANS_LOGI("Remove %{public}s %{public}d %{public}d.", bundleName.c_str(), uid, appIndex);
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;

    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    preferencesInfo.GetAllDoNotDisturbProfiles(userId, profiles);
    for (auto profile : profiles) {
        if (profile == nullptr) {
            ANS_LOGE("The profile is nullptr.");
            continue;
        }
        auto trustList = profile->GetProfileTrustList();
        for (auto it = trustList.begin(); it != trustList.end(); it++) {
            if (it->GetUid() == uid) {
                trustList.erase(it);
                break;
            }
        }
        profile->SetProfileTrustList(trustList);
    }
    preferencesInfo.AddDoNotDisturbProfiles(userId, profiles);
    if (preferncesDB_ == nullptr) {
        ANS_LOGE("The prefernces db is nullptr.");
        return;
    }
    if (!preferncesDB_->AddDoNotDisturbProfiles(userId, profiles)) {
        return;
    }
    preferencesInfo_ = preferencesInfo;
}

ErrCode NotificationPreferences::CheckSlotForCreateSlot(const sptr<NotificationBundleOption> &bundleOption,
    const sptr<NotificationSlot> &slot, NotificationPreferencesInfo &preferencesInfo) const
{
    if (slot == nullptr) {
        ANS_LOGE("Notification slot is nullptr.");
        return ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_NOT_EXIST;
    }

    NotificationPreferencesInfo::BundleInfo bundleInfo;
    if (!GetBundleInfo(preferencesInfo, bundleOption, bundleInfo)) {
        bundleInfo.SetBundleName(bundleOption->GetBundleName());
        bundleInfo.SetBundleUid(bundleOption->GetUid());
        bundleInfo.SetEnableNotification(CheckApiCompatibility(bundleOption));
    }
    bundleInfo.SetSlot(slot);
    preferencesInfo.SetBundleInfo(bundleInfo);

    return ERR_OK;
}

ErrCode NotificationPreferences::CheckSlotForRemoveSlot(const sptr<NotificationBundleOption> &bundleOption,
    const NotificationConstant::SlotType &slotType, NotificationPreferencesInfo &preferencesInfo) const
{
    ErrCode result = ERR_OK;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    if (GetBundleInfo(preferencesInfo, bundleOption, bundleInfo)) {
        if (bundleInfo.IsExsitSlot(slotType)) {
            bundleInfo.RemoveSlot(slotType);
            preferencesInfo.SetBundleInfo(bundleInfo);
        } else {
            ANS_LOGE("Notification slot type does not exsited.");
            result = ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST;
        }
    } else {
        ANS_LOGW("Notification bundle does not exsit.");
        result = ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST;
    }
    return result;
}

ErrCode NotificationPreferences::CheckSlotForUpdateSlot(const sptr<NotificationBundleOption> &bundleOption,
    const sptr<NotificationSlot> &slot, NotificationPreferencesInfo &preferencesInfo) const
{
    if (slot == nullptr) {
        ANS_LOGE("Notification slot is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    if (GetBundleInfo(preferencesInfo, bundleOption, bundleInfo)) {
        if (bundleInfo.IsExsitSlot(slot->GetType())) {
            bundleInfo.SetBundleName(bundleOption->GetBundleName());
            bundleInfo.SetBundleUid(bundleOption->GetUid());
            bundleInfo.SetSlot(slot);
            preferencesInfo.SetBundleInfo(bundleInfo);
        } else {
            ANS_LOGE("Notification slot type does not exist.");
            result = ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST;
        }
    } else {
        ANS_LOGW("Notification bundle does not exsit.");
        result = ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST;
    }

    return result;
}

template <typename T>
ErrCode NotificationPreferences::SetBundleProperty(NotificationPreferencesInfo &preferencesInfo,
    const sptr<NotificationBundleOption> &bundleOption, const BundleType &type, const T &value)
{
    ErrCode result = ERR_OK;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    if (!GetBundleInfo(preferencesInfo_, bundleOption, bundleInfo)) {
        bundleInfo.SetBundleName(bundleOption->GetBundleName());
        bundleInfo.SetBundleUid(bundleOption->GetUid());
        bundleInfo.SetEnableNotification(CheckApiCompatibility(bundleOption));
    }
    result = SaveBundleProperty(bundleInfo, bundleOption, type, value);
    if (result == ERR_OK) {
        preferencesInfo.SetBundleInfo(bundleInfo);
    }

    return result;
}

template <typename T>
ErrCode NotificationPreferences::SaveBundleProperty(NotificationPreferencesInfo::BundleInfo &bundleInfo,
    const sptr<NotificationBundleOption> &bundleOption, const BundleType &type, const T &value)
{
    bool storeDBResult = true;
    switch (type) {
        case BundleType::BUNDLE_IMPORTANCE_TYPE:
            bundleInfo.SetImportance(value);
            storeDBResult = preferncesDB_->PutImportance(bundleInfo, value);
            break;
        case BundleType::BUNDLE_BADGE_TOTAL_NUM_TYPE:
            bundleInfo.SetBadgeTotalNum(value);
            storeDBResult = preferncesDB_->PutTotalBadgeNums(bundleInfo, value);
            break;
        case BundleType::BUNDLE_SHOW_BADGE_TYPE:
            bundleInfo.SetIsShowBadge(value);
            storeDBResult = preferncesDB_->PutShowBadge(bundleInfo, value);
            break;
        case BundleType::BUNDLE_ENABLE_NOTIFICATION_TYPE:
            bundleInfo.SetEnableNotification(value);
            storeDBResult = preferncesDB_->PutNotificationsEnabledForBundle(bundleInfo, value);
            break;
        case BundleType::BUNDLE_POPPED_DIALOG_TYPE:
            ANS_LOGI("Into BUNDLE_POPPED_DIALOG_TYPE:SetHasPoppedDialog.");
            bundleInfo.SetHasPoppedDialog(value);
            storeDBResult = preferncesDB_->PutHasPoppedDialog(bundleInfo, value);
            break;
        case BundleType::BUNDLE_SLOTFLGS_TYPE:
            ANS_LOGI("Into BUNDLE_SLOTFLGS_TYPE:SetSlotFlags.");
            bundleInfo.SetSlotFlags(value);
            storeDBResult = preferncesDB_->PutSlotFlags(bundleInfo, value);
            break;
        default:
            break;
    }
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

template <typename T>
ErrCode NotificationPreferences::GetBundleProperty(
    const sptr<NotificationBundleOption> &bundleOption, const BundleType &type, T &value)
{
    ErrCode result = ERR_OK;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    if (GetBundleInfo(preferencesInfo_, bundleOption, bundleInfo)) {
        switch (type) {
            case BundleType::BUNDLE_IMPORTANCE_TYPE:
                value = bundleInfo.GetImportance();
                break;
            case BundleType::BUNDLE_BADGE_TOTAL_NUM_TYPE:
                value = bundleInfo.GetBadgeTotalNum();
                break;
            case BundleType::BUNDLE_SHOW_BADGE_TYPE:
                value = bundleInfo.GetIsShowBadge();
                break;
            case BundleType::BUNDLE_ENABLE_NOTIFICATION_TYPE:
                value = bundleInfo.GetEnableNotification();
                break;
            case BundleType::BUNDLE_POPPED_DIALOG_TYPE:
                ANS_LOGD("Into BUNDLE_POPPED_DIALOG_TYPE:GetHasPoppedDialog.");
                value = bundleInfo.GetHasPoppedDialog();
                break;
            case BundleType::BUNDLE_SLOTFLGS_TYPE:
                value = bundleInfo.GetSlotFlags();
                ANS_LOGD("Into BUNDLE_SLOTFLGS_TYPE:GetSlotFlags.");
                break;
            default:
                result = ERR_ANS_INVALID_PARAM;
                break;
        }
    } else {
        ANS_LOGW("Notification bundle does not exsit.");
        result = ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST;
    }
    return result;
}

std::string NotificationPreferences::GenerateBundleKey(const sptr<NotificationBundleOption> &bundleOption) const
{
    return bundleOption->GetBundleName().append(std::to_string(bundleOption->GetUid()));
}

ErrCode NotificationPreferences::GetTemplateSupported(const std::string& templateName, bool &support)
{
    if (templateName.length() == 0) {
        ANS_LOGE("template name is null.");
        return ERR_ANS_INVALID_PARAM;
    }

    std::ifstream inFile;
    inFile.open(DEFAULT_TEMPLATE_PATH.c_str(), std::ios::in);
    if (!inFile.is_open()) {
        ANS_LOGE("read template config error.");
        return ERR_ANS_PREFERENCES_NOTIFICATION_READ_TEMPLATE_CONFIG_FAILED;
    }

    nlohmann::json jsonObj;
    inFile >> jsonObj;
    if (jsonObj.is_null() || !jsonObj.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return ERR_ANS_PREFERENCES_NOTIFICATION_READ_TEMPLATE_CONFIG_FAILED;
    }
    if (jsonObj.is_discarded()) {
        ANS_LOGE("template json discarded error.");
        inFile.close();
        return ERR_ANS_PREFERENCES_NOTIFICATION_READ_TEMPLATE_CONFIG_FAILED;
    }

    if (jsonObj.contains(templateName)) {
        support = true;
    }

    jsonObj.clear();
    inFile.close();
    return ERR_OK;
}

ErrCode NotificationPreferences::SetDistributedEnabledByBundle(const sptr<NotificationBundleOption> &bundleOption,
    const std::string &deviceType, const bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleOption->GetBundleName());
    bundleInfo.SetBundleUid(bundleOption->GetUid());
    bundleInfo.SetEnableNotification(CheckApiCompatibility(bundleOption));
    bool storeDBResult = true;
    storeDBResult = preferncesDB_->PutDistributedEnabledForBundle(deviceType, bundleInfo, enabled);
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

ErrCode NotificationPreferences::IsDistributedEnabledByBundle(const sptr<NotificationBundleOption> &bundleOption,
    const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    std::lock_guard<std::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleOption->GetBundleName());
    bundleInfo.SetBundleUid(bundleOption->GetUid());
    bundleInfo.SetEnableNotification(CheckApiCompatibility(bundleOption));
    bool storeDBResult = true;
    storeDBResult = preferncesDB_->GetDistributedEnabledForBundle(deviceType, bundleInfo, enabled);
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

ErrCode NotificationPreferences::SetSmartReminderEnabled(const std::string &deviceType, const bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (deviceType.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    std::lock_guard<std::mutex> lock(preferenceMutex_);
    bool storeDBResult = true;
    storeDBResult = preferncesDB_->SetSmartReminderEnabled(deviceType, enabled);
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

ErrCode NotificationPreferences::IsSmartReminderEnabled(const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (deviceType.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    std::lock_guard<std::mutex> lock(preferenceMutex_);
    bool storeDBResult = true;
    storeDBResult = preferncesDB_->IsSmartReminderEnabled(deviceType, enabled);
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

void NotificationPreferences::InitSettingFromDisturbDB(int32_t userId)
{
    ANS_LOGI("%{public}s userId is %{public}d", __FUNCTION__, userId);
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    if (preferncesDB_ != nullptr) {
        preferncesDB_->ParseFromDisturbeDB(preferencesInfo_, userId);
    }
}

void NotificationPreferences::RemoveSettings(int32_t userId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    std::lock_guard<std::mutex> lock(preferenceMutex_);
    preferencesInfo_.RemoveNotificationEnable(userId);
    preferencesInfo_.RemoveDoNotDisturbDate(userId);
    if (preferncesDB_ != nullptr) {
        preferncesDB_->RemoveNotificationEnable(userId);
        preferncesDB_->RemoveDoNotDisturbDate(userId);
        preferncesDB_->DropUserTable(userId);
    }
}

bool NotificationPreferences::CheckApiCompatibility(const sptr<NotificationBundleOption> &bundleOption) const
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager == nullptr) {
        return false;
    }
    return bundleManager->CheckApiCompatibility(bundleOption);
}

void NotificationPreferences::RemoveAnsBundleDbInfo(const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGE("%{public}s", __FUNCTION__);
    if (preferncesDB_ != nullptr && bundleOption != nullptr) {
        preferncesDB_->RemoveAnsBundleDbInfo(bundleOption->GetBundleName(), bundleOption->GetUid());
    }
}

void NotificationPreferences::RemoveEnabledDbByBundle(const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGE("%{public}s", __FUNCTION__);
    if (preferncesDB_ != nullptr && bundleOption != nullptr) {
        std::lock_guard<std::mutex> lock(preferenceMutex_);
        preferncesDB_->RemoveEnabledDbByBundleName(bundleOption->GetBundleName(), bundleOption->GetUid());
    }
}

bool NotificationPreferences::GetBundleSoundPermission(bool &allPackage, std::set<std::string> &bundleNames)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    std::string value = "";
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetCurrentCallingUserId(userId);
    if (GetKvFromDb("RING_TRUSTLIST_PKG", value, userId) != ERR_OK) {
        ANS_LOGD("Get bundle sound permission failed.");
        return false;
    }

    ANS_LOGD("The bundle permission is :%{public}s.", value.c_str());
    nlohmann::json jsonPermission = nlohmann::json::parse(value, nullptr, false);
    if (jsonPermission.is_null() || jsonPermission.empty()) {
        ANS_LOGE("Invalid JSON object");
        return false;
    }
    if (jsonPermission.is_discarded() || !jsonPermission.is_array()) {
        ANS_LOGE("Parse bundle permission failed due to data is discarded or not array");
        return false;
    }

    for (const auto &item : jsonPermission) {
        bundleNames.insert(item);
        if (item == "ALL_PKG") {
            allPackage = true;
        }
    }
    return true;
}

int32_t NotificationPreferences::SetKvToDb(
    const std::string &key, const std::string &value, const int32_t &userId)
{
    if (preferncesDB_ == nullptr) {
        return ERR_ANS_SERVICE_NOT_READY;
    }
    return preferncesDB_->SetKvToDb(key, value, userId);
}

int32_t NotificationPreferences::SetByteToDb(
    const std::string &key, const std::vector<uint8_t> &value, const int32_t &userId)
{
    if (preferncesDB_ == nullptr) {
        return ERR_ANS_SERVICE_NOT_READY;
    }
    return preferncesDB_->SetByteToDb(key, value, userId);
}

int32_t NotificationPreferences::GetKvFromDb(
    const std::string &key, std::string &value, const int32_t &userId)
{
    if (preferncesDB_ == nullptr) {
        return ERR_ANS_SERVICE_NOT_READY;
    }
    return preferncesDB_->GetKvFromDb(key, value, userId);
}

int32_t NotificationPreferences::GetByteFromDb(
    const std::string &key, std::vector<uint8_t> &value, const int32_t &userId)
{
    if (preferncesDB_ == nullptr) {
        return ERR_ANS_SERVICE_NOT_READY;
    }
    return preferncesDB_->GetByteFromDb(key, value, userId);
}

int32_t NotificationPreferences::GetBatchKvsFromDb(
    const std::string &key, std::unordered_map<std::string, std::string> &values, const int32_t &userId)
{
    if (preferncesDB_ == nullptr) {
        return ERR_ANS_SERVICE_NOT_READY;
    }
    return preferncesDB_->GetBatchKvsFromDb(key, values, userId);
}

int32_t NotificationPreferences::DeleteKvFromDb(const std::string &key, const int32_t &userId)
{
    if (preferncesDB_ == nullptr) {
        return ERR_ANS_SERVICE_NOT_READY;
    }
    return preferncesDB_->DeleteKvFromDb(key, userId);
}

int32_t NotificationPreferences::DeleteBatchKvFromDb(const std::vector<std::string> &keys,  const int32_t &userId)
{
    if (preferncesDB_ == nullptr) {
        return ERR_ANS_SERVICE_NOT_READY;
    }
    return preferncesDB_->DeleteBatchKvFromDb(keys, userId);
}

bool NotificationPreferences::IsAgentRelationship(const std::string &agentBundleName,
    const std::string &sourceBundleName)
{
    if (AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER)) {
        ANS_LOGD("Client has agent permission.");
        return true;
    }

    if (preferncesDB_ == nullptr) {
        ANS_LOGD("perferencdDb is null.");
        return false;
    }

    return preferncesDB_->IsAgentRelationship(agentBundleName, sourceBundleName);
}

std::string NotificationPreferences::GetAdditionalConfig(const std::string &key)
{
    if (preferncesDB_ == nullptr) {
        return "";
    }
    return preferncesDB_->GetAdditionalConfig(key);
}
}  // namespace Notification
}  // namespace OHOS
