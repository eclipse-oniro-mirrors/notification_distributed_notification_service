/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "ability_manager_client.h"
#include "access_token_helper.h"
#include "aes_gcm_helper.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_trace_wrapper.h"
#include "ans_permission_def.h"
#include "bundle_manager_helper.h"
#include "in_process_call_wrapper.h"
#include "nlohmann/json.hpp"
#include "os_account_manager_helper.h"
#include "notification_analytics_util.h"
#include "notification_config_parse.h"
#include "system_sound_helper.h"

namespace OHOS {
namespace Notification {
namespace {
const static std::string KEY_BUNDLE_LABEL = "label_ans_bundle_";
}
ffrt::mutex NotificationPreferences::instanceMutex_;
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
        std::lock_guard<ffrt::mutex> lock(instanceMutex_);
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
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("%{public}s", __FUNCTION__);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_5, EventBranchId::BRANCH_6)
        .BundleName(bundleOption == nullptr ? "" : bundleOption->GetBundleName());
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty() || slots.empty()) {
        message.Message("Invalid param.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_INVALID_PARAM;
    }
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_5, EventBranchId::BRANCH_5);
    message.Message(bundleOption->GetBundleName() + "_" +std::to_string(bundleOption->GetUid()) +
        " slotType: " + std::to_string(static_cast<uint32_t>(slotType)));
    message.SlotType(static_cast<uint32_t>(slotType));
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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
        ANS_LOGD("%{public}s_%{public}d, Remove all successful.",
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
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;

    ErrCode result = ERR_OK;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    if (GetBundleInfo(preferencesInfo, bundleOption, bundleInfo)) {
        preferencesInfo.RemoveBundleInfo(bundleOption);
        if (!preferncesDB_->RemoveBundleFromDisturbeDB(GenerateBundleKey(bundleOption), bundleOption->GetUid())) {
            result = ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
        }
        SystemSoundHelper::GetInstance()->RemoveCustomizedTone(bundleInfo.GetRingtoneInfo());
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
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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

    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_5, EventBranchId::BRANCH_7);
    ErrCode result = ERR_OK;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    if (GetBundleInfo(preferencesInfo_, bundleOption, bundleInfo)) {
        if (!bundleInfo.GetSlot(type, slot)) {
            result = ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST;
            message.ErrorCode(ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST).Message("Slot type not exist.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            ANS_LOGE("Slot type not exist.");
        }
    } else {
        ANS_LOGW("bundle not exist");
        result = ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST;
        message.ErrorCode(ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST).Message("Slot type not exist.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
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
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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


ErrCode NotificationPreferences::SetNotificationSlotFlagsForBundle(
    const sptr<NotificationBundleOption> &bundleOption, uint32_t slotFlags)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    ErrCode result = SetBundleProperty(preferencesInfo, bundleOption, BundleType::BUNDLE_BADGE_TOTAL_NUM_TYPE, num);
    if (result == ERR_OK) {
        preferencesInfo_ = preferencesInfo;
    }
    return result;
}

ErrCode NotificationPreferences::GetNotificationsEnabledForBundle(
    const sptr<NotificationBundleOption> &bundleOption, NotificationConstant::SWITCH_STATE &state)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }
    int32_t val = static_cast<int32_t>(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    ErrCode result = GetBundleProperty(bundleOption, BundleType::BUNDLE_ENABLE_NOTIFICATION_TYPE, val);
    if (result != ERR_OK) {
        return result;
    }
    state = static_cast<NotificationConstant::SWITCH_STATE>(val);
    return ERR_OK;
}

ErrCode NotificationPreferences::SetNotificationsEnabledForBundle(
    const sptr<NotificationBundleOption> &bundleOption, const NotificationConstant::SWITCH_STATE state)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    ErrCode result = SetBundleProperty(preferencesInfo, bundleOption,
        BundleType::BUNDLE_ENABLE_NOTIFICATION_TYPE, static_cast<int32_t>(state));
    if (result == ERR_OK) {
        preferencesInfo_ = preferencesInfo;
    }
    ANS_LOGI("set ntf auht status %{public}s %{public}d %{public}d %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), state, result);
    return result;
}

ErrCode NotificationPreferences::GetNotificationsEnabled(const int32_t &userId, bool &enabled)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    if (!preferencesInfo.GetDoNotDisturbDate(userId, date)) {
        result = ERR_ANS_INVALID_PARAM;
    }
    return result;
}

ErrCode NotificationPreferences::SetDoNotDisturbDate(const int32_t &userId,
    const sptr<NotificationDoNotDisturbDate> date)
{
    ANS_LOGE("called");
    if (userId <= SUBSCRIBE_USER_INIT) {
        return ERR_ANS_INVALID_PARAM;
    }
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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

ErrCode NotificationPreferences::AddDoNotDisturbProfiles(
    int32_t userId, std::vector<sptr<NotificationDoNotDisturbProfile>> profiles)
{
    ANS_LOGD("called");
    for (auto profile : profiles) {
        if (profile == nullptr) {
            ANS_LOGE("The profile is nullptr.");
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
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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

bool NotificationPreferences::IsNotificationSlotFlagsExists(
    const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return false;
    }
    return preferncesDB_->IsNotificationSlotFlagsExists(bundleOption);
}

bool NotificationPreferences::GetBundleInfo(NotificationPreferencesInfo &preferencesInfo,
    const sptr<NotificationBundleOption> &bundleOption, NotificationPreferencesInfo::BundleInfo &info) const
{
    if (preferencesInfo.GetBundleInfo(bundleOption, info)) {
        return true;
    }
    if (!preferncesDB_->GetBundleInfo(bundleOption, info)) {
        return false;
    }
    preferencesInfo.SetBundleInfo(info);
    std::vector<sptr<NotificationSlot>> slots;
    info.GetAllSlots(slots);
    std::string strSlotTypes = "|";
    for (auto slot : slots) {
        strSlotTypes.append(std::to_string(static_cast<int32_t>(slot->GetType()))).append("|");
    }
    ANS_LOGI("%{public}s get Bundle info from DB, slot: %{public}s",
        bundleOption->GetBundleName().c_str(), strSlotTypes.c_str());
    return true;
}

ErrCode NotificationPreferences::RemoveDoNotDisturbProfiles(
    int32_t userId, const std::vector<sptr<NotificationDoNotDisturbProfile>> profiles)
{
    ANS_LOGD("called");
    for (auto profile : profiles) {
        if (profile == nullptr) {
            ANS_LOGE("The profile is nullptr.");
            return ERR_ANS_INVALID_PARAM;
        }
    }
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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

ErrCode NotificationPreferences::UpdateDoNotDisturbProfiles(int32_t userId, int64_t profileId,
    const std::string& name, const std::vector<NotificationBundleOption>& bundleList)
{
    ANS_LOGD("called, update Profile %{public}d %{public}s %{public}zu",
        userId, std::to_string(profileId).c_str(), bundleList.size());
    if (bundleList.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    if (profile == nullptr) {
        ANS_LOGE("profile is nullptr");
        return ERR_ANS_INVALID_PARAM;
    }
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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
    ANS_LOGI("Update profile %{public}d %{public}s %{public}zu",
        userId, std::to_string(profile->GetProfileId()).c_str(),
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
    ANS_LOGD("Event bundle update %{public}s.", cloneBundleInfo.Dump().c_str());
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    if (bundleOption == nullptr) {
        return;
    }
    bundleOption->SetBundleName(cloneBundleInfo.GetBundleName());
    bundleOption->SetUid(cloneBundleInfo.GetUid());
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    if (!GetBundleInfo(preferencesInfo, bundleOption, bundleInfo)) {
        bundleInfo.SetBundleName(cloneBundleInfo.GetBundleName());
        bundleInfo.SetBundleUid(cloneBundleInfo.GetUid());
    }

    /* after clone, override these witch */
    bundleInfo.SetIsShowBadge(cloneBundleInfo.GetIsShowBadge());
    bundleInfo.SetEnableNotification(cloneBundleInfo.GetEnableNotification());
    /* update property to db */
    if (!preferncesDB_->UpdateBundlePropertyToDisturbeDB(userId, bundleInfo)) {
        ANS_LOGW("Clone bundle info failed %{public}s.", cloneBundleInfo.Dump().c_str());
        return;
    }

    if (SaveBundleProperty(bundleInfo, bundleOption,
        BundleType::BUNDLE_SLOTFLGS_TYPE, cloneBundleInfo.GetSlotFlags()) != ERR_OK) {
        ANS_LOGW("Clone bundle slot info %{public}s.", cloneBundleInfo.Dump().c_str());
        return;
    }
    preferencesInfo.SetBundleInfo(bundleInfo);

    /* update slot info */
    std::vector<sptr<NotificationSlot>> slots;
    for (auto& cloneSlot : cloneBundleInfo.GetSlotInfo()) {
        sptr<NotificationSlot> slotInfo = new (std::nothrow) NotificationSlot(cloneSlot.slotType_);
        if (slotInfo == nullptr) {
            return;
        }
        uint32_t slotFlags = bundleInfo.GetSlotFlags();
        auto configSlotReminderMode = DelayedSingleton<NotificationConfigParse>::GetInstance()->
            GetConfigSlotReminderModeByType(slotInfo->GetType());
        slotInfo->SetReminderMode(configSlotReminderMode & slotFlags);
        slotInfo->SetEnable(cloneSlot.enable_);
        slotInfo->SetForceControl(cloneSlot.isForceControl_);
        slotInfo->SetAuthorizedStatus(cloneSlot.GetAuthStaus());
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
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    std::unordered_map<std::string, std::string> bundlesMap;
    if (GetBatchKvsFromDb(KEY_BUNDLE_LABEL, bundlesMap, userId) != ERR_OK) {
        ANS_LOGE("Get bundle map info failed.");
        return;
    }
    preferncesDB_->ParseBundleFromDistureDB(preferencesInfo, bundlesMap, userId);
    preferencesInfo.GetAllCLoneBundlesInfo(userId, bundlesMap, cloneBundles);
    preferencesInfo_ = preferencesInfo;
}

ErrCode NotificationPreferences::InitBundlesInfo(int32_t userId,
    std::unordered_map<std::string, std::string>& bundlesMap)
{
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    return GetBatchKvsFromDb(KEY_BUNDLE_LABEL, bundlesMap, userId);
}

ErrCode NotificationPreferences::GetLiveViewConfigVersion(int32_t& version)
{
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    if (preferncesDB_ == nullptr) {
        ANS_LOGE("the prefernces db is nullptr");
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
    if (preferncesDB_->GetLiveViewConfigVersion(version)) {
        return ERR_OK;
    }
    return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

bool NotificationPreferences::SetLiveViewConfigVersion(const int32_t& version)
{
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
        if (preferncesDB_ == nullptr) {
        ANS_LOGE("the prefernces db is nullptr");
        return false;
    }
    return preferncesDB_->SetLiveViewConfigVersion(version);
}

ErrCode NotificationPreferences::GetLiveViewRebuildFlag(std::string& flag, int32_t userId)
{
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    if (preferncesDB_ == nullptr) {
        ANS_LOGE("the prefernces db is nullptr");
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
    if (preferncesDB_->GetLiveViewRebuildFlag(flag, userId)) {
        return ERR_OK;
    }
    return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

bool NotificationPreferences::SetLiveViewRebuildFlag(int32_t userId)
{
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    if (preferncesDB_ == nullptr) {
        ANS_LOGE("the prefernces db is nullptr");
        return false;
    }
    return preferncesDB_->SetLiveViewRebuildFlag(userId);
}

bool NotificationPreferences::RemoveLiveViewRebuildFlag(int32_t userId)
{
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    if (preferncesDB_ == nullptr) {
        ANS_LOGE("the prefernces db is nullptr");
        return false;
    }
    return preferncesDB_->RemoveLiveViewRebuildFlag(userId);
}

void NotificationPreferences::GetDoNotDisturbProfileListByUserId(int32_t userId,
    std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    preferencesInfo_.GetAllDoNotDisturbProfiles(userId, profiles);
}

ErrCode NotificationPreferences::GetAllNotificationEnabledBundles(std::vector<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("called");
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    if (preferncesDB_ == nullptr) {
        return ERR_ANS_SERVICE_NOT_READY;
    }
    if (!preferncesDB_->GetAllNotificationEnabledBundles(bundleOption)) {
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
    return ERR_OK;
}

ErrCode NotificationPreferences::GetAllLiveViewEnabledBundles(const int32_t userId,
    std::vector<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("called");
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    return preferencesInfo_.GetAllLiveViewEnabledBundles(userId, bundleOption);
}

ErrCode NotificationPreferences::GetAllDistribuedEnabledBundles(int32_t userId,
    const std::string &deviceType, std::vector<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("called");
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    if (preferncesDB_ == nullptr) {
        return ERR_ANS_SERVICE_NOT_READY;
    }
    if (!preferncesDB_->GetAllDistribuedEnabledBundles(userId, deviceType, bundleOption)) {
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
    return ERR_OK;
}

ErrCode NotificationPreferences::ClearNotificationInRestoreFactorySettings()
{
    ErrCode result = ERR_OK;
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    if (!preferncesDB_->RemoveAllDataFromDisturbeDB()) {
        result = ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }

    if (result == ERR_OK) {
        preferencesInfo_ = NotificationPreferencesInfo();
    }
    return result;
}

ErrCode NotificationPreferences::GetDoNotDisturbProfile(
    int64_t profileId, int32_t userId, sptr<NotificationDoNotDisturbProfile> &profile)
{
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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
        NotificationConstant::SWITCH_STATE defaultState = CheckApiCompatibility(bundleOption) ?
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON :
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
        bundleInfo.SetEnableNotification(defaultState);
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
        NotificationConstant::SWITCH_STATE defaultState = CheckApiCompatibility(bundleOption) ?
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON :
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
        bundleInfo.SetEnableNotification(defaultState);
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
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
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
            state = static_cast<NotificationConstant::SWITCH_STATE>(value);
            bundleInfo.SetEnableNotification(state);
            storeDBResult = preferncesDB_->PutNotificationsEnabledForBundle(bundleInfo, state);
            if (storeDBResult) {
                if (state == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON ||
                    state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) {
                    SetDistributedEnabledForBundle(bundleInfo);
                }
            }
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
        case BundleType::BUNDLE_EXTENSION_SUBSCRIPTION_ENABLED_TYPE:
            state = static_cast<NotificationConstant::SWITCH_STATE>(value);
            bundleInfo.SetExtensionSubscriptionEnabled(state);
            storeDBResult = preferncesDB_->PutExtensionSubscriptionEnabled(bundleInfo);
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
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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
                value = static_cast<int32_t>(bundleInfo.GetEnableNotification());
                break;
            case BundleType::BUNDLE_POPPED_DIALOG_TYPE:
                ANS_LOGD("Into BUNDLE_POPPED_DIALOG_TYPE:GetHasPoppedDialog.");
                value = bundleInfo.GetHasPoppedDialog();
                break;
            case BundleType::BUNDLE_SLOTFLGS_TYPE:
                value = bundleInfo.GetSlotFlags();
                ANS_LOGD("Into BUNDLE_SLOTFLGS_TYPE:GetSlotFlags.");
                break;
            case BundleType::BUNDLE_EXTENSION_SUBSCRIPTION_ENABLED_TYPE:
                value = static_cast<int32_t>(bundleInfo.GetExtensionSubscriptionEnabled());
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

    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleOption->GetBundleName());
    bundleInfo.SetBundleUid(bundleOption->GetUid());
    NotificationConstant::SWITCH_STATE defaultState = CheckApiCompatibility(bundleOption) ?
        NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON :
        NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    bundleInfo.SetEnableNotification(defaultState);
    bool storeDBResult = true;
    storeDBResult = preferncesDB_->PutDistributedEnabledForBundle(deviceType, bundleInfo, enabled);
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

ErrCode NotificationPreferences::SetDistributedBundleOption(
    const std::vector<sptr<DistributedBundleOption>> &bundles,
    const std::string &deviceType)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetCurrentCallingUserId(userId);

    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    bool storeDBResult = true;
    storeDBResult = preferncesDB_->PutDistributedBundleOption(bundles, deviceType, userId);
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

ErrCode NotificationPreferences::IsDistributedEnabledByBundle(const sptr<NotificationBundleOption> &bundleOption,
    const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleOption->GetBundleName());
    bundleInfo.SetBundleUid(bundleOption->GetUid());
    NotificationConstant::SWITCH_STATE defaultState = CheckApiCompatibility(bundleOption) ?
        NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON :
        NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    bundleInfo.SetEnableNotification(defaultState);
    bool storeDBResult = true;
    storeDBResult = preferncesDB_->GetDistributedEnabledForBundle(deviceType, bundleInfo, enabled);
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

ErrCode NotificationPreferences::SetSilentReminderEnabled(const sptr<NotificationBundleOption> &bundleOption,
    const bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo::SilentReminderInfo silentReminderInfo;
    silentReminderInfo.bundleName = bundleOption->GetBundleName();
    silentReminderInfo.uid = bundleOption->GetUid();
    silentReminderInfo.enableStatus =
        enabled ? NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON
        : NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    bool storeDBResult = true;
    storeDBResult = preferncesDB_->SetSilentReminderEnabled(silentReminderInfo);
    if (storeDBResult) {
        preferencesInfo_.SetSilentReminderInfo(silentReminderInfo);
    }
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

ErrCode NotificationPreferences::IsSilentReminderEnabled(const sptr<NotificationBundleOption> &bundleOption,
    NotificationConstant::SWITCH_STATE &enableStatus)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo::SilentReminderInfo silentReminderInfo;
    if (preferencesInfo_.GetSilentReminderInfo(bundleOption, silentReminderInfo)) {
        enableStatus = silentReminderInfo.enableStatus;
        return ERR_OK;
    }
    silentReminderInfo.bundleName = bundleOption->GetBundleName();
    silentReminderInfo.uid = bundleOption->GetUid();
    bool storeDBResult = true;
    storeDBResult = preferncesDB_->IsSilentReminderEnabled(silentReminderInfo);
    if (storeDBResult) {
        enableStatus = silentReminderInfo.enableStatus;
        preferencesInfo_.SetSilentReminderInfo(silentReminderInfo);
    }
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

void NotificationPreferences::RemoveSilentEnabledDbByBundle(const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGE("%{public}s", __FUNCTION__);
    if (preferncesDB_ != nullptr && bundleOption != nullptr) {
        std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
        preferncesDB_->RemoveSilentEnabledDbByBundle(bundleOption->GetBundleName(), bundleOption->GetUid());
        preferencesInfo_.RemoveSilentReminderInfo(bundleOption);
    }
}

ErrCode NotificationPreferences::SetDistributedEnabled(
    const std::string &deviceType, const NotificationConstant::SWITCH_STATE &enableStatus)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    bool storeDBResult = true;
    storeDBResult = preferncesDB_->PutDistributedEnabled(deviceType, enableStatus);
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

ErrCode NotificationPreferences::IsDistributedEnabled(
    const std::string &deviceType, NotificationConstant::SWITCH_STATE &enableStatus)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    bool storeDBResult = true;
    enableStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    storeDBResult = preferncesDB_->GetDistributedEnabled(deviceType, enableStatus);
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

ErrCode NotificationPreferences::GetDistributedAuthStatus(
    const std::string &deviceType, const std::string &deviceId, int32_t targetUserId, bool &isAuth)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    bool storeDBResult = true;
    storeDBResult = preferncesDB_->GetDistributedAuthStatus(deviceType, deviceId, targetUserId, isAuth);
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

ErrCode NotificationPreferences::SetDistributedAuthStatus(
    const std::string &deviceType, const std::string &deviceId, int32_t targetUserId, bool isAuth)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    bool storeDBResult = true;
    storeDBResult = preferncesDB_->SetDistributedAuthStatus(deviceType, deviceId, targetUserId, isAuth);
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

ErrCode NotificationPreferences::SetSmartReminderEnabled(const std::string &deviceType, const bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (deviceType.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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

    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    bool storeDBResult = true;
    storeDBResult = preferncesDB_->IsSmartReminderEnabled(deviceType, enabled);
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

ErrCode NotificationPreferences::SetDistributedEnabledBySlot(const NotificationConstant::SlotType &slotType,
    const std::string &deviceType, const NotificationConstant::SWITCH_STATE &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (deviceType.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    bool storeDBResult = true;
    storeDBResult = preferncesDB_->SetDistributedEnabledBySlot(slotType, deviceType, enabled);
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

ErrCode NotificationPreferences::IsDistributedEnabledBySlot(const NotificationConstant::SlotType &slotType,
    const std::string &deviceType, NotificationConstant::SWITCH_STATE &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (deviceType.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    bool storeDBResult = true;
    storeDBResult = preferncesDB_->IsDistributedEnabledBySlot(slotType, deviceType, enabled);
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

void NotificationPreferences::InitSettingFromDisturbDB(int32_t userId)
{
    ANS_LOGI("%{public}s userId is %{public}d", __FUNCTION__, userId);
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    if (preferncesDB_ != nullptr) {
        preferncesDB_->ParseFromDisturbeDB(preferencesInfo_, userId);
    }
}

void NotificationPreferences::RemoveSettings(int32_t userId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (preferncesDB_ != nullptr && bundleOption != nullptr) {
        preferncesDB_->RemoveAnsBundleDbInfo(bundleOption->GetBundleName(), bundleOption->GetUid());
    }
}

void NotificationPreferences::RemoveEnabledDbByBundle(const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (preferncesDB_ != nullptr && bundleOption != nullptr) {
        std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
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

ErrCode NotificationPreferences::SetRingtoneInfoByBundle(const sptr<NotificationBundleOption> &bundleOption,
    const sptr<NotificationRingtoneInfo> &ringtoneInfo)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty() || ringtoneInfo == nullptr) {
        ANS_LOGE("Invalid parameters");
        return ERR_ANS_INVALID_PARAM;
    }

    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    if (!GetBundleInfo(preferencesInfo_, bundleOption, bundleInfo)) {
        bundleInfo.SetBundleName(bundleOption->GetBundleName());
        bundleInfo.SetBundleUid(bundleOption->GetUid());
        NotificationConstant::SWITCH_STATE defaultState = CheckApiCompatibility(bundleOption) ?
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON :
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
        bundleInfo.SetEnableNotification(defaultState);
    }

    bundleInfo.SetRingtoneInfo(ringtoneInfo);
    if (preferncesDB_ == nullptr) {
        ANS_LOGI("Invalid prefernces db.");
        return ERR_ANS_TASK_ERR;
    }

    if (!preferncesDB_->SetRingtoneInfoByBundle(bundleInfo, ringtoneInfo)) {
        ANS_LOGW("Failed set ringtone: %{public}s %{public}d", bundleOption->GetBundleName().c_str(),
            ringtoneInfo->GetRingtoneType());
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
    preferencesInfo_.SetBundleInfo(bundleInfo);
    ANS_LOGI("Set ringtone %{public}s %{public}d %{public}s", bundleOption->GetBundleName().c_str(),
        ringtoneInfo->GetRingtoneType(), ringtoneInfo->GetRingtoneUri().c_str());
    return ERR_OK;
}

ErrCode NotificationPreferences::GetRingtoneInfoByBundle(const sptr<NotificationBundleOption> &bundleOption,
    sptr<NotificationRingtoneInfo> &ringtoneInfo)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        ANS_LOGE("Invalid parameters");
        return ERR_ANS_INVALID_PARAM;
    }

    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    if (!GetBundleInfo(preferencesInfo_, bundleOption, bundleInfo)) {
        ANS_LOGW("Get info failed %{public}s %{public}d", bundleOption->GetBundleName().c_str(),
            bundleOption->GetUid());
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }

    sptr<NotificationRingtoneInfo> savedRingtoneInfo = bundleInfo.GetRingtoneInfo();
    if (savedRingtoneInfo == nullptr) {
        savedRingtoneInfo = new (std::nothrow) NotificationRingtoneInfo();
        if (!preferncesDB_->GetRingtoneInfoByBundle(bundleInfo, savedRingtoneInfo)) {
            savedRingtoneInfo = new (std::nothrow) NotificationRingtoneInfo();
        }
        bundleInfo.SetRingtoneInfo(savedRingtoneInfo);
        preferencesInfo_.SetBundleInfo(bundleInfo);
    }

    if (savedRingtoneInfo->GetRingtoneType() == NotificationConstant::RingtoneType::RINGTONE_TYPE_BUTT) {
        ANS_LOGW("Ringtone not found %{public}s", bundleOption->GetBundleName().c_str());
        return ERR_ANS_NO_CUSTOM_RINGTONE_INFO;
    }
    ringtoneInfo = savedRingtoneInfo;
    ANS_LOGI("Ringtone find : %{public}s %{public}d", bundleOption->GetBundleName().c_str(),
        ringtoneInfo->GetRingtoneType());
    return ERR_OK;
}

void NotificationPreferences::RemoveRingtoneInfoByBundle(const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle option");
        return;
    }
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    if (!GetBundleInfo(preferencesInfo_, bundleOption, bundleInfo)) {
        ANS_LOGW("Get info failed %{public}s %{public}d", bundleOption->GetBundleName().c_str(),
            bundleOption->GetUid());
        return;
    }
    if (preferncesDB_ == nullptr) {
        ANS_LOGE("The prefernces db is nullptr.");
        return;
    }
    sptr<NotificationRingtoneInfo> savedRingtoneInfo = bundleInfo.GetRingtoneInfo();
    if (savedRingtoneInfo == nullptr) {
        if (!preferncesDB_->GetRingtoneInfoByBundle(bundleInfo, savedRingtoneInfo)) {
            return;
        }
    }
    if (savedRingtoneInfo == nullptr) {
        ANS_LOGE("ringtoneInfo is nullptr.");
        return;
    }

    SystemSoundHelper::GetInstance()->RemoveCustomizedTone(savedRingtoneInfo);
    if (preferncesDB_->RemoveRingtoneInfoByBundle(bundleInfo)) {
        bundleInfo.RemoveRingtoneInfo();
        preferencesInfo_.SetBundleInfo(bundleInfo);
        ANS_LOGI("Remove ringtone info successfully for bundle: %{public}s", bundleInfo.GetBundleName().c_str());
        return;
    }
    ANS_LOGE("Failed to remove ringtone info for bundle: %{public}s", bundleInfo.GetBundleName().c_str());
    return;
}

int64_t NotificationPreferences::GetCloneTimeStamp()
{
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    if (cloneTimestamp != -1) {
        return cloneTimestamp;
    }

    if (!preferncesDB_->GetCloneTimeStamp(cloneTimestamp)) {
        ANS_LOGW("Get time stamp failed");
        return 0;
    }
    return cloneTimestamp;
}

void NotificationPreferences::SetCloneTimeStamp(const int32_t& userId, const int64_t& timestamp)
{
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    cloneTimestamp = timestamp;
    auto result = preferncesDB_->SetCloneTimeStamp(userId, timestamp);
    ANS_LOGI("Set time stamp %{public}d %{public}d %{public}" PRId64, userId, result, timestamp);
}

void NotificationPreferences::GetCloneRingtoneInfo(const int32_t& userId,
    const NotificationCloneBundleInfo& bundleInfo, NotificationRingtoneInfo& cloneRingtoneInfos)
{
    std::string originData;
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    if (!preferncesDB_->GetCloneRingtoneInfo(userId, bundleInfo.GetBundleName(),
        bundleInfo.GetAppIndex(), originData)) {
        ANS_LOGW("Get ring tone %{public}s %{public}d failed", bundleInfo.GetBundleName().c_str(),
            bundleInfo.GetAppIndex());
    }
    if (originData.empty()) {
        return;
    }

    cloneRingtoneInfos.FromJson(originData);
    ANS_LOGI("Get ringtone %{public}d %{public}s.", cloneRingtoneInfos.GetRingtoneType(),
        cloneRingtoneInfos.GetRingtoneUri().c_str());
}

void NotificationPreferences::UpdateCloneRingtoneInfo(const int32_t& userId,
    const NotificationCloneBundleInfo& bundleInfo)
{
    auto cloneRingtone = bundleInfo.GetRingtoneInfo();
    if (cloneRingtone == nullptr ||
        (cloneRingtone->GetRingtoneType() != NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL &&
        cloneRingtone->GetRingtoneType() != NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE)) {
        return;
    }

    // clear clone rington info for last not clone information.
    nlohmann::json jsonNewObject = nlohmann::json::array();
    NotificationRingtoneInfo cloneRingtoneInfos;
    GetCloneRingtoneInfo(userId, bundleInfo, cloneRingtoneInfos);
    if (cloneRingtoneInfos.GetRingtoneType() == cloneRingtone->GetRingtoneType() &&
        cloneRingtoneInfos.GetRingtoneTitle() == cloneRingtone->GetRingtoneTitle() &&
        cloneRingtoneInfos.GetRingtoneFileName() == cloneRingtone->GetRingtoneFileName() &&
        cloneRingtoneInfos.GetRingtoneUri() == cloneRingtone->GetRingtoneUri()) {
        return;
    }

    if (cloneRingtoneInfos.GetRingtoneType() == NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL ||
        cloneRingtoneInfos.GetRingtoneType() == NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE) {
        SystemSoundHelper::GetInstance()->RemoveCustomizedTone(cloneRingtoneInfos.GetRingtoneUri());
    }

    std::string ringtoneNode = cloneRingtone->ToJson();
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    auto result = preferncesDB_->SetCloneRingtoneInfo(userId, bundleInfo.GetBundleName(),
        bundleInfo.GetAppIndex(), ringtoneNode);
    ANS_LOGI("Set info %{public}d %{public}d %{public}s %{public}d", userId, result,
        bundleInfo.GetBundleName().c_str(), bundleInfo.GetAppIndex());
}

void NotificationPreferences::DeleteAllCloneRingtoneInfo(const int32_t& userId)
{
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    if (!preferncesDB_->DelAllCloneRingtoneInfo(userId)) {
        ANS_LOGW("Clear ringtone failed %{public}d.", userId);
        return;
    }

    if (preferncesDB_->SetCloneTimeStamp(userId, 0)) {
        cloneTimestamp = 0;
    }
    ANS_LOGI("Clear ringtone %{public}d", userId);
}

void NotificationPreferences::GetAllCloneRingtoneInfo(const int32_t& userId,
    std::vector<NotificationRingtoneInfo>& cloneRingtoneInfos)
{
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    std::vector<std::string> values;
    if (!preferncesDB_->GetAllCloneRingtoneInfo(userId, values)) {
        ANS_LOGW("Clear all ringtone failed %{public}d.", userId);
        return;
    }
    ANS_LOGI("Get all ringtone value %{public}zu", values.size());
    if (values.empty()) {
        return;
    }

    for (auto& ringtonData : values) {
        NotificationRingtoneInfo info;
        info.FromJson(ringtonData);
        cloneRingtoneInfos.push_back(info);
    }
    ANS_LOGI("Get all ringtone %{public}zu", cloneRingtoneInfos.size());
}

void NotificationPreferences::DeleteCloneRingtoneInfo(const int32_t& userId,
    const NotificationCloneBundleInfo& bundleInfo)
{
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    auto result = preferncesDB_->DelCloneRingtoneInfo(userId, bundleInfo);
    ANS_LOGI("del info %{public}d %{public}d %{public}s %{public}d", userId, result,
        bundleInfo.GetBundleName().c_str(), bundleInfo.GetAppIndex());
}

int32_t NotificationPreferences::SetKvToDb(
    const std::string &key, const std::string &value, const int32_t &userId)
{
    if (preferncesDB_ == nullptr) {
        return ERR_ANS_SERVICE_NOT_READY;
    }
    if (key == "kiosk_app_trust_list") {
        isKioskTrustListUpdate_ = true;
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

int32_t NotificationPreferences::GetBatchKvsFromDbContainsKey(
    const std::string &key, std::unordered_map<std::string, std::string> &values, const int32_t &userId)
{
    if (preferncesDB_ == nullptr) {
        return ERR_ANS_SERVICE_NOT_READY;
    }
    return preferncesDB_->GetBatchKvsFromDbContainsKey(key, values, userId);
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

bool NotificationPreferences::DelCloneProfileInfo(const int32_t &userId,
    const sptr<NotificationDoNotDisturbProfile>& info)
{
    if (preferncesDB_ == nullptr) {
        return false;
    }
    return preferncesDB_->DelCloneProfileInfo(userId, info);
}

bool NotificationPreferences::UpdateBatchCloneProfileInfo(const int32_t &userId,
    const std::vector<sptr<NotificationDoNotDisturbProfile>>& profileInfo)
{
    if (preferncesDB_ == nullptr) {
        return false;
    }
    return preferncesDB_->UpdateBatchCloneProfileInfo(userId, profileInfo);
}

void NotificationPreferences::GetAllCloneProfileInfo(const int32_t &userId,
    std::vector<sptr<NotificationDoNotDisturbProfile>>& profilesInfo)
{
    if (preferncesDB_ == nullptr) {
        return;
    }
    return preferncesDB_->GetAllCloneProfileInfo(userId, profilesInfo);
}

void NotificationPreferences::GetAllCloneBundleInfo(const int32_t &userId,
    std::vector<NotificationCloneBundleInfo>& cloneBundleInfo)
{
    if (preferncesDB_ == nullptr) {
        return;
    }
    return preferncesDB_->GetAllCloneBundleInfo(userId, cloneBundleInfo);
}

bool NotificationPreferences::UpdateBatchCloneBundleInfo(const int32_t &userId,
    const std::vector<NotificationCloneBundleInfo>& cloneBundleInfo)
{
    if (preferncesDB_ == nullptr) {
        return false;
    }
    return preferncesDB_->UpdateBatchCloneBundleInfo(userId, cloneBundleInfo);
}

bool NotificationPreferences::DelCloneBundleInfo(const int32_t &userId,
    const NotificationCloneBundleInfo& cloneBundleInfo)
{
    if (preferncesDB_ == nullptr) {
        return false;
    }
    return preferncesDB_->DelCloneBundleInfo(userId, cloneBundleInfo);
}

bool NotificationPreferences::DelBatchCloneProfileInfo(const int32_t &userId,
    const std::vector<sptr<NotificationDoNotDisturbProfile>>& profileInfo)
{
    if (preferncesDB_ == nullptr) {
        return false;
    }
    return preferncesDB_->DelBatchCloneProfileInfo(userId, profileInfo);
}

bool NotificationPreferences::DelBatchCloneBundleInfo(const int32_t &userId,
    const std::vector<NotificationCloneBundleInfo>& cloneBundleInfo)
{
    if (preferncesDB_ == nullptr) {
        return false;
    }
    return preferncesDB_->DelBatchCloneBundleInfo(userId, cloneBundleInfo);
}

ErrCode NotificationPreferences::SetDisableNotificationInfo(const sptr<NotificationDisable> &notificationDisable)
{
    ANS_LOGD("called");
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    preferencesInfo_.SetDisableNotificationInfo(notificationDisable);
    if (preferncesDB_ == nullptr) {
        ANS_LOGE("the prefernces db is nullptr");
        return ERR_ANS_SERVICE_NOT_READY;
    }
    if (!preferncesDB_->SetDisableNotificationInfo(notificationDisable)) {
        ANS_LOGE("db set disable notification info fail");
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }

    return ERR_OK;
}

bool NotificationPreferences::GetDisableNotificationInfo(NotificationDisable &notificationDisable)
{
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    if (preferencesInfo_.GetDisableNotificationInfo(notificationDisable)) {
        ANS_LOGD("info get disable notification success");
        return true;
    }
    if (preferncesDB_ == nullptr) {
        ANS_LOGE("the prefernces db is nullptr");
        return false;
    }
    if (preferncesDB_->GetDisableNotificationInfo(notificationDisable)) {
        ANS_LOGD("db get disable notification success");
        sptr<NotificationDisable> notificationDisablePtr = new (std::nothrow) NotificationDisable(notificationDisable);
        preferencesInfo_.SetDisableNotificationInfo(notificationDisablePtr);
    } else {
        ANS_LOGD("db get disable notification fail");
        return false;
    }
    return true;
}

bool NotificationPreferences::GetUserDisableNotificationInfo(int32_t userId, NotificationDisable &notificationDisable)
{
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    if (preferencesInfo_.GetUserDisableNotificationInfo(userId, notificationDisable)) {
        ANS_LOGD("info get disable notification success");
        return true;
    }
    if (preferncesDB_ == nullptr) {
        ANS_LOGE("the prefernces db is nullptr");
        return false;
    }
    if (preferncesDB_->GetUserDisableNotificationInfo(userId, notificationDisable)) {
        ANS_LOGD("db get disable notification success");
        sptr<NotificationDisable> notificationDisablePtr = new (std::nothrow) NotificationDisable(notificationDisable);
        preferencesInfo_.SetDisableNotificationInfo(notificationDisablePtr);
    } else {
        ANS_LOGD("db get disable notification fail");
        return false;
    }
    return true;
}

bool NotificationPreferences::GetkioskAppTrustList(std::vector<std::string> &kioskAppTrustList)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (preferencesInfo_.GetkioskAppTrustList(kioskAppTrustList) && !isKioskTrustListUpdate_) {
        ANS_LOGD("info get disable notification success");
        return true;
    }
    std::string value = "";
    int32_t userId = -1;
    if (GetKvFromDb("kiosk_app_trust_list", value, userId) != ERR_OK) {
        ANS_LOGD("Get kiosk app trust list failed.");
        return false;
    }
    if (value.empty() || !nlohmann::json::accept(value)) {
        ANS_LOGE("Invalid json string");
        return false;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(value, nullptr, false);
    if (jsonObject.is_null() || jsonObject.empty()) {
        ANS_LOGE("Invalid JSON object");
        return false;
    }
    if (jsonObject.is_discarded() || !jsonObject.is_array()) {
        ANS_LOGE("Parse kiosk app trust list failed due to data is discarded or not array");
        return false;
    }
    kioskAppTrustList = jsonObject.get<std::vector<std::string>>();
    preferencesInfo_.SetkioskAppTrustList(kioskAppTrustList);
    isKioskTrustListUpdate_ = false;
    return true;
}

ErrCode NotificationPreferences::SetDistributedDevicelist(std::vector<std::string> &deviceTypes, const int32_t &userId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    bool storeDBResult = true;
    nlohmann::json deviceTypesJson = deviceTypes;
    std::string deviceTypesjsonString = deviceTypesJson.dump();
    storeDBResult = preferncesDB_->PutDistributedDevicelist(deviceTypesjsonString, userId);
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

ErrCode NotificationPreferences::GetDistributedDevicelist(std::vector<std::string> &deviceTypes)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    std::string value = "";
    auto storeDBResult = preferncesDB_->GetDistributedDevicelist(value);
    if (!storeDBResult) {
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
    if (value.empty()) {
        ANS_LOGE("Empty json");
        return ERR_OK;
    }

    if (!nlohmann::json::accept(value)) {
        ANS_LOGE("Invalid json string");
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(value, nullptr, false);
    if (jsonObject.is_null() || jsonObject.empty()) {
        ANS_LOGE("Invalid JSON object");
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
    if (jsonObject.is_discarded() || !jsonObject.is_array()) {
        ANS_LOGE("Parse device type list failed due to data is discarded or not array");
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
    deviceTypes = jsonObject.get<std::vector<std::string>>();
    return ERR_OK;
}

ErrCode NotificationPreferences::GetExtensionSubscriptionInfos(const sptr<NotificationBundleOption>& bundleOption,
    std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos)
{
    ANS_LOGD("called");
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle option");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    if (GetBundleInfo(preferencesInfo_, bundleOption, bundleInfo)) {
        infos = bundleInfo.GetExtensionSubscriptionInfos();
        for (auto& info : infos) {
            if (info == nullptr) {
                continue;
            }
            std::string decryptedAddr;
            if (AesGcmHelper::Decrypt(decryptedAddr, info->GetAddr()) == ERR_OK) {
                info->SetAddr(decryptedAddr);
            }
        }
    } else {
        ANS_LOGW("Notification bundle does not exsit.");
        infos.clear();
    }
    return ERR_OK;
}

ErrCode NotificationPreferences::SetExtensionSubscriptionInfos(const sptr<NotificationBundleOption>& bundleOption,
    const std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos)
{
    ANS_LOGD("called");
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle option");
        return ERR_ANS_INVALID_PARAM;
    }
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    if (!GetBundleInfo(preferencesInfo_, bundleOption, bundleInfo)) {
        bundleInfo.SetBundleName(bundleOption->GetBundleName());
        bundleInfo.SetBundleUid(bundleOption->GetUid());
        NotificationConstant::SWITCH_STATE defaultState = CheckApiCompatibility(bundleOption) ?
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON :
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
        bundleInfo.SetEnableNotification(defaultState);
    }

    std::vector<sptr<NotificationExtensionSubscriptionInfo>> encryptedInfos = infos;
    for (auto& info : encryptedInfos) {
        if (info != nullptr) {
            std::string encryptedAddr;
            if (AesGcmHelper::Encrypt(info->GetAddr(), encryptedAddr) == ERR_OK) {
                info->SetAddr(encryptedAddr);
            }
        }
    }
    bundleInfo.SetExtensionSubscriptionInfos(encryptedInfos);
    if (preferncesDB_ == nullptr) {
        ANS_LOGE("the prefernces db is nullptr");
        return ERR_ANS_SERVICE_NOT_READY;
    }
    if (preferncesDB_->PutExtensionSubscriptionInfos(bundleInfo)) {
        preferencesInfo.SetBundleInfo(bundleInfo);
        preferencesInfo_ = preferencesInfo;
        return ERR_OK;
    } else {
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
}

ErrCode NotificationPreferences::ClearExtensionSubscriptionInfos(const sptr<NotificationBundleOption>& bundleOption)
{
    ANS_LOGD("called");
    return SetExtensionSubscriptionInfos(bundleOption, std::vector<sptr<NotificationExtensionSubscriptionInfo>>());
}

ErrCode NotificationPreferences::GetExtensionSubscriptionEnabled(
    const sptr<NotificationBundleOption>& bundleOption, NotificationConstant::SWITCH_STATE& state)
{
    ANS_LOGD("called");
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }
    int32_t val = static_cast<int32_t>(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    auto result =  GetBundleProperty(bundleOption, BundleType::BUNDLE_EXTENSION_SUBSCRIPTION_ENABLED_TYPE, val);
    if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
        result = ERR_OK;
    }
    state = static_cast<NotificationConstant::SWITCH_STATE>(val);
    return result;
}

ErrCode NotificationPreferences::SetExtensionSubscriptionEnabled(
    const sptr<NotificationBundleOption>& bundleOption, NotificationConstant::SWITCH_STATE state)
{
    ANS_LOGD("called");
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    ErrCode result = SetBundleProperty(preferencesInfo, bundleOption,
        BundleType::BUNDLE_EXTENSION_SUBSCRIPTION_ENABLED_TYPE, static_cast<int32_t>(state));
    if (result == ERR_OK) {
        preferencesInfo_ = preferencesInfo;
    }
    return result;
}

ErrCode NotificationPreferences::GetExtensionSubscriptionBundles(
    const sptr<NotificationBundleOption>& bundleOption, std::vector<sptr<NotificationBundleOption>>& bundles)
{
    ANS_LOGD("called");
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle option");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    if (GetBundleInfo(preferencesInfo_, bundleOption, bundleInfo)) {
        bundleInfo.GetExtensionSubscriptionBundles(bundles);
    } else {
        ANS_LOGW("Notification bundle does not exsit.");
        bundles.clear();
    }
    return ERR_OK;
}

ErrCode NotificationPreferences::SetExtensionSubscriptionBundles(
    const sptr<NotificationBundleOption>& bundleOption, const std::vector<sptr<NotificationBundleOption>>& bundles)
{
    ANS_LOGD("called");
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle option");
        return ERR_ANS_INVALID_PARAM;
    }
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    if (preferncesDB_ == nullptr) {
        ANS_LOGE("the prefernces db is nullptr");
        return ERR_ANS_SERVICE_NOT_READY;
    }
    if (!GetBundleInfo(preferencesInfo_, bundleOption, bundleInfo)) {
        bundleInfo.SetBundleName(bundleOption->GetBundleName());
        bundleInfo.SetBundleUid(bundleOption->GetUid());
        NotificationConstant::SWITCH_STATE defaultState = CheckApiCompatibility(bundleOption) ?
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON :
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
        bundleInfo.SetEnableNotification(defaultState);
    }
    bundleInfo.SetExtensionSubscriptionBundles(bundles);
    if (preferncesDB_->PutExtensionSubscriptionBundles(bundleInfo)) {
        preferencesInfo.SetBundleInfo(bundleInfo);
        preferencesInfo_ = preferencesInfo;
        return ERR_OK;
    } else {
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
}

ErrCode NotificationPreferences::AddExtensionSubscriptionBundles(
    const sptr<NotificationBundleOption>& bundleOption, const std::vector<sptr<NotificationBundleOption>>& bundles)
{
    ANS_LOGD("called");
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle option");
        return ERR_ANS_INVALID_PARAM;
    }
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    if (preferncesDB_ == nullptr) {
        ANS_LOGE("the prefernces db is nullptr");
        return ERR_ANS_SERVICE_NOT_READY;
    }
    if (!GetBundleInfo(preferencesInfo_, bundleOption, bundleInfo)) {
        bundleInfo.SetBundleName(bundleOption->GetBundleName());
        bundleInfo.SetBundleUid(bundleOption->GetUid());
        NotificationConstant::SWITCH_STATE defaultState = CheckApiCompatibility(bundleOption) ?
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON :
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
        bundleInfo.SetEnableNotification(defaultState);
    }
    bundleInfo.AddExtensionSubscriptionBundles(bundles);
    if (preferncesDB_->PutExtensionSubscriptionBundles(bundleInfo)) {
        preferencesInfo.SetBundleInfo(bundleInfo);
        preferencesInfo_ = preferencesInfo;
        return ERR_OK;
    } else {
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
}

ErrCode NotificationPreferences::RemoveExtensionSubscriptionBundles(
    const sptr<NotificationBundleOption>& bundleOption, const std::vector<sptr<NotificationBundleOption>>& bundles)
{
    ANS_LOGD("called");
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle option");
        return ERR_ANS_INVALID_PARAM;
    }
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    NotificationPreferencesInfo preferencesInfo = preferencesInfo_;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    if (preferncesDB_ == nullptr) {
        ANS_LOGE("the prefernces db is nullptr");
        return ERR_ANS_SERVICE_NOT_READY;
    }
    if (!GetBundleInfo(preferencesInfo_, bundleOption, bundleInfo)) {
        bundleInfo.SetBundleName(bundleOption->GetBundleName());
        bundleInfo.SetBundleUid(bundleOption->GetUid());
        NotificationConstant::SWITCH_STATE defaultState = CheckApiCompatibility(bundleOption) ?
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON :
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
        bundleInfo.SetEnableNotification(defaultState);
    }
    bundleInfo.RemoveExtensionSubscriptionBundles(bundles);
    if (preferncesDB_->PutExtensionSubscriptionBundles(bundleInfo)) {
        preferencesInfo.SetBundleInfo(bundleInfo);
        preferencesInfo_ = preferencesInfo;
        return ERR_OK;
    } else {
        return ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    }
}

ErrCode NotificationPreferences::SetSubscriberExistFlag(const std::string& deviceType, bool existFlag)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (deviceType.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    if (preferncesDB_ == nullptr) {
        return ERR_ANS_SERVICE_NOT_READY;
    }

    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    bool storeDBResult = preferncesDB_->SetSubscriberExistFlag(deviceType, existFlag);
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

ErrCode NotificationPreferences::GetSubscriberExistFlag(const std::string& deviceType, bool& existFlag)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (deviceType.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    if (preferncesDB_ == nullptr) {
        return ERR_ANS_SERVICE_NOT_READY;
    }

    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    bool storeDBResult = preferncesDB_->GetSubscriberExistFlag(deviceType, existFlag);
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

void NotificationPreferences::SetDistributedEnabledForBundle(const NotificationPreferencesInfo::BundleInfo& bundleInfo)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (!isCachedMirrorNotificationEnabledStatus_) {
        if (!DelayedSingleton<NotificationConfigParse>::GetInstance()->GetMirrorNotificationEnabledStatus(
            mirrorNotificationEnabledStatus_)) {
            return;
        }
        isCachedMirrorNotificationEnabledStatus_ = true;
    }
    if (mirrorNotificationEnabledStatus_.empty()) {
        ANS_LOGD("mirrorNotificationEnabledStatus_ is empty");
        return;
    }
    if (preferncesDB_ == nullptr) {
        ANS_LOGD("preferncesDB_ is nullptr");
        return;
    }
    for (const auto& deviceType : mirrorNotificationEnabledStatus_) {
        bool ret = preferncesDB_->IsDistributedEnabledEmptyForBundle(deviceType, bundleInfo);
        if (!ret) {
            ANS_LOGD("get %{public}s distributedEnabled is empty", deviceType.c_str());
            preferncesDB_->PutDistributedEnabledForBundle(deviceType, bundleInfo, true);
        }
    }
}

ErrCode NotificationPreferences::SetHashCodeRule(const int32_t uid, const uint32_t type)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    bool storeDBResult = true;
    storeDBResult = preferncesDB_->SetHashCodeRule(uid, type);
    return storeDBResult ? ERR_OK : ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
}

uint32_t NotificationPreferences::GetHashCodeRule(const int32_t uid)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    std::lock_guard<ffrt::mutex> lock(preferenceMutex_);
    uint32_t result = 0;
    result = preferncesDB_->GetHashCodeRule(uid);
    ANS_LOGD("uid = %{public}d result = %{public}d", uid, result);
    return result;
}

bool NotificationPreferences::GetBundleRemoveFlag(const sptr<NotificationBundleOption> &bundleOption,
    const NotificationConstant::SlotType &slotType, int32_t sourceType)
{
    if (preferncesDB_ == nullptr) {
        return true;
    }
    return preferncesDB_->GetBundleRemoveFlag(bundleOption, slotType, sourceType);
}

bool NotificationPreferences::SetBundleRemoveFlag(const sptr<NotificationBundleOption> &bundleOption,
    const NotificationConstant::SlotType &slotType, int32_t sourceType)
{
    if (preferncesDB_ == nullptr) {
        return false;
    }
    return preferncesDB_->SetBundleRemoveFlag(bundleOption, slotType, sourceType);
}

void NotificationPreferences::SetKioskModeStatus(bool isKioskMode)
{
    isKioskMode_ = isKioskMode;
}

bool NotificationPreferences::IsKioskMode()
{
    AAFwk::KioskStatus kioskStatus;
    auto ret = IN_PROCESS_CALL(AAFwk::AbilityManagerClient::GetInstance()->GetKioskStatus(kioskStatus));
    if (ret != ERR_OK) {
        ANS_LOGE("Get KioskStatus failed");
        return isKioskMode_;
    }
    isKioskMode_ = kioskStatus.isKioskMode_;
    return isKioskMode_;
}

#ifdef ENABLE_ANS_PRIVILEGED_MESSAGE_EXT_WRAPPER
int32_t NotificationPreferences::GetKvFromDb(
    const std::string &key, std::string &value, const int32_t &userId, int32_t &retCode)
{
    if (preferncesDB_ == nullptr) {
        return ERR_ANS_SERVICE_NOT_READY;
    }
    return preferncesDB_->GetKvFromDb(key, value, userId, retCode);
}
#endif
}  // namespace Notification
}  // namespace OHOS
