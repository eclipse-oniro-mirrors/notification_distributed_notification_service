/*os_account_manager
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

#include "notification_preferences_database.h"

#include <regex>
#include <string>
#include <sstream>

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "os_account_manager_helper.h"
#include "ans_log_wrapper.h"
#include "ans_trace_wrapper.h"
#include "os_account_manager.h"
#include "ipc_skeleton.h"
#include "bundle_manager_helper.h"
#include "notification_analytics_util.h"
#include "notification_config_parse.h"
#include "uri.h"
namespace OHOS {
namespace Notification {
/**
 * Indicates that disturbe key which do not disturbe type.
 */
const static std::string KEY_DO_NOT_DISTURB_TYPE = "ans_doNotDisturbType";

/**
 * Indicates that disturbe key which do not disturbe begin date.
 */
const static std::string KEY_DO_NOT_DISTURB_BEGIN_DATE = "ans_doNotDisturbBeginDate";

/**
 * Indicates that disturbe key which do not disturbe end date.
 */
const static std::string KEY_DO_NOT_DISTURB_END_DATE = "ans_doNotDisturbEndDate";

/**
 * Indicates that disturbe key which do not disturbe id.
 */
const static std::string KEY_DO_NOT_DISTURB_ID = "ans_doNotDisturbId";

/**
 * Indicates that disturbe key which enable all notification.
 */
const static std::string KEY_ENABLE_ALL_NOTIFICATION = "ans_notificationAll";

/**
 * Indicates that disturbe key which bundle label.
 */
const static std::string KEY_BUNDLE_LABEL = "label_ans_bundle_";

/**
 * Indicates that disturbe key which under line.
 */
const static std::string KEY_UNDER_LINE = "_";

/**
 * Indicates that disturbe key which middle line.
 */
const static std::string KEY_MIDDLE_LINE = "-";

/**
 * Indicates that disturbe key which bundle begin key.
 */
const static std::string KEY_ANS_BUNDLE = "ans_bundle";

/**
 * Indicates that disturbe key which bundle name.
 */
const static std::string KEY_BUNDLE_NAME = "name";

/**
 * Indicates that disturbe key which bundle imortance.
 */
const static std::string KEY_BUNDLE_IMPORTANCE = "importance";

/**
 * Indicates that disturbe key which bundle show badge.
 */
const static std::string KEY_BUNDLE_SHOW_BADGE = "showBadgeEnable";

/**
 * Indicates that disturbe key which bundle total badge num.
 */
const static std::string KEY_BUNDLE_BADGE_TOTAL_NUM = "badgeTotalNum";

/**
 * Indicates that disturbe key which bundle enable notification.
 */
const static std::string KEY_BUNDLE_ENABLE_NOTIFICATION = "enabledNotification";

/**
 * Indicates that disturbe key which bundle enable notification.
 */
const static std::string KEY_ENABLE_BUNDLE_DISTRIBUTED_NOTIFICATION = "enabledDistributedNotification";

/**
 * Indicates that disturbe key which bundle enable notification.
 */
const static std::string KEY_SMART_REMINDER_ENABLE_NOTIFICATION = "enabledSmartReminder";

/**
 * Indicates that disturbe key which bundle enable notification.
 */
const static std::string KEY_ENABLE_SLOT_DISTRIBUTED_NOTIFICATION = "enabledSlotDistributedNotification";

/**
 * Indicates that disturbe key which bundle popped dialog.
 */
const static std::string KEY_BUNDLE_POPPED_DIALOG = "poppedDialog";

/**
 * Indicates that disturbe key which bundle uid.
 */
const static std::string KEY_BUNDLE_UID = "uid";

/**
 * Indicates that disturbe key which slot.
 */
const static std::string KEY_SLOT = "slot";

/**
 * Indicates that disturbe key which slot type.
 */
const static std::string KEY_SLOT_TYPE = "type";

/**
 * Indicates that disturbe key which slot id.
 */
const static std::string KEY_SLOT_ID = "id";

/**
 * Indicates that disturbe key which slot name.
 */
const static std::string KEY_SLOT_NAME = "name";

/**
 * Indicates that disturbe key which slot description.
 */
const static std::string KEY_SLOT_DESCRIPTION = "description";

/**
 * Indicates that disturbe key which slot level.
 */
const static std::string KEY_SLOT_LEVEL = "level";

/**
 * Indicates that disturbe key which slot show badge.
 */
const static std::string KEY_SLOT_SHOW_BADGE = "showBadge";

/**
 * Indicates that disturbe key which slot enable light.
 */
const static std::string KEY_SLOT_ENABLE_LIGHT = "enableLight";

/**
 * Indicates that disturbe key which slot enable vibration.
 */
const static std::string KEY_SLOT_ENABLE_VRBRATION = "enableVibration";

/**
 * Indicates that disturbe key which slot led light color.
 */
const static std::string KEY_SLOT_LED_LIGHT_COLOR = "ledLightColor";

/**
 * Indicates that disturbe key which slot lockscreen visibleness.
 */
const static std::string KEY_SLOT_LOCKSCREEN_VISIBLENESS = "lockscreenVisibleness";

/**
 * Indicates that disturbe key which slot sound.
 */
const static std::string KEY_SLOT_SOUND = "sound";

/**
 * Indicates that disturbe key which slot vibration style.
 */
const static std::string KEY_SLOT_VIBRATION_STYLE = "vibrationSytle";

/**
 * Indicates that disturbe key which slot enable bypass end.
 */
const static std::string KEY_SLOT_ENABLE_BYPASS_DND = "enableBypassDnd";

/**
 * Indicates whether the type of slot is enabled.
 */
const static std::string KEY_SLOT_ENABLED = "enabled";

/**
 * Indicates whether the type of bundle is flags.
 */
const static std::string KEY_BUNDLE_SLOTFLGS_TYPE = "bundleReminderFlagsType";

/**
 * Indicates whether the type of slot is flags.
 */
const static std::string KEY_SLOT_SLOTFLGS_TYPE = "reminderFlagsType";

/**
 * Indicates that disturbe key which slot authorized status.
 */
const static std::string KEY_SLOT_AUTHORIZED_STATUS = "authorizedStatus";

/**
 * Indicates that disturbe key which slot authorized hint count.
 */
const static std::string KEY_SLOT_AUTH_HINT_CNT = "authHintCnt";

/**
 * Indicates that reminder mode of slot.
 */
const static std::string KEY_REMINDER_MODE = "reminderMode";

constexpr char RELATIONSHIP_JSON_KEY_SERVICE[] = "service";
constexpr char RELATIONSHIP_JSON_KEY_APP[] = "app";

const static std::string KEY_CLONE_LABEL = "label_ans_clone_";

const static std::string KEY_REMOVE_SLOT_FLAG = "label_ans_remove_";

const static std::string KEY_REMOVED_FLAG = "1";

const static std::string KEY_SECOND_REMOVED_FLAG = "2";

constexpr int32_t CLEAR_SLOT_FROM_AVSEESAION = 1;
/**
 * Indicates hashCode rule.
 */
const static std::string KEY_HASH_CODE_RULE = "hashCodeRule";

const static std::string CLONE_BUNDLE = "bundle_";
const static std::string CLONE_PROFILE = "profile_";
const static std::string KEY_DISABLE_NOTIFICATION = "disableNotificationFeature";
constexpr int32_t ZERO_USER_ID = 0;
const static std::string KEY_SUBSCRIBER_EXISTED_FLAG = "existFlag";
const static int32_t DISTRIBUTED_KEY_NUM = 4;
const static int32_t DISTRIBUTED_KEY_BUNDLE_INDEX = 1;
const static int32_t DISTRIBUTED_KEY_UID_INDEX = 2;

/**
 * Indicates that distributed notification switch.
 */
static const char* const KEY_DISTRIBUTED_NOTIFICATION_SWITCH = "distributedNotificationSwitch";

/**
 * Indicates the target device's authorization status.
 */
static const char* const KEY_ENABLE_DISTRIBUTED_AUTH_STATUS = "enabledDistributedAuthStatus";

NotificationPreferencesDatabase::NotificationPreferencesDatabase()
{
    NotificationRdbConfig notificationRdbConfig;
    rdbDataManager_ = std::make_shared<NotificationDataMgr>(notificationRdbConfig);
    ANS_LOGD("Notification Rdb is created");
}

NotificationPreferencesDatabase::~NotificationPreferencesDatabase()
{
    ANS_LOGD("called");
}

bool NotificationPreferencesDatabase::CheckRdbStore()
{
    if (rdbDataManager_ != nullptr) {
        int32_t result = rdbDataManager_->Init();
        if (result == NativeRdb::E_OK) {
            return true;
        }
    }

    return false;
}

bool NotificationPreferencesDatabase::PutSlotsToDisturbeDB(
    const std::string &bundleName, const int32_t &bundleUid, const std::vector<sptr<NotificationSlot>> &slots)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("called");
    if (bundleName.empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }

    if (slots.empty()) {
        ANS_LOGE("Slot is empty.");
        return false;
    }

    std::unordered_map<std::string, std::string> values;
    for (auto iter : slots) {
        bool result = SlotToEntry(bundleName, bundleUid, iter, values);
        if (!result) {
            return result;
        }
    }
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleUid, userId);
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }
    int32_t result = rdbDataManager_->InsertBatchData(values, userId);
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::PutBundlePropertyToDisturbeDB(
    const NotificationPreferencesInfo::BundleInfo &bundleInfo)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_17, EventBranchId::BRANCH_0);
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("Bundle name is null.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return false;
    }

    message.Message(bundleInfo.GetBundleName() + "_" +std::to_string(bundleInfo.GetBundleUid()));
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        NotificationAnalyticsUtil::ReportModifyEvent(message.BranchId(BRANCH_1));
        return false;
    }
    std::string values;
    std::string bundleKeyStr = KEY_BUNDLE_LABEL + GenerateBundleLablel(bundleInfo);
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleInfo.GetBundleUid(), userId);
    bool result = false;
    GetValueFromDisturbeDB(bundleKeyStr, userId, [&](const int32_t &status, std::string &value) {
        switch (status) {
            case NativeRdb::E_EMPTY_VALUES_BUCKET: {
                result = PutBundleToDisturbeDB(bundleKeyStr, bundleInfo);
                break;
            }
            case NativeRdb::E_OK: {
                ANS_LOGE("Current bundle has exsited.");
                break;
            }
            default:
                break;
        }
    });
    return result;
}

bool NotificationPreferencesDatabase::IsNotificationSlotFlagsExists(const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        return false;
    }
    std::string bundleKey = bundleOption->GetBundleName().append(std::to_string(bundleOption->GetUid()));
    std::string key = GenerateBundleKey(bundleKey, KEY_BUNDLE_SLOTFLGS_TYPE);
    std::string value;
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleOption->GetUid(), userId);
    int32_t result = rdbDataManager_->QueryData(key, value, userId);
    return  (result == NativeRdb::E_OK) || (!value.empty());
}

bool NotificationPreferencesDatabase::PutShowBadge(
    const NotificationPreferencesInfo::BundleInfo &bundleInfo, const bool &enable)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_17, EventBranchId::BRANCH_2);
    message.Message("en:" + std::to_string(enable));
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("Bundle name is nullptr.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return false;
    }
    ANS_LOGI("bundelName:%{public}s, uid:%{public}d, showBadge[%{public}d]",
        bundleInfo.GetBundleName().c_str(), bundleInfo.GetBundleUid(), enable);

    if (!CheckBundle(bundleInfo.GetBundleName(), bundleInfo.GetBundleUid())) {
        return false;
    }

    std::string bundleKey = GenerateBundleLablel(bundleInfo);
    int32_t result = PutBundlePropertyToDisturbeDB(bundleKey, BundleType::BUNDLE_SHOW_BADGE_TYPE, enable,
        bundleInfo.GetBundleUid());
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::PutImportance(
    const NotificationPreferencesInfo::BundleInfo &bundleInfo, const int32_t &importance)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_17, EventBranchId::BRANCH_3);
    message.Message("im:" + std::to_string(importance));
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("Bundle name is empty.");
        message.Message("Bundle name is null");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return false;
    }
    ANS_LOGI("bundelName:%{public}s, uid:%{public}d, importance[%{public}d]",
        bundleInfo.GetBundleName().c_str(), bundleInfo.GetBundleUid(), importance);

    if (!CheckBundle(bundleInfo.GetBundleName(), bundleInfo.GetBundleUid())) {
        return false;
    }

    std::string bundleKey = GenerateBundleLablel(bundleInfo);
    int32_t result = PutBundlePropertyToDisturbeDB(bundleKey, BundleType::BUNDLE_IMPORTANCE_TYPE, importance,
        bundleInfo.GetBundleUid());
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::PutTotalBadgeNums(
    const NotificationPreferencesInfo::BundleInfo &bundleInfo, const int32_t &totalBadgeNum)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_17, EventBranchId::BRANCH_4);
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("Bundle name is blank.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return false;
    }
    ANS_LOGI("bundelName:%{public}s, uid:%{public}d, totalBadgeNum[%{public}d]",
        bundleInfo.GetBundleName().c_str(), bundleInfo.GetBundleUid(), totalBadgeNum);

    if (!CheckBundle(bundleInfo.GetBundleName(), bundleInfo.GetBundleUid())) {
        return false;
    }
    std::string bundleKey = GenerateBundleLablel(bundleInfo);
    int32_t result = PutBundlePropertyToDisturbeDB(bundleKey, BundleType::BUNDLE_BADGE_TOTAL_NUM_TYPE, totalBadgeNum,
        bundleInfo.GetBundleUid());
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::PutNotificationsEnabledForBundle(
    const NotificationPreferencesInfo::BundleInfo &bundleInfo, const bool &enabled)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_17, EventBranchId::BRANCH_5);
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("Bundle name is null.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return false;
    }

    ANS_LOGI("bundelName:%{public}s, uid:%{public}d, enabled[%{public}d]",
        bundleInfo.GetBundleName().c_str(), bundleInfo.GetBundleUid(), enabled);
    if (!CheckBundle(bundleInfo.GetBundleName(), bundleInfo.GetBundleUid())) {
        return false;
    }

    std::string bundleKey = GenerateBundleLablel(bundleInfo);
    int32_t result = PutBundlePropertyToDisturbeDB(bundleKey, BundleType::BUNDLE_ENABLE_NOTIFICATION_TYPE, enabled,
        bundleInfo.GetBundleUid());
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::PutNotificationsEnabled(const int32_t &userId, const bool &enabled)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }

    std::string typeKey =
        std::string().append(KEY_ENABLE_ALL_NOTIFICATION).append(KEY_UNDER_LINE).append(std::to_string(userId));
    std::string enableValue = std::to_string(enabled);
    int32_t result = rdbDataManager_->InsertData(typeKey, enableValue, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Store enable notification failed. %{public}d", result);
        return false;
    }
    return true;
}

bool NotificationPreferencesDatabase::PutSlotFlags(NotificationPreferencesInfo::BundleInfo &bundleInfo,
    const int32_t &slotFlags)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }

    ANS_LOGI("bundelName:%{public}s, uid:%{public}d, slotFlags[%{public}d]",
        bundleInfo.GetBundleName().c_str(), bundleInfo.GetBundleUid(), slotFlags);
    std::string bundleKey = GenerateBundleLablel(bundleInfo);
    int32_t result = PutBundlePropertyToDisturbeDB(bundleKey, BundleType::BUNDLE_SLOTFLGS_TYPE, slotFlags,
        bundleInfo.GetBundleUid());
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::PutHasPoppedDialog(
    const NotificationPreferencesInfo::BundleInfo &bundleInfo, const bool &hasPopped)
{
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }
    ANS_LOGI("bundelName:%{public}s, uid:%{public}d, hasPopped[%{public}d]",
        bundleInfo.GetBundleName().c_str(), bundleInfo.GetBundleUid(), hasPopped);

    if (!CheckBundle(bundleInfo.GetBundleName(), bundleInfo.GetBundleUid())) {
        return false;
    }

    std::string bundleKey = GenerateBundleLablel(bundleInfo);
    int32_t result = PutBundlePropertyToDisturbeDB(bundleKey, BundleType::BUNDLE_POPPED_DIALOG_TYPE, hasPopped,
        bundleInfo.GetBundleUid());
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::PutDoNotDisturbDate(
    const int32_t &userId, const sptr<NotificationDoNotDisturbDate> &date)
{
    if (date == nullptr) {
        ANS_LOGE("null date");
        return false;
    }

    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }

    std::string typeKey =
        std::string().append(KEY_DO_NOT_DISTURB_TYPE).append(KEY_UNDER_LINE).append(std::to_string(userId));
    std::string typeValue = std::to_string((int)date->GetDoNotDisturbType());

    std::string beginDateKey =
        std::string().append(KEY_DO_NOT_DISTURB_BEGIN_DATE).append(KEY_UNDER_LINE).append(std::to_string(userId));
    std::string beginDateValue = std::to_string(date->GetBeginDate());

    std::string endDateKey =
        std::string().append(KEY_DO_NOT_DISTURB_END_DATE).append(KEY_UNDER_LINE).append(std::to_string(userId));
    std::string endDateValue = std::to_string(date->GetEndDate());

    std::unordered_map<std::string, std::string> values = {
        {typeKey, typeValue},
        {beginDateKey, beginDateValue},
        {endDateKey, endDateValue},
    };

    int32_t result = rdbDataManager_->InsertBatchData(values, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Store DoNotDisturbDate failed. %{public}d", result);
        return false;
    }

    return true;
}

bool NotificationPreferencesDatabase::AddDoNotDisturbProfiles(
    int32_t userId, const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    if (profiles.empty()) {
        ANS_LOGE("Invalid dates.");
        return false;
    }
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }
    std::unordered_map<std::string, std::string> values;
    for (auto profile : profiles) {
        if (profile == nullptr) {
            ANS_LOGE("null profile");
            return false;
        }
        std::string key = std::string().append(KEY_DO_NOT_DISTURB_ID).append(KEY_UNDER_LINE).append(
            std::to_string(userId)).append(KEY_UNDER_LINE).append(std::to_string((int64_t)profile->GetProfileId()));
        values[key] = profile->ToJson();
    }
    int32_t result = rdbDataManager_->InsertBatchData(values, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Add do not disturb profiles failed.");
        return false;
    }
    return true;
}

bool NotificationPreferencesDatabase::RemoveDoNotDisturbProfiles(
    int32_t userId, const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    if (profiles.empty()) {
        ANS_LOGW("Invalid dates.");
        return false;
    }
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }
    std::vector<std::string> keys;
    for (auto profile : profiles) {
        if (profile == nullptr) {
            ANS_LOGE("null profile");
            return false;
        }
        std::string key = std::string().append(KEY_DO_NOT_DISTURB_ID).append(KEY_UNDER_LINE).append(
            std::to_string(userId)).append(KEY_UNDER_LINE).append(std::to_string((int64_t)profile->GetProfileId()));
        keys.push_back(key);
    }
    int32_t result = rdbDataManager_->DeleteBatchData(keys, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Delete do not disturb profiles failed.");
        return false;
    }
    return true;
}

bool NotificationPreferencesDatabase::GetDoNotDisturbProfiles(
    const std::string &key, sptr<NotificationDoNotDisturbProfile> &profile, const int32_t &userId)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }
    std::string values;
    int32_t result = rdbDataManager_->QueryData(key, values, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Use default value. error code is %{public}d", result);
        return false;
    }
    profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    if (profile == nullptr) {
        ANS_LOGE("null profile");
        return false;
    }
    profile->FromJson(values);
    return true;
}

void NotificationPreferencesDatabase::GetValueFromDisturbeDB(
    const std::string &key, const int32_t &userId, std::function<void(std::string &)> callback)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return;
    }
    std::string value;
    int32_t result = rdbDataManager_->QueryData(key, value, userId);
    if (result == NativeRdb::E_ERROR) {
        ANS_LOGE("Get value failed, use default value. error code is %{public}d", result);
        return;
    }
    callback(value);
}

void NotificationPreferencesDatabase::GetValueFromDisturbeDB(
    const std::string &key, const int32_t &userId, std::function<void(int32_t &, std::string &)> callback)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return;
    }
    std::string value;
    int32_t result = rdbDataManager_->QueryData(key, value, userId);
    callback(result, value);
}

bool NotificationPreferencesDatabase::CheckBundle(const std::string &bundleName, const int32_t &bundleUid)
{
    std::string bundleKeyStr = KEY_BUNDLE_LABEL + bundleName + std::to_string(bundleUid);
    ANS_LOGD("CheckBundle bundleKeyStr %{public}s", bundleKeyStr.c_str());
    bool result = true;
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleUid, userId);
    GetValueFromDisturbeDB(bundleKeyStr, userId, [&](const int32_t &status, std::string &value) {
        switch (status) {
            case NativeRdb::E_EMPTY_VALUES_BUCKET: {
                NotificationPreferencesInfo::BundleInfo bundleInfo;
                bundleInfo.SetBundleName(bundleName);
                bundleInfo.SetBundleUid(bundleUid);
                bundleInfo.SetEnableNotification(CheckApiCompatibility(bundleName, bundleUid));
                result = PutBundleToDisturbeDB(bundleKeyStr, bundleInfo);
                break;
            }
            case NativeRdb::E_OK: {
                result = true;
                break;
            }
            default:
                result = false;
                break;
        }
    });
    return result;
}

bool NotificationPreferencesDatabase::PutBundlePropertyValueToDisturbeDB(
    const NotificationPreferencesInfo::BundleInfo &bundleInfo)
{
    std::unordered_map<std::string, std::string> values;
    std::string bundleKey = bundleInfo.GetBundleName().append(std::to_string(bundleInfo.GetBundleUid()));
    GenerateEntry(GenerateBundleKey(bundleKey, KEY_BUNDLE_NAME), bundleInfo.GetBundleName(), values);
    GenerateEntry(GenerateBundleKey(bundleKey, KEY_BUNDLE_BADGE_TOTAL_NUM),
        std::to_string(bundleInfo.GetBadgeTotalNum()),
        values);
    GenerateEntry(
        GenerateBundleKey(bundleKey, KEY_BUNDLE_IMPORTANCE), std::to_string(bundleInfo.GetImportance()), values);
    GenerateEntry(
        GenerateBundleKey(bundleKey, KEY_BUNDLE_SHOW_BADGE), std::to_string(bundleInfo.GetIsShowBadge()), values);
    GenerateEntry(GenerateBundleKey(bundleKey, KEY_BUNDLE_ENABLE_NOTIFICATION),
        std::to_string(bundleInfo.GetEnableNotification()),
        values);
    GenerateEntry(GenerateBundleKey(bundleKey, KEY_BUNDLE_POPPED_DIALOG),
        std::to_string(bundleInfo.GetHasPoppedDialog()),
        values);
    GenerateEntry(GenerateBundleKey(bundleKey, KEY_BUNDLE_UID), std::to_string(bundleInfo.GetBundleUid()), values);
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleInfo.GetBundleUid(), userId);
    int32_t result = rdbDataManager_->InsertBatchData(values, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Store bundle failed. %{public}d", result);
        return false;
    }
    return true;
}

bool NotificationPreferencesDatabase::ParseFromDisturbeDB(NotificationPreferencesInfo &info, int32_t userId)
{
    ANS_LOGD("called");
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }
    std::vector<int> activeUserId;
    if (userId == -1) {
        OsAccountManagerHelper::GetInstance().GetAllActiveOsAccount(activeUserId);
    } else {
        activeUserId.push_back(userId);
    }

    for (auto iter : activeUserId) {
        GetDoNotDisturbType(info, iter);
        GetDoNotDisturbBeginDate(info, iter);
        GetDoNotDisturbEndDate(info, iter);
        GetEnableAllNotification(info, iter);
        GetDoNotDisturbProfile(info, iter);
    }
    GetDisableNotificationInfo(info);

    return true;
}


bool NotificationPreferencesDatabase::GetBundleInfo(const sptr<NotificationBundleOption> &bundleOption,
    NotificationPreferencesInfo::BundleInfo &bundleInfo)
{
    std::string bundleDBKey = KEY_BUNDLE_LABEL + bundleOption->GetBundleName() +
        std::to_string(bundleOption->GetUid());
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleOption->GetUid(), userId);
    std::string bundleKey;
    int32_t result = rdbDataManager_->QueryData(bundleDBKey, bundleKey, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Get Bundle Info failed,key:%{public}s", bundleDBKey.c_str());
        return false;
    }
    ANS_LOGD("Bundle name is %{public}s.", bundleKey.c_str());
    std::unordered_map<std::string, std::string> bundleEntries;
    rdbDataManager_->QueryDataBeginWithKey((GenerateBundleKey(bundleKey)), bundleEntries, userId);
    ANS_LOGD("Bundle key is %{public}s.", GenerateBundleKey(bundleKey).c_str());
    std::string keyStr = GenerateBundleKey(bundleKey, KEY_BUNDLE_SHOW_BADGE);
    bool badgeEnableExist = false;
    for (auto bundleEntry : bundleEntries) {
        if (IsSlotKey(GenerateBundleKey(bundleKey), bundleEntry.first)) {
            ParseSlotFromDisturbeDB(bundleInfo, bundleKey, bundleEntry, userId);
        } else {
            ParseBundlePropertyFromDisturbeDB(bundleInfo, bundleKey, bundleEntry);
        }

        if (keyStr.compare(bundleEntry.first) == 0) {
            badgeEnableExist = true;
        }
    }

    if (!badgeEnableExist) {
        bundleInfo.SetIsShowBadge(static_cast<bool>(true));
    }
    return true;
}

bool NotificationPreferencesDatabase::RemoveAllDataFromDisturbeDB()
{
    ANS_LOGD("called");
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }
    int32_t result = rdbDataManager_->Destroy();
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::RemoveBundleFromDisturbeDB(
    const std::string &bundleKey, const int32_t &bundleUid)
{
    ANS_LOGD("called");
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleUid, userId);

    std::unordered_map<std::string, std::string> values;
    int32_t result = rdbDataManager_->QueryDataBeginWithKey(
        (KEY_ANS_BUNDLE + KEY_UNDER_LINE + bundleKey + KEY_UNDER_LINE), values, userId);

    if (result == NativeRdb::E_ERROR) {
        ANS_LOGE("Get Bundle Info failed.");
        return false;
    }

    std::vector<std::string> keys;
    for (auto iter : values) {
        keys.push_back(iter.first);
    }

    std::string bundleDBKey = KEY_BUNDLE_LABEL + KEY_BUNDLE_NAME + KEY_UNDER_LINE + bundleKey;
    keys.push_back(bundleDBKey);
    result = rdbDataManager_->DeleteBatchData(keys, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("delete bundle Info failed.");
        return false;
    }
    return true;
}

bool NotificationPreferencesDatabase::RemoveSlotFromDisturbeDB(
    const std::string &bundleKey, const NotificationConstant::SlotType &type, const int32_t &bundleUid)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("called");
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleUid, userId);
    if (bundleKey.empty()) {
        ANS_LOGE("Bundle name is empty.");
        return false;
    }

    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }

    std::unordered_map<std::string, std::string> values;
    std::string slotType = std::to_string(type);
    int32_t result = rdbDataManager_->QueryDataBeginWithKey(
        (GenerateSlotKey(bundleKey, slotType) + KEY_UNDER_LINE), values, userId);
    if (result == NativeRdb::E_ERROR) {
        return false;
    }
    std::vector<std::string> keys;
    for (auto iter : values) {
        keys.push_back(iter.first);
    }

    result = rdbDataManager_->DeleteBatchData(keys, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("delete bundle Info failed.");
        return false;
    }

    return true;
}

bool NotificationPreferencesDatabase::GetAllNotificationEnabledBundles(
    std::vector<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("called");
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }
    std::unordered_map<std::string, std::string> datas;
    const std::string ANS_BUNDLE_BEGIN = "ans_bundle_";
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    int32_t errCode = rdbDataManager_->QueryDataBeginWithKey(ANS_BUNDLE_BEGIN, datas, userId);
    if (errCode != NativeRdb::E_OK) {
        ANS_LOGE("Query data begin with ans_bundle_ from db error");
        return false;
    }
    return HandleDataBaseMap(datas, bundleOption);
}

bool NotificationPreferencesDatabase::GetAllDistribuedEnabledBundles(int32_t userId,
    const std::string &deviceType, std::vector<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("called");
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }
    std::string key = std::string(KEY_ENABLE_BUNDLE_DISTRIBUTED_NOTIFICATION).append(KEY_MIDDLE_LINE);
    ANS_LOGD("key is %{public}s", key.c_str());
    std::unordered_map<std::string, std::string> values;
    int32_t result = rdbDataManager_->QueryDataBeginWithKey(key, values, userId);
    if (result == NativeRdb::E_EMPTY_VALUES_BUCKET) {
        return true;
    } else if (result != NativeRdb::E_OK) {
        ANS_LOGE("Get failed, key %{public}s,result %{public}d.", key.c_str(), result);
        return NativeRdb::E_ERROR;
    }

    for (auto& Item : values) {
        if (!static_cast<bool>(StringToInt(Item.second))) {
            continue;
        }
        std::vector<std::string> result;
        StringSplit(Item.first, '-', result);
        if (result.size() != DISTRIBUTED_KEY_NUM && result.back() != deviceType) {
            continue;
        }
        int32_t uid = StringToInt(result[DISTRIBUTED_KEY_UID_INDEX]);
        NotificationBundleOption bundleInfo(result[DISTRIBUTED_KEY_BUNDLE_INDEX], uid);
        bundleOption.push_back(bundleInfo);
        result.clear();
    }
    return true;
}

void NotificationPreferencesDatabase::StringSplit(const std::string content, char delim,
    std::vector<std::string>& result) const
{
    std::string token;
    std::istringstream in(content);
    while (std::getline(in, token, delim)) {
        result.push_back(token);
    }
}

bool NotificationPreferencesDatabase::HandleDataBaseMap(
    const std::unordered_map<std::string, std::string> &datas, std::vector<NotificationBundleOption> &bundleOption)
{
    std::regex matchBundlenamePattern("^ans_bundle_(.*)_name$");
    std::smatch match;
    int32_t currentUserId = SUBSCRIBE_USER_INIT;
    ErrCode result = ERR_OK;
    result = OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(currentUserId);
    if (result != ERR_OK) {
        ANS_LOGE("Get account id fail");
        return false;
    }
    constexpr int MIDDLE_KEY = 1;
    for (const auto &dataMapItem : datas) {
        const std::string &key = dataMapItem.first;
        const std::string &value = dataMapItem.second;
        if (!std::regex_match(key, match, matchBundlenamePattern)) {
            continue;
        }
        std::string matchKey = match[MIDDLE_KEY].str();
        std::string matchUid = "ans_bundle_" + matchKey + "_uid";
        std::string matchEnableNotification = "ans_bundle_" + matchKey + "_enabledNotification";
        auto enableNotificationItem = datas.find(matchEnableNotification);
        if (enableNotificationItem == datas.end()) {
            continue;
        }
        if (static_cast<bool>(StringToInt(enableNotificationItem->second))) {
            auto uidItem = datas.find(matchUid);
            if (uidItem == datas.end()) {
                continue;
            }
            int userid = -1;
            result =
                OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(StringToInt(uidItem->second), userid);
            if (result != ERR_OK) {
                return false;
            }
            if (userid != currentUserId && !(currentUserId == DEFAULT_USER_ID && userid == ZERO_USER_ID)) {
                continue;
            }
            NotificationBundleOption obj(value, StringToInt(uidItem->second));
            bundleOption.emplace_back(obj);
        }
    }
    return true;
}

bool NotificationPreferencesDatabase::RemoveAllSlotsFromDisturbeDB(
    const std::string &bundleKey, const int32_t &bundleUid)
{
    ANS_LOGD("called");
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleUid, userId);
    if (bundleKey.empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }

    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }

    std::unordered_map<std::string, std::string> values;
    int32_t result = rdbDataManager_->QueryDataBeginWithKey(
        (GenerateSlotKey(bundleKey) + KEY_UNDER_LINE), values, userId);
    if (result == NativeRdb::E_ERROR) {
        return false;
    }
    std::vector<std::string> keys;
    for (auto iter : values) {
        keys.push_back(iter.first);
    }

    result = rdbDataManager_->DeleteBatchData(keys, userId);
    return (result == NativeRdb::E_OK);
}

template <typename T>
int32_t NotificationPreferencesDatabase::PutBundlePropertyToDisturbeDB(
    const std::string &bundleKey, const BundleType &type, const T &t, const int32_t &bundleUid)
{
    std::string keyStr;
    switch (type) {
        case BundleType::BUNDLE_BADGE_TOTAL_NUM_TYPE:
            keyStr = GenerateBundleKey(bundleKey, KEY_BUNDLE_BADGE_TOTAL_NUM);
            break;
        case BundleType::BUNDLE_IMPORTANCE_TYPE:
            keyStr = GenerateBundleKey(bundleKey, KEY_BUNDLE_IMPORTANCE);
            break;
        case BundleType::BUNDLE_SHOW_BADGE_TYPE:
            keyStr = GenerateBundleKey(bundleKey, KEY_BUNDLE_SHOW_BADGE);
            break;
        case BundleType::BUNDLE_ENABLE_NOTIFICATION_TYPE:
            keyStr = GenerateBundleKey(bundleKey, KEY_BUNDLE_ENABLE_NOTIFICATION);
            break;
        case BundleType::BUNDLE_POPPED_DIALOG_TYPE:
            ANS_LOGD("Into BUNDLE_POPPED_DIALOG_TYPE:GenerateBundleKey.");
            keyStr = GenerateBundleKey(bundleKey, KEY_BUNDLE_POPPED_DIALOG);
            break;
        case BundleType::BUNDLE_SLOTFLGS_TYPE:
            ANS_LOGD("Into BUNDLE_SLOTFLGS_TYPE:GenerateBundleKey.");
            keyStr = GenerateBundleKey(bundleKey, KEY_BUNDLE_SLOTFLGS_TYPE);
            break;
        default:
            break;
    }
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleUid, userId);
    std::string valueStr = std::to_string(t);
    int32_t result = rdbDataManager_->InsertData(keyStr, valueStr, userId);
    return result;
}

bool NotificationPreferencesDatabase::PutBundleToDisturbeDB(
    const std::string &bundleKey, const NotificationPreferencesInfo::BundleInfo &bundleInfo)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleInfo.GetBundleUid(), userId);

    ANS_LOGD("Key not fund, so create a bundle, bundle key is %{public}s.", bundleKey.c_str());
    int32_t result = rdbDataManager_->InsertData(bundleKey, GenerateBundleLablel(bundleInfo), userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Store bundle name to db is failed.");
        return false;
    }

    if (!PutBundlePropertyValueToDisturbeDB(bundleInfo)) {
        return false;
    }
    return true;
}

void NotificationPreferencesDatabase::GenerateEntry(
    const std::string &key, const std::string &value, std::unordered_map<std::string, std::string> &values) const
{
    values.emplace(key, value);
}

bool NotificationPreferencesDatabase::SlotToEntry(const std::string &bundleName, const int32_t &bundleUid,
    const sptr<NotificationSlot> &slot, std::unordered_map<std::string, std::string> &values)
{
    if (slot == nullptr) {
        ANS_LOGE("null slot");
        return false;
    }

    if (!CheckBundle(bundleName, bundleUid)) {
        return false;
    }

    std::string bundleKey = bundleName + std::to_string(bundleUid);
    GenerateSlotEntry(bundleKey, slot, values);
    return true;
}

void NotificationPreferencesDatabase::GenerateSlotEntry(const std::string &bundleKey,
    const sptr<NotificationSlot> &slot, std::unordered_map<std::string, std::string> &values) const
{
    std::string slotType = std::to_string(slot->GetType());
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_TYPE), std::to_string(slot->GetType()), values);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_ID), slot->GetId(), values);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_NAME), slot->GetName(), values);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_DESCRIPTION), slot->GetDescription(), values);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_LEVEL), std::to_string(slot->GetLevel()), values);
    GenerateEntry(
        GenerateSlotKey(bundleKey, slotType, KEY_SLOT_SHOW_BADGE), std::to_string(slot->IsShowBadge()), values);
    GenerateEntry(
        GenerateSlotKey(bundleKey, slotType, KEY_SLOT_ENABLE_LIGHT), std::to_string(slot->CanEnableLight()), values);
    GenerateEntry(
        GenerateSlotKey(bundleKey, slotType, KEY_SLOT_ENABLE_VRBRATION), std::to_string(slot->CanVibrate()), values);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_LED_LIGHT_COLOR),
        std::to_string(slot->GetLedLightColor()), values);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_LOCKSCREEN_VISIBLENESS),
        std::to_string(static_cast<int>(slot->GetLockScreenVisibleness())), values);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_SOUND), slot->GetSound().ToString(), values);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_ENABLE_BYPASS_DND),
        std::to_string(slot->IsEnableBypassDnd()), values);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_VIBRATION_STYLE),
        VectorToString(slot->GetVibrationStyle()), values);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_ENABLED), std::to_string(slot->GetEnable()), values);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_AUTHORIZED_STATUS),
        std::to_string(slot->GetAuthorizedStatus()), values);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_AUTH_HINT_CNT),
        std::to_string(slot->GetAuthHintCnt()), values);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_REMINDER_MODE),
        std::to_string(slot->GetReminderMode()), values);
}

void NotificationPreferencesDatabase::ParseBundleFromDistureDB(NotificationPreferencesInfo &info,
    const std::unordered_map<std::string, std::string> &values, const int32_t &userId)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return;
    }
    for (auto item : values) {
        std::string bundleKey = item.second;
        ANS_LOGD("Bundle name is %{public}s.", bundleKey.c_str());
        std::unordered_map<std::string, std::string> bundleEntries;
        rdbDataManager_->QueryDataBeginWithKey((GenerateBundleKey(bundleKey)), bundleEntries, userId);
        ANS_LOGD("Bundle key is %{public}s.", GenerateBundleKey(bundleKey).c_str());
        NotificationPreferencesInfo::BundleInfo bunldeInfo;
        std::string keyStr = GenerateBundleKey(bundleKey, KEY_BUNDLE_SHOW_BADGE);
        bool badgeEnableExist = false;
        for (auto bundleEntry : bundleEntries) {
            if (IsSlotKey(GenerateBundleKey(bundleKey), bundleEntry.first)) {
                ParseSlotFromDisturbeDB(bunldeInfo, bundleKey, bundleEntry, userId);
            } else {
                ParseBundlePropertyFromDisturbeDB(bunldeInfo, bundleKey, bundleEntry);
            }

            if (keyStr.compare(bundleEntry.first) == 0) {
                badgeEnableExist = true;
            }
        }

        if (!badgeEnableExist) {
            bunldeInfo.SetIsShowBadge(static_cast<bool>(true));
        }

        info.SetBundleInfoFromDb(bunldeInfo, bundleKey);
    }
}

void NotificationPreferencesDatabase::ParseSlotFromDisturbeDB(NotificationPreferencesInfo::BundleInfo &bundleInfo,
    const std::string &bundleKey, const std::pair<std::string, std::string> &entry, const int32_t &userId)
{
    std::string slotKey = entry.first;
    std::string typeStr = SubUniqueIdentifyFromString(GenerateSlotKey(bundleKey) + KEY_UNDER_LINE, slotKey);
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(StringToInt(typeStr));
    sptr<NotificationSlot> slot = nullptr;
    if (!bundleInfo.GetSlot(slotType, slot)) {
        slot = new (std::nothrow) NotificationSlot(slotType);
        if (slot == nullptr) {
            ANS_LOGE("null slot");
            return;
        }
    }
    std::string findString = GenerateSlotKey(bundleKey, typeStr) + KEY_UNDER_LINE;
    ParseSlot(findString, slot, entry, userId);
    bundleInfo.SetSlot(slot);
}

void NotificationPreferencesDatabase::ParseBundlePropertyFromDisturbeDB(
    NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &bundleKey,
    const std::pair<std::string, std::string> &entry)
{
    std::string typeStr = FindLastString(GenerateBundleKey(bundleKey), entry.first);
    std::string valueStr = entry.second;

    if (typeStr.compare(KEY_BUNDLE_NAME) == 0) {
        return ParseBundleName(bundleInfo, valueStr);
    }
    if (typeStr.compare(KEY_BUNDLE_IMPORTANCE) == 0) {
        return ParseBundleImportance(bundleInfo, valueStr);
    }
    if (typeStr.compare(KEY_BUNDLE_SHOW_BADGE) == 0) {
        return ParseBundleShowBadgeEnable(bundleInfo, valueStr);
    }
    if (typeStr.compare(KEY_BUNDLE_BADGE_TOTAL_NUM) == 0) {
        return ParseBundleBadgeNum(bundleInfo, valueStr);
    }
    if (typeStr.compare(KEY_BUNDLE_ENABLE_NOTIFICATION) == 0) {
        return ParseBundleEnableNotification(bundleInfo, valueStr);
    }
    if (typeStr.compare(KEY_BUNDLE_POPPED_DIALOG) == 0) {
        return ParseBundlePoppedDialog(bundleInfo, valueStr);
    }
    if (typeStr.compare(KEY_BUNDLE_UID) == 0) {
        return ParseBundleUid(bundleInfo, valueStr);
    }
    if (typeStr.compare(KEY_BUNDLE_SLOTFLGS_TYPE) == 0) {
        return ParseBundleSlotFlags(bundleInfo, valueStr);
    }
}

void NotificationPreferencesDatabase::ParseSlot(const std::string &findString, sptr<NotificationSlot> &slot,
    const std::pair<std::string, std::string> &entry, const int32_t &userId)
{
    std::string typeStr = FindLastString(findString, entry.first);
    std::string valueStr = entry.second;
    ANS_LOGD("db key = %{public}s , %{public}s : %{public}s ",
        entry.first.c_str(),
        typeStr.c_str(),
        entry.second.c_str());
    SetSoltProperty(slot, typeStr, valueStr, findString, userId);
}

void NotificationPreferencesDatabase::SetSoltProperty(sptr<NotificationSlot> &slot, std::string &typeStr,
    std::string &valueStr, const std::string &findString, const int32_t &userId)
{
    if (typeStr.compare(KEY_SLOT_DESCRIPTION) == 0) {
        return ParseSlotDescription(slot, valueStr);
    }
    if (typeStr.compare(KEY_SLOT_LEVEL) == 0) {
        return ParseSlotLevel(slot, valueStr);
    }
    if (typeStr.compare(KEY_SLOT_SHOW_BADGE) == 0) {
        return ParseSlotShowBadge(slot, valueStr);
    }
    if (typeStr.compare(KEY_SLOT_ENABLE_LIGHT) == 0) {
        return ParseSlotEnableLight(slot, valueStr);
    }
    if (typeStr.compare(KEY_SLOT_ENABLE_VRBRATION) == 0) {
        return ParseSlotEnableVrbration(slot, valueStr);
    }
    if (typeStr.compare(KEY_SLOT_LED_LIGHT_COLOR) == 0) {
        return ParseSlotLedLightColor(slot, valueStr);
    }
    if (typeStr.compare(KEY_SLOT_LOCKSCREEN_VISIBLENESS) == 0) {
        return ParseSlotLockscreenVisibleness(slot, valueStr);
    }
    if (typeStr.compare(KEY_SLOT_SOUND) == 0) {
        return ParseSlotSound(slot, valueStr);
    }
    if (typeStr.compare(KEY_SLOT_VIBRATION_STYLE) == 0) {
        return ParseSlotVibrationSytle(slot, valueStr);
    }
    if (typeStr.compare(KEY_SLOT_ENABLE_BYPASS_DND) == 0) {
        return ParseSlotEnableBypassDnd(slot, valueStr);
    }
    if (typeStr.compare(KEY_SLOT_ENABLED) == 0) {
        return ParseSlotEnabled(slot, valueStr);
    }
    if (typeStr.compare(KEY_SLOT_SLOTFLGS_TYPE) == 0) {
        return ParseSlotFlags(slot, valueStr);
    }
    if (typeStr.compare(KEY_SLOT_AUTHORIZED_STATUS) == 0) {
        return ParseSlotAuthorizedStatus(slot, valueStr);
    }
    if (typeStr.compare(KEY_SLOT_AUTH_HINT_CNT) == 0) {
        return ParseSlotAuthHitnCnt(slot, valueStr);
    }
    ExecuteDisturbeDB(slot, typeStr, valueStr, findString, userId);
}

void NotificationPreferencesDatabase::ExecuteDisturbeDB(sptr<NotificationSlot> &slot, std::string &typeStr,
    std::string &valueStr, const std::string &findString, const int32_t &userId)
{
    if (typeStr.compare(KEY_REMINDER_MODE) == 0) {
        return ParseSlotReminderMode(slot, valueStr);
    }
    if (!typeStr.compare(KEY_SLOT_VIBRATION_STYLE)) {
        GetValueFromDisturbeDB(findString + KEY_SLOT_ENABLE_VRBRATION, userId,
            [&](std::string &value) { ParseSlotEnableVrbration(slot, value); });
    }
}

std::string NotificationPreferencesDatabase::FindLastString(
    const std::string &findString, const std::string &inputString) const
{
    std::string keyStr;
    size_t pos = findString.size();
    if (pos != std::string::npos) {
        keyStr = inputString.substr(pos);
    }
    return keyStr;
}

std::string NotificationPreferencesDatabase::VectorToString(const std::vector<int64_t> &data) const
{
    std::stringstream streamStr;
    std::copy(data.begin(), data.end(), std::ostream_iterator<int>(streamStr, KEY_UNDER_LINE.c_str()));
    return streamStr.str();
}

void NotificationPreferencesDatabase::StringToVector(const std::string &str, std::vector<int64_t> &data) const
{
    if (str.empty()) {
        return;
    }

    if (str.find_first_of(KEY_UNDER_LINE) != std::string::npos) {
        std::string str1 = str.substr(0, str.find_first_of(KEY_UNDER_LINE));
        std::string afterStr = str.substr(str.find_first_of(KEY_UNDER_LINE) + 1);
        data.push_back(StringToInt(str1));
        StringToVector(afterStr, data);
    }
}

int32_t NotificationPreferencesDatabase::StringToInt(const std::string &str) const
{
    int32_t value = 0;
    if (!str.empty()) {
        value = atoi(str.c_str());
    }
    return value;
}

int64_t NotificationPreferencesDatabase::StringToInt64(const std::string &str) const
{
    int64_t value = 0;
    if (!str.empty()) {
        value = atoll(str.c_str());
    }
    return value;
}

bool NotificationPreferencesDatabase::IsSlotKey(const std::string &bundleKey, const std::string &key) const
{
    std::string tempStr = FindLastString(bundleKey, key);
    size_t pos = tempStr.find_first_of(KEY_UNDER_LINE);
    std::string slotStr;
    if (pos != std::string::npos) {
        slotStr = tempStr.substr(0, pos);
    }
    if (!slotStr.compare(KEY_SLOT)) {
        return true;
    }
    return false;
}

std::string NotificationPreferencesDatabase::GenerateSlotKey(
    const std::string &bundleKey, const std::string &type, const std::string &subType) const
{
    /* slot key
     *
     * KEY_ANS_BUNDLE_bundlename_slot_type_0_id
     * KEY_ANS_BUNDLE_bundlename_slot_type_0_des
     * KEY_ANS_BUNDLE_bundlename_slot_type_1_id
     * KEY_ANS_BUNDLE_bundlename_slot_type_1_des
     *
     */
    std::string key = GenerateBundleKey(bundleKey).append(KEY_SLOT).append(KEY_UNDER_LINE).append(KEY_SLOT_TYPE);
    if (!type.empty()) {
        key.append(KEY_UNDER_LINE).append(type);
    }
    if (!subType.empty()) {
        key.append(KEY_UNDER_LINE).append(subType);
    }
    ANS_LOGD("Slot key is : %{public}s.", key.c_str());
    return key;
}

std::string NotificationPreferencesDatabase::GenerateBundleKey(
    const std::string &bundleKey, const std::string &type) const
{
    /* bundle key
     *
     * label_KEY_ANS_KEY_BUNDLE_NAME = ""
     * KEY_ANS_BUNDLE_bundlename_
     * KEY_ANS_BUNDLE_bundlename_
     * KEY_ANS_BUNDLE_bundlename_
     * KEY_ANS_BUNDLE_bundlename_
     *
     */
    ANS_LOGD("%{public}s, bundleKey[%{public}s] type[%{public}s]", __FUNCTION__, bundleKey.c_str(), type.c_str());
    std::string key =
        std::string().append(KEY_ANS_BUNDLE).append(KEY_UNDER_LINE).append(bundleKey).append(KEY_UNDER_LINE);
    if (!type.empty()) {
        key.append(type);
    }
    ANS_LOGD("Bundle key : %{public}s.", key.c_str());
    return key;
}

std::string NotificationPreferencesDatabase::SubUniqueIdentifyFromString(
    const std::string &findString, const std::string &keyStr) const
{
    std::string slotType;
    std::string tempStr = FindLastString(findString, keyStr);
    size_t pos = tempStr.find_last_of(KEY_UNDER_LINE);
    if (pos != std::string::npos) {
        slotType = tempStr.substr(0, pos);
    }

    return slotType;
}

void NotificationPreferencesDatabase::ParseBundleName(
    NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &value) const
{
    ANS_LOGD("SetBundleName bundle name is %{public}s.", value.c_str());
    bundleInfo.SetBundleName(value);
}

void NotificationPreferencesDatabase::ParseBundleImportance(
    NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &value) const
{
    ANS_LOGD("SetBundleImportance bundle importance is %{public}s.", value.c_str());
    bundleInfo.SetImportance(static_cast<NotificationSlot::NotificationLevel>(StringToInt(value)));
}

void NotificationPreferencesDatabase::ParseBundleShowBadgeEnable(
    NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &value) const
{
    ANS_LOGD("SetBundleShowBadge bundle show badge is %{public}s.", value.c_str());
    bundleInfo.SetIsShowBadge(static_cast<bool>(StringToInt(value)));
}

void NotificationPreferencesDatabase::ParseBundleBadgeNum(
    NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &value) const
{
    ANS_LOGD("SetBundleBadgeNum bundle badge num is %{public}s.", value.c_str());
    bundleInfo.SetBadgeTotalNum(StringToInt(value));
}

void NotificationPreferencesDatabase::ParseBundleEnableNotification(
    NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &value) const
{
    ANS_LOGD("SetBundleEnableNotification bundle enable is %{public}s.", value.c_str());
    bundleInfo.SetEnableNotification(static_cast<bool>(StringToInt(value)));
}

void NotificationPreferencesDatabase::ParseBundlePoppedDialog(
    NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &value) const
{
    ANS_LOGD("SetBundlePoppedDialog bundle has popped dialog is %{public}s.", value.c_str());
    bundleInfo.SetHasPoppedDialog(static_cast<bool>(StringToInt(value)));
}

void NotificationPreferencesDatabase::ParseBundleUid(
    NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &value) const
{
    ANS_LOGD("SetBundleUid uuid is %{public}s.", value.c_str());
    bundleInfo.SetBundleUid(StringToInt(value));
}

void NotificationPreferencesDatabase::ParseSlotDescription(sptr<NotificationSlot> &slot, const std::string &value) const
{
    ANS_LOGD("ParseSlotDescription slot des is %{public}s.", value.c_str());
    std::string slotDescription = value;
    slot->SetDescription(slotDescription);
}

void NotificationPreferencesDatabase::ParseSlotLevel(sptr<NotificationSlot> &slot, const std::string &value) const
{
    ANS_LOGD("ParseSlotLevel slot level is %{public}s.", value.c_str());
    NotificationSlot::NotificationLevel level = static_cast<NotificationSlot::NotificationLevel>(StringToInt(value));
    slot->SetLevel(level);
}

void NotificationPreferencesDatabase::ParseSlotShowBadge(sptr<NotificationSlot> &slot, const std::string &value) const
{
    ANS_LOGD("ParseSlotShowBadge slot show badge is %{public}s.", value.c_str());
    bool showBadge = static_cast<bool>(StringToInt(value));
    slot->EnableBadge(showBadge);
}

void NotificationPreferencesDatabase::ParseSlotFlags(sptr<NotificationSlot> &slot, const std::string &value) const
{
    ANS_LOGD("ParseSlotFlags slot show flags is %{public}s.", value.c_str());
    uint32_t slotFlags = static_cast<uint32_t>(StringToInt(value));
    slot->SetSlotFlags(slotFlags);
}

void NotificationPreferencesDatabase::ParseBundleSlotFlags(NotificationPreferencesInfo::BundleInfo &bundleInfo,
    const std::string &value) const
{
    ANS_LOGD("ParseBundleSlotFlags slot show flags is %{public}s.", value.c_str());
    bundleInfo.SetSlotFlags(StringToInt(value));
}

void NotificationPreferencesDatabase::ParseSlotEnableLight(sptr<NotificationSlot> &slot, const std::string &value) const
{
    ANS_LOGD("ParseSlotEnableLight slot enable light is %{public}s.", value.c_str());
    bool enableLight = static_cast<bool>(StringToInt(value));
    slot->SetEnableLight(enableLight);
}

void NotificationPreferencesDatabase::ParseSlotEnableVrbration(
    sptr<NotificationSlot> &slot, const std::string &value) const
{
    ANS_LOGD("ParseSlotEnableVrbration slot enable vir is %{public}s.", value.c_str());
    bool enableVrbration = static_cast<bool>(StringToInt(value));
    slot->SetEnableVibration(enableVrbration);
}

void NotificationPreferencesDatabase::ParseSlotLedLightColor(
    sptr<NotificationSlot> &slot, const std::string &value) const
{
    ANS_LOGD("ParseSlotLedLightColor slot led is %{public}s.", value.c_str());
    int32_t ledLightColor = static_cast<int32_t>(StringToInt(value));
    slot->SetLedLightColor(ledLightColor);
}

void NotificationPreferencesDatabase::ParseSlotLockscreenVisibleness(
    sptr<NotificationSlot> &slot, const std::string &value) const
{

    ANS_LOGD("ParseSlotLockscreenVisibleness slot visible is %{public}s.", value.c_str());
    NotificationConstant::VisiblenessType visible =
        static_cast<NotificationConstant::VisiblenessType>(StringToInt(value));
    slot->SetLockscreenVisibleness(visible);
}

void NotificationPreferencesDatabase::ParseSlotSound(sptr<NotificationSlot> &slot, const std::string &value) const
{
    ANS_LOGD("ParseSlotSound slot sound is %{public}s.", value.c_str());
    std::string slotUri = value;
    Uri uri(slotUri);
    slot->SetSound(uri);
}

void NotificationPreferencesDatabase::ParseSlotVibrationSytle(
    sptr<NotificationSlot> &slot, const std::string &value) const
{
    ANS_LOGD("ParseSlotVibrationSytle slot vibration style is %{public}s.", value.c_str());
    std::vector<int64_t> vibrationStyle;
    StringToVector(value, vibrationStyle);
    slot->SetVibrationStyle(vibrationStyle);
}

void NotificationPreferencesDatabase::ParseSlotEnableBypassDnd(
    sptr<NotificationSlot> &slot, const std::string &value) const
{
    ANS_LOGD("ParseSlotEnableBypassDnd slot by pass dnd is %{public}s.", value.c_str());
    bool enable = static_cast<bool>(StringToInt(value));
    slot->EnableBypassDnd(enable);
}

void NotificationPreferencesDatabase::ParseSlotEnabled(
    sptr<NotificationSlot> &slot, const std::string &value) const
{
    ANS_LOGD("ParseSlotEnabled slot enabled is %{public}s.", value.c_str());
    bool enabled = static_cast<bool>(StringToInt(value));
    slot->SetEnable(enabled);
}

void NotificationPreferencesDatabase::ParseSlotAuthorizedStatus(
    sptr<NotificationSlot> &slot, const std::string &value) const
{
    ANS_LOGD("ParseSlotAuthorizedStatus slot status is %{public}s.", value.c_str());
    int32_t status = static_cast<int32_t>(StringToInt(value));
    slot->SetAuthorizedStatus(status);
}

void NotificationPreferencesDatabase::ParseSlotAuthHitnCnt(
    sptr<NotificationSlot> &slot, const std::string &value) const
{
    ANS_LOGD("ParseSlotAuthHitnCnt slot count is %{public}s.", value.c_str());
    int32_t count = static_cast<int32_t>(StringToInt(value));
    slot->SetAuthHintCnt(count);
}

void NotificationPreferencesDatabase::ParseSlotReminderMode(
    sptr<NotificationSlot> &slot, const std::string &value) const
{
    ANS_LOGD("ParseSlotReminderMode slot reminder mode is %{public}s.", value.c_str());
    int32_t reminderMode = static_cast<int32_t>(StringToInt(value));
    slot->SetReminderMode(reminderMode);
}

std::string NotificationPreferencesDatabase::GenerateBundleLablel(
    const NotificationPreferencesInfo::BundleInfo &bundleInfo) const
{
    return bundleInfo.GetBundleName().append(std::to_string(bundleInfo.GetBundleUid()));
}

void NotificationPreferencesDatabase::GetDoNotDisturbType(NotificationPreferencesInfo &info, int32_t userId)
{
    std::string key =
        std::string().append(KEY_DO_NOT_DISTURB_TYPE).append(KEY_UNDER_LINE).append(std::to_string(userId));
    GetValueFromDisturbeDB(
        key, userId, [&](const int32_t &status, std::string &value) {
            sptr<NotificationDoNotDisturbDate> disturbDate = new (std::nothrow)
                NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
            if (disturbDate == nullptr) {
                ANS_LOGE("null disturbDate");
                return;
            }
            info.GetDoNotDisturbDate(userId, disturbDate);
            if (status == NativeRdb::E_EMPTY_VALUES_BUCKET) {
                PutDoNotDisturbDate(userId, disturbDate);
            } else if (status == NativeRdb::E_OK) {
                if (!value.empty()) {
                    if (disturbDate != nullptr) {
                        disturbDate->SetDoNotDisturbType(
                            (NotificationConstant::DoNotDisturbType)StringToInt(value));
                    }
                }
            } else {
                ANS_LOGW("Parse disturbe mode failed, use default value.");
            }
            info.SetDoNotDisturbDate(userId, disturbDate);
        });
}

void NotificationPreferencesDatabase::GetDoNotDisturbBeginDate(NotificationPreferencesInfo &info, int32_t userId)
{
    std::string key =
        std::string().append(KEY_DO_NOT_DISTURB_BEGIN_DATE).append(KEY_UNDER_LINE).append(std::to_string(userId));
    GetValueFromDisturbeDB(
        key, userId, [&](const int32_t &status, std::string &value) {
            sptr<NotificationDoNotDisturbDate> disturbDate = new (std::nothrow)
                NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
            if (disturbDate == nullptr) {
                ANS_LOGE("null disturbDate");
                return;
            }
            info.GetDoNotDisturbDate(userId, disturbDate);
            if (status == NativeRdb::E_EMPTY_VALUES_BUCKET) {
                PutDoNotDisturbDate(userId, disturbDate);
            } else if (status == NativeRdb::E_OK) {
                if (!value.empty()) {
                    if (disturbDate != nullptr) {
                        disturbDate->SetBeginDate(StringToInt64(value));
                    }
                }
            } else {
                ANS_LOGW("Parse disturbe start time failed, use default value.");
            }
            info.SetDoNotDisturbDate(userId, disturbDate);
        });
}

void NotificationPreferencesDatabase::GetDoNotDisturbEndDate(NotificationPreferencesInfo &info, int32_t userId)
{
    std::string key =
        std::string().append(KEY_DO_NOT_DISTURB_END_DATE).append(KEY_UNDER_LINE).append(std::to_string(userId));
    GetValueFromDisturbeDB(
        key, userId, [&](const int32_t &status, std::string &value) {
            sptr<NotificationDoNotDisturbDate> disturbDate = new (std::nothrow)
                NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
            if (disturbDate == nullptr) {
                ANS_LOGE("null disturbDate");
                return;
            }
            info.GetDoNotDisturbDate(userId, disturbDate);
            if (status == NativeRdb::E_EMPTY_VALUES_BUCKET) {
                PutDoNotDisturbDate(userId, disturbDate);
            } else if (status == NativeRdb::E_OK) {
                if (!value.empty()) {
                    if (disturbDate != nullptr) {
                        disturbDate->SetEndDate(StringToInt64(value));
                    }
                }
            } else {
                ANS_LOGW("Parse disturbe end time failed, use default value.");
            }
            info.SetDoNotDisturbDate(userId, disturbDate);
        });
}

void NotificationPreferencesDatabase::GetEnableAllNotification(NotificationPreferencesInfo &info, int32_t userId)
{
    std::string key =
        std::string().append(KEY_ENABLE_ALL_NOTIFICATION).append(KEY_UNDER_LINE).append(std::to_string(userId));
    GetValueFromDisturbeDB(
        key, userId, [&](const int32_t &status, std::string &value) {
            if (status == NativeRdb::E_EMPTY_VALUES_BUCKET) {
                bool enable = true;
                if (!info.GetEnabledAllNotification(userId, enable)) {
                    info.SetEnabledAllNotification(userId, enable);
                    ANS_LOGW("Enable setting not found, default true.");
                }
                PutNotificationsEnabled(userId, enable);
            } else if (status == NativeRdb::E_OK) {
                if (!value.empty()) {
                    info.SetEnabledAllNotification(userId, static_cast<bool>(StringToInt(value)));
                }
            } else {
                ANS_LOGW("Parse enable all notification failed, use default value.");
            }
        });
}

void NotificationPreferencesDatabase::GetDoNotDisturbProfile(NotificationPreferencesInfo &info, int32_t userId)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return;
    }
    std::unordered_map<std::string, std::string> datas;
    int32_t result = rdbDataManager_->QueryAllData(datas, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Query all data failed.");
        return;
    }
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    for (const auto &data : datas) {
        std::string key = data.first;
        auto result = key.find(KEY_DO_NOT_DISTURB_ID);
        if (result != std::string::npos) {
            sptr<NotificationDoNotDisturbProfile> profile;
            GetDoNotDisturbProfiles(data.first, profile, userId);
            profiles.emplace_back(profile);
        }
    }
    info.AddDoNotDisturbProfiles(userId, profiles);
}

bool NotificationPreferencesDatabase::RemoveNotificationEnable(const int32_t userId)
{
    ANS_LOGD("called");
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }

    std::string key =
        std::string(KEY_ENABLE_ALL_NOTIFICATION).append(KEY_UNDER_LINE).append(std::to_string(userId));
    int32_t result = rdbDataManager_->DeleteData(key, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("delete bundle Info failed.");
        return false;
    }

    ANS_LOGD("%{public}s remove notification enable, userId : %{public}d", __FUNCTION__, userId);
    return true;
}

bool NotificationPreferencesDatabase::RemoveDoNotDisturbDate(const int32_t userId)
{
    ANS_LOGD("called");
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }

    std::string typeKey =
        std::string(KEY_DO_NOT_DISTURB_TYPE).append(KEY_UNDER_LINE).append(std::to_string(userId));
    std::string beginDateKey =
        std::string(KEY_DO_NOT_DISTURB_BEGIN_DATE).append(KEY_UNDER_LINE).append(std::to_string(userId));
    std::string endDateKey =
        std::string(KEY_DO_NOT_DISTURB_END_DATE).append(KEY_UNDER_LINE).append(std::to_string(userId));

    std::vector<std::string> keys = {
        typeKey,
        beginDateKey,
        endDateKey
    };

    int32_t result = rdbDataManager_->DeleteBatchData(keys, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("delete DoNotDisturb date failed.");
        return false;
    }

    ANS_LOGD("%{public}s remove DoNotDisturb date, userId : %{public}d", __FUNCTION__, userId);
    return true;
}

bool NotificationPreferencesDatabase::RemoveAnsBundleDbInfo(std::string bundleName, int32_t uid)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }

    std::string key = KEY_BUNDLE_LABEL + bundleName + std::to_string(uid);
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(uid, userId);
    int32_t result = rdbDataManager_->DeleteData(key, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Delete ans bundle db info failed, bundle[%{public}s:%{public}d]", bundleName.c_str(), uid);
        return false;
    }

    ANS_LOGE("Remove ans bundle db info, bundle[%{public}s:%{public}d]", bundleName.c_str(), uid);
    return true;
}

bool NotificationPreferencesDatabase::RemoveEnabledDbByBundleName(std::string bundleName, const int32_t &bundleUid)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleUid, userId);
    std::string key = std::string(KEY_ENABLE_BUNDLE_DISTRIBUTED_NOTIFICATION).append(
        KEY_MIDDLE_LINE).append(std::string(bundleName).append(KEY_MIDDLE_LINE));
    ANS_LOGD("key is %{public}s", key.c_str());
    int32_t result = NativeRdb::E_OK;
    std::unordered_map<std::string, std::string> values;
    result = rdbDataManager_->QueryDataBeginWithKey(key, values, userId);
    if (result == NativeRdb::E_EMPTY_VALUES_BUCKET) {
        return true;
    } else if (result != NativeRdb::E_OK) {
        ANS_LOGE("Get failed, key %{public}s,result %{public}d.", key.c_str(), result);
        return NativeRdb::E_ERROR;
    }

    std::vector<std::string> keys;
    for (auto iter : values) {
        ANS_LOGD("Get failed, key %{public}s", iter.first.c_str());
        keys.push_back(iter.first);
    }

    result = rdbDataManager_->DeleteBatchData(keys, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("delete bundle Info failed.");
        return false;
    }

    return true;
}

int32_t NotificationPreferencesDatabase::SetKvToDb(
    const std::string &key, const std::string &value, const int32_t &userId)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_7, EventBranchId::BRANCH_2);
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        message.Message("RdbStore is nullptr.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return NativeRdb::E_ERROR;
    }
    int32_t result = rdbDataManager_->InsertData(key, value, userId);
    if (result != NativeRdb::E_OK) {
        message.Message("Set key failed: " + key);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("Set key: %{public}s failed, result %{public}d.", key.c_str(), result);
        return NativeRdb::E_ERROR;
    }

    ANS_LOGD("Key:%{public}s, value:%{public}s.", key.c_str(), value.c_str());

    return NativeRdb::E_OK;
}

int32_t NotificationPreferencesDatabase::SetByteToDb(
    const std::string &key, const std::vector<uint8_t> &value, const int32_t &userId)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_7, EventBranchId::BRANCH_2);
    if (!CheckRdbStore()) {
        message.Message("RdbStore is nullptr.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("null RdbStore");
        return NativeRdb::E_ERROR;
    }
    int32_t result = rdbDataManager_->InsertData(key, value, userId);
    if (result != NativeRdb::E_OK) {
        message.Message("Set key failed: " + key);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("Set key: %{public}s failed, result %{public}d.", key.c_str(), result);
        return NativeRdb::E_ERROR;
    }

    return NativeRdb::E_OK;
}

int32_t NotificationPreferencesDatabase::GetKvFromDb(
    const std::string &key, std::string &value, const int32_t &userId)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return NativeRdb::E_ERROR;
    }

    int32_t result = rdbDataManager_->QueryData(key, value, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Get key-value failed, key %{public}s, result %{public}d.", key.c_str(), result);
        return NativeRdb::E_ERROR;
    }

    ANS_LOGD("Key:%{public}s, value:%{public}s.", key.c_str(), value.c_str());

    return NativeRdb::E_OK;
}

#ifdef ENABLE_ANS_PRIVILEGED_MESSAGE_EXT_WRAPPER
int32_t NotificationPreferencesDatabase::GetKvFromDb(
    const std::string &key, std::string &value, const int32_t &userId, int32_t &retCode)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return NativeRdb::E_ERROR;
    }

    retCode = rdbDataManager_->QueryData(key, value, userId);
    return retCode;
}
#endif

int32_t NotificationPreferencesDatabase::GetByteFromDb(
    const std::string &key, std::vector<uint8_t> &value, const int32_t &userId)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return NativeRdb::E_ERROR;
    }

    int32_t result = rdbDataManager_->QueryData(key, value, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Get byte failed, key %{public}s, result %{public}d.", key.c_str(), result);
        return NativeRdb::E_ERROR;
    }

    return NativeRdb::E_OK;
}

int32_t NotificationPreferencesDatabase::GetBatchKvsFromDb(
    const std::string &key, std::unordered_map<std::string, std::string>  &values, const int32_t &userId)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return NativeRdb::E_ERROR;
    }

    int32_t result = rdbDataManager_->QueryDataBeginWithKey(key, values, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Get batch notification request failed, key %{public}s, result %{public}d.", key.c_str(), result);
        return NativeRdb::E_ERROR;
    }
    ANS_LOGD("Key:%{public}s.", key.c_str());
    return NativeRdb::E_OK;
}

int32_t NotificationPreferencesDatabase::GetBatchKvsFromDbContainsKey(
    const std::string &key, std::unordered_map<std::string, std::string>  &values, const int32_t &userId)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return NativeRdb::E_ERROR;
    }

    int32_t result = rdbDataManager_->QueryDataContainsWithKey(key, values, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("QueryDataContainsWithKey failed, key %{public}s, result %{public}d.", key.c_str(), result);
        return NativeRdb::E_ERROR;
    }
    ANS_LOGD("Key:%{public}s.", key.c_str());
    return NativeRdb::E_OK;
}

int32_t NotificationPreferencesDatabase::DeleteKvFromDb(const std::string &key, const int32_t &userId)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return NativeRdb::E_ERROR;
    }

    int32_t result = rdbDataManager_->DeleteData(key, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Delete key-value failed, key %{public}s, result %{public}d.", key.c_str(), result);
        return NativeRdb::E_ERROR;
    }

    ANS_LOGD("Delete key:%{public}s.", key.c_str());

    return NativeRdb::E_OK;
}

int32_t NotificationPreferencesDatabase::DeleteBatchKvFromDb(const std::vector<std::string> &keys,
    const int32_t &userId)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return NativeRdb::E_ERROR;
    }

    int32_t result = rdbDataManager_->DeleteBatchData(keys, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Delete key-value failed, result %{public}d.", result);
        return NativeRdb::E_ERROR;
    }

    return NativeRdb::E_OK;
}

int32_t NotificationPreferencesDatabase::DropUserTable(const int32_t userId)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return NativeRdb::E_ERROR;
    }

    int32_t result = rdbDataManager_->DropUserTable(userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Delete table failed, result %{public}d.", result);
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}

bool NotificationPreferencesDatabase::IsAgentRelationship(const std::string &agentBundleName,
    const std::string &sourceBundleName)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }
    std::string agentShip = "";
    int32_t result = rdbDataManager_->QueryData("PROXY_PKG", agentShip);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Query agent relationships failed.");
        return false;
    }
    ANS_LOGD("The agent relationship is :%{public}s.", agentShip.c_str());
    nlohmann::json jsonAgentShip = nlohmann::json::parse(agentShip, nullptr, false);
    if (jsonAgentShip.is_null() || jsonAgentShip.empty()) {
        ANS_LOGE("Invalid JSON object");
        return false;
    }
    if (jsonAgentShip.is_discarded() || !jsonAgentShip.is_array()) {
        ANS_LOGE("Parse agent ship failed due to data is discarded or not array");
        return false;
    }

    nlohmann::json jsonTarget;
    jsonTarget[RELATIONSHIP_JSON_KEY_SERVICE] = agentBundleName;
    jsonTarget[RELATIONSHIP_JSON_KEY_APP] = sourceBundleName;
    bool isAgentRelationship = false;
    for (const auto &item : jsonAgentShip) {
        if (jsonTarget == item) {
            isAgentRelationship = true;
            break;
        }
    }

    return isAgentRelationship;
}

bool NotificationPreferencesDatabase::PutDistributedEnabledForBundle(const std::string deviceType,
    const NotificationPreferencesInfo::BundleInfo &bundleInfo, const bool &enabled)
{
    ANS_LOGD("%{public}s, deviceType:%{public}s,enabled[%{public}d]", __FUNCTION__, deviceType.c_str(), enabled);
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleInfo.GetBundleUid(), userId);

    std::string key = GenerateBundleLablel(bundleInfo, deviceType);
    int32_t result = PutDataToDB(key, enabled, userId);
    ANS_LOGD("result[%{public}d]", result);
    return (result == NativeRdb::E_OK);
}

std::string NotificationPreferencesDatabase::GenerateBundleLablel(
    const NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &deviceType) const
{
    return std::string(KEY_ENABLE_BUNDLE_DISTRIBUTED_NOTIFICATION).append(KEY_MIDDLE_LINE).append(
        std::string(bundleInfo.GetBundleName()).append(KEY_MIDDLE_LINE).append(std::to_string(
            bundleInfo.GetBundleUid())).append(KEY_MIDDLE_LINE).append(deviceType));
}

std::string NotificationPreferencesDatabase::GenerateBundleLablel(
    const std::string &deviceType,
    const std::string &deviceId,
    const int32_t userId) const
{
    return std::string(KEY_ENABLE_DISTRIBUTED_AUTH_STATUS).append(KEY_MIDDLE_LINE)
        .append(deviceType).append(KEY_MIDDLE_LINE)
        .append(deviceId).append(KEY_MIDDLE_LINE)
        .append(std::to_string(userId));
}

template <typename T>
int32_t NotificationPreferencesDatabase::PutDataToDB(const std::string &key, const T &value, const int32_t &userId)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }
    std::string valueStr = std::to_string(value);
    int32_t result = rdbDataManager_->InsertData(key, valueStr, userId);
    return result;
}

bool NotificationPreferencesDatabase::PutDistributedEnabled(
    const std::string &deviceType, const NotificationConstant::ENABLE_STATUS &enabled)
{
    ANS_LOGD("%{public}s, deviceType: %{public}s, enabled: %{public}d",
        __FUNCTION__, deviceType.c_str(), static_cast<int32_t>(enabled));
    int32_t userId = SUBSCRIBE_USER_INIT;
    OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (userId == SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Current user acquisition failed");
        return false;
    }
    std::string key = std::string(KEY_DISTRIBUTED_NOTIFICATION_SWITCH).append(KEY_MIDDLE_LINE).append(
        deviceType).append(KEY_MIDDLE_LINE).append(std::to_string(userId));
    int32_t result = PutDataToDB(key, static_cast<int32_t>(enabled), userId);
    ANS_LOGD("key: %{public}s, result: %{public}d", key.c_str(), result);
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::GetDistributedEnabled(
    const std::string &deviceType, NotificationConstant::ENABLE_STATUS &enabled)
{
    ANS_LOGD("%{public}s, deviceType: %{public}s", __FUNCTION__, deviceType.c_str());
    int32_t userId = SUBSCRIBE_USER_INIT;
    OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (userId == SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Current user acquisition failed");
        return false;
    }
    std::string key = std::string(KEY_DISTRIBUTED_NOTIFICATION_SWITCH).append(KEY_MIDDLE_LINE).append(
        deviceType).append(KEY_MIDDLE_LINE).append(std::to_string(userId));
    bool result = false;
    enabled = NotificationConstant::ENABLE_STATUS::ENABLE_NONE;
    GetValueFromDisturbeDB(key, userId, [&](const int32_t &status, std::string &value) {
        switch (status) {
            case NativeRdb::E_EMPTY_VALUES_BUCKET: {
                result = true;
                break;
            }
            case NativeRdb::E_OK: {
                result = true;
                enabled = static_cast<NotificationConstant::ENABLE_STATUS>(StringToInt(value));
                break;
            }
            default:
                result = false;
                break;
        }
    });
    return result;
}

ErrCode NotificationPreferencesDatabase::GetDistributedAuthStatus(
    const std::string &deviceType, const std::string &deviceId, int32_t userId, bool &isAuth)
{
    ANS_LOGD("%{public}s, deviceType: %{public}s, deviceId: %{public}s, userId: %{public}d",
        __FUNCTION__, deviceType.c_str(), deviceId.c_str(), userId);
    std::string key = GenerateBundleLablel(deviceType, deviceId, userId);
    bool result = false;
    isAuth = false;
    GetValueFromDisturbeDB(key, userId, [&](const int32_t &status, std::string &value) {
        switch (status) {
            case NativeRdb::E_EMPTY_VALUES_BUCKET: {
                result = true;
                break;
            }
            case NativeRdb::E_OK: {
                result = true;
                isAuth = StringToInt(value) != 0;
                break;
            }
            default:
                result = false;
                break;
        }
    });
    return result;
}

ErrCode NotificationPreferencesDatabase::SetDistributedAuthStatus(
    const std::string &deviceType, const std::string &deviceId, int32_t userId, bool isAuth)
{
    ANS_LOGD("%{public}s, deviceType: %{public}s, deviceId: %{public}s, userId: %{public}d",
        __FUNCTION__, deviceType.c_str(), deviceId.c_str(), userId);
    std::string key = GenerateBundleLablel(deviceType, deviceId, userId);
    int32_t result = PutDataToDB(key, static_cast<int32_t>(isAuth), userId);
    ANS_LOGD("key: %{public}s, result: %{public}d", key.c_str(), result);
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::GetDistributedEnabledForBundle(const std::string deviceType,
    const NotificationPreferencesInfo::BundleInfo &bundleInfo, bool &enabled)
{
    ANS_LOGD("%{public}s, deviceType:%{public}s,enabled[%{public}d]", __FUNCTION__, deviceType.c_str(), enabled);
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }

    std::string key = GenerateBundleLablel(bundleInfo, deviceType);
    bool result = false;
    enabled = false;
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleInfo.GetBundleUid(), userId);
    GetValueFromDisturbeDB(key, userId, [&](const int32_t &status, std::string &value) {
        switch (status) {
            case NativeRdb::E_EMPTY_VALUES_BUCKET: {
                result = true;
                enabled = false;
                break;
            }
            case NativeRdb::E_OK: {
                result = true;
                enabled = static_cast<bool>(StringToInt(value));
                break;
            }
            default:
                result = false;
                break;
        }
    });
    ANS_LOGD("enabled:[%{public}d]KEY:%{public}s", enabled, key.c_str());
    return result;
}

std::string NotificationPreferencesDatabase::GenerateBundleLablel(const std::string &deviceType,
    const int32_t userId) const
{
    return std::string(KEY_SMART_REMINDER_ENABLE_NOTIFICATION).append(KEY_MIDDLE_LINE).append(
        deviceType).append(KEY_MIDDLE_LINE).append(std::to_string(userId));
}

std::string NotificationPreferencesDatabase::GenerateBundleLablel(
    const NotificationConstant::SlotType &slotType,
    const std::string &deviceType,
    const int32_t userId) const
{
    return std::string(KEY_ENABLE_SLOT_DISTRIBUTED_NOTIFICATION).append(KEY_MIDDLE_LINE)
        .append(deviceType).append(KEY_MIDDLE_LINE)
        .append(std::to_string(static_cast<int32_t>(slotType))).append(KEY_MIDDLE_LINE)
        .append(std::to_string(userId));
}

bool NotificationPreferencesDatabase::SetSmartReminderEnabled(const std::string deviceType, const bool &enabled)
{
    ANS_LOGD("%{public}s, deviceType:%{public}s,enabled[%{public}d]", __FUNCTION__, deviceType.c_str(), enabled);
    int32_t userId = SUBSCRIBE_USER_INIT;
    OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (userId == SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Current user acquisition failed");
        return false;
    }

    std::string key = GenerateBundleLablel(deviceType, userId);
    ANS_LOGD("%{public}s, key:%{public}s,enabled[%{public}d]", __FUNCTION__, key.c_str(), enabled);
    int32_t result = PutDataToDB(key, enabled, userId);
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::IsSmartReminderEnabled(const std::string deviceType, bool &enabled)
{
    ANS_LOGD("%{public}s, deviceType:%{public}s,enabled[%{public}d]", __FUNCTION__, deviceType.c_str(), enabled);
    int32_t userId = SUBSCRIBE_USER_INIT;
    OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (userId == SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Current user acquisition failed");
        return false;
    }

    std::string key = GenerateBundleLablel(deviceType, userId);
    bool result = false;
    enabled = false;
    GetValueFromDisturbeDB(key, userId, [&](const int32_t &status, std::string &value) {
        switch (status) {
            case NativeRdb::E_EMPTY_VALUES_BUCKET: {
                result = true;
                GetSmartReminderEnableFromCCM(deviceType, enabled);
                break;
            }
            case NativeRdb::E_OK: {
                result = true;
                enabled = static_cast<bool>(StringToInt(value));
                break;
            }
            default:
                result = false;
                break;
        }
    });
    return result;
}

bool NotificationPreferencesDatabase::SetDistributedEnabledBySlot(
    const NotificationConstant::SlotType &slotType, const std::string &deviceType, const bool enabled)
{
    ANS_LOGD("%{public}s, %{public}d,deviceType:%{public}s,enabled[%{public}d]",
        __FUNCTION__, slotType, deviceType.c_str(), enabled);
    int32_t userId = SUBSCRIBE_USER_INIT;
    OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (userId == SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Current user acquisition failed");
        return false;
    }

    std::string key = GenerateBundleLablel(slotType, deviceType, userId);
    ANS_LOGD("%{public}s, key:%{public}s,enabled[%{public}d]", __FUNCTION__, key.c_str(), enabled);
    int32_t result = PutDataToDB(key, enabled, userId);
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::IsDistributedEnabledBySlot(
    const NotificationConstant::SlotType &slotType, const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("%{public}s, %{public}d,deviceType:%{public}s]",
        __FUNCTION__, slotType, deviceType.c_str());
    int32_t userId = SUBSCRIBE_USER_INIT;
    OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (userId == SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Current user acquisition failed");
        return false;
    }

    std::string key = GenerateBundleLablel(slotType, deviceType, userId);
    bool result = false;
    enabled = false;
    GetValueFromDisturbeDB(key, userId, [&](const int32_t &status, std::string &value) {
        switch (status) {
            case NativeRdb::E_EMPTY_VALUES_BUCKET: {
                result = true;
                enabled = true;
                break;
            }
            case NativeRdb::E_OK: {
                result = true;
                enabled = static_cast<bool>(StringToInt(value));
                break;
            }
            default:
                result = false;
                break;
        }
    });
    return result;
}

std::string NotificationPreferencesDatabase::GetAdditionalConfig(const std::string &key)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return "";
    }
    std::string configValue = "";
    int32_t result = rdbDataManager_->QueryData(key, configValue);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Query additional config failed.");
        return "";
    }
    ANS_LOGD("The additional config key is :%{public}s, value is :%{public}s.", key.c_str(), configValue.c_str());
    return configValue;
}

bool NotificationPreferencesDatabase::CheckApiCompatibility(const std::string &bundleName, const int32_t &uid)
{
    ANS_LOGD("called");
    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager == nullptr) {
        return false;
    }
    return bundleManager->CheckApiCompatibility(bundleName, uid);
}

bool NotificationPreferencesDatabase::UpdateBundlePropertyToDisturbeDB(int32_t userId,
    const NotificationPreferencesInfo::BundleInfo &bundleInfo)
{
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }

    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }
    std::string value;
    std::string bundleLabelKey = KEY_BUNDLE_LABEL + GenerateBundleLablel(bundleInfo);
    int32_t result = rdbDataManager_->QueryData(bundleLabelKey, value, userId);
    if (result == NativeRdb::E_EMPTY_VALUES_BUCKET) {
        if (rdbDataManager_->InsertData(bundleLabelKey, GenerateBundleLablel(bundleInfo), userId)
            != NativeRdb::E_OK) {
            ANS_LOGE("Store bundle name %{public}s to db is failed.", bundleLabelKey.c_str());
            return false;
        }
    }
    if (result == NativeRdb::E_EMPTY_VALUES_BUCKET || result == NativeRdb::E_OK) {
        return PutBundlePropertyValueToDisturbeDB(bundleInfo);
    }
    ANS_LOGW("Query bundle name %{public}s failed %{public}d.", bundleLabelKey.c_str(), result);
    return false;
}

bool NotificationPreferencesDatabase::UpdateBundleSlotToDisturbeDB(int32_t userId, const std::string &bundleName,
    const int32_t &bundleUid, const std::vector<sptr<NotificationSlot>> &slots)
{
    if (bundleName.empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }
    if (slots.empty()) {
        ANS_LOGI("Slot is empty.");
        return true;
    }

    std::string bundleKey = bundleName + std::to_string(bundleUid);
    std::unordered_map<std::string, std::string> values;
    for (auto& slot : slots) {
        GenerateSlotEntry(bundleKey, slot, values);
    }
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }
    int32_t result = rdbDataManager_->InsertBatchData(values, userId);
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::DelCloneProfileInfo(const int32_t &userId,
    const sptr<NotificationDoNotDisturbProfile>& info)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }

    std::string key = KEY_CLONE_LABEL + CLONE_PROFILE + std::to_string(info->GetProfileId());
    int32_t result = rdbDataManager_->DeleteData(key, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("delete clone profile Info failed.");
        return false;
    }
    return true;
}

bool NotificationPreferencesDatabase::DelBatchCloneProfileInfo(const int32_t &userId,
    const std::vector<sptr<NotificationDoNotDisturbProfile>>& profileInfo)
{
    std::string cloneProfile = KEY_CLONE_LABEL + CLONE_PROFILE;
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }

    std::vector<std::string> keys;
    for (auto info : profileInfo) {
        std::string key = cloneProfile + std::to_string(info->GetProfileId());
        keys.emplace_back(key);
    }

    int32_t result = rdbDataManager_->DeleteBatchData(keys, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("delete clone bundle Info failed.");
        return false;
    }
    return true;
}

bool NotificationPreferencesDatabase::UpdateBatchCloneProfileInfo(const int32_t &userId,
    const std::vector<sptr<NotificationDoNotDisturbProfile>>& profileInfo)
{
    std::string cloneProfile = KEY_CLONE_LABEL + CLONE_PROFILE;
    std::unordered_map<std::string, std::string> values;
    for (auto& info : profileInfo) {
        std::string key = cloneProfile + std::to_string(info->GetProfileId());
        std::string jsonString = info->ToJson();
        values.emplace(key, jsonString);
    }
    return UpdateCloneToDisturbeDB(userId, values);
}

void NotificationPreferencesDatabase::GetAllCloneProfileInfo(const int32_t &userId,
    std::vector<sptr<NotificationDoNotDisturbProfile>>& profilesInfo)
{
    std::string cloneProfile = KEY_CLONE_LABEL + CLONE_PROFILE;
    std::unordered_map<std::string, std::string> values;
    if (GetBatchKvsFromDb(cloneProfile, values, userId) != ERR_OK) {
        ANS_LOGW("Get clone bundle map info failed %{public}d.", userId);
        return;
    }

    for (auto item : values) {
        sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow) NotificationDoNotDisturbProfile();
        if (profile == nullptr) {
            ANS_LOGW("Get clone profile failed.");
            continue;
        }
        profile->FromJson(item.second);
        profilesInfo.push_back(profile);
    }
}

void NotificationPreferencesDatabase::GetAllCloneBundleInfo(const int32_t &userId,
    std::vector<NotificationCloneBundleInfo>& cloneBundleInfo)
{
    std::unordered_map<std::string, std::string> values;
    if (GetBatchKvsFromDb(KEY_CLONE_LABEL + CLONE_BUNDLE, values, userId) != ERR_OK) {
        ANS_LOGW("Get clone bundle map info failed %{public}d.", userId);
        return;
    }

    for (auto item : values) {
        NotificationCloneBundleInfo bundleInfo;
        if (item.second.empty() || !nlohmann::json::accept(item.second)) {
            ANS_LOGE("Invalid accept json");
            continue;
        }
        nlohmann::json jsonObject = nlohmann::json::parse(item.second, nullptr, false);
        if (jsonObject.is_null() || !jsonObject.is_object()) {
            ANS_LOGE("Invalid JSON object");
            continue;
        }
        bundleInfo.FromJson(jsonObject);
        cloneBundleInfo.emplace_back(bundleInfo);
    }
}

bool NotificationPreferencesDatabase::DelBatchCloneBundleInfo(const int32_t &userId,
    const std::vector<NotificationCloneBundleInfo>& cloneBundleInfo)
{
    std::string cloneBundle = KEY_CLONE_LABEL + CLONE_BUNDLE;
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }

    std::vector<std::string> keys;
    for (auto bundleInfo : cloneBundleInfo) {
        std::string key = cloneBundle + bundleInfo.GetBundleName() +
            std::to_string(bundleInfo.GetAppIndex());
        keys.emplace_back(key);
    }
    int32_t result = rdbDataManager_->DeleteBatchData(keys, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("delete clone bundle Info failed.");
        return false;
    }
    return true;
}

bool NotificationPreferencesDatabase::UpdateBatchCloneBundleInfo(const int32_t &userId,
    const std::vector<NotificationCloneBundleInfo>& cloneBundleInfo)
{
    std::string cloneBundle = KEY_CLONE_LABEL + CLONE_BUNDLE;
    std::unordered_map<std::string, std::string> values;
    for (auto& info : cloneBundleInfo) {
        nlohmann::json jsonNode;
        std::string key = cloneBundle + info.GetBundleName() + std::to_string(info.GetAppIndex());
        info.ToJson(jsonNode);
        values.emplace(key, jsonNode.dump());
    }
    return UpdateCloneToDisturbeDB(userId, values);
}

bool NotificationPreferencesDatabase::DelCloneBundleInfo(const int32_t &userId,
    const NotificationCloneBundleInfo& cloneBundleInfo)
{
    std::string cloneBundle = KEY_CLONE_LABEL + CLONE_BUNDLE;
    std::string key = cloneBundle + cloneBundleInfo.GetBundleName() +
        std::to_string(cloneBundleInfo.GetAppIndex());
    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }

    int32_t result = rdbDataManager_->DeleteData(key, userId);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("delete clone bundle Info failed.");
        return false;
    }
    return true;
}

bool NotificationPreferencesDatabase::UpdateCloneToDisturbeDB(const int32_t &userId,
    const std::unordered_map<std::string, std::string> values)
{
    if (values.empty() || !CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }

    int32_t result = rdbDataManager_->InsertBatchData(values, userId);
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::SetDisableNotificationInfo(const sptr<NotificationDisable> &notificationDisable)
{
    if (notificationDisable == nullptr || !CheckRdbStore()) {
        ANS_LOGE("null notificationDisable or rdbStore");
        return false;
    }
    if (notificationDisable->GetBundleList().empty()) {
        ANS_LOGE("the bundle list is empty");
        return false;
    }
    std::string value = notificationDisable->ToJson();
    int32_t result = rdbDataManager_->InsertData(KEY_DISABLE_NOTIFICATION, value, ZERO_USER_ID);
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::GetDisableNotificationInfo(NotificationDisable &notificationDisable)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null rdbStore");
        return false;
    }
    std::string value;
    int32_t result = rdbDataManager_->QueryData(KEY_DISABLE_NOTIFICATION, value, ZERO_USER_ID);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("query data failed");
        return false;
    }
    notificationDisable.FromJson(value);
    return true;
}

void NotificationPreferencesDatabase::GetDisableNotificationInfo(NotificationPreferencesInfo &info)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("null rdbStore");
        return;
    }
    std::string value;
    int32_t result = rdbDataManager_->QueryData(KEY_DISABLE_NOTIFICATION, value, ZERO_USER_ID);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("query data failed");
        return;
    }
    info.AddDisableNotificationInfo(value);
}

bool NotificationPreferencesDatabase::IsDistributedEnabledEmptyForBundle(
    const std::string& deviceType, const NotificationPreferencesInfo::BundleInfo& bundleInfo)
{
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("bundle name is empty.");
        return true;
    }

    std::string key = GenerateBundleLablel(bundleInfo, deviceType);
    bool result = true;
    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleInfo.GetBundleUid(), userId);
    GetValueFromDisturbeDB(key, userId, [&](const int32_t& status, std::string& value) {
        if (status == NativeRdb::E_EMPTY_VALUES_BUCKET) {
            result = false;
        }
    });
    return result;
}

void NotificationPreferencesDatabase::GetSmartReminderEnableFromCCM(const std::string& deviceType, bool& enabled)
{
    ANS_LOGD("called");
    if (!isCachedSmartReminderEnableList_) {
        if (!DelayedSingleton<NotificationConfigParse>::GetInstance()->GetSmartReminderEnableList(
            smartReminderEnableList_)) {
            ANS_LOGE("GetSmartReminderEnableList failed from json");
            enabled = false;
            return;
        }
        isCachedSmartReminderEnableList_ = true;
    }

    if (smartReminderEnableList_.empty()) {
        ANS_LOGD("smartReminderEnableList_ is empty");
        enabled = false;
        return;
    }

    if (std::find(smartReminderEnableList_.begin(), smartReminderEnableList_.end(), deviceType) !=
        smartReminderEnableList_.end()) {
        enabled = true;
    } else {
        enabled = false;
    }
    ANS_LOGD("get %{public}s smartReminderEnable is %{public}d from json", deviceType.c_str(), enabled);
}

std::string NotificationPreferencesDatabase::GenerateSubscriberExistFlagKey(
    const std::string& deviceType, const int32_t userId) const
{
    return std::string(KEY_SUBSCRIBER_EXISTED_FLAG)
        .append(KEY_MIDDLE_LINE)
        .append(deviceType)
        .append(KEY_MIDDLE_LINE)
        .append(std::to_string(userId));
}

bool NotificationPreferencesDatabase::SetSubscriberExistFlag(const std::string& deviceType, bool existFlag)
{
    ANS_LOGD("%{public}s, deviceType:%{public}s, existFlag[%{public}d]", __FUNCTION__, deviceType.c_str(), existFlag);
    int32_t userId = SUBSCRIBE_USER_INIT;
    OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    if (userId == SUBSCRIBE_USER_INIT) {
        ANS_LOGE("current user acquisition failed");
        return false;
    }

    std::string key = GenerateSubscriberExistFlagKey(deviceType, userId);
    int32_t result = PutDataToDB(key, existFlag, userId);
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::GetSubscriberExistFlag(const std::string& deviceType, bool& existFlag)
{
    ANS_LOGD("%{public}s, deviceType:%{public}s, existFlag[%{public}d]", __FUNCTION__, deviceType.c_str(), existFlag);
    int32_t userId = SUBSCRIBE_USER_INIT;
    OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    if (userId == SUBSCRIBE_USER_INIT) {
        ANS_LOGE("current user acquisition failed");
        return false;
    }

    std::string key = GenerateSubscriberExistFlagKey(deviceType, userId);
    bool result = false;
    existFlag = false;
    GetValueFromDisturbeDB(key, userId, [&](const int32_t& status, std::string& value) {
        switch (status) {
            case NativeRdb::E_EMPTY_VALUES_BUCKET: {
                result = true;
                break;
            }
            case NativeRdb::E_OK: {
                result = true;
                existFlag = static_cast<bool>(StringToInt(value));
                break;
            }
            default:
                result = false;
                break;
        }
    });
    return result;
}

bool NotificationPreferencesDatabase::SetHashCodeRule(const int32_t uid, const uint32_t type)
{
    ANS_LOGD("%{public}s, %{public}d,", __FUNCTION__, type);
    int32_t userId = SUBSCRIBE_USER_INIT;
    OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    ANS_LOGI("userId = %{public}d", userId);
    if (userId == SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Current user acquisition failed");
        return false;
    }

    std::string key = GenerateHashCodeGenerate(uid);
    ANS_LOGD("%{public}s, key:%{public}s,type = %{public}d", __FUNCTION__, key.c_str(), type);
    int32_t result = PutDataToDB(key, type, userId);
    return (result == NativeRdb::E_OK);
}

uint32_t NotificationPreferencesDatabase::GetHashCodeRule(const int32_t uid)
{
    ANS_LOGD("%{public}s, %{public}d,", __FUNCTION__, uid);
    int32_t userId = SUBSCRIBE_USER_INIT;
    OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (userId == SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Current user acquisition failed");
        return 0;
    }

    std::string key = GenerateHashCodeGenerate(uid);
    ANS_LOGD("%{public}s, key:%{public}s", __FUNCTION__, key.c_str());
    uint32_t result = 0;
    GetValueFromDisturbeDB(key, userId, [&](const int32_t &status, std::string &value) {
        switch (status) {
            case NativeRdb::E_EMPTY_VALUES_BUCKET: {
                break;
            }
            case NativeRdb::E_OK: {
                result = StringToInt(value);
                break;
            }
            default:
                break;
        }
    });
    return result;
}

static std::string GetBundleRemoveFlagKey(const sptr<NotificationBundleOption> &bundleOption,
    const NotificationConstant::SlotType &slotType, int32_t sourceType)
{
    std::string key;
    if (sourceType == CLEAR_SLOT_FROM_AVSEESAION) {
        key = KEY_REMOVE_SLOT_FLAG + bundleOption->GetBundleName() + std::to_string(bundleOption->GetUid()) +
            KEY_UNDER_LINE + std::to_string(slotType);
    } else {
        key = KEY_REMOVE_SLOT_FLAG + std::to_string(sourceType) + KEY_UNDER_LINE + bundleOption->GetBundleName() +
            std::to_string(bundleOption->GetUid()) + KEY_UNDER_LINE + std::to_string(slotType);
    }
    return key;
}

bool NotificationPreferencesDatabase::SetBundleRemoveFlag(const sptr<NotificationBundleOption> &bundleOption,
    const NotificationConstant::SlotType &slotType, int32_t sourceType)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("null bundleOption");
        return false;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (userId == SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Current user acquisition failed");
        return false;
    }

    if (!CheckRdbStore()) {
        ANS_LOGE("null RdbStore");
        return false;
    }
    std::string key = GetBundleRemoveFlagKey(bundleOption, slotType, sourceType);
    int32_t result = rdbDataManager_->InsertData(key, KEY_SECOND_REMOVED_FLAG, userId);
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::GetBundleRemoveFlag(const sptr<NotificationBundleOption> &bundleOption,
    const NotificationConstant::SlotType &slotType, int32_t sourceType)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("null bundleOption");
        return true;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (userId == SUBSCRIBE_USER_INIT) {
        ANS_LOGW("Current user acquisition failed");
        return true;
    }

    std::string key = GetBundleRemoveFlagKey(bundleOption, slotType, sourceType);
    bool existFlag = true;
    std::string result;
    GetValueFromDisturbeDB(key, userId, [&](const int32_t& status, std::string& value) {
        switch (status) {
            case NativeRdb::E_EMPTY_VALUES_BUCKET: {
                existFlag = false;
                break;
            }
            case NativeRdb::E_OK: {
                result = value;
                break;
            }
            default:
                break;
        }
    });

    ANS_LOGI("Get current remove flag %{public}s,%{public}s,%{public}d", key.c_str(), result.c_str(), existFlag);
    if (!existFlag || result == KEY_REMOVED_FLAG) {
        return false;
    }
    return true;
}

std::string NotificationPreferencesDatabase::GenerateHashCodeGenerate(const int32_t uid)
{
    return std::string(KEY_HASH_CODE_RULE).append(KEY_MIDDLE_LINE).append(std::to_string(uid));
}
}  // namespace Notification
}  // namespace OHOS
