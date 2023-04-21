/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "ans_const_define.h"
#include "ans_log_wrapper.h"
#include "hitrace_meter.h"
#include "os_account_manager.h"

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
const static std::string KEY_BUNDLE_SHOW_BADGE = "showBadge";

/**
 * Indicates that disturbe key which bundle total badge num.
 */
const static std::string KEY_BUNDLE_BADGE_TOTAL_NUM = "badgeTotalNum";

/**
 * Indicates that disturbe key which bundle private allowed.
 */
const static std::string KEY_BUNDLE_PRIVATE_ALLOWED = "privateAllowed";

/**
 * Indicates that disturbe key which bundle enable notification.
 */
const static std::string KEY_BUNDLE_ENABLE_NOTIFICATION = "enabledNotification";

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


const std::map<std::string,
    std::function<void(NotificationPreferencesDatabase *, sptr<NotificationSlot> &, std::string &)>>
    NotificationPreferencesDatabase::slotMap_ = {
        {
            KEY_SLOT_DESCRIPTION,
            std::bind(&NotificationPreferencesDatabase::ParseSlotDescription, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3),
        },
        {
            KEY_SLOT_LEVEL,
            std::bind(&NotificationPreferencesDatabase::ParseSlotLevel, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3),
        },
        {
            KEY_SLOT_SHOW_BADGE,
            std::bind(&NotificationPreferencesDatabase::ParseSlotShowBadge, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3),
        },
        {
            KEY_SLOT_ENABLE_LIGHT,
            std::bind(&NotificationPreferencesDatabase::ParseSlotEnableLight, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3),
        },
        {
            KEY_SLOT_ENABLE_VRBRATION,
            std::bind(&NotificationPreferencesDatabase::ParseSlotEnableVrbration, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3),
        },
        {
            KEY_SLOT_LED_LIGHT_COLOR,
            std::bind(&NotificationPreferencesDatabase::ParseSlotLedLightColor, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3),
        },
        {
            KEY_SLOT_LOCKSCREEN_VISIBLENESS,
            std::bind(&NotificationPreferencesDatabase::ParseSlotLockscreenVisibleness, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3),
        },
        {
            KEY_SLOT_SOUND,
            std::bind(&NotificationPreferencesDatabase::ParseSlotSound, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3),
        },
        {
            KEY_SLOT_VIBRATION_STYLE,
            std::bind(&NotificationPreferencesDatabase::ParseSlotVibrationSytle, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3),
        },
        {
            KEY_SLOT_ENABLE_BYPASS_DND,
            std::bind(&NotificationPreferencesDatabase::ParseSlotEnableBypassDnd, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3),
        },
        {
            KEY_SLOT_ENABLED,
            std::bind(&NotificationPreferencesDatabase::ParseSlotEnabled, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3),
        },
};

const std::map<std::string,
    std::function<void(NotificationPreferencesDatabase *, NotificationPreferencesInfo::BundleInfo &, std::string &)>>
    NotificationPreferencesDatabase::bundleMap_ = {
        {
            KEY_BUNDLE_NAME,
            std::bind(&NotificationPreferencesDatabase::ParseBundleName, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3),
        },
        {
            KEY_BUNDLE_IMPORTANCE,
            std::bind(&NotificationPreferencesDatabase::ParseBundleImportance, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3),
        },
        {
            KEY_BUNDLE_SHOW_BADGE,
            std::bind(&NotificationPreferencesDatabase::ParseBundleShowBadge, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3),
        },
        {
            KEY_BUNDLE_BADGE_TOTAL_NUM,
            std::bind(&NotificationPreferencesDatabase::ParseBundleBadgeNum, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3),
        },
        {
            KEY_BUNDLE_PRIVATE_ALLOWED,
            std::bind(&NotificationPreferencesDatabase::ParseBundlePrivateAllowed, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3),
        },
        {
            KEY_BUNDLE_ENABLE_NOTIFICATION,
            std::bind(&NotificationPreferencesDatabase::ParseBundleEnableNotification, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3),
        },
        {
            KEY_BUNDLE_POPPED_DIALOG,
            std::bind(&NotificationPreferencesDatabase::ParseBundlePoppedDialog, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3),
        },
        {
            KEY_BUNDLE_UID,
            std::bind(&NotificationPreferencesDatabase::ParseBundleUid, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3),
        },
};

NotificationPreferencesDatabase::NotificationPreferencesDatabase()
{
    NotificationRdbConfig notificationRdbConfig;
    rdbDataManager_ = std::make_shared<NotificationDataMgr>(notificationRdbConfig);
    ANS_LOGD("Notification Rdb is created");
}

NotificationPreferencesDatabase::~NotificationPreferencesDatabase()
{
    ANS_LOGD("Notification Rdb is deleted");
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
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);
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

    if (!CheckRdbStore()) {
        ANS_LOGE("RdbStore is nullptr.");
        return false;
    }
    int32_t result = rdbDataManager_->InsertBatchData(values);
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::PutBundlePropertyToDisturbeDB(
    const NotificationPreferencesInfo::BundleInfo &bundleInfo)
{
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }

    if (!CheckRdbStore()) {
        ANS_LOGE("RdbStore is nullptr.");
        return false;
    }
    std::string values;
    std::string bundleKeyStr = KEY_BUNDLE_LABEL + GenerateBundleLablel(bundleInfo);
    bool result = false;
    GetValueFromDisturbeDB(bundleKeyStr, [&](const int32_t &status, std::string &value) {
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

bool NotificationPreferencesDatabase::PutShowBadge(
    const NotificationPreferencesInfo::BundleInfo &bundleInfo, const bool &enable)
{
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }

    if (!CheckBundle(bundleInfo.GetBundleName(), bundleInfo.GetBundleUid())) {
        return false;
    }

    std::string bundleKey = GenerateBundleLablel(bundleInfo);
    int32_t result =
        PutBundlePropertyToDisturbeDB(bundleKey, BundleType::BUNDLE_SHOW_BADGE_TYPE, enable);
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::PutImportance(
    const NotificationPreferencesInfo::BundleInfo &bundleInfo, const int32_t &importance)
{
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }

    if (!CheckBundle(bundleInfo.GetBundleName(), bundleInfo.GetBundleUid())) {
        return false;
    }

    std::string bundleKey = GenerateBundleLablel(bundleInfo);
    int32_t result =
        PutBundlePropertyToDisturbeDB(bundleKey, BundleType::BUNDLE_IMPORTANCE_TYPE, importance);
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::PutTotalBadgeNums(
    const NotificationPreferencesInfo::BundleInfo &bundleInfo, const int32_t &totalBadgeNum)
{
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }

    if (!CheckBundle(bundleInfo.GetBundleName(), bundleInfo.GetBundleUid())) {
        return false;
    }
    std::string bundleKey = GenerateBundleLablel(bundleInfo);
    int32_t result =
        PutBundlePropertyToDisturbeDB(bundleKey, BundleType::BUNDLE_BADGE_TOTAL_NUM_TYPE, totalBadgeNum);
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::PutPrivateNotificationsAllowed(
    const NotificationPreferencesInfo::BundleInfo &bundleInfo, const bool &allow)
{
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }

    if (!CheckBundle(bundleInfo.GetBundleName(), bundleInfo.GetBundleUid())) {
        return false;
    }
    std::string bundleKey = GenerateBundleLablel(bundleInfo);
    int32_t result =
        PutBundlePropertyToDisturbeDB(bundleKey, BundleType::BUNDLE_PRIVATE_ALLOWED_TYPE, allow);

    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::PutNotificationsEnabledForBundle(
    const NotificationPreferencesInfo::BundleInfo &bundleInfo, const bool &enabled)
{
    ANS_LOGD("%{public}s, enabled[%{public}d]", __FUNCTION__, enabled);
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }

    if (!CheckBundle(bundleInfo.GetBundleName(), bundleInfo.GetBundleUid())) {
        return false;
    }

    std::string bundleKey = GenerateBundleLablel(bundleInfo);
    int32_t result =
        PutBundlePropertyToDisturbeDB(bundleKey, BundleType::BUNDLE_ENABLE_NOTIFICATION_TYPE, enabled);
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::PutNotificationsEnabled(const int32_t &userId, const bool &enabled)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("RdbStore is nullptr.");
        return false;
    }

    std::string typeKey =
        std::string().append(KEY_ENABLE_ALL_NOTIFICATION).append(KEY_UNDER_LINE).append(std::to_string(userId));
    std::string enableValue = std::to_string(enabled);
    int32_t result = rdbDataManager_->InsertData(typeKey, enableValue);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Store enable notification failed. %{public}d", result);
        return false;
    }
    return true;
}

bool NotificationPreferencesDatabase::PutHasPoppedDialog(
    const NotificationPreferencesInfo::BundleInfo &bundleInfo, const bool &hasPopped)
{
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }

    if (!CheckBundle(bundleInfo.GetBundleName(), bundleInfo.GetBundleUid())) {
        return false;
    }

    std::string bundleKey = GenerateBundleLablel(bundleInfo);
    int32_t result =
        PutBundlePropertyToDisturbeDB(bundleKey, BundleType::BUNDLE_POPPED_DIALOG_TYPE, hasPopped);
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::PutDoNotDisturbDate(
    const int32_t &userId, const sptr<NotificationDoNotDisturbDate> &date)
{
    if (date == nullptr) {
        ANS_LOGE("Invalid date.");
        return false;
    }

    if (!CheckRdbStore()) {
        ANS_LOGE("RdbStore is nullptr.");
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

    int32_t result = rdbDataManager_->InsertBatchData(values);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Store DoNotDisturbDate failed. %{public}d", result);
        return false;
    }

    return true;
}

void NotificationPreferencesDatabase::GetValueFromDisturbeDB(
    const std::string &key, std::function<void(std::string &)> callback)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("RdbStore is nullptr.");
        return;
    }
    std::string value;
    int32_t result = rdbDataManager_->QueryData(key, value);
    if (result == NativeRdb::E_ERROR) {
        ANS_LOGE("Get value failed, use default value. error code is %{public}d", result);
        return;
    }
    callback(value);
}

void NotificationPreferencesDatabase::GetValueFromDisturbeDB(
    const std::string &key, std::function<void(int32_t &, std::string &)> callback)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("RdbStore is nullptr.");
        return;
    }
    std::string value;
    int32_t result = rdbDataManager_->QueryData(key, value);
    callback(result, value);
}

bool NotificationPreferencesDatabase::CheckBundle(const std::string &bundleName, const int32_t &bundleUid)
{
    std::string bundleKeyStr = KEY_BUNDLE_LABEL + bundleName + std::to_string(bundleUid);
    ANS_LOGD("CheckBundle bundleKeyStr %{public}s", bundleKeyStr.c_str());
    bool result = true;
    GetValueFromDisturbeDB(bundleKeyStr, [&](const int32_t &status, std::string &value) {
        switch (status) {
            case NativeRdb::E_EMPTY_VALUES_BUCKET: {
                NotificationPreferencesInfo::BundleInfo bundleInfo;
                bundleInfo.SetBundleName(bundleName);
                bundleInfo.SetBundleUid(bundleUid);
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
    GenerateEntry(GenerateBundleKey(bundleKey, KEY_BUNDLE_PRIVATE_ALLOWED),
        std::to_string(bundleInfo.GetIsPrivateAllowed()),
        values);
    GenerateEntry(GenerateBundleKey(bundleKey, KEY_BUNDLE_ENABLE_NOTIFICATION),
        std::to_string(bundleInfo.GetEnableNotification()),
        values);
    GenerateEntry(GenerateBundleKey(bundleKey, KEY_BUNDLE_POPPED_DIALOG),
        std::to_string(bundleInfo.GetHasPoppedDialog()),
        values);
    GenerateEntry(GenerateBundleKey(bundleKey, KEY_BUNDLE_UID), std::to_string(bundleInfo.GetBundleUid()), values);
    if (!CheckRdbStore()) {
        ANS_LOGE("RdbStore is nullptr.");
        return false;
    }
    int32_t result = rdbDataManager_->InsertBatchData(values);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Store bundle failed. %{public}d", result);
        return false;
    }
    return true;
}

bool NotificationPreferencesDatabase::ParseFromDisturbeDB(NotificationPreferencesInfo &info)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    ParseDoNotDisturbType(info);
    ParseDoNotDisturbBeginDate(info);
    ParseDoNotDisturbEndDate(info);
    ParseEnableAllNotification(info);

    if (!CheckRdbStore()) {
        ANS_LOGE("RdbStore is nullptr.");
        return false;
    }
    std::unordered_map<std::string, std::string> values;
    int32_t result = rdbDataManager_->QueryDataBeginWithKey(KEY_BUNDLE_LABEL, values);
    if (result == NativeRdb::E_ERROR) {
        ANS_LOGE("Get Bundle Info failed.");
        return false;
    }
    ParseBundleFromDistureDB(info, values);
    return true;
}

bool NotificationPreferencesDatabase::RemoveAllDataFromDisturbeDB()
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (!CheckRdbStore()) {
        ANS_LOGE("RdbStore is nullptr.");
        return false;
    }
    int32_t result = rdbDataManager_->Destroy();
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::RemoveBundleFromDisturbeDB(const std::string &bundleKey)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (!CheckRdbStore()) {
        ANS_LOGE("RdbStore is nullptr.");
        return false;
    }

    std::unordered_map<std::string, std::string> values;
    int32_t result = rdbDataManager_->QueryDataBeginWithKey(
        (KEY_ANS_BUNDLE + KEY_UNDER_LINE + bundleKey + KEY_UNDER_LINE), values);

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
    result = rdbDataManager_->DeleteBathchData(keys);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("delete bundle Info failed.");
        return false;
    }
    return true;
}

bool NotificationPreferencesDatabase::RemoveSlotFromDisturbeDB(
    const std::string &bundleKey, const NotificationConstant::SlotType &type)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleKey.empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }

    if (!CheckRdbStore()) {
        ANS_LOGE("RdbStore is nullptr.");
        return false;
    }

    std::unordered_map<std::string, std::string> values;
    std::string slotType = std::to_string(type);
    int32_t result = rdbDataManager_->QueryDataBeginWithKey(
        (GenerateSlotKey(bundleKey, slotType) + KEY_UNDER_LINE), values);
    if (result == NativeRdb::E_ERROR) {
        return false;
    }
    std::vector<std::string> keys;
    for (auto iter : values) {
        keys.push_back(iter.first);
    }

    result = rdbDataManager_->DeleteBathchData(keys);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("delete bundle Info failed.");
        return false;
    }

    return true;
}

bool NotificationPreferencesDatabase::RemoveAllSlotsFromDisturbeDB(const std::string &bundleKey)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleKey.empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }

    if (!CheckRdbStore()) {
        ANS_LOGE("RdbStore is nullptr.");
        return false;
    }

    std::unordered_map<std::string, std::string> values;
    int32_t result = rdbDataManager_->QueryDataBeginWithKey(
        (GenerateSlotKey(bundleKey) + KEY_UNDER_LINE), values);
    if (result == NativeRdb::E_ERROR) {
        return false;
    }
    std::vector<std::string> keys;
    for (auto iter : values) {
        keys.push_back(iter.first);
    }

    result = rdbDataManager_->DeleteBathchData(keys);
    return (result == NativeRdb::E_OK);
}

bool NotificationPreferencesDatabase::StoreDeathRecipient()
{
    ANS_LOGW("distribute remote died");
    rdbDataManager_ = nullptr;
    return true;
}

template <typename T>
int32_t NotificationPreferencesDatabase::PutBundlePropertyToDisturbeDB(
    const std::string &bundleKey, const BundleType &type, const T &t)
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
        case BundleType::BUNDLE_PRIVATE_ALLOWED_TYPE:
            keyStr = GenerateBundleKey(bundleKey, KEY_BUNDLE_PRIVATE_ALLOWED);
            break;
        case BundleType::BUNDLE_ENABLE_NOTIFICATION_TYPE:
            keyStr = GenerateBundleKey(bundleKey, KEY_BUNDLE_ENABLE_NOTIFICATION);
            break;
        case BundleType::BUNDLE_POPPED_DIALOG_TYPE:
            keyStr = GenerateBundleKey(bundleKey, KEY_BUNDLE_POPPED_DIALOG);
            break;
        default:
            break;
    }
    if (!CheckRdbStore()) {
        ANS_LOGE("RdbStore is nullptr.");
        return false;
    }
    std::string valueStr = std::to_string(t);
    int32_t result = rdbDataManager_->InsertData(keyStr, valueStr);
    return result;
}

bool NotificationPreferencesDatabase::PutBundleToDisturbeDB(
    const std::string &bundleKey, const NotificationPreferencesInfo::BundleInfo &bundleInfo)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("RdbStore is nullptr.");
        return false;
    }

    ANS_LOGD("Key not fund, so create a bundle, bundle key is %{public}s.", bundleKey.c_str());
    int32_t result = rdbDataManager_->InsertData(bundleKey, GenerateBundleLablel(bundleInfo));
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
        ANS_LOGE("Notification slot is nullptr.");
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
}

void NotificationPreferencesDatabase::ParseBundleFromDistureDB(
    NotificationPreferencesInfo &info, const std::unordered_map<std::string, std::string> &values)
{
    if (!CheckRdbStore()) {
        ANS_LOGE("RdbStore is nullptr.");
        return;
    }
    for (auto item : values) {
        std::string bundleKey = item.second;
        ANS_LOGD("Bundle name is %{public}s.", bundleKey.c_str());
        std::unordered_map<std::string, std::string> bundleEntries;
        rdbDataManager_->QueryDataBeginWithKey((GenerateBundleKey(bundleKey)), bundleEntries);
        ANS_LOGD("Bundle key is %{public}s.", GenerateBundleKey(bundleKey).c_str());
        NotificationPreferencesInfo::BundleInfo bunldeInfo;
        for (auto bundleEntry : bundleEntries) {
            if (IsSlotKey(GenerateBundleKey(bundleKey), bundleEntry.first)) {
                ParseSlotFromDisturbeDB(bunldeInfo, bundleKey, bundleEntry);
            } else {
                ParseBundlePropertyFromDisturbeDB(bunldeInfo, bundleKey, bundleEntry);
            }
        }

        info.SetBundleInfoFromDb(bunldeInfo, bundleKey);
    }
}

void NotificationPreferencesDatabase::ParseSlotFromDisturbeDB(NotificationPreferencesInfo::BundleInfo &bundleInfo,
    const std::string &bundleKey, const std::pair<std::string, std::string> &entry)
{
    std::string slotKey = entry.first;
    std::string typeStr = SubUniqueIdentifyFromString(GenerateSlotKey(bundleKey) + KEY_UNDER_LINE, slotKey);
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(StringToInt(typeStr));
    sptr<NotificationSlot> slot = nullptr;
    if (!bundleInfo.GetSlot(slotType, slot)) {
        slot = new NotificationSlot(slotType);
    }
    std::string findString = GenerateSlotKey(bundleKey, typeStr) + KEY_UNDER_LINE;
    ParseSlot(findString, slot, entry);
    bundleInfo.SetSlot(slot);
}

void NotificationPreferencesDatabase::ParseBundlePropertyFromDisturbeDB(
    NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &bundleKey,
    const std::pair<std::string, std::string> &entry)
{
    std::string typeStr = FindLastString(GenerateBundleKey(bundleKey), entry.first);
    std::string valueStr = entry.second;

    auto iter = bundleMap_.find(typeStr);
    if (iter != bundleMap_.end()) {
        auto func = iter->second;
        func(this, bundleInfo, valueStr);
    }
}

void NotificationPreferencesDatabase::ParseSlot(
    const std::string &findString, sptr<NotificationSlot> &slot, const std::pair<std::string, std::string> &entry)
{
    std::string typeStr = FindLastString(findString, entry.first);
    std::string valueStr = entry.second;
    ANS_LOGD("db key = %{public}s , %{public}s : %{public}s ",
        entry.first.c_str(),
        typeStr.c_str(),
        entry.second.c_str());

    auto iter = slotMap_.find(typeStr);
    if (iter != slotMap_.end()) {
        auto func = iter->second;
        func(this, slot, valueStr);
    }

    if (!typeStr.compare(KEY_SLOT_VIBRATION_STYLE)) {
        GetValueFromDisturbeDB(findString + KEY_SLOT_ENABLE_VRBRATION,
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
        value = stoi(str, nullptr);
    }
    return value;
}

int64_t NotificationPreferencesDatabase::StringToInt64(const std::string &str) const
{
    int64_t value = 0;
    if (!str.empty()) {
        value = stoll(str, nullptr);
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

void NotificationPreferencesDatabase::ParseDoNotDisturbType(NotificationPreferencesInfo &info)
{
    std::vector<int> activeUserId;
    OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(activeUserId);

    for (auto iter : activeUserId) {
        NotificationPreferencesDatabase::GetDoNotDisturbType(info, iter);
    }
}

void NotificationPreferencesDatabase::ParseDoNotDisturbBeginDate(NotificationPreferencesInfo &info)
{
    std::vector<int> activeUserId;
    OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(activeUserId);

    for (auto iter : activeUserId) {
        NotificationPreferencesDatabase::GetDoNotDisturbBeginDate(info, iter);
    }
}

void NotificationPreferencesDatabase::ParseDoNotDisturbEndDate(NotificationPreferencesInfo &info)
{
    std::vector<int> activeUserId;
    OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(activeUserId);

    for (auto iter : activeUserId) {
        NotificationPreferencesDatabase::GetDoNotDisturbEndDate(info, iter);
    }
}

void NotificationPreferencesDatabase::ParseEnableAllNotification(NotificationPreferencesInfo &info)
{
    std::vector<int> activeUserId;
    OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(activeUserId);

    for (auto iter : activeUserId) {
        NotificationPreferencesDatabase::GetEnableAllNotification(info, iter);
    }
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

void NotificationPreferencesDatabase::ParseBundleShowBadge(
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

void NotificationPreferencesDatabase::ParseBundlePrivateAllowed(
    NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &value) const
{
    ANS_LOGD("SetBundlePrivateAllowed bundle private allowed is %{public}s.", value.c_str());
    bundleInfo.SetIsPrivateAllowed(static_cast<bool>(StringToInt(value)));
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
        key, [&](const int32_t &status, std::string &value) {
            sptr<NotificationDoNotDisturbDate> disturbDate =
                        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
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
        key, [&](const int32_t &status, std::string &value) {
            sptr<NotificationDoNotDisturbDate> disturbDate =
                        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
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
        key, [&](const int32_t &status, std::string &value) {
            sptr<NotificationDoNotDisturbDate> disturbDate =
                        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
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
        key, [&](const int32_t &status, std::string &value) {
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

bool NotificationPreferencesDatabase::RemoveNotificationEnable(const int32_t userId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (!CheckRdbStore()) {
        ANS_LOGE("RdbStore is nullptr.");
        return false;
    }

    std::string key =
        std::string(KEY_ENABLE_ALL_NOTIFICATION).append(KEY_UNDER_LINE).append(std::to_string(userId));
    int32_t result = rdbDataManager_->DeleteData(key);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("delete bundle Info failed.");
        return false;
    }

    ANS_LOGD("%{public}s remove notification enable, userId : %{public}d", __FUNCTION__, userId);
    return true;
}

bool NotificationPreferencesDatabase::RemoveDoNotDisturbDate(const int32_t userId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (!CheckRdbStore()) {
        ANS_LOGE("RdbStore is nullptr.");
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
    
    int32_t result = rdbDataManager_->DeleteBathchData(keys);
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
        ANS_LOGE("RdbStore is nullptr.");
        return false;
    }

    std::string key = KEY_BUNDLE_LABEL + bundleName + std::to_string(uid);
    int32_t result = rdbDataManager_->DeleteData(key);
    if (result != NativeRdb::E_OK) {
        ANS_LOGE("Delete ans bundle db info failed, bundle[%{public}s:%{public}d]", bundleName.c_str(), uid);
        return false;
    }

    ANS_LOGE("Remove ans bundle db info, bundle[%{public}s:%{public}d]", bundleName.c_str(), uid);
    return true;
}
}  // namespace Notification
}  // namespace OHOS