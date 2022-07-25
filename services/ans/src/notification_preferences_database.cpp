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
 * Indicates that disturbe key which group.
 */
const static std::string KEY_GROUP = "group";

/**
 * Indicates that disturbe key which group id.
 */
const static std::string KEY_GROUP_ID = "id";

/**
 * Indicates that disturbe key which group name.
 */
const static std::string KEY_GROUP_NAME = "name";

/**
 * Indicates that disturbe key which group description.
 */
const static std::string KEY_GROUP_DESCRIPTION = "groupDescription";

/**
 * Indicates that disturbe key which group is disable.
 */
const static std::string KEY_GROUP_DISABLE = "isDisable";

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
 * Indicates that disturbe key which slot group id.
 */
const static std::string KEY_SLOT_GROUPID = "groupId";

/**
 * Indicates that disturbe key which slot group name.
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
            KEY_SLOT_GROUPID,
            std::bind(&NotificationPreferencesDatabase::ParseSlotGroupId, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3),
        },
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
    TryTwice([this] { return GetKvStore(); });
}

NotificationPreferencesDatabase::~NotificationPreferencesDatabase()
{
    CloseKvStore();
}

void NotificationPreferencesDatabase::TryTwice(const std::function<DistributedKv::Status()> &func) const
{
    DistributedKv::Status status = func();
    if (status != DistributedKv::Status::SUCCESS) {
        status = func();
        ANS_LOGW("Distribute database error and try to call again, result = %{public}d.", status);
    }
}

DistributedKv::Status NotificationPreferencesDatabase::GetKvStore()
{
    DistributedKv::Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .autoSync = false,
        .kvStoreType = DistributedKv::KvStoreType::SINGLE_VERSION,
    };
    auto status = dataManager_.GetSingleKvStore(options, appId_, storeId_, kvStorePtr_);
    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("Return error: %{public}d.", status);
    } else {
        ANS_LOGD("Get kvStore success.");
    }
    return status;
}

void NotificationPreferencesDatabase::CloseKvStore()
{
    dataManager_.CloseKvStore(appId_, kvStorePtr_);
}

bool NotificationPreferencesDatabase::CheckKvStore()
{
    if (kvStorePtr_ != nullptr) {
        return true;
    }
    TryTwice([this] { return GetKvStore(); });
    return kvStorePtr_ != nullptr;
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

    bool result = true;
    std::vector<DistributedKv::Entry> entries;
    for (auto iter : slots) {
        result = SlotToEntry(bundleName, bundleUid, iter, entries);
        if (!result) {
            return result;
        }
    }

    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return false;
    }
    DistributedKv::Status status = kvStorePtr_->PutBatch(entries);
    return (status == DistributedKv::Status::SUCCESS);
}

bool NotificationPreferencesDatabase::PutGroupsToDisturbeDB(
    const std::string &bundleName, const int32_t &bundleUid, const std::vector<sptr<NotificationSlotGroup>> &groups)
{
    if (bundleName.empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }

    if (groups.empty()) {
        ANS_LOGE("Slot is empty.");
        return false;
    }

    bool result = true;
    std::vector<DistributedKv::Entry> entries;
    for (auto iter : groups) {
        result = GroupToEntry(bundleName, bundleUid, iter, entries);
        if (!result) {
            ANS_LOGE("Group to entry is null.");
            return result;
        }
    }

    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return false;
    }
    DistributedKv::Status status = kvStorePtr_->PutBatch(entries);
    return (status == DistributedKv::Status::SUCCESS);
}

bool NotificationPreferencesDatabase::PutBundlePropertyToDisturbeDB(
    const NotificationPreferencesInfo::BundleInfo &bundleInfo)
{
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }

    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return false;
    }

    std::string bundleKeyStr = KEY_BUNDLE_LABEL + GenerateBundleLablel(bundleInfo);
    bool result = false;
    GetValueFromDisturbeDB(bundleKeyStr, [&](DistributedKv::Status &status, DistributedKv::Value &value) {
        switch (status) {
            case DistributedKv::Status::KEY_NOT_FOUND: {
                result = PutBundleToDisturbeDB(bundleKeyStr, bundleInfo);
                break;
            }
            case DistributedKv::Status::SUCCESS: {
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
    DistributedKv::Status status =
        PutBundlePropertyToDisturbeDB(bundleKey, BundleType::BUNDLE_SHOW_BADGE_TYPE, enable);
    return (status == DistributedKv::Status::SUCCESS);
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
    DistributedKv::Status status =
        PutBundlePropertyToDisturbeDB(bundleKey, BundleType::BUNDLE_IMPORTANCE_TYPE, importance);
    return (status == DistributedKv::Status::SUCCESS);
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
    DistributedKv::Status status =
        PutBundlePropertyToDisturbeDB(bundleKey, BundleType::BUNDLE_BADGE_TOTAL_NUM_TYPE, totalBadgeNum);
    return (status == DistributedKv::Status::SUCCESS);
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
    DistributedKv::Status status =
        PutBundlePropertyToDisturbeDB(bundleKey, BundleType::BUNDLE_PRIVATE_ALLOWED_TYPE, allow);

    return (status == DistributedKv::Status::SUCCESS);
}

bool NotificationPreferencesDatabase::PutNotificationsEnabledForBundle(
    const NotificationPreferencesInfo::BundleInfo &bundleInfo, const bool &enabled)
{
    if (bundleInfo.GetBundleName().empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }

    if (!CheckBundle(bundleInfo.GetBundleName(), bundleInfo.GetBundleUid())) {
        return false;
    }

    std::string bundleKey = GenerateBundleLablel(bundleInfo);
    DistributedKv::Status status =
        PutBundlePropertyToDisturbeDB(bundleKey, BundleType::BUNDLE_ENABLE_NOTIFICATION_TYPE, enabled);
    return (status == DistributedKv::Status::SUCCESS);
}

bool NotificationPreferencesDatabase::PutNotificationsEnabled(const int32_t &userId, const bool &enabled)
{
    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return false;
    }

    std::string typeKey =
        std::string().append(KEY_ENABLE_ALL_NOTIFICATION).append(KEY_UNDER_LINE).append(std::to_string(userId));
    DistributedKv::Key enableKey(typeKey);
    DistributedKv::Value enableValue(std::to_string(enabled));
    DistributedKv::Status status = kvStorePtr_->Put(enableKey, enableValue);
    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("Store enable notification failed. %{public}d", status);
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
    DistributedKv::Status status =
        PutBundlePropertyToDisturbeDB(bundleKey, BundleType::BUNDLE_POPPED_DIALOG_TYPE, hasPopped);
    return (status == DistributedKv::Status::SUCCESS);
}

bool NotificationPreferencesDatabase::PutDoNotDisturbDate(
    const int32_t &userId, const sptr<NotificationDoNotDisturbDate> &date)
{
    if (date == nullptr) {
        ANS_LOGE("Invalid date.");
        return false;
    }

    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return false;
    }

    DistributedKv::Entry type;
    std::string typeKey =
        std::string().append(KEY_DO_NOT_DISTURB_TYPE).append(KEY_UNDER_LINE).append(std::to_string(userId));
    type.key = DistributedKv::Key(typeKey);
    type.value = DistributedKv::Value(std::to_string((int)date->GetDoNotDisturbType()));

    DistributedKv::Entry beginDate;
    std::string beginDateKey =
        std::string().append(KEY_DO_NOT_DISTURB_BEGIN_DATE).append(KEY_UNDER_LINE).append(std::to_string(userId));
    beginDate.key = DistributedKv::Key(beginDateKey);
    beginDate.value = DistributedKv::Value(std::to_string(date->GetBeginDate()));

    DistributedKv::Entry endDate;
    std::string endDateKey =
        std::string().append(KEY_DO_NOT_DISTURB_END_DATE).append(KEY_UNDER_LINE).append(std::to_string(userId));
    endDate.key = DistributedKv::Key(endDateKey);
    endDate.value = DistributedKv::Value(std::to_string(date->GetEndDate()));

    std::vector<DistributedKv::Entry> entries = {
        type,
        beginDate,
        endDate,
    };

    DistributedKv::Status status = kvStorePtr_->PutBatch(entries);
    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("Store DoNotDisturbDate failed. %{public}d", status);
        return false;
    }

    return true;
}

void NotificationPreferencesDatabase::GetValueFromDisturbeDB(
    const std::string &key, std::function<void(DistributedKv::Value &)> callback)
{
    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return;
    }

    DistributedKv::Status status;
    DistributedKv::Value value;
    DistributedKv::Key getKey(key);
    status = kvStorePtr_->Get(getKey, value);
    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("Get value failed, use default value. error code is %{public}d", status);
        return;
    }

    if (value.Empty()) {
        ANS_LOGE("Get value is empty, use default value. error code is %{public}d", value.Empty());
        return;
    }
    callback(value);
}

void NotificationPreferencesDatabase::GetValueFromDisturbeDB(
    const std::string &key, std::function<void(DistributedKv::Status &, DistributedKv::Value &)> callback)
{
    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return;
    }

    DistributedKv::Status status;
    DistributedKv::Value value;
    DistributedKv::Key getKey(key);
    status = kvStorePtr_->Get(getKey, value);
    callback(status, value);
}

bool NotificationPreferencesDatabase::CheckBundle(const std::string &bundleName, const int32_t &bundleUid)
{
    std::string bundleKeyStr = KEY_BUNDLE_LABEL + bundleName + std::to_string(bundleUid);
    ANS_LOGD("CheckBundle bundleKeyStr %{public}s", bundleKeyStr.c_str());
    bool result = true;
    GetValueFromDisturbeDB(bundleKeyStr, [&](DistributedKv::Status &status, DistributedKv::Value &value) {
        switch (status) {
            case DistributedKv::Status::KEY_NOT_FOUND: {
                NotificationPreferencesInfo::BundleInfo bundleInfo;
                bundleInfo.SetBundleName(bundleName);
                bundleInfo.SetBundleUid(bundleUid);
                result = PutBundleToDisturbeDB(bundleKeyStr, bundleInfo);
                break;
            }
            case DistributedKv::Status::SUCCESS: {
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
    std::vector<DistributedKv::Entry> entries;
    std::string bundleKey = bundleInfo.GetBundleName().append(std::to_string(bundleInfo.GetBundleUid()));
    GenerateEntry(GenerateBundleKey(bundleKey, KEY_BUNDLE_NAME), bundleInfo.GetBundleName(), entries);
    GenerateEntry(GenerateBundleKey(bundleKey, KEY_BUNDLE_BADGE_TOTAL_NUM),
        std::to_string(bundleInfo.GetBadgeTotalNum()),
        entries);
    GenerateEntry(
        GenerateBundleKey(bundleKey, KEY_BUNDLE_IMPORTANCE), std::to_string(bundleInfo.GetImportance()), entries);
    GenerateEntry(
        GenerateBundleKey(bundleKey, KEY_BUNDLE_SHOW_BADGE), std::to_string(bundleInfo.GetIsShowBadge()), entries);
    GenerateEntry(GenerateBundleKey(bundleKey, KEY_BUNDLE_PRIVATE_ALLOWED),
        std::to_string(bundleInfo.GetIsPrivateAllowed()),
        entries);
    GenerateEntry(GenerateBundleKey(bundleKey, KEY_BUNDLE_ENABLE_NOTIFICATION),
        std::to_string(bundleInfo.GetEnableNotification()),
        entries);
    GenerateEntry(GenerateBundleKey(bundleKey, KEY_BUNDLE_POPPED_DIALOG),
        std::to_string(bundleInfo.GetHasPoppedDialog()),
        entries);
    GenerateEntry(GenerateBundleKey(bundleKey, KEY_BUNDLE_UID), std::to_string(bundleInfo.GetBundleUid()), entries);
    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return false;
    }
    DistributedKv::Status status = kvStorePtr_->PutBatch(entries);
    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("Store bundle failed. %{public}d", status);
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

    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return false;
    }
    DistributedKv::Status status;
    std::vector<DistributedKv::Entry> entries;
    status = kvStorePtr_->GetEntries(DistributedKv::Key(KEY_BUNDLE_LABEL), entries);
    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("Get Bundle Info failed.");
        return false;
    }
    ParseBundleFromDistureDB(info, entries);
    return true;
}

bool NotificationPreferencesDatabase::RemoveAllDataFromDisturbeDB()
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return false;
    }
    DistributedKv::Status status = dataManager_.DeleteKvStore(appId_, storeId_);
    return (status == DistributedKv::Status::SUCCESS);
}

bool NotificationPreferencesDatabase::RemoveBundleFromDisturbeDB(const std::string &bundleKey)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return false;
    }

    DistributedKv::Status status;
    std::vector<DistributedKv::Entry> entries;
    status = kvStorePtr_->GetEntries(
        DistributedKv::Key(KEY_ANS_BUNDLE + KEY_UNDER_LINE + bundleKey + KEY_UNDER_LINE), entries);

    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("Get Bundle Info failed.");
        return false;
    }

    std::vector<DistributedKv::Key> keys;
    for (auto iter : entries) {
        keys.push_back(iter.key);
    }

    DistributedKv::Key bundleDBKey(KEY_BUNDLE_LABEL + KEY_BUNDLE_NAME + KEY_UNDER_LINE + bundleKey);
    keys.push_back(bundleDBKey);
    status = kvStorePtr_->DeleteBatch(keys);
    if (status != DistributedKv::Status::SUCCESS) {
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

    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return false;
    }

    DistributedKv::Status status;
    std::vector<DistributedKv::Entry> slotentries;
    std::string slotType = std::to_string(type);
    status =
        kvStorePtr_->GetEntries(DistributedKv::Key(GenerateSlotKey(bundleKey, slotType) + KEY_UNDER_LINE), slotentries);
    if (status != DistributedKv::Status::SUCCESS) {
        return false;
    }
    std::vector<DistributedKv::Key> keys;
    for (auto iter : slotentries) {
        keys.push_back(iter.key);
    }

    status = kvStorePtr_->DeleteBatch(keys);
    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("delete bundle Info failed.");
        return false;
    }

    ANS_LOGD("%{public}s remove slot status %{public}d", __FUNCTION__, status);
    return true;
}

bool NotificationPreferencesDatabase::RemoveAllSlotsFromDisturbeDB(const std::string &bundleKey)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleKey.empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }

    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return false;
    }

    DistributedKv::Status status;
    std::vector<DistributedKv::Entry> slotsEntries;
    status = kvStorePtr_->GetEntries(DistributedKv::Key(GenerateSlotKey(bundleKey) + KEY_UNDER_LINE), slotsEntries);
    if (status != DistributedKv::Status::SUCCESS) {
        return false;
    }
    std::vector<DistributedKv::Key> keys;
    for (auto iter : slotsEntries) {
        keys.push_back(iter.key);
    }

    status = kvStorePtr_->DeleteBatch(keys);
    ANS_LOGD("%{public}s remove all slots status %{public}d", __FUNCTION__, status);
    return (status == DistributedKv::Status::SUCCESS);
}

bool NotificationPreferencesDatabase::RemoveGroupsFromDisturbeDB(
    const std::string &bundleKey, const std::vector<std::string> &groupIds)
{
    if (bundleKey.empty()) {
        ANS_LOGE("Bundle name is null.");
        return false;
    }

    if (groupIds.empty()) {
        ANS_LOGE("Group id is empty.");
        return false;
    }

    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return false;
    }

    std::vector<DistributedKv::Key> keys;
    bool result = true;
    for (auto iter : groupIds) {
        result = GetRemoveGroupKeysFromDisturbeDB(bundleKey, iter, keys);
        if (!result) {
            return result;
        }
    }

    DistributedKv::Status status = kvStorePtr_->DeleteBatch(keys);
    ANS_LOGD("%{public}s remove groups status %{public}d", __FUNCTION__, status);
    return (status == DistributedKv::Status::SUCCESS);
}

bool NotificationPreferencesDatabase::GetRemoveGroupKeysFromDisturbeDB(
    const std::string &bundleKey, const std::string &groupId, std::vector<DistributedKv::Key> &keys)
{
    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return false;
    }

    DistributedKv::Status status;
    std::vector<DistributedKv::Entry> groupentries;
    std::string slotKeyStr = GenerateGroupKey(bundleKey, groupId);
    status = kvStorePtr_->GetEntries(DistributedKv::Key(slotKeyStr + KEY_UNDER_LINE), groupentries);
    if (status != DistributedKv::Status::SUCCESS) {
        return false;
    }
    for (auto iter : groupentries) {
        keys.push_back(iter.key);
    }

    return true;
}

bool NotificationPreferencesDatabase::StoreDeathRecipient()
{
    ANS_LOGW("distribute remote died");
    if (kvStorePtr_ != nullptr) {
        kvStorePtr_ = nullptr;
    }
    return true;
}

template <typename T>
DistributedKv::Status NotificationPreferencesDatabase::PutBundlePropertyToDisturbeDB(
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
    DistributedKv::Key key(keyStr);
    DistributedKv::Value value(std::to_string(t));
    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return DistributedKv::Status::ERROR;
    }
    DistributedKv::Status status = kvStorePtr_->Put(key, value);
    return status;
}

bool NotificationPreferencesDatabase::PutBundleToDisturbeDB(
    const std::string &bundleKey, const NotificationPreferencesInfo::BundleInfo &bundleInfo)
{
    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return false;
    }

    ANS_LOGD("Key not fund, so create a bundle, bundle key is %{public}s.", bundleKey.c_str());
    DistributedKv::Key bundleDBKey(bundleKey);
    DistributedKv::Value bundleValue(GenerateBundleLablel(bundleInfo));
    if (kvStorePtr_->Put(bundleDBKey, bundleValue) != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("Store bundle name to db is failed.");
        return false;
    }

    if (!PutBundlePropertyValueToDisturbeDB(bundleInfo)) {
        return false;
    }

    return true;
}

void NotificationPreferencesDatabase::GenerateEntry(
    const std::string &key, const std::string &value, std::vector<DistributedKv::Entry> &entries) const
{
    DistributedKv::Entry entry;
    DistributedKv::Key dbKey(key);
    DistributedKv::Value dbValue(value);
    entry.key = dbKey;
    entry.value = dbValue;
    entries.push_back(entry);
}

bool NotificationPreferencesDatabase::SlotToEntry(const std::string &bundleName, const int32_t &bundleUid,
    const sptr<NotificationSlot> &slot, std::vector<DistributedKv::Entry> &entries)
{
    if (slot == nullptr) {
        ANS_LOGE("Notification group is nullptr.");
        return false;
    }

    if (!CheckBundle(bundleName, bundleUid)) {
        return false;
    }

    std::string bundleKey = bundleName + std::to_string(bundleUid);
    GenerateSlotEntry(bundleKey, slot, entries);
    return true;
}

void NotificationPreferencesDatabase::GenerateSlotEntry(const std::string &bundleKey,
    const sptr<NotificationSlot> &slot, std::vector<DistributedKv::Entry> &entries) const
{
    std::string slotType = std::to_string(slot->GetType());
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_TYPE), std::to_string(slot->GetType()), entries);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_ID), slot->GetId(), entries);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_GROUPID), slot->GetSlotGroup(), entries);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_NAME), slot->GetName(), entries);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_DESCRIPTION), slot->GetDescription(), entries);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_LEVEL), std::to_string(slot->GetLevel()), entries);
    GenerateEntry(
        GenerateSlotKey(bundleKey, slotType, KEY_SLOT_SHOW_BADGE), std::to_string(slot->IsShowBadge()), entries);
    GenerateEntry(
        GenerateSlotKey(bundleKey, slotType, KEY_SLOT_ENABLE_LIGHT), std::to_string(slot->CanEnableLight()), entries);
    GenerateEntry(
        GenerateSlotKey(bundleKey, slotType, KEY_SLOT_ENABLE_VRBRATION), std::to_string(slot->CanVibrate()), entries);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_LED_LIGHT_COLOR),
        std::to_string(slot->GetLedLightColor()),
        entries);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_LOCKSCREEN_VISIBLENESS),
        std::to_string(static_cast<int>(slot->GetLockScreenVisibleness())),
        entries);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_SOUND), slot->GetSound().ToString(), entries);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_ENABLE_BYPASS_DND),
        std::to_string(slot->IsEnableBypassDnd()),
        entries);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_VIBRATION_STYLE),
        VectorToString(slot->GetVibrationStyle()),
        entries);
    GenerateEntry(GenerateSlotKey(bundleKey, slotType, KEY_SLOT_ENABLED), std::to_string(slot->GetEnable()), entries);
}

bool NotificationPreferencesDatabase::GroupToEntry(const std::string &bundleName, const int32_t &bundleUid,
    const sptr<NotificationSlotGroup> &group, std::vector<DistributedKv::Entry> &entries)
{

    if (group == nullptr) {
        ANS_LOGE("Notification group is nullptr.");
        return false;
    }

    if (!CheckBundle(bundleName, bundleUid)) {
        return false;
    }

    std::string bundleKey = bundleName + std::to_string(bundleUid);
    GenerateGroupEntry(bundleKey, group, entries);
    return true;
}

void NotificationPreferencesDatabase::GenerateGroupEntry(const std::string &bundleKey,
    const sptr<NotificationSlotGroup> &group, std::vector<DistributedKv::Entry> &entries) const
{
    std::string groupLebal = group->GetId().append(KEY_UNDER_LINE);
    GenerateEntry(GenerateGroupKey(bundleKey, groupLebal + KEY_GROUP_ID), group->GetId(), entries);
    GenerateEntry(GenerateGroupKey(bundleKey, groupLebal + KEY_GROUP_NAME), group->GetName(), entries);
    GenerateEntry(GenerateGroupKey(bundleKey, groupLebal + KEY_GROUP_DESCRIPTION), group->GetDescription(), entries);
    GenerateEntry(
        GenerateGroupKey(bundleKey, groupLebal + KEY_GROUP_DISABLE), std::to_string(group->IsDisabled()), entries);
}

void NotificationPreferencesDatabase::ParseBundleFromDistureDB(
    NotificationPreferencesInfo &info, const std::vector<DistributedKv::Entry> &entries)
{
    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return;
    }
    for (auto item : entries) {
        std::string bundleKey = item.value.ToString();
        ANS_LOGD("Bundle name is %{public}s.", bundleKey.c_str());
        std::vector<DistributedKv::Entry> bundleEntries;
        kvStorePtr_->GetEntries(DistributedKv::Key(GenerateBundleKey(bundleKey)), bundleEntries);
        ANS_LOGD("Bundle key is %{public}s.", GenerateBundleKey(bundleKey).c_str());
        NotificationPreferencesInfo::BundleInfo bunldeInfo;
        for (auto bundleEntry : bundleEntries) {
            if (IsSlotKey(GenerateBundleKey(bundleKey), bundleEntry.key.ToString())) {
                ParseSlotFromDisturbeDB(bunldeInfo, bundleKey, bundleEntry);
            } else if (IsGroupKey(GenerateBundleKey(bundleKey), bundleEntry.key.ToString())) {
                ParseGroupFromDisturbeDB(bunldeInfo, bundleKey, bundleEntry);
            } else {
                ParseBundlePropertyFromDisturbeDB(bunldeInfo, bundleKey, bundleEntry);
            }
        }

        info.SetBundleInfo(bunldeInfo);
    }
}

void NotificationPreferencesDatabase::ParseSlotFromDisturbeDB(NotificationPreferencesInfo::BundleInfo &bundleInfo,
    const std::string &bundleKey, const DistributedKv::Entry &entry)
{
    std::string slotKey = entry.key.ToString();
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

void NotificationPreferencesDatabase::ParseGroupFromDisturbeDB(NotificationPreferencesInfo::BundleInfo &bundleInfo,
    const std::string &bundleKey, const DistributedKv::Entry &entry)
{
    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return;
    }
    std::string groupKey = entry.key.ToString();
    std::string groupId = SubUniqueIdentifyFromString(GenerateGroupKey(bundleKey) + KEY_UNDER_LINE, groupKey);
    sptr<NotificationSlotGroup> group;
    if (!bundleInfo.GetGroup(groupId, group)) {
        std::string groupName;
        std::string groupNameKey = GenerateGroupKey(bundleKey, groupId + KEY_UNDER_LINE + KEY_GROUP_NAME);
        GetValueFromDisturbeDB(
            groupNameKey, [&groupName](DistributedKv::Value &value) { groupName = value.ToString(); });
        if (groupName.empty()) {
            ANS_LOGE("Group name does not exsited.");
            return;
        }
        group = new NotificationSlotGroup(groupId, groupName);
    }

    ParseGroupDescription(bundleKey, group, entry);
    bundleInfo.SetGroup(group);
}

void NotificationPreferencesDatabase::ParseBundlePropertyFromDisturbeDB(
    NotificationPreferencesInfo::BundleInfo &bundleInfo, const std::string &bundleKey,
    const DistributedKv::Entry &entry)
{
    std::string typeStr = FindLastString(GenerateBundleKey(bundleKey), entry.key.ToString());
    std::string valueStr = entry.value.ToString();
    ANS_LOGD("DB key = %{public}s , type str %{public}s", entry.key.ToString().c_str(), typeStr.c_str());

    auto iter = bundleMap_.find(typeStr);
    if (iter != bundleMap_.end()) {
        auto func = iter->second;
        func(this, bundleInfo, valueStr);
    }
}

void NotificationPreferencesDatabase::ParseSlot(
    const std::string &findString, sptr<NotificationSlot> &slot, const DistributedKv::Entry &entry)
{
    std::string typeStr = FindLastString(findString, entry.key.ToString());
    std::string valueStr = entry.value.ToString();
    ANS_LOGD("db key = %{public}s , %{public}s : %{public}s ",
        entry.key.ToString().c_str(),
        typeStr.c_str(),
        entry.value.ToString().c_str());

    auto iter = slotMap_.find(typeStr);
    if (iter != slotMap_.end()) {
        auto func = iter->second;
        func(this, slot, valueStr);
    }

    if (!typeStr.compare(KEY_SLOT_VIBRATION_STYLE)) {
        GetValueFromDisturbeDB(findString + KEY_SLOT_ENABLE_VRBRATION,
            [&](DistributedKv::Value &value) { ParseSlotEnableVrbration(slot, value.ToString()); });
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

bool NotificationPreferencesDatabase::IsGroupKey(const std::string &bundleKey, const std::string &key) const
{
    std::string tempStr = FindLastString(bundleKey, key);
    size_t pos = tempStr.find_first_of(KEY_UNDER_LINE);
    std::string slotStr;
    if (pos != std::string::npos) {
        slotStr = tempStr.substr(0, pos);
    }
    if (!slotStr.compare(KEY_GROUP)) {
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

std::string NotificationPreferencesDatabase::GenerateGroupKey(
    const std::string &bundleKey, const std::string &type) const
{
    /* group key
     *
     * KEY_ANS_BUNDLE_bundlename_group_id_id0_id:
     * KEY_ANS_BUNDLE_bundlename_group_id_id0_name:
     * KEY_ANS_BUNDLE_bundlename_group_id_id1_name
     *
     */
    std::string key = GenerateBundleKey(bundleKey).append(KEY_GROUP).append(KEY_UNDER_LINE).append(KEY_GROUP_ID);
    if (!type.empty()) {
        key.append(KEY_UNDER_LINE).append(type);
    }
    ANS_LOGD("Group key is %{public}s.", key.c_str());
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

void NotificationPreferencesDatabase::ParseGroupDescription(
    const std::string &bundleKey, sptr<NotificationSlotGroup> &group, const DistributedKv::Entry &entry)
{
    std::string findStr = GenerateGroupKey(bundleKey, group->GetId()) + KEY_UNDER_LINE;
    std::string typeStr = FindLastString(findStr, entry.key.ToString());
    std::string valueStr = entry.value.ToString();
    if (!typeStr.compare(KEY_GROUP_DESCRIPTION)) {
        ANS_LOGD("SetGroupDescription is %{public}s.", valueStr.c_str());
        group->SetDescription(valueStr);
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

void NotificationPreferencesDatabase::ParseSlotGroupId(sptr<NotificationSlot> &slot, const std::string &value) const
{
    ANS_LOGD("ParseSlotGroupId slot group id is %{public}s.", value.c_str());
    std::string slotGroupId = value;
    slot->SetSlotGroup(slotGroupId);
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
        key, [&](DistributedKv::Status &status, DistributedKv::Value &value) {
            sptr<NotificationDoNotDisturbDate> disturbDate =
                        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
            info.GetDoNotDisturbDate(userId, disturbDate);
            if (status == DistributedKv::Status::KEY_NOT_FOUND) {
                PutDoNotDisturbDate(userId, disturbDate);
            } else if (status == DistributedKv::Status::SUCCESS) {
                if (!value.ToString().empty()) {
                    if (disturbDate != nullptr) {
                        disturbDate->SetDoNotDisturbType(
                            (NotificationConstant::DoNotDisturbType)StringToInt(value.ToString()));
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
        key, [&](DistributedKv::Status &status, DistributedKv::Value &value) {
            sptr<NotificationDoNotDisturbDate> disturbDate =
                        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
            info.GetDoNotDisturbDate(userId, disturbDate);
            if (status == DistributedKv::Status::KEY_NOT_FOUND) {
                PutDoNotDisturbDate(userId, disturbDate);
            } else if (status == DistributedKv::Status::SUCCESS) {
                if (!value.ToString().empty()) {
                    if (disturbDate != nullptr) {
                        disturbDate->SetBeginDate(StringToInt64(value.ToString()));
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
        key, [&](DistributedKv::Status &status, DistributedKv::Value &value) {
            sptr<NotificationDoNotDisturbDate> disturbDate =
                        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
            info.GetDoNotDisturbDate(userId, disturbDate);
            if (status == DistributedKv::Status::KEY_NOT_FOUND) {
                PutDoNotDisturbDate(userId, disturbDate);
            } else if (status == DistributedKv::Status::SUCCESS) {
                if (!value.ToString().empty()) {
                    if (disturbDate != nullptr) {
                        disturbDate->SetEndDate(StringToInt64(value.ToString()));
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
        key, [&](DistributedKv::Status &status, DistributedKv::Value &value) {
            if (status == DistributedKv::Status::KEY_NOT_FOUND) {
                bool enable = true;
                if (!info.GetEnabledAllNotification(userId, enable)) {
                    info.SetEnabledAllNotification(userId, enable);
                    ANS_LOGW("Enable setting not found, default true.");
                }
                PutNotificationsEnabled(userId, enable);
            } else if (status == DistributedKv::Status::SUCCESS) {
                if (!value.ToString().empty()) {
                    info.SetEnabledAllNotification(userId, static_cast<bool>(StringToInt(value.ToString())));
                }
            } else {
                ANS_LOGW("Parse enable all notification failed, use default value.");
            }
        });
}

bool NotificationPreferencesDatabase::RemoveNotificationEnable(const int32_t userId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return false;
    }

    std::string key =
        std::string(KEY_ENABLE_ALL_NOTIFICATION).append(KEY_UNDER_LINE).append(std::to_string(userId));
    DistributedKv::Key enableKey(key);
    DistributedKv::Status status = kvStorePtr_->Delete(enableKey);
    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("delete bundle Info failed.");
        return false;
    }

    ANS_LOGD("%{public}s remove notification enable, userId : %{public}d", __FUNCTION__, userId);
    return true;
}

bool NotificationPreferencesDatabase::RemoveDoNotDisturbDate(const int32_t userId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (!CheckKvStore()) {
        ANS_LOGE("KvStore is nullptr.");
        return false;
    }

    std::string typeKey =
        std::string(KEY_DO_NOT_DISTURB_TYPE).append(KEY_UNDER_LINE).append(std::to_string(userId));
    std::string beginDateKey =
        std::string(KEY_DO_NOT_DISTURB_BEGIN_DATE).append(KEY_UNDER_LINE).append(std::to_string(userId));
    std::string endDateKey =
        std::string(KEY_DO_NOT_DISTURB_END_DATE).append(KEY_UNDER_LINE).append(std::to_string(userId));

    std::vector<DistributedKv::Key> keys = {
        DistributedKv::Key(typeKey),
        DistributedKv::Key(beginDateKey),
        DistributedKv::Key(endDateKey)
    };

    DistributedKv::Status status = kvStorePtr_->DeleteBatch(keys);
    if (status != DistributedKv::Status::SUCCESS) {
        ANS_LOGE("delete DoNotDisturb date failed.");
        return false;
    }

    ANS_LOGD("%{public}s remove DoNotDisturb date, userId : %{public}d", __FUNCTION__, userId);
    return true;
}
}  // namespace Notification
}  // namespace OHOS