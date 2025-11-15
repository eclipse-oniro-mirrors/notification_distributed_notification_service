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

#include "common.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi_common.h"
#include "napi_common_util.h"
#include "notification_action_button.h"
#include "notification_capsule.h"
#include "notification_constant.h"
#include "notification_local_live_view_content.h"
#include "notification_progress.h"
#include "notification_ringtone_info.h"
#include "notification_time.h"
#include "pixel_map_napi.h"
#include "napi_common_want_agent.h"

namespace OHOS {
namespace NotificationNapi {
std::set<std::shared_ptr<AbilityRuntime::WantAgent::WantAgent>> Common::wantAgent_;
ffrt::mutex Common::mutex_;

Common::Common()
{}

Common::~Common()
{}

napi_value Common::SetNotificationSortingMap(
    const napi_env &env, const std::shared_ptr<NotificationSortingMap> &sortingMap, napi_value &result)
{
    ANS_LOGD("called");
    if (sortingMap == nullptr) {
        ANS_LOGD("null sortingMap");
        return NapiGetBoolean(env, false);
    }
    if (sortingMap->GetKey().size() == 0) {
        ANS_LOGD("sortingMap GetKey().size is empty");
        return NapiGetBoolean(env, false);
    }

    size_t count = 0;
    napi_value arrSortedHashCode = nullptr;
    napi_create_array(env, &arrSortedHashCode);
    napi_value sortingsResult = nullptr;
    napi_create_object(env, &sortingsResult);
    for (auto key : sortingMap->GetKey()) {
        NotificationSorting sorting;
        if (sortingMap->GetNotificationSorting(key, sorting)) {
            // sortedHashCode: Array<string>
            napi_value keyValue = nullptr;
            ANS_LOGD("sortingMap key = %{public}s", key.c_str());
            napi_create_string_utf8(env, key.c_str(), NAPI_AUTO_LENGTH, &keyValue);
            napi_set_element(env, arrSortedHashCode, count, keyValue);

            // sortings:{[key : string] : NotificationSorting}
            napi_value sortingResult = nullptr;
            napi_create_object(env, &sortingResult);
            if (!SetNotificationSorting(env, sorting, sortingResult)) {
                ANS_LOGE("SetNotificationSorting call failed");
                return NapiGetBoolean(env, false);
            }
            napi_set_named_property(env, sortingsResult, key.c_str(), sortingResult);
            count++;
        } else {
            ANS_LOGW("sortingMap Key: %{public}s match value is empty", key.c_str());
        }
    }
    napi_set_named_property(env, result, "sortedHashCode", arrSortedHashCode);
    napi_set_named_property(env, result, "sortings", sortingsResult);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotificationSorting(const napi_env &env, NotificationSorting &sorting, napi_value &result)
{
    ANS_LOGD("called");

    // slot: NotificationSlot
    napi_value slotResult = nullptr;
    napi_value value = nullptr;
    napi_create_object(env, &slotResult);
    if (!sorting.GetSlot() || !SetNotificationSlot(env, *sorting.GetSlot(), slotResult)) {
        ANS_LOGE("SetNotificationSlot call failed");
        return NapiGetBoolean(env, false);
    }
    napi_set_named_property(env, result, "slot", slotResult);

    // hashCode?: string
    napi_create_string_utf8(env, sorting.GetKey().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "hashCode", value);

    // ranking?: number
    napi_create_int32(env, sorting.GetRanking(), &value);
    napi_set_named_property(env, result, "ranking", value);

    // isDisplayBadge?: boolean
    napi_get_boolean(env, sorting.IsDisplayBadge(), &value);
    napi_set_named_property(env, result, "isDisplayBadge", value);

    // isHiddenNotification?: boolean
    napi_get_boolean(env, sorting.IsHiddenNotification(), &value);
    napi_set_named_property(env, result, "isHiddenNotification", value);

    // importance?: number
    napi_create_int32(env, sorting.GetImportance(), &value);
    napi_set_named_property(env, result, "importance", value);

    // groupKeyOverride?: string
    napi_create_string_utf8(env, sorting.GetGroupKeyOverride().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "groupKeyOverride", value);

    // visiblenessOverride?: number
    napi_create_int32(env, sorting.GetVisiblenessOverride(), &value);
    napi_set_named_property(env, result, "visiblenessOverride", value);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotificationSlot(const napi_env &env, const NotificationSlot &slot, napi_value &result)
{
    ANS_LOGD("called");

    napi_value value = nullptr;
    // type: SlotType
    SlotType outType = SlotType::UNKNOWN_TYPE;
    if (!AnsEnumUtil::SlotTypeCToJS(slot.GetType(), outType)) {
        return NapiGetBoolean(env, false);
    }
    napi_create_int32(env, static_cast<int32_t>(outType), &value);
    napi_set_named_property(env, result, "type", value);
    napi_set_named_property(env, result, "notificationType", value);

    // level?: number
    SlotLevel outLevel = SlotLevel::LEVEL_NONE;
    if (!AnsEnumUtil::SlotLevelCToJS(slot.GetLevel(), outLevel)) {
        return NapiGetBoolean(env, false);
    }
    napi_create_int32(env, static_cast<int32_t>(outLevel), &value);
    napi_set_named_property(env, result, "level", value);

    // desc?: string
    napi_create_string_utf8(env, slot.GetDescription().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "desc", value);

    // badgeFlag?: boolean
    napi_get_boolean(env, slot.IsShowBadge(), &value);
    napi_set_named_property(env, result, "badgeFlag", value);

    // bypassDnd?: boolean
    napi_get_boolean(env, slot.IsEnableBypassDnd(), &value);
    napi_set_named_property(env, result, "bypassDnd", value);

    // lockscreenVisibility?: number
    int32_t lockScreenVisibleness = static_cast<int32_t>(slot.GetLockScreenVisibleness());
    napi_create_int32(env, lockScreenVisibleness, &value);
    napi_set_named_property(env, result, "lockscreenVisibility", value);

    // vibrationEnabled?: boolean
    napi_get_boolean(env, slot.CanVibrate(), &value);
    napi_set_named_property(env, result, "vibrationEnabled", value);

    // sound?: string
    napi_create_string_utf8(env, slot.GetSound().ToString().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "sound", value);

    // lightEnabled?: boolean
    napi_get_boolean(env, slot.CanEnableLight(), &value);
    napi_set_named_property(env, result, "lightEnabled", value);

    // lightColor?: number
    napi_create_int32(env, slot.GetLedLightColor(), &value);
    napi_set_named_property(env, result, "lightColor", value);

    // vibrationValues?: Array<number>
    napi_value arr = nullptr;
    napi_create_array(env, &arr);
    size_t count = 0;
    for (auto vec : slot.GetVibrationStyle()) {
        napi_create_int64(env, vec, &value);
        napi_set_element(env, arr, count, value);
        count++;
    }
    napi_set_named_property(env, result, "vibrationValues", arr);

    // enabled?: boolean
    napi_get_boolean(env, slot.GetEnable(), &value);
    napi_set_named_property(env, result, "enabled", value);

    // authorizedStatus?: number
    napi_create_int32(env, slot.GetAuthorizedStatus(), &value);
    napi_set_named_property(env, result, "authorizedStatus", value);

    // reminderMode?: number
    napi_create_int32(env, slot.GetReminderMode(), &value);
    napi_set_named_property(env, result, "reminderMode", value);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetDoNotDisturbDate(
    const napi_env &env, const NotificationDoNotDisturbDate &date, napi_value &result)
{
    ANS_LOGD("called");
    DoNotDisturbType outType = DoNotDisturbType::TYPE_NONE;
    if (!AnsEnumUtil::DoNotDisturbTypeCToJS(date.GetDoNotDisturbType(), outType)) {
        return NapiGetBoolean(env, false);
    }

    // type:DoNotDisturbType
    napi_value typeNapi = nullptr;
    napi_create_int32(env, static_cast<int32_t>(outType), &typeNapi);
    napi_set_named_property(env, result, "type", typeNapi);

    // begin:Date
    double begind = double(date.GetBeginDate());
    napi_value beginNapi = nullptr;
    napi_create_date(env, begind, &beginNapi);
    napi_set_named_property(env, result, "begin", beginNapi);

    // end:Date
    double endd = double(date.GetEndDate());
    napi_value endNapi = nullptr;
    napi_create_date(env, endd, &endNapi);
    napi_set_named_property(env, result, "end", endNapi);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetEnabledNotificationCallbackData(const napi_env &env, const EnabledNotificationCallbackData &data,
    napi_value &result)
{
    ANS_LOGD("called");
    // bundle: string
    napi_value bundleNapi = nullptr;
    napi_create_string_utf8(env, data.GetBundle().c_str(), NAPI_AUTO_LENGTH, &bundleNapi);
    napi_set_named_property(env, result, "bundle", bundleNapi);

    // uid: uid_t
    napi_value uidNapi = nullptr;
    napi_create_int32(env, data.GetUid(), &uidNapi);
    napi_set_named_property(env, result, "uid", uidNapi);

    // enable: bool
    napi_value enableNapi = nullptr;
    napi_get_boolean(env, data.GetEnable(), &enableNapi);
    napi_set_named_property(env, result, "enable", enableNapi);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetEnabledPriorityNotificationByBundleCallbackData(const napi_env &env,
    const EnabledPriorityNotificationByBundleCallbackData &data, napi_value &result)
{
    ANS_LOGD("called");
    // bundle: string
    napi_value bundleNapi = nullptr;
    napi_create_string_utf8(env, data.GetBundle().c_str(), NAPI_AUTO_LENGTH, &bundleNapi);
    napi_set_named_property(env, result, "bundle", bundleNapi);

    // uid: uid_t
    napi_value uidNapi = nullptr;
    napi_create_int32(env, data.GetUid(), &uidNapi);
    napi_set_named_property(env, result, "uid", uidNapi);

    // enableStatus: number
    napi_value enableNapi = nullptr;
    napi_create_int32(env, static_cast<int32_t>(data.GetEnableStatus()), &enableNapi);
    napi_set_named_property(env, result, "enableStatus", enableNapi);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetBadgeCallbackData(const napi_env &env, const BadgeNumberCallbackData &data,
    napi_value &result)
{
    ANS_LOGD("called");
    // bundle: string
    napi_value bundleNapi = nullptr;
    napi_create_string_utf8(env, data.GetBundle().c_str(), NAPI_AUTO_LENGTH, &bundleNapi);
    napi_set_named_property(env, result, "bundle", bundleNapi);

    // appInstanceKey: string
    napi_value appKeyNapi = nullptr;
    napi_create_string_utf8(env, data.GetAppInstanceKey().c_str(), NAPI_AUTO_LENGTH, &appKeyNapi);
    napi_set_named_property(env, result, "appInstanceKey", appKeyNapi);

    // uid: int32_t
    napi_value uidNapi = nullptr;
    napi_create_int32(env, data.GetUid(), &uidNapi);
    napi_set_named_property(env, result, "uid", uidNapi);

    // badgeNumber: int32_t
    napi_value badgeNapi = nullptr;
    napi_create_int32(env, data.GetBadgeNumber(), &badgeNapi);
    napi_set_named_property(env, result, "badgeNumber", badgeNapi);

    // instanceKey: int32_t
    napi_value keyNapi = nullptr;
    napi_create_int32(env, data.GetInstanceKey(), &keyNapi);
    napi_set_named_property(env, result, "instanceKey", keyNapi);

    return NapiGetBoolean(env, true);
}

napi_value Common::GetNotificationSubscriberInfo(
    const napi_env &env, const napi_value &value, NotificationSubscribeInfo &subscriberInfo)
{
    ANS_LOGD("called");
    uint32_t length = 0;
    size_t strLen = 0;
    bool hasProperty = false;
    bool isArray = false;
    bool hasSlotTypes = false;
    napi_valuetype valuetype = napi_undefined;

    // bundleNames?: Array<string>
    NAPI_CALL(env, napi_has_named_property(env, value, "bundleNames", &hasProperty));
    if (hasProperty) {
        napi_value nBundleNames = nullptr;
        napi_get_named_property(env, value, "bundleNames", &nBundleNames);
        napi_is_array(env, nBundleNames, &isArray);
        if (!isArray) {
            ANS_LOGE("Property bundleNames is expected to be an array.");
            return nullptr;
        }
        napi_get_array_length(env, nBundleNames, &length);
        if (length == 0) {
            ANS_LOGE("The array is empty.");
            return nullptr;
        }
        for (uint32_t i = 0; i < length; ++i) {
            napi_value nBundleName = nullptr;
            char str[STR_MAX_SIZE] = {0};
            napi_get_element(env, nBundleNames, i, &nBundleName);
            NAPI_CALL(env, napi_typeof(env, nBundleName, &valuetype));
            if (valuetype != napi_string) {
                ANS_LOGE("Wrong argument type. String expected.");
                return nullptr;
            }
            NAPI_CALL(env, napi_get_value_string_utf8(env, nBundleName, str, STR_MAX_SIZE - 1, &strLen));
            subscriberInfo.bundleNames.emplace_back(str);
            subscriberInfo.hasSubscribeInfo = true;
        }
    }

    // userId?: number
    NAPI_CALL(env, napi_has_named_property(env, value, "userId", &hasProperty));
    if (hasProperty) {
        napi_value nUserId = nullptr;
        napi_get_named_property(env, value, "userId", &nUserId);
        NAPI_CALL(env, napi_typeof(env, nUserId, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_int32(env, nUserId, &subscriberInfo.userId));
        subscriberInfo.hasSubscribeInfo = true;
    }

    // deviceType?: number
    NAPI_CALL(env, napi_has_named_property(env, value, "deviceType", &hasProperty));
    if (hasProperty) {
        napi_value nDeviceType = nullptr;
        char str[STR_MAX_SIZE] = {0};
        size_t strLen = 0;
        napi_get_named_property(env, value, "deviceType", &nDeviceType);
        NAPI_CALL(env, napi_typeof(env, nDeviceType, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. String expected.");
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, nDeviceType, str, STR_MAX_SIZE - 1, &strLen));
        if (std::strlen(str) == 0) {
            ANS_LOGE("Property deviceType is empty");
            return nullptr;
        }
        subscriberInfo.deviceType = str;
        subscriberInfo.hasSubscribeInfo = true;
    }

    // filterType?: number
    NAPI_CALL(env, napi_has_named_property(env, value, "filterLimit", &hasProperty));
    if (hasProperty) {
        napi_value nFilterType = nullptr;
        napi_get_named_property(env, value, "filterLimit", &nFilterType);
        NAPI_CALL(env, napi_typeof(env, nFilterType, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_uint32(env, nFilterType, &subscriberInfo.filterType));
        subscriberInfo.hasSubscribeInfo = true;
    }

    NAPI_CALL(env, napi_has_named_property(env, value, "slotTypes", &hasSlotTypes));
    if (hasSlotTypes) {
        napi_value nSlotTypes = nullptr;
        napi_get_named_property(env, value, "slotTypes", &nSlotTypes);
        napi_is_array(env, nSlotTypes, &isArray);
        if (!isArray) {
            ANS_LOGE("Property slotTypes is expected to be an array.");
            std::string msg = "Incorrect parameter types.The type of slotTypes must be array.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_array_length(env, nSlotTypes, &length);
        if (length == 0) {
            ANS_LOGE("The array is empty.");
            std::string msg = "Incorrect parameters are left unspecified. The slotTypes list length is zero.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }

        for (uint32_t i = 0; i < length; ++i) {
            napi_value nSlotType = nullptr;
            int32_t slotType = 0;
            napi_get_element(env, nSlotTypes, i, &nSlotType);
            NAPI_CALL(env, napi_typeof(env, nSlotType, &valuetype));
            if (valuetype != napi_number) {
                ANS_LOGE("Wrong argument type. Number expected.");
                std::string msg = "Incorrect parameter types.The type of slotType must be number.";
                Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
                return nullptr;
            }
            napi_get_value_int32(env, nSlotType, &slotType);
            NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
            if (!AnsEnumUtil::SlotTypeJSToC(SlotType(slotType), outType)) {
                std::string msg = "Incorrect parameter types.slotType name must be in enum.";
                Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
                return nullptr;
            }
            subscriberInfo.slotTypes.emplace_back(outType);
            subscriberInfo.hasSubscribeInfo = true;
        }
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationUserInput(
    const napi_env &env, const napi_value &actionButton, std::shared_ptr<NotificationActionButton> &pActionButton)
{
    ANS_LOGD("called");
    napi_valuetype valuetype = napi_undefined;
    napi_value userInputResult = nullptr;
    bool hasProperty = false;

    // userInput?: NotificationUserInput
    NAPI_CALL(env, napi_has_named_property(env, actionButton, "userInput", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, actionButton, "userInput", &userInputResult);
        NAPI_CALL(env, napi_typeof(env, userInputResult, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            return nullptr;
        }
        std::shared_ptr<NotificationUserInput> userInput = nullptr;

        if (!GetNotificationUserInputByInputKey(env, userInputResult, userInput)) {
            return nullptr;
        }
        pActionButton->AddNotificationUserInput(userInput);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationUserInputByInputKey(
    const napi_env &env, const napi_value &userInputResult, std::shared_ptr<NotificationUserInput> &userInput)
{
    ANS_LOGD("called");
    napi_valuetype valuetype = napi_undefined;
    napi_value value = nullptr;
    bool hasProperty = false;
    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;

    // inputKey: string
    NAPI_CALL(env, napi_has_named_property(env, userInputResult, "inputKey", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property inputKey expected.");
        return nullptr;
    }
    napi_get_named_property(env, userInputResult, "inputKey", &value);
    NAPI_CALL(env, napi_typeof(env, value, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, value, str, STR_MAX_SIZE - 1, &strLen));
    ANS_LOGD("NotificationUserInput::inputKey = %{public}s", str);
    userInput = NotificationUserInput::Create(str);
    if (!userInput) {
        ANS_LOGE("Failed to create NotificationUserInput by inputKey=%{public}s", str);
        return nullptr;
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationUserInputByTag(
    const napi_env &env, const napi_value &userInputResult, std::shared_ptr<NotificationUserInput> &userInput)
{
    ANS_LOGD("called");

    napi_valuetype valuetype = napi_undefined;
    napi_value value = nullptr;
    bool hasProperty = false;
    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;

    if (!userInput) {
        return nullptr;
    }
    // tag: string
    NAPI_CALL(env, napi_has_named_property(env, userInputResult, "tag", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property tag expected.");
        return nullptr;
    }
    napi_get_named_property(env, userInputResult, "tag", &value);
    NAPI_CALL(env, napi_typeof(env, value, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, value, str, STR_MAX_SIZE - 1, &strLen));
    userInput->SetTag(str);
    ANS_LOGD("NotificationUserInput::tag = %{public}s", str);

    return NapiGetNull(env);
}

napi_value Common::GetNotificationUserInputByOptions(
    const napi_env &env, const napi_value &userInputResult, std::shared_ptr<NotificationUserInput> &userInput)
{
    ANS_LOGD("called");

    napi_valuetype valuetype = napi_undefined;
    napi_value value = nullptr;
    bool hasProperty = false;
    uint32_t length = 0;
    size_t strLen = 0;
    bool isArray = false;

    if (!userInput) {
        return nullptr;
    }

    // options: Array<string>
    NAPI_CALL(env, napi_has_named_property(env, userInputResult, "options", &hasProperty));

    if (!hasProperty) {
        ANS_LOGE("Property options expected.");
        return nullptr;
    }
    napi_get_named_property(env, userInputResult, "options", &value);
    napi_is_array(env, value, &isArray);
    if (!isArray) {
        ANS_LOGE("Property options is expected to be an array.");
        return nullptr;
    }
    napi_get_array_length(env, value, &length);
    if (length == 0) {
        ANS_LOGE("The array is empty.");
        return nullptr;
    }
    std::vector<std::string> options;
    for (uint32_t i = 0; i < length; ++i) {
        napi_value option = nullptr;
        char str[STR_MAX_SIZE] = {0};
        napi_get_element(env, value, i, &option);
        NAPI_CALL(env, napi_typeof(env, option, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. String expected.");
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, option, str, STR_MAX_SIZE - 1, &strLen));
        options.emplace_back(str);
    }
    userInput->SetOptions(options);

    return NapiGetNull(env);
}

napi_value Common::GetNotificationUserInputByPermitMimeTypes(
    const napi_env &env, const napi_value &userInputResult, std::shared_ptr<NotificationUserInput> &userInput)
{
    ANS_LOGD("called");

    napi_valuetype valuetype = napi_undefined;
    napi_value value = nullptr;
    bool hasProperty = false;
    size_t strLen = 0;
    uint32_t length = 0;
    bool isArray = false;

    if (!userInput) {
        return nullptr;
    }

    // permitMimeTypes?: Array<string>
    NAPI_CALL(env, napi_has_named_property(env, userInputResult, "permitMimeTypes", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, userInputResult, "permitMimeTypes", &value);
        napi_is_array(env, value, &isArray);
        if (!isArray) {
            ANS_LOGE("Property permitMimeTypes is expected to be an array.");
            return nullptr;
        }
        napi_get_array_length(env, value, &length);
        if (length == 0) {
            ANS_LOGE("The array is empty.");
            return nullptr;
        }
        for (uint32_t i = 0; i < length; ++i) {
            napi_value permitMimeType = nullptr;
            char str[STR_MAX_SIZE] = {0};
            napi_get_element(env, value, i, &permitMimeType);
            NAPI_CALL(env, napi_typeof(env, permitMimeType, &valuetype));
            if (valuetype != napi_string) {
                ANS_LOGE("Wrong argument type. String expected.");
                return nullptr;
            }
            NAPI_CALL(env, napi_get_value_string_utf8(env, permitMimeType, str, STR_MAX_SIZE - 1, &strLen));
            userInput->SetPermitMimeTypes(str, true);
        }
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationUserInputByPermitFreeFormInput(
    const napi_env &env, const napi_value &userInputResult, std::shared_ptr<NotificationUserInput> &userInput)
{
    ANS_LOGD("called");
    napi_value value = nullptr;
    napi_valuetype valuetype = napi_undefined;
    bool hasProperty = false;

    if (!userInput) {
        return nullptr;
    }

    // permitFreeFormInput?: boolean
    NAPI_CALL(env, napi_has_named_property(env, userInputResult, "permitFreeFormInput", &hasProperty));
    if (hasProperty) {
        bool permitFreeFormInput = false;
        napi_get_named_property(env, userInputResult, "permitFreeFormInput", &value);
        NAPI_CALL(env, napi_typeof(env, value, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            return nullptr;
        }
        napi_get_value_bool(env, value, &permitFreeFormInput);
        ANS_LOGD("permitFreeFormInput is: %{public}d", permitFreeFormInput);
        userInput->SetPermitFreeFormInput(permitFreeFormInput);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationUserInputByEditType(
    const napi_env &env, const napi_value &userInputResult, std::shared_ptr<NotificationUserInput> &userInput)
{
    ANS_LOGD("called");
    napi_value value = nullptr;
    napi_valuetype valuetype = napi_undefined;
    bool hasProperty = false;
    int32_t editType = 0;

    if (!userInput) {
        return nullptr;
    }

    // editType?: number
    NAPI_CALL(env, napi_has_named_property(env, userInputResult, "editType", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, userInputResult, "editType", &value);
        NAPI_CALL(env, napi_typeof(env, value, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of editType must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int32(env, value, &editType);
        userInput->SetEditType(NotificationConstant::InputEditType(editType));
    }
    return NapiGetNull(env);
}

napi_value Common::GetNotificationUserInputByAdditionalData(
    const napi_env &env, const napi_value &userInputResult, std::shared_ptr<NotificationUserInput> &userInput)
{
    ANS_LOGD("called");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;

    if (!userInput) {
        return nullptr;
    }

    // additionalData?: {[key: string]: Object}
    NAPI_CALL(env, napi_has_named_property(env, userInputResult, "additionalData", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, userInputResult, "additionalData", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types. The type of additionalData must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        AAFwk::WantParams wantParams;
        if (!OHOS::AppExecFwk::UnwrapWantParams(env, result, wantParams)) {
            return nullptr;
        }
        userInput->AddAdditionalData(wantParams);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationContentType(const napi_env &env, const napi_value &result, int32_t &type)
{
    ANS_LOGD("called");

    napi_value contentResult = nullptr;
    napi_valuetype valuetype = napi_undefined;
    bool hasNotificationContentType = false;
    bool hasContentType = false;

    NAPI_CALL(env, napi_has_named_property(env, result, "notificationContentType", &hasNotificationContentType));
    if (hasNotificationContentType) {
        napi_get_named_property(env, result, "notificationContentType", &contentResult);
        NAPI_CALL(env, napi_typeof(env, contentResult, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of notificationContentType must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int32(env, contentResult, &type);

        return NapiGetNull(env);
    } else {
        ANS_LOGE("Property notificationContentType expected.");
    }

    NAPI_CALL(env, napi_has_named_property(env, result, "contentType", &hasContentType));
    if (hasContentType) {
        napi_get_named_property(env, result, "contentType", &contentResult);
        NAPI_CALL(env, napi_typeof(env, contentResult, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of contentType must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int32(env, contentResult, &type);

        return NapiGetNull(env);
    } else {
        ANS_LOGE("Property contentType expected.");
        return nullptr;
    }
}

napi_value Common::GetNotificationSlot(const napi_env &env, const napi_value &value, NotificationSlot &slot)
{
    ANS_LOGD("called");

    napi_value nobj = nullptr;
    napi_valuetype valuetype = napi_undefined;
    bool hasType = false;
    bool hasNotificationType = false;
    int slotType = 0;

    NAPI_CALL(env, napi_has_named_property(env, value, "notificationType", &hasNotificationType));
    NAPI_CALL(env, napi_has_named_property(env, value, "type", &hasType));
    if (hasNotificationType) {
        napi_get_named_property(env, value, "notificationType", &nobj);
        NAPI_CALL(env, napi_typeof(env, nobj, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of notificationType must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
    } else if (!hasNotificationType && hasType) {
        napi_get_named_property(env, value, "type", &nobj);
        NAPI_CALL(env, napi_typeof(env, nobj, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of type must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
    } else {
        ANS_LOGE("Property notificationType or type expected.");
        return nullptr;
    }

    if (nobj != nullptr) {
        napi_get_value_int32(env, nobj, &slotType);
    }

    NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
    if (!AnsEnumUtil::SlotTypeJSToC(SlotType(slotType), outType)) {
        return nullptr;
    }
    slot.SetType(outType);

    if (GetNotificationSlotByString(env, value, slot) == nullptr) {
        return nullptr;
    }
    if (GetNotificationSlotByNumber(env, value, slot) == nullptr) {
        return nullptr;
    }
    if (GetNotificationSlotByVibration(env, value, slot) == nullptr) {
        return nullptr;
    }
    if (GetNotificationSlotByBool(env, value, slot) == nullptr) {
        return nullptr;
    }
    return NapiGetNull(env);
}

napi_value Common::GetNotificationSlotByString(const napi_env &env, const napi_value &value, NotificationSlot &slot)
{
    ANS_LOGD("called");

    napi_value nobj = nullptr;
    napi_valuetype valuetype = napi_undefined;
    bool hasProperty = false;
    size_t strLen = 0;

    // desc?: string
    NAPI_CALL(env, napi_has_named_property(env, value, "desc", &hasProperty));
    if (hasProperty) {
        std::string desc;
        char str[STR_MAX_SIZE] = {0};
        napi_get_named_property(env, value, "desc", &nobj);
        NAPI_CALL(env, napi_typeof(env, nobj, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. String expected.");
            std::string msg = "Incorrect parameter types. The type of desc must be string.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, nobj, str, STR_MAX_SIZE - 1, &strLen));
        desc = str;
        ANS_LOGD("desc is: %{public}s", desc.c_str());
        slot.SetDescription(desc);
    }

    // sound?: string
    NAPI_CALL(env, napi_has_named_property(env, value, "sound", &hasProperty));
    if (hasProperty) {
        std::string sound;
        char str[STR_MAX_SIZE] = {0};
        napi_get_named_property(env, value, "sound", &nobj);
        NAPI_CALL(env, napi_typeof(env, nobj, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. String expected.");
            std::string msg = "Incorrect parameter types. The type of sound must be string.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, nobj, str, STR_MAX_SIZE - 1, &strLen));
        sound = str;
        ANS_LOGD("sound is: %{public}s", sound.c_str());
        slot.SetSound(Uri(sound));
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationSlotByBool(const napi_env &env, const napi_value &value, NotificationSlot &slot)
{
    ANS_LOGD("called");
    napi_value nobj = nullptr;
    napi_valuetype valuetype = napi_undefined;
    bool hasProperty = false;

    // badgeFlag?: boolean
    NAPI_CALL(env, napi_has_named_property(env, value, "badgeFlag", &hasProperty));
    if (hasProperty) {
        bool badgeFlag = false;
        napi_get_named_property(env, value, "badgeFlag", &nobj);
        NAPI_CALL(env, napi_typeof(env, nobj, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types. The type of badgeFlag must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, nobj, &badgeFlag);
        ANS_LOGD("badgeFlag is: %{public}d", badgeFlag);
        slot.EnableBadge(badgeFlag);
    }

    // bypassDnd?: boolean
    NAPI_CALL(env, napi_has_named_property(env, value, "bypassDnd", &hasProperty));
    if (hasProperty) {
        bool bypassDnd = false;
        napi_get_named_property(env, value, "bypassDnd", &nobj);
        NAPI_CALL(env, napi_typeof(env, nobj, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types. The type of bypassDnd must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, nobj, &bypassDnd);
        ANS_LOGD("bypassDnd is: %{public}d", bypassDnd);
        slot.EnableBypassDnd(bypassDnd);
    }

    // lightEnabled?: boolean
    NAPI_CALL(env, napi_has_named_property(env, value, "lightEnabled", &hasProperty));
    if (hasProperty) {
        bool lightEnabled = false;
        napi_get_named_property(env, value, "lightEnabled", &nobj);
        NAPI_CALL(env, napi_typeof(env, nobj, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types. The type of lightEnabled must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, nobj, &lightEnabled);
        ANS_LOGD("lightEnabled is: %{public}d", lightEnabled);
        slot.SetEnableLight(lightEnabled);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationSlotByNumber(const napi_env &env, const napi_value &value, NotificationSlot &slot)
{
    ANS_LOGD("called");

    napi_value nobj = nullptr;
    napi_valuetype valuetype = napi_undefined;
    bool hasProperty = false;

    // level?: number
    NAPI_CALL(env, napi_has_named_property(env, value, "level", &hasProperty));
    if (hasProperty) {
        int inLevel = 0;
        napi_get_named_property(env, value, "level", &nobj);
        NAPI_CALL(env, napi_typeof(env, nobj, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of level must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int32(env, nobj, &inLevel);
        ANS_LOGD("level is: %{public}d", inLevel);

        NotificationSlot::NotificationLevel outLevel {NotificationSlot::NotificationLevel::LEVEL_NONE};
        if (!AnsEnumUtil::SlotLevelJSToC(SlotLevel(inLevel), outLevel)) {
            return nullptr;
        }
        slot.SetLevel(outLevel);
    }

    // lockscreenVisibility?: number
    NAPI_CALL(env, napi_has_named_property(env, value, "lockscreenVisibility", &hasProperty));
    if (hasProperty) {
        int lockscreenVisibility = 0;
        napi_get_named_property(env, value, "lockscreenVisibility", &nobj);
        NAPI_CALL(env, napi_typeof(env, nobj, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of lockscreenVisibility must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int32(env, nobj, &lockscreenVisibility);
        ANS_LOGD("lockscreenVisibility is: %{public}d", lockscreenVisibility);
        slot.SetLockscreenVisibleness(NotificationConstant::VisiblenessType(lockscreenVisibility));
    }

    // lightColor?: number
    NAPI_CALL(env, napi_has_named_property(env, value, "lightColor", &hasProperty));
    if (hasProperty) {
        int lightColor = 0;
        napi_get_named_property(env, value, "lightColor", &nobj);
        NAPI_CALL(env, napi_typeof(env, nobj, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            std::string msg = "Incorrect parameter types. The type of lightColor must be number.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_int32(env, nobj, &lightColor);
        ANS_LOGD("lightColor is: %{public}d", lightColor);
        slot.SetLedLightColor(lightColor);
    }
    return NapiGetNull(env);
}

napi_value Common::GetNotificationSlotByVibration(const napi_env &env, const napi_value &value, NotificationSlot &slot)
{
    ANS_LOGD("called");
    napi_value nobj = nullptr;
    napi_valuetype valuetype = napi_undefined;
    bool hasProperty = false;
    uint32_t length = 0;

    // vibrationEnabled?: boolean
    bool vibrationEnabled = false;
    NAPI_CALL(env, napi_has_named_property(env, value, "vibrationEnabled", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "vibrationEnabled", &nobj);
        NAPI_CALL(env, napi_typeof(env, nobj, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types. The type of vibrationEnabled must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }

        napi_get_value_bool(env, nobj, &vibrationEnabled);
        slot.SetEnableVibration(vibrationEnabled);
    }

    if (!vibrationEnabled) {
        return NapiGetNull(env);
    }

    // vibrationValues?: Array<number>
    NAPI_CALL(env, napi_has_named_property(env, value, "vibrationValues", &hasProperty));
    if (hasProperty) {
        bool isArray = false;
        napi_get_named_property(env, value, "vibrationValues", &nobj);
        napi_is_array(env, nobj, &isArray);
        if (!isArray) {
            ANS_LOGE("Property vibrationValues is expected to be an array.");
            return nullptr;
        }

        napi_get_array_length(env, nobj, &length);
        std::vector<int64_t> vibrationValues;
        for (size_t i = 0; i < length; i++) {
            napi_value nVibrationValue = nullptr;
            int64_t vibrationValue = 0;
            napi_get_element(env, nobj, i, &nVibrationValue);
            NAPI_CALL(env, napi_typeof(env, nVibrationValue, &valuetype));
            if (valuetype != napi_number) {
                ANS_LOGE("Wrong argument type. Number expected.");
                return nullptr;
            }
            napi_get_value_int64(env, nVibrationValue, &vibrationValue);
            vibrationValues.emplace_back(vibrationValue);
        }
        slot.SetVibrationStyle(vibrationValues);
    }

    return NapiGetNull(env);
}

napi_value Common::GetBundleOption(const napi_env &env, const napi_value &value, NotificationBundleOption &option)
{
    ANS_LOGD("called");

    bool hasProperty {false};
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;

    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    // bundle: string
    NAPI_CALL(env, napi_has_named_property(env, value, "bundle", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property bundle expected.");
        return nullptr;
    }
    napi_get_named_property(env, value, "bundle", &result);
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        std::string msg = "Incorrect parameter types. The type of bundle must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
    option.SetBundleName(str);

    // uid?: number
    NAPI_CALL(env, napi_has_named_property(env, value, "uid", &hasProperty));
    if (hasProperty) {
        int32_t uid = 0;
        napi_get_named_property(env, value, "uid", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            return nullptr;
        }
        napi_get_value_int32(env, result, &uid);
        option.SetUid(uid);
    }

    return NapiGetNull(env);
}

napi_value Common::GetReminderInfo(const napi_env &env, const napi_value &value, NotificationReminderInfo &info)
{
    ANS_LOGD("GetReminderInfo");
    bool hasProperty {false};
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    NotificationBundleOption option;

    NAPI_CALL(env, napi_has_named_property(env, value, "bundle", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property bundle expected.");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_named_property(env, value, "bundle", &result));
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_object) {
        std::string msg = "Incorrect parameter types. The type of bundle must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    if (!GetBundleOption(env, result, option)) {
        return nullptr;
    }
    info.SetBundleOption(option);

    NAPI_CALL(env, napi_has_named_property(env, value, "reminderFlags", &hasProperty));
    if (hasProperty) {
        int32_t reminderFlags = 0;
        NAPI_CALL(env, napi_get_named_property(env, value, "reminderFlags", &result));
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            std::string msg = "Wrong argument type. Number expected.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_int32(env, result, &reminderFlags));
        info.SetReminderFlags(reminderFlags);
    }

    NAPI_CALL(env, napi_has_named_property(env, value, "silentReminderEnabled", &hasProperty));
    if (hasProperty) {
        bool silentReminderEnabled = false;
        NAPI_CALL(env, napi_get_named_property(env, value, "silentReminderEnabled", &result));
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            std::string msg = "Wrong argument type. Boolean expected.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_bool(env, result, &silentReminderEnabled));
        info.SetSilentReminderEnabled(silentReminderEnabled);
    }
    return NapiGetNull(env);
}

napi_value Common::GetButtonOption(const napi_env &env, const napi_value &value, NotificationButtonOption &option)
{
    ANS_LOGD("called");

    bool hasProperty {false};
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;

    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    // buttonName: string
    NAPI_CALL(env, napi_has_named_property(env, value, "buttonName", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property buttonName expected.");
        return nullptr;
    }
    napi_get_named_property(env, value, "buttonName", &result);
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        std::string msg = "Incorrect parameter types. The type of buttonName must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
    option.SetButtonName(str);

    return NapiGetNull(env);
}

napi_value Common::GetBundleOption(
    const napi_env &env,
    const napi_value &value,
    std::shared_ptr<NotificationBundleOption> &option)
{
    ANS_LOGD("called");

    bool hasProperty {false};
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;

    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    // bundle: string
    NAPI_CALL(env, napi_has_named_property(env, value, "bundle", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property bundle expected.");
        return nullptr;
    }
    napi_get_named_property(env, value, "bundle", &result);
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        std::string msg = "Incorrect parameter types. The type of bundle must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
    option->SetBundleName(str);

    // uid?: number
    NAPI_CALL(env, napi_has_named_property(env, value, "uid", &hasProperty));
    if (hasProperty) {
        int32_t uid = 0;
        napi_get_named_property(env, value, "uid", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGE("Wrong argument type. Number expected.");
            return nullptr;
        }
        napi_get_value_int32(env, result, &uid);
        option->SetUid(uid);
    }

    return NapiGetNull(env);
}

napi_value Common::GetDistributedBundleOption(
    const napi_env &env,
    const napi_value &value,
    DistributedBundleOption &option)
{
    ANS_LOGD("called");

    bool hasProperty {false};
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;

    // bundle: NotificationBundleOption
    std::shared_ptr<NotificationBundleOption> bundleOption = std::make_shared<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is null");
        return nullptr;
    }
    
    // bundleName
    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    napi_get_named_property(env, value, "bundleName", &result);
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. string expected.");
        std::string msg = "Incorrect parameter bundleName. The type of bundleName must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
    bundleOption->SetBundleName(str);

    // uid
    int32_t uid = 0;
    napi_get_named_property(env, value, "uid", &result);
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Wrong argument type. number expected.");
        std::string msg = "Incorrect parameter uid. The type of uid must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_value_int32(env, result, &uid);
    bundleOption->SetUid(uid);

    option.SetBundle(bundleOption);

    // enable?: bool
    NAPI_CALL(env, napi_has_named_property(env, value, "enable", &hasProperty));
    if (hasProperty) {
        bool enable = false;
        napi_get_named_property(env, value, "enable", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. boolean expected.");
            return nullptr;
        }
        napi_get_value_bool(env, result, &enable);
        option.SetEnable(enable);
    }

    return NapiGetNull(env);
}

napi_value Common::GetHashCodes(const napi_env &env, const napi_value &value, std::vector<std::string> &hashCodes)
{
    ANS_LOGD("called");
    uint32_t length = 0;
    napi_get_array_length(env, value, &length);
    if (length == 0) {
        ANS_LOGE("The array is empty.");
        return nullptr;
    }
    napi_valuetype valuetype = napi_undefined;
    for (size_t i = 0; i < length; i++) {
        napi_value hashCode = nullptr;
        napi_get_element(env, value, i, &hashCode);
        NAPI_CALL(env, napi_typeof(env, hashCode, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. Object expected.");
            return nullptr;
        }
        char str[STR_MAX_SIZE] = {0};
        size_t strLen = 0;
        NAPI_CALL(env, napi_get_value_string_utf8(env, hashCode, str, STR_MAX_SIZE - 1, &strLen));
        hashCodes.emplace_back(str);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationKey(const napi_env &env, const napi_value &value, NotificationKey &key)
{
    ANS_LOGD("called");

    bool hasProperty {false};
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;

    // id: number
    NAPI_CALL(env, napi_has_named_property(env, value, "id", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property id expected.");
        return nullptr;
    }
    napi_get_named_property(env, value, "id", &result);
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Wrong argument type. Number expected.");
        std::string msg = "Incorrect parameter types. The type of id must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_value_int32(env, result, &key.id);

    // label?: string
    NAPI_CALL(env, napi_has_named_property(env, value, "label", &hasProperty));
    if (hasProperty) {
        char str[STR_MAX_SIZE] = {0};
        size_t strLen = 0;
        napi_get_named_property(env, value, "label", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. String expected.");
            std::string msg = "Incorrect parameter types. The type of label must be string.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
        key.label = str;
    }

    return NapiGetNull(env);
}

bool Common::IsValidRemoveReason(int32_t reasonType)
{
    if (reasonType == NotificationConstant::CLICK_REASON_DELETE ||
        reasonType == NotificationConstant::CANCEL_REASON_DELETE) {
        return true;
    }
    ANS_LOGE("Reason %{public}d is an invalid value", reasonType);
    return false;
}

__attribute__((no_sanitize("cfi"))) napi_value Common::CreateWantAgentByJS(const napi_env &env,
    const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> &agent)
{
    if (agent == nullptr) {
        ANS_LOGE("agent is nullptr");
        return nullptr;
    }

    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        wantAgent_.insert(agent);
    }
    napi_finalize finalize = [](napi_env env, void *data, void *hint) {
        AbilityRuntime::WantAgent::WantAgent *objectInfo =
                static_cast<AbilityRuntime::WantAgent::WantAgent *>(data);
            if (objectInfo) {
                std::lock_guard<ffrt::mutex> lock(mutex_);
                for (auto it = wantAgent_.begin(); it != wantAgent_.end(); ++it) {
                    if ((*it).get() == objectInfo) {
                        wantAgent_.erase(it);
                        break;
                    }
                }
            }
    };
    return AppExecFwk::WrapWantAgent(env, agent.get(), finalize);
}

napi_value Common::GetNotificationTemplate(const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("called");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "template", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "template", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types. The type of template must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }

        std::shared_ptr<NotificationTemplate> templ = std::make_shared<NotificationTemplate>();
        if (templ == nullptr) {
            ANS_LOGE("template is null");
            return nullptr;
        }
        if (GetNotificationTemplateInfo(env, result, templ) == nullptr) {
            return nullptr;
        }

        request.SetTemplate(templ);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationBundleOption(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("Called.");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "representativeBundle", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "representativeBundle", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types. The type of representativeBundle must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }

        std::shared_ptr<NotificationBundleOption> bundleOption = std::make_shared<NotificationBundleOption>();
        if (bundleOption == nullptr) {
            ANS_LOGE("The bundleOption is null.");
            return nullptr;
        }
        if (GetBundleOption(env, result, *bundleOption) == nullptr) {
            return nullptr;
        }

        request.SetBundleOption(bundleOption);
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationTemplateInfo(const napi_env &env, const napi_value &value,
    std::shared_ptr<NotificationTemplate> &templ)
{
    ANS_LOGD("called");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;

    // name: string
    NAPI_CALL(env, napi_has_named_property(env, value, "name", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property name expected.");
        return nullptr;
    }
    napi_get_named_property(env, value, "name", &result);
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        std::string msg = "Incorrect parameter types. The type of name must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
    std::string strInput = str;
    templ->SetTemplateName(strInput);

    // data?: {[key: string]: object}
    NAPI_CALL(env, napi_has_named_property(env, value, "data", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "data", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types. The type of data must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        AAFwk::WantParams wantParams;
        if (!OHOS::AppExecFwk::UnwrapWantParams(env, result, wantParams)) {
            return nullptr;
        }

        std::shared_ptr<AAFwk::WantParams> data = std::make_shared<AAFwk::WantParams>(wantParams);
        templ->SetTemplateData(data);
    }

    return NapiGetNull(env);
}

napi_value Common::SetNotificationTemplateInfo(
    const napi_env &env, const std::shared_ptr<NotificationTemplate> &templ, napi_value &result)
{
    ANS_LOGD("called");

    if (templ == nullptr) {
        ANS_LOGE("templ is null");
        return NapiGetBoolean(env, false);
    }

    napi_value value = nullptr;

    // name: string;
    napi_create_string_utf8(env, templ->GetTemplateName().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "name", value);

    std::shared_ptr<AAFwk::WantParams> data = templ->GetTemplateData();
    if (data) {
        value = OHOS::AppExecFwk::WrapWantParams(env, *data);
        napi_set_named_property(env, result, "data", value);
    }

    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotificationEnableStatus(
    const napi_env &env, const NotificationBundleOption &bundleOption, napi_value &result)
{
    ANS_LOGD("Called.");

    // bundle: string
    napi_value bundleNapi = nullptr;
    napi_create_string_utf8(env, bundleOption.GetBundleName().c_str(), NAPI_AUTO_LENGTH, &bundleNapi);
    napi_set_named_property(env, result, "bundle", bundleNapi);

    // uid: uid_t
    napi_value uidNapi = nullptr;
    napi_create_int32(env, bundleOption.GetUid(), &uidNapi);
    napi_set_named_property(env, result, "uid", uidNapi);

    return result;
}

napi_value Common::SetNotificationFlags(
    const napi_env &env, const std::shared_ptr<NotificationFlags> &flags, napi_value &result)
{
    ANS_LOGD("called");

    if (flags == nullptr) {
        ANS_LOGE("flags is null");
        return NapiGetBoolean(env, false);
    }

    napi_value value = nullptr;

    int32_t soundEnabled = static_cast<int32_t>(flags->IsSoundEnabled());
    napi_create_int32(env, soundEnabled, &value);
    napi_set_named_property(env, result, "soundEnabled", value);

    int32_t vibrationEnabled = static_cast<int32_t>(flags->IsVibrationEnabled());
    napi_create_int32(env, vibrationEnabled, &value);
    napi_set_named_property(env, result, "vibrationEnabled", value);

    uint32_t reminderFlags = flags->GetReminderFlags();
    napi_create_uint32(env, reminderFlags, &value);
    napi_set_named_property(env, result, "reminderFlags", value);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetAgentBundle(
    const napi_env &env, const std::shared_ptr<NotificationBundleOption> &agentBundle, napi_value &result)
{
    ANS_LOGD("called");

    if (agentBundle == nullptr) {
        ANS_LOGE("agentBundle is null");
        return NapiGetBoolean(env, false);
    }

    // bundle: string
    napi_value bundleNapi = nullptr;
    napi_create_string_utf8(env, agentBundle->GetBundleName().c_str(), NAPI_AUTO_LENGTH, &bundleNapi);
    napi_set_named_property(env, result, "bundle", bundleNapi);

    // uid: uid_t
    napi_value uidNapi = nullptr;
    napi_create_int32(env, agentBundle->GetUid(), &uidNapi);
    napi_set_named_property(env, result, "uid", uidNapi);

    return result;
}

napi_value Common::SetNotificationUnifiedGroupInfo(
    const napi_env &env, const std::shared_ptr<NotificationUnifiedGroupInfo> &info, napi_value &result)
{
    ANS_LOGD("called");

    if (info == nullptr) {
        ANS_LOGE("info is null");
        return NapiGetBoolean(env, false);
    }

    napi_value value = nullptr;

    // title?: string
    napi_create_string_utf8(env, info->GetTitle().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "title", value);

    // key?: string
    napi_create_string_utf8(env, info->GetKey().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "key", value);

    // content?: string
    napi_create_string_utf8(env, info->GetContent().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "content", value);

    // sceneName?: string
    napi_create_string_utf8(env, info->GetSceneName().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "sceneName", value);

    // extraInfo?: {[key:string] : any}
    std::shared_ptr<AAFwk::WantParams> extraInfoData = info->GetExtraInfo();
    if (extraInfoData) {
        napi_value extraInfo = nullptr;
        extraInfo = OHOS::AppExecFwk::WrapWantParams(env, *extraInfoData);
        napi_set_named_property(env, result, "extraInfo", extraInfo);
    }

    return NapiGetBoolean(env, true);
}

napi_value Common::SetBundleOption(const napi_env &env, const NotificationBundleOption &bundleInfo,
    napi_value &result)
{
    napi_value value = nullptr;
    // bundle: string
    napi_create_string_utf8(env, bundleInfo.GetBundleName().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "bundle", value);

    // uid: uid_t
    napi_create_int32(env, bundleInfo.GetUid(), &value);
    napi_set_named_property(env, result, "uid", value);
    return NapiGetBoolean(env, true);
}

napi_value Common::SetGrantedBundleInfo(const napi_env &env, const NotificationBundleOption &bundleInfo,
    napi_value &result)
{
    napi_value value = nullptr;

    napi_create_string_utf8(env, bundleInfo.GetBundleName().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "bundleName", value);

    napi_create_string_utf8(env, bundleInfo.GetAppName().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "appName", value);

    napi_create_int32(env, bundleInfo.GetAppIndex(), &value);
    napi_set_named_property(env, result, "appIndex", value);
    return NapiGetBoolean(env, true);
}

napi_value Common::SetDoNotDisturbProfile(const napi_env &env, const NotificationDoNotDisturbProfile &data,
    napi_value &result)
{
    ANS_LOGD("called");
    napi_value value = nullptr;
    // id: number
    napi_create_int64(env, data.GetProfileId(), &value);
    napi_set_named_property(env, result, "id", value);

    // name: string
    napi_create_string_utf8(env, data.GetProfileName().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "name", value);

    size_t count = 0;
    napi_create_array(env, &value);
    // trustList?: std::vector<NotificationBundleOption>
    for (auto bundleInfo : data.GetProfileTrustList()) {
        napi_value bundleValue = nullptr;
        napi_create_object(env, &bundleValue);
        if (!Common::SetBundleOption(env, bundleInfo, bundleValue)) {
            continue;
        }
        napi_set_element(env, value, count, bundleValue);
        count++;
    }
    if (count > 0) {
        napi_set_named_property(env, result, "trustlist", value);
    }
    return NapiGetBoolean(env, true);
}

std::string Common::GetAppInstanceKey()
{
    std::shared_ptr<OHOS::AbilityRuntime::ApplicationContext>context =
        OHOS::AbilityRuntime::Context::GetApplicationContext();
    if (context != nullptr) {
        return context->GetCurrentInstanceKey();
    } else {
        ANS_LOGE("GetApplicationContext for instacekey fail.");
        return "";
    }
}

napi_value Common::GetRingtoneInfo(
    const napi_env &env, const napi_value &value, NotificationRingtoneInfo &ringtoneInfo)
{
    ANS_LOGD("called");
    bool hasProperty {false};
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;

    // ringtoneType?: number
    int32_t ringtoneType = 0;
    NAPI_CALL(env, napi_has_named_property(env, value, "ringtoneType", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Property ringtoneType expected.");
        return nullptr;
    }
    napi_get_named_property(env, value, "ringtoneType", &result);
    NAPI_CALL(env, napi_typeof(env, result, &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Wrong argument type. Number expected.");
        std::string msg = "Incorrect parameter types. The type of ringtoneType must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_value_int32(env, result, &ringtoneType);
    ringtoneInfo.SetRingtoneType(static_cast<NotificationConstant::RingtoneType>(ringtoneType));

    return GetRingtoneStringInfo(env, value, ringtoneInfo);
}

napi_value Common::GetRingtoneStringInfo(
    const napi_env &env, const napi_value &value, NotificationRingtoneInfo &ringtoneInfo)
{
    bool hasProperty {false};
    napi_value result = nullptr;
    napi_valuetype valuetype = napi_undefined;
    char ringtoneTitle[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    NAPI_CALL(env, napi_has_named_property(env, value, "ringtoneTitle", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "ringtoneTitle", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. String expected.");
            std::string msg = "Incorrect parameter types. The type of ringtoneTitle must be string.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, ringtoneTitle, STR_MAX_SIZE - 1, &strLen));
        ringtoneInfo.SetRingtoneTitle(ringtoneTitle);
    }
    char ringtoneFileName[STR_MAX_SIZE] = {0};
    strLen = 0;
    NAPI_CALL(env, napi_has_named_property(env, value, "ringtoneFileName", &hasProperty));
    if (hasProperty) {
        NAPI_CALL(env, napi_get_named_property(env, value, "ringtoneFileName", &result));
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. String expected.");
            std::string msg = "Incorrect parameter types. The type of ringtoneFileName must be string.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, ringtoneFileName, STR_MAX_SIZE - 1, &strLen));
        ringtoneInfo.SetRingtoneFileName(ringtoneFileName);
    }
    char ringtoneUri[STR_MAX_SIZE] = {0};
    strLen = 0;
    NAPI_CALL(env, napi_has_named_property(env, value, "ringtoneUri", &hasProperty));
    if (hasProperty) {
        NAPI_CALL(env, napi_get_named_property(env, value, "ringtoneUri", &result));
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            std::string msg = "Incorrect parameter types. The type of ringtoneUri must be string.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, ringtoneUri, STR_MAX_SIZE - 1, &strLen));
        ringtoneInfo.SetRingtoneUri(ringtoneUri);
    }
    return NapiGetNull(env);
}

napi_value Common::SetRingtoneInfo(const napi_env &env, const NotificationRingtoneInfo &ringtoneInfo,
    napi_value &result)
{
    ANS_LOGD("called");

    napi_value value = nullptr;
    // ringtoneType: RingtoneType
    napi_create_int32(env, static_cast<int32_t>(ringtoneInfo.GetRingtoneType()), &value);
    napi_set_named_property(env, result, "ringtoneType", value);

    // ringtoneTitle?: string
    napi_create_string_utf8(env, ringtoneInfo.GetRingtoneTitle().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "ringtoneTitle", value);

    // ringtoneFileName?: string
    napi_create_string_utf8(env, ringtoneInfo.GetRingtoneFileName().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "ringtoneFileName", value);

    // ringtoneUri?: string
    napi_create_string_utf8(env, ringtoneInfo.GetRingtoneUri().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "ringtoneUri", value);

    return NapiGetBoolean(env, true);
}
}  // namespace NotificationNapi
}  // namespace OHOS
