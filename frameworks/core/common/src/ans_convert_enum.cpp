/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ans_convert_enum.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace NotificationNapi {
bool AnsEnumUtil::ContentTypeJSToC(const ContentType &inType, NotificationContent::Type &outType)
{
    switch (inType) {
        case ContentType::NOTIFICATION_CONTENT_BASIC_TEXT:
            outType = NotificationContent::Type::BASIC_TEXT;
            break;
        case ContentType::NOTIFICATION_CONTENT_LONG_TEXT:
            outType = NotificationContent::Type::LONG_TEXT;
            break;
        case ContentType::NOTIFICATION_CONTENT_MULTILINE:
            outType = NotificationContent::Type::MULTILINE;
            break;
        case ContentType::NOTIFICATION_CONTENT_PICTURE:
            outType = NotificationContent::Type::PICTURE;
            break;
        case ContentType::NOTIFICATION_CONTENT_CONVERSATION:
            outType = NotificationContent::Type::CONVERSATION;
            break;
        case ContentType::NOTIFICATION_CONTENT_LOCAL_LIVE_VIEW:
            outType = NotificationContent::Type::LOCAL_LIVE_VIEW;
            break;
        case ContentType::NOTIFICATION_CONTENT_LIVE_VIEW:
            outType = NotificationContent::Type::LIVE_VIEW;
            break;
        default:
            ANS_LOGE("ContentType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool AnsEnumUtil::ContentTypeCToJS(const NotificationContent::Type &inType, ContentType &outType)
{
    switch (inType) {
        case NotificationContent::Type::BASIC_TEXT:
            outType = ContentType::NOTIFICATION_CONTENT_BASIC_TEXT;
            break;
        case NotificationContent::Type::LONG_TEXT:
            outType = ContentType::NOTIFICATION_CONTENT_LONG_TEXT;
            break;
        case NotificationContent::Type::MULTILINE:
            outType = ContentType::NOTIFICATION_CONTENT_MULTILINE;
            break;
        case NotificationContent::Type::PICTURE:
            outType = ContentType::NOTIFICATION_CONTENT_PICTURE;
            break;
        case NotificationContent::Type::CONVERSATION:
            outType = ContentType::NOTIFICATION_CONTENT_CONVERSATION;
            break;
        case NotificationContent::Type::LOCAL_LIVE_VIEW:
            outType = ContentType::NOTIFICATION_CONTENT_LOCAL_LIVE_VIEW;
            break;
        case NotificationContent::Type::LIVE_VIEW:
            outType = ContentType::NOTIFICATION_CONTENT_LIVE_VIEW;
            break;
        default:
            ANS_LOGE("ContentType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool AnsEnumUtil::SlotTypeJSToC(const SlotType &inType, NotificationConstant::SlotType &outType)
{
    switch (inType) {
        case SlotType::SOCIAL_COMMUNICATION:
            outType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
            break;
        case SlotType::SERVICE_INFORMATION:
            outType = NotificationConstant::SlotType::SERVICE_REMINDER;
            break;
        case SlotType::CONTENT_INFORMATION:
            outType = NotificationConstant::SlotType::CONTENT_INFORMATION;
            break;
        case SlotType::LIVE_VIEW:
            outType = NotificationConstant::SlotType::LIVE_VIEW;
            break;
        case SlotType::CUSTOMER_SERVICE:
            outType = NotificationConstant::SlotType::CUSTOMER_SERVICE;
            break;
        case SlotType::EMERGENCY_INFORMATION:
            outType = NotificationConstant::SlotType::EMERGENCY_INFORMATION;
            break;
        case SlotType::UNKNOWN_TYPE:
        case SlotType::OTHER_TYPES:
            outType = NotificationConstant::SlotType::OTHER;
            break;
        default:
            ANS_LOGE("SlotType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool AnsEnumUtil::SlotTypeCToJS(const NotificationConstant::SlotType &inType, SlotType &outType)
{
    switch (inType) {
        case NotificationConstant::SlotType::CUSTOM:
            outType = SlotType::UNKNOWN_TYPE;
            break;
        case NotificationConstant::SlotType::SOCIAL_COMMUNICATION:
            outType = SlotType::SOCIAL_COMMUNICATION;
            break;
        case NotificationConstant::SlotType::SERVICE_REMINDER:
            outType = SlotType::SERVICE_INFORMATION;
            break;
        case NotificationConstant::SlotType::CONTENT_INFORMATION:
            outType = SlotType::CONTENT_INFORMATION;
            break;
        case NotificationConstant::SlotType::LIVE_VIEW:
            outType = SlotType::LIVE_VIEW;
            break;
        case NotificationConstant::SlotType::CUSTOMER_SERVICE:
            outType = SlotType::CUSTOMER_SERVICE;
            break;
        case NotificationConstant::SlotType::EMERGENCY_INFORMATION:
            outType = SlotType::EMERGENCY_INFORMATION;
            break;
        case NotificationConstant::SlotType::OTHER:
            outType = SlotType::OTHER_TYPES;
            break;
        default:
            ANS_LOGE("SlotType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}


bool AnsEnumUtil::SlotLevelJSToC(const SlotLevel &inLevel, NotificationSlot::NotificationLevel &outLevel)
{
    switch (inLevel) {
        case SlotLevel::LEVEL_NONE:
            outLevel = NotificationSlot::NotificationLevel::LEVEL_NONE;
            break;
        case SlotLevel::LEVEL_MIN:
            outLevel = NotificationSlot::NotificationLevel::LEVEL_MIN;
            break;
        case SlotLevel::LEVEL_LOW:
            outLevel = NotificationSlot::NotificationLevel::LEVEL_LOW;
            break;
        case SlotLevel::LEVEL_DEFAULT:
            outLevel = NotificationSlot::NotificationLevel::LEVEL_DEFAULT;
            break;
        case SlotLevel::LEVEL_HIGH:
            outLevel = NotificationSlot::NotificationLevel::LEVEL_HIGH;
            break;
        default:
            ANS_LOGE("SlotLevel %{public}d is an invalid value", inLevel);
            return false;
    }
    return true;
}

bool AnsEnumUtil::LiveViewStatusJSToC(
    const LiveViewStatus &inType, NotificationLiveViewContent::LiveViewStatus &outType)
{
    switch (inType) {
        case LiveViewStatus::LIVE_VIEW_CREATE:
            outType = NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE;
            break;
        case LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE:
            outType = NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE;
            break;
        case LiveViewStatus::LIVE_VIEW_END:
            outType = NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END;
            break;
        case LiveViewStatus::LIVE_VIEW_FULL_UPDATE:
            outType = NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE;
            break;
        default:
            ANS_LOGE("LiveViewStatus %{public}d is an invalid value", inType);
            return false;
    }

    return true;
}

bool AnsEnumUtil::LiveViewTypesJSToC(
    const LiveViewTypes &inType, NotificationLocalLiveViewContent::LiveViewTypes &outType)
{
    switch (inType) {
        case LiveViewTypes::LIVE_VIEW_ACTIVITY:
            outType = NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_ACTIVITY;
            break;
        case LiveViewTypes::LIVE_VIEW_INSTANT:
            outType = NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_INSTANT;
            break;
        case LiveViewTypes::LIVE_VIEW_LONG_TERM:
            outType = NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_LONG_TERM;
            break;
        case LiveViewTypes::LIVE_VIEW_INSTANT_BANNER:
            outType = NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_INSTANT_BANNER;
            break;
        default:
            ANS_LOGE("LiveViewTypes %{public}d is an invalid value", inType);
            return false;
    }

    return true;
}

bool AnsEnumUtil::SlotLevelCToJS(const NotificationSlot::NotificationLevel &inLevel, SlotLevel &outLevel)
{
    switch (inLevel) {
        case NotificationSlot::NotificationLevel::LEVEL_NONE:
        case NotificationSlot::NotificationLevel::LEVEL_UNDEFINED:
            outLevel = SlotLevel::LEVEL_NONE;
            break;
        case NotificationSlot::NotificationLevel::LEVEL_MIN:
            outLevel = SlotLevel::LEVEL_MIN;
            break;
        case NotificationSlot::NotificationLevel::LEVEL_LOW:
            outLevel = SlotLevel::LEVEL_LOW;
            break;
        case NotificationSlot::NotificationLevel::LEVEL_DEFAULT:
            outLevel = SlotLevel::LEVEL_DEFAULT;
            break;
        case NotificationSlot::NotificationLevel::LEVEL_HIGH:
            outLevel = SlotLevel::LEVEL_HIGH;
            break;
        default:
            ANS_LOGE("SlotLevel %{public}d is an invalid value", inLevel);
            return false;
    }
    return true;
}

bool AnsEnumUtil::ReasonCToJS(const int &inType, int &outType)
{
    switch (inType) {
        case NotificationConstant::DEFAULT_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::DEFAULT_REASON_DELETE);
            break;
        case NotificationConstant::CLICK_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::CLICK_REASON_REMOVE);
            break;
        case NotificationConstant::CANCEL_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::CANCEL_REASON_REMOVE);
            break;
        case NotificationConstant::CANCEL_ALL_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::CANCEL_ALL_REASON_REMOVE);
            break;
        case NotificationConstant::ERROR_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::ERROR_REASON_REMOVE);
            break;
        case NotificationConstant::PACKAGE_CHANGED_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::PACKAGE_CHANGED_REASON_REMOVE);
            break;
        case NotificationConstant::USER_STOPPED_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::USER_STOPPED_REASON_REMOVE);
            break;
        case NotificationConstant::APP_CANCEL_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::APP_CANCEL_REASON_REMOVE);
            break;
        case NotificationConstant::APP_CANCEL_ALL_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::APP_CANCEL_ALL_REASON_REMOVE);
            break;
        case NotificationConstant::USER_REMOVED_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::USER_REMOVED_REASON_DELETE);
            break;
        case NotificationConstant::FLOW_CONTROL_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::FLOW_CONTROL_REASON_DELETE);
            break;
        default:
            ReasonCToJSExt(inType, outType);
            break;
    }
    return true;
}

void AnsEnumUtil::ReasonCToJSExt(const int &inType, int &outType)
{
    switch (inType) {
        case NotificationConstant::DISABLE_SLOT_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::DISABLE_SLOT_REASON_DELETE);
            break;
        case NotificationConstant::DISABLE_NOTIFICATION_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::DISABLE_NOTIFICATION_REASON_DELETE);
            break;
        case NotificationConstant::APP_CANCEL_AS_BUNELE_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::APP_CANCEL_AS_BUNELE_REASON_DELETE);
            break;
        case NotificationConstant::APP_CANCEL_AS_BUNELE_WITH_AGENT_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::APP_CANCEL_AS_BUNELE_WITH_AGENT_REASON_DELETE);
            break;
        case NotificationConstant::APP_CANCEL_REMINDER_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::APP_CANCEL_REMINDER_REASON_DELETE);
            break;
        case NotificationConstant::APP_CANCEL_GROPU_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::APP_CANCEL_GROPU_REASON_DELETE);
            break;
        case NotificationConstant::APP_REMOVE_GROUP_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::APP_REMOVE_GROUP_REASON_DELETE);
            break;
        case NotificationConstant::APP_REMOVE_ALL_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::APP_REMOVE_ALL_REASON_DELETE);
            break;
        case NotificationConstant::APP_REMOVE_ALL_USER_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::APP_REMOVE_ALL_USER_REASON_DELETE);
            break;
        case NotificationConstant::TRIGGER_EIGHT_HOUR_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::TRIGGER_EIGHT_HOUR_REASON_DELETE);
            break;
        case NotificationConstant::TRIGGER_FOUR_HOUR_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::TRIGGER_FOUR_HOUR_REASON_DELETE);
            break;
        default:
            ReasonCToJSSecondExt(inType, outType);
            break;
    }
}

void AnsEnumUtil::ReasonCToJSSecondExt(const int &inType, int &outType)
{
    switch (inType) {
        case NotificationConstant::TRIGGER_TEN_MINUTES_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::TRIGGER_TEN_MINUTES_REASON_DELETE);
            break;
        case NotificationConstant::TRIGGER_FIFTEEN_MINUTES_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::TRIGGER_FIFTEEN_MINUTES_REASON_DELETE);
            break;
        case NotificationConstant::TRIGGER_THIRTY_MINUTES_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::TRIGGER_THIRTY_MINUTES_REASON_DELETE);
            break;
        case NotificationConstant::TRIGGER_START_ARCHIVE_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::TRIGGER_START_ARCHIVE_REASON_DELETE);
            break;
        case NotificationConstant::TRIGGER_AUTO_DELETE_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::TRIGGER_AUTO_DELETE_REASON_DELETE);
            break;
        case NotificationConstant::PACKAGE_REMOVE_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::PACKAGE_REMOVE_REASON_DELETE);
            break;
        case NotificationConstant::SLOT_ENABLED_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::SLOT_ENABLED_REASON_DELETE);
            break;
        case NotificationConstant::APP_CANCEL_REASON_OTHER:
            outType = static_cast<int32_t>(RemoveReason::APP_CANCEL_REASON_OTHER);
            break;
        case NotificationConstant::RECOVER_LIVE_VIEW_DELETE:
            outType = static_cast<int32_t>(RemoveReason::RECOVER_LIVE_VIEW_DELETE);
            break;
        case NotificationConstant::DISABLE_NOTIFICATION_FEATURE_REASON_DELETE:
            outType = static_cast<int32_t>(RemoveReason::DISABLE_NOTIFICATION_FEATURE_REASON_DELETE);
            break;
        case NotificationConstant::DISTRIBUTED_COLLABORATIVE_DELETE:
            outType = static_cast<int32_t>(RemoveReason::DISTRIBUTED_COLLABORATIVE_DELETE);
            break;
        default:
            outType = static_cast<int32_t>(RemoveReason::APP_CANCEL_REASON_OTHER);
            ANS_LOGW("Reason %{public}d is an invalid value", inType);
            break;
    }
}

bool AnsEnumUtil::DoNotDisturbTypeJSToC(const DoNotDisturbType &inType, NotificationConstant::DoNotDisturbType &outType)
{
    switch (inType) {
        case DoNotDisturbType::TYPE_NONE:
            outType = NotificationConstant::DoNotDisturbType::NONE;
            break;
        case DoNotDisturbType::TYPE_ONCE:
            outType = NotificationConstant::DoNotDisturbType::ONCE;
            break;
        case DoNotDisturbType::TYPE_DAILY:
            outType = NotificationConstant::DoNotDisturbType::DAILY;
            break;
        case DoNotDisturbType::TYPE_CLEARLY:
            outType = NotificationConstant::DoNotDisturbType::CLEARLY;
            break;
        default:
            ANS_LOGE("DoNotDisturbType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool AnsEnumUtil::DoNotDisturbTypeCToJS(const NotificationConstant::DoNotDisturbType &inType, DoNotDisturbType &outType)
{
    switch (inType) {
        case NotificationConstant::DoNotDisturbType::NONE:
            outType = DoNotDisturbType::TYPE_NONE;
            break;
        case NotificationConstant::DoNotDisturbType::ONCE:
            outType = DoNotDisturbType::TYPE_ONCE;
            break;
        case NotificationConstant::DoNotDisturbType::DAILY:
            outType = DoNotDisturbType::TYPE_DAILY;
            break;
        case NotificationConstant::DoNotDisturbType::CLEARLY:
            outType = DoNotDisturbType::TYPE_CLEARLY;
            break;
        default:
            ANS_LOGE("DoNotDisturbType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool AnsEnumUtil::DeviceRemindTypeCToJS(const NotificationConstant::RemindType &inType, DeviceRemindType &outType)
{
    switch (inType) {
        case NotificationConstant::RemindType::DEVICE_IDLE_DONOT_REMIND:
            outType = DeviceRemindType::IDLE_DONOT_REMIND;
            break;
        case NotificationConstant::RemindType::DEVICE_IDLE_REMIND:
            outType = DeviceRemindType::IDLE_REMIND;
            break;
        case NotificationConstant::RemindType::DEVICE_ACTIVE_DONOT_REMIND:
            outType = DeviceRemindType::ACTIVE_DONOT_REMIND;
            break;
        case NotificationConstant::RemindType::DEVICE_ACTIVE_REMIND:
            outType = DeviceRemindType::ACTIVE_REMIND;
            break;
        default:
            ANS_LOGE("DeviceRemindType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool AnsEnumUtil::SourceTypeCToJS(const NotificationConstant::SourceType &inType, SourceType &outType)
{
    switch (inType) {
        case NotificationConstant::SourceType::TYPE_NORMAL:
            outType = SourceType::TYPE_NORMAL;
            break;
        case NotificationConstant::SourceType::TYPE_CONTINUOUS:
            outType = SourceType::TYPE_CONTINUOUS;
            break;
        case NotificationConstant::SourceType::TYPE_TIMER:
            outType = SourceType::TYPE_TIMER;
            break;
        default:
            ANS_LOGE("SourceType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool AnsEnumUtil::LiveViewStatusCToJS(const NotificationLiveViewContent::LiveViewStatus &inType,
    LiveViewStatus &outType)
{
    switch (inType) {
        case NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE:
            outType = LiveViewStatus::LIVE_VIEW_CREATE;
            break;
        case NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE:
            outType = LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE;
            break;
        case NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END:
            outType = LiveViewStatus::LIVE_VIEW_END;
            break;
        case NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE:
            outType = LiveViewStatus::LIVE_VIEW_FULL_UPDATE;
            break;
        default:
            ANS_LOGE("LiveViewStatus %{public}d is an invalid value", inType);
            return false;
    }

    return true;
}
bool AnsEnumUtil::LiveViewTypesCToJS(const NotificationLocalLiveViewContent::LiveViewTypes &inType,
    LiveViewTypes &outType)
{
    switch (inType) {
        case NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_ACTIVITY:
            outType = LiveViewTypes::LIVE_VIEW_ACTIVITY;
            break;
        case NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_INSTANT:
            outType = LiveViewTypes::LIVE_VIEW_INSTANT;
            break;
        case NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_LONG_TERM:
            outType = LiveViewTypes::LIVE_VIEW_LONG_TERM;
            break;
        case NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_INSTANT_BANNER:
            outType = LiveViewTypes::LIVE_VIEW_INSTANT_BANNER;
            break;
        default:
            ANS_LOGE("LiveViewTypes %{public}d is an invalid value", inType);
            return false;
    }

    return true;
}
}
}
