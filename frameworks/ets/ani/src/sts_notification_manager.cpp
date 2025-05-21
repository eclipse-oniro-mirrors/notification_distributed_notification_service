/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "sts_notification_manager.h"
#include "sts_common.h"
#include "ani_common_util.h"

namespace OHOS {
namespace NotificationSts {
bool SetDate(ani_env *env, ani_object obj, const char *name, int64_t time)
{
    ANS_LOGD("SetDate call");
    if (env == nullptr || obj == nullptr || name == nullptr) {
        ANS_LOGE("SetDate failed, has nullptr");
        return false;
    }
    ani_object timeObj;
    if (!CreateDate(env, time, timeObj)) {
        ANS_LOGE("CreateDate faild.");
        return false;
    }
    if (!SetPropertyByRef(env, obj, name, timeObj)) {
        ANS_LOGE("set '%{public}s' faild.", name);
        return false;
    }
    ANS_LOGD("SetDate end");
    return true;
}

bool StsSlotTypeUtils::StsToC(const STSSlotType inType, SlotType &outType)
{
    switch (inType) {
        case STSSlotType::SOCIAL_COMMUNICATION:
            outType = SlotType::SOCIAL_COMMUNICATION;
            break;
        case STSSlotType::SERVICE_INFORMATION:
            outType = SlotType::SERVICE_REMINDER;
            break;
        case STSSlotType::CONTENT_INFORMATION:
            outType = SlotType::CONTENT_INFORMATION;
            break;
        case STSSlotType::LIVE_VIEW:
            outType = SlotType::LIVE_VIEW;
            break;
        case STSSlotType::CUSTOMER_SERVICE:
            outType = SlotType::CUSTOMER_SERVICE;
            break;
        case STSSlotType::EMERGENCY_INFORMATION:
            outType = SlotType::EMERGENCY_INFORMATION;
            break;
        case STSSlotType::UNKNOWN_TYPE:
        case STSSlotType::OTHER_TYPES:
            outType = SlotType::OTHER;
            break;
        default:
            ANS_LOGE("SlotType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool StsSlotTypeUtils::CToSts(const SlotType inType, STSSlotType &outType)
{
    switch (inType) {
        case SlotType::CUSTOM:
            outType = STSSlotType::UNKNOWN_TYPE;
            break;
        case SlotType::SOCIAL_COMMUNICATION:
            outType = STSSlotType::SOCIAL_COMMUNICATION;
            break;
        case SlotType::SERVICE_REMINDER:
            outType = STSSlotType::SERVICE_INFORMATION;
            break;
        case SlotType::CONTENT_INFORMATION:
            outType = STSSlotType::CONTENT_INFORMATION;
            break;
        case SlotType::LIVE_VIEW:
            outType = STSSlotType::LIVE_VIEW;
            break;
        case SlotType::CUSTOMER_SERVICE:
            outType = STSSlotType::CUSTOMER_SERVICE;
            break;
        case SlotType::EMERGENCY_INFORMATION:
            outType = STSSlotType::EMERGENCY_INFORMATION;
            break;
        case SlotType::OTHER:
            outType = STSSlotType::OTHER_TYPES;
            break;
        default:
            ANS_LOGE("SlotType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool StsContentTypeUtils::StsToC(const STSContentType inType, ContentType &outType)
{
    switch (inType) {
        case STSContentType::NOTIFICATION_CONTENT_BASIC_TEXT:
            outType = ContentType::BASIC_TEXT;
            break;
        case STSContentType::NOTIFICATION_CONTENT_LONG_TEXT:
            outType = ContentType::LONG_TEXT;
            break;
        case STSContentType::NOTIFICATION_CONTENT_MULTILINE:
            outType = ContentType::MULTILINE;
            break;
        case STSContentType::NOTIFICATION_CONTENT_PICTURE:
            outType = ContentType::PICTURE;
            break;
        case STSContentType::NOTIFICATION_CONTENT_CONVERSATION:
            outType = ContentType::CONVERSATION;
            break;
        case STSContentType::NOTIFICATION_CONTENT_SYSTEM_LIVE_VIEW:
            outType = ContentType::LOCAL_LIVE_VIEW;
            break;
        case STSContentType::NOTIFICATION_CONTENT_LIVE_VIEW:
            outType = ContentType::LIVE_VIEW;
            break;
        default:
            ANS_LOGE("ContentType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool StsContentTypeUtils::CToSts(const ContentType inType, STSContentType &outType)
{
    switch (inType) {
        case ContentType::BASIC_TEXT:
            outType = STSContentType::NOTIFICATION_CONTENT_BASIC_TEXT;
            break;
        case ContentType::LONG_TEXT:
            outType = STSContentType::NOTIFICATION_CONTENT_LONG_TEXT;
            break;
        case ContentType::MULTILINE:
            outType = STSContentType::NOTIFICATION_CONTENT_MULTILINE;
            break;
        case ContentType::PICTURE:
            outType = STSContentType::NOTIFICATION_CONTENT_PICTURE;
            break;
        case ContentType::CONVERSATION:
            outType = STSContentType::NOTIFICATION_CONTENT_CONVERSATION;
            break;
        case ContentType::LOCAL_LIVE_VIEW:
            outType = STSContentType::NOTIFICATION_CONTENT_SYSTEM_LIVE_VIEW;
            break;
        case ContentType::LIVE_VIEW:
            outType = STSContentType::NOTIFICATION_CONTENT_LIVE_VIEW;
            break;
        default:
            ANS_LOGE("ContentType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool StsSlotLevelUtils::CToSts(const SlotLevel inLevel, STSSlotLevel &outLevel)
{
    switch (inLevel) {
        case SlotLevel::LEVEL_NONE:
        case SlotLevel::LEVEL_UNDEFINED:
            outLevel = STSSlotLevel::LEVEL_NONE;
            break;
        case SlotLevel::LEVEL_MIN:
            outLevel = STSSlotLevel::LEVEL_MIN;
            break;
        case SlotLevel::LEVEL_LOW:
            outLevel = STSSlotLevel::LEVEL_LOW;
            break;
        case SlotLevel::LEVEL_DEFAULT:
            outLevel = STSSlotLevel::LEVEL_DEFAULT;
            break;
        case SlotLevel::LEVEL_HIGH:
            outLevel = STSSlotLevel::LEVEL_HIGH;
            break;
        default:
            ANS_LOGE("SlotLevel %{public}d is an invalid value", inLevel);
            return false;
    }
    return true;
}

bool StsSlotLevelUtils::StsToC(const STSSlotLevel inLevel, SlotLevel &outLevel)
{
    switch (inLevel) {
        case STSSlotLevel::LEVEL_NONE:
            outLevel = SlotLevel::LEVEL_NONE;
            break;
        case STSSlotLevel::LEVEL_MIN:
            outLevel = SlotLevel::LEVEL_MIN;
            break;
        case STSSlotLevel::LEVEL_LOW:
            outLevel = SlotLevel::LEVEL_LOW;
            break;
        case STSSlotLevel::LEVEL_DEFAULT:
            outLevel = SlotLevel::LEVEL_DEFAULT;
            break;
        case STSSlotLevel::LEVEL_HIGH:
            outLevel = SlotLevel::LEVEL_HIGH;
            break;
        default:
            ANS_LOGE("SlotLevel %{public}d is an invalid value", inLevel);
            return false;
    }
    return true;
}

StsNotificationLocalLiveViewSubscriber::StsNotificationLocalLiveViewSubscriber()
{}

StsNotificationLocalLiveViewSubscriber::~StsNotificationLocalLiveViewSubscriber()
{}

void StsNotificationLocalLiveViewSubscriber::OnConnected()
{}

void StsNotificationLocalLiveViewSubscriber::OnDisconnected()
{}

void StsNotificationLocalLiveViewSubscriber::OnDied()
{}

void StsNotificationLocalLiveViewSubscriber::OnResponse(int32_t notificationId, sptr<ButtonOption> buttonOption)
{
    ANS_LOGD("OnResponse call");
    std::string functionName = "OnResponse";
    ani_env *env = GetAniEnv();
    if (env == nullptr || stsSubscriber_ == nullptr) {
        ANS_LOGE("null env or stsSubscriber_");
        return;
    }
    ani_status status = ANI_OK;
    ani_object stsSubscriberObj = reinterpret_cast<ani_object>(stsSubscriber_->aniRef);
    ani_ref funRef;
    ani_boolean isUndefined = ANI_TRUE;
    status = GetPropertyRef(env, stsSubscriberObj, functionName.c_str(), isUndefined, funRef);
    if (status != ANI_OK || isUndefined == ANI_TRUE || funRef == nullptr) {
        ANS_LOGE("Object_GetField_Ref failed");
        return;
    }
    ani_object notificationIdAni = CreateDouble(env, notificationId);
    ani_object buttonOptionObj = WarpNotificationButtonOption(env, buttonOption);
    if (notificationIdAni == nullptr || buttonOptionObj == nullptr) {
        ANS_LOGE("null args");
        return;
    }
    ani_fn_object onFn = reinterpret_cast<ani_fn_object>(funRef);
    ani_ref resutlt;
    std::vector<ani_ref> argv;
    argv.push_back(notificationIdAni);
    argv.push_back(buttonOptionObj);
    if ((status = env->FunctionalObject_Call(onFn, argv.size(), argv.data(), &resutlt)) != ANI_OK) {
        ANS_LOGE("FunctionalObject_Call failed, status: %{public}d", status);
        return;
    }
}

void StsNotificationLocalLiveViewSubscriber::SetStsNotificationLocalLiveViewSubscriber(
    ani_env *env, ani_object &localLiveViewSubscriberObj)
{
    ANS_LOGD("SetStsNotificationLocalLiveViewSubscriber call");
    if (env == nullptr) {
        ANS_LOGE("Set failed, env is nullptr");
        return;
    }
    stsSubscriber_ = std::make_unique<AbilityRuntime::STSNativeReference>();
    if (stsSubscriber_ == nullptr) {
        ANS_LOGE("stsSubscriber_ is nullptr");
        return;
    }
    ani_ref objRef = nullptr;
    if (env->GlobalReference_Create(localLiveViewSubscriberObj, &objRef) != ANI_OK) {
        ANS_LOGE("create ref failed");
        return;
    }
    ani_vm *aniVM = nullptr;
    if (env->GetVM(&aniVM) != ANI_OK) {
        ANS_LOGE("GetVM failed");
        return;
    }
    vm_ = aniVM;
    stsSubscriber_->aniObj = localLiveViewSubscriberObj;
    stsSubscriber_->aniRef = objRef;
}

ani_env* StsNotificationLocalLiveViewSubscriber::GetAniEnv()
{
    ANS_LOGD("GetAniEnv call");
    if (vm_ == nullptr) {
        ANS_LOGE("vm_ is nullptr");
        return nullptr;
    }
    ani_env* aniEnv = nullptr;
    if (vm_->GetEnv(ANI_VERSION_1, &aniEnv) != ANI_OK) {
        ANS_LOGE("get env failed");
        return nullptr;
    }
    return aniEnv;
}

bool SlotTypeEtsToC(ani_env *env, ani_enum_item enumItem, SlotType &slotType)
{
    ANS_LOGD("SlotTypeEtsToC call");
    STSSlotType stsSlotType = STSSlotType::UNKNOWN_TYPE;
    if (!EnumConvertAniToNative(env, enumItem, stsSlotType) || !StsSlotTypeUtils::StsToC(stsSlotType, slotType)) {
        ANS_LOGE("SlotTypeEtsToC failed");
        return false;
    }
    return true;
}

bool SlotTypeCToEts(ani_env *env, SlotType slotType, ani_enum_item &enumItem)
{
    ANS_LOGD("SlotTypeCToEts call");
    STSSlotType stsSlotType = STSSlotType::UNKNOWN_TYPE;
    if (!StsSlotTypeUtils::CToSts(slotType, stsSlotType)
        || !EnumConvertNativeToAni(
        env, "L@ohos/notificationManager/notificationManager/SlotType;", stsSlotType, enumItem)) {
        ANS_LOGE("SlotTypeCToEts failed");
        return false;
    }
    return true;
}

bool SlotLevelEtsToC(ani_env *env, ani_enum_item enumItem, SlotLevel &slotLevel)
{
    ANS_LOGD("SlotLevelEtsToC call");
    STSSlotLevel stsSlotLevel = STSSlotLevel::LEVEL_NONE;
    if (!EnumConvertAniToNative(env, enumItem, stsSlotLevel)
        || !StsSlotLevelUtils::StsToC(stsSlotLevel, slotLevel)) {
        ANS_LOGE("SlotLevelEtsToC failed");
        return false;
    }
    return true;
}
bool SlotLevelCToEts(ani_env *env, SlotLevel slotLevel, ani_enum_item &enumItem)
{
    ANS_LOGD("SlotLevelCToEts call");
    STSSlotLevel stsSlotLevel = STSSlotLevel::LEVEL_NONE;
    if (!StsSlotLevelUtils::CToSts(slotLevel, stsSlotLevel) || !EnumConvertNativeToAni(env,
        "L@ohos/notificationManager/notificationManager/SlotLevel;", stsSlotLevel, enumItem)) {
        ANS_LOGE("SlotLevelCToEts failed");
        return false;
    }
    return true;
}

bool ContentTypeEtsToC(ani_env *env, ani_enum_item enumItem, ContentType &contentType)
{
    ANS_LOGD("ContentTypeEtsToC call");
    STSContentType stsContentType = STSContentType::NOTIFICATION_CONTENT_BASIC_TEXT;
    if (!EnumConvertAniToNative(env, enumItem, stsContentType)
        || !StsContentTypeUtils::StsToC(stsContentType, contentType)) {
        ANS_LOGE("ContentTypeEtsToC failed");
        return false;
    }
    return true;
}

bool ContentTypeCToEts(ani_env *env, ContentType contentType, ani_enum_item &enumItem)
{
    ANS_LOGD("ContentTypeCToEts call");
    STSContentType stsContentType = STSContentType::NOTIFICATION_CONTENT_BASIC_TEXT;
    if (!StsContentTypeUtils::CToSts(contentType, stsContentType)
        || !EnumConvertNativeToAni(env,
        "L@ohos/notificationManager/notificationManager/ContentType;", stsContentType, enumItem)) {
        ANS_LOGE("ContentTypeCToEts failed");
        return false;
    }
    return true;
}

ani_status UnWarpNotificationButtonOption(ani_env *env, const ani_object buttonOptionObj,
    ButtonOption &buttonOption)
{
    ANS_LOGD("UnWarpNotificationButtonOption call");
    if (env == nullptr || buttonOptionObj == nullptr) {
        ANS_LOGE("UnWarpNotificationButtonOption failed, has nullptr");
        return ANI_ERROR;
    }
    ani_status status = ANI_ERROR;
    ani_boolean isUndefind = ANI_TRUE;
    std::string buttonName = "";
    if((status = GetPropertyString(env, buttonOptionObj, "buttonName", isUndefind, buttonName)) != ANI_OK
        || isUndefind == ANI_TRUE) {
        ANS_LOGE("UnWarpNotificationButtonOption: get buttonName failed");
        return ANI_INVALID_ARGS;
    }
    buttonOption.SetButtonName(buttonName);
    ANS_LOGD("UnWarpNotificationButtonOption end");
    return status;
}

ani_object WarpNotificationButtonOption(ani_env *env, sptr<ButtonOption> buttonOption)
{
    ANS_LOGD("WarpNotificationButtonOption call");
    if (env == nullptr || buttonOption == nullptr) {
        ANS_LOGE("WarpNotificationButtonOption failed, has nullptr");
        return nullptr;
    }
    ani_object optObj = nullptr;
    ani_class optCls = nullptr;
    if (!CreateClassObjByClassName(env,
        "L@ohos/notificationManager/notificationManager/ButtonOptionsInner;", optCls, optObj) || optObj == nullptr) {
        ANS_LOGE("WarpNotificationButtonOption: create class failed");
        return nullptr;
    }
    // title: string;
    if (!SetPropertyOptionalByString(env, optObj, "buttonName", buttonOption->GetButtonName())) {
        ANS_LOGE("WarpNotificationButtonOption: set buttonName failed");
        return nullptr;
    }
    ANS_LOGD("WarpNotificationButtonOption end");
    return optObj;
}

bool WarpNotificationDoNotDisturbDate(
    ani_env *env, const std::shared_ptr<NotificationDoNotDisturbDate> &date, ani_object &outObj)
{
    ANS_LOGD("WarpNotificationDoNotDisturbDate call");
    if (env == nullptr || date == nullptr) {
        ANS_LOGE("WarpNotificationDoNotDisturbDate failed, has nullptr");
        return false;
    }
    ani_class cls;
    ani_enum_item stsEnumValue;
    const char *className = "L@ohos/notificationManager/notificationManager/DoNotDisturbDateInner;";
    if (!CreateClassObjByClassName(env, className, cls, outObj) || outObj == nullptr) {
        ANS_LOGE("WarpNotificationDoNotDisturbDate: create class faild");
        return false;
    }
    if (!EnumConvertNativeToAni(
        env, "L@ohos/notificationManager/notificationManager/DoNotDisturbType;",
            date->GetDoNotDisturbType(), stsEnumValue)) {
        ANS_LOGE("EnumConvert_NativeToSts faild");
        return false;
    }
    if (!SetPropertyByRef(env, outObj, "type", stsEnumValue)) {
        ANS_LOGE("set type faild.");
        return false;
    }
    if (!SetDate(env, outObj, "begin", date->GetBeginDate())) {
        ANS_LOGE("SetDate 'begin' faild.");
        return false;
    }
    if (!SetDate(env, outObj, "end", date->GetEndDate())) {
        ANS_LOGE("SetDate 'end' faild.");
        return false;
    }
    ANS_LOGD("WarpNotificationDoNotDisturbDate end");
    return true;
}
} // namespace NotificationSts
} // OHOS