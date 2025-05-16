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
bool SetDate(ani_env *env, ani_object obj, ani_class cls, const char *name, int64_t time)
{
    ani_object timeObj;
    if (!CreateDate(env, time, timeObj)) {
        ANS_LOGD("CreateDate faild.");
        return false;
    }
    if (!CallSetter(env, cls, obj, name, timeObj)) {
        ANS_LOGD("set '%{public}s' faild.", name);
        return false;
    }
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
    std::string functionName = "OnResponse";
    ani_env *env = GetAniEnv();
    if (env == nullptr || stsSubscriber_ == nullptr) {
        ANS_LOGE("null env or stsSubscriber_");
        return;
    }
    ani_status status = ANI_OK;
    ani_object stsSubscriberObj = reinterpret_cast<ani_object>(stsSubscriber_->aniRef);
    ani_ref funRef;
    status = env->Object_GetPropertyByName_Ref(stsSubscriberObj, functionName.c_str(), &funRef);
    if (status != ANI_OK) {
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
        ANS_LOGD("FunctionalObject_Call failed, status: %{public}d", status);
        return;
    }
}

void StsNotificationLocalLiveViewSubscriber::SetStsNotificationLocalLiveViewSubscriber(
    ani_env *env, ani_object &localLiveViewSubscriberObj)
{
    if (env == nullptr) {
        return;
    }
    stsSubscriber_ = std::make_unique<AbilityRuntime::STSNativeReference>();
    ani_ref objRef = nullptr;
    if (env->GlobalReference_Create(localLiveViewSubscriberObj, &objRef) != ANI_OK) {
        return;
    }

    ani_vm *aniVM = nullptr;
    if (env->GetVM(&aniVM) != ANI_OK) {
        return;
    }
    vm_ = aniVM;
    if (stsSubscriber_ == nullptr) {
        return;
    }
    stsSubscriber_->aniObj = localLiveViewSubscriberObj;
    stsSubscriber_->aniRef = objRef;
}

ani_env* StsNotificationLocalLiveViewSubscriber::GetAniEnv()
{
    if (vm_ == nullptr) {
        return nullptr;
    }
    ani_env* aniEnv = nullptr;
    if (vm_->GetEnv(ANI_VERSION_1, &aniEnv) != ANI_OK) {
        return nullptr;
    }
    return aniEnv;
}

bool SlotTypeEtsToC(ani_env *env, ani_enum_item enumItem, SlotType &slotType)
{
    STSSlotType stsSlotType = STSSlotType::UNKNOWN_TYPE;
    EnumConvertAniToNative(env, enumItem, stsSlotType);
    StsSlotTypeUtils::StsToC(stsSlotType, slotType);
    return true;
}

bool SlotTypeCToEts(ani_env *env, SlotType slotType, ani_enum_item &enumItem)
{
    STSSlotType stsSlotType = STSSlotType::UNKNOWN_TYPE;
    StsSlotTypeUtils::CToSts(slotType, stsSlotType);
    EnumConvertNativeToAni(env,
        "L@ohos/notificationManager/notificationManager/SlotType;", stsSlotType, enumItem);
    return true;
}

bool SlotLevelEtsToC(ani_env *env, ani_enum_item enumItem, SlotLevel &slotLevel)
{
    STSSlotLevel stsSlotLevel = STSSlotLevel::LEVEL_NONE;
    EnumConvertAniToNative(env, enumItem, stsSlotLevel);
    StsSlotLevelUtils::StsToC(stsSlotLevel, slotLevel);
    return true;
}
bool SlotLevelCToEts(ani_env *env, SlotLevel slotLevel, ani_enum_item &enumItem)
{
    STSSlotLevel stsSlotLevel = STSSlotLevel::LEVEL_NONE;
    StsSlotLevelUtils::CToSts(slotLevel, stsSlotLevel);
    EnumConvertNativeToAni(env,
        "L@ohos/notificationManager/notificationManager/SlotLevel;", stsSlotLevel, enumItem);
    return true;
}

bool ContentTypeEtsToC(ani_env *env, ani_enum_item enumItem, ContentType &contentType)
{
    STSContentType stsContentType = STSContentType::NOTIFICATION_CONTENT_BASIC_TEXT;
    if(EnumConvertAniToNative(env, enumItem, stsContentType)) {
        StsContentTypeUtils::StsToC(stsContentType, contentType);
        return true;
    }
    return false;
}

bool ContentTypeCToEts(ani_env *env, ContentType contentType, ani_enum_item &enumItem)
{
    STSContentType stsContentType = STSContentType::NOTIFICATION_CONTENT_BASIC_TEXT;
    StsContentTypeUtils::CToSts(contentType, stsContentType);
    if(EnumConvertNativeToAni(env,
        "L@ohos/notificationManager/notificationManager/ContentType;", stsContentType, enumItem)) {
        return true;
    }
    return false;
}

ani_status UnWarpNotificationButtonOption(ani_env *env, const ani_object buttonOptionObj,
    ButtonOption &buttonOption)
{
    ani_status status = ANI_ERROR;
    ani_boolean isUndefind = ANI_TRUE;
    std::string buttonName = "";
    if((status = GetPropertyString(env, buttonOptionObj, "buttonName", isUndefind, buttonName)) != ANI_OK
        || isUndefind == ANI_TRUE) {
        return ANI_INVALID_ARGS;
    }
    buttonOption.SetButtonName(buttonName);
    return status;
}

ani_object WarpNotificationButtonOption(ani_env *env, sptr<ButtonOption> buttonOption)
{
    if (buttonOption == nullptr) {
        ANS_LOGE("buttonOption is null");
        return nullptr;
    }
    ani_object optObj = nullptr;
    ani_class optCls = nullptr;
    RETURN_NULL_IF_FALSE(CreateClassObjByClassName(env,
        "L@ohos/notificationManager/notificationManager/ButtonOptionsInner;", optCls, optObj));
    // title: string;
    ani_string stringValue = nullptr;
    RETURN_NULL_IF_FALSE(GetAniStringByString(env, buttonOption->GetButtonName(), stringValue));
    RETURN_NULL_IF_FALSE(CallSetter(env, optCls, optObj, "buttonName", stringValue));
    return optObj;
}

bool WarpNotificationDoNotDisturbDate(
    ani_env *env, const std::shared_ptr<NotificationDoNotDisturbDate> &date, ani_object &outObj)
{
    ani_class cls;
    ani_object obj;
    ani_enum_item stsEnumValue;
    const char *className = "L@ohos/notificationManager/notificationManager/DoNotDisturbDateInner;";
    if (!CreateClassObjByClassName(env, className, cls, obj)) {
        ANS_LOGD("CreateClassObjByClassName faild");
        return false;
    }
    if (!EnumConvertNativeToAni(
        env, "L@ohos/notificationManager/notificationManager/DoNotDisturbType;",
            date->GetDoNotDisturbType(), stsEnumValue)) {
        ANS_LOGD("EnumConvert_NativeToSts faild");
        return false;
    }
    if (!CallSetter(env, cls, obj, "type", stsEnumValue)) {
        ANS_LOGD("set type faild.");
        return false;
    }
    if (!SetDate(env, obj, cls, "begin", date->GetBeginDate())) {
        ANS_LOGD("SetDate 'begin' faild.");
        return false;
    }
    if (!SetDate(env, obj, cls, "end", date->GetEndDate())) {
        ANS_LOGD("SetDate 'end' faild.");
        return false;
    }
    outObj = obj;
    return true;
}
} // namespace NotificationSts
} // OHOS