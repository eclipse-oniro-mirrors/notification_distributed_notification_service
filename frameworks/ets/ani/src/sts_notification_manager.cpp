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
#include "ani_common_want.h"

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

bool StsDoNotDisturbTypeUtils::StsToC(const STSDoNotDisturbType inType,
    OHOS::Notification::NotificationConstant::DoNotDisturbType &outType)
{
    switch (inType) {
        case STSDoNotDisturbType::TYPE_NONE:
            outType = Notification::NotificationConstant::DoNotDisturbType::NONE;
            break;
        case STSDoNotDisturbType::TYPE_ONCE:
            outType = Notification::NotificationConstant::DoNotDisturbType::ONCE;
            break;
        case STSDoNotDisturbType::TYPE_DAILY:
            outType = Notification::NotificationConstant::DoNotDisturbType::DAILY;
            break;
        case STSDoNotDisturbType::TYPE_CLEARLY:
            outType = Notification::NotificationConstant::DoNotDisturbType::CLEARLY;
            break;
        default:
            ANS_LOGE("STSDoNotDisturbType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool StsRemindTypeUtils::StsToC(const STSRemindType inType, RemindType &outType)
{
    switch (inType) {
        case STSRemindType::IDLE_DONOT_REMIND:
            outType = RemindType::DEVICE_IDLE_DONOT_REMIND;
            break;
        case STSRemindType::IDLE_REMIND:
            outType = RemindType::DEVICE_IDLE_REMIND;
            break;
        case STSRemindType::ACTIVE_DONOT_REMIND:
            outType = RemindType::DEVICE_ACTIVE_DONOT_REMIND;
            break;
        case STSRemindType::ACTIVE_REMIND:
            outType = RemindType::DEVICE_ACTIVE_REMIND;
            break;
        default:
            ANS_LOGE("STSRemindType %{public}d is an invalid value", inType);
            return false;
    }
    return true;
}

bool StsRemindTypeUtils::CToSts(const RemindType inType, STSRemindType &outType)
{
    switch (inType) {
        case RemindType::NONE:
        case RemindType::DEVICE_IDLE_DONOT_REMIND:
            outType = STSRemindType::IDLE_DONOT_REMIND;
            break;
        case RemindType::DEVICE_IDLE_REMIND:
            outType = STSRemindType::IDLE_REMIND;
            break;
        case RemindType::DEVICE_ACTIVE_DONOT_REMIND:
            outType = STSRemindType::ACTIVE_DONOT_REMIND;
            break;
        case RemindType::DEVICE_ACTIVE_REMIND:
            outType = STSRemindType::ACTIVE_REMIND;
            break;
        default:
            ANS_LOGE("RemindType %{public}d is an invalid value", inType);
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
    ani_object notificationIdAni = CreateInt(env, notificationId);
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
    stsSubscriber_ = std::make_unique<AppExecFwk::ETSNativeReference>();
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
            env, "@ohos.notificationManager.notificationManager.SlotType", stsSlotType, enumItem)) {
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
        "@ohos.notificationManager.notificationManager.SlotLevel", stsSlotLevel, enumItem)) {
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
        "@ohos.notificationManager.notificationManager.ContentType", stsContentType, enumItem)) {
        ANS_LOGE("ContentTypeCToEts failed");
        return false;
    }
    return true;
}

bool DoNotDisturbTypeEtsToC(ani_env *env, ani_enum_item enumItem,
    Notification::NotificationConstant::DoNotDisturbType &doNotDisturbType)
{
    ANS_LOGD("DoNotDisturbTypeEtsToC call");
    STSDoNotDisturbType stsDoNotDisturbType = TYPE_NONE;
    if (!EnumConvertAniToNative(env, enumItem, stsDoNotDisturbType)
        || !StsDoNotDisturbTypeUtils::StsToC(stsDoNotDisturbType, doNotDisturbType)) {
        ANS_LOGE("DoNotDisturbTypeEtsToC failed");
        return false;
    }
    return true;
}

bool DeviceRemindTypeCToEts(ani_env *env, RemindType remindType, ani_enum_item &enumItem)
{
    STSRemindType stsRemindType = STSRemindType::IDLE_DONOT_REMIND;
    StsRemindTypeUtils::CToSts(remindType, stsRemindType);
    EnumConvertNativeToAni(env,
        "@ohos.notificationManager.notificationManager.RemindType", stsRemindType, enumItem);
    return true;
}

bool DeviceRemindTypeEtsToC(ani_env *env, ani_enum_item enumItem, RemindType &remindType)
{
    STSRemindType stsRemindType = STSRemindType::IDLE_DONOT_REMIND;
    if (EnumConvertAniToNative(env, enumItem, stsRemindType)) {
        StsRemindTypeUtils::StsToC(stsRemindType, remindType);
        return true;
    }
    return false;
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
    if ((status = GetPropertyString(env, buttonOptionObj, "buttonName", isUndefind, buttonName)) != ANI_OK
        || isUndefind == ANI_TRUE) {
        ANS_LOGE("UnWarpNotificationButtonOption: get buttonName failed");
        return ANI_INVALID_ARGS;
    }
    buttonOption.SetButtonName(GetResizeStr(buttonName, STR_MAX_SIZE));
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
        "@ohos.notificationManager.notificationManager.ButtonOptionsInner", optCls, optObj) || optObj == nullptr) {
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
    const char *className = "@ohos.notificationManager.notificationManager.DoNotDisturbDateInner";
    if (!CreateClassObjByClassName(env, className, cls, outObj) || outObj == nullptr) {
        ANS_LOGE("WarpNotificationDoNotDisturbDate: create class faild");
        return false;
    }
    if (!EnumConvertNativeToAni(
        env, "@ohos.notificationManager.notificationManager.DoNotDisturbType",
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

bool SetCheckInfoContentType(ani_env *env, ani_object &obj, const std::string &name, ContentType type)
{
    if (env == nullptr || obj == nullptr || name.empty()) {
        ANS_LOGE("InvalidParam");
        return false;
    }
    STSContentType stsType = NOTIFICATION_CONTENT_BASIC_TEXT;
    ani_enum_item item;
    if (!StsContentTypeUtils::CToSts(type, stsType)) {
        ANS_LOGE("CToSts 'contentType' faild.");
        return false;
    }
    if (!EnumConvertNativeToAni(env, "@ohos.notificationManager.notificationManager.ContentType", stsType, item)) {
        ANS_LOGE("EnumConvertNativeToAni 'contentType' faild.");
        return false;
    }
    if (!SetPropertyByRef(env, obj, name.c_str(), static_cast<ani_ref>(item))) {
        ANS_LOGE("SetPropertyByRef 'contentType' faild.");
        return false;
    }
    return true;
}

bool SetCheckInfoSlotType(ani_env *env, ani_object &obj, const std::string &name, SlotType type)
{
    if (env == nullptr || obj == nullptr || name.empty()) {
        ANS_LOGE("InvalidParam");
        return false;
    }
    STSSlotType stsType = UNKNOWN_TYPE;
    ani_enum_item item;
    if (!StsSlotTypeUtils::CToSts(type, stsType)) {
        ANS_LOGE("CToSts 'slotType' faild.");
        return false;
    }
    if (!EnumConvertNativeToAni(env, "@ohos.notificationManager.notificationManager.SlotType", stsType, item)) {
        ANS_LOGE("EnumConvertNativeToAni 'slotType' faild.");
        return false;
    }
    if (!SetPropertyByRef(env, obj, name.c_str(), static_cast<ani_ref>(item))) {
        ANS_LOGE("SetPropertyByRef 'slotType' faild.");
        return false;
    }
    return true;
}

bool SetNotificationCheckInfoNumber(
    ani_env *env, const std::shared_ptr<OHOS::Notification::NotificationCheckInfo> &data, ani_object &outObj)
{
    ani_status status = ANI_OK;
    // notificationId: int;
    if (ANI_OK != (status = env->Object_SetPropertyByName_Int(
        outObj, "notificationId", data->GetNotifyId()))) {
            ANS_LOGE("WarpNotificationCheckInfo. set 'notificationId' faild. status %{public}d", status);
            return false;
        }
    // creatorUserId: int;
    if (ANI_OK != (status = env->Object_SetPropertyByName_Int(
        outObj, "creatorUserId", data->GetCreatorUserId()))) {
            ANS_LOGE("WarpNotificationCheckInfo. set 'creatorUserId' faild. status %{public}d", status);
            return false;
        }
    return true;
}

bool SetNotificationCheckInfoString(
    ani_env *env, const std::shared_ptr<OHOS::Notification::NotificationCheckInfo> &data, ani_object &outObj)
{
    // bundleName: string;
    if (!SetPropertyOptionalByString(env, outObj, "bundleName", data->GetPkgName())) {
        ANS_LOGE("WarpNotificationCheckInfo set 'bundleName' faild");
        return false;
    }
    // label?: string;
    if (!data->GetLabel().empty() && !SetPropertyOptionalByString(env, outObj, "label", data->GetLabel())) {
        ANS_LOGE("WarpNotificationCheckInfo set 'label' faild");
        return false;
    }
    return true;
}

bool SetNotificationCheckInfoEnum(
    ani_env *env, const std::shared_ptr<OHOS::Notification::NotificationCheckInfo> &data, ani_object &outObj)
{
    // contentType: ContentType;
    if (!SetCheckInfoContentType(env, outObj, "contentType", static_cast<ContentType>(data->GetContentType()))) {
        ANS_LOGE("WarpNotificationCheckInfo set 'contentType' faild");
        return false;
    }
    // slotType: SlotType;
    if (!SetCheckInfoSlotType(env, outObj, "slotType", static_cast<SlotType>(data->GetSlotType()))) {
        ANS_LOGE("WarpNotificationCheckInfo set 'slotType' faild");
        return false;
    }
    return true;
}

bool SetNotificationCheckInfo(
    ani_env *env, const std::shared_ptr<OHOS::Notification::NotificationCheckInfo> &data, ani_object &outObj)
{
    if (!SetNotificationCheckInfoNumber(env, data, outObj)) {
        ANS_LOGE("SetNotificationCheckInfoNumber faild");
        return false;
    }
    if (!SetNotificationCheckInfoString(env, data, outObj)) {
        ANS_LOGE("SetNotificationCheckInfoString faild");
        return false;
    }
    if (!SetNotificationCheckInfoEnum(env, data, outObj)) {
        ANS_LOGE("SetNotificationCheckInfoEnum faild");
        return false;
    }
    // extraInfos?: Record<string, Object>;
    if (data->GetExtraInfo() != nullptr) {
        ani_ref extraInfos = OHOS::AppExecFwk::WrapWantParams(env, *(data->GetExtraInfo()));
        if (extraInfos == nullptr) {
            ANS_LOGE("WrapWantParams 'extraInfos' faild");
            return false;
        }
        if (!SetPropertyByRef(env, outObj, "extraInfos", extraInfos)) {
            ANS_LOGE("WarpNotificationCheckInfo set 'extraInfos' faild");
            return false;
        }
    }
    return true;
}

bool WarpNotificationCheckInfo(
    ani_env *env, const std::shared_ptr<OHOS::Notification::NotificationCheckInfo> &data, ani_object &outObj)
{
    ani_object obj;
    ani_class cls;
    if (env == nullptr || data == nullptr) {
        ANS_LOGE("InvalidParam");
        return false;
    }
    if (!CreateClassObjByClassName(
        env, "@ohos.notificationManager.notificationManager.NotificationCheckInfoInner", cls, obj)) {
            ANS_LOGE("WarpNotificationCheckInfo create faild");
            return false;
        }
    if (!SetNotificationCheckInfo(env, data, obj)) {
        ANS_LOGE("SetNotificationCheckInfo faild");
        return false;
    }
    outObj = obj;
    return true;
}

void GetDoNotDisturbDateByDoNotDisturbType(ani_env *env, ani_object obj, NotificationDoNotDisturbDate &doNotDisturbDate)
{
    ANS_LOGD("GetDoNotDisturbDateByDoNotDisturbType start");
    if (env == nullptr || obj == nullptr) {
        ANS_LOGE("GetDoNotDisturbDateByDoNotDisturbType failed, has nullptr");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_boolean isUndefined = ANI_OK;
    ani_ref doNotDisturbTypeRef = {};
    if (ANI_OK != (status = GetPropertyRef(env, obj, "type", isUndefined, doNotDisturbTypeRef))
        || isUndefined == ANI_TRUE || doNotDisturbTypeRef == nullptr) {
        ANS_LOGE("GetDoNotDisturbDateByDoNotDisturbType: get Ref failed");
        return;
    }
    NotificationConstant::DoNotDisturbType type = NotificationConstant::DoNotDisturbType::NONE;

    if (!DoNotDisturbTypeEtsToC(env, static_cast<ani_enum_item>(doNotDisturbTypeRef), type)) {
        ANS_LOGE("GetDoNotDisturbDateByDoNotDisturbType: SlotTypeEtsToC failed");
        return;
    }
    doNotDisturbDate.SetDoNotDisturbType(type);
    ANS_LOGD("GetDoNotDisturbDateByDoNotDisturbType end");
}

bool UnWarpNotificationDoNotDisturbDate(
    ani_env* env,
    const ani_object doNotDisturbDateObj,
    NotificationDoNotDisturbDate& doNotDisturbDate)
{
    ani_boolean isUndefined = false;
    ani_ref mDate = nullptr;
    if (env == nullptr) {
        ANS_LOGE("UnWarpNotificationDoNotDisturbDate: Invalid input parameters");
        return false;
    }
    GetDoNotDisturbDateByDoNotDisturbType(env, doNotDisturbDateObj, doNotDisturbDate);

    int64_t beginTime = 0;
    if (ANI_OK == GetPropertyRef(env, doNotDisturbDateObj, "begin", isUndefined, mDate)
        && isUndefined == ANI_FALSE) {
        if (mDate == nullptr || !GetDateByObject(env, static_cast<ani_object>(mDate), beginTime)) {
            ANS_LOGE("get begin time failed");
            return false;
        }
    }
    int64_t endTime = 0;
    if (ANI_OK == GetPropertyRef(env, doNotDisturbDateObj, "end", isUndefined, mDate)
        && isUndefined == ANI_FALSE) {
        if (mDate == nullptr || !GetDateByObject(env, static_cast<ani_object>(mDate), endTime)) {
            ANS_LOGE("get end time failed");
            return false;
        }
    }
    if (beginTime >= endTime) {
        ANS_LOGE("Invalid time range");
        return false;
    }
    doNotDisturbDate.SetBeginDate(static_cast<int32_t>(beginTime));
    doNotDisturbDate.SetEndDate(static_cast<int32_t>(endTime));
    ANS_LOGD("Successfully parsed DoNotDisturbDate");
    return true;
}
} // namespace NotificationSts
} // OHOS
