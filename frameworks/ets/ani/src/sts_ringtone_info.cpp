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

#include "sts_ringtone_info.h"

#include "ans_log_wrapper.h"
#include "sts_common.h"
#include "sts_notification_manager.h"

namespace OHOS {
namespace NotificationSts {
namespace {
bool UnwrapRingtoneStringInfo(ani_env *env, ani_object obj, NotificationRingtoneInfo &ringtoneInfo)
{
    // ringtoneTitle?: string
    ani_boolean isUndefined = ANI_TRUE;
    std::string ringtoneTitle;
    if (ANI_OK == GetPropertyString(env, obj, "ringtoneTitle", isUndefined, ringtoneTitle)) {
        ringtoneInfo.SetRingtoneTitle(GetResizeStr(ringtoneTitle, STR_MAX_SIZE));
    } else {
        ANS_LOGD("UnwrapRingtoneInfo get ringtoneTitle failed.");
    }

    // ringtoneFileName?: string
    isUndefined = ANI_TRUE;
    std::string ringtoneFileName;
    if (ANI_OK == GetPropertyString(env, obj, "ringtoneFileName", isUndefined, ringtoneFileName)) {
        ringtoneInfo.SetRingtoneFileName(GetResizeStr(ringtoneFileName, STR_MAX_SIZE));
    } else {
        ANS_LOGD("UnwrapRingtoneInfo get ringtoneFileName failed.");
    }

    // ringtoneUri?: string
    isUndefined = ANI_TRUE;
    std::string ringtoneUri;
    if (ANI_OK == GetPropertyString(env, obj, "ringtoneUri", isUndefined, ringtoneUri)) {
        ringtoneInfo.SetRingtoneUri(GetResizeStr(ringtoneUri, STR_MAX_SIZE));
    } else {
        ANS_LOGD("UnwrapRingtoneInfo get ringtoneUri failed.");
    }
    return true;
}

bool WrapRingtoneStringInfo(ani_env *env, ani_class &ringtoneInfoClass,
    const NotificationRingtoneInfo &ringtoneInfo, ani_object &ringtoneInfoObject)
{
    ani_status status = ANI_ERROR;
    ani_string stringValue = nullptr;
    if (ANI_OK != (status = GetAniStringByString(env, ringtoneInfo.GetRingtoneTitle(), stringValue))) {
        ANS_LOGE("GetAniStringByString failed. status %{public}d", status);
        return false;
    }
    if (!CallSetter(env, ringtoneInfoClass, ringtoneInfoObject, "ringtoneTitle", stringValue)) {
        ANS_LOGE("set ringtoneTitle failed");
        return false;
    }

    status = ANI_ERROR;
    stringValue = nullptr;
    if (ANI_OK != (status = GetAniStringByString(env, ringtoneInfo.GetRingtoneFileName(), stringValue))) {
        ANS_LOGE("GetAniStringByString failed. status %{public}d", status);
        return false;
    }
    if (!CallSetter(env, ringtoneInfoClass, ringtoneInfoObject, "ringtoneFileName", stringValue)) {
        ANS_LOGE("set ringtoneFileName failed");
        return false;
    }

    status = ANI_ERROR;
    stringValue = nullptr;
    if (ANI_OK != (status = GetAniStringByString(env, ringtoneInfo.GetRingtoneUri(), stringValue))) {
        ANS_LOGE("GetAniStringByString failed. status %{public}d", status);
        return false;
    }
    if (!CallSetter(env, ringtoneInfoClass, ringtoneInfoObject, "ringtoneUri", stringValue)) {
        ANS_LOGE("set ringtoneUri failed");
        return false;
    }
    return true;
}
}  // namespace
bool UnwrapRingtoneInfo(ani_env *env, ani_object obj, NotificationRingtoneInfo &ringtoneInfo)
{
    ANS_LOGD("UnwrapRingtoneInfo call");
    if (env == nullptr || obj == nullptr) {
        ANS_LOGE("UnwrapRingtoneInfo failed, has nullptr");
        return false;
    }

    // ringtoneType: RingtoneType
    ani_status status = ANI_OK;
    ani_ref ringtoneAniType;
    STSRingtoneType stsRingtoneType = STSRingtoneType::RINGTONE_TYPE_NONE;
    RingtoneType ringtoneType = RingtoneType::RINGTONE_TYPE_NONE;
    if (ANI_OK != (status = env->Object_GetPropertyByName_Ref(obj, "ringtoneType", &ringtoneAniType))) {
        ANS_LOGE("UnwrapRingtoneInfo get ringtoneType failed. status %{public}d", status);
        return false;
    }
    if (ringtoneAniType == nullptr ||
        !EnumConvertAniToNative(env, static_cast<ani_enum_item>(ringtoneAniType), stsRingtoneType)) {
            ANS_LOGE("EnumConvertAniToNative stsRingtoneType failed");
            return false;
        }
    if (!StsRingtoneTypeUtils::StsToC(stsRingtoneType, ringtoneType)) {
        ANS_LOGE("StsToC ringtoneType failed");
        return false;
    }
    ringtoneInfo.SetRingtoneType(ringtoneType);
    UnwrapRingtoneStringInfo(env, obj, ringtoneInfo);

    ANS_LOGD("ringtoneType=%{public}d,ringtoneTitle=%{public}s,ringtoneFileName=%{public}s,ringtoneUri=%{public}s",
        ringtoneInfo.GetRingtoneType(), ringtoneInfo.GetRingtoneTitle().c_str(),
        ringtoneInfo.GetRingtoneFileName().c_str(), ringtoneInfo.GetRingtoneUri().c_str());
    return true;
}

bool WrapRingtoneInfo(ani_env *env, const NotificationRingtoneInfo &ringtoneInfo, ani_object &ringtoneInfoObject)
{
    ANS_LOGD("WrapRingtoneInfo call");
    if (env == nullptr) {
        ANS_LOGE("WrapRingtoneInfo failed, has nullptr");
        return false;
    }
    ani_class ringtoneInfoClass = nullptr;
    const char *className = "@ohos.notificationManager.notificationManager.RingtoneInfoInner";
    if (!CreateClassObjByClassName(env, className, ringtoneInfoClass, ringtoneInfoObject) ||
        ringtoneInfoObject == nullptr) {
        ANS_LOGE("WrapRingtoneInfo: create class failed");
        return false;
    }

    ani_enum_item ringtoneType;
    if (!EnumConvertNativeToAni(env,
        "@ohos.notificationManager.notificationManager.RingtoneType", ringtoneInfo.GetRingtoneType(), ringtoneType)) {
        ANS_LOGE("EnumConvert_NativeToSts failed");
        return false;
    }
    if (!SetPropertyByRef(env, ringtoneInfoObject, "ringtoneType", ringtoneType)) {
        ANS_LOGE("SetPropertyByRef 'ringtoneType' failed.");
        return false;
    }

    return WrapRingtoneStringInfo(env, ringtoneInfoClass, ringtoneInfo, ringtoneInfoObject);
}
}  // namespace NotificationSts
}  // namespace OHOS
