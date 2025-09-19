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

#include "ani_push_callback.h"
#include "ans_log_wrapper.h"
#include "sts_notification_manager.h"
#include "sts_common.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace OHOS::Notification;
using namespace OHOS::NotificationSts;
StsPushCallBack::StsPushCallBack(ani_env *env)
{
    if (env == nullptr || env->GetVM(&vm_) != ANI_OK) {
        ANS_LOGE("InvalidParam 'env'");
    }
}

StsPushCallBack::~StsPushCallBack()
{
}

int32_t StsPushCallBack::OnCheckNotification(
    const std::string &notificationData, const std::shared_ptr<PushCallBackParam> &pushCallBackParam)
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> l(mutexlock);
    if (vm_ == nullptr || pushCallBackParam == nullptr) {
        ANS_LOGE("InvalidParam");
        return ERR_INVALID_STATE;
    }
    ani_env* env;
    ani_status aniResult = ANI_ERROR;
    if (ANI_OK != (aniResult = vm_->GetEnv(ANI_VERSION_1, &env))) {
        ANS_LOGD("GetEnv error. result: %{public}d.", aniResult);
        return ERR_INVALID_STATE;
    }
    return CheckNotification(env, notificationData, pushCallBackParam);
}

void StsPushCallBack::SetJsPushCallBackObject(
    ani_env *env, NotificationConstant::SlotType slotType, ani_ref pushCallBackObject)
{
    ANS_LOGD("enter");
    if (env == nullptr || pushCallBackObject == nullptr) {
        ANS_LOGE("InvalidParam");
        return;
    }
    ani_ref pushCheckObject;
    ani_status status = ANI_OK;
    if (ANI_OK != (status = env->GlobalReference_Create(pushCallBackObject, &pushCheckObject))) {
        ANS_LOGE("GlobalReference_Create pushCallBackObject faild. status %{public}d", status);
        return;
    }
    pushCallBackObjects_.insert_or_assign(slotType, pushCheckObject);
}

void StsPushCallBack::HandleCheckCallback(
    ani_env *env, ani_fn_object fn, ani_object value, const std::shared_ptr<PushCallBackParam> &pushCallBackParam)
{
    ANS_LOGD("enter");
    if (env == nullptr || fn == nullptr || value == nullptr || pushCallBackParam == nullptr) {
        ANS_LOGE("pushCallBackObjects is nullptr");
        return;
    }
    std::vector<ani_ref> vec;
    vec.push_back(value);
    ani_ref funcResult;
    ani_status status = ANI_OK;
    if (ANI_OK != (status = env->FunctionalObject_Call(fn, vec.size(), vec.data(), &funcResult))) {
        ANS_LOGE("FunctionalObject_Call faild. status %{public}d", status);
        return;
    }
    ResultParam result;
    if (!WarpFunctionResult(env, static_cast<ani_object>(funcResult), result)) {
        ANS_LOGE("WarpFunctionResult faild");
        return;
    }
    std::unique_lock<ffrt::mutex> uniqueLock(pushCallBackParam->callBackMutex);
    pushCallBackParam->result = result.code;
    pushCallBackParam->ready = true;
    pushCallBackParam->callBackCondition.notify_all();
    ANS_LOGD("done");
}

int32_t StsPushCallBack::CheckNotification(
    ani_env *env,
    const std::string &notificationData,
    const std::shared_ptr<PushCallBackParam> &pushCallBackParam)
{
    ANS_LOGD("enter");
    auto checkInfo = std::make_shared<NotificationCheckInfo>();
    checkInfo->ConvertJsonStringToValue(notificationData);
    NotificationConstant::SlotType outSlotType = static_cast<NotificationConstant::SlotType>(checkInfo->GetSlotType());
if (pushCallBackObjects_.find(outSlotType) == pushCallBackObjects_.end()) {
        ANS_LOGE("pushCallBackObjects is nullptr");
        return ERR_INVALID_STATE;
    }

    ani_object checkInfoObj;
    if (!WarpNotificationCheckInfo(env, checkInfo, checkInfoObj) || checkInfoObj == nullptr) {
        ANS_LOGE("WarpNotificationCheckInfo faild");
        return ERR_INVALID_STATE;
    }
    HandleCheckCallback(
        env, static_cast<ani_fn_object>(pushCallBackObjects_[outSlotType]), checkInfoObj, pushCallBackParam);
    return ERR_OK;
}

bool StsPushCallBack::WarpFunctionResult(ani_env *env, ani_object obj, ResultParam &result)
{
    ANS_LOGD("enter");
    if (env == nullptr || obj == nullptr) return false;
    ani_status status = ANI_OK;
    ani_int code;
    ani_ref msg;
    std::string message = "";
    if (ANI_OK != (status = env->Object_GetPropertyByName_Int(obj, "code", &code))) {
        ANS_LOGE("WarpFunctionResult. code faild. status %{public}d", status);
        return false;
    }
    if (ANI_OK != (status = env->Object_GetPropertyByName_Ref(obj, "message", &msg))) {
        ANS_LOGE("WarpFunctionResult. message faild. status %{public}d", status);
        return false;
    }
    if (ANI_OK != (status = GetStringByAniString(env, static_cast<ani_string>(msg), message))) {
        ANS_LOGE("GetStringByAniString faild. status %{public}d", status);
        return false;
    }
    result.code = code;
    result.msg = message;
    ANS_LOGD("WarpFunctionResult: code %{public}d message %{public}s", result.code, result.msg.c_str());
    return true;
}
}
}