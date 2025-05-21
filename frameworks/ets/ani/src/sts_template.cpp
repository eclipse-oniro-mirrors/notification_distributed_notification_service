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
#include "sts_template.h" 

#include "sts_common.h"
#include "want_params.h"
#include "ani_common_want.h"

namespace OHOS {
namespace NotificationSts {
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

ani_status UnwrapNotificationTemplate(ani_env *env, ani_object aniObj, NotificationTemplate& tmplate)
{
    if (env == nullptr || aniObj == nullptr) {
        ANS_LOGE("invalid parameter value");
        return ANI_ERROR;
    }
    ani_status status = ANI_ERROR;
    ani_ref nameRef;
    if (ANI_OK != (status = env->Object_CallMethodByName_Ref(aniObj, "<get>name",":Lstd/core/String;", &nameRef))) {
        ANS_LOGE("Object_CallMethodByName_Ref faild. status %{public}d", status);
        return status;
    }
    std::string nameStr = "";
    if (ANI_OK != (status = GetStringByAniString(env, static_cast<ani_string>(nameRef), nameStr))) {
        ANS_LOGE("GetStringByAniString faild. status %{public}d", status);
        return status;
    }
    ani_ref dataRef;
    if (ANI_OK != (status = env->Object_GetPropertyByName_Ref(aniObj, "data", &dataRef))) {
        ANS_LOGE("Object_GetPropertyByName_Ref 'data' faild. status %{public}d", status);
        return status;
    }
    WantParams wantParams;
    if(!UnwrapWantParams(env, dataRef, wantParams)) {
        ANS_LOGE("UnwrapWantParams faild");
        return ANI_ERROR;
    }
    tmplate.SetTemplateName(nameStr);
    tmplate.SetTemplateData(std::make_shared<WantParams>(wantParams));
    return status;
}

ani_object WrapNotificationTemplate(ani_env* env, const std::shared_ptr<NotificationTemplate> &templ)
{
    if (templ == nullptr || env == nullptr) {
        ANS_LOGE("invalid parameter value");
        return nullptr;
    }
    ani_object templateObject = nullptr;
    ani_class templateCls = nullptr;
    ani_status status = ANI_OK;
    if (!CreateClassObjByClassName(env,
        "Lnotification/notificationTemplate/NotificationTemplateInner;", templateCls, templateObject)) {
            ANS_LOGE("Create faild");
            return nullptr;
        }
    // name: string;
    ani_string stringValue = nullptr;
    if (ANI_OK != (status = GetAniStringByString(env, templ->GetTemplateName(), stringValue))) {
        ANS_LOGE("GetAniStringByString faild. status %{public}d", status);
        return nullptr;
    }
    if (!CallSetter(env, templateCls, templateObject, "name", stringValue)) {
        ANS_LOGE("set 'name' faild.");
        return nullptr;
    }
    // data: Record<string, Object>;
    std::shared_ptr<AAFwk::WantParams> data = templ->GetTemplateData();
    if (data) {
        ani_ref valueRef = OHOS::AppExecFwk::WrapWantParams(env, *data);
        if (valueRef == nullptr) {
            ANS_LOGE("WrapWantParams faild");
            return nullptr;
        }
        if (!CallSetter(env, templateCls, templateObject, "data", valueRef)) {
            ANS_LOGE("set 'data' faild");
            return nullptr;
        }
    }
    return templateObject;
}

} // namespace NotificationSts
} // OHOS
