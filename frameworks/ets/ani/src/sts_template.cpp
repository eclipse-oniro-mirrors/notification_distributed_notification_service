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
    ani_status status = ANI_ERROR;
    ani_ref nameRef;
    if (ANI_OK != (status = env->Object_CallMethodByName_Ref(aniObj, "<get>name",":Lstd/core/String;", &nameRef))) {
        return status;
    }
    std::string nameStr = "";
    if (ANI_OK != (status = GetStringByAniString(env, static_cast<ani_string>(nameRef), nameStr))) {
        return status;
    }
    ani_ref dataRef;
    if (ANI_OK != (status = env->Object_GetPropertyByName_Ref(aniObj, "data", &dataRef))) {
        return status;
    }
    WantParams wantParams;
    if(!UnwrapWantParams(env, dataRef, wantParams)) {
        return ANI_ERROR;
    }
    tmplate.SetTemplateName(nameStr);
    tmplate.SetTemplateData(std::make_shared<WantParams>(wantParams));
    return status;
}

ani_object WrapNotificationTemplate(ani_env* env, const std::shared_ptr<NotificationTemplate> &templ)
{
    if (templ == nullptr) {
        ANS_LOGE("templ is null");
        return nullptr;
    }
    ani_object templateObject = nullptr;
    ani_class templateCls = nullptr;
    RETURN_NULL_IF_FALSE(CreateClassObjByClassName(env,
        "Lnotification/notificationTemplate/NotificationTemplateInner;", templateCls, templateObject));
    // name: string;
    ani_string stringValue = nullptr;
    RETURN_NULL_IF_FALSE(GetAniStringByString(env, templ->GetTemplateName(), stringValue));
    RETURN_NULL_IF_FALSE(CallSetter(env, templateCls, templateObject, "name", stringValue));
    // data: Record<string, Object>;
    std::shared_ptr<AAFwk::WantParams> data = templ->GetTemplateData();
    if (data) {
        ani_ref valueRef = OHOS::AppExecFwk::WrapWantParams(env, *data);
        RETURN_NULL_IF_FALSE(CallSetter(env, templateCls, templateObject, "data", valueRef));
    }
    return templateObject;
}

} // namespace NotificationSts
} // OHOS
