/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "napi_common_want.h"

namespace OHOS {
namespace NotificationNapi {
napi_value Common::SetNotificationParameters(const napi_env &env, const sptr<NotificationParameters> parameters,
    napi_value &result)
{
    napi_value value = nullptr;
    std::string wantAction = parameters->GetWantAction();
    napi_create_string_utf8(env, wantAction.c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "wantAction", value);

    std::string wantUri = parameters->GetWantUri();
    napi_create_string_utf8(env, wantUri.c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "wantUri", value);

    auto wantParams = parameters->GetWantParameters();
    if (wantParams != nullptr) {
        value = OHOS::AppExecFwk::WrapWantParams(env, *wantParams);
        napi_set_named_property(env, result, "wantParameters", value);
    }
    return result;
}
}
}