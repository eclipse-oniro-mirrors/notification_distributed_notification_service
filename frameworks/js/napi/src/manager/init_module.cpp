/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "init_module.h"
#include "constant.h"
#include "napi_publish.h"
#include "pixel_map_napi.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

EXTERN_C_START

napi_value NotificationManagerInit(napi_env env, napi_value exports)
{
    ANS_LOGI("NotificationManagerInit start");

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("publish", NapiPublish),
        DECLARE_NAPI_FUNCTION("publishAsBundle", NapiPublishAsBundle),
        DECLARE_NAPI_FUNCTION("show", NapiShowNotification),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));

    return exports;
}

/*
 * Module export function
 */
static napi_value Init(napi_env env, napi_value exports)
{
    /*
     * Propertise define
     */
    NotificationManagerInit(env, exports);
    ConstantInit(env, exports);
    OHOS::Media::PixelMapNapi::Init(env, exports);

    return exports;
}

/*
 * Module register function
 */
__attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&_module_manager);
}
EXTERN_C_END
}  // namespace NotificationNapi
}  // namespace OHOS