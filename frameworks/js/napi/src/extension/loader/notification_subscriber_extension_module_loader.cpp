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

#include "notification_subscriber_extension_module_loader.h"

#include "ans_log_wrapper.h"
#include "bundle_info.h"
#include "notification_subscriber_extension.h"
#include "js_notification_subscriber_extension.h"

#include <dlfcn.h>

constexpr char STS_NOTIFICATION_SUBSCRIBER_EXT_LIB_NAME[] = "libnotification_subscriber_extension_ani.z.so";
static constexpr char STS_NOTIFICATION_SUBSCRIBER_EXT_CREATE_FUNC[] =
    "OHOS_STS_NotificationSubscriberExtension_Creation";

namespace OHOS {
namespace EventFwk {
using namespace Notification;
using namespace NotificationNapi;
typedef NotificationSubscriberExtension* (*CREATE_FUNC)(const std::unique_ptr<AbilityRuntime::Runtime>& runtime);

__attribute__((no_sanitize("cfi"))) NotificationSubscriberExtension* CreateStsExtension(
    const std::unique_ptr<AbilityRuntime::Runtime>& runtime)
{
    void *handle = dlopen(STS_NOTIFICATION_SUBSCRIBER_EXT_LIB_NAME, RTLD_LAZY);
    if (handle == nullptr) {
        ANS_LOGE("open sts_notification_subscriber_extension library %{public}s failed, reason: %{public}sn",
            STS_NOTIFICATION_SUBSCRIBER_EXT_LIB_NAME, dlerror());
        return new (std::nothrow) NotificationSubscriberExtension();
    }

    auto func = reinterpret_cast<CREATE_FUNC>(dlsym(handle, STS_NOTIFICATION_SUBSCRIBER_EXT_CREATE_FUNC));
    if (func == nullptr) {
        dlclose(handle);
        ANS_LOGE("get sts_notification_subscriber_extension symbol %{public}s in %{public}s failed",
            STS_NOTIFICATION_SUBSCRIBER_EXT_CREATE_FUNC, STS_NOTIFICATION_SUBSCRIBER_EXT_LIB_NAME);
        return new (std::nothrow) NotificationSubscriberExtension();
    }

    auto instance = func(runtime);
    if (instance == nullptr) {
        dlclose(handle);
        ANS_LOGE("get sts_notification_subscriber_extension instance in %{public}s failed",
            STS_NOTIFICATION_SUBSCRIBER_EXT_CREATE_FUNC);
        return new (std::nothrow) NotificationSubscriberExtension();
    }
    return instance;
}

NotificationSubscriberExtensionModuleLoader::NotificationSubscriberExtensionModuleLoader() = default;
NotificationSubscriberExtensionModuleLoader::~NotificationSubscriberExtensionModuleLoader() = default;

AbilityRuntime::Extension* NotificationSubscriberExtensionModuleLoader::Create(
    const std::unique_ptr<AbilityRuntime::Runtime>& runtime) const
{
    ANS_LOGD("Create module loader.");
    if (!runtime) {
        return NotificationSubscriberExtension::Create(runtime);
    }

    ANS_LOGI("Create runtime");
    switch (runtime->GetLanguage()) {
        case AbilityRuntime::Runtime::Language::JS:
            return JsNotificationSubscriberExtension::Create(runtime);
        case AbilityRuntime::Runtime::Language::ETS:
            return CreateStsExtension(runtime);
        default:
            return NotificationSubscriberExtension::Create(runtime);
    }
}

std::map<std::string, std::string> NotificationSubscriberExtensionModuleLoader::GetParams()
{
    ANS_LOGD("Get params.");
    std::map<std::string, std::string> params;
    // type means extension type in ExtensionAbilityType of extension_ability_info.h
    params.insert(std::pair<std::string, std::string>(
        "type", std::to_string(static_cast<int32_t>(AppExecFwk::ExtensionAbilityType::NOTIFICATION_SUBSCRIBER))));
    // extension name
    params.insert(std::pair<std::string, std::string>("name", "NotificationSubscriber"));
    return params;
}

extern "C" __attribute__((visibility("default"))) void* OHOS_EXTENSION_GetExtensionModule()
{
    return &NotificationSubscriberExtensionModuleLoader::GetInstance();
}
} // namespace EventFwk
} // namespace OHOS
 