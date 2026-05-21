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

#include "mock_dlfcn.h"

#include <cstring>
#include <dlfcn.h>
#include <string>

#include "notification_request.h"

using OHOS::sptr;
using OHOS::Notification::NotificationRequest;
using OHOS::Notification::Infra::Test::g_mockDlfcn;
using OHOS::Notification::Infra::Test::MockDlfcnState;

static void* const MOCK_HANDLE = reinterpret_cast<void*>(0x12345678);
static const char* VOICE_SO_NAME = "libnotification_voice.z.so";

static int32_t MockGenerateVoiceContent(
    const sptr<NotificationRequest>&, std::string& content, std::string& externInfo)
{
    content = "mock_content";
    externInfo = "mock_extern";
    return g_mockDlfcn.generateResult;
}

static int32_t MockUpdateVoiceConfig(const std::string& configs)
{
    g_mockDlfcn.lastUpdateConfig = configs;
    return g_mockDlfcn.updateResult;
}

static int32_t MockNotifyVoiceEvent(const std::string& event, const sptr<NotificationRequest>&)
{
    g_mockDlfcn.lastNotifyEvent = event;
    return g_mockDlfcn.notifyResult;
}

namespace OHOS {
namespace Notification {
namespace Infra {
namespace Test {

MockDlfcnState g_mockDlfcn;

void ResetMockDlfcn()
{
    g_mockDlfcn = {};
    g_mockDlfcn.dlsymSuccessMap["GenerateVoiceContent"] = true;
    g_mockDlfcn.dlsymSuccessMap["UpdateVoiceConfig"] = true;
    g_mockDlfcn.dlsymSuccessMap["NotifyVoiceEvent"] = true;
}

}  // namespace Test
}  // namespace Infra
}  // namespace Notification
}  // namespace OHOS

extern void* __real_dlopen(const char* filename, int flag);
extern void* __wrap_dlopen(const char* filename, int flag)
{
    if (filename != nullptr && strcmp(filename, VOICE_SO_NAME) == 0) {
        if (g_mockDlfcn.dlopenSuccess) {
            return MOCK_HANDLE;
        }
        return nullptr;
    }
    return __real_dlopen(filename, flag);
}

extern void* __real_dlsym(void* handle, const char* symbol);
extern void* __wrap_dlsym(void* handle, const char* symbol)
{
    if (handle == MOCK_HANDLE) {
        if (strcmp(symbol, "GenerateVoiceContent") == 0 && g_mockDlfcn.dlsymSuccessMap["GenerateVoiceContent"]) {
            return reinterpret_cast<void*>(MockGenerateVoiceContent);
        }
        if (strcmp(symbol, "UpdateVoiceConfig") == 0 && g_mockDlfcn.dlsymSuccessMap["UpdateVoiceConfig"]) {
            return reinterpret_cast<void*>(MockUpdateVoiceConfig);
        }
        if (strcmp(symbol, "NotifyVoiceEvent") == 0 && g_mockDlfcn.dlsymSuccessMap["NotifyVoiceEvent"]) {
            return reinterpret_cast<void*>(MockNotifyVoiceEvent);
        }
        return nullptr;
    }
    return __real_dlsym(handle, symbol);
}

extern int __real_dlclose(void* handle);
extern int __wrap_dlclose(void* handle)
{
    if (handle == MOCK_HANDLE) {
        g_mockDlfcn.dlcloseCalled = true;
        return 0;
    }
    return __real_dlclose(handle);
}