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

#include <dlfcn.h>
#include <cstring>
#include <string>

namespace OHOS::Notification::Infra::Test {

static void* const MOCK_HANDLE = reinterpret_cast<void*>(0x12345678);
static const char* VOICE_SO_NAME = "libnotification_voice.z.so";

MockDlfcnState g_mockDlfcn;

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

void ResetMockDlfcn()
{
    g_mockDlfcn = {};
    g_mockDlfcn.dlsymSuccessMap["GenerateVoiceContent"] = true;
    g_mockDlfcn.dlsymSuccessMap["UpdateVoiceConfig"] = true;
    g_mockDlfcn.dlsymSuccessMap["NotifyVoiceEvent"] = true;
}

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
        auto it = g_mockDlfcn.dlsymSuccessMap.find(std::string(symbol));
        if (it != g_mockDlfcn.dlsymSuccessMap.end() && it->second) {
            if (std::string(symbol) == "GenerateVoiceContent") {
                return reinterpret_cast<void*>(MockGenerateVoiceContent);
            }
            if (std::string(symbol) == "UpdateVoiceConfig") {
                return reinterpret_cast<void*>(MockUpdateVoiceConfig);
            }
            if (std::string(symbol) == "NotifyVoiceEvent") {
                return reinterpret_cast<void*>(MockNotifyVoiceEvent);
            }
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

}  // namespace Test
}  // namespace Infra
}  // namespace Notification
}  // namespace OHOS