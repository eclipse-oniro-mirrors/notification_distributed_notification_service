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
using OHOS::Notification::NotificationBundleOption;
using OHOS::Notification::Infra::Test::g_mockDlfcn;
using OHOS::Notification::Infra::Test::MockDlfcnState;

static void* const MOCK_HANDLE = reinterpret_cast<void*>(0x12345678);
static const char* ALL_SCENARIOS_SO_NAME = "libliveview.z.so";

// Mock functions for required symbols
static int32_t MockUpdateLiveviewReminderFlags(const sptr<NotificationRequest>&)
{
    return 0;
}

static int32_t MockUpdateLiveviewVoiceContent(const sptr<NotificationRequest>&)
{
    return 0;
}

static int32_t MockUpdateLiveViewConfig(const std::string&)
{
    return 0;
}

static int32_t MockCheckLiveViewConfig(const std::string&, const std::string&, int32_t, bool&)
{
    return 0;
}

static int32_t MockGetLiveViewConfigVersion(int32_t&)
{
    return 0;
}

static int32_t MockNotifyLiveViewEvent(const std::string&, const sptr<NotificationBundleOption>&)
{
    return 0;
}

// Mock function for optional symbol: CheckLiveViewRights
static int32_t MockCheckLiveViewRights(const sptr<NotificationRequest>&)
{
    return g_mockDlfcn.checkLiveViewRightsResult;
}

namespace OHOS {
namespace Notification {
namespace Infra {
namespace Test {

MockDlfcnState g_mockDlfcn;

void ResetMockDlfcn()
{
    g_mockDlfcn = {};
    // Required symbols - all succeed by default
    g_mockDlfcn.dlsymSuccessMap["UpdateLiveviewReminderFlags"] = true;
    g_mockDlfcn.dlsymSuccessMap["UpdateLiveviewVoiceContent"] = true;
    g_mockDlfcn.dlsymSuccessMap["UpdateLiveViewConfig"] = true;
    g_mockDlfcn.dlsymSuccessMap["CheckLiveViewConfig"] = true;
    g_mockDlfcn.dlsymSuccessMap["GetLiveViewConfigVersion"] = true;
    g_mockDlfcn.dlsymSuccessMap["NotifyLiveViewEvent"] = true;
    // Optional symbols - all succeed by default
    g_mockDlfcn.dlsymSuccessMap["OnNotifyDelayedNotification"] = true;
    g_mockDlfcn.dlsymSuccessMap["OnNotifyClearNotification"] = true;
    g_mockDlfcn.dlsymSuccessMap["CheckLiveViewRights"] = true;
}

}  // namespace Test
}  // namespace Infra
}  // namespace Notification
}  // namespace OHOS

extern "C" void* __real_dlopen(const char* filename, int flag);
extern "C" void* __wrap_dlopen(const char* filename, int flag)
{
    if (filename != nullptr && strcmp(filename, ALL_SCENARIOS_SO_NAME) == 0) {
        if (g_mockDlfcn.dlopenSuccess) {
            return MOCK_HANDLE;
        }
        return nullptr;
    }
    return __real_dlopen(filename, flag);
}

extern "C" void* __real_dlsym(void* handle, const char* symbol);
extern "C" void* __wrap_dlsym(void* handle, const char* symbol)
{
    if (handle == MOCK_HANDLE) {
        // Required symbols
        if (strcmp(symbol, "UpdateLiveviewReminderFlags") == 0 &&
            g_mockDlfcn.dlsymSuccessMap["UpdateLiveviewReminderFlags"]) {
            return reinterpret_cast<void*>(MockUpdateLiveviewReminderFlags);
        }
        if (strcmp(symbol, "UpdateLiveviewVoiceContent") == 0 &&
            g_mockDlfcn.dlsymSuccessMap["UpdateLiveviewVoiceContent"]) {
            return reinterpret_cast<void*>(MockUpdateLiveviewVoiceContent);
        }
        if (strcmp(symbol, "UpdateLiveViewConfig") == 0 &&
            g_mockDlfcn.dlsymSuccessMap["UpdateLiveViewConfig"]) {
            return reinterpret_cast<void*>(MockUpdateLiveViewConfig);
        }
        if (strcmp(symbol, "CheckLiveViewConfig") == 0 &&
            g_mockDlfcn.dlsymSuccessMap["CheckLiveViewConfig"]) {
            return reinterpret_cast<void*>(MockCheckLiveViewConfig);
        }
        if (strcmp(symbol, "GetLiveViewConfigVersion") == 0 &&
            g_mockDlfcn.dlsymSuccessMap["GetLiveViewConfigVersion"]) {
            return reinterpret_cast<void*>(MockGetLiveViewConfigVersion);
        }
        if (strcmp(symbol, "NotifyLiveViewEvent") == 0 &&
            g_mockDlfcn.dlsymSuccessMap["NotifyLiveViewEvent"]) {
            return reinterpret_cast<void*>(MockNotifyLiveViewEvent);
        }
        // Optional symbols
        if (strcmp(symbol, "CheckLiveViewRights") == 0 &&
            g_mockDlfcn.dlsymSuccessMap["CheckLiveViewRights"]) {
            return reinterpret_cast<void*>(MockCheckLiveViewRights);
        }
        return nullptr;
    }
    return __real_dlsym(handle, symbol);
}

extern "C" int __real_dlclose(void* handle);
extern "C" int __wrap_dlclose(void* handle)
{
    if (handle == MOCK_HANDLE) {
        g_mockDlfcn.dlcloseCalled = true;
        return 0;
    }
    return __real_dlclose(handle);
}
