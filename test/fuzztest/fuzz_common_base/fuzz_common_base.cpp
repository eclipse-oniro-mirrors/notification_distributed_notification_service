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

#include "accesstoken_kit.h"
#include "access_token.h"
#include "access_token_error.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "fuzz_common_base.h"

extern "C" {
static constexpr uint32_t U32_AT_SIZE     = 3;
static constexpr uint32_t MAX_MEMORY_SIZE = 4 * 1024 * 1024;

using namespace OHOS::Security::AccessToken;

uint32_t GetU32Size()
{
    return U32_AT_SIZE;
}

uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 16) | (ptr[1] << 8) | ptr[2];
}

char* ParseData(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return nullptr;
    }

    if (size > MAX_MEMORY_SIZE) {
        return nullptr;
    }

    char* ch = (char *)malloc(size + 1);
    if (ch == nullptr) {
        return nullptr;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return nullptr;
    }

    return ch;
}

void NativeTokenGet(const std::vector<std::string> &permissions)
{
    uint64_t tokenId;
    size_t size = permissions.size();
    const char **perms = new const char *[size];
    for (size_t i = 0; i < permissions.size(); i++) {
        perms[i] = permissions[i].c_str();
    }
    
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = size,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
    };

    infoInstance.processName = "AnsFuzzTest";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete []perms;
}

void SystemHapTokenGet(const std::vector<std::string> &permissions)
{

    HapPolicyParams hapPolicyPrams = {
        .apl = APL_SYSTEM_CORE,
        .domain = "com.ohos.notificationdialog",
        .permList = {},
        .permStateList = {}
    };
    
    for (auto permission : permissions) {
        PermissionStateFull permStateFull = {
            .permissionName = permission,
            .isGeneral = true,
            .resDeviceID = {"local"},
            .grantStatus = {PermissionState::PERMISSION_GRANTED},
            .grantFlags = {1}
        };
        PermissionDef permDef = {
            .permissionName = permission,
            .bundleName = "com.ohos.notificationdialog",
            .grantMode = 1,
            .availableLevel = APL_NORMAL,
            .label = "label",
            .labelId = 1,
            .description = "break the door",
            .descriptionId = 1,
        };
        hapPolicyPrams.permList.emplace_back(permDef);
        hapPolicyPrams.permStateList.emplace_back(permStateFull);
    }

    HapInfoParams hapInfoParams = {
        .userID = 100,
        .bundleName = "com.ohos.notificationdialog",
        .instIndex = 0,
        .appIDDesc = "com.ohos.notificationdialog",
        .apiVersion = 12,
        .isSystemApp = true
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(hapInfoParams, hapPolicyPrams);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}
}