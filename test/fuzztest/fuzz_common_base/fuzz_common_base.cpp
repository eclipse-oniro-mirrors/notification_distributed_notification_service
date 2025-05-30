/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include <iostream>
#include <fstream>

extern "C" {
using namespace OHOS::Security::AccessToken;

void MockRandomToken(FuzzedDataProvider *fdp, const std::vector<std::string> &permissions)
{
    int caseNum = fdp->ConsumeIntegralInRange(0, 3);
    switch (caseNum) {
        case 0:
            NativeTokenGet(permissions);
            break;
        case 1:
            SystemHapTokenGet(permissions);
            break;
        case 2:
        default:
            NormalHapTokenGet();
    }
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
        .domain = "test.fuzz.ans",
        .permList = {},
        .permStateList = {}
    };
    
    for (auto permission : permissions) {
        PermissionStateFull permStateFull = {
            .permissionName = permission,
            .isGeneral = false,
            .resDeviceID = {"device 1", "device 2"},
            .grantStatus = {PermissionState::PERMISSION_GRANTED, PermissionState::PERMISSION_GRANTED},
            .grantFlags = {1, 2}
        };
        PermissionDef permDef = {
            .permissionName = permission,
            .bundleName = "test.fuzz.ans",
            .grantMode = 1,
            .availableLevel = APL_SYSTEM_CORE,
            .label = "label3",
            .labelId = 1,
            .description = "break the door",
            .descriptionId = 1,
        };
        hapPolicyPrams.permList.emplace_back(permDef);
        hapPolicyPrams.permStateList.emplace_back(permStateFull);
    }

    HapInfoParams hapInfoParams = {
        .userID = 100,
        .bundleName = "test.fuzz.ans",
        .instIndex = 0,
        .appIDDesc = "test.fuzz.ans",
        .apiVersion = 12,
        .isSystemApp = true
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(hapInfoParams, hapPolicyPrams);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void NormalHapTokenGet()
{
    HapPolicyParams hapPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.fuzz.ans",
        .permList = {},
        .permStateList = {}
    };

    HapInfoParams hapInfoParams = {
        .userID = 100,
        .bundleName = "test.fuzz.ans",
        .instIndex = 0,
        .appIDDesc = "test.fuzz.ans",
        .apiVersion = 12,
        .isSystemApp = false
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(hapInfoParams, hapPolicyPrams);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}
}