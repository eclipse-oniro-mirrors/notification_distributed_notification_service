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

#ifndef BASE_NOTIFICATION_MOCK_RESOURCE_MANAGER_H
#define BASE_NOTIFICATION_MOCK_RESOURCE_MANAGER_H

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <tuple>
#include "resource_manager.h"

namespace OHOS {
namespace Global {
namespace Resource {
namespace Mock {

extern bool g_mockGetResourceManagerReturnNull;

void MockGetRawFileDescriptorFail(bool fail);
void MockGetRawFileDescriptorReturn(int fd, long offset, long length);
void MockCloseRawFileDescriptorFail(bool fail);
void MockGetResourceManagerReturnNull(bool isNull);
void MockResetGetResourceManagerState();
void MockResetResourceManagerState();

class MockResourceManager : public ResourceManager {
public:
    MockResourceManager();
    ~MockResourceManager() override;

    bool AddResource(const char *path, const uint32_t &selectedTypes = SELECT_ALL,
        bool forceReload = false) override { return true; }

    RState UpdateResConfig(ResConfig &resConfig, bool isUpdateTheme = false) override { return SUCCESS; }

    void GetResConfig(ResConfig &resConfig) override {}

    RState GetResConfigById(uint32_t resId, ResConfig &resConfig, uint32_t density = 0) override { return SUCCESS; }

    RState GetResConfigByName(const std::string &name, const ResType type,
        ResConfig &resConfig, uint32_t density = 0) override { return SUCCESS; }

    RState GetStringById(uint32_t id, std::string &outValue) override { return SUCCESS; }

    RState GetStringByName(const char *name, std::string &outValue) override { return SUCCESS; }

    RState GetStringFormatById(std::string &outValue, uint32_t id, ...) override { return SUCCESS; }

    RState GetStringFormatByName(std::string &outValue, const char *name, ...) override { return SUCCESS; }

    RState GetStringArrayById(uint32_t id, std::vector<std::string> &outValue) override { return SUCCESS; }

    RState GetStringArrayByName(const char *name, std::vector<std::string> &outValue) override { return SUCCESS; }

    RState GetPatternById(uint32_t id, std::map<std::string, std::string> &outValue) override { return SUCCESS; }

    RState GetPatternByName(const char *name, std::map<std::string, std::string> &outValue) override { return SUCCESS; }

    RState GetPluralStringById(uint32_t id, int quantity, std::string &outValue) override { return SUCCESS; }

    RState GetPluralStringByName(const char *name, int quantity, std::string &outValue) override { return SUCCESS; }

    RState GetPluralStringByIdFormat(std::string &outValue, uint32_t id, int quantity, ...) override { return SUCCESS; }

    RState GetPluralStringByNameFormat(std::string &outValue, const char *name, int quantity, ...) override
    { return SUCCESS; }

    RState GetThemeById(uint32_t id, std::map<std::string, std::string> &outValue) override { return SUCCESS; }

    RState GetThemeByName(const char *name, std::map<std::string, std::string> &outValue) override { return SUCCESS; }

    RState GetBooleanById(uint32_t id, bool &outValue) override { return SUCCESS; }

    RState GetBooleanByName(const char *name, bool &outValue) override { return SUCCESS; }

    RState GetIntegerById(uint32_t id, int &outValue) override { return SUCCESS; }

    RState GetIntegerByName(const char *name, int &outValue) override { return SUCCESS; }

    RState GetFloatById(uint32_t id, float &outValue) override { return SUCCESS; }

    RState GetFloatById(uint32_t id, float &outValue, std::string &unit) override { return SUCCESS; }

    RState GetFloatByName(const char *name, float &outValue) override { return SUCCESS; }

    RState GetFloatByName(const char *name, float &outValue, std::string &unit) override { return SUCCESS; }

    RState GetIntArrayById(uint32_t id, std::vector<int> &outValue) override { return SUCCESS; }

    RState GetIntArrayByName(const char *name, std::vector<int> &outValue) override { return SUCCESS; }

    RState GetColorById(uint32_t id, uint32_t &outValue) override { return SUCCESS; }

    RState GetColorByName(const char *name, uint32_t &outValue) override { return SUCCESS; }

    RState GetProfileById(uint32_t id, std::string &outValue) override { return SUCCESS; }

    RState GetProfileByName(const char *name, std::string &outValue) override { return SUCCESS; }

    RState GetMediaById(uint32_t id, std::string &outValue, uint32_t density = 0) override { return SUCCESS; }

    RState GetMediaByName(const char *name, std::string &outValue, uint32_t density = 0) override { return SUCCESS; }

    RState GetRawFilePathByName(const std::string &name, std::string &outValue) override { return SUCCESS; }

    RState GetRawFileDescriptor(const std::string &name, RawFileDescriptor &descriptor) override;

    RState CloseRawFileDescriptor(const std::string &name) override;

    RState GetMediaDataById(uint32_t id, size_t& len, std::unique_ptr<uint8_t[]> &outValue,
        uint32_t density = 0) override { return SUCCESS; }

    RState GetMediaDataByName(const char *name, size_t& len, std::unique_ptr<uint8_t[]> &outValue,
        uint32_t density = 0) override { return SUCCESS; }

    RState GetMediaBase64DataById(uint32_t id, std::string &outValue, uint32_t density = 0) override { return SUCCESS; }

    RState GetMediaBase64DataByName(const char *name, std::string &outValue, uint32_t density = 0) override
    { return SUCCESS; }

    RState GetProfileDataById(uint32_t id, size_t &len, std::unique_ptr<uint8_t[]> &outValue) override
    { return SUCCESS; }

    RState GetProfileDataByName(const char *name, size_t &len, std::unique_ptr<uint8_t[]> &outValue) override
    { return SUCCESS; }

    RState GetRawFileFromHap(const std::string &rawFileName, size_t &len,
        std::unique_ptr<uint8_t[]> &outValue) override { return SUCCESS; }

    RState GetRawFileDescriptorFromHap(const std::string &rawFileName, RawFileDescriptor &descriptor) override
    { return SUCCESS; }

    RState IsLoadHap(std::string &hapPath) override { return SUCCESS; }

    RState GetRawFileList(const std::string &rawDirPath, std::vector<std::string> &rawfileList) override
    { return SUCCESS; }

    RState GetDrawableInfoById(uint32_t id, std::string &type, size_t &len,
        std::unique_ptr<uint8_t[]> &outValue, uint32_t density = 0) override { return SUCCESS; }

    RState GetDrawableInfoByName(const char *name, std::string &type, size_t &len,
        std::unique_ptr<uint8_t[]> &outValue, uint32_t density = 0) override { return SUCCESS; }

    bool AddResource(const std::string &path, const std::vector<std::string> &overlayPaths) override { return true; }

    bool RemoveResource(const std::string &path, const std::vector<std::string> &overlayPaths) override { return true; }

    RState GetStringFormatById(uint32_t id, std::string &outValue,
        std::vector<std::tuple<NapiValueType, std::string>> &jsParams) override { return SUCCESS; }

    RState GetStringFormatByName(const char *name, std::string &outValue,
        std::vector<std::tuple<NapiValueType, std::string>> &jsParams) override { return SUCCESS; }

    uint32_t GetResourceLimitKeys() override { return 0; }

    bool AddAppOverlay(const std::string &path) override { return true; }

    bool RemoveAppOverlay(const std::string &path) override { return true; }

    RState GetRawFdNdkFromHap(const std::string &rawFileName, RawFileDescriptor &descriptor) override
        { return SUCCESS; }

    RState GetResId(const std::string &resTypeName, uint32_t &resId) override { return SUCCESS; }

    void GetLocales(std::vector<std::string> &outValue, bool includeSystem = false) override {}

    RState GetDrawableInfoById(uint32_t id, std::tuple<std::string, size_t, std::string> &drawableInfo,
        std::unique_ptr<uint8_t[]> &outValue, uint32_t iconType, uint32_t density = 0) override { return SUCCESS; }

    RState GetDrawableInfoByName(const char *name, std::tuple<std::string, size_t, std::string> &drawableInfo,
        std::unique_ptr<uint8_t[]> &outValue, uint32_t iconType, uint32_t density = 0) override { return SUCCESS; }

    RState GetSymbolById(uint32_t id, uint32_t &outValue) override { return SUCCESS; }

    RState GetSymbolByName(const char *name, uint32_t &outValue) override { return SUCCESS; }

    RState GetThemeIcons(uint32_t resId, std::pair<std::unique_ptr<uint8_t[]>, size_t> &foregroundInfo,
        std::pair<std::unique_ptr<uint8_t[]>, size_t> &backgroundInfo, uint32_t density = 0,
        const std::string &abilityName = "") override { return SUCCESS; }

    std::string GetThemeMask() override { return ""; }

    bool HasIconInTheme(const std::string &bundleName) override { return false; }

    RState GetOtherIconsInfo(const std::string &iconName, std::unique_ptr<uint8_t[]> &outValue, size_t &len,
        bool isGlobalMask) override { return SUCCESS; }

    RState IsRawDirFromHap(const std::string &pathName, bool &outValue) override { return SUCCESS; }

    std::shared_ptr<ResourceManager> GetOverrideResourceManager(
        std::shared_ptr<ResConfig> overrideResConfig) override { return nullptr; }

    RState UpdateOverrideResConfig(ResConfig &resConfig) override { return SUCCESS; }

    void GetOverrideResConfig(ResConfig &resConfig) override {}

    RState GetDynamicIcon(const std::string &resName, std::pair<std::unique_ptr<uint8_t[]>, size_t> &iconInfo,
        uint32_t density = 0) override { return SUCCESS; }

    RState GetStringFormatById(std::string &outValue, uint32_t id, va_list args) override { return SUCCESS; }

    RState GetStringFormatByName(std::string &outValue, const char *name, va_list args) override { return SUCCESS; }

    RState GetFormatPluralStringById(std::string &outValue, uint32_t id, int quantity,
        std::vector<std::tuple<ResourceManager::NapiValueType, std::string>> &jsParams) override { return SUCCESS; }

    RState GetFormatPluralStringByName(std::string &outValue, const char *name, int quantity,
        std::vector<std::tuple<ResourceManager::NapiValueType, std::string>> &jsParams) override { return SUCCESS; }

    bool AddPatchResource(const char *path, const char *patchPath) override { return true; }

    RState GetThemeDataByName(const char *name, std::map<std::string, ResData> &outValue) override { return SUCCESS; }

    RState GetThemeDataById(uint32_t id, std::map<std::string, ResData> &outValue) override { return SUCCESS; }

    RState GetPatternDataById(uint32_t id, std::map<std::string, ResData> &outValue) override { return SUCCESS; }

    RState GetPatternDataByName(const char *name, std::map<std::string, ResData> &outValue) override { return SUCCESS; }

    RState GetFormatPluralStringById(std::string &outValue, uint32_t id, Quantity quantity,
        va_list args) override { return SUCCESS; }

    RState GetFormatPluralStringById(std::string &outValue, uint32_t id, Quantity quantity,
        std::vector<std::tuple<ResourceManager::NapiValueType, std::string>> &jsParams) override { return SUCCESS; }

    RState GetFormatPluralStringByName(std::string &outValue, const char *name, Quantity quantity,
        va_list args) override { return SUCCESS; }

    RState GetFormatPluralStringByName(std::string &outValue, const char *name, Quantity quantity,
        std::vector<std::tuple<ResourceManager::NapiValueType, std::string>> &jsParams) override { return SUCCESS; }

    RState GetResName(uint32_t id, std::string &outValue) override { return SUCCESS; }
};

}  // namespace Mock
}  // namespace Resource
}  // namespace Global
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_MOCK_RESOURCE_MANAGER_H