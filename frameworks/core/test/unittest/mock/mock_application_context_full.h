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

#ifndef BASE_NOTIFICATION_MOCK_APPLICATION_CONTEXT_FULL_H
#define BASE_NOTIFICATION_MOCK_APPLICATION_CONTEXT_FULL_H

#include "application_context.h"
#include "resource_manager.h"

namespace OHOS {
namespace AbilityRuntime {
namespace Mock {

void MockCreateBundleContextReturnNull(bool isNull);
void MockResetCreateBundleContextState();

class MockApplicationContext : public ApplicationContext {
public:
    MockApplicationContext();
    ~MockApplicationContext() override = default;

    std::shared_ptr<Context> CreateBundleContext(const std::string &bundleName) override;
    std::shared_ptr<Global::Resource::ResourceManager> GetResourceManager() const override;
    std::string GetBundleName() const override;

private:
    std::shared_ptr<Global::Resource::ResourceManager> mockResourceManager_;
};

class MockContext : public Context {
public:
    explicit MockContext(const std::string &bundleName = "com.test");
    ~MockContext() override = default;

    std::string GetBundleName() const override;
    std::shared_ptr<Context> CreateBundleContext(const std::string &bundleName) override;
    std::shared_ptr<Global::Resource::ResourceManager> GetResourceManager() const override;
    std::shared_ptr<AppExecFwk::ApplicationInfo> GetApplicationInfo() const override { return nullptr; }
    std::string GetBundleCodePath() const override { return ""; }
    std::shared_ptr<AppExecFwk::HapModuleInfo> GetHapModuleInfo() const override { return nullptr; }
    std::string GetBundleCodeDir() override { return ""; }
    std::string GetCacheDir() override { return ""; }
    std::string GetTempDir() override { return ""; }
    std::string GetFilesDir() override { return ""; }
    std::string GetResourceDir(const std::string &moduleName = "") override { return ""; }
    bool IsUpdatingConfigurations() override { return false; }
    bool PrintDrawnCompleted() override { return false; }
    std::string GetDatabaseDir() override { return ""; }
    int32_t GetSystemDatabaseDir(const std::string &groupId, bool checkExist, std::string &databaseDir) override
    { return 0; }
    std::string GetPreferencesDir() override { return ""; }
    int32_t GetSystemPreferencesDir(const std::string &groupId, bool checkExist,
        std::string &preferencesDir) override { return 0; }
    std::string GetGroupDir(std::string groupId) override { return ""; }
    std::string GetDistributedFilesDir() override { return ""; }
    std::string GetCloudFileDir() override { return ""; }
    std::string GetLogFileDir() override { return ""; }
    sptr<IRemoteObject> GetToken() override { return nullptr; }
    void SetToken(const sptr<IRemoteObject> &token) override {}
    void SwitchArea(int mode) override {}
    std::shared_ptr<Context> CreateModuleContext(const std::string &moduleName) override { return nullptr; }
    std::shared_ptr<Context> CreateModuleContext(const std::string &bundleName,
        const std::string &moduleName) override { return nullptr; }
    std::shared_ptr<Global::Resource::ResourceManager> CreateModuleResourceManager(
        const std::string &bundleName, const std::string &moduleName) override { return nullptr; }
    int32_t CreateSystemHspModuleResourceManager(const std::string &bundleName,
        const std::string &moduleName,
        std::shared_ptr<Global::Resource::ResourceManager> &resourceManager) override { return 0; }
    int GetArea() override { return 0; }
    std::string GetProcessName() override { return ""; }
    std::shared_ptr<AppExecFwk::Configuration> GetConfiguration() const override { return nullptr; }
    std::string GetBaseDir() const override { return ""; }
    Global::Resource::DeviceType GetDeviceType() const override { return Global::Resource::DeviceType::DEVICE_PHONE; }
    std::shared_ptr<Context> CreateAreaModeContext(int areaMode) override { return nullptr; }
    std::shared_ptr<Context> CreateModuleOrPluginContext(const std::string &bundleName,
        const std::string &moduleName) override { return nullptr; }
#ifdef SUPPORT_GRAPHICS
    std::shared_ptr<Context> CreateDisplayContext(uint64_t displayId) override { return nullptr; }
#endif

private:
    std::string bundleName_;
    std::shared_ptr<Global::Resource::ResourceManager> mockResourceManager_;
};

}  // namespace Mock
}  // namespace AbilityRuntime
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_MOCK_APPLICATION_CONTEXT_FULL_H