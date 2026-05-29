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

#include "mock_application_context_full.h"
#include "mock_resource_manager.h"

namespace {
bool g_mockCreateBundleContextReturnNull = false;
}

namespace OHOS {
namespace AbilityRuntime {
namespace Mock {

void MockCreateBundleContextReturnNull(bool isNull)
{
    g_mockCreateBundleContextReturnNull = isNull;
}

void MockResetCreateBundleContextState()
{
    g_mockCreateBundleContextReturnNull = false;
}

MockApplicationContext::MockApplicationContext()
{
    mockResourceManager_ = std::make_shared<Global::Resource::Mock::MockResourceManager>();
}

std::shared_ptr<Context> MockApplicationContext::CreateBundleContext(const std::string &bundleName)
{
    if (g_mockCreateBundleContextReturnNull) {
        return nullptr;
    }
    return std::make_shared<MockContext>(bundleName);
}

std::shared_ptr<Global::Resource::ResourceManager> MockApplicationContext::GetResourceManager() const
{
    return mockResourceManager_;
}

std::string MockApplicationContext::GetBundleName() const
{
    return "com.test.mock";
}

MockContext::MockContext(const std::string &bundleName) : bundleName_(bundleName)
{
    mockResourceManager_ = std::make_shared<Global::Resource::Mock::MockResourceManager>();
}

std::string MockContext::GetBundleName() const
{
    return bundleName_;
}

std::shared_ptr<Context> MockContext::CreateBundleContext(const std::string &bundleName)
{
    return std::make_shared<MockContext>(bundleName);
}

std::shared_ptr<Global::Resource::ResourceManager> MockContext::GetResourceManager() const
{
    if (OHOS::Global::Resource::Mock::g_mockGetResourceManagerReturnNull) {
        return nullptr;
    }
    return mockResourceManager_;
}

}  // namespace Mock
}  // namespace AbilityRuntime
}  // namespace OHOS