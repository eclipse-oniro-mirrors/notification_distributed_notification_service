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

#include "mock_application_context.h"
#include "mock_application_context_full.h"
#include "context.h"

namespace {
bool g_mockApplicationContextReturnNull = false;
std::shared_ptr<OHOS::AbilityRuntime::ApplicationContext> g_mockApplicationContext = nullptr;
}

namespace OHOS {
namespace AbilityRuntime {
namespace Mock {

bool MockGetApplicationContextReturnNull(bool isNull)
{
    g_mockApplicationContextReturnNull = isNull;
    return g_mockApplicationContextReturnNull;
}

void MockResetApplicationContextState()
{
    g_mockApplicationContextReturnNull = false;
    g_mockApplicationContext = nullptr;
    MockResetCreateBundleContextState();
}

std::shared_ptr<ApplicationContext> GetMockApplicationContext()
{
    if (g_mockApplicationContextReturnNull) {
        return nullptr;
    }
    if (g_mockApplicationContext) {
        return g_mockApplicationContext;
    }
    static auto mockContext = std::make_shared<MockApplicationContext>();
    return std::static_pointer_cast<ApplicationContext>(mockContext);
}

void MockSetApplicationContext(std::shared_ptr<ApplicationContext> context)
{
    g_mockApplicationContext = context;
}

}  // namespace Mock

std::shared_ptr<ApplicationContext> Context::GetApplicationContext()
{
    return Mock::GetMockApplicationContext();
}

}  // namespace AbilityRuntime
}  // namespace OHOS