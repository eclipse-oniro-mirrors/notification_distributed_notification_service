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

#include "mock_datashare_helper.h"

namespace OHOS {
static std::shared_ptr<DataShare::DataShareHelper> g_mockHelper;
static int32_t g_mockCreateRet = 0;
namespace Notification {
void MockDataShareHelper::MockCreate(const int32_t ret, const std::shared_ptr<DataShareHelper> helper)
{
    g_mockCreateRet = ret;
    g_mockHelper = helper;
}
}

namespace DataShare {
std::pair<int, std::shared_ptr<DataShareHelper>> DataShareHelper::Create(const sptr<IRemoteObject>& token,
    const std::string& strUri, const std::string& extUri, const int waitTime)
{
    return std::make_pair(g_mockCreateRet, g_mockHelper);
}
}
}  // namespace OHOS