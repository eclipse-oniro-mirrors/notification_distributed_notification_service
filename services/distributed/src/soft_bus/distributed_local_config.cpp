/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "distributed_local_config.h"


namespace OHOS {
namespace Notification {

DistributedLocalConfig& DistributedLocalConfig::GetInstance()
{
    static DistributedLocalConfig distributedLocalConfig;
    return distributedLocalConfig;
}

void DistributedLocalConfig::SetLocalDevice(const DistributedDeviceConfig config)
{
    localConfig_ = config;
}

int32_t DistributedLocalConfig::GetTitleLength() const
{
    return localConfig_.maxTitleLength;
}

int32_t DistributedLocalConfig::GetContentLength() const
{
    return localConfig_.maxContentLength;
}

uint32_t DistributedLocalConfig::GetStartAbilityTimeout() const
{
    return localConfig_.startAbilityTimeout;
}

std::unordered_set<std::string> DistributedLocalConfig::GetCollaborativeDeleteTypes() const
{
    return localConfig_.collaborativeDeleteTypes;
}

}
}
